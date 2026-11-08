package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"sentinela/internal/model"
)

// Categorias (equivalentes às abas do Autoruns).
const (
	CatLogon       = "Logon"
	CatStartup     = "Pasta Inicializar"
	CatServices    = "Serviços"
	CatDrivers     = "Drivers"
	CatTasks       = "Tarefas Agendadas"
	CatWinlogon    = "Winlogon"
	CatImageHijack = "Image Hijacks (IFEO)"
	CatAppInit     = "AppInit"
	CatActiveSetup = "Active Setup"
)

// Tipos de entrada, usados pela remediação para saber como desfazer.
const (
	KindRegValue = "regvalue" // valor de registro que pode ser removido
	KindWinlogon = "winlogon" // valor que deve voltar ao padrão
	KindAppInit  = "appinit"
	KindService  = "service"
	KindTask     = "task"
	KindStartup  = "startup" // arquivo na pasta Inicializar
)

// RegRef identifica um valor de registro. Root é "HKLM" ou "HKU".
type RegRef struct {
	Root  string `json:"root"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (r RegRef) RootKey() registry.Key {
	if r.Root == "HKU" {
		return registry.USERS
	}
	return registry.LOCAL_MACHINE
}

// Entry é um Autorun com os dados internos necessários para a remediação.
type Entry struct {
	model.Autorun
	Kind        string
	Reg         *RegRef
	ServiceName string
	TaskPath    string // relativo a System32\Tasks, ex.: \Microsoft\Foo
	FilePath    string // arquivo na pasta Inicializar
}

type userCtx struct {
	SID, Name, Profile string
}

func (u userCtx) env(name string) string {
	if u.Profile != "" {
		switch strings.ToUpper(name) {
		case "USERPROFILE":
			return u.Profile
		case "APPDATA":
			return filepath.Join(u.Profile, `AppData\Roaming`)
		case "LOCALAPPDATA":
			return filepath.Join(u.Profile, `AppData\Local`)
		case "TEMP", "TMP":
			return filepath.Join(u.Profile, `AppData\Local\Temp`)
		case "USERNAME":
			if i := strings.LastIndexByte(u.Name, '\\'); i >= 0 {
				return u.Name[i+1:]
			}
		}
	}
	return os.Getenv(name)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func winDir() string {
	if d := os.Getenv("SystemRoot"); d != "" {
		return d
	}
	return `C:\Windows`
}

func newResolver(u *userCtx) *Resolver {
	env := os.Getenv
	if u != nil {
		env = u.env
	}
	return &Resolver{WinDir: winDir(), Env: env, Exists: fileExists}
}

func entryID(cat, loc, name string) string {
	h := sha256.Sum256([]byte(strings.ToLower(cat + "|" + loc + "|" + name)))
	return hex.EncodeToString(h[:8])
}

func sidName(sid string) string {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return sid
	}
	acc, dom, _, err := s.LookupAccount("")
	if err != nil {
		return sid
	}
	if dom != "" {
		return dom + `\` + acc
	}
	return acc
}

// profiles lista os perfis de usuários reais (S-1-5-21-*) da máquina.
func profiles() map[string]userCtx {
	out := map[string]userCtx{}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return out
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") {
			continue
		}
		sk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		p, _, _ := sk.GetStringValue("ProfileImagePath")
		sk.Close()
		out[sid] = userCtx{SID: sid, Name: sidName(sid), Profile: os.ExpandEnv(strings.ReplaceAll(p, "%SystemDrive%", os.Getenv("SystemDrive")))}
	}
	return out
}

// loadedUsers lista os usuários com hive carregado em HKEY_USERS (logados).
func loadedUsers(profs map[string]userCtx) []userCtx {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []userCtx
	for _, n := range names {
		if !strings.HasPrefix(n, "S-1-5-21-") || strings.HasSuffix(n, "_Classes") {
			continue
		}
		u, ok := profs[n]
		if !ok {
			u = userCtx{SID: n, Name: sidName(n)}
		}
		out = append(out, u)
	}
	return out
}

// startupApproved lê o estado definido pelo Gerenciador de Tarefas
// (aba Inicializar). Byte 0 ímpar = desativado.
func startupApproved(root registry.Key, base, sub, name string) bool {
	k, err := registry.OpenKey(root, base+`\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\`+sub, registry.QUERY_VALUE)
	if err != nil {
		return true
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue(name)
	if err != nil || len(b) == 0 {
		return true
	}
	return b[0]&1 == 0
}

// Persistence enumera os pontos de inicialização automática.
func Persistence(in *Inspector, errs *[]string) []Entry {
	c := &pcol{in: in, errs: errs}
	profs := profiles()
	users := loadedUsers(profs)

	// --- Logon: chaves Run/RunOnce da máquina
	for _, loc := range []struct{ key, approved string }{
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "Run"},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
		{`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Run32"},
		{`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, ""},
	} {
		c.runKey("HKLM", registry.LOCAL_MACHINE, loc.key, "SOFTWARE", loc.approved, nil)
	}
	// --- Logon: chaves Run/RunOnce por usuário logado
	for i := range users {
		u := &users[i]
		for _, loc := range []struct{ key, approved string }{
			{`Software\Microsoft\Windows\CurrentVersion\Run`, "Run"},
			{`Software\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
			{`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, ""},
		} {
			c.runKey("HKU", registry.USERS, u.SID+`\`+loc.key, u.SID+`\Software`, loc.approved, u)
		}
		// Valores legados "Load"/"Run" e Shell por usuário
		c.singleValue("HKU", u.SID+`\Software\Microsoft\Windows NT\CurrentVersion\Windows`, "Load", CatLogon, KindRegValue, u)
		c.singleValue("HKU", u.SID+`\Software\Microsoft\Windows NT\CurrentVersion\Windows`, "Run", CatLogon, KindRegValue, u)
		c.singleValue("HKU", u.SID+`\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", CatWinlogon, KindRegValue, u)
	}

	// --- Pastas Inicializar (todos os usuários + cada perfil)
	c.startupFolder(filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`), nil)
	for _, u := range profs {
		u := u
		c.startupFolder(filepath.Join(u.Profile, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), &u)
	}

	// --- Winlogon (Shell / Userinit)
	for _, v := range []string{"Shell", "Userinit"} {
		c.singleValue("HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, v, CatWinlogon, KindWinlogon, nil)
	}

	// --- IFEO Debugger, AppInit_DLLs, Active Setup
	for _, base := range []string{`SOFTWARE`, `SOFTWARE\WOW6432Node`} {
		c.ifeo(base + `\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`)
		c.appInit(base + `\Microsoft\Windows NT\CurrentVersion\Windows`)
		c.activeSetup(base + `\Microsoft\Active Setup\Installed Components`)
	}

	c.services()
	c.tasks()
	return c.out
}

type pcol struct {
	in   *Inspector
	errs *[]string
	out  []Entry
}

func (c *pcol) errf(s string) { *c.errs = append(*c.errs, s) }

// finish resolve o executável, o payload e coleta as informações de arquivo.
func (c *pcol) finish(e Entry, u *userCtx) {
	r := newResolver(u)
	if e.ImagePath == "" {
		img, args := r.Resolve(e.Command)
		e.ImagePath = img
		if p := r.Payload(img, args); p != "" && e.Payload == nil {
			e.Payload = c.in.Inspect(p)
		}
	}
	if u != nil && e.User == "" {
		e.User = u.Name
	}
	e.File = c.in.Inspect(e.ImagePath)
	e.ID = entryID(e.Category, e.Location, e.Name)
	c.out = append(c.out, e)
}

func rootName(root string) string {
	if root == "HKU" {
		return "HKU"
	}
	return "HKLM"
}

func (c *pcol) runKey(root string, rk registry.Key, key, approvedBase, approvedSub string, u *userCtx) {
	k, err := registry.OpenKey(rk, key, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	for _, n := range names {
		v, _, err := k.GetStringValue(n)
		if err != nil || strings.TrimSpace(v) == "" {
			continue
		}
		enabled := true
		if approvedSub != "" {
			enabled = startupApproved(rk, approvedBase, approvedSub, n)
		}
		c.finish(Entry{
			Autorun: model.Autorun{Category: CatLogon, Location: rootName(root) + `\` + key, Name: n, Command: v, Enabled: enabled},
			Kind:    KindRegValue,
			Reg:     &RegRef{Root: root, Key: key, Value: n},
		}, u)
	}
}

func (c *pcol) singleValue(root, key, name, cat, kind string, u *userCtx) {
	rk := RegRef{Root: root}.RootKey()
	k, err := registry.OpenKey(rk, key, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil || strings.TrimSpace(v) == "" {
		return
	}
	e := Entry{
		Autorun: model.Autorun{Category: cat, Location: rootName(root) + `\` + key, Name: name, Command: v, Enabled: true},
		Kind:    kind,
		Reg:     &RegRef{Root: root, Key: key, Value: name},
	}
	// Userinit pode ter vários executáveis separados por vírgula; o primeiro
	// é o principal, os demais são suspeitos e ficam visíveis no Command.
	if name == "Userinit" {
		first := strings.TrimSpace(strings.Split(v, ",")[0])
		e.ImagePath, _ = newResolver(u).Resolve(first)
	}
	c.finish(e, u)
}

func (c *pcol) startupFolder(dir string, u *userCtx) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	approvedRoot, approvedBase := registry.LOCAL_MACHINE, "SOFTWARE"
	if u != nil {
		approvedRoot, approvedBase = registry.USERS, u.SID+`\Software`
	}
	for _, de := range ents {
		if de.IsDir() || strings.EqualFold(de.Name(), "desktop.ini") {
			continue
		}
		full := filepath.Join(dir, de.Name())
		e := Entry{
			Autorun: model.Autorun{Category: CatStartup, Location: dir, Name: de.Name(),
				Enabled: startupApproved(approvedRoot, approvedBase, "StartupFolder", de.Name())},
			Kind:     KindStartup,
			FilePath: full,
		}
		if strings.EqualFold(filepath.Ext(full), ".lnk") {
			li, err := ParseLnkFile(full)
			if err != nil {
				c.errf("atalho " + full + ": " + err.Error())
				e.Command = full
				e.ImagePath = full
			} else {
				target := li.Target
				if target == "" && li.RelPath != "" {
					target = filepath.Join(dir, li.RelPath)
				}
				r := newResolver(u)
				target = r.Normalize(target)
				e.Command = strings.TrimSpace(`"` + target + `" ` + li.Args)
				e.ImagePath = target
				if p := r.Payload(target, li.Args); p != "" {
					e.Payload = c.in.Inspect(p)
				}
			}
		} else {
			e.Command = full
			e.ImagePath = full
		}
		c.finish(e, u)
	}
}

func (c *pcol) ifeo(key string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		sk, err := registry.OpenKey(k, s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := sk.GetStringValue("Debugger")
		sk.Close()
		if err != nil || strings.TrimSpace(v) == "" {
			continue
		}
		c.finish(Entry{
			Autorun: model.Autorun{Category: CatImageHijack, Location: `HKLM\` + key + `\` + s, Name: s, Command: v, Enabled: true},
			Kind:    KindRegValue,
			Reg:     &RegRef{Root: "HKLM", Key: key + `\` + s, Value: "Debugger"},
		}, nil)
	}
}

func (c *pcol) appInit(key string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	v, _, err := k.GetStringValue("AppInit_DLLs")
	if err != nil || strings.TrimSpace(v) == "" {
		return
	}
	load, _, _ := k.GetIntegerValue("LoadAppInit_DLLs")
	for _, dll := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		c.finish(Entry{
			Autorun: model.Autorun{Category: CatAppInit, Location: `HKLM\` + key, Name: "AppInit_DLLs", Command: dll, Enabled: load == 1},
			Kind:    KindAppInit,
			Reg:     &RegRef{Root: "HKLM", Key: key, Value: "AppInit_DLLs"},
		}, nil)
	}
}

func (c *pcol) activeSetup(key string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		sk, err := registry.OpenKey(k, s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := sk.GetStringValue("StubPath")
		name, _, _ := sk.GetStringValue("")
		isInstalled, _, ierr := sk.GetIntegerValue("IsInstalled")
		sk.Close()
		if err != nil || strings.TrimSpace(v) == "" {
			continue
		}
		if name == "" {
			name = s
		}
		c.finish(Entry{
			Autorun: model.Autorun{Category: CatActiveSetup, Location: `HKLM\` + key + `\` + s, Name: name, Command: v,
				Enabled: ierr != nil || isInstalled != 0},
			Kind: KindRegValue,
			Reg:  &RegRef{Root: "HKLM", Key: key + `\` + s, Value: "StubPath"},
		}, nil)
	}
}
