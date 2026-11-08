package collect

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"sentinela/internal/model"
)

const servicesKey = `SYSTEM\CurrentControlSet\Services`

// services lista serviços e drivers com início automático (Start 0, 1 ou 2).
func (c *pcol) services() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		c.errf("serviços: " + err.Error())
		return
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	r := newResolver(nil)
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		start, _, err1 := sk.GetIntegerValue("Start")
		typ, _, err2 := sk.GetIntegerValue("Type")
		img, _, _ := sk.GetStringValue("ImagePath")
		dll, _, _ := sk.GetStringValue("ServiceDll")
		sk.Close()
		if err1 != nil || err2 != nil || start > 2 {
			continue
		}
		if dll == "" {
			if pk, err := registry.OpenKey(k, n+`\Parameters`, registry.QUERY_VALUE); err == nil {
				dll, _, _ = pk.GetStringValue("ServiceDll")
				pk.Close()
			}
		}

		var cat string
		switch {
		case typ == 1 || typ == 2:
			cat = CatDrivers
			if strings.TrimSpace(img) == "" {
				img = filepath.Join(winDir(), `System32\drivers`, n+".sys")
			}
		case typ&0x30 != 0:
			cat = CatServices
		default:
			continue
		}
		if strings.TrimSpace(img) == "" {
			continue
		}
		e := Entry{
			Autorun: model.Autorun{Category: cat, Location: `HKLM\` + servicesKey + `\` + n, Name: n, Command: img, Enabled: true},
			Kind:        KindService,
			ServiceName: n,
		}
		// Serviços hospedados no svchost: o código real está na ServiceDll.
		if dll != "" {
			e.Payload = c.in.Inspect(r.Normalize(dll))
		}
		c.finish(e, nil)
	}
}

// ---------------------------------------------------------------------------
// Tarefas agendadas (arquivos XML em System32\Tasks)

type taskXML struct {
	Settings struct {
		Enabled *bool `xml:"Enabled"`
	} `xml:"Settings"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
		ComHandler []struct {
			ClassID string `xml:"ClassId"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
	Principals struct {
		Principal []struct {
			UserID  string `xml:"UserId"`
			GroupID string `xml:"GroupId"`
		} `xml:"Principal"`
	} `xml:"Principals"`
}

func decodeTaskXML(b []byte) (*taskXML, error) {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE { // UTF-16 LE com BOM
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2+i*2:])
		}
		b = []byte(string(utf16.Decode(u)))
	} else if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	// O conteúdo já está em UTF-8; ignora o encoding declarado.
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var t taskXML
	if err := d.Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

func clsidServer(clsid string) string {
	for _, key := range []string{`SOFTWARE\Classes\CLSID\` + clsid + `\InprocServer32`, `SOFTWARE\Classes\CLSID\` + clsid + `\LocalServer32`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, _ := k.GetStringValue("")
		k.Close()
		if v != "" {
			return v
		}
	}
	return ""
}

func (c *pcol) tasks() {
	root := filepath.Join(winDir(), `System32\Tasks`)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // sem permissão em alguma subpasta: segue
		}
		if d.IsDir() {
			return nil
		}
		info, _ := d.Info()
		if info != nil && info.Size() > 2<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		t, err := decodeTaskXML(b)
		if err != nil {
			c.errf("tarefa " + p + ": " + err.Error())
			return nil
		}
		rel := strings.TrimPrefix(p, root)
		enabled := t.Settings.Enabled == nil || *t.Settings.Enabled
		user := ""
		if len(t.Principals.Principal) > 0 {
			user = t.Principals.Principal[0].UserID
			if user == "" {
				user = t.Principals.Principal[0].GroupID
			}
			if strings.HasPrefix(user, "S-1-") {
				user = sidName(user)
			}
		}
		n := 0
		name := func() string {
			n++
			if n == 1 {
				return rel
			}
			return fmt.Sprintf("%s (ação %d)", rel, n)
		}
		for _, ex := range t.Actions.Exec {
			cmd := strings.TrimSpace(ex.Command)
			if cmd == "" {
				continue
			}
			if !strings.HasPrefix(cmd, `"`) && strings.Contains(cmd, " ") {
				cmd = `"` + cmd + `"`
			}
			c.finish(Entry{
				Autorun:  model.Autorun{Category: CatTasks, Location: "Agendador de Tarefas", Name: name(), Command: strings.TrimSpace(cmd + " " + ex.Arguments), Enabled: enabled, User: user},
				Kind:     KindTask,
				TaskPath: rel,
			}, nil)
		}
		for _, ch := range t.Actions.ComHandler {
			srv := clsidServer(ch.ClassID)
			c.finish(Entry{
				Autorun:  model.Autorun{Category: CatTasks, Location: "Agendador de Tarefas (COM " + ch.ClassID + ")", Name: name(), Command: srv, Enabled: enabled, User: user},
				Kind:     KindTask,
				TaskPath: rel,
			}, nil)
		}
		return nil
	})
	if err != nil {
		c.errf("tarefas: " + err.Error())
	}
}
