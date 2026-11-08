// Package remediate executa as ações de resposta do agente.
//
// Princípio: toda alteração é reversível. Entradas de inicialização são
// salvas antes de serem desativadas e arquivos vão para quarentena
// (codificados, para não poderem ser executados) em vez de serem apagados.
package remediate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"sentinela/internal/agent/collect"
	"sentinela/internal/model"
)

// Valores padrão do Winlogon, restaurados quando a entrada é desativada.
var winlogonDefaults = map[string]string{
	"Shell":    "explorer.exe",
	"Userinit": `C:\Windows\system32\userinit.exe,`,
}

// Processos do sistema que nunca devem ser finalizados quando estão no
// local legítimo (finalizá-los causa tela azul ou logoff).
var criticalProcs = map[string]bool{
	"csrss.exe": true, "wininit.exe": true, "winlogon.exe": true, "smss.exe": true,
	"lsass.exe": true, "services.exe": true, "svchost.exe": true, "system": true,
	"lsaiso.exe": true, "fontdrvhost.exe": true, "dwm.exe": true,
}

const xorKey = 0x5A

type Remediator struct {
	DataDir string
	// Entries reenumera as entradas de inicialização (a remediação sempre
	// age sobre o estado atual, nunca sobre um snapshot antigo).
	Entries func() []collect.Entry
}

type backup struct {
	ID          string          `json:"id"`
	Created     time.Time       `json:"created"`
	Kind        string          `json:"kind"`
	AutorunID   string          `json:"autorun_id"`
	Name        string          `json:"name"`
	Reg         *collect.RegRef `json:"reg,omitempty"`
	RegType     uint32          `json:"reg_type,omitempty"`
	RegData     string          `json:"reg_data,omitempty"`
	ServiceName string          `json:"service_name,omitempty"`
	OldStart    uint32          `json:"old_start,omitempty"`
	TaskPath    string          `json:"task_path,omitempty"`
	OrigPath    string          `json:"orig_path,omitempty"`
	StoredPath  string          `json:"stored_path,omitempty"`
}

type quarantined struct {
	ID       string    `json:"id"`
	Created  time.Time `json:"created"`
	OrigPath string    `json:"orig_path"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (r *Remediator) dir(sub string) string {
	d := filepath.Join(r.DataDir, sub)
	os.MkdirAll(d, 0o700)
	return d
}

func ok(msg, undo string) model.CommandResult {
	return model.CommandResult{OK: true, Message: msg, UndoID: undo}
}

func fail(err error) model.CommandResult {
	return model.CommandResult{OK: false, Message: err.Error()}
}

// Execute despacha a ação. A verificação de assinatura e validade do
// comando é feita antes, pelo agente.
func (r *Remediator) Execute(p model.CommandPayload) model.CommandResult {
	var res model.CommandResult
	switch p.Action {
	case model.ActionKillProcess:
		res = r.kill(p.Params["pid"], p.Params["image_path"])
	case model.ActionDisableAutorun:
		res = r.disable(p.Params["autorun_id"])
	case model.ActionRestoreAutorun:
		res = r.restore(p.Params["backup_id"])
	case model.ActionQuarantineFile:
		res = r.quarantine(p.Params["path"], p.Params["sha256"])
	case model.ActionRestoreFile:
		res = r.restoreFile(p.Params["quarantine_id"])
	default:
		res = fail(fmt.Errorf("ação não permitida: %q", p.Action))
	}
	return res
}

// ---------------------------------------------------------------------------
// Finalizar processo

func (r *Remediator) kill(pidStr, image string) model.CommandResult {
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil || pid <= 4 {
		return fail(errors.New("PID inválido"))
	}
	if uint32(pid) == windows.GetCurrentProcessId() {
		return fail(errors.New("o agente não pode finalizar a si mesmo"))
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return fail(fmt.Errorf("não foi possível abrir o processo %d: %w", pid, err))
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return fail(fmt.Errorf("não foi possível ler o caminho do processo: %w", err))
	}
	actual := windows.UTF16ToString(buf[:n])
	// Protege contra reutilização de PID: o processo precisa ser o mesmo
	// que o analista viu no painel.
	if !strings.EqualFold(actual, image) {
		return fail(fmt.Errorf("o PID %d agora pertence a %s (esperado %s); nada foi feito", pid, actual, image))
	}
	sysDir := strings.ToLower(filepath.Join(os.Getenv("SystemRoot"), "System32")) + `\`
	if criticalProcs[strings.ToLower(filepath.Base(actual))] && strings.HasPrefix(strings.ToLower(actual), sysDir) {
		return fail(fmt.Errorf("%s é um processo crítico do Windows e não será finalizado", actual))
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fail(fmt.Errorf("falha ao finalizar: %w", err))
	}
	return ok(fmt.Sprintf("processo %d (%s) finalizado", pid, filepath.Base(actual)), "")
}

// ---------------------------------------------------------------------------
// Desativar / restaurar entrada de inicialização

func (r *Remediator) saveBackup(b *backup) error {
	data, _ := json.MarshalIndent(b, "", "  ")
	return os.WriteFile(filepath.Join(r.dir("backups"), b.ID+".json"), data, 0o600)
}

func openReg(ref *collect.RegRef, access uint32) (registry.Key, error) {
	return registry.OpenKey(ref.RootKey(), ref.Key, access)
}

func (r *Remediator) disable(id string) model.CommandResult {
	var e *collect.Entry
	for _, x := range r.Entries() {
		if x.ID == id {
			x := x
			e = &x
			break
		}
	}
	if e == nil {
		return fail(errors.New("entrada não encontrada (já foi removida ou alterada)"))
	}
	b := &backup{ID: newID(), Created: time.Now().UTC(), Kind: e.Kind, AutorunID: e.ID, Name: e.Name}

	switch e.Kind {
	case collect.KindRegValue, collect.KindWinlogon, collect.KindAppInit:
		k, err := openReg(e.Reg, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			return fail(fmt.Errorf("abrir chave: %w", err))
		}
		defer k.Close()
		val, typ, err := k.GetStringValue(e.Reg.Value)
		if err != nil {
			return fail(fmt.Errorf("ler valor: %w", err))
		}
		b.Reg, b.RegType, b.RegData = e.Reg, typ, val
		if err := r.saveBackup(b); err != nil {
			return fail(fmt.Errorf("salvar backup: %w", err))
		}
		switch e.Kind {
		case collect.KindWinlogon:
			err = k.SetStringValue(e.Reg.Value, winlogonDefaults[e.Reg.Value])
		case collect.KindAppInit:
			err = k.SetStringValue(e.Reg.Value, "")
		default:
			err = k.DeleteValue(e.Reg.Value)
		}
		if err != nil {
			return fail(fmt.Errorf("alterar registro: %w", err))
		}

	case collect.KindService:
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+e.ServiceName, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			return fail(fmt.Errorf("abrir serviço: %w", err))
		}
		defer k.Close()
		old, _, err := k.GetIntegerValue("Start")
		if err != nil {
			return fail(err)
		}
		b.ServiceName, b.OldStart = e.ServiceName, uint32(old)
		if err := r.saveBackup(b); err != nil {
			return fail(err)
		}
		if err := k.SetDWordValue("Start", 4); err != nil {
			return fail(fmt.Errorf("desativar serviço: %w", err))
		}
		stopService(e.ServiceName)

	case collect.KindTask:
		b.TaskPath = e.TaskPath
		if err := r.saveBackup(b); err != nil {
			return fail(err)
		}
		if out, err := exec.Command("schtasks.exe", "/Change", "/TN", e.TaskPath, "/DISABLE").CombinedOutput(); err != nil {
			return fail(fmt.Errorf("schtasks: %v: %s", err, strings.TrimSpace(string(out))))
		}

	case collect.KindStartup:
		b.OrigPath = e.FilePath
		b.StoredPath = filepath.Join(r.dir("backups"), b.ID+".file")
		if err := r.saveBackup(b); err != nil {
			return fail(err)
		}
		if err := os.Rename(b.OrigPath, b.StoredPath); err != nil {
			return fail(fmt.Errorf("mover atalho: %w", err))
		}

	default:
		return fail(fmt.Errorf("tipo de entrada não suportado: %s", e.Kind))
	}
	return ok(fmt.Sprintf("entrada %q desativada (backup %s)", e.Name, b.ID), b.ID)
}

func stopService(name string) {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return
	}
	defer s.Close()
	s.Control(svc.Stop)
}

func (r *Remediator) restore(id string) model.CommandResult {
	if !isHexID(id) {
		return fail(errors.New("backup inválido"))
	}
	path := filepath.Join(r.dir("backups"), id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fail(fmt.Errorf("backup %s não encontrado", id))
	}
	var b backup
	if err := json.Unmarshal(data, &b); err != nil {
		return fail(err)
	}
	switch b.Kind {
	case collect.KindRegValue, collect.KindWinlogon, collect.KindAppInit:
		k, _, err := registry.CreateKey(b.Reg.RootKey(), b.Reg.Key, registry.SET_VALUE)
		if err != nil {
			return fail(err)
		}
		defer k.Close()
		if b.RegType == registry.EXPAND_SZ {
			err = k.SetExpandStringValue(b.Reg.Value, b.RegData)
		} else {
			err = k.SetStringValue(b.Reg.Value, b.RegData)
		}
		if err != nil {
			return fail(err)
		}
	case collect.KindService:
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+b.ServiceName, registry.SET_VALUE)
		if err != nil {
			return fail(err)
		}
		defer k.Close()
		if err := k.SetDWordValue("Start", b.OldStart); err != nil {
			return fail(err)
		}
	case collect.KindTask:
		if out, err := exec.Command("schtasks.exe", "/Change", "/TN", b.TaskPath, "/ENABLE").CombinedOutput(); err != nil {
			return fail(fmt.Errorf("schtasks: %v: %s", err, strings.TrimSpace(string(out))))
		}
	case collect.KindStartup:
		if _, err := os.Stat(b.OrigPath); err == nil {
			return fail(fmt.Errorf("já existe um arquivo em %s", b.OrigPath))
		}
		if err := os.Rename(b.StoredPath, b.OrigPath); err != nil {
			return fail(err)
		}
	}
	os.Remove(path)
	return ok(fmt.Sprintf("entrada %q restaurada", b.Name), "")
}

func isHexID(s string) bool {
	if len(s) != 16 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ---------------------------------------------------------------------------
// Quarentena de arquivos

func xorBytes(b []byte) {
	for i := range b {
		b[i] ^= xorKey
	}
}

func (r *Remediator) quarantine(path, wantHash string) model.CommandResult {
	if path == "" || !filepath.IsAbs(path) {
		return fail(errors.New("caminho inválido"))
	}
	if self, err := os.Executable(); err == nil && strings.EqualFold(self, path) {
		return fail(errors.New("o agente não pode colocar a si mesmo em quarentena"))
	}
	fi := collect.NewInspector()
	info := fi.Inspect(path)
	fi.Close()
	if info == nil || !info.Exists {
		return fail(errors.New("arquivo não encontrado"))
	}
	// O arquivo precisa ser exatamente o que foi analisado no painel.
	if !strings.EqualFold(info.SHA256, wantHash) {
		return fail(errors.New("o hash do arquivo mudou desde a análise; faça uma nova varredura"))
	}
	if info.Signature == "valid" && strings.HasPrefix(info.Signer, "Microsoft Windows") {
		return fail(errors.New("arquivo do sistema assinado pela Microsoft; quarentena recusada"))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fail(err)
	}
	q := quarantined{ID: newID(), Created: time.Now().UTC(), OrigPath: path, SHA256: info.SHA256, Size: info.Size}
	xorBytes(data)
	bin := filepath.Join(r.dir("quarantine"), q.ID+".bin")
	if err := os.WriteFile(bin, data, 0o600); err != nil {
		return fail(err)
	}
	if err := os.Remove(path); err != nil {
		os.Remove(bin)
		return fail(fmt.Errorf("não foi possível remover o arquivo (provavelmente está em uso; finalize o processo antes): %w", err))
	}
	meta, _ := json.MarshalIndent(q, "", "  ")
	os.WriteFile(filepath.Join(r.dir("quarantine"), q.ID+".json"), meta, 0o600)
	return ok(fmt.Sprintf("%s movido para a quarentena", filepath.Base(path)), q.ID)
}

func (r *Remediator) restoreFile(id string) model.CommandResult {
	if !isHexID(id) {
		return fail(errors.New("identificador de quarentena inválido"))
	}
	dir := r.dir("quarantine")
	meta, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return fail(fmt.Errorf("item de quarentena %s não encontrado", id))
	}
	var q quarantined
	if err := json.Unmarshal(meta, &q); err != nil {
		return fail(err)
	}
	if _, err := os.Stat(q.OrigPath); err == nil {
		return fail(fmt.Errorf("já existe um arquivo em %s", q.OrigPath))
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".bin"))
	if err != nil {
		return fail(err)
	}
	xorBytes(data)
	os.MkdirAll(filepath.Dir(q.OrigPath), 0o755)
	if err := os.WriteFile(q.OrigPath, data, 0o644); err != nil {
		return fail(err)
	}
	os.Remove(filepath.Join(dir, id+".bin"))
	os.Remove(filepath.Join(dir, id+".json"))
	return ok(fmt.Sprintf("%s restaurado", q.OrigPath), "")
}
