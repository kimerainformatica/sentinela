package procmon

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"
)

// Monta o payload de um evento Process/Start do kernel (layout V4, x64)
// e confere a leitura manual usada quando o TDH não tem o esquema.
func TestKernelProcessStartLayout(t *testing.T) {
	var b []byte
	u32 := func(v uint32) { b = binary.LittleEndian.AppendUint32(b, v) }
	u64 := func(v uint64) { b = binary.LittleEndian.AppendUint64(b, v) }

	u64(0xFFFF8000DEADBEEF) // UniqueProcessKey
	u32(4321)               // ProcessId
	u32(1234)               // ParentId
	u32(1)                  // SessionId
	u32(0)                  // ExitStatus
	u64(0x1AA000)           // DirectoryTableBase
	u32(0)                  // Flags (V3+)
	// UserSID: TOKEN_USER (2 ponteiros) + SID S-1-5-21-a-b-c-1001
	u64(0x1)
	u64(0)
	b = append(b, 1, 5, 0, 0, 0, 0, 0, 5) // revisão, 5 subautoridades, autoridade NT
	for _, s := range []uint32{21, 111, 222, 333, 1001} {
		u32(s)
	}
	b = append(b, []byte("powershell.exe")...)
	b = append(b, 0)
	cmd := `powershell.exe -w hidden -enc SQBFAFgA`
	for _, c := range utf16.Encode([]rune(cmd)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	b = append(b, 0, 0, 0, 0) // terminador + PackageFullName vazio

	rec := &eventRecord{Version: 4, UserData: uintptr(unsafe.Pointer(&b[0])), UserDataLength: uint16(len(b))}
	pid, ppid, name, got, ok := kernelProcessStart(rec)
	if !ok || pid != 4321 || ppid != 1234 || name != "powershell.exe" || got != cmd {
		t.Fatalf("obtido pid=%d ppid=%d name=%q cmd=%q ok=%v", pid, ppid, name, got, ok)
	}

	// SID ausente (uint32 zero) e versão 2 (sem Flags)
	b = b[:0]
	u64(1)
	u32(10)
	u32(20)
	u32(0)
	u32(0)
	u64(0)
	u32(0) // SID ausente
	b = append(b, []byte("cmd.exe")...)
	b = append(b, 0)
	for _, c := range utf16.Encode([]rune("cmd /c echo oi")) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	b = append(b, 0, 0)
	rec = &eventRecord{Version: 2, UserData: uintptr(unsafe.Pointer(&b[0])), UserDataLength: uint16(len(b))}
	if pid, ppid, name, got, ok := kernelProcessStart(rec); !ok || pid != 10 || ppid != 20 || name != "cmd.exe" || got != "cmd /c echo oi" {
		t.Fatalf("v2: pid=%d ppid=%d name=%q cmd=%q", pid, ppid, name, got)
	}
}

// As duas partes de uma execução (linha de comando do kernel e caminho do
// Kernel-Process) devem ser unidas, em qualquer ordem.
func TestMergeParts(t *testing.T) {
	t0 := time.Now()
	cmdPart := rawStart{pid: 7, ppid: 3, image: "cmd.exe", cmdline: "cmd /c echo oi", when: t0.Add(time.Millisecond), parts: partCmd}
	imgPart := rawStart{pid: 7, ppid: 3, image: `C:\Windows\System32\cmd.exe`, when: t0, parts: partImage}

	for _, order := range [][2]rawStart{{cmdPart, imgPart}, {imgPart, cmdPart}} {
		a := order[0]
		merge(&a, order[1])
		if a.image != `C:\Windows\System32\cmd.exe` || a.cmdline != "cmd /c echo oi" || a.parts != partCmd|partImage || !a.when.Equal(t0) {
			t.Fatalf("merge: %+v", a)
		}
	}
}

func TestProcCacheEarly(t *testing.T) {
	c := newProcCache()
	// Só o provedor do kernel: nome curto + linha de comando.
	c.early(10, 1, "curl.exe", `"C:\Windows\System32\curl.exe" -s https://example.com`)
	if e, ok := c.get(10); !ok || !strings.EqualFold(e.name, "curl.exe") || !strings.HasSuffix(strings.ToLower(e.image), `\curl.exe`) {
		t.Fatalf("early com linha de comando: %+v %v", e, ok)
	}
	// Não sobrescreve um registro completo do mesmo programa.
	c.set(20, procEntry{name: "app.exe", image: `C:\App\app.exe`})
	c.early(20, 1, "app.exe", "")
	if e, _ := c.get(20); e.image != `C:\App\app.exe` {
		t.Fatalf("registro completo foi sobrescrito: %+v", e)
	}
	// PID reutilizado por outro programa: atualiza.
	c.early(20, 1, `C:\Windows\System32\cmd.exe`, "")
	if e, _ := c.get(20); e.name != "cmd.exe" {
		t.Fatalf("PID reutilizado não atualizou: %+v", e)
	}
}
