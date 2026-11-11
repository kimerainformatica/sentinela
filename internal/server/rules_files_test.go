package server

import (
	"testing"
	"time"

	"sentinela/internal/model"
)

func TestFileRules(t *testing.T) {
	now := time.Now().UTC()
	unsigned := func(path string) *model.FileInfo {
		return &model.FileInfo{Path: path, Exists: true, SHA256: path, Signature: "unsigned", Created: now.Add(-30 * 24 * time.Hour)}
	}
	cases := []struct {
		name    string
		file    *model.FileInfo
		autorun bool
		want    map[string]string // regra -> severidade (só R20-R24)
	}{
		{"PowerShell renomeado (assinado pela Microsoft)", &model.FileInfo{Path: `C:\Users\ana\AppData\Local\update.exe`, Exists: true, SHA256: "ps",
			Signature: "valid", Signer: "Microsoft Windows", OriginalFilename: "PowerShell.EXE.MUI"}, false, map[string]string{"R20": SevAlta}},
		{"PsExec com nome normal não dispara", &model.FileInfo{Path: `C:\Tools\PsExec64.exe`, Exists: true, SHA256: "px",
			Signature: "valid", Signer: "Microsoft Corporation", OriginalFilename: "psexec.c"}, false, map[string]string{}},
		{"rclone disfarçado", func() *model.FileInfo {
			f := unsigned(`C:\Users\ana\AppData\Roaming\svc\backupsvc.exe`)
			f.OriginalFilename = "rclone.exe"
			return f
		}(), false, map[string]string{"R20": SevAlta}},
		{"extensão dupla", unsigned(`C:\Users\ana\Downloads\fatura_2026.pdf.exe`), false, map[string]string{"R21": SevAlta}},
		{"caractere de inversão", unsigned(`C:\Users\ana\Downloads\fatura` + "\u202E" + `fdp.exe`), false, map[string]string{"R21": SevAlta}},
		{"oculto em AppData", func() *model.FileInfo {
			f := unsigned(`C:\Users\ana\AppData\Roaming\x\host.exe`)
			f.Attributes = []string{"oculto", "sistema"}
			return f
		}(), false, map[string]string{"R22": SevMedia}},
		{"empacotado com UPX na inicialização", func() *model.FileInfo {
			f := unsigned(`C:\Users\ana\AppData\Roaming\x\agent.exe`)
			f.PE = &model.PEInfo{IsPE: true, Packer: "UPX", Packed: true, MaxEntropy: 7.9}
			return f
		}(), true, map[string]string{"R23": SevAlta}},
		{"baixado da internet e na inicialização", func() *model.FileInfo {
			f := unsigned(`C:\Users\ana\AppData\Local\Temp\setup.exe`)
			f.Origin = &model.FileOrigin{Zone: 3, ZoneName: "internet", HostURL: "https://exemplo.invalid/setup.exe"}
			return f
		}(), true, map[string]string{"R24": SevAlta}},
		{"baixado da internet, mas assinado", &model.FileInfo{Path: `C:\Users\ana\Downloads\ChromeSetup.exe`, Exists: true, SHA256: "cs",
			Signature: "valid", Signer: "Google LLC", Origin: &model.FileOrigin{Zone: 3}}, true, map[string]string{}},
		{"arquivo do sistema limpo", &model.FileInfo{Path: `C:\Windows\System32\notepad.exe`, Exists: true, SHA256: "np",
			Signature: "valid", Signer: "Microsoft Windows", OriginalFilename: "NOTEPAD.EXE.MUI"}, false, map[string]string{}},
	}
	for _, c := range cases {
		e := &evaluator{rep: &model.Report{CollectedAt: now}, seen: map[string]bool{}}
		e.fileChecks(c.file, "autorun", "x", "ctx", c.autorun)
		got := map[string]string{}
		for _, f := range e.out {
			got[f.RuleID] = f.Severity
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: achados %v, esperado %v", c.name, got, c.want)
			continue
		}
		for id, sev := range c.want {
			if got[id] != sev {
				t.Errorf("%s: %s = %q, esperado %q", c.name, id, got[id], sev)
			}
		}
	}
}

func TestDescribeExtra(t *testing.T) {
	f := &model.FileInfo{Path: `C:\x\a.exe`, Signature: "unsigned", OriginalFilename: "b.exe",
		Origin: &model.FileOrigin{Zone: 3, ZoneName: "internet", HostURL: "https://h/a.exe"},
		PE:     &model.PEInfo{IsPE: true, Packed: true, Packer: "UPX"}}
	d := describe(f)
	for _, want := range []string{"nome original: b.exe", "baixado da internet (https://h/a.exe)", "empacotado com UPX"} {
		if !contains(d, want) {
			t.Errorf("descrição sem %q: %s", want, d)
		}
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
