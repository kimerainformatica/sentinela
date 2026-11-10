package server

import (
	"testing"
	"time"

	"sentinela/internal/model"
)

func rules(fs []Finding) map[string]string {
	out := map[string]string{}
	for _, f := range fs {
		out[f.RuleID] = f.Severity
	}
	return out
}

func TestEvaluateTrojanScenario(t *testing.T) {
	now := time.Now().UTC()
	evil := &model.FileInfo{Path: `C:\Users\ana\AppData\Roaming\svchost.exe`, Exists: true, SHA256: "aa", Signature: "unsigned", Created: now.Add(-time.Hour)}
	ms := &model.FileInfo{Path: `C:\Windows\System32\svchost.exe`, Exists: true, SHA256: "bb", Signature: "valid", Signer: "Microsoft Windows Publisher"}
	rep := &model.Report{
		CollectedAt: now,
		Autoruns: []model.Autorun{
			{ID: "a1", Category: "Logon", Name: "WindowsUpdate", Command: evil.Path, ImagePath: evil.Path, File: evil, Enabled: true},
			{ID: "a2", Category: "Serviços", Name: "Dnscache", Command: ms.Path + " -k NetworkService", ImagePath: ms.Path, File: ms, Enabled: true},
			{ID: "a3", Category: "Logon", Name: "ps", Command: `powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`, ImagePath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, File: ms},
			{ID: "a4", Category: "Winlogon", Location: `HKLM\SOFTWARE\...\Winlogon`, Name: "Shell", Command: `explorer.exe, C:\ProgramData\x.exe`, File: ms},
			{ID: "a5", Category: "Winlogon", Location: `HKLM\SOFTWARE\...\Winlogon`, Name: "Userinit", Command: `C:\Windows\system32\userinit.exe,`, File: ms},
			{ID: "a6", Category: "Logon", Name: "velho", Command: `C:\Program Files\Removido\app.exe`, ImagePath: `C:\Program Files\Removido\app.exe`, File: &model.FileInfo{Path: `C:\Program Files\Removido\app.exe`}},
		},
		Processes: []model.Process{
			{PID: 100, PPID: 1, Name: "WINWORD.EXE", ImagePath: `C:\Program Files\Microsoft Office\WINWORD.EXE`},
			{PID: 200, PPID: 100, Name: "powershell.exe", ImagePath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine: "powershell -nop", File: ms},
			{PID: 300, PPID: 1, Name: "svchost.exe", ImagePath: evil.Path, File: evil},
		},
		Connections: []model.Connection{
			{Proto: "TCP", State: "ESTABLISHED", RemoteAddr: "45.9.148.10", RemotePort: 4444, PID: 300},
			{Proto: "TCP", State: "ESTABLISHED", RemoteAddr: "192.168.0.5", RemotePort: 445, PID: 300},
		},
	}
	intel := Intel{
		Hashes: map[string]HashRep{"aa": {Status: "known", Malicious: 41, Total: 72, Label: "trojan.agenttesla"}},
		IPs:    map[string]IPRep{"45.9.148.10": {Status: "known", Score: 100, Country: "NL"}},
	}
	got := rules(Evaluate(rep, intel))
	want := map[string]string{
		"R01": SevCritica, // VirusTotal
		"R02": SevAlta,    // sem assinatura em AppData
		"R03": SevAlta,    // powershell -enc
		"R05": SevCritica, // svchost.exe fora do System32
		"R06": SevCritica, // Winlogon Shell alterado
		"R09": SevBaixa,   // entrada órfã
		"R10": SevAlta,    // conexão externa de binário sem assinatura
		"R11": SevCritica, // IP malicioso
		"R14": SevAlta,    // Word -> PowerShell
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("regra %s: severidade %q, esperado %q", id, got[id], sev)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("achado inesperado: %s", id)
		}
	}
}

func TestEvaluateExecution(t *testing.T) {
	ms := &model.FileInfo{Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Exists: true, Signature: "valid", Signer: "Microsoft Windows"}
	// Word abrindo PowerShell codificado por meio segundo: só o tempo real vê.
	ev := &model.ProcessEvent{Time: time.Now(), PID: 900, PPID: 800, Name: "powershell.exe", ImagePath: ms.Path,
		CommandLine: "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", File: ms,
		ParentName: "WINWORD.EXE", ParentImage: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`}
	got := rules(EvaluateExecution(ev, Intel{}))
	if got["R14"] != SevAlta || got["R15"] != SevAlta || len(got) != 2 {
		t.Fatalf("obtido %v", got)
	}

	dl := &model.FileInfo{Path: `C:\Users\ana\Downloads\boleto_2026.exe`, Exists: true, SHA256: "cc", Signature: "unsigned"}
	ev = &model.ProcessEvent{Time: time.Now(), PID: 1, PPID: 2, Name: "boleto_2026.exe", ImagePath: dl.Path, File: dl, ParentName: "explorer.exe"}
	fs := EvaluateExecution(ev, Intel{})
	if len(fs) != 1 || fs[0].RuleID != "R17" || fs[0].Key[:3] != RealtimePrefix {
		t.Fatalf("obtido %+v", fs)
	}

	// Programa assinado comum não gera nada
	ok := &model.FileInfo{Path: `C:\Users\ana\AppData\Local\Discord\app\Discord.exe`, Exists: true, Signature: "valid", Signer: "Discord Inc."}
	ev = &model.ProcessEvent{Time: time.Now(), PID: 3, PPID: 4, Name: "Discord.exe", ImagePath: ok.Path, File: ok, ParentName: "explorer.exe"}
	if fs := EvaluateExecution(ev, Intel{}); len(fs) != 0 {
		t.Fatalf("falso positivo: %+v", fs)
	}
}

func TestNoFindingsForCleanSystem(t *testing.T) {
	ms := &model.FileInfo{Path: `C:\Windows\System32\svchost.exe`, Exists: true, SHA256: "bb", Signature: "valid", Signer: "Microsoft Windows Publisher"}
	discord := &model.FileInfo{Path: `C:\Users\ana\AppData\Local\Discord\Update.exe`, Exists: true, Signature: "valid", Signer: "Discord Inc."}
	rep := &model.Report{
		CollectedAt: time.Now(),
		Autoruns: []model.Autorun{
			{ID: "a", Category: "Logon", Name: "Discord", Command: discord.Path, ImagePath: discord.Path, File: discord},
			{ID: "b", Category: "Winlogon", Location: `HKLM\x`, Name: "Shell", Command: "explorer.exe", File: ms},
			{ID: "c", Category: "Active Setup", Name: "x", Command: "U", ImagePath: "U", File: &model.FileInfo{Path: "U"}},
		},
		Processes: []model.Process{{PID: 9, Name: "svchost.exe", ImagePath: ms.Path, File: ms}},
		Connections: []model.Connection{
			{Proto: "TCP", State: "ESTABLISHED", RemoteAddr: "8.8.8.8", RemotePort: 443, PID: 9},
		},
	}
	if fs := Evaluate(rep, Intel{}); len(fs) != 0 {
		t.Fatalf("esperava nenhum achado, obtido %+v", fs)
	}
}
