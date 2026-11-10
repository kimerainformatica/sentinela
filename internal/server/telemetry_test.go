package server_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"sentinela/internal/agent"
	"sentinela/internal/model"
	"sentinela/internal/server"
)

func TestRealtimeExecutions(t *testing.T) {
	s, pw, err := server.New(server.Config{Addr: ":0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{s.TLSCertificate()}}
	ts.StartTLS()
	defer ts.Close()

	cl, _ := agent.NewClient(ts.URL, s.Fingerprint)
	enr, err := cl.Enroll(s.EnrollToken, "PC-RECEPCAO", "Windows 11")
	if err != nil {
		t.Fatal(err)
	}
	cl.SetCredentials(enr.AgentID, enr.Secret, enr.CommandPubKey)

	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	call := func(method, path string, body, out any) int {
		var b bytes.Buffer
		if body != nil {
			json.NewEncoder(&b).Encode(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, &b)
		req.Header.Set("X-Sentinela", "1")
		resp, err := web.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	call("POST", "/api/login", map[string]string{"username": "admin", "password": pw}, nil)

	// Anexo malicioso: Word abre PowerShell oculto que dura meio segundo.
	ps := &model.FileInfo{Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Exists: true, Signature: "valid", Signer: "Microsoft Windows"}
	now := time.Now().UTC()
	batch := &model.TelemetryBatch{Processes: []model.ProcessEvent{
		{Time: now, PID: 4321, PPID: 1234, Name: "powershell.exe", ImagePath: ps.Path, File: ps, Source: "etw",
			CommandLine: "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=",
			ParentName: "WINWORD.EXE", ParentImage: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`},
		{Time: now, PID: 50, PPID: 4, Name: "notepad.exe", ImagePath: `C:\Windows\System32\notepad.exe`, Source: "etw",
			File: &model.FileInfo{Path: `C:\Windows\System32\notepad.exe`, Exists: true, Signature: "valid", Signer: "Microsoft Windows"}},
	}}
	if err := cl.SendTelemetry(batch); err != nil {
		t.Fatal(err)
	}

	openRules := func() map[string]string {
		var fs []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
		}
		call("GET", "/api/findings?status=aberto&agent="+enr.AgentID, nil, &fs)
		m := map[string]string{}
		for _, f := range fs {
			m[f.RuleID] = f.Severity
		}
		return m
	}
	if got := openRules(); got["R14"] != "alta" || got["R15"] != "alta" || len(got) != 2 {
		t.Fatalf("achados em tempo real inesperados: %v", got)
	}

	// Uma varredura limpa depois NÃO pode resolver achados de tempo real.
	data, _ := agent.GzipReport(&model.Report{Schema: model.SchemaVersion, CollectedAt: time.Now(), Trigger: "agendada",
		Host: model.HostInfo{Hostname: "PC-RECEPCAO"}})
	if err := cl.SendReportGz(data); err != nil {
		t.Fatal(err)
	}
	if got := openRules(); len(got) != 2 {
		t.Fatalf("varredura resolveu achados de tempo real: %v", got)
	}

	var execs []struct {
		Name       string `json:"name"`
		ParentName string `json:"parent_name"`
		Source     string `json:"source"`
	}
	call("GET", "/api/agents/"+enr.AgentID+"/executions", nil, &execs)
	if len(execs) != 2 || execs[1].ParentName != "WINWORD.EXE" || execs[0].Source != "etw" {
		t.Fatalf("execuções: %+v", execs)
	}

	// Lote acima do limite é recusado
	big := &model.TelemetryBatch{Processes: make([]model.ProcessEvent, 1001)}
	if err := cl.SendTelemetry(big); err == nil {
		t.Fatal("lote gigante aceito")
	}
}

func TestRealtimeConnections(t *testing.T) {
	s, pw, err := server.New(server.Config{Addr: ":0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{s.TLSCertificate()}}
	ts.StartTLS()
	defer ts.Close()

	cl, _ := agent.NewClient(ts.URL, s.Fingerprint)
	enr, err := cl.Enroll(s.EnrollToken, "PC-CAIXA", "Windows 10")
	if err != nil {
		t.Fatal(err)
	}
	cl.SetCredentials(enr.AgentID, enr.Secret, enr.CommandPubKey)

	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	get := func(path string, out any) {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		resp, err := web.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		json.NewDecoder(resp.Body).Decode(out)
	}
	b, _ := json.Marshal(map[string]string{"username": "admin", "password": pw})
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(b))
	req.Header.Set("X-Sentinela", "1")
	if resp, err := web.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatal("login falhou")
	}

	ps := &model.FileInfo{Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Exists: true, Signature: "valid", Signer: "Microsoft Windows"}
	now := time.Now().UTC()
	err = cl.SendTelemetry(&model.TelemetryBatch{Connections: []model.NetEvent{
		{Time: now, PID: 900, ProcessName: "powershell.exe", ImagePath: ps.Path, File: ps, Direction: "saida", Proto: "TCP",
			LocalAddr: "192.168.0.20", LocalPort: 50111, RemoteAddr: "93.184.216.34", RemotePort: 443, Source: "etw"},
		{Time: now, PID: 901, ProcessName: "chrome.exe", Direction: "saida", Proto: "TCP",
			LocalAddr: "192.168.0.20", LocalPort: 50112, RemoteAddr: "142.250.1.1", RemotePort: 443, Source: "etw", Repeats: 12},
	}})
	if err != nil {
		t.Fatal(err)
	}

	var fs []struct {
		RuleID string `json:"rule_id"`
	}
	get("/api/findings?status=aberto&agent="+enr.AgentID, &fs)
	if len(fs) != 1 || fs[0].RuleID != "R19" {
		t.Fatalf("achados: %+v", fs)
	}
	var conns []struct {
		Process string `json:"process"`
		Public  bool   `json:"public"`
		Repeats int    `json:"repeats"`
	}
	get("/api/agents/"+enr.AgentID+"/net-events", &conns)
	if len(conns) != 2 || !conns[0].Public || conns[0].Repeats != 12 || conns[1].Process != "powershell.exe" {
		t.Fatalf("conexões: %+v", conns)
	}
}
