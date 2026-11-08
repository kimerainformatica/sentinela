package server_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinela/internal/agent"
	"sentinela/internal/model"
	"sentinela/internal/server"
)

// Fluxo completo: cadastro do agente -> relatório com Trojan -> achados ->
// comando assinado -> verificação no agente -> resultado -> verificação
// posterior limpa resolve os achados.
func TestEndToEnd(t *testing.T) {
	s, pw, err := server.New(server.Config{Addr: ":0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{s.TLSCertificate()}}
	ts.StartTLS()
	defer ts.Close()

	// --- Agente com fingerprint errado deve recusar a conexão (pinning)
	bad, _ := agent.NewClient(ts.URL, strings.Repeat("0", 64))
	if _, err := bad.Enroll(s.EnrollToken, "x", "y"); err == nil {
		t.Fatal("esperava falha de pinning")
	}

	cl, err := agent.NewClient(ts.URL, s.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Enroll("token-errado", "PC-01", "Windows 11"); err == nil {
		t.Fatal("esperava recusa com token inválido")
	}
	enr, err := cl.Enroll(s.EnrollToken, "PC-RECEPCAO", "Windows 11 Pro")
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.SetCredentials(enr.AgentID, enr.Secret, enr.CommandPubKey); err != nil {
		t.Fatal(err)
	}

	// --- Relatório com persistência maliciosa
	evil := &model.FileInfo{Path: `C:\Users\Public\svchost.exe`, Exists: true, SHA256: strings.Repeat("a", 64), Signature: "unsigned"}
	rep := &model.Report{
		Schema: model.SchemaVersion, CollectedAt: time.Now().UTC(), Trigger: "inicial",
		Host: model.HostInfo{Hostname: "PC-RECEPCAO", OS: "Windows 11 Pro", AgentVer: "test"},
		Autoruns: []model.Autorun{{ID: "0123456789abcdef", Category: "Logon", Name: "svc", Command: evil.Path, ImagePath: evil.Path, File: evil, Enabled: true}},
	}
	data, _ := agent.GzipReport(rep)
	if err := cl.SendReportGz(data); err != nil {
		t.Fatal(err)
	}

	// --- Painel: login
	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	call := func(method, path string, body any, out any) int {
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
	if code := call("POST", "/api/login", map[string]string{"username": "admin", "password": "errada"}, nil); code != 401 {
		t.Fatalf("login com senha errada: %d", code)
	}
	if code := call("POST", "/api/login", map[string]string{"username": "admin", "password": pw}, nil); code != 200 {
		t.Fatalf("login: %d", code)
	}

	var findings []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Status   string `json:"status"`
	}
	call("GET", "/api/findings?status=aberto", nil, &findings)
	rules := map[string]string{}
	for _, f := range findings {
		rules[f.RuleID] = f.Severity
	}
	if rules["R02"] != "alta" || rules["R05"] != "critica" {
		t.Fatalf("achados inesperados: %+v", findings)
	}

	// --- Comando inválido é recusado pela allowlist
	if code := call("POST", "/api/agents/"+enr.AgentID+"/commands", map[string]any{"action": "format_c", "params": map[string]string{}}, nil); code != 400 {
		t.Fatalf("ação fora da allowlist aceita: %d", code)
	}
	// --- Sem cabeçalho CSRF é recusado
	req, _ := http.NewRequest("POST", ts.URL+"/api/agents/"+enr.AgentID+"/commands", strings.NewReader(`{"action":"rescan"}`))
	if resp, _ := web.Do(req); resp.StatusCode != 403 {
		t.Fatalf("requisição sem X-Sentinela aceita: %d", resp.StatusCode)
	}

	// --- Comando de remediação assinado
	if code := call("POST", "/api/agents/"+enr.AgentID+"/commands", map[string]any{
		"action": "disable_autorun", "params": map[string]string{"autorun_id": "0123456789abcdef"},
	}, nil); code != 201 {
		t.Fatalf("criar comando: %d", code)
	}
	cmds, err := cl.PollCommands()
	if err != nil || len(cmds) != 1 {
		t.Fatalf("poll: %v %d", err, len(cmds))
	}
	p, err := cl.Verify(cmds[0])
	if err != nil {
		t.Fatalf("assinatura do comando rejeitada: %v", err)
	}
	if p.Action != model.ActionDisableAutorun {
		t.Fatalf("ação: %s", p.Action)
	}
	// Payload adulterado deve ser rejeitado
	tampered := cmds[0]
	tampered.Payload = strings.Replace(tampered.Payload, "disable_autorun", "kill_process", 1)
	if _, err := cl.Verify(tampered); err == nil {
		t.Fatal("payload adulterado foi aceito")
	}
	if err := cl.SendResult(p.ID, model.CommandResult{OK: true, Message: "ok", UndoID: "fedcba9876543210"}); err != nil {
		t.Fatal(err)
	}

	// --- Verificação posterior: relatório limpo resolve os achados
	rep.Autoruns = nil
	rep.Trigger = "pos-remediacao"
	data, _ = agent.GzipReport(rep)
	if err := cl.SendReportGz(data); err != nil {
		t.Fatal(err)
	}
	findings = nil
	call("GET", "/api/findings?status=aberto", nil, &findings)
	if len(findings) != 0 {
		t.Fatalf("achados ainda abertos após remediação: %+v", findings)
	}

	// O host continua marcado como comprometido (recomendação de formatação)
	var detail struct {
		Agent struct {
			CompromisedAt int64  `json:"compromised_at"`
			Status        string `json:"status"`
		} `json:"agent"`
	}
	call("GET", "/api/agents/"+enr.AgentID, nil, &detail)
	if detail.Agent.CompromisedAt == 0 || detail.Agent.Status != "ok" {
		t.Fatalf("estado do agente inesperado: %+v", detail.Agent)
	}
}
