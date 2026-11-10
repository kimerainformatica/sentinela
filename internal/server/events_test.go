package server_test

import (
	"bufio"
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

// O painel deve receber, ao vivo, o que acontece quando um agente se
// cadastra, envia uma varredura e quando um comando é criado.
func TestLiveEventStream(t *testing.T) {
	s, pw, err := server.New(server.Config{Addr: ":0", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{s.TLSCertificate()}}
	ts.StartTLS()
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	post := func(path string, body any) int {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
		req.Header.Set("X-Sentinela", "1")
		resp, err := web.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if post("/api/login", map[string]string{"username": "admin", "password": pw}) != 200 {
		t.Fatal("login falhou")
	}

	// Sem sessão, o stream é recusado
	if resp, _ := http.DefaultClient.Do(mustReq(t, ts.URL+"/api/events/stream")); resp != nil && resp.StatusCode == 200 {
		t.Fatal("stream aceito sem sessão")
	}

	resp, err := web.Get(ts.URL + "/api/events/stream")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("abrir stream: %v %v", err, resp)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type %q", ct)
	}

	got := make(chan server.Event, 100)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var e server.Event
				json.Unmarshal([]byte(data), &e)
				got <- e
			}
		}
	}()

	// Agente: cadastro + evento próprio + relatório com Trojan
	cl, _ := agent.NewClient(ts.URL, s.Fingerprint)
	enr, err := cl.Enroll(s.EnrollToken, "PC-FARMACIA", "Windows 10 Pro")
	if err != nil {
		t.Fatal(err)
	}
	cl.SetCredentials(enr.AgentID, enr.Secret, enr.CommandPubKey)
	if err := cl.Event("scan_started", "Varredura agendada iniciada", nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.Event("tipo_inventado", "x", nil); err == nil {
		t.Fatal("tipo de evento fora da lista foi aceito")
	}
	evil := &model.FileInfo{Path: `C:\Users\Public\lsass.exe`, Exists: true, SHA256: strings.Repeat("b", 64), Signature: "unsigned"}
	data, _ := agent.GzipReport(&model.Report{
		Schema: model.SchemaVersion, CollectedAt: time.Now().UTC(), Trigger: "agendada",
		Host:     model.HostInfo{Hostname: "PC-FARMACIA"},
		Autoruns: []model.Autorun{{ID: "1111222233334444", Category: "Logon", Name: "x", Command: evil.Path, ImagePath: evil.Path, File: evil, Enabled: true}},
	})
	if err := cl.SendReportGz(data); err != nil {
		t.Fatal(err)
	}
	post("/api/agents/"+enr.AgentID+"/commands", map[string]any{"action": "rescan", "params": map[string]string{}})

	want := map[string]bool{"agent_enrolled": false, "scan_started": false, "scan_received": false,
		"finding_opened": false, "status_changed": false, "compromised": false, "command_created": false}
	deadline := time.After(5 * time.Second)
	for {
		done := true
		for _, ok := range want {
			done = done && ok
		}
		if done {
			break
		}
		select {
		case e := <-got:
			if _, ok := want[e.Kind]; ok {
				want[e.Kind] = true
				if e.ID == 0 || e.TS == 0 {
					t.Errorf("evento sem id/ts: %+v", e)
				}
				if e.Kind == "scan_received" && e.Hostname != "PC-FARMACIA" {
					t.Errorf("hostname não preenchido: %+v", e)
				}
			}
		case <-deadline:
			t.Fatalf("eventos não recebidos a tempo: %v", want)
		}
	}

	// Histórico via REST
	req := mustReq(t, ts.URL+"/api/events?agent="+enr.AgentID+"&limit=50")
	r2, err := web.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var hist []server.Event
	json.NewDecoder(r2.Body).Decode(&hist)
	r2.Body.Close()
	if len(hist) < 5 || hist[0].ID < hist[len(hist)-1].ID {
		t.Fatalf("histórico inesperado: %d eventos", len(hist))
	}
}

func mustReq(t *testing.T, url string) *http.Request {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
