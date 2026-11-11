package server

import (
	"strings"
	"testing"
	"time"

	"sentinela/internal/model"
)

func TestIncidentFinding(t *testing.T) {
	out := incidentFinding(&model.IncidentReport{
		Action: "kill", Mitigated: true, KilledPID: 1234, Outcome: "processo 1234 (bot.exe) finalizado",
		Incident: model.FloodIncident{Time: time.Now(), Direction: "saida", Reason: "alvo", PID: 1234,
			Image: `C:\Users\ana\AppData\Roaming\bot.exe`, WindowS: 10, Count: 900, Distinct: 1, Target: "203.0.113.5"},
	})
	if out.RuleID != "R25" || out.Severity != SevCritica {
		t.Fatalf("saída: %+v", out)
	}
	if !strings.HasPrefix(out.Key, RealtimePrefix) || !strings.Contains(out.Detail, "finalizado") || !strings.Contains(out.Detail, "203.0.113.5") {
		t.Fatalf("detalhe/chave da saída: %q / %q", out.Detail, out.Key)
	}

	in := incidentFinding(&model.IncidentReport{
		Action: "block", Mitigated: true, BlockedIPs: []string{"45.0.0.1", "45.0.0.2"},
		Incident: model.FloodIncident{Time: time.Now(), Direction: "entrada", Reason: "entrada",
			WindowS: 10, Count: 500, Distinct: 4, LocalPort: 443},
	})
	if in.RuleID != "R26" || in.Severity != SevAlta {
		t.Fatalf("entrada: %+v", in)
	}
	if !strings.Contains(in.Detail, "porta 443") || !strings.Contains(in.Detail, "45.0.0.1") {
		t.Fatalf("detalhe da entrada: %q", in.Detail)
	}
}

func TestValidateDDoSCommands(t *testing.T) {
	ok := []struct {
		action string
		params map[string]string
	}{
		{model.ActionBlockIP, map[string]string{"ip": "203.0.113.5"}},
		{model.ActionBlockIP, map[string]string{"ip": "203.0.113.5", "minutes": "30", "reason": "DDoS"}},
		{model.ActionUnblockIP, map[string]string{"ip": "2001:db8::1"}},
		{model.ActionSetProtection, map[string]string{"enabled": "0"}},
		{model.ActionSetProtection, map[string]string{"enabled": "1"}},
	}
	for _, c := range ok {
		if err := validateCommand(c.action, c.params); err != nil {
			t.Errorf("%s %v: inesperado %v", c.action, c.params, err)
		}
	}
	bad := []struct {
		action string
		params map[string]string
	}{
		{model.ActionBlockIP, map[string]string{"ip": "não-é-ip"}},
		{model.ActionBlockIP, map[string]string{"ip": "203.0.113.5; rm -rf"}},
		{model.ActionBlockIP, map[string]string{"ip": "203.0.113.5", "minutes": "abc"}},
		{model.ActionBlockIP, map[string]string{"ip": "203.0.113.5", "porta": "80"}}, // parâmetro inesperado
		{model.ActionUnblockIP, map[string]string{"ip": ""}},
		{model.ActionSetProtection, map[string]string{"enabled": "talvez"}},
	}
	for _, c := range bad {
		if err := validateCommand(c.action, c.params); err == nil {
			t.Errorf("%s %v: deveria ter sido recusado", c.action, c.params)
		}
	}
}
