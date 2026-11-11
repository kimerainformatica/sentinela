package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"sentinela/internal/model"
)

// Recebe os incidentes de DDoS detectados pelo agente, transforma em achados
// (para a máquina aparecer na lista de alertas, e marcada como comprometida
// quando ela mesma está atacando) e registra os bloqueios de firewall.

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	id := agentID(r)
	var rep model.IncidentReport
	if err := readJSON(r, &rep, 64<<10); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	inc := rep.Incident
	f := incidentFinding(&rep)

	s.evalMu.Lock()
	res, err := s.db.UpsertRealtimeFindings(id, []Finding{f})
	s.evalMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erro ao registrar achado")
		return
	}

	// Bloqueios feitos automaticamente também viram registro.
	for _, ip := range rep.BlockedIPs {
		s.upsertBlock(id, ip, incidentReason(&inc), time.Now().Add(time.Hour))
	}

	lvl := LvlCrit
	if inc.Direction == "entrada" {
		lvl = LvlWarn
	}
	s.emit(Event{TS: inc.Time.UnixMilli(), Category: CatNetwork, Kind: "ddos", Level: lvl, AgentID: id,
		Message: incidentMessage(&rep), Data: map[string]any{
			"direction": inc.Direction, "reason": inc.Reason, "pid": inc.PID, "image": inc.Image,
			"count": inc.Count, "distinct": inc.Distinct, "target": inc.Target, "local_port": inc.LocalPort,
			"mitigated": rep.Mitigated, "action": rep.Action, "blocked_ips": rep.BlockedIPs}})
	s.emitSync(id, res, "ddos")
	s.db.Audit("agente", "ddos_"+inc.Direction, id, incidentMessage(&rep))
	w.WriteHeader(http.StatusNoContent)
}

func incidentReason(inc *model.FloodIncident) string {
	if inc.Direction == "entrada" {
		return fmt.Sprintf("DDoS na porta %d", inc.LocalPort)
	}
	return "DDoS de saída (" + inc.Reason + ")"
}

// incidentFinding monta o achado correspondente ao incidente.
func incidentFinding(rep *model.IncidentReport) Finding {
	inc := rep.Incident
	done := incidentOutcome(rep)
	if inc.Direction == "saida" {
		who := base(inc.Image)
		if who == "" {
			who = fmt.Sprintf("PID %d", inc.PID)
		}
		alvo := fmt.Sprintf("%d destinos", inc.Distinct)
		if inc.Reason == "alvo" && inc.Target != "" {
			alvo = inc.Target
		}
		return Finding{
			Key:      RealtimePrefix + "ddos|out|" + strings.ToLower(inc.Image) + "|" + inc.Target,
			RuleID:   "R25", Severity: SevCritica, Technique: "T1498.001",
			Title:  "DDoS de saída: a máquina está atacando (" + who + ")",
			Detail: fmt.Sprintf("%s abriu %d conexões em %.0f s para %s — avalanche típica de bot de botnet. %s",
				who, inc.Count, inc.WindowS, alvo, done),
			ObjectType: "connection", ObjectRef: "ddos-out|" + inc.Target, Path: inc.Image,
		}
	}
	return Finding{
		Key:      RealtimePrefix + "ddos|in|" + fmt.Sprint(inc.LocalPort),
		RuleID:   "R26", Severity: SevAlta, Technique: "T1499",
		Title:  fmt.Sprintf("DDoS de entrada: avalanche de conexões na porta %d", inc.LocalPort),
		Detail: fmt.Sprintf("%d conexões em %.0f s de %d origens na porta %d. %s",
			inc.Count, inc.WindowS, inc.Distinct, inc.LocalPort, done),
		ObjectType: "connection", ObjectRef: "ddos-in|" + fmt.Sprint(inc.LocalPort),
	}
}

func incidentOutcome(rep *model.IncidentReport) string {
	switch rep.Action {
	case "kill":
		return "Resposta automática: processo finalizado. " + rep.Outcome
	case "block":
		return fmt.Sprintf("Resposta automática: %d IP(s) bloqueado(s) no firewall (%s).", len(rep.BlockedIPs), strings.Join(rep.BlockedIPs, ", "))
	default:
		return "Ação: " + rep.Outcome
	}
}

func incidentMessage(rep *model.IncidentReport) string {
	inc := rep.Incident
	if inc.Direction == "saida" {
		return fmt.Sprintf("DDoS de SAÍDA detectado: %s (PID %d) — %s", base(inc.Image), inc.PID, incidentOutcome(rep))
	}
	return fmt.Sprintf("DDoS de ENTRADA detectado na porta %d — %s", inc.LocalPort, incidentOutcome(rep))
}

// ---------------------------------------------------------------------------
// Bloqueios de firewall

func (s *Server) upsertBlock(agentID, ip, reason string, expires time.Time) {
	s.db.Exec(`INSERT INTO ddos_blocks(agent_id,ip,created_at,expires_at,reason,removed_at)
		VALUES(?,?,?,?,?,0)
		ON CONFLICT(agent_id,ip) DO UPDATE SET created_at=excluded.created_at,
		  expires_at=excluded.expires_at, reason=excluded.reason, removed_at=0`,
		agentID, ip, now(), expires.Unix(), reason)
}

func (s *Server) removeBlock(agentID, ip string) {
	s.db.Exec(`UPDATE ddos_blocks SET removed_at=? WHERE agent_id=? AND ip=? AND removed_at=0`, now(), agentID, ip)
}

type blockView struct {
	IP      string `json:"ip"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	Reason  string `json:"reason"`
}

func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rows, err := s.db.Query(`SELECT ip,created_at,expires_at,reason FROM ddos_blocks
		WHERE agent_id=? AND removed_at=0 ORDER BY created_at DESC`, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erro")
		return
	}
	defer rows.Close()
	out := []blockView{}
	for rows.Next() {
		var b blockView
		rows.Scan(&b.IP, &b.Created, &b.Expires, &b.Reason)
		out = append(out, b)
	}
	writeJSON(w, http.StatusOK, out)
}
