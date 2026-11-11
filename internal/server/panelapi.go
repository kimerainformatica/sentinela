package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/model"
)

func (s *Server) panelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(csrfHeader) != "1" {
			writeErr(w, http.StatusForbidden, "cabeçalho de proteção ausente")
			return
		}
		s.handleLogin(w, r)
	})
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	h := func(pattern string, fn http.HandlerFunc) { mux.Handle(pattern, s.panelAuth(fn)) }
	h("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"username": "admin"})
	})
	h("GET /api/overview", s.handleOverview)
	h("GET /api/agents", s.handleAgents)
	h("GET /api/agents/{id}", s.handleAgent)
	h("DELETE /api/agents/{id}", s.handleDeleteAgent)
	h("GET /api/agents/{id}/snapshot", s.handleSnapshot)
	h("GET /api/agents/{id}/executions", s.handleExecutions)
	h("GET /api/agents/{id}/net-events", s.handleNetEvents)
	h("GET /api/agents/{id}/blocks", s.handleBlocks)
	h("GET /api/agents/{id}/commands", s.handleListCommands)
	h("POST /api/agents/{id}/commands", s.handleCreateCommand)
	h("POST /api/agents/{id}/clear-compromise", s.handleClearCompromise)
	h("GET /api/findings", s.handleFindings)
	h("POST /api/findings/{id}/status", s.handleFindingStatus)
	h("GET /api/settings", s.handleSettings)
	h("POST /api/settings/rotate-token", s.handleRotateToken)
	h("POST /api/settings/password", s.handleChangePassword)
	h("GET /api/audit", s.handleAudit)
	h("GET /api/events", s.handleEvents)
	h("GET /api/events/stream", s.handleEventStream)
}

// ---------------------------------------------------------------------------
// Endpoints (agentes)

type agentView struct {
	ID              string `json:"id"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	AgentVersion    string `json:"agent_version"`
	EnrolledAt      int64  `json:"enrolled_at"`
	LastSeen        int64  `json:"last_seen"`
	LastReportAt    int64  `json:"last_report_at"`
	RemoteIP        string `json:"remote_ip"`
	CompromisedAt   int64  `json:"compromised_at"`
	Online          bool   `json:"online"`
	OpenFindings    int    `json:"open_findings"`
	MaxSeverity     string `json:"max_severity"`
	Status          string `json:"status"`
	PendingCommands int    `json:"pending_commands"`
}

func (s *Server) loadAgents(where string, args ...any) ([]agentView, error) {
	rows, err := s.db.Query(`SELECT id,hostname,os,agent_version,enrolled_at,last_seen,last_report_at,remote_ip,compromised_at,
		(SELECT count(*) FROM commands c WHERE c.agent_id=agents.id AND c.status IN ('pendente','enviado'))
		FROM agents `+where+` ORDER BY hostname`, args...)
	if err != nil {
		return nil, err
	}
	var out []agentView
	for rows.Next() {
		var a agentView
		rows.Scan(&a.ID, &a.Hostname, &a.OS, &a.AgentVersion, &a.EnrolledAt, &a.LastSeen, &a.LastReportAt, &a.RemoteIP, &a.CompromisedAt, &a.PendingCommands)
		out = append(out, a)
	}
	rows.Close()
	for i := range out {
		a := &out[i]
		// O agente consulta comandos a cada 30s.
		a.Online = now()-a.LastSeen < 120
		a.OpenFindings, a.MaxSeverity = s.db.MaxOpenSeverity(a.ID)
		a.Status = HostStatus(a.MaxSeverity)
		if a.LastReportAt == 0 {
			a.Status = "sem_dados"
		}
	}
	return out, nil
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.loadAgents("")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if agents == nil {
		agents = []agentView{}
	}
	writeJSON(w, 200, agents)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	agents, err := s.loadAgents("")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ov := map[string]any{"agents": len(agents)}
	status := map[string]int{}
	online := 0
	for _, a := range agents {
		status[a.Status]++
		if a.Online {
			online++
		}
	}
	ov["online"] = online
	ov["status"] = status

	sev := map[string]int{}
	rows, _ := s.db.Query(`SELECT severity, count(*) FROM findings WHERE status='aberto' GROUP BY severity`)
	for rows != nil && rows.Next() {
		var k string
		var n int
		rows.Scan(&k, &n)
		sev[k] = n
	}
	if rows != nil {
		rows.Close()
	}
	ov["findings_by_severity"] = sev

	var pending, checked int
	s.db.QueryRow(`SELECT count(*) FROM hash_rep WHERE status='pending'`).Scan(&pending)
	s.db.QueryRow(`SELECT count(*) FROM hash_rep WHERE status IN ('known','unknown')`).Scan(&checked)
	ov["intel"] = map[string]any{
		"vt_enabled": s.intel.VTKey != "", "abuseipdb_enabled": s.intel.AbuseIPDBKey != "",
		"hashes_pending": pending, "hashes_checked": checked,
	}
	writeJSON(w, 200, ov)
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	agents, err := s.loadAgents("WHERE id=?", r.PathValue("id"))
	if err != nil || len(agents) == 0 {
		writeErr(w, 404, "endpoint não encontrado")
		return
	}
	type scan struct {
		ReceivedAt   int64  `json:"received_at"`
		Trigger      string `json:"trigger"`
		Autoruns     int    `json:"autoruns"`
		Processes    int    `json:"processes"`
		Connections  int    `json:"connections"`
		DurationMS   int64  `json:"duration_ms"`
		OpenFindings int    `json:"open_findings"`
		MaxSeverity  string `json:"max_severity"`
	}
	scans := []scan{}
	rows, err := s.db.Query(`SELECT received_at,trigger,autoruns,processes,connections,duration_ms,open_findings,coalesce(max_severity,'')
		FROM scans WHERE agent_id=? ORDER BY received_at DESC LIMIT 20`, agents[0].ID)
	if err == nil {
		for rows.Next() {
			var sc scan
			rows.Scan(&sc.ReceivedAt, &sc.Trigger, &sc.Autoruns, &sc.Processes, &sc.Connections, &sc.DurationMS, &sc.OpenFindings, &sc.MaxSeverity)
			scans = append(scans, sc)
		}
		rows.Close()
	}
	writeJSON(w, 200, map[string]any{"agent": agents[0], "scans": scans})
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := s.db.Exec(`DELETE FROM agents WHERE id=?`, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 404, "endpoint não encontrado")
		return
	}
	s.db.Audit(actor(r), "agente_removido", id, "")
	w.WriteHeader(204)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rep, err := s.db.Snapshot(id)
	if err != nil {
		writeErr(w, 404, "nenhuma varredura recebida deste endpoint ainda")
		return
	}
	intel, _ := s.db.LoadIntel()
	hashes := map[string]HashRep{}
	addHash := func(f *model.FileInfo) {
		if f != nil && f.SHA256 != "" {
			if h, ok := intel.Hashes[f.SHA256]; ok {
				hashes[f.SHA256] = h
			}
		}
	}
	for _, a := range rep.Autoruns {
		addHash(a.File)
		addHash(a.Payload)
	}
	for _, p := range rep.Processes {
		addHash(p.File)
	}
	ips := map[string]IPRep{}
	for _, c := range rep.Connections {
		if ipr, ok := intel.IPs[c.RemoteAddr]; ok {
			ips[c.RemoteAddr] = ipr
		}
	}
	writeJSON(w, 200, map[string]any{
		"report": rep, "hashes": hashes, "ips": ips,
		"intel": map[string]bool{"vt": s.intel.VTKey != "", "abuseipdb": s.intel.AbuseIPDBKey != ""},
	})
}

func (s *Server) handleClearCompromise(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.db.Exec(`UPDATE agents SET compromised_at=0 WHERE id=?`, id)
	s.db.Audit(actor(r), "reinstalacao_confirmada", id, "recomendação de formatação encerrada pelo analista")
	s.emitf(CatAgent, "reinstall_confirmed", LvlOK, id, "%s confirmou a reinstalação limpa da máquina", actor(r))
	w.WriteHeader(204)
}

// ---------------------------------------------------------------------------
// Achados

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := `SELECT f.id,f.agent_id,a.hostname,f.rule_id,f.severity,f.title,f.detail,f.technique,f.object_type,f.object_ref,
		f.path,f.sha256,f.status,f.first_seen,f.last_seen,f.resolved_at
		FROM findings f JOIN agents a ON a.id=f.agent_id WHERE 1=1`
	var args []any
	if st := r.URL.Query().Get("status"); st != "" && st != "todos" {
		q += ` AND f.status=?`
		args = append(args, st)
	}
	if ag := r.URL.Query().Get("agent"); ag != "" {
		q += ` AND f.agent_id=?`
		args = append(args, ag)
	}
	q += ` ORDER BY CASE f.severity WHEN 'critica' THEN 0 WHEN 'alta' THEN 1 WHEN 'media' THEN 2 ELSE 3 END, f.last_seen DESC LIMIT 1000`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type fv struct {
		ID         int64  `json:"id"`
		AgentID    string `json:"agent_id"`
		Hostname   string `json:"hostname"`
		RuleID     string `json:"rule_id"`
		Severity   string `json:"severity"`
		Title      string `json:"title"`
		Detail     string `json:"detail"`
		Technique  string `json:"technique"`
		ObjectType string `json:"object_type"`
		ObjectRef  string `json:"object_ref"`
		Path       string `json:"path"`
		SHA256     string `json:"sha256"`
		Status     string `json:"status"`
		FirstSeen  int64  `json:"first_seen"`
		LastSeen   int64  `json:"last_seen"`
		ResolvedAt int64  `json:"resolved_at"`
	}
	out := []fv{}
	for rows.Next() {
		var f fv
		rows.Scan(&f.ID, &f.AgentID, &f.Hostname, &f.RuleID, &f.Severity, &f.Title, &f.Detail, &f.Technique, &f.ObjectType,
			&f.ObjectRef, &f.Path, &f.SHA256, &f.Status, &f.FirstSeen, &f.LastSeen, &f.ResolvedAt)
		out = append(out, f)
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := readJSON(r, &req, 1<<10); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Status != "aberto" && req.Status != "falso_positivo" && req.Status != "resolvido" {
		writeErr(w, 400, "status inválido")
		return
	}
	id := r.PathValue("id")
	var agent, title string
	if err := s.db.QueryRow(`SELECT agent_id,title FROM findings WHERE id=?`, id).Scan(&agent, &title); err != nil {
		writeErr(w, 404, "achado não encontrado")
		return
	}
	s.db.Exec(`UPDATE findings SET status=?, resolved_at=? WHERE id=?`, req.Status, now(), id)
	s.db.Audit(actor(r), "achado_"+req.Status, agent, title)
	switch req.Status {
	case "falso_positivo":
		s.emitf(CatFinding, "finding_false_positive", LvlInfo, agent, "%s marcou como falso positivo: %s", actor(r), title)
	case "resolvido":
		s.emitf(CatFinding, "finding_resolved", LvlOK, agent, "%s marcou como resolvido: %s", actor(r), title)
	default:
		s.emitf(CatFinding, "finding_reopened", LvlWarn, agent, "%s reabriu o achado: %s", actor(r), title)
	}
	w.WriteHeader(204)
}

// ---------------------------------------------------------------------------
// Comandos de remediação

var (
	hex16Re = regexp.MustCompile(`^[0-9a-f]{16}$`)
	hex64Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	digitRe = regexp.MustCompile(`^[0-9]{1,10}$`)
	absWinRe = regexp.MustCompile(`^(?i)[a-z]:\\`)
)

// validateCommand aplica a allowlist de ações e valida os parâmetros.
func validateCommand(action string, p map[string]string) error {
	need := func(k string, re *regexp.Regexp) error {
		if !re.MatchString(p[k]) {
			return fmt.Errorf("parâmetro %q inválido", k)
		}
		return nil
	}
	var allowed []string
	var err error
	switch action {
	case model.ActionRescan:
	case model.ActionKillProcess:
		allowed = []string{"pid", "image_path"}
		if err = need("pid", digitRe); err == nil {
			err = need("image_path", absWinRe)
		}
	case model.ActionDisableAutorun:
		allowed = []string{"autorun_id"}
		err = need("autorun_id", hex16Re)
	case model.ActionRestoreAutorun:
		allowed = []string{"backup_id"}
		err = need("backup_id", hex16Re)
	case model.ActionQuarantineFile:
		allowed = []string{"path", "sha256"}
		if err = need("path", absWinRe); err == nil {
			err = need("sha256", hex64Re)
		}
	case model.ActionRestoreFile:
		allowed = []string{"quarantine_id"}
		err = need("quarantine_id", hex16Re)
	case model.ActionBlockIP:
		allowed = []string{"ip", "minutes", "reason"}
		if net.ParseIP(p["ip"]) == nil {
			err = fmt.Errorf("parâmetro %q inválido", "ip")
		} else if p["minutes"] != "" && !digitRe.MatchString(p["minutes"]) {
			err = fmt.Errorf("parâmetro %q inválido", "minutes")
		}
	case model.ActionUnblockIP:
		allowed = []string{"ip"}
		if net.ParseIP(p["ip"]) == nil {
			err = fmt.Errorf("parâmetro %q inválido", "ip")
		}
	case model.ActionSetProtection:
		allowed = []string{"enabled"}
		if p["enabled"] != "0" && p["enabled"] != "1" {
			err = fmt.Errorf("parâmetro %q inválido", "enabled")
		}
	default:
		return fmt.Errorf("ação não permitida: %q", action)
	}
	if err != nil {
		return err
	}
	for k := range p {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			return fmt.Errorf("parâmetro inesperado: %q", k)
		}
	}
	return nil
}

func (s *Server) signCommand(agentID, action string, params map[string]string) (model.Command, model.CommandPayload) {
	p := model.CommandPayload{
		ID: randomHex(8), AgentID: agentID, Action: action, Params: params,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
	}
	payload, _ := json.Marshal(p)
	sig := ed25519.Sign(s.signKey, payload)
	return model.Command{ID: p.ID, Payload: string(payload), Signature: base64.StdEncoding.EncodeToString(sig)}, p
}

func (s *Server) handleCreateCommand(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	var req struct {
		Action string            `json:"action"`
		Params map[string]string `json:"params"`
	}
	if err := readJSON(r, &req, 8<<10); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Params == nil {
		req.Params = map[string]string{}
	}
	if err := validateCommand(req.Action, req.Params); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var exists int
	s.db.QueryRow(`SELECT count(*) FROM agents WHERE id=?`, agentID).Scan(&exists)
	if exists == 0 {
		writeErr(w, 404, "endpoint não encontrado")
		return
	}
	cmd, p := s.signCommand(agentID, req.Action, req.Params)
	params, _ := json.Marshal(req.Params)
	_, err := s.db.Exec(`INSERT INTO commands(id,agent_id,action,params,payload,signature,status,created_at,created_by,expires_at)
		VALUES(?,?,?,?,?,?,'pendente',?,?,?)`, cmd.ID, agentID, req.Action, string(params), cmd.Payload, cmd.Signature,
		now(), actor(r), p.ExpiresAt.Unix())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.db.Audit(actor(r), "comando_"+req.Action, agentID, string(params))
	target := req.Params["path"]
	if target == "" {
		target = req.Params["image_path"]
	}
	if target != "" {
		target = " → " + target
	}
	s.emit(Event{Category: CatCommand, Kind: "command_created", Level: LvlInfo, AgentID: agentID,
		Message: fmt.Sprintf("%s enviou: %s%s (aguardando o agente buscar)", actor(r), actionText(req.Action), target),
		Data:    map[string]any{"command_id": cmd.ID, "action": req.Action, "params": req.Params}})
	writeJSON(w, 201, map[string]string{"id": cmd.ID})
}

func (s *Server) handleListCommands(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT id,action,params,status,created_at,created_by,delivered_at,finished_at,result,undo_id
		FROM commands WHERE agent_id=? ORDER BY created_at DESC LIMIT 100`, r.PathValue("id"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type cv struct {
		ID          string            `json:"id"`
		Action      string            `json:"action"`
		Params      map[string]string `json:"params"`
		Status      string            `json:"status"`
		CreatedAt   int64             `json:"created_at"`
		CreatedBy   string            `json:"created_by"`
		DeliveredAt int64             `json:"delivered_at"`
		FinishedAt  int64             `json:"finished_at"`
		Result      string            `json:"result"`
		UndoID      string            `json:"undo_id"`
	}
	out := []cv{}
	for rows.Next() {
		var c cv
		var params string
		rows.Scan(&c.ID, &c.Action, &params, &c.Status, &c.CreatedAt, &c.CreatedBy, &c.DeliveredAt, &c.FinishedAt, &c.Result, &c.UndoID)
		json.Unmarshal([]byte(params), &c.Params)
		out = append(out, c)
	}
	writeJSON(w, 200, out)
}

// ---------------------------------------------------------------------------
// Configurações e auditoria

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	_, port, _ := net.SplitHostPort(s.cfg.Addr)
	if port == "" {
		port = strings.TrimPrefix(s.cfg.Addr, ":")
	}
	var urls []string
	for _, ip := range localIPs() {
		if strings.Contains(ip, ":") {
			continue
		}
		urls = append(urls, "https://"+ip+":"+port)
	}
	writeJSON(w, 200, map[string]any{
		"enroll_token":      s.EnrollToken,
		"fingerprint":       FormatFingerprint(s.Fingerprint),
		"fingerprint_hex":   s.Fingerprint,
		"server_urls":       urls,
		"vt_enabled":        s.intel.VTKey != "",
		"abuseipdb_enabled": s.intel.AbuseIPDBKey != "",
	})
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	tok := s.RotateEnrollToken()
	s.db.Audit(actor(r), "token_rotacionado", "", "")
	writeJSON(w, 200, map[string]string{"enroll_token": tok})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := readJSON(r, &req, 4<<10); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	stored, _ := s.db.Setting("admin_password")
	if !checkPassword(req.Current, stored) {
		writeErr(w, 403, "senha atual incorreta")
		return
	}
	if len(req.New) < 12 {
		writeErr(w, 400, "a nova senha precisa ter pelo menos 12 caracteres")
		return
	}
	s.db.SetSetting("admin_password", hashPassword(req.New))
	s.db.Audit(actor(r), "senha_alterada", "", "")
	w.WriteHeader(204)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	rows, err := s.db.Query(`SELECT a.ts,a.actor,a.action,a.agent_id,coalesce(g.hostname,''),a.detail
		FROM audit a LEFT JOIN agents g ON g.id=a.agent_id ORDER BY a.id DESC LIMIT ?`, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type av struct {
		TS       int64  `json:"ts"`
		Actor    string `json:"actor"`
		Action   string `json:"action"`
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
		Detail   string `json:"detail"`
	}
	out := []av{}
	for rows.Next() {
		var a av
		rows.Scan(&a.TS, &a.Actor, &a.Action, &a.AgentID, &a.Hostname, &a.Detail)
		out = append(out, a)
	}
	writeJSON(w, 200, out)
}
