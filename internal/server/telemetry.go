package server

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/model"
)

// Execuções de programas em tempo real: recebidas do agente em lotes,
// gravadas, avaliadas na hora e transmitidas para a tela Ao vivo.

const (
	CatProcess        = "processo"
	maxBatchProcesses = 1000
	maxStoredProcEvts = 100000
)

func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	id := agentID(r)
	var b model.TelemetryBatch
	if err := readJSON(r, &b, 16<<20); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(b.Processes) > maxBatchProcesses {
		writeErr(w, 413, "lote grande demais")
		return
	}
	if err := s.ingestExecutions(id, b.Processes); err != nil {
		log.Printf("telemetria %s: %v", id, err)
		writeErr(w, 500, "erro ao processar telemetria")
		return
	}
	if b.Dropped > 0 {
		s.emitf(CatProcess, "telemetry_dropped", LvlWarn, id, "%d execuções foram descartadas no agente por excesso de volume", b.Dropped)
	}
	w.WriteHeader(204)
}

func (s *Server) ingestExecutions(agentID string, evs []model.ProcessEvent) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := range evs {
		e := &evs[i]
		f := e.File
		if f == nil {
			f = &model.FileInfo{}
		}
		_, err := tx.Exec(`INSERT INTO proc_events(agent_id,ts,pid,ppid,name,image,cmdline,user,parent_name,parent_image,sha256,signature,signer,company,source,exited,restricted)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			agentID, e.Time.UnixMilli(), e.PID, e.PPID, truncate(e.Name, 260), truncate(e.ImagePath, 1024), truncate(e.CommandLine, 8192),
			truncate(e.User, 256), truncate(e.ParentName, 260), truncate(e.ParentImage, 1024),
			f.SHA256, f.Signature, truncate(f.Signer, 256), truncate(f.Company, 256), e.Source, e.Exited, e.Restricted)
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// Reputação dos executáveis (mesma fila das varreduras).
	rep := &model.Report{}
	for i := range evs {
		rep.Processes = append(rep.Processes, model.Process{PID: evs[i].PID, Name: evs[i].Name, ImagePath: evs[i].ImagePath, File: evs[i].File})
	}
	s.queueIntel(rep)

	// Evento ao vivo para cada execução
	for i := range evs {
		e := &evs[i]
		s.emit(executionEvent(agentID, e))
	}

	// Detecção imediata
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	intel, err := s.db.LoadIntel()
	if err != nil {
		return err
	}
	var fs []Finding
	for i := range evs {
		fs = append(fs, EvaluateExecution(&evs[i], intel)...)
	}
	if len(fs) == 0 {
		return nil
	}
	res, err := s.db.UpsertRealtimeFindings(agentID, fs)
	if err != nil {
		return err
	}
	s.emitSync(agentID, res, "tempo-real")
	return nil
}

func executionEvent(agentID string, e *model.ProcessEvent) Event {
	parent := e.ParentName
	if parent == "" {
		parent = fmt.Sprintf("PID %d", e.PPID)
	}
	what := e.CommandLine
	if what == "" {
		what = e.ImagePath
	}
	msg := fmt.Sprintf("%s (PID %d) iniciado por %s", e.Name, e.PID, parent)
	if what != "" {
		msg += " — " + truncate(what, 300)
	}
	switch {
	case e.Exited:
		msg += " [encerrou antes da análise]"
	case e.Restricted:
		msg += " [sem permissão para analisar: processo protegido ou agente sem administrador]"
	}
	data := map[string]any{"pid": e.PID, "ppid": e.PPID, "image": e.ImagePath, "parent": e.ParentImage,
		"user": e.User, "source": e.Source, "exited": e.Exited, "restricted": e.Restricted}
	ms := false
	if f := e.File; f != nil {
		data["signature"], data["signer"], data["sha256"] = f.Signature, f.Signer, f.SHA256
		ms = microsoft(f)
	}
	data["microsoft"] = ms
	return Event{TS: e.Time.UnixMilli(), Category: CatProcess, Kind: "process_started", Level: LvlInfo,
		AgentID: agentID, Message: msg, Data: data}
}

// UpsertRealtimeFindings grava achados de tempo real sem resolver nada.
func (d *DB) UpsertRealtimeFindings(agentID string, fs []Finding) (*SyncResult, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res := &SyncResult{}
	t := now()

	rows, err := tx.Query(`SELECT severity FROM findings WHERE agent_id=? AND status='aberto'`, agentID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		rows.Scan(&sev)
		if sevRank[sev] > sevRank[res.PrevMaxSev] {
			res.PrevMaxSev = sev
		}
	}
	rows.Close()

	for _, f := range fs {
		var st string
		tx.QueryRow(`SELECT status FROM findings WHERE agent_id=? AND fkey=?`, agentID, f.Key).Scan(&st)
		if st == "" || st == "resolvido" {
			res.Opened = append(res.Opened, f)
		}
		_, err := tx.Exec(`INSERT INTO findings(agent_id,fkey,rule_id,severity,title,detail,technique,object_type,object_ref,path,sha256,status,first_seen,last_seen)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,'aberto',?,?)
			ON CONFLICT(agent_id,fkey) DO UPDATE SET
			  severity=excluded.severity, title=excluded.title, detail=excluded.detail,
			  sha256=excluded.sha256, last_seen=excluded.last_seen,
			  status=CASE WHEN findings.status='falso_positivo' THEN 'falso_positivo' ELSE 'aberto' END,
			  resolved_at=CASE WHEN findings.status='falso_positivo' THEN findings.resolved_at ELSE 0 END`,
			agentID, f.Key, f.RuleID, f.Severity, f.Title, f.Detail, f.Technique, f.ObjectType, f.ObjectRef, f.Path, f.SHA256, t, t)
		if err != nil {
			return nil, err
		}
	}

	rows, err = tx.Query(`SELECT severity FROM findings WHERE agent_id=? AND status='aberto'`, agentID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		rows.Scan(&sev)
		res.Open++
		if sevRank[sev] > sevRank[res.MaxSev] {
			res.MaxSev = sev
		}
	}
	rows.Close()
	if res.MaxSev == SevCritica {
		r, err := tx.Exec(`UPDATE agents SET compromised_at=? WHERE id=? AND compromised_at=0`, t, agentID)
		if err != nil {
			return nil, err
		}
		n, _ := r.RowsAffected()
		res.NewCompromise = n > 0
	}
	return res, tx.Commit()
}

// reevaluateExecutions reaplica as regras às execuções das últimas 24 h
// cujo executável acabou de ser identificado como malicioso no VirusTotal.
func (s *Server) reevaluateExecutions() {
	rows, err := s.db.Query(`SELECT p.agent_id,p.ts,p.pid,p.ppid,p.name,p.image,p.cmdline,p.user,p.parent_name,p.parent_image,
		p.sha256,p.signature,p.signer,p.source
		FROM proc_events p JOIN hash_rep h ON h.sha256=p.sha256
		WHERE h.status='known' AND h.malicious>0 AND p.ts > ?
		GROUP BY p.agent_id, p.sha256`, time.Now().Add(-24*time.Hour).UnixMilli())
	if err != nil {
		return
	}
	type item struct {
		agent string
		ev    model.ProcessEvent
	}
	var items []item
	for rows.Next() {
		var it item
		var ts int64
		f := &model.FileInfo{Exists: true}
		rows.Scan(&it.agent, &ts, &it.ev.PID, &it.ev.PPID, &it.ev.Name, &it.ev.ImagePath, &it.ev.CommandLine, &it.ev.User,
			&it.ev.ParentName, &it.ev.ParentImage, &f.SHA256, &f.Signature, &f.Signer, &it.ev.Source)
		f.Path = it.ev.ImagePath
		it.ev.File, it.ev.Time = f, time.UnixMilli(ts)
		items = append(items, it)
	}
	rows.Close()
	if len(items) == 0 {
		return
	}
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	intel, err := s.db.LoadIntel()
	if err != nil {
		return
	}
	byAgent := map[string][]Finding{}
	for i := range items {
		byAgent[items[i].agent] = append(byAgent[items[i].agent], EvaluateExecution(&items[i].ev, intel)...)
	}
	for agent, fs := range byAgent {
		if res, err := s.db.UpsertRealtimeFindings(agent, fs); err == nil {
			s.emitSync(agent, res, "reputacao")
		}
	}
}

// GET /api/agents/{id}/executions?limit=300&q=texto
func (s *Server) handleExecutions(w http.ResponseWriter, r *http.Request) {
	limit := 300
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 2000 {
		limit = n
	}
	where := "WHERE p.agent_id=?"
	args := []any{r.PathValue("id")}
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		where += " AND (p.name LIKE ? OR p.cmdline LIKE ? OR p.parent_name LIKE ?)"
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	rows, err := s.db.Query(`SELECT p.id,p.ts,p.pid,p.ppid,p.name,p.image,p.cmdline,p.user,p.parent_name,p.parent_image,
		p.sha256,p.signature,p.signer,p.company,p.source,p.exited,p.restricted,
		coalesce(h.status,''),coalesce(h.malicious,0),coalesce(h.total,0),coalesce(h.label,'')
		FROM proc_events p LEFT JOIN hash_rep h ON h.sha256=p.sha256 AND p.sha256!=''
		`+where+` ORDER BY p.id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type exec struct {
		ID          int64   `json:"id"`
		TS          int64   `json:"ts"`
		PID         uint32  `json:"pid"`
		PPID        uint32  `json:"ppid"`
		Name        string  `json:"name"`
		Image       string  `json:"image"`
		CommandLine string  `json:"command_line"`
		User        string  `json:"user"`
		ParentName  string  `json:"parent_name"`
		ParentImage string  `json:"parent_image"`
		SHA256      string  `json:"sha256"`
		Signature   string  `json:"signature"`
		Signer      string  `json:"signer"`
		Company     string  `json:"company"`
		Source      string  `json:"source"`
		Exited      bool    `json:"exited"`
		Restricted  bool    `json:"restricted"`
		VT          HashRep `json:"vt"`
	}
	out := []exec{}
	for rows.Next() {
		var e exec
		rows.Scan(&e.ID, &e.TS, &e.PID, &e.PPID, &e.Name, &e.Image, &e.CommandLine, &e.User, &e.ParentName, &e.ParentImage,
			&e.SHA256, &e.Signature, &e.Signer, &e.Company, &e.Source, &e.Exited, &e.Restricted,
			&e.VT.Status, &e.VT.Malicious, &e.VT.Total, &e.VT.Label)
		out = append(out, e)
	}
	writeJSON(w, 200, out)
}
