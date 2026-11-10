package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Eventos em tempo real: tudo o que o sistema faz (agentes, varreduras,
// achados, consultas de reputação, comandos, painel) vira um evento que é
// gravado no banco e transmitido ao painel via Server-Sent Events.

// Categorias
const (
	CatAgent    = "agente"
	CatScan     = "varredura"
	CatFinding  = "achado"
	CatIntel    = "inteligencia"
	CatCommand  = "comando"
	CatPanel    = "painel"
)

// Níveis
const (
	LvlInfo = "info"
	LvlOK   = "ok"
	LvlWarn = "alerta"
	LvlCrit = "critico"
)

type Event struct {
	ID       int64          `json:"id"`
	TS       int64          `json:"ts"` // unix em milissegundos
	Category string         `json:"category"`
	Kind     string         `json:"kind"`
	Level    string         `json:"level"`
	AgentID  string         `json:"agent_id,omitempty"`
	Hostname string         `json:"hostname,omitempty"`
	Message  string         `json:"message"`
	Data     map[string]any `json:"data,omitempty"`
}

const maxStoredEvents = 20000

type eventBus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func (b *eventBus) subscribe() chan Event {
	ch := make(chan Event, 256)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[chan Event]struct{}{}
	}
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *eventBus) unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

func (b *eventBus) publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // assinante lento: descarta em vez de travar o servidor
		}
	}
}

func (s *Server) hostname(agentID string) string {
	var h string
	s.db.QueryRow(`SELECT hostname FROM agents WHERE id=?`, agentID).Scan(&h)
	return h
}

// emit grava e transmite um evento.
func (s *Server) emit(e Event) {
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	if e.Level == "" {
		e.Level = LvlInfo
	}
	if e.AgentID != "" && e.Hostname == "" {
		e.Hostname = s.hostname(e.AgentID)
	}
	data := ""
	if len(e.Data) > 0 {
		b, _ := json.Marshal(e.Data)
		data = string(b)
	}
	res, err := s.db.Exec(`INSERT INTO events(ts,category,kind,level,agent_id,hostname,message,data) VALUES(?,?,?,?,?,?,?,?)`,
		e.TS, e.Category, e.Kind, e.Level, e.AgentID, e.Hostname, e.Message, data)
	if err != nil {
		log.Printf("gravar evento: %v", err)
	} else {
		e.ID, _ = res.LastInsertId()
	}
	s.bus.publish(e)
}

func (s *Server) emitf(cat, kind, level, agentID, format string, args ...any) {
	s.emit(Event{Category: cat, Kind: kind, Level: level, AgentID: agentID, Message: fmt.Sprintf(format, args...)})
}

func (s *Server) loadEvents(where string, args []any, limit int) ([]Event, error) {
	rows, err := s.db.Query(`SELECT id,ts,category,kind,level,agent_id,hostname,message,data FROM events `+where+` ORDER BY id DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var data string
		rows.Scan(&e.ID, &e.TS, &e.Category, &e.Kind, &e.Level, &e.AgentID, &e.Hostname, &e.Message, &data)
		if data != "" {
			json.Unmarshal([]byte(data), &e.Data)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GET /api/events?limit=200&agent=ID&before=ID  (mais recentes primeiro)
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 200
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	where := "WHERE 1=1"
	var args []any
	if a := q.Get("agent"); a != "" {
		where += " AND agent_id=?"
		args = append(args, a)
	}
	if b, err := strconv.ParseInt(q.Get("before"), 10, 64); err == nil && b > 0 {
		where += " AND id<?"
		args = append(args, b)
	}
	evs, err := s.loadEvents(where, args, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, evs)
}

// GET /api/events/stream — Server-Sent Events. Suporta Last-Event-ID para
// reenviar o que foi perdido durante uma reconexão.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming não suportado")
		return
	}
	// A conexão fica aberta indefinidamente: remove o WriteTimeout global.
	http.NewResponseController(w).SetWriteDeadline(time.Time{})

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")

	ch := s.bus.subscribe()
	defer s.bus.unsubscribe(ch)

	write := func(e Event) error {
		b, _ := json.Marshal(e)
		_, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.ID, b)
		return err
	}

	fmt.Fprint(w, "retry: 3000\n\n")
	if last, err := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64); err == nil && last > 0 {
		missed, _ := s.loadEvents("WHERE id>?", []any{last}, 500)
		for i := len(missed) - 1; i >= 0; i-- {
			write(missed[i])
		}
	}
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if write(e) != nil {
				return
			}
			flusher.Flush()
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// ---------------------------------------------------------------------------
// Eventos enviados pelo próprio agente (o que ele está fazendo agora)

var agentEventKinds = map[string]string{
	"agent_started":     LvlOK,
	"procmon_started":   LvlInfo,
	"agent_stopping":    LvlWarn,
	"scan_started":      LvlInfo,
	"scan_phase":        LvlInfo,
	"scan_sent":         LvlInfo,
	"scan_spooled":      LvlWarn,
	"command_received":  LvlInfo,
	"command_rejected":  LvlCrit,
	"command_executing": LvlInfo,
}

type agentEventReq struct {
	Kind    string         `json:"kind"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

func (s *Server) handleAgentEvent(w http.ResponseWriter, r *http.Request) {
	id := agentID(r)
	var req agentEventReq
	if err := readJSON(r, &req, 16<<10); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	lvl, ok := agentEventKinds[req.Kind]
	if !ok {
		writeErr(w, 400, "tipo de evento desconhecido")
		return
	}
	if !s.agentEventAllowed(id) {
		writeErr(w, 429, "eventos demais")
		return
	}
	cat := CatAgent
	if len(req.Kind) > 5 && req.Kind[:5] == "scan_" {
		cat = CatScan
	} else if len(req.Kind) > 8 && req.Kind[:8] == "command_" {
		cat = CatCommand
	}
	s.emit(Event{Category: cat, Kind: req.Kind, Level: lvl, AgentID: id, Message: truncate(req.Message, 500), Data: req.Data})
	w.WriteHeader(204)
}

// Limite simples: 120 eventos por minuto por agente.
func (s *Server) agentEventAllowed(id string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	r := s.agentRate[id]
	if now.Sub(r.start) > time.Minute {
		r = rateWindow{start: now}
	}
	r.n++
	s.agentRate[id] = r
	return r.n <= 120
}

type rateWindow struct {
	start time.Time
	n     int
}

// ---------------------------------------------------------------------------
// Online / offline

func (s *Server) noteAgentSeen(id string, prevSeen int64) {
	if prevSeen > 0 && now()-prevSeen > agentOfflineAfter {
		s.emitf(CatAgent, "agent_online", LvlOK, id, "Agente voltou a se comunicar (estava sem contato há %s)", humanDur(now()-prevSeen))
	}
	s.offMu.Lock()
	delete(s.offlineNotified, id)
	s.offMu.Unlock()
}

const agentOfflineAfter = 120 // segundos (o agente consulta a cada 30s)

func (s *Server) checkOffline(initial bool) {
	rows, err := s.db.Query(`SELECT id,last_seen FROM agents WHERE last_seen < ?`, now()-agentOfflineAfter)
	if err != nil {
		return
	}
	type ag struct {
		id   string
		seen int64
	}
	var list []ag
	for rows.Next() {
		var a ag
		rows.Scan(&a.id, &a.seen)
		list = append(list, a)
	}
	rows.Close()
	for _, a := range list {
		s.offMu.Lock()
		done := s.offlineNotified[a.id]
		s.offlineNotified[a.id] = true
		s.offMu.Unlock()
		if !done && !initial {
			s.emitf(CatAgent, "agent_offline", LvlWarn, a.id, "Agente sem contato há %s (máquina desligada, sem rede ou serviço parado)", humanDur(now()-a.seen))
		}
	}
}

func humanDur(sec int64) string {
	switch {
	case sec < 120:
		return fmt.Sprintf("%d s", sec)
	case sec < 7200:
		return fmt.Sprintf("%d min", sec/60)
	case sec < 172800:
		return fmt.Sprintf("%d h", sec/3600)
	}
	return fmt.Sprintf("%d dias", sec/86400)
}
