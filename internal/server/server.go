// Package server implementa o servidor central: ingestão dos relatórios
// dos agentes, motor de detecção, inteligência de ameaças, fila de
// comandos de remediação e a API do painel web.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinela/internal/model"
)

type Config struct {
	Addr    string
	DataDir string
	Hosts   []string // nomes/IPs incluídos no certificado
	Intel   IntelConfig
	Web     fs.FS // arquivos do painel (build do React)
}

type Server struct {
	cfg         Config
	db          *DB
	intel       IntelConfig
	signKey     ed25519.PrivateKey
	cert        tls.Certificate
	Fingerprint string
	EnrollToken string

	evalMu sync.Mutex
	dirty  atomic.Bool

	loginMu       sync.Mutex
	loginFailures map[string][]time.Time

	bus             eventBus
	rateMu          sync.Mutex
	agentRate       map[string]rateWindow
	offMu           sync.Mutex
	offlineNotified map[string]bool
}

// New prepara o servidor. Na primeira execução gera certificado, chave de
// assinatura, token de cadastro e senha do administrador; a senha inicial é
// retornada apenas uma vez para ser exibida no console.
func New(cfg Config) (*Server, string, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, "", err
	}
	db, err := OpenDB(filepath.Join(cfg.DataDir, "sentinela.db"))
	if err != nil {
		return nil, "", fmt.Errorf("banco de dados: %w", err)
	}
	s := &Server{cfg: cfg, db: db, intel: cfg.Intel, loginFailures: map[string][]time.Time{},
		agentRate: map[string]rateWindow{}, offlineNotified: map[string]bool{}}

	hosts := append([]string{"localhost", "127.0.0.1"}, cfg.Hosts...)
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	hosts = append(hosts, localIPs()...)
	if s.cert, s.Fingerprint, err = loadOrCreateCert(cfg.DataDir, hosts); err != nil {
		return nil, "", fmt.Errorf("certificado: %w", err)
	}
	if s.signKey, err = loadOrCreateSigningKey(cfg.DataDir); err != nil {
		return nil, "", fmt.Errorf("chave de comandos: %w", err)
	}

	if s.EnrollToken, _ = db.Setting("enroll_token"); s.EnrollToken == "" {
		s.EnrollToken = randomToken(18)
		db.SetSetting("enroll_token", s.EnrollToken)
	}
	initialPw := ""
	if h, _ := db.Setting("admin_password"); h == "" {
		initialPw = randomToken(12)
		db.SetSetting("admin_password", hashPassword(initialPw))
	}
	return s, initialPw, nil
}

// ResetAdminPassword gera uma nova senha para o administrador.
func (s *Server) ResetAdminPassword() string {
	pw := randomToken(12)
	s.db.SetSetting("admin_password", hashPassword(pw))
	s.db.Exec(`DELETE FROM sessions`)
	s.db.Audit("console", "reset_senha", "", "senha do administrador redefinida")
	return pw
}

func (s *Server) RotateEnrollToken() string {
	s.EnrollToken = randomToken(18)
	s.db.SetSetting("enroll_token", s.EnrollToken)
	return s.EnrollToken
}

func localIPs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// Handler monta as rotas da API dos agentes, do painel e os arquivos web.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.agentRoutes(mux)
	s.panelRoutes(mux)
	if s.cfg.Web != nil {
		mux.Handle("GET /", spaHandler(s.cfg.Web))
	}
	return securityHeaders(mux)
}

func (s *Server) Close() error { return s.db.Close() }

// TLSCertificate é o certificado do servidor (usado nos testes).
func (s *Server) TLSCertificate() tls.Certificate { return s.cert }

func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(tlsNoiseFilter{}, "", 0),
	}

	s.checkOffline(true) // agentes já offline ao iniciar não geram alerta
	s.emitf(CatPanel, "server_started", LvlOK, "", "Servidor iniciado em %s", s.cfg.Addr)
	s.runIntel(ctx)
	go s.reevaluateLoop(ctx)
	go s.housekeeping(ctx)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	select {
	case <-ctx.Done():
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sh)
	case err := <-errc:
		return err
	}
}

// tlsNoiseFilter silencia o log de handshakes recusados (navegadores que
// ainda não aceitaram o certificado autoassinado).
type tlsNoiseFilter struct{}

func (tlsNoiseFilter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil
	}
	log.Print(string(p))
	return len(p), nil
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Strict-Transport-Security", "max-age=31536000")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		h.ServeHTTP(w, r)
	})
}

// spaHandler serve o build do React e devolve index.html para rotas do
// cliente.
func spaHandler(fsys fs.FS) http.Handler {
	files := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(fsys, p); err == nil {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		b, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			http.Error(w, "painel não compilado: rode o build do diretório web/", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(b)
	})
}

// ---------------------------------------------------------------------------
// Utilitários HTTP

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("JSON inválido: " + err.Error())
	}
	return nil
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------------------------------------------------------------------------
// Detecção

var triggerText = map[string]string{
	"inicial": "inicial", "agendada": "agendada", "manual": "manual", "pos-remediacao": "de verificação pós-remediação",
}

// ingest processa um relatório recém-recebido.
func (s *Server) ingest(agentID string, rep *model.Report) error {
	if err := s.db.SaveSnapshot(agentID, rep); err != nil {
		return err
	}
	s.emit(Event{Category: CatScan, Kind: "scan_received", Level: LvlInfo, AgentID: agentID,
		Message: fmt.Sprintf("Varredura %s recebida: %d entradas de inicialização, %d processos, %d conexões (coleta em %.1f s)",
			triggerText[rep.Trigger], len(rep.Autoruns), len(rep.Processes), len(rep.Connections), float64(rep.DurationMS)/1000),
		Data: map[string]any{"trigger": rep.Trigger, "autoruns": len(rep.Autoruns), "processes": len(rep.Processes),
			"connections": len(rep.Connections), "duration_ms": rep.DurationMS, "elevated": rep.Host.IsElevated}})
	if n := s.queueIntel(rep); n > 0 {
		s.emitf(CatIntel, "intel_queued", LvlInfo, agentID, "%d arquivos/IPs novos na fila de consulta de reputação", n)
	}
	res, err := s.evaluate(agentID, rep, "varredura")
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO scans(agent_id,received_at,trigger,autoruns,processes,connections,duration_ms,open_findings,max_severity)
		VALUES(?,?,?,?,?,?,?,?,?)`, agentID, now(), rep.Trigger, len(rep.Autoruns), len(rep.Processes), len(rep.Connections),
		rep.DurationMS, res.Open, res.MaxSev)
	if rep.Trigger == "pos-remediacao" {
		lvl, msg := LvlOK, "Verificação posterior concluída: nenhum achado aberto"
		if res.Open > 0 {
			lvl, msg = LvlWarn, fmt.Sprintf("Verificação posterior concluída: ainda há %d achados abertos", res.Open)
		}
		s.emitf(CatScan, "post_check", lvl, agentID, "%s", msg)
	}
	return err
}

var sevLevel = map[string]string{SevCritica: LvlCrit, SevAlta: LvlCrit, SevMedia: LvlWarn, SevBaixa: LvlInfo}
var statusText = map[string]string{"comprometido": "COMPROMETIDO", "suspeito": "suspeito", "atencao": "atenção", "ok": "sem achados"}

// evaluate aplica as regras e emite eventos com o que mudou. cause indica
// o motivo (nova varredura ou reputação nova).
func (s *Server) evaluate(agentID string, rep *model.Report, cause string) (*SyncResult, error) {
	s.evalMu.Lock()
	defer s.evalMu.Unlock()
	intel, err := s.db.LoadIntel()
	if err != nil {
		return nil, err
	}
	res, err := s.db.SyncFindings(agentID, Evaluate(rep, intel))
	if err != nil {
		return nil, err
	}
	for _, f := range res.Opened {
		s.emit(Event{Category: CatFinding, Kind: "finding_opened", Level: sevLevel[f.Severity], AgentID: agentID,
			Message: fmt.Sprintf("Novo achado [%s] %s: %s", f.Severity, f.RuleID, f.Title),
			Data:    map[string]any{"rule": f.RuleID, "severity": f.Severity, "path": f.Path, "technique": f.Technique, "cause": cause}})
	}
	for _, t := range res.Resolved {
		s.emitf(CatFinding, "finding_resolved", LvlOK, agentID, "Achado resolvido (não aparece mais): %s", t)
	}
	if before, after := HostStatus(res.PrevMaxSev), HostStatus(res.MaxSev); before != after {
		lvl := LvlOK
		if sevRank[res.MaxSev] > sevRank[res.PrevMaxSev] {
			lvl = sevLevel[res.MaxSev]
		}
		s.emitf(CatAgent, "status_changed", lvl, agentID, "Situação da máquina: %s → %s", statusText[before], statusText[after])
	}
	if res.NewCompromise {
		s.emitf(CatAgent, "compromised", LvlCrit, agentID, "Máquina marcada como comprometida: reinstalação limpa recomendada")
	}
	return res, nil
}

func (s *Server) markDirty() { s.dirty.Store(true) }

// reevaluateLoop reaplica as regras quando chega reputação nova (ex.: o
// VirusTotal respondeu que um hash já visto é malicioso).
func (s *Server) reevaluateLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !s.dirty.Swap(false) {
			continue
		}
		ids, err := s.db.SnapshotAgents()
		if err != nil {
			continue
		}
		for _, id := range ids {
			rep, err := s.db.Snapshot(id)
			if err != nil {
				continue
			}
			if _, err := s.evaluate(id, rep, "reputacao"); err != nil {
				log.Printf("reavaliação %s: %v", id, err)
			}
		}
	}
}

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n := now()
		s.checkOffline(false)
		s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, n)
		if r, err := s.db.Exec(`UPDATE commands SET status='expirado', finished_at=? WHERE status IN ('pendente','enviado') AND expires_at < ?`, n, n); err == nil {
			if k, _ := r.RowsAffected(); k > 0 {
				s.emitf(CatCommand, "command_expired", LvlWarn, "", "%d comandos expiraram sem resposta do agente", k)
			}
		}
		s.db.Exec(`DELETE FROM scans WHERE received_at < ?`, n-90*86400)
		s.db.Exec(`DELETE FROM events WHERE id <= (SELECT max(id) FROM events) - ?`, maxStoredEvents)
	}
}
