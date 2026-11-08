package server

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"sentinela/internal/model"
)

type ctxKey int

const agentKey ctxKey = 1

func (s *Server) agentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /agent/v1/enroll", s.handleEnroll)
	mux.Handle("POST /agent/v1/report", s.agentAuth(http.HandlerFunc(s.handleReport)))
	mux.Handle("GET /agent/v1/commands", s.agentAuth(http.HandlerFunc(s.handlePollCommands)))
	mux.Handle("POST /agent/v1/commands/{id}/result", s.agentAuth(http.HandlerFunc(s.handleCommandResult)))
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooManyFailures("enroll:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "muitas tentativas; aguarde alguns minutos")
		return
	}
	var req model.EnrollRequest
	if err := readJSON(r, &req, 64<<10); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !constEq(req.Token, s.EnrollToken) {
		s.recordFailure("enroll:" + ip)
		s.db.Audit("agente@"+ip, "cadastro_recusado", "", "token de cadastro inválido para "+req.Hostname)
		writeErr(w, http.StatusUnauthorized, "token de cadastro inválido")
		return
	}
	host := strings.TrimSpace(req.Hostname)
	if host == "" || len(host) > 255 {
		writeErr(w, http.StatusBadRequest, "hostname inválido")
		return
	}
	id := randomHex(8)
	secret := randomToken(32)
	_, err := s.db.Exec(`INSERT INTO agents(id,hostname,os,secret_hash,enrolled_at,last_seen,remote_ip) VALUES(?,?,?,?,?,?,?)`,
		id, host, req.OS, sha256Hex(secret), now(), now(), ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erro ao cadastrar")
		return
	}
	s.db.Audit("agente@"+ip, "agente_cadastrado", id, host)
	log.Printf("novo agente cadastrado: %s (%s) de %s", host, id, ip)
	writeJSON(w, http.StatusOK, model.EnrollResponse{
		AgentID: id, Secret: secret,
		CommandPubKey: base64.StdEncoding.EncodeToString(s.signKey.Public().(ed25519.PublicKey)),
	})
}

func (s *Server) agentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		id, secret, ok2 := strings.Cut(tok, ".")
		if !ok || !ok2 {
			writeErr(w, http.StatusUnauthorized, "credenciais ausentes")
			return
		}
		var hash string
		err := s.db.QueryRow(`SELECT secret_hash FROM agents WHERE id=?`, id).Scan(&hash)
		if err != nil || !constEq(hash, sha256Hex(secret)) {
			writeErr(w, http.StatusUnauthorized, "credenciais inválidas")
			return
		}
		s.db.Exec(`UPDATE agents SET last_seen=?, remote_ip=? WHERE id=?`, now(), clientIP(r), id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentKey, id)))
	})
}

func agentID(r *http.Request) string { return r.Context().Value(agentKey).(string) }

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := agentID(r)
	var body io.Reader = http.MaxBytesReader(w, r.Body, 50<<20)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "gzip inválido")
			return
		}
		defer zr.Close()
		body = io.LimitReader(zr, 300<<20)
	}
	var rep model.Report
	if err := json.NewDecoder(body).Decode(&rep); err != nil {
		writeErr(w, http.StatusBadRequest, "relatório inválido: "+err.Error())
		return
	}
	if rep.Schema != model.SchemaVersion {
		writeErr(w, http.StatusBadRequest, "versão de schema não suportada")
		return
	}
	s.db.Exec(`UPDATE agents SET hostname=?, os=?, agent_version=?, last_report_at=? WHERE id=?`,
		rep.Host.Hostname, rep.Host.OS, rep.Host.AgentVer, now(), id)
	if err := s.ingest(id, &rep); err != nil {
		log.Printf("ingestão %s: %v", id, err)
		writeErr(w, http.StatusInternalServerError, "erro ao processar relatório")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePollCommands(w http.ResponseWriter, r *http.Request) {
	id := agentID(r)
	rows, err := s.db.Query(`SELECT id,payload,signature FROM commands
		WHERE agent_id=? AND status='pendente' AND expires_at > ? ORDER BY created_at`, id, now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erro")
		return
	}
	cmds := []model.Command{}
	for rows.Next() {
		var c model.Command
		rows.Scan(&c.ID, &c.Payload, &c.Signature)
		cmds = append(cmds, c)
	}
	rows.Close()
	for _, c := range cmds {
		s.db.Exec(`UPDATE commands SET status='enviado', delivered_at=? WHERE id=?`, now(), c.ID)
	}
	writeJSON(w, http.StatusOK, cmds)
}

func (s *Server) handleCommandResult(w http.ResponseWriter, r *http.Request) {
	id := agentID(r)
	cmdID := r.PathValue("id")
	var res model.CommandResult
	if err := readJSON(r, &res, 64<<10); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	status := "falha"
	if res.OK {
		status = "sucesso"
	}
	var action string
	err := s.db.QueryRow(`SELECT action FROM commands WHERE id=? AND agent_id=? AND status IN ('pendente','enviado')`, cmdID, id).Scan(&action)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "comando não encontrado")
		return
	}
	s.db.Exec(`UPDATE commands SET status=?, result=?, undo_id=?, finished_at=? WHERE id=?`,
		status, truncate(res.Message, 2000), truncate(res.UndoID, 64), now(), cmdID)
	s.db.Audit("agente", "resultado_"+action, id, status+": "+truncate(res.Message, 500))
	w.WriteHeader(http.StatusNoContent)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
