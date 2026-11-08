package server

import (
	"context"
	"net/http"
	"time"
)

const (
	sessionCookie = "sentinela_session"
	sessionTTL    = 12 * time.Hour
	csrfHeader    = "X-Sentinela"
	userKey       ctxKey = 2
)

// Limite de tentativas: 5 falhas em 15 minutos bloqueiam o IP.
const (
	maxFailures   = 5
	failureWindow = 15 * time.Minute
)

func (s *Server) tooManyFailures(key string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	cut := time.Now().Add(-failureWindow)
	var recent []time.Time
	for _, t := range s.loginFailures[key] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	s.loginFailures[key] = recent
	return len(recent) >= maxFailures
}

func (s *Server) recordFailure(key string) {
	s.loginMu.Lock()
	s.loginFailures[key] = append(s.loginFailures[key], time.Now())
	s.loginMu.Unlock()
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooManyFailures("login:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "muitas tentativas; aguarde 15 minutos")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req, 4<<10); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	stored, _ := s.db.Setting("admin_password")
	if req.Username != "admin" || !checkPassword(req.Password, stored) {
		s.recordFailure("login:" + ip)
		s.db.Audit(req.Username+"@"+ip, "login_falhou", "", "")
		writeErr(w, http.StatusUnauthorized, "usuário ou senha inválidos")
		return
	}
	tok := randomToken(32)
	exp := time.Now().Add(sessionTTL)
	s.db.Exec(`INSERT INTO sessions(token_hash,username,expires_at) VALUES(?,?,?)`, sha256Hex(tok), "admin", exp.Unix())
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	s.db.Audit("admin@"+ip, "login", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"username": "admin"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, sha256Hex(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// panelAuth exige sessão válida. Requisições que alteram estado também
// precisam do cabeçalho X-Sentinela: um site de terceiros não consegue
// enviá-lo sem CORS, o que (junto com SameSite=Strict) bloqueia CSRF.
func (s *Server) panelAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "não autenticado")
			return
		}
		var user string
		err = s.db.QueryRow(`SELECT username FROM sessions WHERE token_hash=? AND expires_at>?`, sha256Hex(c.Value), now()).Scan(&user)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "sessão expirada")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) != "1" {
			writeErr(w, http.StatusForbidden, "cabeçalho de proteção ausente")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	})
}

func actor(r *http.Request) string {
	u, _ := r.Context().Value(userKey).(string)
	return u + "@" + clientIP(r)
}
