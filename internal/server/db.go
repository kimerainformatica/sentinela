package server

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"sentinela/internal/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  os TEXT NOT NULL DEFAULT '',
  secret_hash TEXT NOT NULL,
  enrolled_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL DEFAULT 0,
  last_report_at INTEGER NOT NULL DEFAULT 0,
  remote_ip TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  -- primeira vez que um achado crítico foi visto: aciona a recomendação de
  -- formatação do relatório técnico até alguém confirmar a reinstalação.
  compromised_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS snapshots(
  agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  received_at INTEGER NOT NULL,
  trigger TEXT NOT NULL,
  data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  received_at INTEGER NOT NULL,
  trigger TEXT NOT NULL,
  autoruns INTEGER, processes INTEGER, connections INTEGER,
  duration_ms INTEGER, open_findings INTEGER, max_severity TEXT
);
CREATE INDEX IF NOT EXISTS scans_agent ON scans(agent_id, received_at);

CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  fkey TEXT NOT NULL,
  rule_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL,
  technique TEXT NOT NULL DEFAULT '', object_type TEXT NOT NULL, object_ref TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'aberto', -- aberto | resolvido | falso_positivo
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, resolved_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(agent_id, fkey)
);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status);

CREATE TABLE IF NOT EXISTS hash_rep(
  sha256 TEXT PRIMARY KEY,
  status TEXT NOT NULL, -- pending | known | unknown | error
  malicious INTEGER NOT NULL DEFAULT 0, suspicious INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0,
  label TEXT NOT NULL DEFAULT '',
  priority INTEGER NOT NULL DEFAULT 9,
  requested_at INTEGER NOT NULL, checked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS hash_rep_queue ON hash_rep(status, priority, requested_at);

CREATE TABLE IF NOT EXISTS ip_rep(
  ip TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  score INTEGER NOT NULL DEFAULT 0, reports INTEGER NOT NULL DEFAULT 0,
  country TEXT NOT NULL DEFAULT '', isp TEXT NOT NULL DEFAULT '',
  requested_at INTEGER NOT NULL, checked_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commands(
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  action TEXT NOT NULL, params TEXT NOT NULL,
  payload TEXT NOT NULL, signature TEXT NOT NULL,
  status TEXT NOT NULL, -- pendente | enviado | sucesso | falha | expirado
  created_at INTEGER NOT NULL, created_by TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  delivered_at INTEGER NOT NULL DEFAULT 0, finished_at INTEGER NOT NULL DEFAULT 0,
  result TEXT NOT NULL DEFAULT '', undo_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS commands_agent ON commands(agent_id, status);

CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, agent_id TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL, -- unix ms
  category TEXT NOT NULL, kind TEXT NOT NULL, level TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL, data TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_agent ON events(agent_id, id);
`

// Migrações para bancos criados por versões anteriores. Erros de "coluna
// duplicada" significam que já foram aplicadas.
var migrations = []string{
	`ALTER TABLE hash_rep ADD COLUMN sample_path TEXT NOT NULL DEFAULT ''`,
}

type DB struct{ *sql.DB }

func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: um escritor por vez evita "database is locked"
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return nil, fmt.Errorf("migração %q: %w", m, err)
		}
	}
	return &DB{db}, nil
}

func now() int64 { return time.Now().Unix() }

func (d *DB) Setting(key string) (string, error) {
	var v string
	err := d.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (d *DB) SetSetting(key, value string) error {
	_, err := d.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (d *DB) Audit(actor, action, agentID, detail string) {
	d.Exec(`INSERT INTO audit(ts,actor,action,agent_id,detail) VALUES(?,?,?,?,?)`, now(), actor, action, agentID, detail)
}

// ---------------------------------------------------------------------------
// Snapshots

func gz(v any) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	zw.Close()
	return buf.Bytes(), nil
}

func ungz(b []byte, v any) error {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer zr.Close()
	return json.NewDecoder(io.LimitReader(zr, 200<<20)).Decode(v)
}

func (d *DB) SaveSnapshot(agentID string, rep *model.Report) error {
	data, err := gz(rep)
	if err != nil {
		return err
	}
	_, err = d.Exec(`INSERT INTO snapshots(agent_id,received_at,trigger,data) VALUES(?,?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET received_at=excluded.received_at, trigger=excluded.trigger, data=excluded.data`,
		agentID, now(), rep.Trigger, data)
	return err
}

func (d *DB) Snapshot(agentID string) (*model.Report, error) {
	var data []byte
	if err := d.QueryRow(`SELECT data FROM snapshots WHERE agent_id=?`, agentID).Scan(&data); err != nil {
		return nil, err
	}
	var rep model.Report
	return &rep, ungz(data, &rep)
}

func (d *DB) SnapshotAgents() ([]string, error) {
	rows, err := d.Query(`SELECT agent_id FROM snapshots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---------------------------------------------------------------------------
// Inteligência (cache de reputação)

func (d *DB) LoadIntel() (Intel, error) {
	in := Intel{Hashes: map[string]HashRep{}, IPs: map[string]IPRep{}}
	rows, err := d.Query(`SELECT sha256,status,malicious,suspicious,total,label FROM hash_rep`)
	if err != nil {
		return in, err
	}
	for rows.Next() {
		var sha string
		var r HashRep
		rows.Scan(&sha, &r.Status, &r.Malicious, &r.Suspicious, &r.Total, &r.Label)
		in.Hashes[sha] = r
	}
	rows.Close()
	rows, err = d.Query(`SELECT ip,status,score,reports,country,isp FROM ip_rep`)
	if err != nil {
		return in, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var r IPRep
		rows.Scan(&ip, &r.Status, &r.Score, &r.Reports, &r.Country, &r.ISP)
		in.IPs[ip] = r
	}
	return in, rows.Err()
}

// ---------------------------------------------------------------------------
// Achados

// SyncResult descreve o que mudou numa avaliação (usado para os eventos).
type SyncResult struct {
	Open       int
	MaxSev     string
	PrevMaxSev string
	Opened     []Finding // novos ou reabertos
	Resolved   []string  // títulos dos achados que deixaram de aparecer
	NewCompromise bool   // primeira vez que a máquina teve achado crítico
}

// SyncFindings aplica o resultado da avaliação: abre achados novos,
// atualiza os existentes e marca como "resolvido" o que não apareceu mais
// (a "verificação posterior" do procedimento manual).
func (d *DB) SyncFindings(agentID string, fs []Finding) (*SyncResult, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res := &SyncResult{}
	t := now()

	// Estado anterior
	prev := map[string]string{} // fkey -> status
	rows, err := tx.Query(`SELECT fkey,status,severity FROM findings WHERE agent_id=?`, agentID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, st, sev string
		rows.Scan(&k, &st, &sev)
		prev[k] = st
		if st == "aberto" && sevRank[sev] > sevRank[res.PrevMaxSev] {
			res.PrevMaxSev = sev
		}
	}
	rows.Close()

	current := map[string]bool{}
	for _, f := range fs {
		current[f.Key] = true
		if st, ok := prev[f.Key]; !ok || st == "resolvido" {
			res.Opened = append(res.Opened, f)
		}
		_, err = tx.Exec(`INSERT INTO findings(agent_id,fkey,rule_id,severity,title,detail,technique,object_type,object_ref,path,sha256,status,first_seen,last_seen)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,'aberto',?,?)
			ON CONFLICT(agent_id,fkey) DO UPDATE SET
			  severity=excluded.severity, title=excluded.title, detail=excluded.detail,
			  path=excluded.path, sha256=excluded.sha256, last_seen=excluded.last_seen,
			  status=CASE WHEN findings.status='falso_positivo' THEN 'falso_positivo' ELSE 'aberto' END,
			  resolved_at=CASE WHEN findings.status='falso_positivo' THEN findings.resolved_at ELSE 0 END`,
			agentID, f.Key, f.RuleID, f.Severity, f.Title, f.Detail, f.Technique, f.ObjectType, f.ObjectRef, f.Path, f.SHA256, t, t)
		if err != nil {
			return nil, err
		}
	}

	rows, err = tx.Query(`SELECT id,fkey,title FROM findings WHERE agent_id=? AND status='aberto'`, agentID)
	if err != nil {
		return nil, err
	}
	var gone []int64
	for rows.Next() {
		var id int64
		var k, title string
		rows.Scan(&id, &k, &title)
		if !current[k] {
			gone = append(gone, id)
			res.Resolved = append(res.Resolved, title)
		}
	}
	rows.Close()
	for _, id := range gone {
		if _, err := tx.Exec(`UPDATE findings SET status='resolvido', resolved_at=? WHERE id=?`, t, id); err != nil {
			return nil, err
		}
	}

	rows, err = tx.Query(`SELECT severity FROM findings WHERE agent_id=? AND status='aberto'`, agentID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		rows.Scan(&s)
		res.Open++
		if sevRank[s] > sevRank[res.MaxSev] {
			res.MaxSev = s
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

// MaxOpenSeverity é usado para o status do host na listagem.
func (d *DB) MaxOpenSeverity(agentID string) (open int, maxSev string) {
	rows, err := d.Query(`SELECT severity FROM findings WHERE agent_id=? AND status='aberto'`, agentID)
	if err != nil {
		return 0, ""
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		rows.Scan(&s)
		open++
		if sevRank[s] > sevRank[maxSev] {
			maxSev = s
		}
	}
	return open, maxSev
}
