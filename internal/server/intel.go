package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"sentinela/internal/model"
)

// Integração com inteligência de ameaças. Automatiza a "verificação
// integrada com o VirusTotal" do procedimento manual, mas:
//   - consulta apenas o hash (o arquivo nunca é enviado);
//   - usa fila com prioridade e cache, respeitando a cota gratuita
//     (4 consultas/min, 500/dia no VirusTotal);
//   - não consulta arquivos assinados pela Microsoft (como o filtro
//     "Hide Microsoft Entries" do Autoruns).

var (
	vtBaseURL    = "https://www.virustotal.com/api/v3/files/"
	abuseBaseURL = "https://api.abuseipdb.com/api/v2/check"
)

type IntelConfig struct {
	VTKey        string
	VTInterval   time.Duration // padrão 16s (cota gratuita: 4/min)
	AbuseIPDBKey string
}

// Prioridades da fila de hashes (menor = consultado antes).
const (
	prioAutorunUnsigned = 1
	prioProcessUnsigned = 2
	prioAutorunSigned   = 3
	prioProcessSigned   = 4
)

func hashPriority(f *model.FileInfo, autorun bool) int {
	if f == nil || f.SHA256 == "" || microsoft(f) {
		return 0
	}
	switch {
	case autorun && !trusted(f):
		return prioAutorunUnsigned
	case !trusted(f):
		return prioProcessUnsigned
	case autorun:
		return prioAutorunSigned
	}
	return prioProcessSigned
}

// queueIntel coloca na fila os hashes e IPs do relatório que ainda não têm
// reputação (ou cuja reputação expirou). Retorna quantos entraram na fila.
func (s *Server) queueIntel(rep *model.Report) int {
	t := now()
	hashes := map[string]int{}
	paths := map[string]string{}
	add := func(f *model.FileInfo, autorun bool) {
		if p := hashPriority(f, autorun); p > 0 {
			if old, ok := hashes[f.SHA256]; !ok || p < old {
				hashes[f.SHA256] = p
			}
			paths[f.SHA256] = f.Path
		}
	}
	for i := range rep.Autoruns {
		add(rep.Autoruns[i].File, true)
		add(rep.Autoruns[i].Payload, true)
	}
	procs := map[uint32]*model.Process{}
	for i := range rep.Processes {
		add(rep.Processes[i].File, false)
		procs[rep.Processes[i].PID] = &rep.Processes[i]
	}
	queued := 0
	for sha, p := range hashes {
		var before string
		s.db.QueryRow(`SELECT status FROM hash_rep WHERE sha256=?`, sha).Scan(&before)
		s.db.Exec(`INSERT INTO hash_rep(sha256,status,priority,requested_at,sample_path) VALUES(?,'pending',?,?,?)
			ON CONFLICT(sha256) DO UPDATE SET
			  priority=min(priority, excluded.priority),
			  sample_path=CASE WHEN sample_path='' THEN excluded.sample_path ELSE sample_path END,
			  status=CASE
			    WHEN status IN ('unknown','error') AND checked_at < ? THEN 'pending'
			    WHEN status='known' AND checked_at < ? THEN 'pending'
			    ELSE status END,
			  requested_at=CASE WHEN status='pending' THEN requested_at ELSE excluded.requested_at END`,
			sha, p, t, paths[sha], t-3*86400, t-14*86400)
		var after string
		s.db.QueryRow(`SELECT status FROM hash_rep WHERE sha256=?`, sha).Scan(&after)
		// Sem chave do VirusTotal os hashes ficam guardados para quando ela
		// for configurada, mas não contam como "consulta em andamento".
		if s.intel.VTKey != "" && after == "pending" && before != "pending" {
			queued++
		}
	}

	if s.intel.AbuseIPDBKey == "" {
		return queued
	}
	for _, c := range rep.Connections {
		if (c.State != "ESTABLISHED" && c.State != "SYN_SENT") || !publicIP(c.RemoteAddr) {
			continue
		}
		if p := procs[c.PID]; p != nil && microsoft(p.File) {
			continue
		}
		r, _ := s.db.Exec(`INSERT INTO ip_rep(ip,status,requested_at) VALUES(?,'pending',?)
			ON CONFLICT(ip) DO UPDATE SET
			  requested_at=CASE WHEN status!='pending' AND checked_at < ? THEN excluded.requested_at ELSE requested_at END,
			  status=CASE WHEN status!='pending' AND checked_at < ? THEN 'pending' ELSE status END`,
			c.RemoteAddr, t, t-86400, t-86400)
		var st string
		var req int64
		s.db.QueryRow(`SELECT status,requested_at FROM ip_rep WHERE ip=?`, c.RemoteAddr).Scan(&st, &req)
		if r != nil && st == "pending" && req == t {
			queued++
		}
	}
	return queued
}

func (s *Server) runIntel(ctx context.Context) {
	if s.intel.VTKey != "" {
		go s.vtWorker(ctx)
	} else {
		log.Print("VirusTotal não configurado (SENTINELA_VT_KEY): reputação de arquivos desativada")
	}
	if s.intel.AbuseIPDBKey != "" {
		go s.abuseWorker(ctx)
	} else {
		log.Print("AbuseIPDB não configurado (SENTINELA_ABUSEIPDB_KEY): reputação de IPs desativada")
	}
}

var intelHTTP = &http.Client{Timeout: 20 * time.Second}

func (s *Server) vtWorker(ctx context.Context) {
	interval := s.intel.VTInterval
	if interval <= 0 {
		interval = 16 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var sha, path string
		err := s.db.QueryRow(`SELECT sha256,sample_path FROM hash_rep WHERE status='pending' ORDER BY priority, requested_at LIMIT 1`).Scan(&sha, &path)
		if err != nil {
			continue // fila vazia
		}
		name := base(path)
		if name == "" {
			name = sha[:12]
		}
		rep, wait, err := queryVT(ctx, s.intel.VTKey, sha)
		if err != nil {
			log.Printf("VirusTotal %s: %v", sha[:12], err)
			s.emitf(CatIntel, "vt_error", LvlWarn, "", "VirusTotal: erro ao consultar %s (%v)", name, err)
			if wait > 0 {
				time.Sleep(wait)
				continue
			}
			rep.Status = "error"
		}
		s.db.Exec(`UPDATE hash_rep SET status=?,malicious=?,suspicious=?,total=?,label=?,checked_at=? WHERE sha256=?`,
			rep.Status, rep.Malicious, rep.Suspicious, rep.Total, rep.Label, now(), sha)
		label := ""
		if rep.Label != "" {
			label = " (" + rep.Label + ")"
		}
		ev := Event{Category: CatIntel, Kind: "vt_result", Level: LvlOK,
			Data: map[string]any{"sha256": sha, "path": path, "malicious": rep.Malicious, "total": rep.Total, "label": rep.Label}}
		switch {
		case rep.Status == "unknown":
			ev.Level, ev.Message = LvlInfo, fmt.Sprintf("VirusTotal: %s nunca foi analisado (arquivo desconhecido)", name)
		case rep.Status != "known":
			continue
		case rep.Malicious >= 5:
			ev.Level, ev.Message = LvlCrit, fmt.Sprintf("VirusTotal: %s detectado por %d/%d antivírus%s", name, rep.Malicious, rep.Total, label)
		case rep.Malicious > 0:
			ev.Level, ev.Message = LvlWarn, fmt.Sprintf("VirusTotal: %s detectado por %d/%d antivírus%s", name, rep.Malicious, rep.Total, label)
		default:
			ev.Message = fmt.Sprintf("VirusTotal: %s limpo (0/%d)", name, rep.Total)
		}
		s.emit(ev)
		if rep.Status == "known" && rep.Malicious > 0 {
			s.markDirty()
		}
	}
}

func queryVT(ctx context.Context, key, sha string) (HashRep, time.Duration, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", vtBaseURL+sha, nil)
	req.Header.Set("x-apikey", key)
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return HashRep{}, 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return HashRep{Status: "unknown"}, 0, nil
	case http.StatusTooManyRequests:
		return HashRep{}, 60 * time.Second, fmt.Errorf("cota excedida, aguardando")
	case http.StatusUnauthorized, http.StatusForbidden:
		return HashRep{}, 10 * time.Minute, fmt.Errorf("chave da API inválida (HTTP %d)", resp.StatusCode)
	case http.StatusOK:
	default:
		return HashRep{}, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				Class struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<20)).Decode(&body); err != nil {
		return HashRep{}, 0, err
	}
	st := body.Data.Attributes.Stats
	return HashRep{
		Status: "known", Malicious: st.Malicious, Suspicious: st.Suspicious,
		Total: st.Malicious + st.Suspicious + st.Undetected + st.Harmless,
		Label: body.Data.Attributes.Class.Label,
	}, 0, nil
}

func (s *Server) abuseWorker(ctx context.Context) {
	t := time.NewTicker(4 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var ip string
		if err := s.db.QueryRow(`SELECT ip FROM ip_rep WHERE status='pending' ORDER BY requested_at LIMIT 1`).Scan(&ip); err != nil {
			continue
		}
		r, err := queryAbuseIPDB(ctx, s.intel.AbuseIPDBKey, ip)
		if err != nil {
			log.Printf("AbuseIPDB %s: %v", ip, err)
			r.Status = "error"
		}
		s.db.Exec(`UPDATE ip_rep SET status=?,score=?,reports=?,country=?,isp=?,checked_at=? WHERE ip=?`,
			r.Status, r.Score, r.Reports, r.Country, r.ISP, now(), ip)
		if r.Status == "known" {
			lvl := LvlOK
			if r.Score >= 75 {
				lvl = LvlCrit
			} else if r.Score >= 25 {
				lvl = LvlWarn
			}
			s.emit(Event{Category: CatIntel, Kind: "ip_result", Level: lvl,
				Message: fmt.Sprintf("AbuseIPDB: %s (%s, %s) com %d%% de confiança de abuso", ip, r.Country, r.ISP, r.Score),
				Data:    map[string]any{"ip": ip, "score": r.Score, "reports": r.Reports}})
		}
		if r.Score >= 25 {
			s.markDirty()
		}
	}
}

func queryAbuseIPDB(ctx context.Context, key, ip string) (IPRep, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", abuseBaseURL+"?maxAgeInDays=90&ipAddress="+url.QueryEscape(ip), nil)
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return IPRep{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return IPRep{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Score   int    `json:"abuseConfidenceScore"`
			Country string `json:"countryCode"`
			ISP     string `json:"isp"`
			Reports int    `json:"totalReports"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return IPRep{}, err
	}
	d := body.Data
	return IPRep{Status: "known", Score: d.Score, Country: d.Country, ISP: d.ISP, Reports: d.Reports}, nil
}
