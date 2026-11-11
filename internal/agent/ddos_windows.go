package agent

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"sentinela/internal/agent/procmon"
	"sentinela/internal/model"
)

// Resposta a DDoS em tempo real.
//
// O detector (procmon) sinaliza uma enxurrada de conexões assim que ela
// começa. Aqui o agente responde na hora, sem esperar o servidor: finaliza o
// processo que está atacando (saída) ou bloqueia no firewall os IPs que mais
// atacam (entrada). Toda ação é registrada e relatada ao painel, e pode ser
// desligada pelo analista (comando set_protection).
//
// Travas de segurança: nunca finaliza processos críticos do Windows nem
// bloqueia IPs protegidos (servidor e a própria máquina); os bloqueios são
// reversíveis e expiram sozinhos.

func onOff(b bool) string {
	if b {
		return "ligada"
	}
	return "desligada"
}

func (r *runner) setProtection(on bool) {
	r.protect.Store(on)
	r.cfg.AutoMitigate = &on
	if err := saveConfig(r.cfg); err != nil {
		log.Printf("salvar configuração: %v", err)
	}
	msg := "Resposta automática a DDoS " + onOff(on) + " pelo painel."
	r.event("protection", msg, map[string]any{"protect": on})
	log.Print(msg)
}

func (r *runner) mitigationLoop(mon *procmon.Monitor, stop <-chan struct{}) {
	expire := time.NewTicker(time.Minute)
	defer expire.Stop()
	for {
		select {
		case <-stop:
			return
		case inc := <-mon.Incidents:
			r.handleFlood(inc)
		case <-expire.C:
			for _, ip := range r.rem.ExpireBlocks() {
				r.event("ddos_unblock", "Bloqueio de "+ip+" expirou e foi removido", map[string]any{"ip": ip})
			}
		}
	}
}

func (r *runner) handleFlood(inc model.FloodIncident) {
	auto := r.protect.Load()
	rep := model.IncidentReport{Incident: inc, Action: "alerta"}

	if inc.Direction == "saida" {
		rep.Outcome, rep.Mitigated, rep.KilledPID = r.mitigateOutbound(inc, auto)
		if rep.Mitigated {
			rep.Action = "kill"
		}
	} else {
		var blocked []string
		blocked, rep.Outcome = r.mitigateInbound(inc, auto)
		rep.BlockedIPs = blocked
		if len(blocked) > 0 {
			rep.Action, rep.Mitigated = "block", true
		}
	}

	log.Printf("DDoS %s/%s pid=%d alvo=%s porta=%d: %s", inc.Direction, inc.Reason, inc.PID, inc.Target, inc.LocalPort, rep.Outcome)
	if err := r.cl.SendIncident(rep); err != nil {
		log.Printf("relatar incidente: %v", err)
	}
}

// mitigateOutbound decide e executa a resposta a um flood de saída.
func (r *runner) mitigateOutbound(inc model.FloodIncident, auto bool) (outcome string, killed bool, pid uint32) {
	image := inc.Image
	if !auto {
		return "resposta automática desligada; apenas alertado", false, 0
	}
	if image == "" || !filepath.IsAbs(image) {
		return "processo não pôde ser identificado com segurança; apenas alertado", false, 0
	}
	// Para "espalhada" (pode ser P2P/torrent legítimo), só finaliza sem
	// assinatura válida. Para "alvo"/"volume" (avalanche a uma vítima), o
	// sinal é inequívoco: finaliza (processos críticos ficam protegidos).
	if inc.Reason == "espalhada" {
		if f := r.in.Inspect(image); f != nil && f.Signature == "valid" {
			return "programa assinado com muitos destinos (possível P2P); apenas alertado", false, 0
		}
	}
	res := r.rem.Execute(model.CommandPayload{Action: model.ActionKillProcess,
		Params: map[string]string{"pid": strconv.FormatUint(uint64(inc.PID), 10), "image_path": image}})
	if res.OK {
		return res.Message, true, inc.PID
	}
	return "não finalizado (" + res.Message + ")", false, 0
}

// mitigateInbound bloqueia as origens mais agressivas de um flood de entrada.
func (r *runner) mitigateInbound(inc model.FloodIncident, auto bool) (blocked []string, outcome string) {
	if !auto {
		return nil, "resposta automática desligada; apenas alertado"
	}
	if len(inc.Sources) == 0 {
		return nil, fmt.Sprintf("ataque distribuído por %d origens leves; sem IP concentrado para bloquear (apenas alertado)", inc.Distinct)
	}
	reason := fmt.Sprintf("DDoS na porta %d", inc.LocalPort)
	for i, s := range inc.Sources {
		if i >= 16 {
			break
		}
		res := r.rem.Execute(model.CommandPayload{Action: model.ActionBlockIP,
			Params: map[string]string{"ip": s.IP, "reason": reason}})
		if res.OK {
			blocked = append(blocked, s.IP)
			r.event("ddos_block", fmt.Sprintf("IP %s bloqueado automaticamente (%d conexões à porta %d)", s.IP, s.Count, inc.LocalPort),
				map[string]any{"ip": s.IP, "reason": reason, "count": s.Count, "expires": time.Now().Add(time.Hour).Unix()})
		} else {
			log.Printf("bloquear %s: %s", s.IP, res.Message)
		}
	}
	if len(blocked) == 0 {
		return nil, "nenhum IP pôde ser bloqueado"
	}
	return blocked, fmt.Sprintf("%d IP(s) bloqueado(s) no firewall", len(blocked))
}

// protectedIPs são os endereços que a resposta a DDoS nunca bloqueia: o
// servidor (canal de gerência) e os IPs da própria máquina.
func protectedIPs(serverURL string) []string {
	var ips []string
	if u, err := url.Parse(serverURL); err == nil {
		if h := u.Hostname(); net.ParseIP(h) != nil {
			ips = append(ips, h)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ips = append(ips, ipn.IP.String())
			}
		}
	}
	return ips
}
