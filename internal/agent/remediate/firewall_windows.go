package remediate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/model"
)

// Resposta a DDoS de entrada: bloqueio de IPs de origem no Firewall do
// Windows. Reversível (a regra pode ser removida) e temporário (cada bloqueio
// tem validade; expirados são removidos sozinhos), para não deixar um IP
// legítimo bloqueado para sempre por engano.

const (
	rulewPrefix    = "Sentinela-block-" // prefixo das regras no firewall
	defaultBlockMin = 60
	maxBlockMin     = 24 * 60
)

type blockMeta struct {
	IP      string    `json:"ip"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Reason  string    `json:"reason,omitempty"`
}

func ruleName(ip string) string { return rulewPrefix + ip }

func blockFile(dir, ip string) string {
	safe := strings.NewReplacer(":", "_", ".", "_", "/", "_").Replace(ip)
	return filepath.Join(dir, safe+".json")
}

// blockableIP valida o IP e recusa o que nunca se deve bloquear (localhost,
// faixas especiais e os IPs protegidos, como o do próprio servidor).
func (r *Remediator) blockableIP(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("IP inválido: %q", s)
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return nil, errors.New("este endereço não pode ser bloqueado (local ou reservado)")
	}
	for _, p := range r.ProtectIPs {
		if strings.EqualFold(strings.TrimSpace(p), s) {
			return nil, errors.New("endereço protegido (servidor ou a própria máquina); bloqueio recusado")
		}
	}
	return ip, nil
}

func (r *Remediator) blockIP(ipStr, minutesStr, reason string) model.CommandResult {
	ip, err := r.blockableIP(ipStr)
	if err != nil {
		return fail(err)
	}
	canon := ip.String()
	minutes := defaultBlockMin
	if minutesStr != "" {
		if m, err := strconv.Atoi(minutesStr); err == nil && m > 0 {
			minutes = min(m, maxBlockMin)
		}
	}
	name := ruleName(canon)
	// Remove uma regra anterior de mesmo nome (renova o bloqueio) e cria.
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name, "dir=in", "action=block", "remoteip="+canon).CombinedOutput()
	if err != nil {
		return fail(fmt.Errorf("firewall: %v: %s", err, strings.TrimSpace(string(out))))
	}
	meta := blockMeta{IP: canon, Created: time.Now().UTC(),
		Expires: time.Now().Add(time.Duration(minutes) * time.Minute).UTC(), Reason: reason}
	data, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(blockFile(r.dir("blocks"), canon), data, 0o600)
	return ok(fmt.Sprintf("IP %s bloqueado no firewall por %d min", canon, minutes), canon)
}

func (r *Remediator) unblockIP(ipStr string) model.CommandResult {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fail(fmt.Errorf("IP inválido: %q", ipStr))
	}
	canon := ip.String()
	out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName(canon)).CombinedOutput()
	os.Remove(blockFile(r.dir("blocks"), canon))
	if err != nil {
		// netsh devolve erro quando a regra já não existe: tratamos como sucesso.
		return ok(fmt.Sprintf("IP %s desbloqueado (regra já não existia: %s)", canon, strings.TrimSpace(string(out))), "")
	}
	return ok(fmt.Sprintf("IP %s desbloqueado", canon), "")
}

// ActiveBlocks lê os bloqueios registrados.
func (r *Remediator) ActiveBlocks() []model.FirewallBlock {
	dir := r.dir("blocks")
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	var out []model.FirewallBlock
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var m blockMeta
		if json.Unmarshal(data, &m) == nil && m.IP != "" {
			out = append(out, model.FirewallBlock{IP: m.IP, Created: m.Created, Expires: m.Expires, Reason: m.Reason})
		}
	}
	return out
}

// ExpireBlocks remove do firewall os bloqueios vencidos e devolve os IPs.
func (r *Remediator) ExpireBlocks() []string {
	var removed []string
	for _, b := range r.ActiveBlocks() {
		if time.Now().After(b.Expires) {
			r.unblockIP(b.IP)
			removed = append(removed, b.IP)
		}
	}
	return removed
}
