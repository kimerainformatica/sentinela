package collect

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"sentinela/internal/model"
)

// Scan executa a varredura completa, na mesma ordem do procedimento manual:
// inicialização automática -> processos -> conexões de rede.
// Retorna também as entradas internas (com dados de remediação).
func Scan(trigger, agentVersion string) (*model.Report, []Entry) {
	start := time.Now()
	rep := &model.Report{Schema: model.SchemaVersion, CollectedAt: start.UTC(), Trigger: trigger}
	rep.Host = Host(agentVersion)
	if !rep.Host.IsElevated {
		rep.Errors = append(rep.Errors, "agente sem privilégios de administrador: a coleta ficará incompleta")
	}

	in := NewInspector()
	defer in.Close()

	entries := Persistence(in, &rep.Errors)
	for _, e := range entries {
		rep.Autoruns = append(rep.Autoruns, e.Autorun)
	}
	rep.Processes = Processes(in, &rep.Errors)

	names := map[uint32]string{}
	for _, p := range rep.Processes {
		names[p.PID] = p.Name
	}
	rep.Connections = Connections(names, &rep.Errors)
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep, entries
}

func Host(agentVersion string) model.HostInfo {
	h := model.HostInfo{AgentVer: agentVersion}
	h.Hostname, _ = os.Hostname()
	h.IsElevated = windows.GetCurrentProcessToken().IsElevated()

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		name, _, _ := k.GetStringValue("ProductName")
		disp, _, _ := k.GetStringValue("DisplayVersion")
		build, _, _ := k.GetStringValue("CurrentBuild")
		ubr, _, _ := k.GetIntegerValue("UBR")
		k.Close()
		// O registro do Windows 11 ainda diz "Windows 10" no ProductName.
		if b, _ := strconv.Atoi(build); b >= 22000 {
			name = strings.Replace(name, "Windows 10", "Windows 11", 1)
		}
		h.OS = strings.TrimSpace(name + " " + disp)
		h.OSBuild = fmt.Sprintf("%s.%d", build, ubr)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
		h.Domain, _, _ = k.GetStringValue("Domain")
		k.Close()
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				h.IPs = append(h.IPs, ipn.IP.String())
			}
		}
	}
	return h
}
