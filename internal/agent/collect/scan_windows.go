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
//
// progress (opcional) é chamado ao fim de cada fase, para acompanhamento
// em tempo real.
func Scan(trigger, agentVersion string, progress func(phase string, count int, took time.Duration)) (*model.Report, []Entry) {
	in := NewInspector()
	defer in.Close()
	return ScanWith(in, trigger, agentVersion, progress)
}

// ScanWith usa um Inspector já existente: o agente mantém o mesmo entre
// varreduras, e arquivos que não mudaram não são analisados de novo.
func ScanWith(in *Inspector, trigger, agentVersion string, progress func(phase string, count int, took time.Duration)) (*model.Report, []Entry) {
	if progress == nil {
		progress = func(string, int, time.Duration) {}
	}
	// Prioridade baixa de CPU e disco: a varredura não deve atrapalhar o usuário.
	defer Background()()
	start := time.Now()
	cpu0 := SelfCPU()
	in.TakePerf() // mede só esta varredura
	perf := &model.ScanPerf{}
	phase := func(name string, n int, took time.Duration) {
		perf.Phases = append(perf.Phases, model.PhaseCost{Phase: name, Count: n, MS: float64(took.Microseconds()) / 1000})
		progress(name, n, took)
	}

	rep := &model.Report{Schema: model.SchemaVersion, CollectedAt: start.UTC(), Trigger: trigger}
	rep.Host = Host(agentVersion)
	if !rep.Host.IsElevated {
		rep.Errors = append(rep.Errors, "agente sem privilégios de administrador: a coleta ficará incompleta")
	}

	t := time.Now()
	entries := Persistence(in, &rep.Errors)
	for _, e := range entries {
		rep.Autoruns = append(rep.Autoruns, e.Autorun)
	}
	phase("inicializacao", len(rep.Autoruns), time.Since(t))

	t = time.Now()
	rep.Processes = Processes(in, &rep.Errors)
	phase("processos", len(rep.Processes), time.Since(t))

	t = time.Now()
	names := map[uint32]string{}
	for _, p := range rep.Processes {
		names[p.PID] = p.Name
	}
	rep.Connections = Connections(names, &rep.Errors)
	phase("rede", len(rep.Connections), time.Since(t))

	rep.DurationMS = time.Since(start).Milliseconds()
	perf.WallMS = float64(time.Since(start).Microseconds()) / 1000
	perf.CPUMS = float64((SelfCPU() - cpu0).Microseconds()) / 1000
	perf.MemMB = SelfMemMB()
	perf.Inspect = in.TakePerf()
	rep.Perf = perf
	return rep, entries
}

func Host(agentVersion string) model.HostInfo {
	h := model.HostInfo{AgentVer: agentVersion}
	h.Hostname, _ = os.Hostname()
	h.IsElevated = windows.GetCurrentProcessToken().IsElevated()
	if exe, err := os.Executable(); err == nil {
		h.AgentSHA256, _ = hashFile(exe)
	}

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
