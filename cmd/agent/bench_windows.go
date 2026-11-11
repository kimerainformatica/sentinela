package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"sentinela/internal/agent"
	"sentinela/internal/agent/collect"
	"sentinela/internal/agent/procmon"
	"sentinela/internal/model"
)

// cmdBench mede o custo de processamento de cada parte do agente:
// varredura completa (primeira vez e com cache) e monitor em tempo real.
func cmdBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	n := fs.Int("n", 3, "número de varreduras (a primeira sem cache)")
	live := fs.Duration("live", 0, "também mede o monitor em tempo real por este tempo (ex.: 30s)")
	fs.Parse(args)

	fmt.Printf("Sentinela %s — medição de custo (%d núcleos, admin=%v)\n",
		agent.Version, runtime.NumCPU(), collect.Host("").IsElevated)

	in := collect.NewInspector()
	defer in.Close()
	for i := 1; i <= *n; i++ {
		label := "com cache"
		if i == 1 {
			label = "sem cache (primeira análise de cada arquivo)"
		}
		rep, _ := collect.ScanWith(in, "manual", agent.Version, nil)
		fmt.Printf("\n=== Varredura %d de %d — %s ===\n", i, *n, label)
		printScanPerf(rep)
	}

	if *live > 0 {
		benchLive(*live)
	}
}

func printScanPerf(rep *model.Report) {
	p := rep.Perf
	fmt.Printf("Tempo total %.0f ms · CPU do agente %.0f ms (%.0f%% de 1 núcleo) · memória %.0f MB\n",
		p.WallMS, p.CPUMS, 100*p.CPUMS/max(p.WallMS, 1), p.MemMB)
	fmt.Println("  Fase                  Itens    Tempo")
	for _, ph := range p.Phases {
		fmt.Printf("  %-20s %6d %8.0f ms\n", ph.Phase, ph.Count, ph.MS)
	}
	printInspect(p.Inspect)
}

func printInspect(ip model.InspectPerf) {
	hitPct := 0.0
	if ip.Lookups > 0 {
		hitPct = 100 * float64(ip.CacheHits) / float64(ip.Lookups)
	}
	fmt.Printf("  Análise de arquivos: %d pedidos, %d no cache (%.0f%%), %d analisados\n",
		ip.Lookups, ip.CacheHits, hitPct, ip.Lookups-ip.CacheHits)
	total := 0.0
	for _, c := range ip.Ops {
		total += c.MS
	}
	if total == 0 {
		return
	}
	fmt.Println("  Operação       Vezes    Total     Média   % do tempo   Dados")
	for _, op := range collect.OpOrder() {
		c, ok := ip.Ops[op]
		if !ok {
			continue
		}
		data := ""
		if c.Bytes > 0 {
			mb := float64(c.Bytes) / (1 << 20)
			data = fmt.Sprintf("%.0f MB (%.0f MB/s)", mb, mb/max(c.MS/1000, 0.001))
		}
		fmt.Printf("  %-12s %7d %7.0f ms %7.2f ms %8.1f%%   %s\n",
			op, c.Count, c.MS, c.MS/float64(c.Count), 100*c.MS/total, data)
	}
	if len(ip.Slowest) > 0 {
		fmt.Println("  Arquivos mais demorados:")
		for i, f := range ip.Slowest {
			if i == 5 {
				break
			}
			fmt.Printf("    %7.0f ms  %s\n", f.MS, f.Path)
		}
	}
}

func benchLive(d time.Duration) {
	fmt.Printf("\n=== Monitor em tempo real por %s ===\n", d)
	cpu0, t0 := collect.SelfCPU(), time.Now()
	m := procmon.Start()
	defer m.Stop()
	src := m.Source
	if m.Mode != "" {
		src += " (" + m.Mode + ")"
	}
	fmt.Printf("Execuções: %s · Rede: %s\n", src, m.NetSource)
	var procs, nets int
	names := map[string]int{}
	deadline := time.After(d)
loop:
	for {
		select {
		case e := <-m.Events:
			procs++
			names[strings.ToLower(e.Name)]++
		case <-m.NetEvents:
			nets++
		case <-deadline:
			break loop
		}
	}
	wall := time.Since(t0)
	cpu := collect.SelfCPU() - cpu0
	fmt.Printf("CPU do agente: %.0f ms em %.0f s = %.2f%% de 1 núcleo · memória %.0f MB\n",
		float64(cpu.Milliseconds()), wall.Seconds(), 100*cpu.Seconds()/wall.Seconds(), collect.SelfMemMB())
	fmt.Printf("Eventos: %d execuções, %d conexões (%.1f/s)\n", procs, nets, float64(procs+nets)/wall.Seconds())
	if st := m.Stats(); st.ProcEvents > 0 {
		fmt.Printf("Tempo médio para analisar uma execução: %.2f ms\n", st.EnrichAvgMS)
		printInspect(st.Inspect)
	}
	if len(os.Args) > 0 && procs == 0 {
		fmt.Println("(nenhuma execução no período — abra alguns programas durante a medição)")
	}
}
