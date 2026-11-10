// Agente Sentinela para Windows.
//
//	sentinela-agent scan [-out arquivo.json]       varredura local, sem servidor
//	sentinela-agent install -server URL -token T -fingerprint FP [-interval 30m]
//	sentinela-agent uninstall
//	sentinela-agent run                             executa em primeiro plano (debug)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"

	"sentinela/internal/agent"
	"sentinela/internal/agent/collect"
)

func usage() {
	fmt.Fprintln(os.Stderr, `uso:
  sentinela-agent scan [-out relatorio.json]
  sentinela-agent install -server https://HOST:8443 -token TOKEN -fingerprint SHA256 [-interval 30m]
  sentinela-agent uninstall
  sentinela-agent run
  sentinela-agent dev -token TOKEN -fingerprint SHA256 [-server URL] [-interval 2m]
      (desenvolvimento: roda em primeiro plano, sem serviço e sem exigir admin)`)
	os.Exit(2)
}

func main() {
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		agent.RunService()
		return
	}
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "install":
		cmdInstall(os.Args[2:])
	case "uninstall":
		if err := agent.Uninstall(); err != nil {
			fatal(err)
		}
		fmt.Println("Serviço removido.")
	case "run":
		if err := agent.RunForeground(); err != nil {
			fatal(err)
		}
	case "dev":
		fs := flag.NewFlagSet("dev", flag.ExitOnError)
		server := fs.String("server", "https://127.0.0.1:8443", "URL do servidor")
		token := fs.String("token", "", "token de cadastro")
		fp := fs.String("fingerprint", "", "impressão digital SHA-256 do certificado do servidor")
		interval := fs.Duration("interval", 2*time.Minute, "intervalo entre varreduras")
		fs.Parse(os.Args[2:])
		if *token == "" || *fp == "" {
			usage()
		}
		if err := agent.Dev(*server, *token, *fp, *interval); err != nil {
			fatal(err)
		}
	default:
		usage()
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "erro:", err)
	os.Exit(1)
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	out := fs.String("out", "", "grava o relatório completo em JSON")
	fs.Parse(args)

	rep, _ := collect.Scan("manual", agent.Version, func(phase string, n int, took time.Duration) {
		fmt.Fprintf(os.Stderr, "  %-14s %4d itens em %.1fs\n", phase, n, took.Seconds())
	})
	fmt.Printf("Host: %s (%s, build %s)  admin=%v  duração=%dms\n",
		rep.Host.Hostname, rep.Host.OS, rep.Host.OSBuild, rep.Host.IsElevated, rep.DurationMS)

	byCat := map[string]int{}
	unsigned := 0
	for _, a := range rep.Autoruns {
		byCat[a.Category]++
		if a.File != nil && a.File.Exists && a.File.Signature != "valid" {
			unsigned++
		}
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	fmt.Printf("\nInicialização automática: %d entradas (%d com executável sem assinatura válida)\n", len(rep.Autoruns), unsigned)
	for _, c := range cats {
		fmt.Printf("  %-24s %d\n", c, byCat[c])
	}

	fmt.Printf("\nEntradas fora da Microsoft ou sem assinatura válida:\n")
	for _, a := range rep.Autoruns {
		f := a.File
		if f != nil && f.Signature == "valid" && strings.HasPrefix(f.Signer, "Microsoft") {
			continue
		}
		sig, signer := "-", ""
		if f != nil {
			sig, signer = f.Signature, f.Signer
			if !f.Exists {
				sig = "arquivo não encontrado"
			}
		}
		fmt.Printf("  [%s] %s\n      %s\n      assinatura=%s %s\n", a.Category, a.Name, a.ImagePath, sig, signer)
	}

	est := 0
	for _, c := range rep.Connections {
		if c.State == "ESTABLISHED" {
			est++
		}
	}
	fmt.Printf("\nProcessos: %d   Conexões: %d (%d estabelecidas)\n", len(rep.Processes), len(rep.Connections), est)
	if len(rep.Errors) > 0 {
		fmt.Printf("\nAvisos (%d):\n", len(rep.Errors))
		for i, e := range rep.Errors {
			if i == 10 {
				fmt.Printf("  ... e mais %d\n", len(rep.Errors)-10)
				break
			}
			fmt.Println("  -", e)
		}
	}
	if *out != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*out, b, 0o600); err != nil {
			fatal(err)
		}
		fmt.Println("\nRelatório salvo em", *out)
	}
}

func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	server := fs.String("server", "", "URL do servidor, ex.: https://192.168.0.10:8443")
	token := fs.String("token", "", "token de cadastro exibido pelo servidor")
	fp := fs.String("fingerprint", "", "impressão digital SHA-256 do certificado do servidor")
	interval := fs.Duration("interval", agent.DefaultInterval, "intervalo entre varreduras")
	fs.Parse(args)
	if *server == "" || *token == "" || *fp == "" {
		usage()
	}
	if err := agent.Install(*server, *token, *fp, *interval); err != nil {
		fatal(err)
	}
	fmt.Println("Agente cadastrado e serviço 'Sentinela' iniciado.")
}
