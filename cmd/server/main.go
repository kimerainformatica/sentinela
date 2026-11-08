// Servidor central Sentinela: API dos agentes + painel web.
//
//	sentinela-server [-addr :8443] [-data ./data] [-host nome1,ip2]
//	sentinela-server -reset-admin     gera nova senha do administrador
//	sentinela-server -rotate-token    gera novo token de cadastro de agentes
//
// Variáveis de ambiente opcionais:
//
//	SENTINELA_VT_KEY         chave da API do VirusTotal
//	SENTINELA_ABUSEIPDB_KEY  chave da API do AbuseIPDB
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"sentinela/internal/server"
	"sentinela/web"
)

func main() {
	addr := flag.String("addr", ":8443", "endereço de escuta HTTPS")
	data := flag.String("data", "data", "pasta de dados (banco, certificado, chaves)")
	hosts := flag.String("host", "", "nomes/IPs extras para o certificado, separados por vírgula")
	resetAdmin := flag.Bool("reset-admin", false, "gera uma nova senha para o usuário admin e sai")
	rotate := flag.Bool("rotate-token", false, "gera um novo token de cadastro de agentes e sai")
	flag.Parse()

	var extra []string
	for _, h := range strings.Split(*hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			extra = append(extra, h)
		}
	}

	s, initialPw, err := server.New(server.Config{
		Addr: *addr, DataDir: *data, Hosts: extra, Web: web.FS(),
		Intel: server.IntelConfig{
			VTKey:        os.Getenv("SENTINELA_VT_KEY"),
			AbuseIPDBKey: os.Getenv("SENTINELA_ABUSEIPDB_KEY"),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case *resetAdmin:
		fmt.Println("Nova senha do usuário admin:", s.ResetAdminPassword())
		return
	case *rotate:
		fmt.Println("Novo token de cadastro:", s.RotateEnrollToken())
		return
	}

	port := *addr
	if i := strings.LastIndex(port, ":"); i >= 0 {
		port = port[i+1:]
	}
	fmt.Println("================================================================")
	fmt.Println(" Sentinela - servidor central")
	fmt.Println("================================================================")
	fmt.Printf(" Painel:            https://localhost:%s\n", port)
	fmt.Printf(" Certificado (SHA-256):\n   %s\n", server.FormatFingerprint(s.Fingerprint))
	fmt.Printf(" Token de cadastro: %s\n", s.EnrollToken)
	if initialPw != "" {
		fmt.Println("----------------------------------------------------------------")
		fmt.Println(" PRIMEIRA EXECUÇÃO - anote a senha inicial (não será exibida de novo):")
		fmt.Printf("   usuário: admin   senha: %s\n", initialPw)
	}
	fmt.Println("----------------------------------------------------------------")
	fmt.Println(" Instalar o agente em uma máquina (PowerShell como Administrador):")
	fmt.Printf("   .\\sentinela-agent.exe install -server https://<IP-DESTE-SERVIDOR>:%s `\n", port)
	fmt.Printf("     -token %s `\n     -fingerprint %s\n", s.EnrollToken, s.Fingerprint)
	fmt.Println("================================================================")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
