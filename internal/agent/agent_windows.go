package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"sentinela/internal/agent/collect"
	"sentinela/internal/agent/procmon"
	"sentinela/internal/agent/remediate"
	"sentinela/internal/model"
)

const (
	Version         = "0.1.0"
	ServiceName     = "Sentinela"
	DefaultInterval = 30 * time.Minute
	pollInterval    = 30 * time.Second
	maxSpool        = 10
)

type Config struct {
	ServerURL     string `json:"server_url"`
	Fingerprint   string `json:"fingerprint"`
	AgentID       string `json:"agent_id"`
	Secret        string `json:"secret"`
	CommandPubKey string `json:"command_pubkey"`
	Interval      string `json:"interval"`
}

// dataDir é C:\ProgramData\Sentinela na instalação normal, ou uma pasta do
// usuário no modo dev.
var dataDir = func() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Sentinela")
}()

func DataDir() string { return dataDir }

// hostSuffix diferencia o agente de desenvolvimento da máquina real no painel.
var hostSuffix = ""

func configPath() string { return filepath.Join(DataDir(), "config.json") }

// secureDir cria a pasta de dados acessível apenas por SYSTEM e
// Administradores (ela guarda o segredo do agente, backups e quarentena).
func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func loadConfig() (*Config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return nil, fmt.Errorf("agente não instalado (%w)", err)
	}
	var c Config
	return &c, json.Unmarshal(b, &c)
}

// ---------------------------------------------------------------------------
// Instalação

func Install(server, token, fingerprint string, interval time.Duration) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("execute como Administrador")
	}
	if err := secureDir(DataDir()); err != nil {
		return fmt.Errorf("criar pasta de dados: %w", err)
	}
	cl, err := NewClient(server, fingerprint)
	if err != nil {
		return err
	}
	host := collect.Host(Version)
	res, err := cl.Enroll(token, host.Hostname, host.OS)
	if err != nil {
		return fmt.Errorf("cadastro no servidor falhou: %w", err)
	}
	cfg := Config{
		ServerURL: server, Fingerprint: NormalizeFingerprint(fingerprint),
		AgentID: res.AgentID, Secret: res.Secret, CommandPubKey: res.CommandPubKey,
		Interval: interval.String(),
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath(), b, 0o600); err != nil {
		return err
	}

	// Copia o executável para Program Files.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dstDir := filepath.Join(os.Getenv("ProgramFiles"), "Sentinela")
	dst := filepath.Join(dstDir, "sentinela-agent.exe")
	if !strings.EqualFold(self, dst) {
		os.MkdirAll(dstDir, 0o755)
		if err := copyFile(self, dst); err != nil {
			return fmt.Errorf("copiar executável: %w", err)
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		return errors.New("o serviço já existe; rode 'uninstall' antes de reinstalar")
	}
	s, err := m.CreateService(ServiceName, dst, mgr.Config{
		DisplayName: "Sentinela - Agente de Segurança",
		Description: "Coleta inicialização automática, processos e conexões e envia ao servidor Sentinela.",
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)
	return s.Start()
}

// Dev roda o agente em primeiro plano, sem instalar serviço e sem exigir
// administrador, guardando os dados em %LOCALAPPDATA%\Sentinela-dev. Serve
// para desenvolver e acompanhar o agente ao vivo. Sem admin, a coleta fica
// parcial (ex.: tarefas agendadas) e remediações em HKLM falham.
func Dev(server, token, fingerprint string, interval time.Duration) error {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	dataDir = filepath.Join(base, "Sentinela-dev")
	hostSuffix = " (dev)"
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	fp := NormalizeFingerprint(fingerprint)
	cfg, err := loadConfig()
	if err != nil || cfg.ServerURL != server || cfg.Fingerprint != fp {
		cl, err := NewClient(server, fp)
		if err != nil {
			return err
		}
		host := collect.Host(Version)
		res, err := cl.Enroll(token, host.Hostname+hostSuffix, host.OS)
		if err != nil {
			return fmt.Errorf("cadastro no servidor falhou: %w", err)
		}
		cfg = &Config{ServerURL: server, Fingerprint: fp, AgentID: res.AgentID, Secret: res.Secret, CommandPubKey: res.CommandPubKey}
		fmt.Printf("Agente de desenvolvimento cadastrado (%s)\n", res.AgentID)
	}
	cfg.Interval = interval.String()
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath(), b, 0o600); err != nil {
		return err
	}
	fmt.Printf("Modo dev: dados em %s, varredura a cada %s. Ctrl+C para parar.\n", dataDir, interval)
	return RunForeground()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("serviço não encontrado: %w", err)
	}
	defer s.Close()
	s.Control(svc.Stop)
	// A pasta de dados (backups e quarentena) é mantida de propósito.
	return s.Delete()
}

// ---------------------------------------------------------------------------
// Execução

type service struct{}

func (service) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		if err := run(stop); err != nil {
			log.Printf("agente encerrado com erro: %v", err)
		}
		close(done)
	}()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		case <-done:
			return false, 1
		}
	}
}

func setupLog() {
	p := filepath.Join(DataDir(), "agent.log")
	if st, err := os.Stat(p); err == nil && st.Size() > 5<<20 {
		os.Rename(p, p+".1")
	}
	if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		log.SetOutput(f)
	}
}

func RunService() {
	setupLog()
	if err := svc.Run(ServiceName, service{}); err != nil {
		log.Printf("svc.Run: %v", err)
	}
}

func RunForeground() error {
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; close(stop) }()
	return run(stop)
}

type runner struct {
	cfg      *Config
	cl       *Client
	rem      *remediate.Remediator
	mu       sync.Mutex // uma varredura/ação por vez
	executed map[string]bool
}

func run(stop <-chan struct{}) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cl, err := NewClient(cfg.ServerURL, cfg.Fingerprint)
	if err != nil {
		return err
	}
	if err := cl.SetCredentials(cfg.AgentID, cfg.Secret, cfg.CommandPubKey); err != nil {
		return err
	}
	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil || interval < 30*time.Second {
		interval = DefaultInterval
	}
	r := &runner{
		cfg: cfg, cl: cl, executed: map[string]bool{},
		rem: &remediate.Remediator{DataDir: DataDir(), Entries: func() []collect.Entry {
			in := collect.NewInspector()
			defer in.Close()
			var errs []string
			return collect.Persistence(in, &errs)
		}},
	}
	log.Printf("Sentinela %s iniciado (agente %s, servidor %s, intervalo %s)", Version, cfg.AgentID, cfg.ServerURL, interval)
	elevated := windows.GetCurrentProcessToken().IsElevated()
	priv := "como administrador"
	if !elevated {
		priv = "SEM privilégios de administrador (coleta parcial)"
	}
	r.event("agent_started", fmt.Sprintf("Agente %s iniciado %s; varredura a cada %s", Version, priv, interval),
		map[string]any{"version": Version, "elevated": elevated, "interval": interval.String()})

	mon := procmon.Start()
	defer mon.Stop()
	if mon.Source == "etw" {
		r.event("procmon_started", "Monitor de execuções ativo via ETW em tempo real: "+mon.Mode, map[string]any{"source": "etw", "mode": mon.Mode})
	} else {
		r.event("procmon_started", "Monitor de execuções ativo via verificação a cada 1 s (sem ETW: "+mon.Reason+"); processos muito rápidos podem não ser vistos",
			map[string]any{"source": "poll", "reason": mon.Reason})
	}
	go r.telemetryLoop(mon, stop)

	r.scan("inicial")
	scanT := time.NewTicker(interval)
	pollT := time.NewTicker(pollInterval)
	defer scanT.Stop()
	defer pollT.Stop()
	for {
		select {
		case <-stop:
			log.Print("agente parado")
			r.event("agent_stopping", "Agente sendo encerrado", nil)
			return nil
		case <-scanT.C:
			r.scan("agendada")
		case <-pollT.C:
			r.poll()
		}
	}
}

// telemetryLoop envia as execuções em lotes a cada 2 s. Se o servidor
// estiver fora, guarda até 5.000 em memória (as mais antigas são
// descartadas e contadas).
func (r *runner) telemetryLoop(mon *procmon.Monitor, stop <-chan struct{}) {
	const maxBuf, maxBatch = 5000, 500
	var buf []model.ProcessEvent
	dropped := 0
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case e := <-mon.Events:
			buf = append(buf, e)
			if len(buf) > maxBuf {
				dropped += len(buf) - maxBuf
				buf = buf[len(buf)-maxBuf:]
			}
		case <-t.C:
			dropped += mon.Dropped()
			for len(buf) > 0 || dropped > 0 {
				n := min(len(buf), maxBatch)
				b := &model.TelemetryBatch{Processes: buf[:n], Dropped: dropped}
				if err := r.cl.SendTelemetry(b); err != nil {
					log.Printf("telemetria: %v (%d execuções aguardando)", err, len(buf))
					break
				}
				buf, dropped = buf[n:], 0
			}
		}
	}
}

func spoolDir() string { return filepath.Join(DataDir(), "spool") }

// event informa o servidor (melhor esforço: falhas só vão para o log).
func (r *runner) event(kind, msg string, data map[string]any) {
	if err := r.cl.Event(kind, msg, data); err != nil {
		log.Printf("evento %s não enviado: %v", kind, err)
	}
}

var phaseText = map[string]string{
	"inicializacao": "Inicialização automática analisada: %d entradas (%.1f s)",
	"processos":     "Processos analisados: %d em execução (%.1f s)",
	"rede":          "Conexões de rede coletadas: %d (%.1f s)",
}

func (r *runner) scan(trigger string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.event("scan_started", "Varredura iniciada ("+trigger+")", map[string]any{"trigger": trigger})
	rep, _ := collect.Scan(trigger, Version, func(phase string, n int, took time.Duration) {
		r.event("scan_phase", fmt.Sprintf(phaseText[phase], n, took.Seconds()),
			map[string]any{"phase": phase, "count": n, "ms": took.Milliseconds()})
	})
	rep.Host.Hostname += hostSuffix
	log.Printf("varredura %s: %d autoruns, %d processos, %d conexões em %dms",
		trigger, len(rep.Autoruns), len(rep.Processes), len(rep.Connections), rep.DurationMS)
	data, err := GzipReport(rep)
	if err != nil {
		log.Printf("serializar relatório: %v", err)
		return
	}
	r.flushSpool()
	if err := r.cl.SendReportGz(data); err != nil {
		log.Printf("envio falhou, guardando no spool: %v", err)
		r.spool(data)
		r.event("scan_spooled", "Falha ao enviar o relatório; guardado para reenvio: "+err.Error(), nil)
		return
	}
	r.event("scan_sent", fmt.Sprintf("Relatório enviado (%d KB compactado)", len(data)/1024), map[string]any{"bytes": len(data)})
}

// spool guarda relatórios não enviados (servidor fora do ar) para reenvio.
func (r *runner) spool(data []byte) {
	os.MkdirAll(spoolDir(), 0o700)
	name := filepath.Join(spoolDir(), fmt.Sprintf("%d.json.gz", time.Now().UnixNano()))
	os.WriteFile(name, data, 0o600)
	files, _ := filepath.Glob(filepath.Join(spoolDir(), "*.json.gz"))
	sort.Strings(files)
	for len(files) > maxSpool {
		os.Remove(files[0])
		files = files[1:]
	}
}

func (r *runner) flushSpool() {
	files, _ := filepath.Glob(filepath.Join(spoolDir(), "*.json.gz"))
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if err := r.cl.SendReportGz(data); err != nil {
			return
		}
		os.Remove(f)
	}
}

func (r *runner) poll() {
	cmds, err := r.cl.PollCommands()
	if err != nil {
		log.Printf("buscar comandos: %v", err)
		return
	}
	for _, c := range cmds {
		if r.executed[c.ID] {
			continue
		}
		r.executed[c.ID] = true
		p, err := r.cl.Verify(c)
		if err != nil {
			log.Printf("comando %s rejeitado: %v", c.ID, err)
			r.event("command_rejected", "Comando REJEITADO pelo agente: "+err.Error(), map[string]any{"command_id": c.ID})
			r.cl.SendResult(c.ID, model.CommandResult{OK: false, Message: "rejeitado pelo agente: " + err.Error()})
			continue
		}
		log.Printf("executando comando %s: %s %v", p.ID, p.Action, p.Params)
		r.event("command_executing", "Assinatura do comando verificada; executando "+p.Action,
			map[string]any{"command_id": p.ID, "action": p.Action})

		if p.Action == model.ActionRescan {
			r.cl.SendResult(p.ID, model.CommandResult{OK: true, Message: "varredura iniciada"})
			r.scan("manual")
			continue
		}
		r.mu.Lock()
		res := r.rem.Execute(*p)
		r.mu.Unlock()
		log.Printf("resultado %s: ok=%v %s", p.ID, res.OK, res.Message)
		if err := r.cl.SendResult(p.ID, res); err != nil {
			log.Printf("enviar resultado: %v", err)
		}
		// "Verificação posterior": após qualquer remediação bem-sucedida,
		// uma nova varredura confirma se a ameaça foi removida.
		if res.OK {
			r.scan("pos-remediacao")
		}
	}
}
