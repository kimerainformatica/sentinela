// Package model define o contrato de dados entre agente e servidor.
//
// O relatório (Report) é um "snapshot" do endpoint e espelha o procedimento
// manual documentado no relatório técnico (Autoruns + VirusTotal + netstat):
//
//	Autoruns          -> Report.Autoruns
//	Análise processos -> Report.Processes
//	Propriedades arq. -> FileInfo (local, nome, fabricante, data de criação, assinatura)
//	netstat -ano      -> Report.Connections
package model

import "time"

const SchemaVersion = 1

// FileInfo reúne as "informações dos arquivos" verificadas manualmente no
// procedimento: localização, nome, fabricante, data de criação e propriedades.
type FileInfo struct {
	Path     string    `json:"path"`
	Exists   bool      `json:"exists"`
	Size     int64     `json:"size,omitempty"`
	SHA256   string    `json:"sha256,omitempty"`
	Created  time.Time `json:"created,omitempty"`
	Modified time.Time `json:"modified,omitempty"`

	// Assinatura digital (Authenticode embutida ou via catálogo do Windows).
	// valid | unsigned | invalid | error
	Signature string `json:"signature,omitempty"`
	Signer    string `json:"signer,omitempty"`
	// true quando a assinatura foi validada através de um catálogo (.cat),
	// como acontece com a maioria dos binários do próprio Windows.
	CatalogSigned bool `json:"catalog_signed,omitempty"`

	// Recurso de versão (aba "Detalhes" das propriedades do arquivo).
	Company          string `json:"company,omitempty"`
	Product          string `json:"product,omitempty"`
	Description      string `json:"description,omitempty"`
	OriginalFilename string `json:"original_filename,omitempty"`

	// Atributos relevantes do arquivo: oculto, sistema, somente-leitura.
	Attributes []string `json:"attributes,omitempty"`
	// Origem (Mark of the Web): de onde o arquivo foi baixado, gravado pelo
	// navegador, cliente de e-mail ou descompactador.
	Origin *FileOrigin `json:"origin,omitempty"`
	// Estrutura do executável. Analisada só para arquivos sem assinatura
	// válida (os assinados já têm a integridade garantida pela assinatura).
	PE *PEInfo `json:"pe,omitempty"`

	Error string `json:"error,omitempty"`
}

// Autorun é uma entrada de inicialização automática (equivalente a uma linha
// do Autoruns).
type Autorun struct {
	// ID estável (hash de categoria+local+nome) usado para remediação.
	ID        string `json:"id"`
	Category  string `json:"category"`   // Logon, Serviços, Drivers, Tarefas Agendadas, ...
	Location  string `json:"location"`   // chave de registro, pasta ou caminho da tarefa
	Name      string `json:"name"`       // nome do valor / serviço / tarefa / atalho
	Command   string `json:"command"`    // linha de comando bruta
	ImagePath string `json:"image_path"` // executável resolvido
	Enabled   bool   `json:"enabled"`
	User      string `json:"user,omitempty"` // para entradas por usuário (HKU / pasta Startup)

	File *FileInfo `json:"file,omitempty"`
	// Payload é o arquivo realmente executado quando o comando usa um
	// "hospedeiro" (rundll32, regsvr32, wscript, mshta, powershell...).
	Payload *FileInfo `json:"payload,omitempty"`
}

type Process struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	ImagePath   string    `json:"image_path,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	User        string    `json:"user,omitempty"`
	Started     time.Time `json:"started,omitempty"`
	File        *FileInfo `json:"file,omitempty"`
}

// Connection equivale a uma linha do `netstat -ano`, enriquecida com o
// processo dono.
type Connection struct {
	Proto       string `json:"proto"` // TCP, TCP6, UDP, UDP6
	LocalAddr   string `json:"local_addr"`
	LocalPort   uint16 `json:"local_port"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	RemotePort  uint16 `json:"remote_port,omitempty"`
	State       string `json:"state,omitempty"`
	PID         uint32 `json:"pid"`
	ProcessName string `json:"process_name,omitempty"`
}

type HostInfo struct {
	Hostname   string   `json:"hostname"`
	OS         string   `json:"os"`
	OSBuild    string   `json:"os_build"`
	Domain     string   `json:"domain,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	AgentVer   string   `json:"agent_version"`
	IsElevated bool     `json:"is_elevated"`
	// SHA-256 do executável do próprio agente: o servidor não gera
	// achados heurísticos sobre ele (ele não é assinado no MVP).
	AgentSHA256 string `json:"agent_sha256,omitempty"`
}

type Report struct {
	Schema      int          `json:"schema"`
	CollectedAt time.Time    `json:"collected_at"`
	DurationMS  int64        `json:"duration_ms"`
	Trigger     string       `json:"trigger"` // agendada | manual | pos-remediacao | inicial
	Host        HostInfo     `json:"host"`
	Autoruns    []Autorun    `json:"autoruns"`
	Processes   []Process    `json:"processes"`
	Connections []Connection `json:"connections"`
	Errors      []string     `json:"errors,omitempty"`
	// Custo de processamento da varredura (tempo por fase e por operação).
	Perf *ScanPerf `json:"perf,omitempty"`
}

// ---------------------------------------------------------------------------
// Telemetria em tempo real

// ProcessEvent é a execução de um programa, capturada no momento em que
// acontece (ETW ou verificação a cada segundo).
type ProcessEvent struct {
	Time        time.Time `json:"time"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	ImagePath   string    `json:"image_path,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	User        string    `json:"user,omitempty"`
	ParentName  string    `json:"parent_name,omitempty"`
	ParentImage string    `json:"parent_image,omitempty"`
	File        *FileInfo `json:"file,omitempty"`
	// etw = evento do kernel (captura até processos de milissegundos);
	// poll = verificação periódica (modo sem administrador).
	Source string `json:"source"`
	// true quando o processo já tinha terminado ao ser analisado (só o
	// caminho veio do evento; linha de comando e usuário ficam vazios).
	Exited bool `json:"exited,omitempty"`
	// true quando o processo existe mas o agente não tem permissão para
	// abri-lo (processo protegido ou de outro usuário, agente sem admin).
	Restricted bool `json:"restricted,omitempty"`
}

// NetEvent é uma conexão TCP aberta (saída) ou aceita (entrada), capturada
// no momento em que acontece.
type NetEvent struct {
	Time        time.Time `json:"time"`
	PID         uint32    `json:"pid"`
	ProcessName string    `json:"process_name,omitempty"`
	ImagePath   string    `json:"image_path,omitempty"`
	Direction   string    `json:"direction"` // saida | entrada
	Proto       string    `json:"proto"`     // TCP | TCP6
	LocalAddr   string    `json:"local_addr"`
	LocalPort   uint16    `json:"local_port"`
	RemoteAddr  string    `json:"remote_addr"`
	RemotePort  uint16    `json:"remote_port"`
	File        *FileInfo `json:"file,omitempty"`
	Source      string    `json:"source"` // etw | poll
	// Quantas vezes a mesma conexão (processo -> destino) se repetiu desde
	// o último envio (o agente agrupa repetições por 10 minutos).
	Repeats int `json:"repeats,omitempty"`
}

type TelemetryBatch struct {
	Processes   []ProcessEvent `json:"processes"`
	Connections []NetEvent     `json:"connections,omitempty"`
	// Eventos descartados no agente por excesso de volume.
	Dropped int `json:"dropped,omitempty"`
}

// ---------------------------------------------------------------------------
// Enrollment e comandos

type EnrollRequest struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type EnrollResponse struct {
	AgentID string `json:"agent_id"`
	Secret  string `json:"secret"`
	// Chave pública Ed25519 (base64) usada pelo agente para verificar a
	// assinatura dos comandos de remediação.
	CommandPubKey string `json:"command_pubkey"`
}

// Ações de remediação permitidas (allowlist). Qualquer outra é recusada.
const (
	ActionRescan         = "rescan"
	ActionKillProcess    = "kill_process"
	ActionDisableAutorun = "disable_autorun"
	ActionRestoreAutorun = "restore_autorun"
	ActionQuarantineFile = "quarantine_file"
	ActionRestoreFile    = "restore_file"
)

// Command é assinado pelo servidor. Payload contém o JSON canônico de
// CommandPayload e Signature é a assinatura Ed25519 desse payload.
type Command struct {
	ID        string `json:"id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type CommandPayload struct {
	ID        string            `json:"id"`
	AgentID   string            `json:"agent_id"`
	Action    string            `json:"action"`
	Params    map[string]string `json:"params"`
	ExpiresAt time.Time         `json:"expires_at"`
}

type CommandResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Para ações reversíveis: identificador do backup / quarentena.
	UndoID string `json:"undo_id,omitempty"`
}

// FileOrigin vem do fluxo alternativo Zone.Identifier.
type FileOrigin struct {
	Zone     int    `json:"zone"` // 0 local, 1 intranet, 2 confiável, 3 internet, 4 não confiável
	ZoneName string `json:"zone_name"`
	HostURL  string `json:"host_url,omitempty"`     // endereço do download
	Referrer string `json:"referrer_url,omitempty"` // página de onde veio o link
}

// PEInfo resume o cabeçalho de um executável Windows (PE).
type PEInfo struct {
	IsPE       bool       `json:"is_pe"`
	Machine    string     `json:"machine,omitempty"` // x64 | x86 | ARM64
	DLL        bool       `json:"dll,omitempty"`
	Compiled   *time.Time `json:"compiled,omitempty"` // data de compilação declarada (omitida se implausível: builds reprodutíveis gravam um hash)
	Sections   []string   `json:"sections,omitempty"`
	MaxEntropy float64    `json:"max_entropy"`       // maior entropia entre as seções executáveis (0 a 8)
	Packer     string     `json:"packer,omitempty"`  // empacotador identificado (UPX, Themida...)
	Packed     bool       `json:"packed,omitempty"`  // empacotado/cifrado (oculta o código real)
	Overlay    int64      `json:"overlay,omitempty"` // bytes após a última seção
}

// ---------------------------------------------------------------------------
// Custo de processamento

// OpCost é o custo acumulado de uma operação (ex.: calcular SHA-256).
type OpCost struct {
	Count int64   `json:"count"`
	MS    float64 `json:"ms"`
	Bytes int64   `json:"bytes,omitempty"`
}

// SlowFile é um dos arquivos que mais demoraram para ser analisados.
type SlowFile struct {
	Path string  `json:"path"`
	MS   float64 `json:"ms"`
}

// InspectPerf mede a análise de arquivos (hash, assinatura, versão...).
type InspectPerf struct {
	Lookups   int64             `json:"lookups"`    // pedidos de análise
	CacheHits int64             `json:"cache_hits"` // respondidos pelo cache
	Ops       map[string]OpCost `json:"ops"`
	Slowest   []SlowFile        `json:"slowest,omitempty"`
}

// PhaseCost é o tempo de uma fase da varredura.
type PhaseCost struct {
	Phase string  `json:"phase"`
	Count int     `json:"count"`
	MS    float64 `json:"ms"`
}

// ScanPerf é o custo de uma varredura.
type ScanPerf struct {
	WallMS  float64     `json:"wall_ms"`
	CPUMS   float64     `json:"cpu_ms"` // CPU do processo do agente durante a varredura
	MemMB   float64     `json:"mem_mb"` // memória do agente (working set) ao final
	Phases  []PhaseCost `json:"phases"`
	Inspect InspectPerf `json:"inspect"`
}

// AgentPerf é o consumo do agente em tempo real, enviado periodicamente.
type AgentPerf struct {
	WindowS     float64     `json:"window_s"`    // período medido
	CPUPercent  float64     `json:"cpu_percent"` // média no período (100 = 1 núcleo)
	MemMB       float64     `json:"mem_mb"`      // working set
	Goroutines  int         `json:"goroutines"`
	ProcEvents  int64       `json:"proc_events"`   // execuções tratadas no período
	NetEvents   int64       `json:"net_events"`    // conexões tratadas no período
	EnrichAvgMS float64     `json:"enrich_avg_ms"` // tempo médio para analisar uma execução
	Inspect     InspectPerf `json:"inspect"`
}
