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

	Error string `json:"error,omitempty"`
}

// Autorun é uma entrada de inicialização automática (equivalente a uma linha
// do Autoruns).
type Autorun struct {
	// ID estável (hash de categoria+local+nome) usado para remediação.
	ID        string `json:"id"`
	Category  string `json:"category"`  // Logon, Serviços, Drivers, Tarefas Agendadas, ...
	Location  string `json:"location"`  // chave de registro, pasta ou caminho da tarefa
	Name      string `json:"name"`      // nome do valor / serviço / tarefa / atalho
	Command   string `json:"command"`   // linha de comando bruta
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
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	OSBuild   string `json:"os_build"`
	Domain    string `json:"domain,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	AgentVer  string `json:"agent_version"`
	IsElevated bool  `json:"is_elevated"`
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
	ActionRescan          = "rescan"
	ActionKillProcess     = "kill_process"
	ActionDisableAutorun  = "disable_autorun"
	ActionRestoreAutorun  = "restore_autorun"
	ActionQuarantineFile  = "quarantine_file"
	ActionRestoreFile     = "restore_file"
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
