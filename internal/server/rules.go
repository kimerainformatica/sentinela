package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"sentinela/internal/model"
)

// Motor de detecção. Avalia o snapshot enviado pelo agente e produz
// achados. As regras automatizam os critérios usados na análise manual do
// relatório técnico: detecções no VirusTotal, local do arquivo, fabricante,
// assinatura, data de criação e conexões de rede.

const (
	SevBaixa   = "baixa"
	SevMedia   = "media"
	SevAlta    = "alta"
	SevCritica = "critica"
)

var sevRank = map[string]int{SevBaixa: 1, SevMedia: 2, SevAlta: 3, SevCritica: 4}

type Finding struct {
	Key        string `json:"key"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Technique  string `json:"technique"` // MITRE ATT&CK
	ObjectType string `json:"object_type"` // autorun | process | connection
	ObjectRef  string `json:"object_ref"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
}

type HashRep struct {
	Status     string `json:"status"` // pending | known | unknown | error | skipped
	Malicious  int    `json:"malicious"`
	Suspicious int    `json:"suspicious"`
	Total      int    `json:"total"`
	Label      string `json:"label"`
}

type IPRep struct {
	Status  string `json:"status"`
	Score   int    `json:"score"` // AbuseIPDB abuseConfidenceScore (0-100)
	Country string `json:"country"`
	ISP     string `json:"isp"`
	Reports int    `json:"reports"`
}

type Intel struct {
	Hashes map[string]HashRep
	IPs    map[string]IPRep
}

// ---------------------------------------------------------------------------
// Auxiliares

func base(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func dir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return ""
}

var absPathRe = regexp.MustCompile(`^(?i)[a-z]:\\`)

// Pastas onde qualquer usuário consegue gravar: local preferido de malware.
var userWritableParts = []string{
	`\appdata\`, `\temp\`, `\tmp\`, `\users\public\`, `\downloads\`, `\desktop\`,
	`\$recycle.bin\`, `\windows\temp\`, `\perflogs\`,
}

func userWritable(p string) bool {
	l := strings.ToLower(p)
	if strings.HasPrefix(l[min(len(l), 1):], `:\programdata\`) {
		return true
	}
	for _, s := range userWritableParts {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func trusted(f *model.FileInfo) bool { return f != nil && f.Signature == "valid" }

func microsoft(f *model.FileInfo) bool {
	return trusted(f) && strings.HasPrefix(f.Signer, "Microsoft")
}

func unsignedFile(f *model.FileInfo) bool {
	return f != nil && f.Exists && (f.Signature == "unsigned" || f.Signature == "invalid")
}

func describe(f *model.FileInfo) string {
	if f == nil {
		return ""
	}
	var parts []string
	switch f.Signature {
	case "valid":
		parts = append(parts, "assinado por "+f.Signer)
	case "unsigned":
		parts = append(parts, "sem assinatura digital")
	case "invalid":
		parts = append(parts, "assinatura INVÁLIDA ("+f.Error+")")
	}
	if f.Company != "" {
		parts = append(parts, "fabricante declarado: "+f.Company)
	}
	if !f.Created.IsZero() {
		parts = append(parts, "criado em "+f.Created.Local().Format("02/01/2006 15:04"))
	}
	return strings.Join(parts, "; ")
}

// Binários do sistema e onde eles legitimamente ficam.
var sysDirRe = regexp.MustCompile(`^(?i)[a-z]:\\windows\\(system32|syswow64)$`)
var winDirRe = regexp.MustCompile(`^(?i)[a-z]:\\windows$`)
var psDirRe = regexp.MustCompile(`^(?i)[a-z]:\\windows\\(system32|syswow64)\\windowspowershell\\v1\.0$`)

var systemBinaries = map[string]*regexp.Regexp{
	"svchost.exe": sysDirRe, "lsass.exe": sysDirRe, "csrss.exe": sysDirRe, "winlogon.exe": sysDirRe,
	"services.exe": sysDirRe, "smss.exe": sysDirRe, "wininit.exe": sysDirRe, "taskhostw.exe": sysDirRe,
	"spoolsv.exe": sysDirRe, "dllhost.exe": sysDirRe, "conhost.exe": sysDirRe, "rundll32.exe": sysDirRe,
	"dwm.exe": sysDirRe, "taskmgr.exe": sysDirRe, "regsvr32.exe": sysDirRe, "cmd.exe": sysDirRe,
	"lsm.exe": sysDirRe, "sihost.exe": sysDirRe, "ctfmon.exe": sysDirRe, "wscript.exe": sysDirRe,
	"cscript.exe": sysDirRe, "mshta.exe": sysDirRe, "powershell.exe": psDirRe,
	"explorer.exe": regexp.MustCompile(`^(?i)[a-z]:\\windows(\\syswow64)?$`),
}

var userinitRe = regexp.MustCompile(`^([a-z]:\\windows\\system32\\)?userinit(\.exe)?$`)

func masquerading(path string) bool {
	if !absPathRe.MatchString(path) {
		return false
	}
	re, ok := systemBinaries[strings.ToLower(base(path))]
	return ok && !re.MatchString(dir(path))
}

type cmdPattern struct {
	re   *regexp.Regexp
	desc string
}

var suspiciousCmd = []cmdPattern{
	{regexp.MustCompile(`(?i)\s-(e|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{20,}`), "PowerShell com comando codificado em Base64"},
	{regexp.MustCompile(`(?i)-w(in(dow(style)?)?)?\s+hidden`), "PowerShell com janela oculta"},
	{regexp.MustCompile(`(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod)`), "download de conteúdo da internet"},
	{regexp.MustCompile(`(?i)(\biex\b|invoke-expression)`), "execução dinâmica de código (IEX)"},
	{regexp.MustCompile(`(?i)frombase64string`), "decodificação de Base64"},
	{regexp.MustCompile(`(?i)mshta(\.exe)?["']?\s+["']?(https?|javascript|vbscript):`), "mshta executando script remoto/inline"},
	{regexp.MustCompile(`(?i)regsvr32.*/i:\s*["']?https?://`), "regsvr32 carregando script remoto (Squiblydoo)"},
	{regexp.MustCompile(`(?i)rundll32(\.exe)?["']?\s+.*javascript:`), "rundll32 executando JavaScript"},
	{regexp.MustCompile(`(?i)certutil.*-(urlcache|decode)`), "certutil usado para baixar/decodificar arquivo"},
	{regexp.MustCompile(`(?i)bitsadmin.*/transfer`), "bitsadmin baixando arquivo"},
	{regexp.MustCompile(`(?i)(wscript|cscript)(\.exe)?["']?\s+.*\\(appdata|temp|users\\public|programdata)\\.*\.(vbs|vbe|js|jse|wsf)`), "script VBS/JS executado de pasta do usuário"},
	{regexp.MustCompile(`(?i)cmd(\.exe)?["']?\s+/[ck].*\^.*\^.*\^`), "comando ofuscado com ^"},
}

func matchCmd(cmd string) []string {
	var out []string
	for _, p := range suspiciousCmd {
		if p.re.MatchString(cmd) {
			out = append(out, p.desc)
		}
	}
	return out
}

func publicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalMulticast()
}

var officeParents = map[string]bool{
	"winword.exe": true, "excel.exe": true, "powerpnt.exe": true, "outlook.exe": true,
	"msaccess.exe": true, "mspub.exe": true, "acrord32.exe": true, "acrobat.exe": true,
}
var scriptChildren = map[string]bool{
	"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true,
	"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "certutil.exe": true, "bitsadmin.exe": true,
}

// ---------------------------------------------------------------------------
// Avaliação

type evaluator struct {
	rep   *model.Report
	intel Intel
	out   []Finding
	seen  map[string]bool
}

func (e *evaluator) add(f Finding) {
	f.Key = f.RuleID + "|" + f.ObjectType + "|" + strings.ToLower(f.ObjectRef)
	if e.seen[f.Key] {
		return
	}
	e.seen[f.Key] = true
	e.out = append(e.out, f)
}

func Evaluate(rep *model.Report, intel Intel) []Finding {
	e := &evaluator{rep: rep, intel: intel, seen: map[string]bool{}}
	for i := range rep.Autoruns {
		e.autorun(&rep.Autoruns[i])
	}
	procs := map[uint32]*model.Process{}
	for i := range rep.Processes {
		procs[rep.Processes[i].PID] = &rep.Processes[i]
	}
	for i := range rep.Processes {
		e.process(&rep.Processes[i], procs)
	}
	for i := range rep.Connections {
		e.connection(&rep.Connections[i], procs)
	}
	return e.out
}

// reputation gera o achado R01 (detecções no VirusTotal) para um arquivo.
func (e *evaluator) reputation(f *model.FileInfo, objType, ref, context string) {
	if f == nil || f.SHA256 == "" {
		return
	}
	r, ok := e.intel.Hashes[f.SHA256]
	if !ok || r.Status != "known" || r.Malicious == 0 {
		return
	}
	sev := SevMedia
	switch {
	case r.Malicious >= 5:
		sev = SevCritica
	case r.Malicious >= 2:
		sev = SevAlta
	}
	label := ""
	if r.Label != "" {
		label = " — classificado como " + r.Label
	}
	e.add(Finding{
		RuleID: "R01", Severity: sev, Technique: "T1204",
		Title:      fmt.Sprintf("Arquivo detectado por %d de %d antivírus no VirusTotal", r.Malicious, r.Total),
		Detail:     fmt.Sprintf("%s%s. %s", context, label, describe(f)),
		ObjectType: objType, ObjectRef: ref, Path: f.Path, SHA256: f.SHA256,
	})
}

func (e *evaluator) autorun(a *model.Autorun) {
	ctx := fmt.Sprintf("Entrada de inicialização [%s] %q executa %s", a.Category, a.Name, a.ImagePath)
	files := []*model.FileInfo{a.File, a.Payload}

	for _, f := range files {
		e.reputation(f, "autorun", a.ID, ctx)
		if f != nil && f.Signature == "invalid" {
			e.add(Finding{RuleID: "R04", Severity: SevAlta, Technique: "T1036.001",
				Title:  "Assinatura digital inválida em arquivo de inicialização",
				Detail: ctx + ". " + describe(f), ObjectType: "autorun", ObjectRef: a.ID, Path: f.Path, SHA256: f.SHA256})
		}
	}

	// R02: arquivo sem assinatura em pasta gravável pelo usuário
	r02 := false
	for _, f := range files {
		if unsignedFile(f) && userWritable(f.Path) {
			r02 = true
			tech, title := "T1547.001", "Inicialização automática de arquivo sem assinatura em pasta do usuário"
			switch a.Category {
			case "Serviços":
				tech, title = "T1543.003", "Serviço executa arquivo sem assinatura em pasta gravável pelo usuário"
			case "Tarefas Agendadas":
				tech, title = "T1053.005", "Tarefa agendada executa arquivo sem assinatura em pasta do usuário"
			}
			e.add(Finding{RuleID: "R02", Severity: SevAlta, Technique: tech, Title: title,
				Detail: ctx + ". Arquivo: " + f.Path + " — " + describe(f), ObjectType: "autorun", ObjectRef: a.ID, Path: f.Path, SHA256: f.SHA256})
			break
		}
	}

	// R03: linha de comando suspeita
	if m := matchCmd(a.Command); len(m) > 0 {
		e.add(Finding{RuleID: "R03", Severity: SevAlta, Technique: "T1059",
			Title:  "Inicialização automática com linha de comando suspeita",
			Detail: ctx + ". Indicadores: " + strings.Join(m, ", ") + ". Comando: " + a.Command,
			ObjectType: "autorun", ObjectRef: a.ID, Path: a.ImagePath})
	}

	// R05: nome de binário do sistema fora do local legítimo
	if masquerading(a.ImagePath) {
		f := a.File
		e.add(Finding{RuleID: "R05", Severity: SevCritica, Technique: "T1036.005",
			Title:  "Arquivo se passando por componente do Windows (" + base(a.ImagePath) + ")",
			Detail: ctx + ". Esse nome pertence a um arquivo do sistema, mas está fora da pasta do Windows. " + describe(f),
			ObjectType: "autorun", ObjectRef: a.ID, Path: a.ImagePath, SHA256: shaOf(f)})
	}

	switch a.Category {
	case "Winlogon":
		v := strings.ToLower(strings.TrimSpace(a.Command))
		bad := false
		switch {
		case strings.HasPrefix(a.Location, "HKU"):
			bad = true // Shell por usuário não deveria existir
		case a.Name == "Shell":
			bad = v != "explorer.exe"
		case a.Name == "Userinit":
			v = strings.TrimSuffix(v, ",")
			bad = !userinitRe.MatchString(v)
		}
		if bad {
			e.add(Finding{RuleID: "R06", Severity: SevCritica, Technique: "T1547.004",
				Title:  "Valor do Winlogon (" + a.Name + ") alterado",
				Detail: "O Windows executa este valor a cada logon. Valor atual: " + a.Command,
				ObjectType: "autorun", ObjectRef: a.ID, Path: a.ImagePath, SHA256: shaOf(a.File)})
		}
	case "Image Hijacks (IFEO)":
		sev := SevAlta
		if trusted(a.File) {
			sev = SevMedia
		}
		e.add(Finding{RuleID: "R07", Severity: sev, Technique: "T1546.012",
			Title:  "Sequestro de execução via IFEO para " + a.Name,
			Detail: "Sempre que " + a.Name + " for aberto, o Windows executará: " + a.Command + ". " + describe(a.File),
			ObjectType: "autorun", ObjectRef: a.ID, Path: a.ImagePath, SHA256: shaOf(a.File)})
	case "AppInit":
		sev := SevBaixa
		if a.Enabled {
			sev = SevAlta
		}
		e.add(Finding{RuleID: "R08", Severity: sev, Technique: "T1546.010",
			Title:  "DLL carregada via AppInit_DLLs",
			Detail: "A DLL " + a.Command + " é injetada em processos com interface gráfica. " + describe(a.File),
			ObjectType: "autorun", ObjectRef: a.ID, Path: a.ImagePath, SHA256: shaOf(a.File)})
	case "Drivers":
		if unsignedFile(a.File) {
			e.add(Finding{RuleID: "R13", Severity: SevAlta, Technique: "T1014",
				Title:  "Driver sem assinatura válida",
				Detail: ctx + ". " + describe(a.File), ObjectType: "autorun", ObjectRef: a.ID, Path: a.ImagePath, SHA256: shaOf(a.File)})
		}
	}

	// R09: entrada órfã (aponta para arquivo inexistente)
	if a.File != nil && !a.File.Exists && a.File.Error == "" && absPathRe.MatchString(a.ImagePath) {
		e.add(Finding{RuleID: "R09", Severity: SevBaixa, Technique: "T1547",
			Title:  "Entrada de inicialização aponta para arquivo inexistente",
			Detail: ctx + ". Pode ser resíduo de um programa desinstalado ou de malware já removido.",
			ObjectType: "autorun", ObjectRef: a.ID, Path: a.ImagePath})
	}

	// R12: arquivo sem assinatura criado recentemente
	if !r02 {
		for _, f := range files {
			if unsignedFile(f) && !f.Created.IsZero() && e.rep.CollectedAt.Sub(f.Created) < 7*24*time.Hour {
				e.add(Finding{RuleID: "R12", Severity: SevMedia, Technique: "T1547",
					Title:  "Inicialização automática recente de arquivo sem assinatura",
					Detail: ctx + ". " + describe(f), ObjectType: "autorun", ObjectRef: a.ID, Path: f.Path, SHA256: f.SHA256})
				break
			}
		}
	}
}

func shaOf(f *model.FileInfo) string {
	if f == nil {
		return ""
	}
	return f.SHA256
}

// Processos são identificados pelo caminho (o PID muda a cada execução).
func procRef(p *model.Process) string {
	if p.ImagePath != "" {
		return p.ImagePath
	}
	return p.Name
}

func (e *evaluator) process(p *model.Process, procs map[uint32]*model.Process) {
	ctx := fmt.Sprintf("Processo %s (PID %d) em execução a partir de %s", p.Name, p.PID, p.ImagePath)
	ref := procRef(p)
	e.reputation(p.File, "process", ref, ctx)

	if p.File != nil && p.File.Signature == "invalid" {
		e.add(Finding{RuleID: "R04", Severity: SevAlta, Technique: "T1036.001",
			Title:  "Processo com assinatura digital inválida",
			Detail: ctx + ". " + describe(p.File), ObjectType: "process", ObjectRef: ref, Path: p.ImagePath, SHA256: shaOf(p.File)})
	}
	if masquerading(p.ImagePath) {
		e.add(Finding{RuleID: "R05", Severity: SevCritica, Technique: "T1036.005",
			Title:  "Processo se passando por componente do Windows (" + base(p.ImagePath) + ")",
			Detail: ctx + ". Esse nome pertence a um arquivo do sistema, mas está fora da pasta do Windows. " + describe(p.File),
			ObjectType: "process", ObjectRef: ref, Path: p.ImagePath, SHA256: shaOf(p.File)})
	}
	if m := matchCmd(p.CommandLine); len(m) > 0 {
		e.add(Finding{RuleID: "R15", Severity: SevAlta, Technique: "T1059",
			Title:  "Processo com linha de comando suspeita",
			Detail: ctx + ". Indicadores: " + strings.Join(m, ", ") + ". Comando: " + p.CommandLine,
			ObjectType: "process", ObjectRef: ref, Path: p.ImagePath, SHA256: shaOf(p.File)})
	}
	if parent, ok := procs[p.PPID]; ok && officeParents[strings.ToLower(parent.Name)] && scriptChildren[strings.ToLower(p.Name)] {
		e.add(Finding{RuleID: "R14", Severity: SevAlta, Technique: "T1204.002",
			Title:  parent.Name + " abriu " + p.Name,
			Detail: "Documentos do Office/PDF iniciando interpretadores de comando é típico de anexo malicioso (macro). Comando: " + p.CommandLine,
			ObjectType: "process", ObjectRef: ref, Path: p.ImagePath, SHA256: shaOf(p.File)})
	}
}

func (e *evaluator) connection(c *model.Connection, procs map[uint32]*model.Process) {
	p := procs[c.PID]
	var pf *model.FileInfo
	pname, ppath := c.ProcessName, ""
	if p != nil {
		pf, ppath = p.File, p.ImagePath
	}
	ctx := fmt.Sprintf("%s (PID %d, %s)", pname, c.PID, ppath)
	remote := fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort)

	if strings.HasPrefix(c.Proto, "TCP") && (c.State == "ESTABLISHED" || c.State == "SYN_SENT") && publicIP(c.RemoteAddr) {
		if r, ok := e.intel.IPs[c.RemoteAddr]; ok && r.Status == "known" && r.Score >= 25 {
			sev := SevMedia
			if r.Score >= 75 {
				sev = SevCritica
			}
			e.add(Finding{RuleID: "R11", Severity: sev, Technique: "T1071",
				Title:  fmt.Sprintf("Conexão com IP de má reputação (%d%% de confiança de abuso)", r.Score),
				Detail: fmt.Sprintf("%s conectado a %s (%s, %s, %d denúncias no AbuseIPDB)", ctx, remote, r.Country, r.ISP, r.Reports),
				ObjectType: "connection", ObjectRef: ppath + "|" + c.RemoteAddr, Path: ppath, SHA256: shaOf(pf)})
		}
		if p != nil && unsignedFile(pf) && userWritable(ppath) {
			e.add(Finding{RuleID: "R10", Severity: SevAlta, Technique: "T1071",
				Title:  "Programa sem assinatura em pasta do usuário com conexão externa",
				Detail: ctx + " conectado a " + remote + ". " + describe(pf),
				ObjectType: "connection", ObjectRef: ppath, Path: ppath, SHA256: shaOf(pf)})
		}
	}
	if c.State == "LISTENING" && p != nil && unsignedFile(pf) && userWritable(ppath) &&
		c.LocalAddr != "127.0.0.1" && c.LocalAddr != "::1" {
		e.add(Finding{RuleID: "R16", Severity: SevMedia, Technique: "T1571",
			Title:  fmt.Sprintf("Programa sem assinatura aguardando conexões na porta %d", c.LocalPort),
			Detail: ctx + " escutando em " + fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort) + ". Pode ser um acesso remoto (backdoor). " + describe(pf),
			ObjectType: "connection", ObjectRef: ppath + "|listen", Path: ppath, SHA256: shaOf(pf)})
	}
}

// HostStatus resume a situação do endpoint pela maior severidade aberta.
func HostStatus(maxSev string) string {
	switch maxSev {
	case SevCritica:
		return "comprometido"
	case SevAlta:
		return "suspeito"
	case SevMedia:
		return "atencao"
	}
	return "ok"
}
