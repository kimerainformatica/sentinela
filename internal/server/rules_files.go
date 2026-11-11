package server

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"sentinela/internal/model"
)

// Regras sobre o próprio arquivo, a partir da análise aprofundada do agente
// (nome original, atributos, origem do download e estrutura do executável).
//
//	R20  programa renomeado (ferramenta de ataque ou utilitário do Windows com outro nome)
//	R21  extensão dupla ou caractere de inversão no nome ("fatura.pdf.exe")
//	R22  executável oculto em pasta do usuário
//	R23  executável empacotado/cifrado e sem assinatura em pasta do usuário
//	R24  inicialização automática de arquivo baixado da internet e sem assinatura

// Nome original (recurso de versão) -> nome da ferramenta. Utilitários do
// Windows usados em ataques e ferramentas de invasão conhecidas: quando um
// deles aparece com outro nome, alguém quis esconder o que está rodando.
var watchedOriginals = map[string]string{
	"powershell.exe": "PowerShell", "pwsh.dll": "PowerShell 7", "cmd.exe": "Prompt de comando",
	"rundll32.exe": "rundll32", "mshta.exe": "mshta", "certutil.exe": "certutil",
	"wscript.exe": "Windows Script Host", "cscript.exe": "Windows Script Host",
	"regsvr32.exe": "regsvr32", "bitsadmin.exe": "bitsadmin", "wmic.exe": "WMIC",
	"msbuild.exe": "MSBuild", "installutil.exe": "InstallUtil",
	"psexec.c": "PsExec", "psexec.exe": "PsExec", "psexesvc.exe": "PsExec",
	"procdump": "ProcDump", "procdump.exe": "ProcDump",
	"mimikatz.exe": "Mimikatz", "rclone.exe": "rclone", "nc.exe": "netcat", "ncat.exe": "ncat",
	"plink.exe": "plink (túnel SSH)", "ngrok.exe": "ngrok (túnel)", "chisel.exe": "chisel (túnel)",
	"lazagne.exe": "LaZagne (roubo de senhas)", "rubeus.exe": "Rubeus", "sharphound.exe": "SharpHound",
	"adfind.exe": "AdFind", "advanced_ip_scanner.exe": "Advanced IP Scanner",
}

// Extensões de documento/mídia seguidas de extensão executável.
var doubleExtRe = regexp.MustCompile(`(?i)\.(pdf|docx?|xlsx?|pptx?|rtf|txt|csv|jpe?g|png|gif|bmp|zip|rar|7z|mp3|mp4|avi|mov|html?)[\s._-]*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|msi|lnk|ps1|cpl)$`)

// Caracteres invisíveis/de direção usados para disfarçar a extensão
// (ex.: "fatura‮fdp.exe" aparece como "fatura exe.pdf").
var bidiChars = "‪‫‬‭‮⁦⁧⁨⁩‎‏"

// fileChecks aplica R20 a R24 a um arquivo (de inicialização ou processo).
func (e *evaluator) fileChecks(f *model.FileInfo, objType, ref, ctx string, autorun bool) {
	if f == nil || !f.Exists {
		return
	}
	name := filepath.Base(f.Path)
	lname := strings.ToLower(name)
	add := func(id, sev, tech, title, detail string) {
		e.add(Finding{RuleID: id, Severity: sev, Technique: tech, Title: title,
			Detail: ctx + ". " + detail, ObjectType: objType, ObjectRef: ref, Path: f.Path, SHA256: f.SHA256})
	}

	// R20: programa renomeado
	if orig := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f.OriginalFilename)), ".mui"); orig != "" {
		if tool, ok := watchedOriginals[orig]; ok && !sameProgramName(lname, orig) {
			add("R20", SevAlta, "T1036.003", fmt.Sprintf("Programa renomeado: %s com o nome %q", tool, name),
				fmt.Sprintf("O nome original gravado no arquivo é %q, mas ele está salvo como %q. Renomear %s é uma forma comum de passar despercebido. %s",
					f.OriginalFilename, name, tool, describe(f)))
		}
	}

	// R21: extensão dupla ou caractere de inversão de texto
	if strings.ContainsAny(name, bidiChars) {
		add("R21", SevAlta, "T1036.002", "Nome de arquivo com caractere invisível de inversão de texto",
			fmt.Sprintf("O nome %q contém caracteres que invertem a ordem do texto na tela, usados para disfarçar a extensão verdadeira. %s",
				showBidi(name), describe(f)))
	} else if doubleExtRe.MatchString(lname) {
		add("R21", SevAlta, "T1036.007", "Arquivo com extensão dupla ("+name+")",
			"Um executável com nome de documento engana quem não vê a extensão final (o Windows a esconde por padrão). "+describe(f))
	}

	user := userWritable(f.Path)

	// R22: executável oculto em pasta do usuário
	if user && hasAttr(f, "oculto") && unsignedFile(f) {
		add("R22", SevMedia, "T1564.001", "Executável oculto em pasta do usuário",
			"O arquivo tem o atributo \"oculto\" e não tem assinatura: não aparece no Explorer com as opções padrão. "+describe(f))
	}

	// R23: empacotado/cifrado e sem assinatura
	if user && unsignedFile(f) && f.PE != nil && f.PE.Packed {
		how := fmt.Sprintf("entropia %.2f de 8", f.PE.MaxEntropy)
		if f.PE.Packer != "" {
			how = "empacotador " + f.PE.Packer + ", " + how
		}
		sev := SevMedia
		if autorun {
			sev = SevAlta
		}
		add("R23", sev, "T1027.002", "Executável empacotado e sem assinatura em pasta do usuário",
			"O código está comprimido ou cifrado ("+how+"), o que impede ver o que ele faz sem executá-lo. "+
				"Programas legítimos raramente fazem isso sem também serem assinados. "+describe(f))
	}

	// R24: inicialização automática de arquivo baixado da internet
	if autorun && unsignedFile(f) && f.Origin != nil && f.Origin.Zone >= 3 {
		add("R24", SevAlta, "T1204.002", "Inicialização automática de arquivo baixado da internet",
			"O arquivo veio da internet (Mark of the Web) e não tem assinatura, mas foi configurado para iniciar sozinho. "+describe(f))
	}
}

// sameProgramName compara o nome no disco com o nome original, ignorando a
// extensão (ex.: "psexec.c" é o nome original do PsExec.exe).
func sameProgramName(diskName, orig string) bool {
	trim := func(s string) string { return strings.TrimSuffix(s, filepath.Ext(s)) }
	d, o := trim(diskName), trim(orig)
	return d == o || strings.HasPrefix(d, o+"64") || strings.HasPrefix(d, o+"_") // procdump64, psexec64
}

// showBidi torna visíveis os caracteres de direção (ex.: "[U+202E]").
func showBidi(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(bidiChars, r) {
			fmt.Fprintf(&b, "[U+%04X]", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hasAttr(f *model.FileInfo, a string) bool {
	for _, x := range f.Attributes {
		if x == a {
			return true
		}
	}
	return false
}

// describeExtra completa a descrição do arquivo com a análise aprofundada.
func describeExtra(f *model.FileInfo) []string {
	var parts []string
	orig := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f.OriginalFilename)), ".mui")
	if orig != "" && !sameProgramName(strings.ToLower(filepath.Base(f.Path)), orig) {
		parts = append(parts, "nome original: "+f.OriginalFilename)
	}
	if o := f.Origin; o != nil && o.Zone >= 3 {
		s := "baixado da " + o.ZoneName
		if o.HostURL != "" {
			s += " (" + o.HostURL + ")"
		}
		parts = append(parts, s)
	}
	if len(f.Attributes) > 0 {
		parts = append(parts, "atributos: "+strings.Join(f.Attributes, ", "))
	}
	if p := f.PE; p != nil {
		switch {
		case !p.IsPE && strings.HasSuffix(strings.ToLower(f.Path), ".exe"):
			parts = append(parts, "extensão .exe mas não é um executável Windows")
		case p.Packed && p.Packer != "":
			parts = append(parts, "empacotado com "+p.Packer)
		case p.Packed:
			parts = append(parts, fmt.Sprintf("código comprimido ou cifrado (entropia %.2f)", p.MaxEntropy))
		}
	}
	return parts
}
