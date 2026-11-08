package collect

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Resolver transforma a linha de comando bruta de uma entrada de
// inicialização no caminho do executável, como o Autoruns faz na coluna
// "Image Path".
type Resolver struct {
	WinDir string // C:\Windows
	// Env resolve variáveis de ambiente. Para entradas por usuário, deve
	// apontar %APPDATA%, %USERPROFILE% etc. para o perfil daquele usuário.
	Env func(string) string
	// Exists verifica a existência de um arquivo (injetável para testes).
	Exists func(string) bool
}

var envRe = regexp.MustCompile(`%([^%\s]+)%`)

func (r *Resolver) Expand(s string) string {
	return envRe.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if v := r.Env(name); v != "" {
			return v
		}
		return m
	})
}

// Normalize trata os prefixos usados pelo registro de serviços/drivers.
func (r *Resolver) Normalize(p string) string {
	p = strings.TrimSpace(r.Expand(p))
	lp := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lp, `\??\`):
		p = p[4:]
	case strings.HasPrefix(lp, `\\?\`):
		p = p[4:]
	case strings.HasPrefix(lp, `\systemroot\`):
		p = filepath.Join(r.WinDir, p[len(`\systemroot\`):])
	case strings.HasPrefix(lp, `system32\`), strings.HasPrefix(lp, `syswow64\`):
		p = filepath.Join(r.WinDir, p)
	}
	return p
}

// SplitArgs separa argumentos respeitando aspas duplas (aproximação das
// regras do CommandLineToArgvW, suficiente para análise).
func SplitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for _, c := range s {
		switch {
		case c == '"':
			inQ = !inQ
			has = true
		case (c == ' ' || c == '\t') && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

func (r *Resolver) searchSystem(name string) string {
	cands := []string{name}
	if filepath.Ext(name) == "" {
		cands = append(cands, name+".exe")
	}
	for _, dir := range []string{
		filepath.Join(r.WinDir, "System32"),
		r.WinDir,
		filepath.Join(r.WinDir, "SysWOW64"),
		filepath.Join(r.WinDir, "System32", "WindowsPowerShell", "v1.0"),
	} {
		for _, c := range cands {
			p := filepath.Join(dir, c)
			if r.Exists(p) {
				return p
			}
		}
	}
	return ""
}

func hasDir(p string) bool { return strings.ContainsAny(p, `\/`) }

// Resolve retorna (executável, argumentos) a partir de uma linha de comando.
func (r *Resolver) Resolve(cmd string) (image, args string) {
	cmd = strings.TrimSpace(r.Normalize(cmd))
	if cmd == "" {
		return "", ""
	}
	if cmd[0] == '"' {
		end := strings.IndexByte(cmd[1:], '"')
		if end < 0 {
			image, args = cmd[1:], ""
		} else {
			image, args = cmd[1:end+1], strings.TrimSpace(cmd[end+2:])
		}
	} else {
		// Caminho sem aspas e com espaços: testa progressivamente
		// "C:\Program", "C:\Program Files\App\x.exe", ...
		parts := strings.Split(cmd, " ")
		image, args = parts[0], strings.Join(parts[1:], " ")
		for i := 1; i <= len(parts); i++ {
			cand := strings.Join(parts[:i], " ")
			if hasDir(cand) && (r.Exists(cand) || r.Exists(cand+".exe")) {
				image, args = cand, strings.TrimSpace(strings.Join(parts[i:], " "))
				if !r.Exists(image) {
					image += ".exe"
				}
				break
			}
		}
	}
	image = r.Normalize(image)
	if !hasDir(image) {
		if p := r.searchSystem(image); p != "" {
			image = p
		}
	} else if filepath.Ext(image) == "" && r.Exists(image+".exe") {
		image += ".exe"
	}
	return image, args
}

// Programas que executam outro arquivo (o "payload" real da persistência).
var hostBinaries = map[string]bool{
	"rundll32.exe": true, "regsvr32.exe": true, "wscript.exe": true, "cscript.exe": true,
	"mshta.exe": true, "powershell.exe": true, "pwsh.exe": true, "cmd.exe": true,
	"conhost.exe": true, "explorer.exe": true,
}

var payloadExts = map[string]bool{
	".dll": true, ".exe": true, ".scr": true, ".cpl": true, ".ocx": true, ".vbs": true,
	".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true, ".ps1": true,
	".bat": true, ".cmd": true, ".com": true, ".pif": true,
}

// IsHostBinary indica se o executável é um "hospedeiro" (LOLBin/script host).
func IsHostBinary(image string) bool {
	return hostBinaries[strings.ToLower(filepath.Base(image))]
}

// Payload extrai o arquivo executado por um hospedeiro, ex.:
//
//	rundll32.exe C:\Users\x\AppData\a.dll,Start -> C:\Users\x\AppData\a.dll
//	wscript.exe "C:\ProgramData\run.vbs"       -> C:\ProgramData\run.vbs
func (r *Resolver) Payload(image, args string) string {
	if !IsHostBinary(image) {
		return ""
	}
	for _, tok := range SplitArgs(r.Expand(args)) {
		t := tok
		if i := strings.IndexByte(t, ','); i > 0 { // rundll32 x.dll,Entry
			t = t[:i]
		}
		if strings.Contains(strings.ToLower(t), "://") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(t))
		if !payloadExts[ext] {
			continue
		}
		if !hasDir(t) {
			if p := r.searchSystem(t); p != "" {
				return p
			}
			continue
		}
		return r.Normalize(t)
	}
	return ""
}
