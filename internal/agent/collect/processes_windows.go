package collect

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinela/internal/model"
)

// Processes lista os processos em execução com caminho, linha de comando,
// usuário e informações do executável.
func Processes(in *Inspector, errs *[]string) []model.Process {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		*errs = append(*errs, "processos: "+err.Error())
		return nil
	}
	defer windows.CloseHandle(snap)

	users := map[string]string{}
	var out []model.Process
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		p := model.Process{
			PID:  pe.ProcessID,
			PPID: pe.ParentProcessID,
			Name: windows.UTF16ToString(pe.ExeFile[:]),
		}
		if p.PID > 4 {
			fillProcess(&p, users)
		}
		if p.ImagePath != "" {
			p.File = in.Inspect(p.ImagePath)
		}
		out = append(out, p)
	}
	return out
}

// DescribeProcess preenche caminho, linha de comando, usuário e horário de
// início de um processo em execução. users é um cache SID -> nome.
// Retorna false se o processo não pôde ser aberto (já terminou ou é protegido).
func DescribeProcess(p *model.Process, users map[string]string) bool {
	fillProcess(p, users)
	return p.ImagePath != ""
}

func fillProcess(p *model.Process, users map[string]string) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		p.ImagePath = windows.UTF16ToString(buf[:n])
	}
	p.CommandLine = commandLine(h)

	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) == nil {
		p.Started = time.Unix(0, c.Nanoseconds()).UTC()
	}

	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) == nil {
		defer tok.Close()
		if tu, err := tok.GetTokenUser(); err == nil {
			sid := tu.User.Sid.String()
			name, ok := users[sid]
			if !ok {
				name = sidName(sid)
				users[sid] = name
			}
			p.User = name
		}
	}
}

// commandLine usa ProcessCommandLineInformation (Windows 8.1+), que não
// exige ler a memória do processo.
func commandLine(h windows.Handle) string {
	var size uint32
	windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &size)
	if size == 0 || size > 1<<20 {
		return ""
	}
	buf := make([]uint64, (size+7)/8)
	if err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
		unsafe.Pointer(&buf[0]), size, &size); err != nil {
		return ""
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	return us.String()
}
