// Package procmon captura a execução de programas em tempo real.
//
// Duas fontes:
//   - ETW (kernel + Microsoft-Windows-Kernel-Process): vê cada processo no
//     instante da criação, com linha de comando, inclusive os que duram
//     milissegundos. Exige administrador.
//   - Verificação a cada 1 segundo (fallback sem administrador): vê
//     processos que ficam abertos por pelo menos ~1 s.
package procmon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinela/internal/agent/collect"
	"sentinela/internal/model"
)

type Monitor struct {
	// Source é "etw" ou "poll".
	Source string
	// Mode descreve as fontes ETW em uso.
	Mode string
	// Reason explica por que o ETW não foi usado (quando Source == "poll").
	Reason string
	Events <-chan model.ProcessEvent

	need    uint8 // partes que cada execução deve reunir (0 = processa na hora)
	dropped atomic.Int64
	stop    chan struct{}
	etw     *etwSession
	once    sync.Once
}

// Dropped devolve (e zera) quantos eventos foram descartados por excesso.
func (m *Monitor) Dropped() int { return int(m.dropped.Swap(0)) }

func (m *Monitor) Stop() {
	m.once.Do(func() {
		close(m.stop)
		if m.etw != nil {
			m.etw.Close()
		}
	})
}

type procEntry struct {
	ppid  uint32
	name  string
	image string
}

// snapshot lista os processos atuais (leve: só PID, PPID e nome).
func snapshot() map[uint32]procEntry {
	out := map[uint32]procEntry{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		out[pe.ProcessID] = procEntry{ppid: pe.ParentProcessID, name: windows.UTF16ToString(pe.ExeFile[:])}
	}
	return out
}

// Start inicia o monitor, preferindo ETW.
func Start() *Monitor {
	raw := make(chan rawStart, 8192)
	out := make(chan model.ProcessEvent, 4096)
	m := &Monitor{Events: out, stop: make(chan struct{})}

	if s, err := startETW(raw); err == nil {
		m.Source, m.Mode, m.etw, m.need = "etw", s.mode, s, s.need
	} else {
		m.Source, m.Mode, m.Reason = "poll", "verificação a cada 1 s", err.Error()
		go pollLoop(raw, m.stop)
	}
	go m.enrich(raw, out)
	return m
}

func pollLoop(raw chan<- rawStart, stop <-chan struct{}) {
	prev := snapshot()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		cur := snapshot()
		for pid, e := range cur {
			if _, ok := prev[pid]; !ok {
				select {
				case raw <- rawStart{pid: pid, ppid: e.ppid, image: e.name, when: time.Now(), source: "poll"}:
				default:
				}
			}
		}
		prev = cur
	}
}

// mergeTimeout é quanto esperar pela segunda parte de uma execução ETW.
const mergeTimeout = 800 * time.Millisecond

type pending struct {
	r     rawStart
	since time.Time
}

func merge(a *rawStart, b rawStart) {
	if b.parts&partImage != 0 && filepath.IsAbs(b.image) {
		a.image = b.image
	} else if a.image == "" {
		a.image = b.image
	}
	if b.cmdline != "" {
		a.cmdline = b.cmdline
	}
	if a.ppid == 0 {
		a.ppid = b.ppid
	}
	if b.when.Before(a.when) {
		a.when = b.when
	}
	a.parts |= b.parts
}

// imageFromCmdline deduz o executável pela linha de comando (usado quando
// só o provedor do kernel, que não traz o caminho completo, está ativo).
func imageFromCmdline(cmd string) string {
	if cmd == "" {
		return ""
	}
	r := &collect.Resolver{
		WinDir: os.Getenv("SystemRoot"),
		Env:    os.Getenv,
		Exists: func(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() },
	}
	img, _ := r.Resolve(cmd)
	if filepath.IsAbs(img) && r.Exists(img) {
		return img
	}
	return ""
}

// enrich reúne as partes de cada execução, completa com o que o processo
// ainda puder informar e analisa o executável (hash, assinatura,
// fabricante) com cache.
func (m *Monitor) enrich(raw <-chan rawStart, out chan<- model.ProcessEvent) {
	in := collect.NewInspector()
	defer in.Close()
	users := map[string]string{}
	self := windows.GetCurrentProcessId()

	// Mapa PID -> processo, para descobrir o pai mesmo depois de ele sair.
	known := map[uint32]procEntry{}
	for pid, e := range snapshot() {
		known[pid] = e
	}
	waiting := map[uint32]*pending{}
	prune := time.NewTicker(time.Minute)
	flush := time.NewTicker(200 * time.Millisecond)
	defer prune.Stop()
	defer flush.Stop()

	describeParent := func(ppid uint32) (string, string) {
		if e, ok := known[ppid]; ok {
			if e.image == "" {
				p := model.Process{PID: ppid}
				if collect.DescribeProcess(&p, users) {
					e.image = p.ImagePath
					known[ppid] = e
				}
			}
			return e.name, e.image
		}
		p := model.Process{PID: ppid}
		if collect.DescribeProcess(&p, users) {
			return filepath.Base(p.ImagePath), p.ImagePath
		}
		return "", ""
	}

	process := func(r rawStart) {
		p := model.Process{PID: r.pid, PPID: r.ppid}
		ev := model.ProcessEvent{Time: r.when.UTC(), PID: r.pid, PPID: r.ppid, Source: r.source, CommandLine: r.cmdline}
		if collect.DescribeProcess(&p, users) {
			ev.ImagePath, ev.User = p.ImagePath, p.User
			if p.CommandLine != "" {
				ev.CommandLine = p.CommandLine
			}
			if !p.Started.IsZero() {
				ev.Time = p.Started
			}
		} else {
			// Fica o que o ETW informou. Distingue "já terminou" de "sem permissão".
			if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, r.pid); err == nil {
				windows.CloseHandle(h)
				ev.Restricted = true
			} else if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				ev.Restricted = true
			} else {
				ev.Exited = true
			}
			switch {
			case filepath.IsAbs(r.image):
				ev.ImagePath = r.image
			default:
				ev.ImagePath = imageFromCmdline(r.cmdline)
			}
		}
		ev.Name = filepath.Base(ev.ImagePath)
		if ev.ImagePath == "" {
			ev.Name = filepath.Base(r.image)
		}
		ev.ParentName, ev.ParentImage = describeParent(r.ppid)
		if ev.ImagePath != "" {
			ev.File = in.Inspect(ev.ImagePath)
		}
		known[r.pid] = procEntry{ppid: r.ppid, name: ev.Name, image: ev.ImagePath}

		select {
		case out <- ev:
		default:
			m.dropped.Add(1)
		}
	}

	for {
		select {
		case <-m.stop:
			return
		case <-prune.C:
			cur := snapshot()
			for pid, e := range known {
				if c, ok := cur[pid]; !ok || !strings.EqualFold(c.name, e.name) {
					delete(known, pid)
				}
			}
		case <-flush.C:
			for pid, w := range waiting {
				if time.Since(w.since) >= mergeTimeout {
					delete(waiting, pid)
					process(w.r)
				}
			}
		case r := <-raw:
			if r.pid == self || r.pid <= 4 {
				continue
			}
			if m.need == 0 {
				process(r)
				continue
			}
			w, ok := waiting[r.pid]
			if !ok {
				w = &pending{r: r, since: time.Now()}
				waiting[r.pid] = w
			} else {
				merge(&w.r, r)
			}
			if w.r.parts&m.need == m.need {
				delete(waiting, r.pid)
				process(w.r)
			}
		}
	}
}
