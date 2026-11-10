// Package procmon captura a execução de programas em tempo real.
//
// Duas fontes:
//   - ETW (Microsoft-Windows-Kernel-Process): vê cada processo no instante
//     da criação, inclusive os que duram milissegundos. Exige administrador.
//   - Verificação a cada 1 segundo (fallback sem administrador): vê
//     processos que ficam abertos por pelo menos ~1 s.
package procmon

import (
	"errors"
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
	// Reason explica por que o ETW não foi usado (quando Source == "poll").
	Reason string
	Events <-chan model.ProcessEvent

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
		m.Source, m.etw = "etw", s
	} else {
		m.Source, m.Reason = "poll", err.Error()
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

// enrich completa cada execução e analisa o executável (hash, assinatura,
// fabricante) com cache, para não repetir trabalho com programas comuns.
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
	prune := time.NewTicker(time.Minute)
	defer prune.Stop()

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
		case r := <-raw:
			if r.pid == self || r.pid <= 4 {
				continue
			}
			p := model.Process{PID: r.pid, PPID: r.ppid}
			ev := model.ProcessEvent{Time: r.when.UTC(), PID: r.pid, PPID: r.ppid, Source: r.source}
			if collect.DescribeProcess(&p, users) {
				ev.ImagePath, ev.CommandLine, ev.User = p.ImagePath, p.CommandLine, p.User
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
				if filepath.IsAbs(r.image) {
					ev.ImagePath = r.image
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
	}
}
