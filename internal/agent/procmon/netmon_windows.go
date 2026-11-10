package procmon

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sentinela/internal/agent/collect"
	"sentinela/internal/model"
)

// Conexões TCP em tempo real: abertas (saída) e aceitas (entrada).

// Repetições da mesma conexão (programa -> destino) são agrupadas.
const netDedupWindow = 10 * time.Minute

// procCache é compartilhado entre os monitores de execução e de rede:
// PID -> programa, para saber de quem é uma conexão.
type procCache struct {
	mu sync.Mutex
	m  map[uint32]procEntry
}

func newProcCache() *procCache { return &procCache{m: map[uint32]procEntry{}} }

func (c *procCache) set(pid uint32, e procEntry) {
	c.mu.Lock()
	c.m[pid] = e
	c.mu.Unlock()
}

func (c *procCache) get(pid uint32) (procEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[pid]
	return e, ok
}

func (c *procCache) prune(alive map[uint32]procEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid, e := range c.m {
		if a, ok := alive[pid]; !ok || !strings.EqualFold(a.name, e.name) {
			delete(c.m, pid)
		}
	}
}

func ignorableAddr(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsLoopback() || ip.IsUnspecified()
}

// netPollLoop é o fallback sem administrador: compara a tabela de conexões
// TCP a cada 2 s e informa as novas (estabelecidas ou tentando conectar).
func netPollLoop(raw chan<- rawNet, stop <-chan struct{}) {
	type key struct {
		proto, la, ra string
		lp, rp        uint16
		pid           uint32
	}
	read := func() (map[key]model.Connection, map[string]bool) {
		var errs []string
		conns := collect.Connections(map[uint32]string{}, &errs)
		cur := map[key]model.Connection{}
		listening := map[string]bool{}
		for _, c := range conns {
			if !strings.HasPrefix(c.Proto, "TCP") {
				continue
			}
			if c.State == "LISTENING" {
				listening[fmt.Sprintf("%d|%d", c.PID, c.LocalPort)] = true
				continue
			}
			if c.State == "ESTABLISHED" || c.State == "SYN_SENT" {
				cur[key{c.Proto, c.LocalAddr, c.RemoteAddr, c.LocalPort, c.RemotePort, c.PID}] = c
			}
		}
		return cur, listening
	}
	prev, _ := read()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		cur, listening := read()
		for k, c := range cur {
			if _, ok := prev[k]; ok {
				continue
			}
			dir := "saida"
			if listening[fmt.Sprintf("%d|%d", c.PID, c.LocalPort)] {
				dir = "entrada"
			}
			select {
			case raw <- rawNet{pid: c.PID, dir: dir, proto: c.Proto, laddr: c.LocalAddr, lport: c.LocalPort,
				raddr: c.RemoteAddr, rport: c.RemotePort, when: time.Now(), source: "poll"}:
			default:
			}
		}
		prev = cur
	}
}

type seenConn struct {
	last       time.Time
	suppressed int
}

// enrichNet identifica o programa dono de cada conexão, agrupa repetições
// e analisa o executável (assinatura, hash) com cache.
func (m *Monitor) enrichNet(raw <-chan rawNet, out chan<- model.NetEvent) {
	in := collect.NewInspector()
	defer in.Close()
	users := map[string]string{}
	seen := map[string]*seenConn{}
	cleanup := time.NewTicker(5 * time.Minute)
	defer cleanup.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-cleanup.C:
			for k, s := range seen {
				if time.Since(s.last) > netDedupWindow {
					delete(seen, k)
				}
			}
		case r := <-raw:
			if ignorableAddr(r.raddr) {
				continue
			}
			name, image := "", ""
			if r.pid == 4 {
				name = "System"
			} else if e, ok := m.procs.get(r.pid); ok && e.image != "" {
				name, image = e.name, e.image
			} else {
				p := model.Process{PID: r.pid}
				if collect.DescribeProcess(&p, users) {
					image = p.ImagePath
					name = filepath.Base(image)
					m.procs.set(r.pid, procEntry{name: name, image: image})
				} else if ok {
					name = e.name
				} else if s, found := snapshot()[r.pid]; found {
					// Sem permissão para abrir o processo (serviço, agente sem
					// admin): o nome ainda vem da lista de processos.
					name = s.name
					m.procs.set(r.pid, s)
				}
			}

			// Agrupa: mesma conexão do mesmo programa vira um evento a cada 10 min.
			who := strings.ToLower(image)
			if who == "" {
				who = fmt.Sprintf("pid:%d", r.pid)
			}
			port := r.rport
			if r.dir == "entrada" {
				port = r.lport // a porta remota de quem chega é aleatória
			}
			k := fmt.Sprintf("%s|%s|%s|%d", who, r.dir, r.raddr, port)
			repeats := 0
			if s, ok := seen[k]; ok && time.Since(s.last) < netDedupWindow {
				s.suppressed++
				continue
			} else if ok {
				repeats = s.suppressed
			}
			seen[k] = &seenConn{last: time.Now()}

			ev := model.NetEvent{Time: r.when.UTC(), PID: r.pid, ProcessName: name, ImagePath: image,
				Direction: r.dir, Proto: r.proto, LocalAddr: r.laddr, LocalPort: r.lport,
				RemoteAddr: r.raddr, RemotePort: r.rport, Source: r.source, Repeats: repeats}
			if image != "" {
				ev.File = in.Inspect(image)
			}
			select {
			case out <- ev:
			default:
				m.dropped.Add(1)
			}
		}
	}
}
