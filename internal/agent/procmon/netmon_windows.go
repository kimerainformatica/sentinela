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

// early registra o que o ETW já informou de uma execução, sem sobrescrever
// um registro mais completo do mesmo PID.
func (c *procCache) early(pid, ppid uint32, image, cmdline string) {
	if !filepath.IsAbs(image) {
		if img := imageFromCmdline(cmdline); img != "" {
			image = img
		}
	}
	if image == "" {
		return
	}
	e := procEntry{ppid: ppid, name: filepath.Base(image)}
	if filepath.IsAbs(image) {
		e.image = image
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.m[pid]; ok && old.image != "" && strings.EqualFold(old.name, e.name) {
		return
	}
	c.m[pid] = e
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
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()

	// Conexões cujo dono ainda não é conhecido: o processo pode ter terminado
	// antes de o monitor de execuções registrá-lo. Esperam até ownerWait.
	type waitingConn struct {
		r     rawNet
		since time.Time
	}
	var waiting []waitingConn

	owner := func(pid uint32) (name, image string) {
		if pid == 4 {
			return "System", ""
		}
		e, ok := m.procs.get(pid)
		if ok && e.image != "" {
			return e.name, e.image
		}
		p := model.Process{PID: pid}
		if collect.DescribeProcess(&p, users) {
			image = p.ImagePath
			name = filepath.Base(image)
			m.procs.set(pid, procEntry{name: name, image: image})
			return name, image
		}
		if ok {
			return e.name, ""
		}
		if s, found := snapshot()[pid]; found {
			// Sem permissão para abrir o processo (serviço, agente sem
			// admin): o nome ainda vem da lista de processos.
			m.procs.set(pid, s)
			return s.name, ""
		}
		return "", ""
	}

	for {
		var r rawNet
		var name, image string
		select {
		case <-m.stop:
			return
		case <-cleanup.C:
			for k, s := range seen {
				if time.Since(s.last) > netDedupWindow {
					delete(seen, k)
				}
			}
			continue
		case <-retry.C:
			if len(waiting) == 0 {
				continue
			}
			// Reenvia, na ordem, as que já têm dono ou esgotaram a espera.
			keep := waiting[:0]
			var ready []rawNet
			for _, w := range waiting {
				if n, _ := owner(w.r.pid); n != "" || time.Since(w.since) >= ownerWait {
					ready = append(ready, w.r)
				} else {
					keep = append(keep, w)
				}
			}
			waiting = keep
			for _, rr := range ready {
				n, img := owner(rr.pid)
				m.emitNet(rr, n, img, seen, in, out)
			}
			continue
		case r = <-raw:
		}
		if ignorableAddr(r.raddr) {
			continue
		}
		if name, image = owner(r.pid); name == "" && len(waiting) < 2000 {
			waiting = append(waiting, waitingConn{r: r, since: time.Now()})
			continue
		}
		m.emitNet(r, name, image, seen, in, out)
	}
}

// ownerWait é quanto uma conexão espera o monitor de execuções informar
// o dono do PID antes de ser enviada sem o nome do programa.
const ownerWait = 3 * time.Second

// emitNet agrupa repetições (mesma conexão do mesmo programa vira um evento
// a cada 10 min), analisa o executável e envia o evento.
func (m *Monitor) emitNet(r rawNet, name, image string, seen map[string]*seenConn, in *collect.Inspector, out chan<- model.NetEvent) {
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
		return
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
