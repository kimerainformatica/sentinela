package collect

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinela/internal/model"
)

// Medição do custo de processamento: cada operação da análise de arquivos
// é cronometrada, para saber onde o agente gasta CPU e disco.

// Nomes das operações (aparecem no painel e no comando bench).
const (
	OpStat      = "metadados"   // tamanho, datas, atributos
	OpHash      = "sha256"      // leitura completa + hash
	OpVersion   = "versao"      // recurso de versão (fabricante, descrição)
	OpSignature = "assinatura"  // WinVerifyTrust da assinatura embutida
	OpCatalog   = "catalogo"    // busca e verificação no catálogo do Windows
	OpSigner    = "assinante"   // nome de quem assinou
	OpPE        = "pe"          // cabeçalho PE, seções, entropia
	OpMOTW      = "origem"      // Mark of the Web (Zone.Identifier)
)

var opOrder = []string{OpStat, OpHash, OpVersion, OpSignature, OpCatalog, OpSigner, OpPE, OpMOTW}

type opTimer struct{ n, ns, bytes atomic.Int64 }

func (o *opTimer) add(d time.Duration, b int64) {
	o.n.Add(1)
	o.ns.Add(int64(d))
	o.bytes.Add(b)
}

type inspectPerf struct {
	lookups, hits atomic.Int64
	ops           map[string]*opTimer

	slowMu sync.Mutex
	slow   []model.SlowFile
}

func newInspectPerf() *inspectPerf {
	p := &inspectPerf{ops: map[string]*opTimer{}}
	for _, o := range opOrder {
		p.ops[o] = &opTimer{}
	}
	return p
}

// track cronometra uma operação: defer in.track(OpHash, time.Now(), &n)
func (p *inspectPerf) time(op string, start time.Time, bytes int64) {
	p.ops[op].add(time.Since(start), bytes)
}

const keepSlowest = 10

func (p *inspectPerf) file(path string, d time.Duration) {
	ms := float64(d.Microseconds()) / 1000
	p.slowMu.Lock()
	defer p.slowMu.Unlock()
	if len(p.slow) == keepSlowest && ms <= p.slow[len(p.slow)-1].MS {
		return
	}
	p.slow = append(p.slow, model.SlowFile{Path: path, MS: ms})
	sort.Slice(p.slow, func(i, j int) bool { return p.slow[i].MS > p.slow[j].MS })
	if len(p.slow) > keepSlowest {
		p.slow = p.slow[:keepSlowest]
	}
}

// snapshot devolve os totais; reset zera para o próximo período.
func (p *inspectPerf) snapshot(reset bool) model.InspectPerf {
	out := model.InspectPerf{Ops: map[string]model.OpCost{}}
	if reset {
		out.Lookups, out.CacheHits = p.lookups.Swap(0), p.hits.Swap(0)
	} else {
		out.Lookups, out.CacheHits = p.lookups.Load(), p.hits.Load()
	}
	for name, o := range p.ops {
		var c model.OpCost
		if reset {
			c = model.OpCost{Count: o.n.Swap(0), MS: float64(o.ns.Swap(0)) / 1e6, Bytes: o.bytes.Swap(0)}
		} else {
			c = model.OpCost{Count: o.n.Load(), MS: float64(o.ns.Load()) / 1e6, Bytes: o.bytes.Load()}
		}
		if c.Count > 0 {
			out.Ops[name] = c
		}
	}
	p.slowMu.Lock()
	out.Slowest = append([]model.SlowFile(nil), p.slow...)
	if reset {
		p.slow = nil
	}
	p.slowMu.Unlock()
	return out
}

// Perf devolve o custo acumulado da análise de arquivos.
func (in *Inspector) Perf() model.InspectPerf { return in.perf.snapshot(false) }

// TakePerf devolve o custo acumulado e zera os contadores.
func (in *Inspector) TakePerf() model.InspectPerf { return in.perf.snapshot(true) }

// OpOrder é a ordem de exibição das operações.
func OpOrder() []string { return append([]string(nil), opOrder...) }

// ---------------------------------------------------------------------------
// Consumo do próprio processo

var procGetProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// SelfCPU é o tempo de CPU (usuário + kernel) já usado por este processo.
func SelfCPU() time.Duration {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u) != nil {
		return 0
	}
	ft := func(f windows.Filetime) int64 { return int64(f.HighDateTime)<<32 | int64(f.LowDateTime) }
	return time.Duration((ft(k) + ft(u)) * 100)
}

// SelfMemMB é o working set deste processo, em MB.
func SelfMemMB() float64 {
	var m processMemoryCounters
	m.cb = uint32(unsafe.Sizeof(m))
	r, _, _ := procGetProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&m)), uintptr(m.cb))
	if r == 0 {
		return 0
	}
	return float64(m.WorkingSetSize) / (1 << 20)
}

