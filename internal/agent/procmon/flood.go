package procmon

import (
	"sort"
	"time"

	"sentinela/internal/model"
)

// Detector de enxurrada (flood) de conexões TCP em tempo real.
//
// A máquina pode estar de dois lados de um DDoS:
//   - saída: um processo abre uma avalanche de conexões — sinal de que a
//     máquina virou bot de uma botnet e está atacando alguém;
//   - entrada: uma avalanche de conexões chega a uma porta local — a máquina
//     é a vítima.
//
// Para cada processo (saída) e cada porta local (entrada) o detector mantém
// contadores numa janela deslizante curta. Quando um limite é ultrapassado,
// emite um incidente — uma vez por episódio (há um tempo de silêncio entre
// incidentes do mesmo alvo) — e o agente responde.
//
// É de propósito simples e barato (só somas em mapas pequenos): precisa
// aguentar justamente o momento de pico, quando chegam milhares de conexões.

// FloodConfig reúne os limites de detecção.
type FloodConfig struct {
	Window       time.Duration // janela de observação
	OutPerTarget int           // conexões de saída ao mesmo destino -> flood a um alvo
	OutSpread    int           // destinos distintos -> varredura/disparo em massa
	OutTotal     int           // total de conexões de saída de um processo
	InPerPort    int           // conexões de entrada à mesma porta local
	InPerSource  int           // conexões de entrada da mesma origem -> origem a bloquear
	Cooldown     time.Duration // silêncio mínimo entre incidentes do mesmo alvo
	MaxKeys      int           // teto de origens/destinos distintos rastreados por alvo
}

// DefaultFloodConfig traz limites pensados para não disparar com uso normal
// (navegador, sincronização, torrent espalham-se por muitos destinos com
// poucas conexões cada; um DDoS concentra um volume alto num curto intervalo).
func DefaultFloodConfig() FloodConfig {
	return FloodConfig{
		Window:       10 * time.Second,
		OutPerTarget: 300,
		OutSpread:    150,
		OutTotal:     800,
		InPerPort:    400,
		InPerSource:  80,
		Cooldown:     45 * time.Second,
		MaxKeys:      8192,
	}
}

// window é o contador de uma janela (tumbling): zera quando a janela expira.
type window struct {
	start   time.Time
	total   int
	targets map[string]int // destino/origem -> contagem (limitado por MaxKeys)
	capped  bool           // atingiu MaxKeys: muitos destinos/origens distintos
	firedAt time.Time      // último incidente emitido para este alvo
}

type floodDetector struct {
	cfg FloodConfig
	out map[uint32]*window // por PID (saída)
	in  map[uint16]*window // por porta local (entrada)
	// prune ocasional para não acumular alvos inativos.
	lastPrune time.Time
}

func newFloodDetector(cfg FloodConfig) *floodDetector {
	return &floodDetector{cfg: cfg, out: map[uint32]*window{}, in: map[uint16]*window{}}
}

func (w *window) roll(now time.Time, win time.Duration) {
	if w.start.IsZero() || now.Sub(w.start) >= win {
		w.start = now
		w.total = 0
		w.targets = nil
		w.capped = false
	}
}

func (w *window) add(key string, max int) {
	w.total++
	if w.targets == nil {
		w.targets = make(map[string]int, 16)
	}
	if _, ok := w.targets[key]; ok || len(w.targets) < max {
		w.targets[key]++
	} else {
		w.capped = true
	}
}

func (w *window) distinct() int {
	if w.capped {
		return len(w.targets) // já no teto; é um limite inferior
	}
	return len(w.targets)
}

func (w *window) maxTarget() (string, int) {
	best, n := "", 0
	for k, c := range w.targets {
		if c > n {
			best, n = k, c
		}
	}
	return best, n
}

// observe registra uma conexão e devolve um incidente quando um limite é
// cruzado. suppress indica que o alvo está em pleno flood (um incidente já
// foi emitido há pouco): o chamador deve contar mas não gerar telemetria
// individual, para não inundar o canal durante o ataque.
func (d *floodDetector) observe(dir string, pid uint32, raddr string, lport uint16, now time.Time) (inc *model.FloodIncident, suppress bool) {
	if now.Sub(d.lastPrune) > 2*d.cfg.Window {
		d.prune(now)
	}
	if dir == "entrada" {
		return d.observeIn(pid, raddr, lport, now)
	}
	return d.observeOut(pid, raddr, now)
}

func (d *floodDetector) observeOut(pid uint32, raddr string, now time.Time) (*model.FloodIncident, bool) {
	w := d.out[pid]
	if w == nil {
		w = &window{}
		d.out[pid] = w
	}
	w.roll(now, d.cfg.Window)
	w.add(raddr, d.cfg.MaxKeys)

	if !w.firedAt.IsZero() && now.Sub(w.firedAt) < d.cfg.Cooldown {
		return nil, true // já em flood: conta, mas silencia a telemetria
	}

	reason, target := "", ""
	if top, n := w.maxTarget(); n >= d.cfg.OutPerTarget {
		reason, target = "alvo", top
	} else if w.distinct() >= d.cfg.OutSpread || w.capped {
		reason = "espalhada"
	} else if w.total >= d.cfg.OutTotal {
		reason = "volume"
	}
	if reason == "" {
		return nil, false
	}
	w.firedAt = now
	inc := &model.FloodIncident{
		Time: now.UTC(), Direction: "saida", Reason: reason, PID: pid,
		WindowS: d.cfg.Window.Seconds(), Count: w.total, Distinct: w.distinct(), Target: target,
	}
	return inc, true
}

func (d *floodDetector) observeIn(pid uint32, raddr string, lport uint16, now time.Time) (*model.FloodIncident, bool) {
	w := d.in[lport]
	if w == nil {
		w = &window{}
		d.in[lport] = w
	}
	w.roll(now, d.cfg.Window)
	w.add(raddr, d.cfg.MaxKeys)

	if !w.firedAt.IsZero() && now.Sub(w.firedAt) < d.cfg.Cooldown {
		return nil, true
	}
	if w.total < d.cfg.InPerPort {
		return nil, false
	}
	w.firedAt = now
	inc := &model.FloodIncident{
		Time: now.UTC(), Direction: "entrada", Reason: "entrada", PID: pid,
		WindowS: d.cfg.Window.Seconds(), Count: w.total, Distinct: w.distinct(), LocalPort: lport,
		Sources: topSources(w.targets, d.cfg.InPerSource),
	}
	return inc, true
}

// topSources devolve as origens que passaram do limite por origem, da maior
// para a menor (as que vale a pena bloquear no firewall).
func topSources(m map[string]int, min int) []model.SourceCount {
	var out []model.SourceCount
	for ip, c := range m {
		if c >= min {
			out = append(out, model.SourceCount{IP: ip, Count: c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func (d *floodDetector) prune(now time.Time) {
	d.lastPrune = now
	for pid, w := range d.out {
		if now.Sub(w.start) > 2*d.cfg.Window && now.Sub(w.firedAt) > d.cfg.Cooldown {
			delete(d.out, pid)
		}
	}
	for port, w := range d.in {
		if now.Sub(w.start) > 2*d.cfg.Window && now.Sub(w.firedAt) > d.cfg.Cooldown {
			delete(d.in, port)
		}
	}
}
