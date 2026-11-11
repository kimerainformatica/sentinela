package procmon

import (
	"fmt"
	"testing"
	"time"
)

func TestFloodOutboundTarget(t *testing.T) {
	d := newFloodDetector(DefaultFloodConfig())
	now := time.Now()
	var got int
	for i := 0; i < 500; i++ {
		inc, _ := d.observe("saida", 100, "203.0.113.5", 0, now.Add(time.Duration(i)*time.Millisecond))
		if inc != nil {
			got++
			if inc.Reason != "alvo" || inc.Target != "203.0.113.5" || inc.Direction != "saida" {
				t.Fatalf("incidente inesperado: %+v", inc)
			}
		}
	}
	if got != 1 {
		t.Fatalf("esperado 1 incidente (cooldown), veio %d", got)
	}
}

func TestFloodOutboundSpread(t *testing.T) {
	d := newFloodDetector(DefaultFloodConfig())
	now := time.Now()
	fired := false
	for i := 0; i < 200; i++ {
		in, _ := d.observe("saida", 7, fmt.Sprintf("198.51.100.%d", i%256), 0, now.Add(time.Duration(i)*time.Millisecond))
		if in != nil {
			fired = true
			if in.Reason != "espalhada" {
				t.Fatalf("esperado espalhada, veio %q (distinct=%d)", in.Reason, in.Distinct)
			}
		}
	}
	if !fired {
		t.Fatal("varredura espalhada não gerou incidente")
	}
}

func TestFloodInboundHeavySources(t *testing.T) {
	d := newFloodDetector(DefaultFloodConfig())
	now := time.Now()
	fired := false
	for i := 0; i < 600; i++ {
		// Poucas origens pesadas (cada uma passa de InPerSource) à porta 443.
		src := fmt.Sprintf("45.0.0.%d", i%4)
		in, _ := d.observe("entrada", 0, src, 443, now.Add(time.Duration(i)*time.Millisecond))
		if in != nil {
			fired = true
			if in.Direction != "entrada" || in.LocalPort != 443 {
				t.Fatalf("incidente de entrada inesperado: %+v", in)
			}
			if len(in.Sources) == 0 {
				t.Fatalf("origens pesadas deveriam aparecer para bloquear: %+v", in)
			}
		}
	}
	if !fired {
		t.Fatal("flood de entrada não gerou incidente")
	}
}

// Um flood distribuído por milhares de origens leves ainda dispara o alerta,
// mas sem origens "pesadas" o bastante para valer um bloqueio individual.
func TestFloodInboundDistributed(t *testing.T) {
	d := newFloodDetector(DefaultFloodConfig())
	now := time.Now()
	fired := false
	for i := 0; i < 600; i++ {
		src := fmt.Sprintf("45.%d.%d.%d", i/65536, (i/256)%256, i%256)
		in, _ := d.observe("entrada", 0, src, 80, now.Add(time.Duration(i)*time.Millisecond))
		if in != nil {
			fired = true
			if len(in.Sources) != 0 {
				t.Fatalf("flood distribuído não deveria ter origens bloqueáveis: %+v", in.Sources)
			}
		}
	}
	if !fired {
		t.Fatal("flood distribuído de entrada não gerou alerta")
	}
}

func TestFloodNoFalsePositive(t *testing.T) {
	d := newFloodDetector(DefaultFloodConfig())
	now := time.Now()
	// Uso normal: 40 destinos, poucas conexões cada, espalhado em 10 s.
	n := 0
	for i := 0; i < 120; i++ {
		in, _ := d.observe("saida", 50, fmt.Sprintf("93.184.216.%d", i%40), 0, now.Add(time.Duration(i)*80*time.Millisecond))
		if in != nil {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("uso normal gerou %d incidentes (falso positivo)", n)
	}
}

func TestFloodWindowResets(t *testing.T) {
	cfg := DefaultFloodConfig()
	d := newFloodDetector(cfg)
	now := time.Now()
	// 200 conexões ao mesmo alvo, mas espalhadas por 100 s: nunca passa de
	// OutPerTarget dentro de uma janela de 10 s.
	n := 0
	for i := 0; i < 200; i++ {
		in, _ := d.observe("saida", 9, "203.0.113.9", 0, now.Add(time.Duration(i)*500*time.Millisecond))
		if in != nil {
			n++
		}
	}
	if n != 0 {
		t.Fatalf("taxa baixa disparou %d incidentes", n)
	}
}
