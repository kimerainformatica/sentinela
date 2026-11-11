package collect

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildPE monta um executável mínimo (só cabeçalhos e seções) para o teste.
func buildPE(t *testing.T, sections map[string][]byte, order []string, overlay int) []byte {
	t.Helper()
	const lfanew = 0x80
	var b bytes.Buffer
	dos := make([]byte, lfanew)
	dos[0], dos[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(dos[60:], lfanew)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	fh := make([]byte, 20)
	binary.LittleEndian.PutUint16(fh[0:], 0x8664)
	binary.LittleEndian.PutUint16(fh[2:], uint16(len(order)))
	binary.LittleEndian.PutUint32(fh[4:], uint32(time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC).Unix()))
	binary.LittleEndian.PutUint16(fh[16:], 0) // sem cabeçalho opcional
	binary.LittleEndian.PutUint16(fh[18:], 0x0002)
	b.Write(fh)
	dataStart := lfanew + 24 + 40*len(order)
	off := dataStart
	for _, name := range order {
		sh := make([]byte, 40)
		copy(sh, name)
		binary.LittleEndian.PutUint32(sh[16:], uint32(len(sections[name])))
		binary.LittleEndian.PutUint32(sh[20:], uint32(off))
		binary.LittleEndian.PutUint32(sh[36:], 0x60000020) // código, executável, leitura
		b.Write(sh)
		off += len(sections[name])
	}
	for _, name := range order {
		b.Write(sections[name])
	}
	b.Write(make([]byte, overlay))
	return b.Bytes()
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnalyzePE(t *testing.T) {
	plain := bytes.Repeat([]byte("mov eax, ebx; ret; "), 4000) // baixa entropia
	random := make([]byte, 64<<10)
	rand.Read(random) // entropia ~8: conteúdo cifrado/comprimido

	p := writeTemp(t, "normal.exe", buildPE(t, map[string][]byte{".text": plain}, []string{".text"}, 1000))
	info := analyzePE(p)
	if info == nil || !info.IsPE || info.Machine != "x64" || info.Packed || info.Overlay != 1000 || info.Compiled == nil || info.Compiled.Year() != 2024 {
		t.Fatalf("PE normal: %+v", info)
	}

	p = writeTemp(t, "upx.exe", buildPE(t, map[string][]byte{"UPX0": plain, "UPX1": plain}, []string{"UPX0", "UPX1"}, 0))
	if info := analyzePE(p); !info.Packed || info.Packer != "UPX" {
		t.Fatalf("UPX: %+v", info)
	}

	p = writeTemp(t, "cifrado.exe", buildPE(t, map[string][]byte{".text": random}, []string{".text"}, 0))
	if info := analyzePE(p); !info.Packed || info.MaxEntropy < 7.9 {
		t.Fatalf("cifrado: %+v", info)
	}

	p = writeTemp(t, "script.exe", []byte("@echo off\r\necho isto nao e um executavel\r\n"))
	if info := analyzePE(p); info == nil || info.IsPE {
		t.Fatalf("não-PE: %+v", info)
	}
}

func TestReadOrigin(t *testing.T) {
	p := writeTemp(t, "baixado.exe", []byte("x"))
	if readOrigin(p) != nil {
		t.Fatal("arquivo sem Zone.Identifier deveria não ter origem")
	}
	zi := "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://site.invalid/pagina\r\nHostUrl=https://site.invalid/baixado.exe\r\n"
	if err := os.WriteFile(p+":Zone.Identifier", []byte(zi), 0o600); err != nil {
		t.Skipf("sistema de arquivos sem fluxos alternativos: %v", err)
	}
	o := readOrigin(p)
	if o == nil || o.Zone != 3 || o.ZoneName != "internet" || o.HostURL != "https://site.invalid/baixado.exe" || !strings.Contains(o.Referrer, "pagina") {
		t.Fatalf("origem: %+v", o)
	}
}

func TestInspectorCache(t *testing.T) {
	p := writeTemp(t, "app.exe", []byte("versão 1"))
	in := NewInspector()
	defer in.Close()

	a := in.Inspect(p)
	if b := in.Inspect(p); b != a {
		t.Fatal("arquivo sem mudança deveria vir do cache")
	}
	// Conteúdo trocado e data de modificação restaurada (disfarce comum):
	// o ChangeTime do NTFS denuncia a troca.
	st, _ := os.Stat(p)
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(p, []byte("versão 2"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(p, st.ModTime(), st.ModTime())
	c := in.Inspect(p)
	if c == a || c.SHA256 == a.SHA256 {
		t.Fatalf("troca de conteúdo com data restaurada não foi detectada: %s", c.SHA256)
	}

	// Gravar e carregar o cache.
	cp := filepath.Join(t.TempDir(), "cache.json")
	if err := in.SaveCache(cp); err != nil {
		t.Fatal(err)
	}
	in2 := NewInspector()
	defer in2.Close()
	if n, err := in2.LoadCache(cp); err != nil || n != 1 {
		t.Fatalf("carregar cache: n=%d err=%v", n, err)
	}
	if d := in2.Inspect(p); d.SHA256 != c.SHA256 || in2.Perf().CacheHits != 1 {
		t.Fatalf("cache carregado não foi usado: %+v", in2.Perf())
	}

	// Entrada vencida é refeita mesmo sem mudança.
	in2.mu.Lock()
	for _, e := range in2.cache {
		e.Checked = time.Now().Add(-48 * time.Hour)
	}
	in2.mu.Unlock()
	in2.Inspect(p)
	if in2.Perf().CacheHits != 1 {
		t.Fatal("entrada vencida não deveria vir do cache")
	}
}

func TestEntropy(t *testing.T) {
	if e := entropy(bytes.NewReader(bytes.Repeat([]byte{7}, 1000))); e != 0 {
		t.Fatalf("entropia de bytes iguais = %v", e)
	}
	all := make([]byte, 256*16)
	for i := range all {
		all[i] = byte(i)
	}
	if e := entropy(bytes.NewReader(all)); e < 7.99 || e > 8.0001 {
		t.Fatalf("entropia de distribuição uniforme = %v", e)
	}
}
