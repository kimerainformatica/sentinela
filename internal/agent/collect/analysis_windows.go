package collect

import (
	"bufio"
	"encoding/binary"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinela/internal/model"
)

// Análise aprofundada de arquivos, além de hash e assinatura:
//   - origem (Mark of the Web): de onde o arquivo foi baixado;
//   - estrutura do executável (PE): data de compilação, seções, entropia e
//     empacotadores, que escondem o código real de quem analisa.
//
// O custo é controlado: a origem é só a leitura de um fluxo pequeno; o PE
// é analisado apenas para arquivos sem assinatura válida, e o arquivo já
// está no cache do sistema por causa do hash.

// Limite de bytes lidos das seções para calcular a entropia.
const maxEntropyBytes = 32 << 20

func (in *Inspector) deepAnalysis(path string, fi *model.FileInfo) {
	if !underWindows(path) {
		t := time.Now()
		fi.Origin = readOrigin(path)
		in.perf.time(OpMOTW, t, 0)
	}
	if fi.Signature != "valid" && fi.Size > 0 {
		t := time.Now()
		fi.PE = analyzePE(path)
		in.perf.time(OpPE, t, 0)
	}
}

func underWindows(path string) bool {
	wd := strings.ToLower(winDir())
	return wd != "" && strings.HasPrefix(strings.ToLower(path), wd+`\`)
}

var zoneNames = map[int]string{0: "computador local", 1: "intranet", 2: "sites confiáveis", 3: "internet", 4: "sites não confiáveis"}

// readOrigin lê o fluxo alternativo Zone.Identifier (nil se não houver).
func readOrigin(path string) *model.FileOrigin {
	f, err := os.Open(path + ":Zone.Identifier")
	if err != nil {
		return nil
	}
	defer f.Close()
	o := &model.FileOrigin{Zone: -1}
	sc := bufio.NewScanner(io.LimitReader(f, 8<<10))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "zoneid":
			o.Zone, _ = strconv.Atoi(strings.TrimSpace(v))
		case "hosturl":
			o.HostURL = truncateStr(v, 500)
		case "referrerurl":
			o.Referrer = truncateStr(v, 500)
		}
	}
	if o.Zone < 0 {
		return nil
	}
	o.ZoneName = zoneNames[o.Zone]
	return o
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Nomes de seção deixados por empacotadores/protetores conhecidos.
var packerSections = map[string]string{
	"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
	".aspack": "ASPack", ".adata": "ASPack",
	".themida": "Themida", ".winlice": "Themida/WinLicense",
	".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
	".mpress1": "MPRESS", ".mpress2": "MPRESS",
	".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack",
	".enigma1": "Enigma", ".enigma2": "Enigma",
	"pec1": "PECompact", "pec2": "PECompact", ".pec": "PECompact",
	".mew": "MEW", ".fsg": "FSG", ".packed": "desconhecido",
}

// Entropia a partir da qual o código está, quase certamente, comprimido ou
// cifrado (código de máquina comum fica entre 5,5 e 6,8).
const packedEntropy = 7.2

// Campos do cabeçalho PE usados aqui.
const (
	peFileDLL      = 0x2000
	peScnCntCode   = 0x00000020
	peScnMemExec   = 0x20000000
	peMaxSections  = 96
	peSectionBytes = 40
)

// analyzePE lê só os cabeçalhos (DOS, COFF e tabela de seções) e o conteúdo
// das seções de código. Não usa debug/pe, que carrega a tabela de símbolos
// inteira (centenas de MB em binários grandes compilados em Go).
func analyzePE(path string) *model.PEInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	notPE := &model.PEInfo{IsPE: false}

	var dos [64]byte
	if _, err := io.ReadFull(f, dos[:]); err != nil || dos[0] != 'M' || dos[1] != 'Z' {
		return notPE
	}
	lfanew := int64(binary.LittleEndian.Uint32(dos[60:]))
	if lfanew <= 0 || lfanew > 64<<10 || lfanew+24 > st.Size() {
		return notPE
	}
	var hdr [24]byte // assinatura "PE\x00\x00" + IMAGE_FILE_HEADER
	if _, err := f.ReadAt(hdr[:], lfanew); err != nil || string(hdr[:4]) != "PE\x00\x00" {
		return notPE
	}
	machine := binary.LittleEndian.Uint16(hdr[4:])
	nsec := int(binary.LittleEndian.Uint16(hdr[6:]))
	stamp := binary.LittleEndian.Uint32(hdr[8:])
	optSize := int64(binary.LittleEndian.Uint16(hdr[20:]))
	chars := binary.LittleEndian.Uint16(hdr[22:])

	info := &model.PEInfo{IsPE: true, DLL: chars&peFileDLL != 0}
	switch machine {
	case 0x8664:
		info.Machine = "x64"
	case 0x14c:
		info.Machine = "x86"
	case 0xaa64:
		info.Machine = "ARM64"
	default:
		info.Machine = "0x" + strconv.FormatUint(uint64(machine), 16)
	}
	// Builds reprodutíveis (ex.: Windows) gravam um hash no lugar da data.
	if c := time.Unix(int64(stamp), 0).UTC(); stamp != 0 && c.Year() >= 1995 && c.Before(time.Now().Add(48*time.Hour)) {
		info.Compiled = &c
	}
	if nsec > peMaxSections {
		nsec = peMaxSections
	}
	tbl := make([]byte, nsec*peSectionBytes)
	if _, err := f.ReadAt(tbl, lfanew+24+optSize); err != nil {
		return info
	}

	var end int64
	budget := int64(maxEntropyBytes)
	for i := 0; i < nsec; i++ {
		sh := tbl[i*peSectionBytes : (i+1)*peSectionBytes]
		name := strings.TrimRight(string(sh[:8]), "\x00")
		rawSize := int64(binary.LittleEndian.Uint32(sh[16:]))
		rawPtr := int64(binary.LittleEndian.Uint32(sh[20:]))
		scn := binary.LittleEndian.Uint32(sh[36:])
		info.Sections = append(info.Sections, name)
		if p, ok := packerSections[strings.ToLower(name)]; ok && info.Packer == "" {
			info.Packer = p
		}
		if rawPtr+rawSize > end && rawPtr+rawSize <= st.Size() {
			end = rawPtr + rawSize
		}
		if scn&(peScnMemExec|peScnCntCode) == 0 || rawSize == 0 || budget <= 0 || rawPtr >= st.Size() {
			continue
		}
		n := min(rawSize, budget, st.Size()-rawPtr)
		budget -= n
		if e := entropy(io.NewSectionReader(f, rawPtr, n)); e > info.MaxEntropy {
			info.MaxEntropy = e
		}
	}
	if end > 0 && st.Size() > end {
		info.Overlay = st.Size() - end
	}
	info.MaxEntropy = math.Round(info.MaxEntropy*100) / 100
	info.Packed = info.Packer != "" || info.MaxEntropy >= packedEntropy
	return info
}

// entropy é a entropia de Shannon em bits por byte (0 a 8).
func entropy(r io.Reader) float64 {
	var hist [256]int64
	buf := make([]byte, 64<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			hist[b]++
		}
		total += int64(n)
		if err != nil {
			break
		}
	}
	if total == 0 {
		return 0
	}
	h := 0.0
	for _, c := range hist {
		if c > 0 {
			p := float64(c) / float64(total)
			h -= p * math.Log2(p)
		}
	}
	return h
}
