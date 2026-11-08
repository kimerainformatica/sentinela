package collect

import (
	"encoding/binary"
	"errors"
	"os"
	"unicode/utf16"
)

// Parser mínimo do formato Shell Link (.lnk), suficiente para descobrir o
// alvo e os argumentos de atalhos na pasta "Inicializar".
// Referência: [MS-SHLLINK].

const (
	lnkHasIDList   = 0x01
	lnkHasLinkInfo = 0x02
	lnkHasName     = 0x04
	lnkHasRelPath  = 0x08
	lnkHasWorkDir  = 0x10
	lnkHasArgs     = 0x20
	lnkHasIcon     = 0x40
	lnkIsUnicode   = 0x80

	lnkEnvBlockSig = 0xA0000001
)

var errBadLnk = errors.New("atalho .lnk inválido")

type LnkInfo struct {
	Target  string
	Args    string
	WorkDir string
	RelPath string
}

func ParseLnkFile(path string) (*LnkInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > 1<<20 {
		return nil, errBadLnk
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseLnk(b)
}

type lnkReader struct {
	b []byte
}

func (r lnkReader) u16(off int) (int, bool) {
	if off < 0 || off+2 > len(r.b) {
		return 0, false
	}
	return int(binary.LittleEndian.Uint16(r.b[off:])), true
}

func (r lnkReader) u32(off int) (int, bool) {
	if off < 0 || off+4 > len(r.b) {
		return 0, false
	}
	return int(binary.LittleEndian.Uint32(r.b[off:])), true
}

func (r lnkReader) asciiZ(off int) string {
	if off < 0 || off >= len(r.b) {
		return ""
	}
	end := off
	for end < len(r.b) && r.b[end] != 0 {
		end++
	}
	return string(r.b[off:end])
}

func (r lnkReader) utf16Z(off, maxChars int) string {
	var u []uint16
	for i := 0; i < maxChars; i++ {
		c, ok := r.u16(off + i*2)
		if !ok || c == 0 {
			break
		}
		u = append(u, uint16(c))
	}
	return string(utf16.Decode(u))
}

func ParseLnk(b []byte) (*LnkInfo, error) {
	r := lnkReader{b}
	hdr, ok := r.u32(0)
	if !ok || hdr != 0x4C {
		return nil, errBadLnk
	}
	flags, _ := r.u32(0x14)
	off := 0x4C
	info := &LnkInfo{}

	if flags&lnkHasIDList != 0 {
		n, ok := r.u16(off)
		if !ok {
			return nil, errBadLnk
		}
		off += 2 + n
	}

	if flags&lnkHasLinkInfo != 0 {
		size, ok1 := r.u32(off)
		hsize, ok2 := r.u32(off + 4)
		liFlags, ok3 := r.u32(off + 8)
		if !ok1 || !ok2 || !ok3 || size < 0x1C {
			return nil, errBadLnk
		}
		if liFlags&1 != 0 { // VolumeIDAndLocalBasePath
			if hsize >= 0x24 {
				if uo, ok := r.u32(off + 0x1C); ok && uo > 0 {
					info.Target = r.utf16Z(off+uo, 32768)
				}
			}
			if info.Target == "" {
				if lo, ok := r.u32(off + 0x10); ok && lo > 0 {
					info.Target = r.asciiZ(off + lo)
				}
			}
			if so, ok := r.u32(off + 0x18); ok && so > 0 {
				info.Target += r.asciiZ(off + so)
			}
		}
		off += size
	}

	unicode := flags&lnkIsUnicode != 0
	readStr := func() (string, bool) {
		n, ok := r.u16(off)
		if !ok {
			return "", false
		}
		off += 2
		if unicode {
			if off+n*2 > len(b) {
				return "", false
			}
			u := make([]uint16, n)
			for i := 0; i < n; i++ {
				u[i] = binary.LittleEndian.Uint16(b[off+i*2:])
			}
			off += n * 2
			return string(utf16.Decode(u)), true
		}
		if off+n > len(b) {
			return "", false
		}
		s := string(b[off : off+n])
		off += n
		return s, true
	}

	for _, f := range []int{lnkHasName, lnkHasRelPath, lnkHasWorkDir, lnkHasArgs, lnkHasIcon} {
		if flags&f == 0 {
			continue
		}
		s, ok := readStr()
		if !ok {
			return info, nil
		}
		switch f {
		case lnkHasRelPath:
			info.RelPath = s
		case lnkHasWorkDir:
			info.WorkDir = s
		case lnkHasArgs:
			info.Args = s
		}
	}

	// ExtraData: o EnvironmentVariableDataBlock guarda o alvo com variáveis
	// de ambiente (ex.: %APPDATA%\x.exe) quando não há LinkInfo.
	if info.Target == "" {
		for {
			size, ok := r.u32(off)
			if !ok || size < 8 {
				break
			}
			sig, _ := r.u32(off + 4)
			if uint32(sig) == lnkEnvBlockSig && size >= 0x314 {
				info.Target = r.utf16Z(off+268, 260)
				if info.Target == "" {
					info.Target = r.asciiZ(off + 8)
				}
				break
			}
			off += size
		}
	}
	return info, nil
}
