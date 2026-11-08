package collect

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func testResolver(files ...string) *Resolver {
	set := map[string]bool{}
	for _, f := range files {
		set[strings.ToLower(f)] = true
	}
	return &Resolver{
		WinDir: `C:\Windows`,
		Env: func(k string) string {
			switch strings.ToUpper(k) {
			case "SYSTEMROOT", "WINDIR":
				return `C:\Windows`
			case "APPDATA":
				return `C:\Users\ana\AppData\Roaming`
			}
			return ""
		},
		Exists: func(p string) bool { return set[strings.ToLower(p)] },
	}
}

func TestResolve(t *testing.T) {
	r := testResolver(
		`C:\Program Files\Acme App\acme.exe`,
		`C:\Windows\System32\rundll32.exe`,
		`C:\Windows\System32\svchost.exe`,
		`C:\Windows\System32\drivers\acpi.sys`,
	)
	cases := []struct{ in, img, args string }{
		{`"C:\Program Files\Acme App\acme.exe" /min`, `C:\Program Files\Acme App\acme.exe`, `/min`},
		{`C:\Program Files\Acme App\acme.exe /min`, `C:\Program Files\Acme App\acme.exe`, `/min`},
		{`C:\Program Files\Acme App\acme /min`, `C:\Program Files\Acme App\acme.exe`, `/min`},
		{`rundll32.exe C:\x\a.dll,Start`, `C:\Windows\System32\rundll32.exe`, `C:\x\a.dll,Start`},
		{`%SystemRoot%\System32\svchost.exe -k netsvcs`, `C:\Windows\System32\svchost.exe`, `-k netsvcs`},
		{`\SystemRoot\System32\drivers\acpi.sys`, `C:\Windows\System32\drivers\acpi.sys`, ``},
		{`System32\drivers\acpi.sys`, `C:\Windows\System32\drivers\acpi.sys`, ``},
		{`\??\C:\evil\drv.sys`, `C:\evil\drv.sys`, ``},
		{`%APPDATA%\upd\updater.exe`, `C:\Users\ana\AppData\Roaming\upd\updater.exe`, ``},
	}
	for _, c := range cases {
		img, args := r.Resolve(c.in)
		if img != c.img || args != c.args {
			t.Errorf("Resolve(%q) = (%q, %q), esperado (%q, %q)", c.in, img, args, c.img, c.args)
		}
	}
}

func TestPayload(t *testing.T) {
	r := testResolver(`C:\Windows\System32\shell32.dll`)
	cases := []struct{ img, args, want string }{
		{`C:\Windows\System32\rundll32.exe`, `C:\Users\a\AppData\Local\x.dll,DllMain`, `C:\Users\a\AppData\Local\x.dll`},
		{`C:\Windows\System32\wscript.exe`, `//B "%APPDATA%\run me.vbs"`, `C:\Users\ana\AppData\Roaming\run me.vbs`},
		{`C:\Windows\System32\rundll32.exe`, `shell32.dll,Control_RunDLL`, `C:\Windows\System32\shell32.dll`},
		{`C:\Windows\System32\mshta.exe`, `http://evil/x.hta`, ``},
		{`C:\Program Files\app.exe`, `C:\x.dll`, ``},
	}
	for _, c := range cases {
		if got := r.Payload(c.img, c.args); got != c.want {
			t.Errorf("Payload(%q, %q) = %q, esperado %q", c.img, c.args, got, c.want)
		}
	}
}

// Monta um .lnk mínimo com LinkInfo (LocalBasePath) e argumentos Unicode.
func TestParseLnk(t *testing.T) {
	target := `C:\Users\ana\AppData\Roaming\x\evil.exe`
	b := make([]byte, 0x4C)
	binary.LittleEndian.PutUint32(b[0:], 0x4C)
	binary.LittleEndian.PutUint32(b[0x14:], lnkHasLinkInfo|lnkHasArgs|lnkIsUnicode)

	li := make([]byte, 0x1C)
	binary.LittleEndian.PutUint32(li[4:], 0x1C)  // header size
	binary.LittleEndian.PutUint32(li[8:], 1)     // VolumeIDAndLocalBasePath
	binary.LittleEndian.PutUint32(li[0x10:], 0x1C) // LocalBasePathOffset
	li = append(li, []byte(target)...)
	li = append(li, 0)
	binary.LittleEndian.PutUint32(li[0x18:], uint32(len(li))) // CommonPathSuffixOffset -> ""
	li = append(li, 0)
	binary.LittleEndian.PutUint32(li[0:], uint32(len(li)))
	b = append(b, li...)

	args := utf16.Encode([]rune("-silent"))
	n := make([]byte, 2)
	binary.LittleEndian.PutUint16(n, uint16(len(args)))
	b = append(b, n...)
	for _, c := range args {
		x := make([]byte, 2)
		binary.LittleEndian.PutUint16(x, c)
		b = append(b, x...)
	}

	info, err := ParseLnk(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.Target != target || info.Args != "-silent" {
		t.Fatalf("obtido %+v", info)
	}
	if _, err := ParseLnk([]byte("lixo")); err == nil {
		t.Fatal("esperava erro para entrada inválida")
	}
}
