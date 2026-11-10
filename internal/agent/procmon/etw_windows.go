package procmon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Consumidor ETW em tempo real. Uma única sessão recebe duas fontes:
//
//  1. Provedor de processos do kernel (SystemTraceProvider, flag PROCESS),
//     em "system logger mode" (Windows 8+): traz a LINHA DE COMANDO no
//     próprio evento, mesmo para processos que duram milissegundos.
//  2. Microsoft-Windows-Kernel-Process: traz o CAMINHO COMPLETO do
//     executável (o provedor do kernel só informa o nome curto).
//
// As duas partes são unidas pelo PID no enriquecimento. Exige administrador.

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modtdh      = windows.NewLazySystemDLL("tdh.dll")

	procStartTraceW    = modadvapi32.NewProc("StartTraceW")
	procControlTraceW  = modadvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modadvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = modadvapi32.NewProc("OpenTraceW")
	procProcessTrace   = modadvapi32.NewProc("ProcessTrace")
	procCloseTrace     = modadvapi32.NewProc("CloseTrace")
	procTdhGetPropSize = modtdh.NewProc("TdhGetPropertySize")
	procTdhGetProperty = modtdh.NewProc("TdhGetProperty")
)

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} Microsoft-Windows-Kernel-Process
var kernelProcessGUID = windows.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B,
	Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}

// {3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C} classe de eventos "Process" do kernel
var processClassGUID = windows.GUID{Data1: 0x3D6FA8D0, Data2: 0xFE05, Data3: 0x11D0,
	Data4: [8]byte{0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C}}

const (
	sessionName = "Sentinela-ProcMon"

	wnodeFlagTracedGUID         = 0x00020000
	eventTraceRealTimeMode      = 0x00000100
	eventTraceSystemLoggerMode  = 0x02000000
	eventTraceFlagProcess       = 0x00000001
	eventTraceControlStop       = 1
	eventControlCodeEnable      = 1
	traceLevelVerbose           = 5
	keywordProcess              = 0x10
	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000
	invalidProcessTraceHandle   = ^uint64(0)
	errAlreadyExists            = 183
	eventHeaderFlag32BitHeader  = 0x0020

	eventIDProcessStart = 1 // Kernel-Process: ProcessStart
	opcodeProcessStart  = 1 // classe Process do kernel: Start
)

// Partes de uma execução (cada fonte traz uma).
const (
	partImage = 1 << iota // caminho completo (Kernel-Process)
	partCmd               // linha de comando (provedor do kernel)
)

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// EVENT_TRACE_PROPERTIES (120 bytes em x64)
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// EVENT_TRACE_LOGFILEW (448 bytes em x64). As estruturas internas que não
// usamos (EVENT_TRACE e TRACE_LOGFILE_HEADER) ficam como bytes opacos.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [88]byte
	LogfileHeader       [280]byte
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	_                   uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	_                   uint32
	Context             uintptr
}

// EVENT_RECORD
type eventRecord struct {
	Size              uint16
	HeaderType        uint16
	Flags             uint16
	EventProperty     uint16
	ThreadID          uint32
	ProcessID         uint32
	TimeStamp         int64
	ProviderID        windows.GUID
	ID                uint16
	Version           uint8
	Channel           uint8
	Level             uint8
	Opcode            uint8
	Task              uint16
	Keyword           uint64
	ProcessorTime     uint64
	ActivityID        windows.GUID
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

type propertyDataDescriptor struct {
	PropertyName uint64
	ArrayIndex   uint32
	Reserved     uint32
}

func init() {
	// Garante que os layouts batem com os do Windows (x64).
	if unsafe.Sizeof(eventTraceProperties{}) != 120 || unsafe.Sizeof(eventTraceLogfile{}) != 448 ||
		unsafe.Sizeof(eventRecord{}) != 112 {
		panic("procmon: layout de estrutura ETW inesperado")
	}
}

// rawStart é o que o callback ETW (ou a verificação periódica) extrai.
type rawStart struct {
	pid, ppid uint32
	image     string // caminho completo (ou só o nome, no modo de verificação)
	cmdline   string
	when      time.Time
	source    string
	parts     uint8
}

type etwSession struct {
	props   []uint64
	handle  uint64
	trace   uint64
	logfile *eventTraceLogfile
	out     chan<- rawStart
	devices *deviceMap
	// parts que cada execução deve reunir antes de ser processada.
	need uint8
	// Descrição do modo, para o painel.
	mode string
	once sync.Once
}

var (
	activeMu  sync.Mutex
	activeETW *etwSession
)

var etwCallback = syscall.NewCallback(func(rec *eventRecord) uintptr {
	activeMu.Lock()
	s := activeETW
	activeMu.Unlock()
	if s == nil {
		return 0
	}
	var ev rawStart
	switch {
	case rec.ProviderID == kernelProcessGUID && rec.ID == eventIDProcessStart:
		pid, ok1 := tdhUint32(rec, "ProcessID")
		ppid, ok2 := tdhUint32(rec, "ParentProcessID")
		if !ok1 || !ok2 {
			return 0
		}
		ev = rawStart{pid: pid, ppid: ppid, image: s.devices.toDOS(tdhString(rec, "ImageName")), parts: partImage}
	case rec.ProviderID == processClassGUID && rec.Opcode == opcodeProcessStart:
		pid, ppid, name, cmd, ok := kernelProcessStart(rec)
		if !ok {
			return 0
		}
		ev = rawStart{pid: pid, ppid: ppid, image: name, cmdline: cmd, parts: partCmd}
	default:
		return 0
	}
	// ProcessTrace converte o carimbo de tempo para FILETIME (hora do sistema).
	ev.when, ev.source = filetimeToTime(rec.TimeStamp), "etw"
	select {
	case s.out <- ev:
	default: // fila cheia: descarta para nunca travar o ETW
	}
	return 0
})

func filetimeToTime(ft int64) time.Time {
	f := windows.Filetime{LowDateTime: uint32(ft), HighDateTime: uint32(ft >> 32)}
	return time.Unix(0, f.Nanoseconds())
}

// ---------------------------------------------------------------------------
// Leitura das propriedades

func tdhProp(rec *eventRecord, name string) ([]byte, bool) {
	n, _ := windows.UTF16PtrFromString(name)
	desc := propertyDataDescriptor{PropertyName: uint64(uintptr(unsafe.Pointer(n))), ArrayIndex: 0xFFFFFFFF}
	var size uint32
	r, _, _ := procTdhGetPropSize.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&desc)), uintptr(unsafe.Pointer(&size)))
	if r != 0 || size == 0 || size > 64<<10 {
		return nil, false
	}
	buf := make([]byte, size)
	r, _, _ = procTdhGetProperty.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&desc)), uintptr(size), uintptr(unsafe.Pointer(&buf[0])))
	return buf, r == 0
}

func tdhUint32(rec *eventRecord, name string) (uint32, bool) {
	b, ok := tdhProp(rec, name)
	if !ok || len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func utf16z(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func ansiz(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func tdhString(rec *eventRecord, name string) string {
	b, ok := tdhProp(rec, name)
	if !ok {
		return ""
	}
	return utf16z(b)
}

// kernelProcessStart lê um evento Process/Start do kernel. Usa o TDH e,
// se o esquema não estiver disponível, interpreta o layout documentado
// (Process_V2..V4_TypeGroup1).
func kernelProcessStart(rec *eventRecord) (pid, ppid uint32, name, cmd string, ok bool) {
	if p, ok1 := tdhUint32(rec, "ProcessId"); ok1 {
		if pp, ok2 := tdhUint32(rec, "ParentId"); ok2 {
			if b, ok3 := tdhProp(rec, "ImageFileName"); ok3 {
				name = ansiz(b)
			}
			return p, pp, name, tdhString(rec, "CommandLine"), true
		}
	}
	if rec.UserData == 0 || rec.UserDataLength < 32 {
		return 0, 0, "", "", false
	}
	// UserData aponta para memória do ETW, válida durante o callback.
	// Lê o campo como ponteiro (evita converter uintptr -> unsafe.Pointer).
	data := *(*unsafe.Pointer)(unsafe.Pointer(&rec.UserData))
	b := unsafe.Slice((*byte)(data), rec.UserDataLength)
	ptr := 8
	if rec.Flags&eventHeaderFlag32BitHeader != 0 {
		ptr = 4
	}
	off := ptr // UniqueProcessKey
	pid = binary.LittleEndian.Uint32(b[off:])
	ppid = binary.LittleEndian.Uint32(b[off+4:])
	off += 16  // ProcessId, ParentId, SessionId, ExitStatus
	off += ptr // DirectoryTableBase
	if rec.Version >= 3 {
		off += 4 // Flags
	}
	// UserSID: TOKEN_USER (2 ponteiros) + SID, ou um uint32 zero.
	if off+4 > len(b) {
		return 0, 0, "", "", false
	}
	if binary.LittleEndian.Uint32(b[off:]) == 0 {
		off += 4
	} else {
		off += 2 * ptr
		if off+2 > len(b) {
			return 0, 0, "", "", false
		}
		off += 8 + 4*int(b[off+1])
	}
	if off >= len(b) {
		return pid, ppid, "", "", true
	}
	name = ansiz(b[off:])
	off += len(name) + 1
	if off < len(b) {
		cmd = utf16z(b[off:])
	}
	return pid, ppid, name, cmd, true
}

// ---------------------------------------------------------------------------
// Sessão

func newProps(systemLogger bool) []uint64 {
	const nameBytes = 1024
	total := int(unsafe.Sizeof(eventTraceProperties{})) + nameBytes
	buf := make([]uint64, (total+7)/8)
	p := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	p.Wnode.BufferSize = uint32(total)
	p.Wnode.Flags = wnodeFlagTracedGUID
	p.Wnode.ClientContext = 1 // relógio QPC
	p.LogFileMode = eventTraceRealTimeMode
	if systemLogger {
		p.LogFileMode |= eventTraceSystemLoggerMode
		p.EnableFlags = eventTraceFlagProcess
	}
	p.FlushTimer = 1 // entrega eventos em até 1 s
	p.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	return buf
}

func stopSession(name string) {
	props := newProps(false)
	n, _ := windows.UTF16PtrFromString(name)
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&props[0])), eventTraceControlStop)
}

func (s *etwSession) start(systemLogger bool) error {
	name, _ := windows.UTF16PtrFromString(sessionName)
	for attempt := 0; attempt < 2; attempt++ {
		s.props = newProps(systemLogger)
		r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&s.props[0])))
		if r == 0 {
			return nil
		}
		if r == errAlreadyExists && attempt == 0 {
			// Sessão órfã de uma execução anterior que caiu: encerra e tenta de novo.
			stopSession(sessionName)
			continue
		}
		return fmt.Errorf("StartTrace: %w", syscall.Errno(r))
	}
	return errors.New("StartTrace: sessão já existe")
}

func (s *etwSession) enableKernelProcess() error {
	guid := kernelProcessGUID
	r, _, _ := procEnableTraceEx2.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&guid)), eventControlCodeEnable,
		traceLevelVerbose, keywordProcess, 0, 0, 0)
	if r != 0 {
		return fmt.Errorf("EnableTraceEx2: %w", syscall.Errno(r))
	}
	return nil
}

// startETW inicia a sessão e começa a entregar eventos em out. Retorna
// erro (ex.: acesso negado sem administrador) para o chamador usar o
// modo de verificação periódica.
func startETW(out chan<- rawStart) (*etwSession, error) {
	activeMu.Lock()
	busy := activeETW != nil
	activeMu.Unlock()
	if busy {
		return nil, errors.New("já existe uma sessão ETW ativa neste processo")
	}
	if err := procStartTraceW.Find(); err != nil {
		return nil, err
	}
	s := &etwSession{out: out, devices: newDeviceMap()}

	// 1ª opção: provedor do kernel (linha de comando) + Kernel-Process (caminho).
	if err := s.start(true); err == nil {
		if s.enableKernelProcess() == nil {
			s.need, s.mode = partImage|partCmd, "kernel + Kernel-Process (caminho e linha de comando)"
		} else {
			s.need, s.mode = partCmd, "kernel (linha de comando; caminho deduzido)"
		}
	} else {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, err
		}
		// 2ª opção (Windows antigo): só Kernel-Process, sem linha de comando.
		stopSession(sessionName)
		if err := s.start(false); err != nil {
			return nil, err
		}
		if err := s.enableKernelProcess(); err != nil {
			stopSession(sessionName)
			return nil, err
		}
		s.need, s.mode = partImage, "Kernel-Process (sem linha de comando de processos rápidos)"
	}

	name, _ := windows.UTF16PtrFromString(sessionName)
	s.logfile = &eventTraceLogfile{
		LoggerName:          name,
		ProcessTraceMode:    processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: etwCallback,
	}
	th, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(s.logfile)))
	if uint64(th) == invalidProcessTraceHandle {
		stopSession(sessionName)
		return nil, errors.New("OpenTrace falhou")
	}
	s.trace = uint64(th)

	activeMu.Lock()
	activeETW = s
	activeMu.Unlock()

	go func() {
		// ProcessTrace bloqueia até a sessão ser encerrada.
		procProcessTrace.Call(uintptr(unsafe.Pointer(&s.trace)), 1, 0, 0)
	}()
	return s, nil
}

func (s *etwSession) Close() {
	s.once.Do(func() {
		stopSession(sessionName)
		procCloseTrace.Call(uintptr(s.trace))
		activeMu.Lock()
		if activeETW == s {
			activeETW = nil
		}
		activeMu.Unlock()
	})
}

// ---------------------------------------------------------------------------
// O ETW entrega caminhos de kernel (\Device\HarddiskVolume3\...): converte
// para letras de unidade (C:\...).

type deviceMap struct {
	mu sync.Mutex
	m  map[string]string // \device\harddiskvolume3 -> C:
	at time.Time
}

func newDeviceMap() *deviceMap { return &deviceMap{} }

func (d *deviceMap) refresh() {
	m := map[string]string{}
	buf := make([]uint16, 1024)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		dp, _ := windows.UTF16PtrFromString(drive)
		n, err := windows.QueryDosDevice(dp, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		m[strings.ToLower(windows.UTF16ToString(buf))] = drive
	}
	d.m, d.at = m, time.Now()
}

func (d *deviceMap) toDOS(p string) string {
	if p == "" || !strings.HasPrefix(strings.ToLower(p), `\device\`) {
		return p
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil || time.Since(d.at) > 5*time.Minute {
		d.refresh()
	}
	lp := strings.ToLower(p)
	for dev, drive := range d.m {
		if strings.HasPrefix(lp, dev+`\`) {
			return drive + p[len(dev):]
		}
	}
	return p
}
