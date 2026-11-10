package procmon

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Consumidor ETW em tempo real do provedor Microsoft-Windows-Kernel-Process.
// É o mesmo mecanismo usado por EDRs comerciais para ver cada processo no
// instante em que é criado, sem driver de kernel. Exige administrador.

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modtdh      = windows.NewLazySystemDLL("tdh.dll")

	procStartTraceW     = modadvapi32.NewProc("StartTraceW")
	procControlTraceW   = modadvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2  = modadvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW      = modadvapi32.NewProc("OpenTraceW")
	procProcessTrace    = modadvapi32.NewProc("ProcessTrace")
	procCloseTrace      = modadvapi32.NewProc("CloseTrace")
	procTdhGetPropSize  = modtdh.NewProc("TdhGetPropertySize")
	procTdhGetProperty  = modtdh.NewProc("TdhGetProperty")
)

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
var kernelProcessGUID = windows.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B,
	Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}

const (
	sessionName = "Sentinela-ProcMon"

	wnodeFlagTracedGUID          = 0x00020000
	eventTraceRealTimeMode       = 0x00000100
	eventTraceControlStop        = 1
	eventControlCodeEnable       = 1
	traceLevelVerbose            = 5
	keywordProcess               = 0x10
	processTraceModeRealTime     = 0x00000100
	processTraceModeEventRecord  = 0x10000000
	invalidProcessTraceHandle    = ^uint64(0)
	errAlreadyExists             = 183

	eventIDProcessStart = 1
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
	if unsafe.Sizeof(eventTraceProperties{}) != 120 || unsafe.Sizeof(eventTraceLogfile{}) != 448 {
		panic("procmon: layout de estrutura ETW inesperado")
	}
}

type etwSession struct {
	props   []uint64 // buffer alinhado contendo EVENT_TRACE_PROPERTIES + nome
	handle  uint64
	trace   uint64
	logfile *eventTraceLogfile
	out     chan<- rawStart
	devices *deviceMap
	once    sync.Once
}

// rawStart é o que o callback ETW extrai (o resto é preenchido depois).
type rawStart struct {
	pid, ppid uint32
	image     string
	when      time.Time
	source    string
}

// O callback ETW é uma função C global; guardamos a sessão ativa aqui.
var (
	activeMu  sync.Mutex
	activeETW *etwSession
)

var etwCallback = syscall.NewCallback(func(rec *eventRecord) uintptr {
	activeMu.Lock()
	s := activeETW
	activeMu.Unlock()
	if s == nil || rec.ProviderID != kernelProcessGUID || rec.ID != eventIDProcessStart {
		return 0
	}
	pid, ok1 := tdhUint32(rec, "ProcessID")
	ppid, ok2 := tdhUint32(rec, "ParentProcessID")
	if !ok1 || !ok2 {
		return 0
	}
	img := s.devices.toDOS(tdhString(rec, "ImageName"))
	// ProcessTrace converte o carimbo de tempo para FILETIME (hora do sistema).
	ev := rawStart{pid: pid, ppid: ppid, image: img, when: filetimeToTime(rec.TimeStamp), source: "etw"}
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
	return *(*uint32)(unsafe.Pointer(&b[0])), true
}

func tdhString(rec *eventRecord, name string) string {
	b, ok := tdhProp(rec, name)
	if !ok || len(b) < 2 {
		return ""
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return windows.UTF16ToString(u)
}

func newProps() []uint64 {
	const nameBytes = 1024
	total := int(unsafe.Sizeof(eventTraceProperties{})) + nameBytes
	buf := make([]uint64, (total+7)/8)
	p := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	p.Wnode.BufferSize = uint32(total)
	p.Wnode.Flags = wnodeFlagTracedGUID
	p.Wnode.ClientContext = 1 // relógio QPC
	p.LogFileMode = eventTraceRealTimeMode
	p.FlushTimer = 1 // entrega eventos em até 1 s
	p.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	return buf
}

func stopSession(name string) {
	props := newProps()
	n, _ := windows.UTF16PtrFromString(name)
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&props[0])), eventTraceControlStop)
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
	name, _ := windows.UTF16PtrFromString(sessionName)
	s := &etwSession{out: out, devices: newDeviceMap()}

	for attempt := 0; attempt < 2; attempt++ {
		s.props = newProps()
		r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&s.props[0])))
		if r == 0 {
			break
		}
		if r == errAlreadyExists && attempt == 0 {
			// Sessão órfã de uma execução anterior que caiu: encerra e tenta de novo.
			stopSession(sessionName)
			continue
		}
		return nil, fmt.Errorf("StartTrace: %w", syscall.Errno(r))
	}

	guid := kernelProcessGUID
	r, _, _ := procEnableTraceEx2.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&guid)), eventControlCodeEnable,
		traceLevelVerbose, keywordProcess, 0, 0, 0)
	if r != 0 {
		stopSession(sessionName)
		return nil, fmt.Errorf("EnableTraceEx2: %w", syscall.Errno(r))
	}

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
