package collect

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinela/internal/model"
)

// Equivalente ao `netstat -ano`: conexões TCP/UDP com o PID dono.

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet               = 2
	afInet6              = 23
	tcpTableOwnerPIDAll  = 5
	udpTableOwnerPID     = 1
	errInsufficientBuffer = 122
)

var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RECEIVED", 5: "ESTABLISHED",
	6: "FIN_WAIT_1", 7: "FIN_WAIT_2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
	11: "TIME_WAIT", 12: "DELETE_TCB",
}

func getTable(proc *windows.LazyProc, af, class uintptr) ([]byte, error) {
	size := uint32(16 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		if r == 0 {
			return buf[:size], nil
		}
		if r != errInsufficientBuffer {
			return nil, fmt.Errorf("%s: erro %d", proc.Name, r)
		}
	}
	return nil, fmt.Errorf("%s: buffer insuficiente", proc.Name)
}

func port(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) }

func Connections(names map[uint32]string, errs *[]string) []model.Connection {
	var out []model.Connection
	add := func(c model.Connection) {
		c.ProcessName = names[c.PID]
		out = append(out, c)
	}
	le := binary.LittleEndian

	// TCP IPv4: MIB_TCPROW_OWNER_PID (24 bytes)
	if b, err := getTable(procGetExtendedTcpTable, afInet, tcpTableOwnerPIDAll); err == nil {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*24 <= len(b); i++ {
			r := b[4+i*24:]
			add(model.Connection{
				Proto: "TCP", State: tcpStates[le.Uint32(r[0:])],
				LocalAddr: net.IP(r[4:8]).String(), LocalPort: port(r[8:]),
				RemoteAddr: net.IP(r[12:16]).String(), RemotePort: port(r[16:]),
				PID: le.Uint32(r[20:]),
			})
		}
	} else {
		*errs = append(*errs, err.Error())
	}

	// TCP IPv6: MIB_TCP6ROW_OWNER_PID (56 bytes)
	if b, err := getTable(procGetExtendedTcpTable, afInet6, tcpTableOwnerPIDAll); err == nil {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*56 <= len(b); i++ {
			r := b[4+i*56:]
			add(model.Connection{
				Proto:     "TCP6",
				LocalAddr: net.IP(append([]byte(nil), r[0:16]...)).String(), LocalPort: port(r[20:]),
				RemoteAddr: net.IP(append([]byte(nil), r[24:40]...)).String(), RemotePort: port(r[44:]),
				State: tcpStates[le.Uint32(r[48:])], PID: le.Uint32(r[52:]),
			})
		}
	} else {
		*errs = append(*errs, err.Error())
	}

	// UDP IPv4: MIB_UDPROW_OWNER_PID (12 bytes)
	if b, err := getTable(procGetExtendedUdpTable, afInet, udpTableOwnerPID); err == nil {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*12 <= len(b); i++ {
			r := b[4+i*12:]
			add(model.Connection{Proto: "UDP", LocalAddr: net.IP(r[0:4]).String(), LocalPort: port(r[4:]), PID: le.Uint32(r[8:])})
		}
	} else {
		*errs = append(*errs, err.Error())
	}

	// UDP IPv6: MIB_UDP6ROW_OWNER_PID (28 bytes)
	if b, err := getTable(procGetExtendedUdpTable, afInet6, udpTableOwnerPID); err == nil {
		n := int(le.Uint32(b))
		for i := 0; i < n && 4+(i+1)*28 <= len(b); i++ {
			r := b[4+i*28:]
			add(model.Connection{Proto: "UDP6", LocalAddr: net.IP(append([]byte(nil), r[0:16]...)).String(), LocalPort: port(r[20:]), PID: le.Uint32(r[24:])})
		}
	} else {
		*errs = append(*errs, err.Error())
	}
	return out
}
