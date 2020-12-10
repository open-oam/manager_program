package bfd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// BFD statefulness
type BfdState uint8

const (
	STATE_ADMIN_DOWN BfdState = 0 // AdminDown
	STATE_DOWN       BfdState = 1 // Down
	STATE_INIT       BfdState = 2 // Init
	STATE_UP         BfdState = 3 // Up
)

func (s BfdState) String() string {
	switch s {
	case STATE_ADMIN_DOWN:
		return "ADMIN_DOWN"
	case STATE_DOWN:
		return "DOWN"
	case STATE_INIT:
		return "INIT"
	case STATE_UP:
		return "UP"
	default:
		return "UNK"
	}
}

// BFD Diagnostics
type BfdDiagnostic uint8

const (
/*
	0 -- No Diagnostic
	1 -- Control Detection Time Expired
	2 -- Echo Function Failed
	3 -- Neighbor Signaled Session Down
	4 -- Forwarding Plane Reset
	5 -- Path Down
	6 -- Concatenated Path Down
	7 -- Administratively Down
	8 -- Reverse Concatenated Path Down
	9-31 -- Reserved for future use
*/
)

// Session describes a BFD session in userspace
// and in the XDP map
type Session struct {
	State       BfdState
	RemoteState BfdState

	Diagnostic BfdDiagnostic

	DetectMulti uint8
	Flags       uint8

	LocalDisc  uint32
	RemoteDisc uint32
	IpAddr     string

	// rate in us of control packets local system -> remote system.
	MinTx       uint32
	RemoteMinRx uint32

	// rate in us of control packets remote system -> local system.
	MinRx       uint32
	RemoteMinTx uint32

	// rate in us of echo packets local system -> remote system.
	MinEchoTx    uint32
	RemoteEchoRx uint32
}

// MarshalSession Convert a session into a valid session entry in the ebpf session map
func (ses *Session) MarshalSession() []byte {
	buf := bytes.NewBuffer([]uint8{})

	state := uint8(ses.State & 0b11)                     // 0b|00|
	state |= uint8((ses.RemoteState & 0b11) << 2)        // 0b|00| |00|
	state |= uint8((ses.Flags & FLAG_DEMAND) << 3)       // 0b10 << 2 -> 0b|1| |00| |00|
	state |= (uint8(ses.RemoteState) & FLAG_DEMAND) << 4 // 0b10 << 2 -> 0b|1| |1| |00| |00|

	binary.Write(buf, binary.LittleEndian, state)

	binary.Write(buf, binary.LittleEndian, ses.Diagnostic)
	binary.Write(buf, binary.LittleEndian, ses.DetectMulti)
	// binary.Write(buf, binary.LittleEndian, ses.Flags)
	binary.Write(buf, binary.LittleEndian, ses.LocalDisc)
	binary.Write(buf, binary.LittleEndian, ses.RemoteDisc)
	binary.Write(buf, binary.LittleEndian, ses.MinTx)
	binary.Write(buf, binary.LittleEndian, ses.RemoteMinTx)
	binary.Write(buf, binary.LittleEndian, ses.MinRx)
	binary.Write(buf, binary.LittleEndian, ses.RemoteMinRx)
	binary.Write(buf, binary.LittleEndian, ses.MinEchoTx)
	binary.Write(buf, binary.LittleEndian, ses.RemoteEchoRx)

	return buf.Bytes()
}

type EchoPacket struct {
	Version    uint8 // 3 bits
	Reply      uint8 // 1
	Code       uint8 // 4
	LocalDisc  uint32
	RemoteDisc uint32
	Timestamp  uint32
}

// BFD constants
const (
	VERSION          uint8  = 1
	BFD_PORT         int    = 3784
	RESPONSE_TIMEOUT uint32 = 1_000_000 // microseconds
)

// BFD Flags
const (
	FLAG_POLL              uint8 = 0x20
	FLAG_FINAL             uint8 = 0x10
	FLAG_CONTROL_PLANE_IND uint8 = 0x08
	FLAG_DEMAND            uint8 = 0x02
	FLAG_MULTIPOINT        uint8 = 0x01
)

// DefaultSession returns a default BFD session
func DefaultSession() Session {
	session := Session{}

	session.MinRx = 150000    // Microseconds
	session.MinTx = 150000    // Microseconds
	session.MinEchoTx = 50000 // Microseconds
	session.DetectMulti = 5
	session.State = STATE_DOWN

	return session
}

// PerfEvent describes updates the BFD session
// mapped by LocalDisc

const (
	EVENT_RX_CONTROL       uint16 = 0x00
	EVENT_RX_ECHO          uint16 = 0x01
	EVENT_RX_FINAL         uint16 = 0x02
	EVENT_CREATE_SESSION   uint16 = 0x04
	EVENT_TEARDOWN_SESSION uint16 = 0x08

	EVENT_CHNG_STATE  uint16 = 0x10
	EVENT_CHNG_DEMAND uint16 = 0x20
	EVENT_CHNG_DISC   uint16 = 0x40
	EVENT_CHNG_TIMING uint16 = 0x80
)

type PerfEvent struct {
	Diagnostic      uint8
	NewRemoteState  BfdState
	Flags           uint16
	LocalDisc       uint32
	IpAddr          uint32
	Timestamp       uint32
	NewRemoteDisc   uint32
	NewRemoteMinTx  uint32
	NewRemoteMinRx  uint32
	NewRemoteEchoRx uint32
}

func (e PerfEvent) String() string {
	return fmt.Sprintf("{%d, %s, %s, L%d, IP%d, T%d, RD%d, RMT%d, RMR%d, RMER%d}", e.Diagnostic, e.NewRemoteState, flagsToString(e.Flags), e.LocalDisc, e.IpAddr, e.Timestamp, e.NewRemoteDisc, e.NewRemoteMinTx, e.NewRemoteMinRx, e.NewRemoteEchoRx)
}

func flagsToString(flags uint16) string {
	ret := ""

	// RX_CONTROl
	if flags&1 == 1 {
		ret += "RX_CONTROL"
	}

	if flags&EVENT_RX_ECHO == EVENT_RX_ECHO {
		if ret != "" {
			ret += "+"
		}

		ret += "RX_ECHO"
	}

	if flags&EVENT_RX_FINAL == EVENT_RX_FINAL {
		if ret != "" {
			ret += "+"
		}

		ret += "RX_FINAL"
	}

	if flags&EVENT_CREATE_SESSION == EVENT_CREATE_SESSION {
		if ret != "" {
			ret += "+"
		}

		ret += "CREATE_SESSION"
	}
	if flags&EVENT_TEARDOWN_SESSION == EVENT_TEARDOWN_SESSION {
		if ret != "" {
			ret += "+"
		}

		ret += "TEARDOWN_SESSION"
	}

	if flags&EVENT_CHNG_STATE == EVENT_CHNG_STATE {
		if ret != "" {
			ret += "+"
		}

		ret += "CHNG_STATE"
	}

	if flags&EVENT_CHNG_DEMAND == EVENT_CHNG_DEMAND {
		if ret != "" {
			ret += "+"
		}

		ret += "CHNG_DEMAND"
	}

	if flags&EVENT_CHNG_DISC == EVENT_CHNG_DISC {
		if ret != "" {
			ret += "+"
		}

		ret += "CHNG_DISC"
	}

	if flags&EVENT_CHNG_TIMING == EVENT_CHNG_TIMING {
		if ret != "" {
			ret += "+"
		}

		ret += "RX_ECHO"
	}

	return ret
}

const (
	CHANGE_TIME_RX   uint8 = 0
	CHANGE_TIME_TX   uint8 = 1
	CHANGE_TIME_ECHO uint8 = 2
	CHANGE_MODE      uint8 = 3
	CHANGE_MULTI     uint8 = 4
	SHUTDOWN         uint8 = 5
)

const (
	DEMAND uint32 = 0
	ASYNC  uint32 = 1
)

type CommandEvent struct {
	Type uint8       // = ChangeMode
	Data interface{} // uint32
}

func NewCommandEvent(Type uint8, Data interface{}) CommandEvent {
	return CommandEvent{Type, Data}
}

const (
	// ProgKeyPort Port that the BFD Program listens on
	PROG_PORT uint32 = 1

	// ProIfIndex Interface for the XDP Program
	PROG_IF_IDX uint32 = 2

	// ProMinRx Minimum RX time
	PROG_MIN_RX uint32 = 3

	// PROG_MIN_TX Minimum TX time
	PROG_MIN_TX uint32 = 4

	// PROG_ECHO_RX Minimum Echo RX time
	PROG_ECHO_RX uint32 = 5

	// PROG_DETECT_MULTI Detect Multicast (?)
	PROG_DETECT_MULTI uint32 = 6
)

const (
	PROG_DEFAULT_PORT        uint32 = 3784
	PROG_DEFAULT_IF_IDX      uint32 = 0
	PROG_DEFAULT_MIN_RX      uint32 = 150000
	PROG_DEFAULT_MIN_TX      uint32 = 150000
	PROG_DEFAULT_ECHO_RX     uint32 = 50000
	PROG_DEFAULT_DETECT_MULT uint32 = 1
)

type SessionInfo struct {
	LocalId uint32
	State   BfdState
	Error error
}

func (ses *Session) MarshalControl() []byte {
	buf := bytes.NewBuffer([]uint8{})
	length := uint8(24)

	binary.Write(buf, binary.BigEndian, (VERSION<<5 | (uint8(ses.Diagnostic) & 0x1f)))

	binary.Write(buf, binary.BigEndian, (uint8(ses.State)<<6 | ses.Flags))
	binary.Write(buf, binary.BigEndian, ses.DetectMulti)
	binary.Write(buf, binary.BigEndian, length)

	binary.Write(buf, binary.BigEndian, ses.LocalDisc)
	binary.Write(buf, binary.BigEndian, ses.RemoteDisc)
	binary.Write(buf, binary.BigEndian, uint32(ses.MinTx))
	binary.Write(buf, binary.BigEndian, uint32(ses.MinRx))
	binary.Write(buf, binary.BigEndian, uint32(ses.MinEchoTx))

	return buf.Bytes()
}

func (ses *Session) MarshalEcho() []byte {
	buf := bytes.NewBuffer([]uint8{})

	binary.Write(buf, binary.BigEndian, uint8(1)) // version
	binary.Write(buf, binary.BigEndian, uint8(0)) // code
	binary.Write(buf, binary.BigEndian, uint8(0)) // reply
	binary.Write(buf, binary.BigEndian, uint8(0)) // empty

	binary.Write(buf, binary.BigEndian, ses.LocalDisc)
	binary.Write(buf, binary.BigEndian, ses.RemoteDisc)

	// need to be microsecond timestamp
	binary.Write(buf, binary.BigEndian, int32((int64(time.Nanosecond) * time.Now().UnixNano() / int64(time.Microsecond))))

	return buf.Bytes()
}

func (pck *EchoPacket) Marshal() []byte {
	buf := bytes.NewBuffer([]uint8{})

	binary.Write(buf, binary.LittleEndian, (pck.Code | (pck.Reply << 4) | (pck.Version << 5)))

	binary.Write(buf, binary.LittleEndian, pck.LocalDisc)
	binary.Write(buf, binary.LittleEndian, pck.RemoteDisc)
	binary.Write(buf, binary.LittleEndian, pck.Timestamp)

	return buf.Bytes()
}
