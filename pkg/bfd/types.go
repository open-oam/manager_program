package bfd

import (
	"bytes"
	"encoding/binary"
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
	State      BfdState
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

	binary.Write(buf, binary.LittleEndian, ses.State)
	binary.Write(buf, binary.LittleEndian, ses.Diagnostic)
	binary.Write(buf, binary.LittleEndian, ses.DetectMulti)
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
	BFD_PORT         string = "3784"
	RESPONSE_TIMEOUT uint32 = 2000 // miliseconds
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

	session.MinTx = 150000    // Microseconds
	session.MinEchoTx = 50000 // Microseconds
	session.DetectMulti = 1
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
	Error   error
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

	// not sure what code and reply stand for
	//binary.Write(buf, binary.BigEndian, ( (pck.Code | (pck.Reply << 4) | (VERSION << 5))
	binary.Write(buf, binary.BigEndian, (1 | (0 << 4) | (VERSION << 5)))

	binary.Write(buf, binary.BigEndian, ses.LocalDisc)
	binary.Write(buf, binary.BigEndian, ses.RemoteDisc)

	// need to be microsecond timestamp
	binary.Write(buf, binary.BigEndian, int32((int64(time.Nanosecond) * time.Now().UnixNano() / int64(time.Microsecond))))

	return buf.Bytes()
}

func (pck *EchoPacket) Marshal() []byte {
	buf := bytes.NewBuffer([]uint8{})

	binary.Write(buf, binary.BigEndian, (pck.Code | (pck.Reply << 4) | (pck.Version << 5)))

	binary.Write(buf, binary.BigEndian, pck.LocalDisc)
	binary.Write(buf, binary.BigEndian, pck.RemoteDisc)
	binary.Write(buf, binary.BigEndian, pck.Timestamp)

	return buf.Bytes()
}
