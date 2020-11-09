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
	Diagnostic BfdDiagnostic
	State      BfdState

	Flags       uint8
	DetectMulti uint8

	LocalDisc  uint32
	RemoteDisc uint32
	IpAddr     string

	// rate in us of control packets local system -> remote system.
	MinTx uint32

	// rate in us of control packets remote system -> local system.
	MinRx uint32

	// rate in us of echo packets remote system -> local system.
	MinEchoRx uint32

	// rate in us of echo packets local system -> remote system.
	MinEchoTx uint32
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
	VERSION  uint8  = 1
	BFD_PORT string = "3784"
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
	session.MinEchoRx = 50000 // Microseconds
	session.DetectMulti = 1

	return session
}

// message CreateSessionRequest {
// 	string IPAddr = 1;
// 	uint32 DesiredTx = 2; // 150 ms
// 	uint32 DesiredRx = 3; // 150 ms
// 	uint32 EchoRx = 4;    //  50 ms
// 	uint32 DetectMulti = 5;
// 	Mode mode = 6;
//   }

// PerfEvent describes updates the BFD session
// mapped by LocalDisc
type PerfEvent struct {
	// IpAddr uint32
	Flags      uint16
	LocalDisc  uint32
	Timestamp  uint32
	Diagnostic uint8

	NewRemoteState  BfdState
	NewRemoteDisc   uint32
	NewRemoteMinTx  uint32
	NewRemoteMinRx  uint32
	NewRemoteEchoRx uint32
}

const (
	// ProgKeyPort Port that the BFD Program listens on
	ProgKeyPort uint32 = 1

	// ProgKeyIfIndex Interface for the XDP Program
	ProgKeyIfIndex uint32 = 2

	// ProgKeyMinRx Minimum RX time
	ProgKeyMinRx uint32 = 3

	// ProgKeyMinTx Minimum TX time
	ProgKeyMinTx uint32 = 4

	// ProgKeyMinEchoRx Minimum Echo RX time
	ProgKeyMinEchoRx uint32 = 5

	// ProgKeyDetectMulti Detect Multicast (?)
	ProgKeyDetectMulti uint32 = 6
)

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
	binary.Write(buf, binary.BigEndian, uint32(ses.MinEchoRx))

	return buf.Bytes()
}

func (ses *Session) MarshalEcho() []byte {
	buf := bytes.NewBuffer([]uint8{})

	// not sure what code and reply stand for
	//binary.Write(buf, binary.BigEndian, ( (pck.Code | (pck.Reply << 4) | (VERSION << 5))
	binary.Write(buf, binary.BigEndian, (1 | (1 << 4) | (VERSION << 5)))

	binary.Write(buf, binary.BigEndian, ses.LocalDisc)
	binary.Write(buf, binary.BigEndian, ses.RemoteDisc)

	// not sure type of timestamp
	binary.Write(buf, binary.BigEndian, time.Now().Format(time.StampMicro))

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
