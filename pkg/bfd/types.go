package bfd

// Session describes a BFD session in userspace
// and in the XDP map
type Session struct {
	Flags        uint8
	Diagnostic   uint8
	DetectMulti  uint8
	LocalDisc    uint32
	RemoteDisc   uint32
	MinTx        uint32
	RemoteMinTx  uint32
	EchoRx       uint32
	RemoteEchoRx uint32
}

// PerfEvent describes updates the BFD session
// mapped by LocalDisc
type PerfEvent struct {
	Flags           uint16
	LocalDisc       uint32
	Timestamp       uint32
	Diagnostic      uint8
	NewRemoteState  uint8
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
