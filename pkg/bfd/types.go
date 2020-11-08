package bfd



// BFD statefulness 

type BfdState uint8
type BfdDiagnostic uint8

const (
	STATE_ADMIN_DOWN BfdState = 0 // AdminDown
	STATE_DOWN       BfdState = 1 // Down
	STATE_INIT       BfdState = 2 // Init
	STATE_UP         BfdState = 3 // Up
)

// Session describes a BFD session in userspace
// and in the XDP map
type Session struct {
	Flags        uint8
	Diagnostic   BfdDiagnostic
	State 		 BfdState
	DetectMulti  uint8
	LocalDisc    uint32
	RemoteDisc   uint32
	MinTx        uint32
	RemoteMinTx  uint32
	EchoRx       uint32
	RemoteEchoRx uint32
}

// BFD constants
const (
	VERSION uint8 = 1
	BFD_PORT string "3784"
)

// BFD Flags
const (
	FLAG_POLL  				uint8 = 0x20
	FLAG_FINAL 				uint8 = 0x10
	FLAG_CONTROL_PLANE_IND  uint8 = 0x08
	FLAG_DEMAND 		    uint8 = 0x02
	FLAG_MULTIPOINT 		uint8 = 0x01
	
)


// DefaultSession returns a default BFD session
func DefaultSession() Session {
	session := Session{}

	session.MinTx = 150_000 // Microseconds
	session.EchoRx = 50_000 // Microseconds
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



func (ses *Session) Marshal() []byte {
	var auth []byte
	buf := bytes.NewBuffer([]uint8{})
	length := uint8(24)

	binary.Write(buf, binary.BigEndian, (VERSION << 5 | (uint8(sess.Diagnostic) & 0x1f)))


	binary.Write(buf, binary.BigEndian, (uint8(p.State)<<6 | flags))
	binary.Write(buf, binary.BigEndian, p.DetectMult)
	binary.Write(buf, binary.BigEndian, length)

	binary.Write(buf, binary.BigEndian, p.MyDiscriminator)
	binary.Write(buf, binary.BigEndian, p.YourDiscriminator)
	binary.Write(buf, binary.BigEndian, uint32(p.DesiredMinTxInterval))
	binary.Write(buf, binary.BigEndian, uint32(p.RequiredMinRxInterval))
	binary.Write(buf, binary.BigEndian, uint32(p.RequiredMinEchoRxInterval))

	if len(auth) > 0 {
		binary.Write(buf, binary.BigEndian, auth)
	}

	return buf.Bytes()
}