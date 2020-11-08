package bfd

import (
	"fmt"
	"net"
	"time"

	"github.com/dropbox/goebpf"
)

// SessionController Controls a running BFD session
type SessionController struct {
	id          uint32
	sessionMap  goebpf.Map
	sessionData *Session
	events      chan PerfEvent
	// state       chan StateUpdate
	// commands    chan Command
	// lock       *sync.Mutex
}

// NewController Create a new controller from the given bpf System
func NewController(bpf *goebpf.System, sessionData *Session, ipAddr string, id uint32) *SessionController {
	controller := &SessionController{}

	sessionMap := (*bpf).GetMapByName("session_map")
	events := make(chan PerfEvent)

	controller.id = id
	controller.events = events
	controller.sessionMap = sessionMap
	controller.sessionData = sessionData

	// Start listening for perf events
	go func() {
		current_state := STATE_DOWN //?
		echoTxTimer := time.NewTimer(time.Duration(sessionData.EchoRx) * time.Microsecond)
		echoRxTimer := time.NewTimer(time.Duration(sessionData.RemoteEchoRx) * time.Microsecond)
		// create socket
		//sendControlPacket(sessionData, ipAddr)

		for {
			// TODO:
			// switch statement for state?

			select {
			case event := <-events:
				fmt.Println("[%s] [%s : %d] recieved perf event", time.Now().Format(time.StampMicro), ipAddr, controller.id)
				// We may need to update the session
				// state or data.
				fmt.Println(event)
	
			case txTimeOut := <-echoTxTimer.C:
				fmt.Println("[%s] [%s : %d] sending echo packet", txTimeOut.Format(time.StampMicro), ipAddr, controller.id)
				// We need to send an echo packet
				// 	sendControlPacket(sessionData, ipAddr)
			case rxTimeOut := <-echoRxTimer.C:			
				fmt.Println("[%s] [%s : %d] remote down", txTimeOut.Format(time.StampMicro), ipAddr, controller.id)
				// Remote failed to send a packet quickly enough
			}
		}
	}()

	return &SessionController{id, sessionMap, sessionData, state, commands, events}
}

func SendControlPacket(sessionData Session, ipAddr string) {
	addr, err := net.ResolveUDPAddr("udp4", ipAddr+":"+BPF_PORT)
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	Packet := BfdControlPacket{
		Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
		Poll: false, Final: true, ControlPlaneIndependent: false, AuthPresent: false, Demand: sessionData., Multipoint: false,
		DetectMult: sessionData., MyDiscriminator: sessionData.LocalDisc, YourDiscriminator: 0,
		DesiredMinTxInterval: sessionData.MinTx, RequiredMinRxInterval: sessionData.MinRx, RequiredMinEchoRxInterval: 0,
		AuthHeader: nil,
	}

	buffer := Packet.Marshal()
	if buffer == nil {
		fmt.Println("Error Marshalling BFD Control Packet")
	}

	_, err = conn.Write(buffer)
	if err != nil {
		fmt.Printf("Error writing data.\n")
	}
}

func (controller *SessionController) SendEvent(event PerfEvent) {
	controller.events <- event
}

type StateUpdate int

const (
	A StateUpdate = iota
	B
	C
)

type Command int

const (
	Stop Command = iota
	Pause
	ModeAsync
	ModeDemand
)
