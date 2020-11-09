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

		// create socket
		addr, err := net.ResolveUDPAddr("udp4", ipAddr+":"+BFD_PORT)
		sckt, err := net.DialUDP("udp4", nil, addr)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer sckt.Close()

		for {
			switch sessionData.State {
			case STATE_DOWN:
				// Either on creation or link down, either way try sending BFD control packets
				StartSession(events, sessionData, sckt)

			case STATE_INIT:
				// This indicates we are passive side and need to reply to handshake
				InitSession(events, sessionData, sckt)

			case STATE_UP:
				// Maintian echos
				MaintainSession(events, sessionData, sckt)

			case STATE_ADMIN_DOWN:
				// exit routine
				return
			}

		}
	}()

	return &SessionController{id, sessionMap, sessionData, events} //, state, commands}
}

func StartSession(events chan PerfEvent, sessionData *Session, sckt *net.UDPConn) {
	/*
	* This function streams control packets to start the handshake. It starts in state DOWN and
	* will continuously send control packet until it recieves a perf event indicating a response,
	* where it will change to UP state send final control packet and return.
	 */
	TxTimer := time.NewTimer(time.Duration(sessionData.MinTx) * time.Microsecond)

	// Send first control packet
	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Println("[%s] [%s : %d] recieved perf event", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// TODO: Unsure if correct parsing from perfevent
			if event.NewRemoteState == STATE_INIT {
				sessionData.RemoteDisc = event.NewRemoteDisc
				sessionData.MinRx = event.NewRemoteMinTx
				sessionData.MinEchoRx = event.NewRemoteEchoRx

				sessionData.State = STATE_UP

				// send final conformation with updated discriminator and state
				_, err := sckt.Write(sessionData.MarshalControl())
				if err != nil {
					fmt.Println(err)
				}

				return

			} else {
				// not sure what other events possible, but will be discarded
			}

		case txTimeOut := <-TxTimer.C:
			fmt.Println("[%s] [%s : %d] sending echo packet", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)

			// timeout send another control packet
			_, err := sckt.Write(sessionData.MarshalControl())
			if err != nil {
				fmt.Println(err)
			}
			TxTimer.Reset(time.Duration(sessionData.MinTx) * time.Microsecond)
		}
	}
}

func InitSession(events chan PerfEvent, sessionData *Session, sckt *net.UDPConn) {
	/*
	* This function is on the passive side of handshake, and must respond with control packets.
	* It begins in state INIT and will send control packets until recieving an event indicating
	* the handshake is complete, where it will change to state UP and return.
	 */
	TxTimer := time.NewTimer(time.Duration(sessionData.MinTx) * time.Microsecond)

	// Send first control packet
	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Println("[%s] [%s : %d] recieved perf event", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			if event.NewRemoteState == STATE_UP {

				// update own state
				sessionData.State = STATE_UP

				// must send final control packet for updated state
				_, err := sckt.Write(sessionData.MarshalControl())
				if err != nil {
					fmt.Println(err)
				}

				return

			} else {
				// not sure what other events possible, but will be discarded
			}

		case txTimeOut := <-TxTimer.C:
			fmt.Println("[%s] [%s : %d] sending control packet", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)

			_, err := sckt.Write(sessionData.MarshalControl())
			if err != nil {
				fmt.Println(err)
			}
			TxTimer.Reset(time.Duration(sessionData.MinTx) * time.Microsecond)
		}
	}
}

func MaintainSession(events chan PerfEvent, sessionData *Session, sckt *net.UDPConn) {
	/*
	* This function will send echos on timeouts and ensure recieveing echos on time outs until state change.
	* TODO: Funcitonality should be added for asymmetric echos and occasional control packets. Also other modes.
	 */

	echoTxTimer := time.NewTimer(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
	echoRxTimer := time.NewTimer(time.Duration(sessionData.MinEchoRx) * time.Microsecond)

	_, err := sckt.Write(sessionData.MarshalEcho())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Println("[%s] [%s : %d] recieved perf event", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// TODO: not sure how echos will come up in perf events
			if event.Flags == 0 {
				echoTxTimer.Reset(time.Duration(sessionData.MinEchoRx) * time.Microsecond)
			}

		case txTimeOut := <-echoTxTimer.C:
			fmt.Println("[%s] [%s : %d] sending echo packet", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			_, err := sckt.Write(sessionData.MarshalEcho())
			if err != nil {
				fmt.Println(err)
			}

			echoTxTimer.Reset(time.Duration(sessionData.MinEchoRx) * time.Microsecond)

		case rxTimeOut := <-echoRxTimer.C:
			fmt.Println("[%s] [%s : %d] remote down", rxTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			// Remote failed to send a packet quickly enough
			sessionData.State = STATE_DOWN
			return
		}
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
