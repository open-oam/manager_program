package bfd

import (
	"fmt"
	"net"
	"time"

	"github.com/dropbox/goebpf"
)

/*
TODO:

	- diagnostics
	- closing handshake
	- calc correct timeouts

*/

// SessionController Controls a running BFD session
type SessionController struct {
	Id          uint32
	sessionMap  goebpf.Map
	SessionData *Session
	events      chan PerfEvent
	// state       chan StateUpdate
	// commands    chan Command
	// lock       *sync.Mutex
}

// NewController Create a new controller from the given bpf System
func NewController(id uint32, bpf *goebpf.System, sessionData *Session, sessionInfo chan<- SessionInfo) *SessionController {
	controller := &SessionController{}

	sessionMap := (*bpf).GetMapByName("session_map")
	events := make(chan PerfEvent)

	controller.Id = id
	controller.events = events
	controller.sessionMap = sessionMap
	controller.SessionData = sessionData

	// Start listening for perf events
	go func() {

		// create socket
		addr, err := net.ResolveUDPAddr("udp4", sessionData.IpAddr+":"+BFD_PORT)
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
				sesInfo := startSession(events, sessionData, sckt)
				sessionInfo <- *sesInfo

				if sesInfo.Error != nil {
					return
				}

			case STATE_INIT:
				// This indicates we are passive side and need to reply to handshake
				sesInfo := initSession(events, sessionData, sckt)
				sessionInfo <- *sesInfo

				if sesInfo.Error != nil {
					return
				}

			case STATE_UP:
				// Maintian echos
				var sesInfo *SessionInfo

				if sessionData.Flags&FLAG_DEMAND > 0 {
					sesInfo = maintainSessionDemand(events, sessionData, sckt)
				} else {
					sesInfo = maintainSessionAsync(events, sessionData, sckt)
				}

				sessionInfo <- *sesInfo

				if sesInfo.Error != nil {
					return
				}

			case STATE_ADMIN_DOWN:
				// exit routine
				return
			}

		}
	}()

	return &SessionController{id, sessionMap, sessionData, events} //, state, commands}
}

func startSession(events chan PerfEvent, sessionData *Session, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function streams control packets to start the handshake. It starts in state DOWN and
	* will continuously send control packet until it recieves a perf event indicating a response,
	* where it will change to UP state send final control packet and return.
	 */
	TxTimer := time.NewTimer(time.Duration(sessionData.MinTx) * time.Microsecond)

	// Send first control packet
	sessionData.Flags |= FLAG_POLL
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
				sessionData.MinEchoTx = event.NewRemoteEchoRx

				sessionData.State = STATE_UP

				// send final conformation with updated discriminator and state
				_, err := sckt.Write(sessionData.MarshalControl())
				if err != nil {
					fmt.Println(err)
				}

				// remove poll flag
				sessionData.Flags &= (FLAG_POLL ^ 0xff)

				return &SessionInfo{sessionData.LocalDisc, STATE_UP, nil}

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

func initSession(events chan PerfEvent, sessionData *Session, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function is on the passive side of handshake, and must respond with control packets.
	* It begins in state INIT and will send control packets until recieving an event indicating
	* the handshake is complete, where it will change to state UP and return.
	 */
	resTimer := time.NewTimer(time.Duration(RESPONSE_TIMEOUT) * time.Millisecond)

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

				return nil

			} else {
				// In INIT state no other event is valid, drop it and wait for correct event
			}

		case resTimeOut := <-resTimer.C:
			fmt.Println("[%s] [%s : %d] remote timed out", resTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			return &SessionInfo{sessionData.LocalDisc, STATE_INIT, fmt.Errorf("[%s : %d] remote timed out", sessionData.IpAddr, sessionData.LocalDisc)}
		}
	}
}

func maintainSessionAsync(events chan PerfEvent, sessionData *Session, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function will send control packets on timeouts to maintain a session in async mode.
	 */

	txTimer := time.NewTimer(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
	rxTimer := time.NewTimer(time.Duration(sessionData.MinEchoTx) * time.Microsecond)

	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Println("[%s] [%s : %d] recieved perf event", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// exit
			if event.Flags&EVENT_TEARDOWN_SESSION > 0 {
				return &SessionInfo{sessionData.LocalDisc, STATE_ADMIN_DOWN, fmt.Errorf("[%s : %d] recieved teardown", sessionData.IpAddr, sessionData.LocalDisc)}
			}

			// recieved control packet reset timer
			if event.Flags&EVENT_RX_CONTROL > 0 {
				rxTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
			}

			// update anthing else
			if event.Flags&0xf0 > 0 {
				updateSessionChange(event, sessionData)
				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}
			}

		case txTimeOut := <-rxTimer.C:
			fmt.Println("[%s] [%s : %d] sending echo packet", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			_, err := sckt.Write(sessionData.MarshalEcho())
			if err != nil {
				fmt.Println(err)
			}

			txTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)

		case rxTimeOut := <-rxTimer.C:
			fmt.Println("[%s] [%s : %d] remote down", rxTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			// Remote failed to send a packet quickly enough
			sessionData.State = STATE_DOWN
			return &SessionInfo{sessionData.LocalDisc, STATE_DOWN, fmt.Errorf("[%s : %d] remote control timed out", sessionData.IpAddr, sessionData.LocalDisc)}
		}
	}
}

func maintainSessionDemand(events chan PerfEvent, sessionData *Session, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function will send echos on timeouts and ensure recieveing echos on time outs until state change.
	* TODO: Funcitonality would need to be added for asymmetric echos.
	 */

	echoTxTimer := time.NewTimer(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
	echoRxTimer := time.NewTimer(time.Duration(sessionData.MinEchoTx) * time.Microsecond)

	_, err := sckt.Write(sessionData.MarshalEcho())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Println("[%s] [%s : %d] recieved perf event", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// exit
			if event.Flags&EVENT_TEARDOWN_SESSION > 0 {
				return &SessionInfo{sessionData.LocalDisc, STATE_ADMIN_DOWN, fmt.Errorf("[%s : %d] recieved teardown", sessionData.IpAddr, sessionData.LocalDisc)}
			}

			// Rest timer on echo reply
			if event.Flags&EVENT_RX_ECHO > 0 {
				echoTxTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
			}

			// update anthing else
			if event.Flags&0xf0 > 0 {
				updateSessionChange(event, sessionData)
				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}
			}

		case txTimeOut := <-echoTxTimer.C:
			fmt.Println("[%s] [%s : %d] sending echo packet", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			_, err := sckt.Write(sessionData.MarshalEcho())
			if err != nil {
				fmt.Println(err)
			}

			echoTxTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)

		case rxTimeOut := <-echoRxTimer.C:
			fmt.Println("[%s] [%s : %d] remote down", rxTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			// Remote failed to send a packet quickly enough
			sessionData.State = STATE_DOWN
			return &SessionInfo{sessionData.LocalDisc, STATE_DOWN, fmt.Errorf("[%s : %d] remote echo timed out", sessionData.IpAddr, sessionData.LocalDisc)}
		}
	}
}

func updateSessionChange(event PerfEvent, sessionData *Session) {

	if event.Flags&EVENT_CHNG_DISC > 0 {
		sessionData.RemoteDisc = event.NewRemoteDisc
	}

	if event.Flags&EVENT_CHNG_DEMAND > 0 {
		sessionData.Flags |= FLAG_DEMAND // | sessionData.Flags
	}

	if event.Flags&EVENT_CHNG_STATE > 0 {
		updateStateChange(event, sessionData)
	}

	if event.Flags&EVENT_CHNG_TIMING > 0 {
		sessionData.MinTx = event.NewRemoteMinRx
		sessionData.MinRx = event.NewRemoteMinTx
		sessionData.MinEchoTx = event.NewRemoteEchoRx
	}

}

func updateStateChange(event PerfEvent, sessionData *Session) {

}

// func (controller *SessionController) SendEvent(event PerfEvent) {
// 	controller.events <- event
// }

// type StateUpdate int

// const (
// 	A StateUpdate = iota
// 	B
// 	C
// )

// type Command int

// const (
// 	Stop Command = iota
// 	Pause
// 	ModeAsync
// 	ModeDemand
// )
