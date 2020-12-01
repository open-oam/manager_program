package bfd

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/dropbox/goebpf"
)

// SessionController Controls a running BFD session
type SessionController struct {
	Id          uint32
	sessionMap  goebpf.Map
	SessionData *Session
	events      chan PerfEvent
	command     chan CommandEvent
}

// NewController Create a new controller from the given bpf System
func NewController(id uint32, bpf *goebpf.System, sessionData *Session, sessionInfo chan<- SessionInfo) *SessionController {
	controller := &SessionController{}

	sessionMap := (*bpf).GetMapByName("session_map")
	events := make(chan PerfEvent, 1024)
	commands := make(chan CommandEvent, 1024)

	sessionData.LocalDisc = id
	controller.Id = id

	controller.events = events
	controller.sessionMap = sessionMap
	controller.SessionData = sessionData

	writeSession(sessionMap, sessionData)
	fmt.Printf("[%s] [%s : %d] Creating session with localDisc: %d\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, id)

	// Start listening for perf events
	go func() {

		// create socket
		addr, err := net.ResolveUDPAddr("udp4", sessionData.IpAddr+":"+strconv.Itoa(BFD_PORT))
		srcAddr := net.UDPAddr{IP: nil, Port: BFD_PORT}
		sckt, err := net.DialUDP("udp4", &srcAddr, addr)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer sckt.Close()

		for {
			switch sessionData.State {
			case STATE_DOWN:
				// Either on creation or link down, either way try sending BFD control packets
				sesInfo := startSession(events, sessionData, sessionMap, sckt)
				sessionInfo <- *sesInfo

				if sesInfo.Error != nil {
					return
				}

			case STATE_INIT:
				// This indicates we are passive side and need to reply to handshake
				sesInfo := initSession(events, sessionData, sessionMap, sckt)
				sessionInfo <- *sesInfo

				if sesInfo.Error != nil {
					return
				}

			case STATE_UP:
				// Maintian echos
				var sesInfo *SessionInfo

				if sessionData.Flags&FLAG_DEMAND > 0 {
					sesInfo = maintainSessionDemand(events, commands, sessionData, sessionMap, sckt)
				} else {
					sesInfo = maintainSessionAsync(events, commands, sessionData, sessionMap, sckt)
				}

				sessionInfo <- *sesInfo

				if sesInfo.Error != nil {
					return
				}

			case STATE_ADMIN_DOWN:
				// exit routine
				return
			}

			fmt.Printf("[%s] [%s : %d] Session state %d\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, sessionData.State)

		}
	}()

	return &SessionController{id, sessionMap, sessionData, events, commands} //, state, commands}
}

// func (controller *SessionController) sendSessionInfo(info SessionInfo) {

// }

func startSession(events chan PerfEvent, sessionData *Session, sessionMap goebpf.Map, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function streams control packets to start the handshake. It starts in state DOWN and
	* will continuously send control packet until it recieves a perf event indicating a response,
	* where it will change to UP state send final control packet and return.
	 */

	timeOut := RESPONSE_TIMEOUT

	fmt.Printf("[%s] [%s : %d] Starting session with %d timing\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, time.Duration(timeOut)*time.Microsecond)

	txTimer := time.NewTimer(time.Duration(timeOut) * time.Microsecond)

	// Send first control packet
	sessionData.Flags |= FLAG_POLL
	sessionData.RemoteState = STATE_DOWN

	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Printf("[%s] [%s : %d] recieved perfevent session routine.\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			if event.NewRemoteState == STATE_INIT {

				sessionData.RemoteDisc = event.NewRemoteDisc
				sessionData.RemoteMinRx = event.NewRemoteMinRx
				sessionData.RemoteMinTx = event.NewRemoteMinTx
				sessionData.RemoteEchoRx = event.NewRemoteEchoRx

				sessionData.State = STATE_UP
				sessionData.RemoteState = STATE_INIT

				// must send final control packet for updated state
				fmt.Printf("[%s] [%s : %d] Sending state UP control packet\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
				_, err := sckt.Write(sessionData.MarshalControl())
				if err != nil {
					fmt.Println(err)
				}

				writeSession(sessionMap, sessionData)

				txTimer.Reset(time.Duration(timeOut) * time.Microsecond)
				//return &SessionInfo{sessionData.LocalDisc, STATE_UP, nil}

			} else if event.NewRemoteState == STATE_UP && sessionData.State == STATE_UP {
				// waiting for other side
				fmt.Printf("[%s] [%s : %d] Recieved remote State up, handshake complete moving to async.\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
				sessionData.RemoteState = STATE_UP

				// remove poll flag
				sessionData.Flags &= (FLAG_POLL ^ 0xff)
				return &SessionInfo{sessionData.LocalDisc, STATE_UP, nil}

			} else {
				fmt.Printf("[%d] on startSession got NewRemoteState: %d instead of %d\n", sessionData.LocalDisc, event.NewRemoteState, STATE_INIT)
				// not sure what other events possible, but will be discarded
			}

		case txTimeOut := <-txTimer.C:
			fmt.Printf("[%s] [%s : %d] sending handshake control packet with state %d\n", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, sessionData.State)

			// timeout send another control packet
			_, err := sckt.Write(sessionData.MarshalControl())
			if err != nil {
				fmt.Println(err)
			}

			txTimer.Reset(time.Duration(timeOut) * time.Microsecond)
		}
	}
}

func initSession(events chan PerfEvent, sessionData *Session, sessionMap goebpf.Map, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function is on the passive side of handshake and will basically wait for perf event
	* indicating state change to UP
	 */
	resTimer := time.NewTimer(time.Duration(RESPONSE_TIMEOUT) * time.Millisecond)

	// // Send first control packet
	// _, err := sckt.Write(sessionData.MarshalControl())
	// if err != nil {
	// 	fmt.Println(err)
	// }

	for {
		select {
		case event := <-events:
			fmt.Printf("[%s] [%s : %d] recieved perf event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			if event.NewRemoteState == STATE_UP {
				fmt.Printf("[%s] [%s : %d] Server side recieved final remote state UP response, moving to async.\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)

				// update own state, must do here not in updateSessionChange because
				// it is the first time seeing these and change flags may not be set
				sessionData.RemoteDisc = event.NewRemoteDisc
				sessionData.RemoteMinTx = event.NewRemoteMinTx
				sessionData.RemoteEchoRx = event.NewRemoteEchoRx
				sessionData.State = STATE_UP
				sessionData.RemoteState = STATE_UP

				writeSession(sessionMap, sessionData)

				// // must send final control packet for updated state
				// sessionData.Flags |= FLAG_POLL
				// _, err := sckt.Write(sessionData.MarshalControl())
				// if err != nil {
				// 	fmt.Println(err)
				// }
				// sessionData.Flags &= (FLAG_POLL ^ 0xff)

				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}

			} else {
				fmt.Printf("[%d] on initSession got NewRemoteState: %d instead of %d\n", sessionData.LocalDisc, event.NewRemoteState, STATE_UP)
				// In INIT state no other event is valid, drop it and wait for correct event
			}

		case resTimeOut := <-resTimer.C:
			fmt.Printf("[%s] [%s : %d] Server handshake timed out waiting for client response\n", resTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			return &SessionInfo{sessionData.LocalDisc, STATE_INIT, fmt.Errorf("[%s : %d] remote timed out", sessionData.IpAddr, sessionData.LocalDisc)}
		}
	}
}

func maintainSessionAsync(events chan PerfEvent, commands chan CommandEvent, sessionData *Session, sessionMap goebpf.Map, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function will send control packets on timeouts to maintain a session in async mode.
	 */

	timeOutTx := sessionData.MinTx
	if timeOutTx < sessionData.RemoteMinRx {
		timeOutTx = sessionData.RemoteMinRx
	}

	timeOutRx := sessionData.MinRx
	if timeOutRx < sessionData.RemoteMinTx {
		timeOutRx = sessionData.RemoteMinTx
	}

	fmt.Printf("[%s] [%s : %d] Entering Async with %d timing\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, time.Duration(timeOutTx)*time.Microsecond)
	txTimer := time.NewTimer(time.Duration(timeOutTx) * time.Microsecond)
	rxTimer := time.NewTimer(time.Duration(timeOutRx) * time.Microsecond)

	dropCount := 0
	expectFinal := false

	fmt.Printf("[%s] [%s : %d] sending first async control packet\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case command := <-commands:
			fmt.Printf("[%s] [%s : %d] recieved command event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			expectFinal = handleCommand(command, sessionData, sckt)

		case event := <-events:
			fmt.Printf("[%s] [%s : %d] recieved perf event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// check if waiting on final packet to change mode
			if expectFinal && event.Flags&EVENT_RX_FINAL > 0 {
				writeSession(sessionMap, sessionData)
				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}
			}

			// exit
			if event.Flags&EVENT_TEARDOWN_SESSION > 0 {
				return &SessionInfo{sessionData.LocalDisc, STATE_ADMIN_DOWN, nil}
			}

			// recieved control packet reset timer
			if event.Flags&1 == EVENT_RX_CONTROL {
				dropCount = 0
				rxTimer.Reset(time.Duration(timeOutRx) * time.Microsecond)
			}

			// update anthing else
			if event.Flags&0xf0 > 0 {
				updateSessionChange(event, sessionData)
				writeSession(sessionMap, sessionData)
				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}
			}

		case txTimeOut := <-txTimer.C:
			fmt.Printf("[%s] [%s : %d] sending continued async control packet\n", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			_, err := sckt.Write(sessionData.MarshalControl())
			if err != nil {
				fmt.Println(err)
			}

			txTimer.Reset(time.Duration(timeOutTx) * time.Microsecond)
		case rxTimeOut := <-rxTimer.C:
			dropCount++

			// Remote failed to send a packet quickly enough
			if dropCount >= int(sessionData.DetectMulti) {
				fmt.Printf("[%s] [%s : %d] remote down, [%d missed]\n", rxTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, dropCount)
				sessionData.State = STATE_DOWN
				sessionData.RemoteState = STATE_DOWN

				return &SessionInfo{sessionData.LocalDisc, STATE_DOWN, fmt.Errorf("[%s : %d] remote control timed out\n", sessionData.IpAddr, sessionData.LocalDisc)}
			}

			rxTimer.Reset(time.Duration(timeOutRx) * time.Microsecond)
		}
	}
}

func maintainSessionDemand(events chan PerfEvent, commands chan CommandEvent, sessionData *Session, sessionMap goebpf.Map, sckt *net.UDPConn) *SessionInfo {
	/*
	* This function will send echos on timeouts and ensure recieveing echos on time outs until state change.
	* TODO: Funcitonality would need to be added for asymmetric echos.
	 */

	echoTimeOut := sessionData.MinEchoTx
	if echoTimeOut < sessionData.RemoteEchoRx {
		echoTimeOut = sessionData.RemoteEchoRx
	}

	echoTxTimer := time.NewTimer(time.Duration(echoTimeOut) * time.Microsecond)
	echoRxTimer := time.NewTimer(time.Duration(echoTimeOut) * time.Microsecond)

	dropCount := 0
	expectFinal := false

	_, err := sckt.Write(sessionData.MarshalEcho())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case command := <-commands:

			fmt.Printf("[%s] [%s : %d] recieved command event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			expectFinal = handleCommand(command, sessionData, sckt)

		case event := <-events:
			fmt.Printf("[%s] [%s : %d] recieved perf event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// check if waiting on final packet to change mode or timing
			if expectFinal && event.Flags&EVENT_RX_FINAL > 0 {
				writeSession(sessionMap, sessionData)
				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}
			}

			// exit
			if event.Flags&EVENT_TEARDOWN_SESSION > 0 {
				return &SessionInfo{sessionData.LocalDisc, STATE_ADMIN_DOWN, nil}
			}

			// Rest timer on echo reply
			if event.Flags&EVENT_RX_ECHO > 0 {
				dropCount = 0
				echoTxTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
			}

			// update anthing elsess
			if event.Flags&0xf0 > 0 {
				updateSessionChange(event, sessionData)
				writeSession(sessionMap, sessionData)
				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}
			}

		case txTimeOut := <-echoTxTimer.C:
			fmt.Printf("[%s] [%s : %d] sending echo packet\n", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			_, err := sckt.Write(sessionData.MarshalEcho())
			if err != nil {
				fmt.Println(err)
			}

			echoTxTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)

		case rxTimeOut := <-echoRxTimer.C:
			fmt.Printf("[%s] [%s : %d] remote down\n", rxTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			// Remote failed to send a packet quickly enough

			dropCount++
			if dropCount >= int(sessionData.DetectMulti) {
				sessionData.State = STATE_DOWN
				sessionData.RemoteState = STATE_DOWN
				return &SessionInfo{sessionData.LocalDisc, STATE_DOWN, fmt.Errorf("[%s : %d] remote echo timed out", sessionData.IpAddr, sessionData.LocalDisc)}
			}

			echoRxTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
		}
	}
}

func handleCommand(command CommandEvent, sessionData *Session, sckt *net.UDPConn) bool {
	fmt.Printf("[%s : %d] handleCommand SessionData:\n", sessionData.IpAddr, sessionData.LocalDisc)
	fmt.Println(*sessionData)

	switch command.Type {
	case SHUTDOWN:

		// change state
		sessionData.State = STATE_ADMIN_DOWN

	case CHANGE_MODE:

		// If we are in demand mode and are asked to move
		// to demand mode, do nothing.
		if sessionData.Flags&FLAG_DEMAND > 0 && command.Data.(uint32) == DEMAND {
			fmt.Printf("[%s : %d] Invalid command, already in Demand mode.\n", sessionData.IpAddr, sessionData.LocalDisc)
			return false
		}

		// If we are in ASYNC mode and are asked to
		// move to ASYNC mode, do nothing?
		if sessionData.Flags&FLAG_DEMAND == 0 && command.Data.(uint32) == ASYNC {
			fmt.Printf("[%s : %d] Invalid command, already in Async mode.\n", sessionData.IpAddr, sessionData.LocalDisc)
			return false
		}

		// toggle mode
		sessionData.Flags ^= FLAG_DEMAND

	case CHANGE_TIME_RX:
		sessionData.MinRx = command.Data.(uint32)

	case CHANGE_TIME_TX:
		sessionData.MinTx = command.Data.(uint32)

	case CHANGE_TIME_ECHO:
		sessionData.MinEchoTx = command.Data.(uint32)

	case CHANGE_MULTI:
		// Multi is only onh our side and doesnt need to be updated over session
		sessionData.DetectMulti = command.Data.(uint8)
		return false
	}

	// add poll flag
	sessionData.Flags |= FLAG_POLL

	// send control packet
	fmt.Printf("[%s : %d] Sending control packet on command event.\n", sessionData.IpAddr, sessionData.LocalDisc)
	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	// remove poll flag
	sessionData.Flags &= (FLAG_POLL ^ 0xff)

	// return expecting Final packet
	return true
}

func updateSessionChange(event PerfEvent, sessionData *Session) {

	if event.Flags&EVENT_CHNG_DISC > 0 {
		sessionData.RemoteDisc = event.NewRemoteDisc
	}

	if event.Flags&EVENT_CHNG_STATE > 0 {

		switch event.NewRemoteState {
		case STATE_ADMIN_DOWN:
			sessionData.State = STATE_ADMIN_DOWN

		case STATE_DOWN:
			sessionData.State = STATE_DOWN

		case STATE_INIT:
			// nothing additional to do in this case, is taken care of in initSession

		case STATE_UP:
			sessionData.State = STATE_UP
		}

	}

	if event.Flags&EVENT_CHNG_TIMING > 0 {
		sessionData.MinTx = event.NewRemoteMinRx
		sessionData.MinRx = event.NewRemoteMinTx
		sessionData.MinEchoTx = event.NewRemoteEchoRx
	}

	if event.Flags&EVENT_CHNG_DEMAND > 0 {
		sessionData.Flags ^= FLAG_DEMAND
	}

}

func writeSession(sessionMap goebpf.Map, sessionData *Session) {
	disc := sessionData.LocalDisc
	fmt.Printf("[%s] [%s : %d] Writing to session map with key: %d\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, disc)

	err := sessionMap.Upsert(disc, sessionData.MarshalSession())
	if err != nil {
		fmt.Printf("[%s] [%s : %d] Failed to write to map.\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
		fmt.Println(err)
	}
}

func (controller *SessionController) SendEvent(event PerfEvent) {
	controller.events <- event
}

func (controller *SessionController) SendCommand(command CommandEvent) {
	controller.command <- command
}
