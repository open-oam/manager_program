package bfd

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/dropbox/goebpf"
)

/*
TODO:
	- diagnostics
	- closing handshake
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

	sessionData.LocalDisc = id
	controller.Id = id

	controller.events = events
	controller.sessionMap = sessionMap
	controller.SessionData = sessionData

	writeSession(sessionMap, sessionData)

	// Start listening for perf events
	go func() {

		// create socket
		addr, err := net.ResolveUDPAddr("udp4", sessionData.IpAddr+":"+strconv.Itoa(BFD_PORT))
		src_addr := net.UDPAddr{IP: nil, Port: BFD_PORT}
		sckt, err := net.DialUDP("udp4", &src_addr, addr)
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
				sesInfo := initSession(events, sessionData, sessionMap, sckt)
				sessionInfo <- *sesInfo

				if sesInfo.Error != nil {
					return
				}

			case STATE_UP:
				// Maintian echos
				var sesInfo *SessionInfo

				if sessionData.Flags&FLAG_DEMAND > 0 {
					sesInfo = maintainSessionDemand(events, sessionData, sessionMap, sckt)
				} else {
					sesInfo = maintainSessionAsync(events, sessionData, sessionMap, sckt)
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

	timeOut := sessionData.MinRx
	if timeOut < sessionData.MinTx {
		timeOut = sessionData.MinTx
	}

	fmt.Printf("[%s] [%s : %d] Starting session with %d timing\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc, time.Duration(timeOut)*time.Microsecond)

	txTimer := time.NewTimer(time.Duration(timeOut) * time.Microsecond)

	// Send first control packet
	sessionData.Flags |= FLAG_POLL
	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Printf("[%s] [%s : %d] recieved perf event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// TODO: Write the session data:
			// writeSession(sessionMap, sessionData)
			if event.NewRemoteState == STATE_INIT {

				// TODO: Set bpfmap key values here:
				sessionData.RemoteDisc = event.NewRemoteDisc
				sessionData.RemoteMinRx = event.NewRemoteMinTx
				sessionData.RemoteEchoRx = event.NewRemoteEchoRx

				sessionData.State = STATE_UP

				// must send final control packet for updated state
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

		case txTimeOut := <-txTimer.C:
			fmt.Printf("[%s] [%s : %d] sending control packet\n", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)

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
	* indicating state chang to UP
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
			fmt.Printf("[%s] [%s : %d] recieved perf event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			if event.NewRemoteState == STATE_UP {

				// update own state, must do here not in updateSessionChange because
				// it is the first time seeing these and change flags may not be set
				sessionData.RemoteDisc = event.NewRemoteDisc
				sessionData.RemoteMinTx = event.NewRemoteMinTx
				sessionData.RemoteEchoRx = event.NewRemoteEchoRx
				sessionData.State = STATE_UP
				writeSession(sessionMap, sessionData)

				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}

			} else {
				// In INIT state no other event is valid, drop it and wait for correct event
			}

		case resTimeOut := <-resTimer.C:
			fmt.Printf("[%s] [%s : %d] remote timed out\n", resTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			return &SessionInfo{sessionData.LocalDisc, STATE_INIT, fmt.Errorf("[%s : %d] remote timed out", sessionData.IpAddr, sessionData.LocalDisc)}
		}
	}
}

func maintainSessionAsync(events chan PerfEvent, sessionData *Session, sessionMap goebpf.Map, sckt *net.UDPConn) *SessionInfo {
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

	_, err := sckt.Write(sessionData.MarshalControl())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Printf("[%s] [%s : %d] recieved perf event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// exit
			if event.Flags&EVENT_TEARDOWN_SESSION > 0 {
				return &SessionInfo{sessionData.LocalDisc, STATE_ADMIN_DOWN, fmt.Errorf("[%s : %d] recieved teardown", sessionData.IpAddr, sessionData.LocalDisc)}
			}

			// recieved control packet reset timer
			if event.Flags&EVENT_RX_CONTROL > 0 {
				rxTimer.Reset(time.Duration(timeOutRx) * time.Microsecond)
			}

			// update anthing else
			if event.Flags&0xf0 > 0 {
				updateSessionChange(event, sessionData)
				writeSession(sessionMap, sessionData)
				return &SessionInfo{sessionData.LocalDisc, sessionData.State, nil}
			}

		case txTimeOut := <-rxTimer.C:
			fmt.Printf("[%s] [%s : %d] sending control packet\n", txTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			_, err := sckt.Write(sessionData.MarshalControl())
			if err != nil {
				fmt.Println(err)
			}

			txTimer.Reset(time.Duration(timeOutTx) * time.Microsecond)

		case rxTimeOut := <-rxTimer.C:
			fmt.Printf("[%s] [%s : %d] remote down\n", rxTimeOut.Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)

			dropCount++
			// Remote failed to send a packet quickly enough
			if dropCount >= int(sessionData.DetectMulti) {
				sessionData.State = STATE_DOWN
				return &SessionInfo{sessionData.LocalDisc, STATE_DOWN, fmt.Errorf("[%s : %d] remote control timed out\n", sessionData.IpAddr, sessionData.LocalDisc)}

			}
		}
	}
}

func maintainSessionDemand(events chan PerfEvent, sessionData *Session, sessionMap goebpf.Map, sckt *net.UDPConn) *SessionInfo {
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

	_, err := sckt.Write(sessionData.MarshalEcho())
	if err != nil {
		fmt.Println(err)
	}

	for {
		select {
		case event := <-events:
			fmt.Printf("[%s] [%s : %d] recieved perf event\n", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)
			fmt.Println(event)

			// exit
			if event.Flags&EVENT_TEARDOWN_SESSION > 0 {
				return &SessionInfo{sessionData.LocalDisc, STATE_ADMIN_DOWN, fmt.Errorf("[%s : %d] recieved teardown\n", sessionData.IpAddr, sessionData.LocalDisc)}
			}

			// Rest timer on echo reply
			if event.Flags&EVENT_RX_ECHO > 0 {
				echoTxTimer.Reset(time.Duration(sessionData.MinEchoTx) * time.Microsecond)
			}

			// update anthing else
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
				return &SessionInfo{sessionData.LocalDisc, STATE_DOWN, fmt.Errorf("[%s : %d] remote echo timed out\n", sessionData.IpAddr, sessionData.LocalDisc)}
			}
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

}

func writeSession(sessionMap goebpf.Map, sessionData *Session) {
	disc := sessionData.LocalDisc
	sessionMap.Upsert(disc, sessionData.MarshalSession())
}

func (controller *SessionController) SendEvent(event PerfEvent) {
	controller.events <- event
}

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
