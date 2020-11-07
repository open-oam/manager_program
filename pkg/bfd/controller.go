package bfd

import (
	"fmt"

	"github.com/dropbox/goebpf"
)

// SessionController Controls a running BFD session
type SessionController struct {
	sessionMap  goebpf.Map
	sessionData Session
	state       chan StateUpdate
	commands    chan Command
	events      chan PerfEvent
	// lock       *sync.Mutex
}

// NewController Create a new controller from the given bpf System
func NewController(bpf *goebpf.System, sessionData Session) *SessionController {
	sessionMap := (*bpf).GetMapByName("session_map")
	state := make(chan StateUpdate)
	commands := make(chan Command)
	events := make(chan PerfEvent)

	// Start listening for perf events
	go func() {
		for {
			event := <-events
			fmt.Println(event)
		}

	}()

	return &SessionController{sessionMap, sessionData, state, commands, events}
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
