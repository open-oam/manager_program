package bfd

import "github.com/dropbox/goebpf"

// SessionController Controls a running BFD session
type SessionController struct {
	sessionMap goebpf.Map
	state      chan StateUpdate
	commands   chan Command
	events     chan PerfEvent
}

// NewController Create a new controller from the given bpf System
func NewController(bpf *goebpf.System) SessionController {
	sessionMap := (*bpf).GetMapByName("session_map")
	state := make(chan StateUpdate)
	commands := make(chan Command)
	events := make(chan PerfEvent)

	return SessionController{sessionMap, state, commands, events}
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
