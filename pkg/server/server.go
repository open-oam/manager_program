package server

import (
	"math/rand"
	"sync"

	"github.com/open-oam/manager_program/internal/loader"
	"github.com/open-oam/manager_program/pkg/bfd"
	bfdpb "github.com/open-oam/manager_program/proto/bfd"
)

// #define PROGKEY_PORT 1
// #define PROGKEY_IFINDEX 2
// #define PROGKEY_MIN_RX 3
// #define PROGKEY_MIN_TX 4
// #define PROGKEY_MIN_ECHO_RX 5
// #define PROGKEY_DETECT_MULTI 6

type ServerConfig struct {
	Port        uint32
	MinRx       uint32
	MinTx       uint32
	EchoRx      uint32
	DetectMulti uint32
}

type Server struct {
	sessions map[uint32]bfd.Session
	ipAddrs  map[string]uint32
	lock     *sync.Mutex
	bpf      *loader.BpfInfo
	port     uint16
	// kill   chan bool
	// events chan PerfEventItem
}

// New Create a new Server from the given config and interface
func New(iface string, config ServerConfig) *Server {
	bpf := loader.LoadNewBPF(iface, "./xdp.elf", "xdp_prog")

	// TODO: Finish BPF initialization, make goroutine to send events over

	// server := Server{}
	return &Server{bpf: bpf}
}

func (server *Server) newSession(ipAddr string, desiredTx uint32, desiredRx uint32, echoRx uint32, detectMulti uint32, mode bfdpb.Mode) {
	server.lock.Lock()

	key := newKey(server.sessions)
	session := bfd.DefaultSession()

	session.MinTx = desiredTx
	session.RemoteEchoRx = desiredRx
	session.EchoRx = echoRx

	server.sessions[key] = session
	server.ipAddrs[ipAddr] = key

	server.lock.Unlock()
}

func newKey(sessions map[uint32]bfd.Session) uint32 {
	for {
		key := rand.Uint32()

		if _, ok := sessions[key]; !ok {
			return key
		}
	}
}

// func (server Server) testLock() {
// 	server.lock.Lock()
// 	defer server.lock.Unlock()
// }
