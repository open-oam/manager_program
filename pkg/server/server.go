package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"

	"github.com/dropbox/goebpf"
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

type LocalDisc uint32

type Server struct {
	sessions map[LocalDisc]*bfd.SessionController
	ipAddrs  map[string]LocalDisc
	lock     *sync.Mutex
	bpf      *loader.BpfInfo
	// kill   chan bool
	// events chan PerfEventItem
}

// New Create a new Server from the given config and interface
func New(iface string, config ServerConfig) (*Server, error) {
	server := &Server{}

	bpf := loader.LoadNewBPF(iface, "./xdp.elf", "xdp_prog")
	perfmap := bpf.Bpf.GetMapByName("perfmap")

	// Start listening to Perf Events
	perf, err := goebpf.NewPerfEvents(perfmap)
	if err != nil {
		fmt.Printf("LFPE Error: %s\n", err)
		return nil, err
	}

	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		fmt.Printf("LFPE Error: %s\n", err)
		return nil, err
	}

	server.bpf = bpf

	// Start reading from the bpf PerfEvents
	go func() {
		var event bfd.PerfEvent

		for {
			eventData := <-perfEvents
			reader := bytes.NewReader(eventData)
			binary.Read(reader, binary.BigEndian, &event)

			id := LocalDisc(event.LocalDisc)

			server.lock.Lock()
			defer server.lock.Unlock()

			session := server.sessions[id]

			// TODO: Figure out what happens if the LocalDisc
			// doesn't exist? Accept a new session?
			// if _, ok := server.sessions[id]; !ok {
			// 	server.acceptNewSession(...)
			// }
			// or:
			// if id == 0 {
			// 	server.acceptNewSession(...)
			// }

			session.SendEvent(event)
		}

	}()

	// TODO: Finish BPF initialization, make goroutine to send events over
	// server := Server{}
	return server, nil
}

func (server *Server) createNewSession(ipAddr string, desiredTx uint32, desiredRx uint32, echoRx uint32, detectMulti uint32, mode bfdpb.Mode) {

	// Create a new session key
	key := newKey(server.sessions)

	// Initialize the Session Data
	sessionData := &bfd.DefaultSession()

	sessionData.MinTx = desiredTx
	sessionData.RemoteEchoRx = desiredRx
	sessionData.EchoRx = echoRx

	controller := bfd.NewController(&server.bpf.Bpf, sessionData, ipAddr, key)

	// Need to lock to modify the map
	server.lock.Lock()
	defer server.lock.Unlock()

	server.sessions[key] = controller
	server.ipAddrs[ipAddr] = key
}

// func (server *Server) acceptNewSession(ipAddr string, ...) {

// }

func newKey(sessions map[LocalDisc]*bfd.SessionController) LocalDisc {
	for {
		key := LocalDisc(rand.Uint32())

		if _, ok := sessions[key]; !ok {
			return key
		}
	}
}

func (server *Server) CreateSession(ctx context.Context, req *bfdpb.CreateSessionRequest) (*bfdpb.CreateSessionResponse, error) {
	server.createNewSession(req.IPAddr, req.DesiredTx, req.DesiredRx, req.EchoRx, req.DetectMulti, req.Mode)

	return &bfdpb.CreateSessionResponse{IPAddr: req.IPAddr}, nil
}
