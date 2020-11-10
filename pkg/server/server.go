package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
	"unsafe"

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
	sessions    map[LocalDisc]*bfd.SessionController
	ipAddrs     map[string]LocalDisc
	lock        *sync.Mutex
	bpf         *loader.BpfInfo
	sessionInfo chan bfd.SessionInfo
	// kill   chan bool
	// events chan PerfEventItem
}

// New Create a new Server from the given config and interface
func New(iface string, config ServerConfig) (*Server, error) {
	server := &Server{}
	server.sessionInfo = make(chan bfd.SessionInfo)

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
			select {
			case eventData := <-perfEvents:
				reader := bytes.NewReader(eventData)
				binary.Read(reader, binary.BigEndian, &event)

				id := LocalDisc(event.LocalDisc)

				server.lock.Lock()
				defer server.lock.Unlock()

				if _, ok := server.sessions[id]; !ok {
					ipBytes := (*[4]byte)(unsafe.Pointer(&eventData.ipAddr))[:]
					ip := net.IP.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
					ipAddr = ip.String()

					controller := server.newSession(ipAddr, eventData.NewRemoteMinTx, eventData.NewRemoteMinRx, true)
					controller.Id = id

					server.sessions[id] = controller
					server.ipAddrs[ipAddr] = id
				}

				session := server.sessions[id]
				session.SendEvent(event)
			case sessionInfo := <-server.sessionInfo:
				if sessionInfo.Error != nil {
					fmt.Println("[%s] server: [%s : %d] had an error, tearing down", time.Now().Format(time.StampMicro), sessionData.IpAddr, sessionData.LocalDisc)

					server.lock.Lock()
					defer server.lock.Unlock()

					ipAddr := server.sessions[sessionInfo.LocalDisc].SessionData.ipAddr

					// Delete the IpAddr -> LocalDisc
					delete(server.ipAddrs, ipAddr)

					// Delete the session
					delete(server.sessions, sessionInfo.LocalDisc)
				}
			}

		}

	}()

	// TODO: Finish BPF initialization, make goroutine to send events over
	// server := Server{}
	return server, nil
}

func (server *Server) newSession(ipAddr string, desiredTx uint32, desiredRx uint32, echoRx uint32, detectMulti uint32, mode bfdpb.Mode, isInit bool) *bfd.SessionController {

	// Create a new session keys
	key := newKey(server.sessions)

	// Initialize the Session Data
	sessionData := new(bfd.Session)
	*sessionData = bfd.DefaultSession()
	sessionData.IpAddr = ipAddr

	// todo: not sure mapping these correctly
	sessionData.MinTx = desiredTx
	sessionData.MinRx = desiredRx
	sessionData.MinEchoTx = echoRx

	if isInit {
		sessionData.State = bfd.STATE_INIT
	} else {
		sessionData.Sate = bfd.STATE_DOWN
	}

	return bfd.NewController(uint32(key), &server.bpf.Bpf, sessionData, server.sessionInfo)
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
	server.lock.Lock()
	defer server.lock.Unlock()

	controller := server.createNewSession(req.IPAddr, req.DesiredTx, req.DesiredRx, req.EchoRx, req.DetectMulti, req.Mode)
	key := LocalDics(controller.Id)
	server.sessions[key] = controller
	server.ipAddrs[ipAddr] = key

	return &bfdpb.CreateSessionResponse{IPAddr: req.IPAddr}, nil
}
