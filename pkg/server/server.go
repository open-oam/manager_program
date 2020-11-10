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
	Iface       string
	Port        uint32
	MinRx       uint32
	MinTx       uint32
	EchoRx      uint32
	DetectMulti uint32
}

type LocalDisc uint32

type Server struct {
	iface       string
	sessions    map[LocalDisc]*bfd.SessionController
	subs        map[LocalDisc]chan bfd.SessionInfo
	ipAddrs     map[string]LocalDisc
	sessionInfo chan bfd.SessionInfo
	lock        *sync.Mutex
	bpf         *loader.BpfInfo
	// kill   chan bool
	// events chan PerfEventItem
}

// New Create a new Server from the given config and interface
func New(config ServerConfig) (*Server, error) {
	server := &Server{}
	server.sessionInfo = make(chan bfd.SessionInfo)

	bpf := loader.LoadNewBPF(config.Iface, "./xdp.elf", "xdp_prog")

	sessionMap := bpf.Bpf.GetMapByName("session_map")
	fmt.Println("Loaded %s", sessionMap.GetName())

	// Set defaults in the program map:
	programInfo := bpf.Bpf.GetMapByName("program_info")

	programInfo.Insert(bfd.PROG_PORT, bfd.PROG_DEFAULT_PORT)
	programInfo.Insert(bfd.PROG_IF_IDX, bfd.PROG_DEFAULT_IF_IDX)
	programInfo.Insert(bfd.PROG_MIN_RX, bfd.PROG_DEFAULT_MIN_RX)
	programInfo.Insert(bfd.PROG_MIN_TX, bfd.PROG_DEFAULT_MIN_TX)
	programInfo.Insert(bfd.PROG_ECHO_RX, bfd.PROG_ECHO_RX)
	programInfo.Insert(bfd.PROG_DETECT_MULTI, bfd.PROG_DETECT_MULTI)

	// === Perf event handling ===
	// perfmap := bpf.Bpf.GetMapByName("perfmap")

	// Start listening to Perf Events
	perf, err := goebpf.NewPerfEvents(bpf.Perfmap)
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
					ipBytes := (*[4]byte)(unsafe.Pointer(&event.IpAddr))[:]
					ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
					ipAddr := ip.String()

					controller := server.newSession(ipAddr, event.NewRemoteMinTx, event.NewRemoteMinRx, bfd.PROG_DEFAULT_ECHO_RX, true)
					controller.Id = uint32(id)

					server.sessions[id] = controller
					server.ipAddrs[ipAddr] = id
				}

				session := server.sessions[id]
				session.SendEvent(event)
			case sessionInfo := <-server.sessionInfo:
				if sessionInfo.Error != nil {
					server.lock.Lock()
					defer server.lock.Unlock()

					id := LocalDisc(sessionInfo.LocalId)

					ipAddr := server.sessions[id].SessionData.IpAddr
					fmt.Println("[%s] server: [%s : %d] had an error, tearing down", time.Now().Format(time.StampMicro), ipAddr, sessionInfo.LocalId)

					// Delete the IpAddr -> LocalDisc
					delete(server.ipAddrs, ipAddr)

					// Delete the session
					delete(server.sessions, id)
				}
			}

		}

	}()

	// Finally, attach the interface:
	server.bpf.AttachInterface()

	// TODO: Finish BPF initialization, make goroutine to send events over
	// server := Server{}
	return server, nil
}

func (server *Server) newSession(ipAddr string, desiredTx uint32, desiredRx uint32, echoRx uint32, isInit bool) *bfd.SessionController {

	// Create a new session keys
	key := newKey(server.sessions)

	// Initialize the Session Data
	sessionData := new(bfd.Session)
	*sessionData = bfd.DefaultSession()
	sessionData.IpAddr = ipAddr
	sessionData.Flags |= bfd.FLAG_CONTROL_PLANE_IND // because we encapsulate in udp

	// todo: not sure mapping these correctly
	sessionData.MinTx = desiredTx
	sessionData.MinRx = desiredRx
	sessionData.MinEchoTx = echoRx

	if isInit {
		sessionData.State = bfd.STATE_INIT
	} else {
		sessionData.State = bfd.STATE_DOWN
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

func (server *Server) createSub(ipAddr string) (<-chan bfd.SessionInfo, error) {
	server.lock.Lock()
	defer server.lock.Unlock()

	id, ok := server.ipAddrs[ipAddr]
	if !ok {
		return nil, fmt.Errorf("IPAddr not found: %s", ipAddr)
	}

	c := make(chan bfd.SessionInfo)
	server.subs[id] = c

	return c, nil
}

func (server *Server) removeSub(ipAddr string) {
	server.lock.Lock()
	defer server.lock.Unlock()

	id := server.ipAddrs[ipAddr]
	delete(server.subs, id)
}

func (server *Server) CreateSession(ctx context.Context, req *bfdpb.CreateSessionRequest) (*bfdpb.CreateSessionResponse, error) {
	server.lock.Lock()
	defer server.lock.Unlock()

	controller := server.newSession(req.IPAddr, req.DesiredTx, req.DesiredRx, req.EchoRx, false) // req.DetectMulti, req.Mode
	key := LocalDisc(controller.Id)
	server.sessions[key] = controller
	server.ipAddrs[req.IPAddr] = key

	return &bfdpb.CreateSessionResponse{IPAddr: req.IPAddr}, nil
}

func (server *Server) SessionState(req *bfdpb.SessionStateRequest, res bfdpb.BFD_SessionStateServer) error {
	ipAddr := req.IPAddr

	infoEvents, err := server.createSub(ipAddr)
	if err != nil {
		return err
	}
	defer server.removeSub(ipAddr)

	for {
		info := <-infoEvents

		respInfo := &bfdpb.SessionInfo{}
		respInfo.IpAddr = ipAddr
		respInfo.State = uint32(info.State)
		respInfo.Error = info.Error.Error()

		err = res.Send(respInfo)
		if err != nil {
			return err
		}
	}

	return nil
}

// func (self Server) StreamPerf(empt *pingpb.Empty, stream pingpb.Pinger_StreamPerfServer) error {
// 	fmt.Println("Streaming Perf Events")
// 	for {
// 		perfEvent := <-self.events

// 		fmt.Println("Sending Event")
// 		err := stream.SendMsg(&pingpb.PerfMessage{
// 			Id:       uint32(perfEvent.ID),
// 			Seq:      uint32(perfEvent.Seq),
// 			OrigTime: perfEvent.OrigTime,
// 			RecvTime: perfEvent.RecTime,
// 			SrcIP:    perfEvent.SrcIP,
// 		})
// 		if err != nil {
// 			fmt.Println(err)
// 			return err
// 		}
// 	}
// }
