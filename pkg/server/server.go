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
	bfdpb "github.com/open-oam/manager_program/gen/proto/bfd"
	"github.com/open-oam/manager_program/internal/loader"
	"github.com/open-oam/manager_program/pkg/bfd"
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
	iface    string
	config   ServerConfig
	sessions map[LocalDisc]*bfd.SessionController
	subs     map[LocalDisc]chan bfd.SessionInfo
	// ipAddrs     map[string]LocalDisc
	sessionInfo chan bfd.SessionInfo
	lock        *sync.Mutex
	Bpf         *loader.BpfInfo
	// kill   chan bool
	// events chan PerfEventItem
}

// New Create a new Server from the given config and interface
func New(config ServerConfig) (*Server, error) {
	rand.Seed(int64(time.Now().Nanosecond()))

	server := &Server{}
	server.config = config
	server.sessions = make(map[LocalDisc]*bfd.SessionController)
	server.subs = make(map[LocalDisc]chan bfd.SessionInfo)
	server.sessionInfo = make(chan bfd.SessionInfo, 1024)
	server.lock = new(sync.Mutex)

	bpf := loader.LoadNewBPF(config.Iface, "./xdp.elf", "xdp_prog")

	sessionMap := bpf.Bpf.GetMapByName("session_map")
	fmt.Printf("Loaded %s\n", sessionMap.GetName())

	// Set defaults in the program map:
	programInfo := bpf.Bpf.GetMapByName("program_info")

	if config.Port == 0 {
		server.config.Port = bfd.PROG_DEFAULT_PORT
	}

	if config.MinRx == 0 {
		server.config.MinRx = bfd.PROG_DEFAULT_MIN_RX
	}

	if config.MinTx == 0 {
		server.config.MinTx = bfd.PROG_DEFAULT_MIN_TX
	}

	if config.EchoRx == 0 {
		server.config.EchoRx = bfd.PROG_ECHO_RX
	}

	if config.DetectMulti == 0 {
		server.config.DetectMulti = bfd.PROG_DETECT_MULTI
	}

	programInfo.Upsert(bfd.PROG_PORT, server.config.Port)
	programInfo.Upsert(bfd.PROG_IF_IDX, bpf.Iface)
	programInfo.Upsert(bfd.PROG_MIN_RX, server.config.MinRx)
	programInfo.Upsert(bfd.PROG_MIN_TX, server.config.MinTx)
	programInfo.Upsert(bfd.PROG_ECHO_RX, server.config.EchoRx)
	programInfo.Upsert(bfd.PROG_DETECT_MULTI, server.config.DetectMulti)

	port, err := programInfo.LookupInt(bfd.PROG_PORT)
	if err != nil {
		panic(err)
	}
	fmt.Printf("BFD Port: %d\n", port)

	// === Perf event handling ===
	perfmap := bpf.Bpf.GetMapByName("perfmap")
	if perfmap == nil {
		panic("unable to get perfmap")
	}

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

	server.Bpf = bpf

	// Start reading from the bpf PerfEvents
	go func() {
		var event bfd.PerfEvent

		for {
			select {
			case eventData := <-perfEvents:
				reader := bytes.NewReader(eventData)
				binary.Read(reader, binary.LittleEndian, &event)
				id := LocalDisc(event.LocalDisc)

				if _, ok := server.sessions[id]; !ok {
					server.lock.Lock()
					defer server.lock.Unlock()

					fmt.Printf("[%s] [%d] perfevent -> create new session\n", time.Now().Format(time.StampMicro), event.LocalDisc)

					ipBytes := (*[4]byte)(unsafe.Pointer(&event.IpAddr))[:]
					ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
					ipAddr := ip.String()

					controller := server.newSession(&id, ipAddr, event.NewRemoteMinTx, event.NewRemoteMinRx, bfd.PROG_DEFAULT_ECHO_RX, true)
					controller.Id = uint32(id)

					server.sessions[id] = controller
					// server.ipAddrs[ipAddr] = id
				}

				session := server.sessions[id]
				session.SendEvent(event)

			case sessionInfo := <-server.sessionInfo:
				id := LocalDisc(sessionInfo.LocalId)

				if c, ok := server.subs[id]; ok {
					c <- sessionInfo
				}

				if sessionInfo.Error != nil || sessionInfo.State == bfd.STATE_ADMIN_DOWN {
					server.lock.Lock()
					defer server.lock.Unlock()

					id := LocalDisc(sessionInfo.LocalId)
					ipAddr := server.sessions[id].SessionData.IpAddr

					if sessionInfo.Error != nil {
						fmt.Printf("[%s] server: [%s : %d] had an error, tearing down\n", time.Now().Format(time.StampMicro), ipAddr, sessionInfo.LocalId)
						fmt.Printf("[%s] server error: [%s : %d] %s\n", time.Now().Format(time.StampMicro), ipAddr, sessionInfo.LocalId, sessionInfo.Error.Error())
					} else {
						fmt.Printf("[%s] server: [%s : %d] Change to Admin Down... tearing down\n", time.Now().Format(time.StampMicro), ipAddr, sessionInfo.LocalId)
					}

					// Delete the IpAddr -> LocalDisc
					// delete(server.ipAddrs, ipAddr)

					// Delete the session
					delete(server.sessions, id)
				}
			}

		}

	}()

	// Finally, attach the interface:
	server.Bpf.AttachToInterface(config.Iface)

	// TODO: Finish BPF initialization, make goroutine to send events over
	// server := Server{}
	return server, nil
}

func (server *Server) newSession(localDisc *LocalDisc, ipAddr string, desiredTx uint32, desiredRx uint32, echoRx uint32, isInit bool) *bfd.SessionController {

	// Create a new session keys
	var key LocalDisc
	if localDisc != nil {
		key = *localDisc
	} else {
		key = newKey(server.sessions)
	}

	fmt.Printf("[%s] new session for %s: %d\n", time.Now().Format(time.StampMicro), ipAddr, uint32(key))

	// Initialize the Session Data
	sessionData := new(bfd.Session)
	*sessionData = bfd.DefaultSession()
	sessionData.IpAddr = ipAddr
	sessionData.Flags |= bfd.FLAG_CONTROL_PLANE_IND // because we encapsulate in udp

	// todo: not sure mapping these correctly
	if desiredTx > 0 {
		sessionData.MinTx = desiredTx
	}

	if desiredRx > 0 {
		sessionData.MinRx = desiredRx
	}

	if echoRx > 0 {
		sessionData.MinEchoTx = echoRx
	}

	if isInit {
		sessionData.State = bfd.STATE_INIT
	} else {
		sessionData.State = bfd.STATE_DOWN
	}

	return bfd.NewController(uint32(key), &server.Bpf.Bpf, sessionData, server.sessionInfo)
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

func (server *Server) createSub(id LocalDisc) (<-chan bfd.SessionInfo, error) {
	server.lock.Lock()
	defer server.lock.Unlock()

	// id, ok := server.ipAddrs[ipAddr]
	// if !ok {
	// 	return nil, fmt.Errorf("IPAddr not found: %s", ipAddr)
	// }

	c := make(chan bfd.SessionInfo, 1024)
	server.subs[id] = c

	return c, nil
}

func (server *Server) removeSub(id LocalDisc) {
	server.lock.Lock()
	defer server.lock.Unlock()

	// id := server.ipAddrs[ipAddr]
	delete(server.subs, id)
}

func (server *Server) CreateSession(ctx context.Context, req *bfdpb.CreateSessionRequest) (*bfdpb.CreateSessionResponse, error) {
	fmt.Printf("Create Session: %s\n", req.IPAddr)

	server.lock.Lock()

	fmt.Println("Defering the unlock")

	defer server.lock.Unlock()

	controller := server.newSession(nil, req.IPAddr, req.DesiredTx, req.DesiredRx, req.EchoRx, false) // req.DetectMulti, req.Mode
	key := LocalDisc(controller.Id)
	server.sessions[key] = controller
	// server.ipAddrs[req.IPAddr] = key

	return &bfdpb.CreateSessionResponse{LocalId: uint32(key)}, nil
}

func (server *Server) SessionState(req *bfdpb.SessionStateRequest, res bfdpb.BFD_SessionStateServer) error {
	// ipAddr := req.IPAddr
	id := LocalDisc(req.GetLocalId())

	infoEvents, err := server.createSub(id)
	if err != nil {
		return err
	}
	defer server.removeSub(id)

	for {
		info := <-infoEvents

		respInfo := &bfdpb.SessionInfo{}
		respInfo.LocalId = info.LocalId
		respInfo.State = uint32(info.State)
		respInfo.Error = ""

		if info.Error != nil {
			respInfo.Error = info.Error.Error()
		}

		err = res.Send(respInfo)
		if err != nil {
			return err
		}
	}
}

func (server *Server) ChangeMode(ctx context.Context, req *bfdpb.ChangeModeRequest) (*bfdpb.Empty, error) {
	localId := LocalDisc(req.LocalId)
	mode := uint32(req.Mode)

	server.lock.Lock()

	session, ok := server.sessions[localId]
	if !ok {
		return nil, fmt.Errorf("Unknown LocalId: %d", uint32(localId))
	}

	server.lock.Unlock()

	command := bfd.CommandEvent{Type: bfd.CHANGE_MODE, Data: mode}
	session.SendCommand(command)

	return &bfdpb.Empty{}, nil
}

// func (server *Server) mustEmbedUnimplementedBFDServer() {}

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
