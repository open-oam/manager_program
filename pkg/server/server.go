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

// ServerConfig holds the configurable parameters of a server
type ServerConfig struct {
	Iface       string
	Port        uint32
	MinRx       uint32
	MinTx       uint32
	EchoRx      uint32
	DetectMulti uint32
}

// LocalDisc Type for Unique session discriminator
type LocalDisc uint32

// Server is the main object creating/removing and storing all sessions
type Server struct {
	iface       string
	config      ServerConfig
	sessions    map[LocalDisc]*bfd.SessionController
	subs        map[LocalDisc]chan bfd.SessionInfo
	sessionInfo chan bfd.SessionInfo
	lock        *sync.Mutex
	Bpf         *loader.BpfInfo
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

					// Delete the session
					delete(server.sessions, id)
				}
			}

		}

	}()

	// Finally, attach the interface:
	server.Bpf.AttachToInterface(config.Iface)
	return server, nil
}

func (server *Server) newSession(localDisc *LocalDisc, ipAddr string, desiredTx uint32, desiredRx uint32, echoRx uint32, isInit bool) *bfd.SessionController {
	/*
	*  Function creates and initializes a new session with a new sessionController.
	 */

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

func newKey(sessions map[LocalDisc]*bfd.SessionController) LocalDisc {
	/*
	* Creates a unique u32 LocalDisc for session.
	 */
	for {
		key := LocalDisc(rand.Uint32())

		if _, ok := sessions[key]; !ok {
			return key
		}
	}
}

func (server *Server) createSub(id LocalDisc) (<-chan bfd.SessionInfo, error) {
	/*
	* Creates a channel for sesssion info
	 */

	server.lock.Lock()
	defer server.lock.Unlock()

	c := make(chan bfd.SessionInfo, 1024)
	server.subs[id] = c

	return c, nil
}

func (server *Server) removeSub(id LocalDisc) {
	/*
	* Deletes a channel for sesssion info
	 */

	server.lock.Lock()
	defer server.lock.Unlock()

	delete(server.subs, id)
}

// CreateSession Creates a new session from the gRPC api side.
func (server *Server) CreateSession(ctx context.Context, req *bfdpb.CreateSessionRequest) (*bfdpb.CreateSessionResponse, error) {

	server.lock.Lock()
	defer server.lock.Unlock()

	controller := server.newSession(nil, req.IPAddr, req.DesiredTx, req.DesiredRx, req.EchoRx, false)
	key := LocalDisc(controller.Id)
	server.sessions[key] = controller

	return &bfdpb.CreateSessionResponse{LocalId: uint32(key)}, nil
}

// 	SessionState Streams session state.
func (server *Server) SessionState(req *bfdpb.SessionStateRequest, res bfdpb.BFD_SessionStateServer) error {

	id := LocalDisc(req.GetLocalId())

	infoEvents, err := server.createSub(id)

	controller, ok := server.sessions[id]
	initialInfo := &bfdpb.SessionInfo{LocalId: uint32(id), State: uint32(controller.SessionData.State), Error: ""}

	if !ok {
		return fmt.Errorf("Unkown ID: %d", id)
	}

	if err != nil {
		return err
	}
	defer server.removeSub(id)

	err = res.Send(initialInfo)
	if err != nil {
		return err
	}

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

// ChangeMode chanes the session mode, ASYNC -> DEMAND, DEMAND -> ASYNC
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
