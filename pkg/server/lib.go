package server

import (
	"context"
	"fmt"

	"github.com/open-oam/manager_program/internal/loader"
	pingpb "github.com/open-oam/manager_program/proto/ping"
)

type Server struct {
	bpf    *loader.BpfInfo
	kill   chan bool
	events chan PerfEventItem
}

func New() Server {
	return Server{nil, make(chan bool, 1), make(chan PerfEventItem, 4096)}
}

func (self Server) LoadEbpf(ctx context.Context, req *pingpb.LoadEbpfRequest) (*pingpb.Empty, error) {
	self.bpf = loader.LoadNewBPF(req.Interface, req.File, req.Program)
	fmt.Printf("%p", self.bpf)

	fmt.Println("Starting perf events")
	err := listenForPerfEvents(self.bpf, req.PerfMap, self.kill, self.events)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return &pingpb.Empty{}, nil
}

func (self Server) UnloadEbpf(ctx context.Context, req *pingpb.Empty) (*pingpb.Empty, error) {
	self.kill <- true

	if self.bpf != nil {
		self.bpf.Unload()
	}

	return &pingpb.Empty{}, nil
}

func (self Server) StreamPerf(empt *pingpb.Empty, stream pingpb.Pinger_StreamPerfServer) error {
	fmt.Println("Streaming Perf Events")
	for {
		perfEvent := <-self.events

		fmt.Println("Sending Event")
		err := stream.SendMsg(&pingpb.PerfMessage{
			Id:       uint32(perfEvent.ID),
			Seq:      uint32(perfEvent.Seq),
			OrigTime: perfEvent.OrigTime,
			RecvTime: perfEvent.RecTime,
			SrcIP:    perfEvent.SrcIP,
		})
		if err != nil {
			fmt.Println(err)
			return err
		}
	}
}
