package main

import (
	"context"
	"flag"
	"fmt"
	"net"

	bfdpb "github.com/open-oam/manager_program/proto/bfd"
	"google.golang.org/grpc"
)

// var iface = flag.String("iface", "enp5s0", "Interface to bind XDP program to")
// var elf = flag.String("elf", "./xdp.elf", "clang/llvm compiled eBPF")
// var programName = flag.String("program", "xdp_prog", "Name of XDP program (function name)")
// var perfmap = flag.String("map", "perfmap", "Name of perfmap to read from")
// var command = flag.String("cmd", "load", "load or unload a bpf")

var remote = flag.String("remote", "", "Remote server to create session with")
var stream = flag.Bool("stream", false, "Stream events for the given session")

func main() {
	flag.Parse()
	if *remote == "" {
		panic("-remote is required.")
	}

	ip := net.ParseIP(*remote)
	if ip == nil || ip.To4() == nil {
		panic("-remote must be a valid IPv4 address in dot notation")
	}

	// if *iface == "" {
	// 	panic("-iface is required.")
	// }

	fmt.Println("Connecting to server")
	opts := []grpc.DialOption{grpc.WithInsecure()}
	conn, err := grpc.Dial("localhost:5555", opts...)
	if err != nil {
		fmt.Println(err)
		panic("Unable to connect to server")
	}
	defer conn.Close()

	client := bfdpb.NewBFDClient(conn)

	if !*stream {
		req := &bfdpb.CreateSessionRequest{IPAddr: ip.String()}
		resp, err := client.CreateSession(context.Background(), req)
		if err != nil {
			fmt.Printf("Unable to create session for %s\n", ip.String())
			panic(err)
		}

		fmt.Printf("Successfully started session with %s\n", resp.IPAddr)
	} else {
		req := &bfdpb.SessionStateRequest{IPAddr: ip.String()}
		infoEvents, err := client.SessionState(context.Background(), req)
		if err != nil {
			d := fmt.Sprintf("Unable to create session for %s", ip.String())
			panic(d)
		}

		for {
			info, err := infoEvents.Recv()
			if err != nil {
				panic(err)
			}
			fmt.Println(info)
		}
	}

	// client.
	// fmt.Println("Running command:", *command)
	// if *command == "unload" {
	// 	client.UnloadEbpf(context.Background(), &bfdpb.Empty{})
	// 	os.Exit(0)
	// }

	// _, err = client.LoadEbpf(context.Background(), &bfdpb.LoadEbpfRequest{
	// 	Interface: *iface,
	// 	File:      *elf,
	// 	Program:   *programName,
	// 	PerfMap:   *perfmap,
	// })
	// if err != nil {
	// 	fmt.Println(err)
	// 	panic("Unable to load eBPF")
	// }

	// stream, _ := client.StreamPerf(context.Background(), &bfdpb.Empty{})
}
