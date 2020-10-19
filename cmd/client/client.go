package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/open-oam/manager_program/proto/gen"
	"google.golang.org/grpc"
)

var iface = flag.String("iface", "enp5s0", "Interface to bind XDP program to")
var elf = flag.String("elf", "./xdp.elf", "clang/llvm compiled eBPF")
var programName = flag.String("program", "xdp_prog", "Name of XDP program (function name)")
var perfmap = flag.String("map", "perfmap", "Name of perfmap to read from")
var command = flag.String("cmd", "load", "load or unload a bpf")

func main() {
	flag.Parse()
	if *iface == "" {
		panic("-iface is required.")
	}

	fmt.Println("Connecting to server")
	opts := []grpc.DialOption{grpc.WithInsecure()}
	conn, err := grpc.Dial("localhost:5555", opts...)
	if err != nil {
		fmt.Println(err)
		panic("Unable to connect to server")
	}
	defer conn.Close()

	client := gen.NewPingerClient(conn)
	fmt.Println("Running command:", *command)
	if *command == "unload" {
		client.UnloadEbpf(context.Background(), &gen.Empty{})
		os.Exit(0)
	}

	_, err = client.LoadEbpf(context.Background(), &gen.LoadEbpfRequest{
		Interface: *iface,
		File:      *elf,
		Program:   *programName,
		PerfMap:   *perfmap,
	})
	if err != nil {
		fmt.Println(err)
		panic("Unable to load eBPF")
	}

	stream, _ := client.StreamPerf(context.Background(), &gen.Empty{})

	for {
		event, err := stream.Recv()
		if err != nil {
			panic(err)
		}

		fmt.Println(event)
	}
}
