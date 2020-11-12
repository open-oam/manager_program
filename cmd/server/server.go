package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-oam/manager_program/pkg/server"
	bfdpb "github.com/open-oam/manager_program/proto/bfd"
	"google.golang.org/grpc"
)

// type ServerConfig struct {
// 	Iface       string
// 	Port        uint32
// 	MinRx       uint32
// 	MinTx       uint32
// 	EchoRx      uint32
// 	DetectMulti uint32
// }

func main() {
	iface := flag.String("i", "ens4", "The interface to attach the program to")
	bfdPort := flag.Uint("b", 3784, "The eBPF intercept port for BFD Packets")
	grpcPort := flag.Uint("p", 5555, "The grpc port to listen on.")
	minRx := flag.Uint("rx", 150000, "Min rx rate in µs.")
	minTx := flag.Uint("tx", 150000, "Min Tx rat in µs.")
	echoRx := flag.Uint("echo", 50000, "The echo packet send rate in µs.")
	detectMulti := flag.Uint("multi", 1, "Number of timeouts before a session is down.")

	flag.Parse()
	if *iface == "" {
		panic("-i must be a non-empty interface.")
	}

	if *bfdPort == 0 || *bfdPort >= 65535 {
		panic("bfd port must be a valid port")
	}

	if *grpcPort == 0 || *grpcPort >= 65535 {
		panic("grpc port must be a valid port")
	}

	if *minRx == 0 || *minTx == 0 {
		panic("Minimum transmission rate must be above 0")
	}

	if *echoRx == 0 {
		panic("Echo transmission rate must be above 0")
	}

	if *detectMulti == 0 {
		panic("Must have detect multi greater than 0")
	}

	config := server.ServerConfig{
		Iface:       *iface,
		Port:        uint32(*bfdPort),
		MinRx:       uint32(*minRx),
		MinTx:       uint32(*minTx),
		EchoRx:      uint32(*echoRx),
		DetectMulti: uint32(*detectMulti),
	}

	server, err := server.New(config)
	if err != nil {
		panic(err)
	}

	// make sure to unload on graceful and Interrupt exit
	defer server.Bpf.Unload()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		server.Bpf.Unload()
		os.Exit(10)
	}()

	fmt.Println("Listening on localhost:5555")
	lis, err := net.Listen("tcp", "localhost:5555")
	if err != nil {
		panic("Unable to listen on 5555")
	}
	var opts []grpc.ServerOption

	fmt.Println("Creating Server")
	grpcServer := grpc.NewServer(opts...)
	bfdpb.RegisterBFDServer(grpcServer, server)

	fmt.Println("Running Server")
	grpcServer.Serve(lis)
}
