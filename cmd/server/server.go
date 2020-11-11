package main

import (
	"fmt"
	"net"

	"github.com/open-oam/manager_program/pkg/server"
	bfdpb "github.com/open-oam/manager_program/proto/bfd"
	"google.golang.org/grpc"
)

// var iface = flag.String("iface", "ens4", "The interface to attach the program to")

func main() {
	// flag.Parse()
	// if *iface == "" {
	// 	panic("-iface must be a non-empty interface.")
	// }

	iface := "veth0"

	config := server.ServerConfig{Iface: iface}
	server, err := server.New(config)
	if err != nil {
		panic(err)
	}
	defer server.Bpf.Unload()

	fmt.Println("Listening on 10.11.1.2:5555")
	lis, err := net.Listen("tcp", "10.11.1.2:5555")
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
