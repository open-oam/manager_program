package main

import (
	"fmt"
	"net"

	"github.com/open-oam/manager_program/pkg/server"
	"github.com/open-oam/manager_program/proto/gen"
	"google.golang.org/grpc"
)

func main() {
	server := server.New()

	fmt.Println("Listening on localhost:5555")
	lis, err := net.Listen("tcp", "localhost:5555")
	if err != nil {
		panic("Unable to listen on 5555")
	}
	var opts []grpc.ServerOption

	fmt.Println("Creating Server")
	grpcServer := grpc.NewServer(opts...)
	gen.RegisterPingerServer(grpcServer, server)

	fmt.Println("Running Server")
	grpcServer.Serve(lis)
}
