package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	bfdpb "github.com/open-oam/manager_program/gen/proto/bfd"
	"github.com/open-oam/manager_program/pkg/bfd"
	"google.golang.org/grpc"
)

var createSession = flag.Bool("create", false, "Create a BFD Session with a given -remote server")
var changeMode = flag.Bool("change-mode", false, "Change the mode of a given LocalDisc")
var streamState = flag.Bool("stream", false, "Stream events for the given session")

var remote = flag.String("remote", "", "Remote server to create session with")
var mode = flag.String("mode", "", "Change the mode of a remote server")
var id = flag.Uint("disc", 0, "The local discriminator of the session")

func main() {
	flag.Parse()

	fmt.Println("Connecting to server")
	opts := []grpc.DialOption{grpc.WithInsecure()}
	conn, err := grpc.Dial("localhost:5555", opts...)
	if err != nil {
		fmt.Println(err)
		panic("Unable to connect to server")
	}
	defer conn.Close()

	client := bfdpb.NewBFDClient(conn)

	if *createSession {
		if *remote == "" {
			panic("-remote is required for creating a session.")
		}

		ip := net.ParseIP(*remote)
		if ip == nil || ip.To4() == nil {
			panic("-remote must be a valid IPv4 address in dot notation")
		}

		req := &bfdpb.CreateSessionRequest{IPAddr: ip.String()}
		resp, err := client.CreateSession(context.Background(), req)
		if err != nil {
			fmt.Printf("Unable to create session for %s\n", ip.String())
			panic(err)
		}

		fmt.Printf("Started session with: %s\n", *remote)
		fmt.Printf("Session ID: %d\n", resp.GetLocalId())
	} else if *streamState {
		req := &bfdpb.SessionStateRequest{LocalId: uint32(*id)}
		infoEvents, err := client.SessionState(context.Background(), req)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Streaming State changes for %d:\n", *id)

		for {
			info, err := infoEvents.Recv()
			if err != nil {
				panic(err)
			}

			fmt.Printf("[%s] %d: %s\n", time.Now().Format(time.RFC3339Nano), info.LocalId, bfd.BfdState(info.State).String())
		}
	} else if *changeMode {
		changeMode := bfdpb.Mode_value[*mode]
		req := &bfdpb.ChangeModeRequest{LocalId: uint32(*id), Mode: bfdpb.Mode(changeMode)}
		_, err = client.ChangeMode(context.Background(), req)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Successfully changed modes to: %s\n", *mode)
	}

}
