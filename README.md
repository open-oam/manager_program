# BFD with eBPFs and XDP

This repository contains the core code running two BFD sessions using XDP and eBPFs. The core manager program is written with `go` and compiled server and client binaries can be found at `./server` and `./client` respectively. You may have to rebuild the binaries.

## Building the Client and Server Binaries:

Install a go compiler that supports modules, e.g. 1.15+ and run:

```bash
go build cmd/client/client.go # build the client
go build cmd/server/server.go # build the server
```

## Compiling the Protobufs:

We use [buf](https://buf.build/) for compiling the protobufs for go. We found that buf made it easier to manage the protobuf compilation stage as well as switching between workspaces. The bfd protobuf is in `./proto/bfd/bfd.proto`, generated code lands in `./gen/proto/bfd`, and the buf config file is `./buf.gen.yaml`.

After installing `buf`, `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc`, run the following to compile the protobufs:

```bash
buf build proto/
```

## Creating and Managing a Session:

Transfer over the server binary and `xdp.elf` to two devices, make sure port 5555 and 3784 are available. On both servers execute:

```bash
sudo ./server
```

You should see output indicating that the xdp program was successfully loaded. If there are any errors, make sure `xdp.elf` is in the same directory as the server. 

The rest of the configuration is done by a main server. The following client commands should be execute on this main server. Remote in this case is the IP address of the non-main server.

### Create a Session:

```bash
# Do not write the carets
./client -create -remote <remote_ip>
```

The local discriminator for the session should be printed to the screen. Copy this and save it for later commands.

At this point, both servers should be logging the fact that they are sending, or replying to, BFD control packets since the server begins in `ASYNC` mode. Note that the timestamps for the logging appear ~150 ms. apart.

### Switching Modes:

To switch to demand mode:

```bash
./client -change-mode DEMAND -disc <local_disc>
```

and back to async mode:

```bash
./client -change-mode ASYNC -disc <local_disc>
```

### Streaming State Changes:

To stream the state changes of a specific session (for usage in programmatically detecting a DOWN):

```bash
./client -stream -disc <local_disc>
```

Any change to state, including switching modes, will send a `StateInfo` message across the stream. If there was an error in the stream, the error field will not be empty. The codes that describe if a state is down or up can be found in `./pkg/bfd/types.go`

### Stopping a Stream:

There is not yet a good way to programmatically kill a stream. For now, simply `Ctrl-C` one of the server processes. You should be able to detect a state change and a `DOWN` event will be fired.

## Program Architecture:

The overall architecture is represented in the following diagram:

[arch]: https://github.com/open-oam/manager_program/blob/master/res/bfd_architecture.jpg

![bfd architecture][arch]

Code for the main server process is under `pkg/server/server.go` and session controller lives under `pkg/bfd/controller.go`.

PerfEvents from the kernel space are continuously read in a go routine spun-off during server initialization. These events are then multiplexed to the proper session controller based off of the local discriminator, or a new session controller is created.

Write operations within a [Server](https://github.com/open-oam/manager_program/blob/master/pkg/server/server.go#L34) must first `Lock()` the server before they can commence. The server may be handling multiple requests in parallel and memory safety needs to be maintained.

[SessionControllers](https://github.com/open-oam/manager_program/blob/master/pkg/bfd/controller.go#L13) use [PerfEvents](https://github.com/open-oam/manager_program/blob/master/pkg/bfd/types.go#L161) and flags within those events to either change modes, update [SessionState](https://github.com/open-oam/manager_program/blob/master/pkg/bfd/types.go#L55), or reset timers. 