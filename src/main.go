package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"./loader"
	"./pinger"
)

func main() {

	// the main bpf tp be loaded in
	var bpf *loader.BpfInfo
	defer func() {
		if bpf != nil {
			bpf.Unload()
		}
	}()

	// channel to communicate with the routine that interfaces with perfevents and bpf
	var quitRoutine chan bool

	// command input loop
	scanner := bufio.NewScanner(os.Stdin)

inputLoop:
	for scanner.Scan() {
		command := scanner.Text()

		switch {
		case command == "exit":
			fmt.Println("Exiting...")
			break inputLoop

		case command == "load":
			fmt.Println("Loading...")
			bpf = loader.LoadNewBPF("test", "src/pinger/kernel_program/xdp.elf", "xdp_prog")

		case command == "unload":
			fmt.Println("Unloading...")
			if bpf != nil {
				bpf.Unload()
			}

		case command == "kill pinger":
			fmt.Println("Stopping pinger...")
			quitRoutine <- true

		case strings.Contains(command, "pinger"):

			fmt.Println("Pinger go routine starting...")
			if bpf != nil {
				quitRoutine = pinger.KickOffPinger("10.11.1.2", bpf.Perfmap)
			} else {
				fmt.Println("Must load bpf first.")
			}

		default:
			fmt.Println("Unkown command.")

		}
	}

}
