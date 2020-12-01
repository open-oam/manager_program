package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-oam/manager_program/internal/loader"
)

func main() {
	iface := flag.String("iface", "ens0", "Interface to load on")
	file := flag.String("file", "xdp.elf", "ELF File to load")
	prog := flag.String("prog", "xdp_prog", "Program to load")

	flag.Parse()

	fmt.Printf("iface=%s file=%s prog=%s\n", *iface, *file, *prog)

	bpfInfo := loader.LoadNewBPF(*iface, *file, *prog)
	bpfInfo.AttachToInterface(*iface)
	defer bpfInfo.Unload()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		bpfInfo.Unload()
		os.Exit(10)
	}()

	for {
	}
}
