package loader

import (
	"fmt"
	"net"
	"os"

	"github.com/dropbox/goebpf"
)

type BpfInfo struct {
	Bpf     goebpf.System
	Perfmap goebpf.Map
	Xdp     goebpf.Program
	Iface   int
}

func (storage BpfInfo) Unload() {
	if storage.Xdp != nil {
		storage.Xdp.Detach()
	}
}

func (storage *BpfInfo) Load(iface string, elfPath string, programName string) {
	// Create eBPF system / load .ELF files compiled by clang/llvm
	storage.Bpf = goebpf.NewDefaultEbpfSystem()
	err := storage.Bpf.LoadElf(elfPath)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(storage.Bpf)

	fmt.Printf("%+v\n", storage.Bpf)

	// Find special "PERF_EVENT" eBPF map
	// storage.Perfmap = storage.Bpf.GetMapByName("perfmap")
	// if storage.Perfmap == nil {
	// 	fatalError("eBPF map 'perfmap' not found")
	// }

	// Program name matches function name in xdp.c:
	//      int xdp_dump(struct xdp_md *ctx)
	storage.Xdp = storage.Bpf.GetProgramByName(programName)
	if storage.Xdp == nil {
		fatalError("Program '%s' not found.", programName)
	}

	fmt.Println("Got Program")

	// Load XDP program into kernel
	err = storage.Xdp.Load()

	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	fmt.Println("Loaded Program")

	ifaceNet, err := net.InterfaceByName(iface)
	if err != nil {
		fatalError("Unable to get iface: %v", err)
	}

	storage.Iface = ifaceNet.Index

	fmt.Println("XDP program successfully loaded.")
	fmt.Println()
}

func (storage *BpfInfo) AttachInterface() {
	// Attach to interface
	err := storage.Xdp.Attach(storage.Iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
}

func (storage *BpfInfo) AttachToInterface(iface string) {
	// storage.Iface = iface

	// Attach to interface
	err := storage.Xdp.Attach(iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
}

func LoadNewBPF(iface string, elfPath string, programName string) *BpfInfo {
	ret := &BpfInfo{}
	ret.Load(iface, elfPath, programName)

	// doesnt dangle in go ... nice
	return ret
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		m := item.(*goebpf.EbpfMap)
		fmt.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}
