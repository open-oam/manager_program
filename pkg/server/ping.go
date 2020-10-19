package server

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
	"github.com/open-oam/manager_program/internal/loader"
)

var iface = flag.String("iface", "lo", "Interface to bind XDP program to")
var elf = flag.String("elf", "../kernel_program/xdp.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "xdp_prog", "Name of XDP program (function name)")

const (
	// Size of structure used to pass metadata
	metadataSize = 16
)

// In sync with xdp_dump.c  "struct perf_event_item"
type PerfEventItem struct {
	ID, Seq  uint16
	OrigTime uint32
	RecTime  uint64
	SrcIP    uint32
}

func listenForPerfEvents(bpf *loader.BpfInfo, mapName string, kill <-chan bool, events chan<- PerfEventItem) error {
	fmt.Printf("Listening for perf events on: %s\n", mapName)

	perfmap := bpf.Bpf.GetMapByName("perfmap")

	// Start listening to Perf Events
	perf, err := goebpf.NewPerfEvents(perfmap)
	if err != nil {
		fmt.Println("LFPE Error:", err)
	}

	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		fmt.Printf("LFPE Error: %s\n", err)
		return err
	}

	fmt.Println("LFPE: Starting goroutine")
	go func(events chan<- PerfEventItem) {
		for {
			fmt.Println("Looping on Events")
			var event PerfEventItem
			select {
			case msg := <-kill:
				// BPF was unloaded, end the stream
				fmt.Println("Bpf Unloaded:", msg)
				break
			case eventData := <-perfEvents:
				reader := bytes.NewReader(eventData)
				binary.Read(reader, binary.BigEndian, &event)

				// bpf_get_ktime_ns returns time in LittleEndian order
				// since we read it in as BigEndian, we need to convert it
				b := make([]byte, 8)
				binary.BigEndian.PutUint64(b, event.RecTime)

				event.RecTime = uint64(binary.LittleEndian.Uint64(b))

				fmt.Println("LFPE: Sending Perf Event")
				// Send the event
				events <- event
			}

			// fmt.Println("Reading in PerfEvent")
			// if eventData, ok := <-perfEvents; ok {
			// 	reader := bytes.NewReader(eventData)
			// 	binary.Read(reader, binary.BigEndian, &event)

			// 	fmt.Println("LFPE: Sending Perf Event")
			// 	// Send the event
			// 	events <- event
			// } else {
			// 	// Update channel closed
			// 	fmt.Println("Update channel closed")
			// 	break
			// }
		}
	}(events)

	return nil
}

func main() {
	flag.Parse()
	if *iface == "" {
		fatalError("-iface is required.")
	}

	fmt.Println("XDP dump example program")

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	fmt.Printf("%+v\n", bpf)

	// Find special "PERF_EVENT" eBPF map
	perfmap := bpf.GetMapByName("perfmap")
	if perfmap == nil {
		fatalError("eBPF map 'perfmap' not found")
	}

	// ifaceMap := bpf.GetMapByName("iface_lookup")
	// if perfmap == nil {
	// 	fatalError("eBPF map 'iface_lookup' not found")
	// }

	// Program name matches function name in xdp.c:
	//      int xdp_dump(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName(*programName)
	if xdp == nil {
		fatalError("Program '%s' not found.", *programName)
	}

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Start listening to Perf Events
	perf, _ := goebpf.NewPerfEvents(perfmap)
	perfEvents, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		fatalError("perf.StartForAllProcessesAndCPUs(): %v", err)
	}

	fmt.Println("XDP program successfully loaded and attached.")
	fmt.Println("All ICMP coming to this host will be dumped here.")
	fmt.Println()

	go func() {
		var event PerfEventItem
		for {
			if eventData, ok := <-perfEvents; ok {
				reader := bytes.NewReader(eventData)
				fmt.Printf("%+v\n", reader)
				binary.Read(reader, binary.BigEndian, &event)
				fmt.Printf("ID: %v,\nSequence: %v,\nOriginate Timestamp: %v,\nRecieve Timestamp: %v \n",
					event.ID, event.Seq,
					event.OrigTime, event.RecTime,
				)
				if len(eventData)-metadataSize > 0 {
					// event contains packet sample as well
					fmt.Println(hex.Dump(eventData[metadataSize:]))
				}
			} else {
				// Update channel closed
				break
			}
		}
	}()

	// Wait until Ctrl+C pressed
	<-ctrlC

	// Stop perf events and print summary
	perf.Stop()
	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", perf.EventsReceived)
	fmt.Printf("\t%d Event(s) lost (e.g. small buffer, delays in processing)\n", perf.EventsLost)
	fmt.Println("\nDetaching program and exit...")
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
