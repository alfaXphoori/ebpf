//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf oom_watcher.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type oomAlert struct {
	TsNs        uint64
	TotalVMKb   uint64
	AnonRSSKb   uint64
	VictimPid   uint32
	Uid         uint32
	Comm        [16]byte
}

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF Memory Subsystem & OOM Forensics Watcher")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tpOOM, err := link.Tracepoint("oom", "mark_victim", objs.OnOomMarkVictim, nil)
	if err != nil {
		log.Fatalf("Failed to attach oom:mark_victim: %v", err)
	}
	defer tpOOM.Close()

	tpPF, err := link.Tracepoint("exceptions", "page_fault_user", objs.OnUserPageFault, nil)
	if err != nil {
		log.Fatalf("Failed to attach exceptions:page_fault_user: %v", err)
	}
	defer tpPF.Close()

	rd, err := ringbuf.NewReader(objs.OomEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Watching for User Page Faults and OOM Killer events...\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Background OOM alert listener
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			var alert oomAlert
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &alert); err == nil {
				comm := string(bytes.TrimRight(alert.Comm[:], "\x00"))
				fmt.Printf("\n\033[1;31m[CRITICAL OOM KILLER TRIGGERED]\033[0m\n")
				fmt.Printf("  • Victim Process : %s (PID: %d, UID: %d)\n", comm, alert.VictimPid, alert.Uid)
				fmt.Printf("  • Total VM Size  : %d KB (%.2f MB)\n", alert.TotalVMKb, float64(alert.TotalVMKb)/1024.0)
				fmt.Printf("  • Anonymous RSS  : %d KB (%.2f MB)\n\n", alert.AnonRSSKb, float64(alert.AnonRSSKb)/1024.0)
			}
		}
	}()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			type pfEntry struct {
				comm  string
				count uint64
			}
			var entries []pfEntry

			var (
				k [16]byte
				v uint64
			)
			iter := objs.PageFaultCounts.Iterate()
			for iter.Next(&k, &v) {
				entries = append(entries, pfEntry{
					comm:  string(bytes.TrimRight(k[:], "\x00")),
					count: v,
				})
			}

			sort.Slice(entries, func(i, j int) bool {
				return entries[i].count > entries[j].count
			})

			fmt.Printf("[%s] Top Processes by User-Space Page Faults:\n", time.Now().Format("15:04:05"))
			limit := 5
			if len(entries) < limit {
				limit = len(entries)
			}
			for i := 0; i < limit; i++ {
				fmt.Printf("   #%d %-16s : %-8d page faults\n", i+1, entries[i].comm, entries[i].count)
			}
			fmt.Println()

		case <-stopper:
			fmt.Println("\n[INFO] Detaching Memory Watcher...")
			return
		}
	}
}
