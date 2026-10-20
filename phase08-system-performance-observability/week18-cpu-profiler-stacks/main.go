//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf cpu_stacks.c

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type stackKey struct {
	Pid           uint32
	KernelStackID int32
	UserStackID   int32
	Comm          [16]byte
}

type ksymbol struct {
	addr uint64
	name string
}

var ksymbols []ksymbol

func loadKallsyms() {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 3 {
			addr, err := strconv.ParseUint(parts[0], 16, 64)
			if err == nil {
				ksymbols = append(ksymbols, ksymbol{addr: addr, name: parts[2]})
			}
		}
	}
	sort.Slice(ksymbols, func(i, j int) bool {
		return ksymbols[i].addr < ksymbols[j].addr
	})
	log.Printf("[INFO] Loaded %d symbols from /proc/kallsyms\n", len(ksymbols))
}

func resolveKaddr(addr uint64) string {
	idx := sort.Search(len(ksymbols), func(i int) bool {
		return ksymbols[i].addr > addr
	})
	if idx > 0 {
		return ksymbols[idx-1].name
	}
	return fmt.Sprintf("0x%x", addr)
}

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF High-Resolution CPU Profiler & Stack Collector (Flame Graph)")
	fmt.Println("======================================================================")

	loadKallsyms()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_switch", objs.OnSchedSwitch, nil)
	if err != nil {
		log.Fatalf("Failed to attach sched_switch: %v", err)
	}
	defer tp.Close()

	log.Printf("[INFO] Sampling CPU stacks via 'sched/sched_switch'...")
	log.Printf("[INFO] Profile collecting. Press Ctrl+C to terminate and view top stacks.\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var totalSamples uint64
	for {
		select {
		case <-ticker.C:
			var (
				key stackKey
				val uint64
			)
			iter := objs.StackCounts.Iterate()
			totalSamples = 0
			uniqueChains := 0
			for iter.Next(&key, &val) {
				totalSamples += val
				uniqueChains++
			}
			fmt.Printf("[%s] Total CPU Stacks Sampled: %-8d | Unique Call Chains: %-6d\n",
				time.Now().Format("15:04:05"), totalSamples, uniqueChains)

		case <-stopper:
			fmt.Println("\n[INFO] Detaching profiler and rendering Top Call Stacks...")

			type stackEntry struct {
				key   stackKey
				count uint64
			}
			var entries []stackEntry

			var (
				key stackKey
				val uint64
			)
			iter := objs.StackCounts.Iterate()
			for iter.Next(&key, &val) {
				entries = append(entries, stackEntry{key: key, count: val})
			}

			sort.Slice(entries, func(i, j int) bool {
				return entries[i].count > entries[j].count
			})

			limit := 5
			if len(entries) < limit {
				limit = len(entries)
			}

			fmt.Println("\n=================== TOP CPU CALL CHAINS ===================")
			for i := 0; i < limit; i++ {
				e := entries[i]
				comm := string(bytes.TrimRight(e.key.Comm[:], "\x00"))
				fmt.Printf("\n#%d [%s (PID: %d)] - Sample Count: %d\n", i+1, comm, e.key.Pid, e.count)

				if e.key.KernelStackID >= 0 {
					var rawStack [127]uint64
					kid := uint32(e.key.KernelStackID)
					if err := objs.StackTraces.Lookup(&kid, &rawStack); err == nil {
						for _, ip := range rawStack {
							if ip == 0 {
								break
							}
							fmt.Printf("    -> %s\n", resolveKaddr(ip))
						}
					}
				}
			}
			fmt.Println("===========================================================")
			return
		}
	}
}
