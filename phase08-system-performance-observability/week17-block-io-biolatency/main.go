//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf biolatency.c

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func renderHistogram(hist [32]uint64) {
	var maxCount uint64
	for _, v := range hist {
		if v > maxCount {
			maxCount = v
		}
	}

	fmt.Printf("\n%-18s : %-8s %s\n", "Latency (us)", "Count", "Distribution")
	fmt.Println("----------------------------------------------------------------------")

	for i := 0; i < 30; i++ {
		low := uint64(1) << i
		high := (uint64(1) << (i + 1)) - 1
		if i == 0 {
			low = 0
			high = 1
		}
		count := hist[i]

		if count == 0 && (i > 15 && i < 28) {
			continue // skip empty trailing large buckets
		}

		barLen := 0
		if maxCount > 0 {
			barLen = int((count * 40) / maxCount)
		}
		bar := strings.Repeat("*", barLen)

		fmt.Printf("%-8d -> %-7d : %-8d |%-40s|\n", low, high, count, bar)
	}
	fmt.Println("----------------------------------------------------------------------")
}

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF Block I/O Latency Analyzer (CO-RE biolatency)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tpIssue, err := link.Tracepoint("block", "block_rq_issue", objs.TraceRqIssue, nil)
	if err != nil {
		log.Fatalf("Failed to attach block_rq_issue: %v", err)
	}
	defer tpIssue.Close()

	tpComplete, err := link.Tracepoint("block", "block_rq_complete", objs.TraceRqComplete, nil)
	if err != nil {
		log.Fatalf("Failed to attach block_rq_complete: %v", err)
	}
	defer tpComplete.Close()

	log.Printf("[INFO] Attached to 'block:block_rq_issue' & 'block:block_rq_complete'!")
	log.Printf("[INFO] Tracing disk I/O requests. (Press Ctrl+C to stop and view histogram)\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var k0, k1 uint32 = 0, 1
			var cnt, lat uint64
			objs.IoTotals.Lookup(&k0, &cnt)
			objs.IoTotals.Lookup(&k1, &lat)
			avgLat := uint64(0)
			if cnt > 0 {
				avgLat = lat / cnt
			}
			fmt.Printf("[%s] Total I/O Ops: %-6d | Cumulative: %-8d us | Avg Latency: %-6d us\n",
				time.Now().Format("15:04:05"), cnt, lat, avgLat)

		case <-stopper:
			fmt.Println("\n[INFO] Detaching probes and generating final I/O latency histogram...")
			var hist [32]uint64
			for i := uint32(0); i < 32; i++ {
				var val uint64
				if err := objs.IoLatencyHist.Lookup(&i, &val); err == nil {
					hist[i] = val
				}
			}
			renderHistogram(hist)
			return
		}
	}
}
