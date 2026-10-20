//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf counter.c

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF Syscall Execve Monitor (Cilium ebpf-go + CO-RE)")
	fmt.Println("======================================================================")

	// In older kernels (< 5.11), BPF map and program memory is constrained by RLIMIT_MEMLOCK.
	// rlimit.RemoveMemlock adjusts resource limits to allow eBPF allocation.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock limit: %v", err)
	}

	// Load pre-compiled eBPF ELF objects into kernel memory
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach the eBPF program to the tracepoint: syscalls/sys_enter_execve
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to sys_enter_execve: %v", err)
	}
	defer tp.Close()

	log.Printf("Successfully hooked tracepoint 'syscalls/sys_enter_execve'!\n")
	log.Printf("Monitoring active processes... Press Ctrl+C to terminate.\n\n")

	// Set up channel to capture OS interrupt / termination signals
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Polling ticker: query the exec_count BPF map every 1 second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var previousCount uint64
	var key uint32 = 0

	for {
		select {
		case <-ticker.C:
			var count uint64
			if err := objs.ExecCount.Lookup(&key, &count); err != nil {
				log.Printf("Error looking up exec_count map: %v", err)
				continue
			}

			rate := count - previousCount
			previousCount = count

			fmt.Printf("[%s] Total execve() invocations: %-8d | Rate: %-4d calls/sec\n",
				time.Now().Format("15:04:05"), count, rate)

		case sig := <-stopper:
			fmt.Printf("\nReceived signal '%s'. Shutting down cleanly...\n", sig)

			// Print final count
			var finalCount uint64
			if err := objs.ExecCount.Lookup(&key, &finalCount); err == nil {
				fmt.Printf("Final cumulative execve() syscall count: %d\n", finalCount)
			}
			fmt.Println("eBPF program and tracepoint links detached successfully.")
			return
		}
	}
}
