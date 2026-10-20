//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf task_iter.c

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF Kernel Task Iterator (bpf_iter_task / Zero-Context-Switch Proc)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach BPF Iterator
	it, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTask,
	})
	if err != nil {
		log.Fatalf("Failed to attach BPF iterator: %v", err)
	}
	defer it.Close()

	start := time.Now()

	// Open synthetic seq_file reader directly from the in-kernel iterator
	reader, err := it.Open()
	if err != nil {
		log.Fatalf("Failed to open iterator stream: %v", err)
	}
	defer reader.Close()

	output, err := io.ReadAll(reader)
	if err != nil {
		log.Fatalf("Failed to read from iterator: %v", err)
	}

	elapsed := time.Since(start)

	log.Printf("[INFO] BPF Iterator traversed all kernel task_structs in %v!\n\n", elapsed)

	fmt.Printf("%-8s %-8s %-10s %-16s\n", "PID", "UID", "VM_SIZE_KB", "COMM")
	fmt.Println("------------------------------------------------------------")
	fmt.Print(string(output))
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("Kernel introspection complete. Process table generated 100%% inside BPF.\n")
}
