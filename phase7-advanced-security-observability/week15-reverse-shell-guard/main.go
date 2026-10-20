//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf revshell_detect.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type threatAlert struct {
	TsNs               uint64
	Pid                uint32
	Ppid               uint32
	Uid                uint32
	IsSuspiciousParent uint8
	Pad                [3]byte
	Comm               [16]byte
	Pcomm              [16]byte
}

const (
	colorRed    = "\033[1;31m"
	colorYellow = "\033[1;33m"
	colorReset  = "\033[0m"
)

func cleanStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(bytes.ToValidUTF8(b[:n], []byte("")))
}

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF Reverse Shell & Interactive Threat Detector (CO-RE + RingBuffer)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExecThreat, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.ThreatEvents)
	if err != nil {
		log.Fatalf("Failed to open ringbuf: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Hooked tracepoint 'sched/sched_process_exec'.")
	log.Printf("[INFO] Watching for interactive shell spawns and parent process anomalies...\n\n")

	fmt.Printf("%-9s %-22s %-6s %-6s %-12s %-14s\n",
		"TIME", "SEVERITY", "PID", "PPID", "PROCESS", "PARENT")
	fmt.Println("--------------------------------------------------------------------------------")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n[INFO] Stopping Threat Guard...")
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}

		var alert threatAlert
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &alert); err != nil {
			continue
		}

		comm := cleanStr(alert.Comm[:])
		pcomm := cleanStr(alert.Pcomm[:])

		severity := colorYellow + "SUSPICIOUS-SHELL" + colorReset
		if alert.IsSuspiciousParent == 1 {
			severity = colorRed + "CRITICAL-RCE" + colorReset
		}

		fmt.Printf("%-9s %-32s %-6d %-6d %-12s %-14s\n",
			time.Now().Format("15:04:05"),
			severity,
			alert.Pid,
			alert.Ppid,
			comm,
			pcomm,
		)
	}

	fmt.Println("[SUCCESS] Threat Guard cleanly shutdown.")
}
