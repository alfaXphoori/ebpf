//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf trampoline.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
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

type fexitEvent struct {
	DurationNs uint64
	Pid        uint32
	Ret        int32
	Comm       [16]byte
	Filename   [64]byte
}

func main() {
	commFilter := flag.String("comm", "", "show only events whose process name (comm) equals this value, e.g. -comm cat")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Trampoline (fentry & fexit) do_sys_openat2 Latency Tracer")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	linkEntry, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TraceOpenat2Entry,
	})
	if err != nil {
		log.Fatalf("Failed to attach fentry hook: %v", err)
	}
	defer linkEntry.Close()
	log.Printf("[INFO] Attached BPF Trampoline fentry to 'do_sys_openat2'\n")

	linkExit, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TraceOpenat2Exit,
	})
	if err != nil {
		log.Fatalf("Failed to attach fexit hook: %v", err)
	}
	defer linkExit.Close()
	log.Printf("[INFO] Attached BPF Trampoline fexit to 'do_sys_openat2'\n")

	rd, err := ringbuf.NewReader(objs.FexitEvents)
	if err != nil {
		log.Fatalf("Failed to open ringbuf: %v", err)
	}
	defer rd.Close()

	if *commFilter != "" {
		log.Printf("[INFO] Filtering events: comm == %q (filter applied in userspace)\n", *commFilter)
	}
	log.Printf("[INFO] Tracing do_sys_openat2 latency (fentry -> fexit). Press Ctrl+C to stop.\n\n")

	fmt.Printf("%-9s %-8s %-16s %-10s %-10s %s\n",
		"TIME", "PID", "COMM", "FD / RET", "LATENCY", "FILENAME")
	fmt.Println("---------------------------------------------------------------------------------------------------")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n[INFO] Detaching trampoline links...")
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

		var ev fexitEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		comm := cString(ev.Comm[:])
		if *commFilter != "" && comm != *commFilter {
			continue
		}
		filename := cString(ev.Filename[:])

		retStr := fmt.Sprintf("%d", ev.Ret)
		if ev.Ret < 0 {
			retStr = fmt.Sprintf("ERR(%d)", ev.Ret)
		}

		fmt.Printf("%-9s %-8d %-16s %-10s %-10s %s\n",
			time.Now().Format("15:04:05"),
			ev.Pid,
			comm,
			retStr,
			fmt.Sprintf("%.2fus", float64(ev.DurationNs)/1000.0),
			filename,
		)
	}

	fmt.Println("[SUCCESS] BPF Trampoline detached safely.")
}

// cString converts a NUL-terminated C char array into a Go string.
// (bpf_get_current_comm / bpf_probe_read_user_str ใส่ NUL ปิดท้าย แต่ไบต์หลัง NUL
// ไม่รับประกันว่าเป็นศูนย์ จึงต้องตัดที่ NUL ตัวแรก ไม่ใช่ TrimRight)
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
