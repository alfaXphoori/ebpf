//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf bpf_audit.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfAuditEvent struct {
	TsNs uint64
	Pid  uint32
	Uid  uint32
	Cmd  uint32
	Comm [16]byte
}

var bpfCmdNames = map[uint32]string{
	0:  "BPF_MAP_CREATE",
	1:  "BPF_MAP_LOOKUP_ELEM",
	2:  "BPF_MAP_UPDATE_ELEM",
	3:  "BPF_MAP_DELETE_ELEM",
	4:  "BPF_MAP_GET_NEXT_KEY",
	5:  "BPF_PROG_LOAD",
	6:  "BPF_OBJ_PIN",
	7:  "BPF_OBJ_GET",
	8:  "BPF_PROG_ATTACH",
	9:  "BPF_PROG_DETACH",
	10: "BPF_PROG_TEST_RUN",
	14: "BPF_PROG_QUERY",
	28: "BPF_LINK_CREATE",
	29: "BPF_LINK_UPDATE",
	30: "BPF_LINK_GET_FD_BY_ID",
	31: "BPF_LINK_GET_NEXT_ID",
}

func getCmdName(cmd uint32) string {
	if name, ok := bpfCmdNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("CMD_%d", cmd)
}

func readSysctl(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "UNKNOWN"
	}
	return strings.TrimSpace(string(data))
}

func auditHardening() {
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" [1] Host eBPF Security & Hardening Posture Assessment")
	fmt.Println("----------------------------------------------------------------------")

	unpriv := readSysctl("/proc/sys/kernel/unprivileged_bpf_disabled")
	fmt.Printf("  • kernel.unprivileged_bpf_disabled : %s ", unpriv)
	if unpriv == "1" || unpriv == "2" {
		fmt.Printf("[\033[1;32mSECURE / HARDENED\033[0m]\n")
	} else {
		fmt.Printf("[\033[1;31mVULNERABLE: Unprivileged users can load BPF\033[0m]\n")
	}

	jitHarden := readSysctl("/proc/sys/net/core/bpf_jit_harden")
	fmt.Printf("  • net.core.bpf_jit_harden          : %s ", jitHarden)
	if jitHarden == "1" || jitHarden == "2" {
		fmt.Printf("[\033[1;32mSECURE / HARDENED\033[0m]\n")
	} else {
		fmt.Printf("[\033[1;33mDEFAULT / UNHARDENED\033[0m]\n")
	}

	jitEnable := readSysctl("/proc/sys/net/core/bpf_jit_enable")
	fmt.Printf("  • net.core.bpf_jit_enable          : %s\n", jitEnable)
	fmt.Println("----------------------------------------------------------------------\n")
}

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF Rootkit Detector & Integrity Scanner (sys_enter_bpf)")
	fmt.Println("======================================================================")

	auditHardening()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_bpf", objs.TraceBpfCall, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.BpfAuditEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Hooked tracepoint 'syscalls/sys_enter_bpf'.")
	log.Printf("[INFO] Auditing all sys_bpf() calls and kernel modifications in real time...\n\n")

	fmt.Printf("%-9s %-6s %-6s %-16s %-24s %s\n",
		"TIME", "PID", "UID", "COMM", "BPF COMMAND", "RISK")
	fmt.Println("--------------------------------------------------------------------------------")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n[INFO] Stopping BPF integrity auditor...")
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

		var ev bpfAuditEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		n := bytes.IndexByte(ev.Comm[:], 0)
		if n == -1 {
			n = len(ev.Comm)
		}
		comm := string(ev.Comm[:n])

		risk := "INFO"
		if ev.Cmd == 5 /* BPF_PROG_LOAD */ {
			risk = "\033[1;33mPROG_LOAD\033[0m"
		} else if ev.Cmd == 8 || ev.Cmd == 28 /* ATTACH or LINK */ {
			risk = "\033[1;31mPROG_ATTACH\033[0m"
		}

		fmt.Printf("%-9s %-6d %-6d %-16s %-24s %s\n",
			time.Now().Format("15:04:05"),
			ev.Pid,
			ev.Uid,
			comm,
			getCmdName(ev.Cmd),
			risk,
		)
	}

	fmt.Println("[SUCCESS] BPF Integrity Auditor stopped safely.")
}
