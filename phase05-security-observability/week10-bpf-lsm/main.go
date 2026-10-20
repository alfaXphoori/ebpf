package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf bpf lsm_file_guard.c

// lsmAlert matches C struct lsm_alert
type lsmAlert struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [64]byte
	Action   int32
}

func checkLSMStatus() {
	content, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		log.Printf("[WARN] Cannot read /sys/kernel/security/lsm: %v. Assuming BPF LSM might not be enabled.", err)
		return
	}
	activeLSMs := string(content)
	log.Printf("[INFO] Active Linux Security Modules: %s", strings.TrimSpace(activeLSMs))
	if !strings.Contains(activeLSMs, "bpf") {
		log.Println("[WARNING] 'bpf' is NOT in /sys/kernel/security/lsm!")
		log.Println("[WARNING] To enable BPF LSM, add 'lsm=...,bpf' to your kernel boot parameters:")
		log.Println("[WARNING]   Edit /etc/default/grub -> GRUB_CMDLINE_LINUX=\"lsm=lockdown,capability,landlock,yama,apparmor,bpf\"")
		log.Println("[WARNING]   Then run: sudo update-grub && sudo reboot")
	}
}

func cStringToString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}

func main() {
	blockAllFlag := flag.Bool("block-all", false, "Block secret* file access for all users, including root (UID 0)")
	flag.Parse()

	// 1. Remove Memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// 2. Check kernel BPF LSM capability
	checkLSMStatus()

	// 3. Load eBPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects (make sure your kernel supports BPF LSM and BTF): %v", err)
	}
	defer objs.Close()

	// 4. Configure policy map
	var policyKey uint32 = 0
	var policyVal uint32 = 0
	if *blockAllFlag {
		policyVal = 1
		log.Println("[POLICY] Enforce Mode: BLOCK ALL (including root UID 0)")
	} else {
		log.Println("[POLICY] Enforce Mode: BLOCK NON-ROOT (root UID 0 allowed)")
	}

	if err := objs.PolicyMap.Put(&policyKey, &policyVal); err != nil {
		log.Printf("[WARN] Failed to update policy map: %v", err)
	}

	// 5. Attach LSM Hook
	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.RestrictSecretFiles,
	})
	if err != nil {
		log.Fatalf("Failed to attach LSM program (verify kernel supports CONFIG_BPF_LSM=y): %v", err)
	}
	defer lsmLink.Close()

	log.Println("[INFO] Successfully attached BPF LSM hook to 'file_open'!")
	log.Println("[INFO] Watching for unauthorized attempts to access 'secret*' files...")

	// 6. Open Ring Buffer Reader
	rd, err := ringbuf.NewReader(objs.LsmEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\n[INFO] Termination signal received. Detaching LSM hook and exiting...")
		rd.Close()
	}()

	fmt.Printf("%-18s %-7s %-6s %-16s %-20s %s\n", "SECURITY_ACTION", "PID", "UID", "COMM", "FILENAME", "RESULT")
	fmt.Println(strings.Repeat("-", 85))

	var alert lsmAlert
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[INFO] Ringbuf reader closed. Goodbye.")
				return
			}
			log.Printf("[ERROR] Reading ringbuf record: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &alert); err != nil {
			log.Printf("[ERROR] Failed to decode LSM alert: %v", err)
			continue
		}

		comm := cStringToString(alert.Comm[:])
		filename := cStringToString(alert.Filename[:])

		resultStr := "PASS"
		if alert.Action == -1 {
			resultStr = "EPERM (Blocked)"
		}

		fmt.Printf("\033[1;31m%-18s\033[0m %-7d %-6d %-16s %-20s %s\n",
			"[BLOCKED -EPERM]", alert.Pid, alert.Uid, comm, filename, resultStr)
	}
}
