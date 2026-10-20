//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf dropwatch.c

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

type dropEvent struct {
	Pid      uint32
	Reason   uint32
	Location uint64
	Protocol uint16
	Comm     [16]byte
}

var dropReasonNames = map[uint32]string{
	2:   "NOT_SPECIFIED",
	3:   "NO_SOCKET",
	4:   "SOCKET_CLOSE",
	5:   "SOCKET_FILTER",
	6:   "SOCKET_RCVBUFF",
	7:   "UNIX_DISCONNECT",
	8:   "UNIX_SKIP_OOB",
	9:   "PKT_TOO_SMALL",
	10:  "TCP_CSUM",
	11:  "UDP_CSUM",
	12:  "NETFILTER_DROP",
	13:  "OTHERHOST",
	14:  "IP_CSUM",
	15:  "IP_INHDR",
	16:  "IP_RPFILTER",
	17:  "UNICAST_IN_L2_MULTICAST",
	18:  "XFRM_POLICY",
	19:  "IP_NOPROTO",
	29:  "SOCKET_BACKLOG",
	30:  "TCP_FLAGS",
	45:  "TCP_RESET",
	47:  "TCP_CLOSE",
	54:  "IP_OUTNOROUTES",
	55:  "BPF_CGROUP_EGRESS",
	62:  "TC_EGRESS",
	63:  "SECURITY_HOOK",
	64:  "QDISC_DROP",
	73:  "XDP",
	74:  "TC_INGRESS",
	83:  "NOMEM",
	89:  "IP_INADDRERRORS",
	90:  "IP_INNOROUTES",
}

func getReasonStr(r uint32) string {
	if name, ok := dropReasonNames[r]; ok {
		return name
	}
	return fmt.Sprintf("REASON_%d", r)
}

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" eBPF Kernel Dropwatch & Packet Loss Diagnostics (kfree_skb)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceKfreeSkb, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to skb:kfree_skb: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.DropEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Attached to 'skb:kfree_skb'! Monitoring dropped packets live...\n")
	fmt.Printf("%-9s %-6s %-16s %-24s %-18s\n", "TIME", "PID", "COMM", "DROP REASON", "KERNEL PC")
	fmt.Println("--------------------------------------------------------------------------------")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n[INFO] Received interrupt. Shutting down dropwatch...")
		rd.Close()
	}()

	var totalDrops uint64
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Error reading ringbuf: %v", err)
			continue
		}

		var ev dropEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		totalDrops++
		comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
		fmt.Printf("%-9s %-6d %-16s %-24s 0x%-16x\n",
			time.Now().Format("15:04:05"),
			ev.Pid,
			comm,
			getReasonStr(ev.Reason),
			ev.Location,
		)
	}

	fmt.Printf("\n========== Drop Summary ==========\n")
	fmt.Printf("Total Captured Dropped Packets: %d\n", totalDrops)

	// Dump drop_reason_stats map
	var (
		reason uint32
		count  uint64
	)
	iter := objs.DropReasonStats.Iterate()
	for iter.Next(&reason, &count) {
		fmt.Printf("  - %-24s : %d packets\n", getReasonStr(reason), count)
	}
	fmt.Println("==================================")
}
