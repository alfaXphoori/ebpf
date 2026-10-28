//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sockops.c

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Index layout of bypass_stats (must match the enum in sockops.c)
const (
	statRedirectMsgs uint32 = iota
	statRedirectBytes
	statFallbackMsgs
	statFallbackBytes
	statSocksAdded
)

// readStat returns one counter from bypass_stats (0 on lookup error)
func readStat(m *ebpf.Map, idx uint32) uint64 {
	var v uint64
	if err := m.Lookup(&idx, &v); err != nil {
		return 0
	}
	return v
}

// countSockhashEntries walks the SOCKHASH keys (sockets closed by the
// application are removed from the map automatically by the kernel)
func countSockhashEntries(m *ebpf.Map) int {
	var key, next bpfSockKey
	n := 0
	err := m.NextKey(nil, &next)
	for err == nil {
		n++
		key = next
		err = m.NextKey(&key, &next)
	}
	return n
}

func main() {
	// Attaching sockops to the ROOT cgroup affects every TCP socket on the host.
	// Default to a dedicated child cgroup and only move test processes into it.
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup/w20-sockops-lab", "Target cgroup v2 path (created if missing)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF TCP Sockops & Direct Socket-to-Socket Bypass (Cilium Mesh FastPath)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	createdCgroup := false
	if _, err := os.Stat(*cgroupPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(*cgroupPath, 0755); err != nil {
			log.Fatalf("Failed to create cgroup %s: %v", *cgroupPath, err)
		}
		createdCgroup = true
		log.Printf("[INFO] Created cgroup %s\n", *cgroupPath)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 1. Attach BPF_PROG_TYPE_SOCK_OPS to target cgroup
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.BpfSockopsHandler,
	})
	if err != nil {
		log.Fatalf("Failed to attach sockops to cgroup %s: %v", *cgroupPath, err)
	}
	defer cgroupLink.Close()
	log.Printf("[INFO] Attached BPF_PROG_TYPE_SOCK_OPS to cgroup %s\n", *cgroupPath)

	// 2. Attach BPF_PROG_TYPE_SK_MSG verdict to sock_hash map
	attachOpts := link.RawAttachProgramOptions{
		Target:  objs.SockHash.FD(),
		Program: objs.BpfSkMsgHandler,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	if err := link.RawAttachProgram(attachOpts); err != nil {
		log.Fatalf("Failed to attach sk_msg verdict to sock_hash: %v", err)
	}
	defer link.RawDetachProgram(link.RawDetachProgramOptions(attachOpts))
	log.Printf("[INFO] Attached BPF_PROG_TYPE_SK_MSG verdict to BPF_MAP_TYPE_SOCKHASH\n")

	log.Printf("[INFO] Socket bypass active for NEW IPv4 TCP connections inside %s\n", *cgroupPath)
	log.Printf("[INFO] Move a shell into it: echo $$ | sudo tee %s/cgroup.procs\n\n", *cgroupPath)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	printStats := func() {
		fmt.Printf("[%s] Sockets: %-4d (live %-4d) | Redirected: %-8d msgs %-12d B | Fallback: %-6d msgs %-10d B\n",
			time.Now().Format("15:04:05"),
			readStat(objs.BypassStats, statSocksAdded),
			countSockhashEntries(objs.SockHash),
			readStat(objs.BypassStats, statRedirectMsgs),
			readStat(objs.BypassStats, statRedirectBytes),
			readStat(objs.BypassStats, statFallbackMsgs),
			readStat(objs.BypassStats, statFallbackBytes))
	}

	for {
		select {
		case <-ticker.C:
			printStats()

		case <-stopper:
			fmt.Println("\n[INFO] Detaching sockops and sk_msg hooks...")
			printStats()
			if createdCgroup {
				// Only succeeds when no process is left inside the cgroup
				if err := os.Remove(*cgroupPath); err == nil {
					log.Printf("[INFO] Removed cgroup %s\n", *cgroupPath)
				}
			}
			return
		}
	}
}
