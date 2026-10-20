//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sockops.c

import (
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

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Target cgroup v2 path")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF TCP Sockops & Direct Socket-to-Socket Bypass (Cilium Mesh FastPath)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
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

	log.Printf("[INFO] Localhost socket bypass active! Zero-copy socket routing enabled.\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var k0, k1 uint32 = 0, 1
			var msgs, bytes uint64
			objs.BypassStats.Lookup(&k0, &msgs)
			objs.BypassStats.Lookup(&k1, &bytes)
			fmt.Printf("[%s] Accelerated TCP Messages: %-8d | Direct Bypassed Bytes: %-10d\n",
				time.Now().Format("15:04:05"), msgs, bytes)

		case <-stopper:
			fmt.Println("\n[INFO] Detaching sockops and sk_msg hooks...")
			return
		}
	}
}
