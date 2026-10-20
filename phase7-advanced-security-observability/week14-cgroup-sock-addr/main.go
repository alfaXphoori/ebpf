//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sock_enforce.c

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Target cgroup v2 path to attach egress policy")
	blockPort := flag.Int("block-port", 2323, "Destination TCP port to block at socket layer (e.g. 23, 2323)")
	blockIPStr := flag.String("block-ip", "10.99.99.99", "Destination IPv4 address to block")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Zero-Trust Socket Egress Enforcer (cgroup/connect4)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Register blocked port
	port := uint16(*blockPort)
	var initVal uint64 = 0
	if err := objs.BlockedPorts.Put(&port, &initVal); err != nil {
		log.Fatalf("Failed to add port %d to blocklist: %v", port, err)
	}
	log.Printf("[POLICY] Blocked destination port: %d (TCP)\n", port)

	// Register blocked IP
	if *blockIPStr != "" {
		ip := net.ParseIP(*blockIPStr).To4()
		if ip != nil {
			ipUint := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
			if err := objs.BlockedIps.Put(&ipUint, &initVal); err != nil {
				log.Fatalf("Failed to add IP %s to blocklist: %v", *blockIPStr, err)
			}
			log.Printf("[POLICY] Blocked destination IPv4: %s\n", *blockIPStr)
		}
	}

	// Attach to cgroup
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4Connect,
	})
	if err != nil {
		log.Fatalf("Failed to attach to cgroup %s: %v", *cgroupPath, err)
	}
	defer cgroupLink.Close()

	log.Printf("[INFO] Successfully attached to cgroup %s!\n", *cgroupPath)
	log.Printf("[INFO] Zero-overhead socket filter active. (Press Ctrl+C to stop)\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var portDrops uint64
			if err := objs.BlockedPorts.Lookup(&port, &portDrops); err == nil {
				fmt.Printf("[%s] Blocked Port %d attempts: %-6d\n",
					time.Now().Format("15:04:05"), port, portDrops)
			}
		case <-stopper:
			fmt.Println("\n[INFO] Detaching from cgroup and stopping...")
			var portDrops uint64
			objs.BlockedPorts.Lookup(&port, &portDrops)
			fmt.Printf("Final drops on Port %d: %d\n", port, portDrops)
			return
		}
	}
}
