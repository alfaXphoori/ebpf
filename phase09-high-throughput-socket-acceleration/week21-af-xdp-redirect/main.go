//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf xsk_kern.c

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifaceName := flag.String("iface", "lo", "Target network interface to attach AF_XDP pipeline")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF AF_XDP Wire-Speed Packet Pipeline (BPF_MAP_TYPE_XSKMAP)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", *ifaceName, err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XskRedirectProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to %s: %v", *ifaceName, err)
	}
	defer xdpLink.Close()

	log.Printf("[INFO] Attached AF_XDP redirect program to %s [Index: %d]!\n", *ifaceName, iface.Index)
	log.Printf("[INFO] Monitoring XSK pipeline telemetry... (Press Ctrl+C to stop)\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var k0, k1 uint32 = 0, 1
			var redir, pass uint64
			objs.XskStats.Lookup(&k0, &redir)
			objs.XskStats.Lookup(&k1, &pass)
			fmt.Printf("[%s] XSK Redirects: %-8d | Fallback Passed Packets: %-8d\n",
				time.Now().Format("15:04:05"), redir, pass)

		case <-stopper:
			fmt.Println("\n[INFO] Detaching XDP link and exiting cleanly...")
			var k0, k1 uint32 = 0, 1
			var redir, pass uint64
			objs.XskStats.Lookup(&k0, &redir)
			objs.XskStats.Lookup(&k1, &pass)
			fmt.Printf("Final Summary -> Redirects: %d, Passed: %d\n", redir, pass)
			return
		}
	}
}
