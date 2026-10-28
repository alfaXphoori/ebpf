//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf xdp_firewall.c

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// ipKey converts an IPv4 address into the __u32 map key used by blocked_ips.
// The kernel compares the 4 raw bytes of iph->saddr (network byte order), so we
// reinterpret the same 4 bytes in host (native) byte order. On little-endian
// x86_64/arm64 this equals binary.LittleEndian.Uint32(ip).
func ipKey(ip net.IP) uint32 {
	return binary.NativeEndian.Uint32(ip.To4())
}

func main() {
	ifaceName := flag.String("iface", "lo", "Target network interface to attach XDP (e.g., lo, eth0, veth1)")
	blockIPsList := flag.String("block-ip", "", "Comma-separated IPv4 addresses to drop (e.g., 10.10.1.1,192.168.1.100)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF High-Speed XDP Firewall & Packet Parser")
	fmt.Println("======================================================================")

	// Remove memlock memory limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Resolve the specified network interface
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Could not find network interface %q: %v", *ifaceName, err)
	}

	// Load BPF objects
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach XDP program to network interface
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewallProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program to %s (index %d): %v", iface.Name, iface.Index, err)
	}
	defer xdpLink.Close()

	log.Printf("Successfully attached XDP filter to %s [Index: %d]\n", iface.Name, iface.Index)

	// Populate the blocked_ips map if provided
	if *blockIPsList != "" {
		for _, rawIP := range strings.Split(*blockIPsList, ",") {
			trimmed := strings.TrimSpace(rawIP)
			if trimmed == "" {
				continue
			}
			parsedIP := net.ParseIP(trimmed).To4()
			if parsedIP == nil {
				log.Fatalf("Invalid IPv4 address provided: %s", trimmed)
			}

			// iph->saddr is read from packet memory as raw bytes, so the map key must
			// have the same in-memory byte layout (see ipKey above).
			key := ipKey(parsedIP)
			initialStats := bpfDropStats{
				DroppedPackets: 0,
				DroppedBytes:   0,
			}
			if err := objs.BlockedIps.Put(&key, &initialStats); err != nil {
				log.Fatalf("Failed to populate blocked_ips for %s: %v", trimmed, err)
			}
			log.Printf("Added %s (Key: 0x%08x) to XDP blocklist map\n", trimmed, key)
		}
	} else {
		log.Printf("No -block-ip specified. Running in promiscuous monitoring mode.\n")
	}

	// Setup signal interception
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	possibleCPUs := ebpf.MustPossibleCPU()

	for {
		select {
		case <-ticker.C:
			renderDashboard(&objs, iface.Name, possibleCPUs)

		case sig := <-stopper:
			fmt.Printf("\nReceived signal '%s'. Detaching XDP link and exiting cleanly...\n", sig)
			renderDashboard(&objs, iface.Name, possibleCPUs)
			return
		}
	}
}

// renderDashboard prints live protocol statistics and dropped packet metrics
func renderDashboard(objs *bpfObjects, iface string, numCPUs int) {
	fmt.Printf("\033[H\033[2J") // Clear terminal screen
	fmt.Println("=================================================================================")
	fmt.Printf(" eBPF XDP Live Monitor | Interface: %-10s | Host CPUs: %d | Time: %s\n",
		iface, numCPUs, time.Now().Format("15:04:05"))
	fmt.Println("=================================================================================")

	// Query Per-CPU Protocol Counters
	protocols := []struct {
		Name string
		Num  uint32
	}{
		{"ICMP", 1},
		{"TCP", 6},
		{"UDP", 17},
	}

	fmt.Println(" [ Protocol Activity (Per-CPU Array Sum) ]")
	fmt.Printf("  %-10s  %-12s  %-16s\n", "PROTOCOL", "CODE", "TOTAL PACKETS")
	fmt.Println("  ---------------------------------------------")

	for _, p := range protocols {
		var perCpuCounts []uint64 = make([]uint64, numCPUs)
		if err := objs.ProtoCounters.Lookup(&p.Num, &perCpuCounts); err != nil {
			fmt.Printf("  %-10s  %-12d  <lookup error>\n", p.Name, p.Num)
			continue
		}

		var totalPkts uint64
		for _, cnt := range perCpuCounts {
			totalPkts += cnt
		}
		fmt.Printf("  %-10s  %-12d  %-16d\n", p.Name, p.Num, totalPkts)
	}

	fmt.Println("\n [ Blocked IP Drop Telemetry (BPF_MAP_TYPE_HASH) ]")
	fmt.Printf("  %-18s  %-16s  %-16s\n", "IP ADDRESS", "DROPPED PACKETS", "DROPPED BYTES")
	fmt.Println("  -------------------------------------------------------------")

	var key uint32
	var stat bpfDropStats
	iter := objs.BlockedIps.Iterate()
	countBlocked := 0

	for iter.Next(&key, &stat) {
		countBlocked++
		// Reconstruct IPv4 address from uint32
		ipBytes := make([]byte, 4)
		binary.NativeEndian.PutUint32(ipBytes, key)
		ipStr := net.IP(ipBytes).String()

		fmt.Printf("  %-18s  %-16d  %-16d\n", ipStr, stat.DroppedPackets, stat.DroppedBytes)
	}

	if countBlocked == 0 {
		fmt.Println("  (No blocked IPs currently configured in map)")
	}

	fmt.Println("=================================================================================")
	fmt.Println(" Press Ctrl+C to detach XDP program and exit.")
}
