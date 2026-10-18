//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdplb xdp_lb.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcegress tc_egress.c

import (
	"encoding/binary"
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

func parseMac(macStr string) [6]uint8 {
	var macBytes [6]uint8
	hw, err := net.ParseMAC(macStr)
	if err != nil {
		log.Fatalf("Invalid MAC address %q: %v", macStr, err)
	}
	copy(macBytes[:], hw[:6])
	return macBytes
}

func parseIPv4(ipStr string) uint32 {
	parsed := net.ParseIP(ipStr).To4()
	if parsed == nil {
		log.Fatalf("Invalid IPv4 address: %s", ipStr)
	}
	// Return network byte order as uint32
	return binary.LittleEndian.Uint32(parsed)
}

func main() {
	ifaceName := flag.String("iface", "lo", "Target network interface")
	vipStr := flag.String("vip", "10.10.1.100", "Load Balancer Virtual IP (VIP)")
	lbMacStr := flag.String("lb-mac", "02:00:00:00:01:00", "Load Balancer MAC address")
	b0IPStr := flag.String("backend0-ip", "10.10.1.2", "Backend 0 IPv4 address")
	b0MacStr := flag.String("backend0-mac", "02:00:00:00:02:00", "Backend 0 MAC address")
	b1IPStr := flag.String("backend1-ip", "10.10.1.3", "Backend 1 IPv4 address")
	b1MacStr := flag.String("backend1-mac", "02:00:00:00:03:00", "Backend 1 MAC address")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Dual Pipeline: High-Speed XDP Load Balancer & TC Egress Marker")
	fmt.Println("======================================================================")

	// Remove memlock memory limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Resolve target network interface
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Interface %q not found: %v", *ifaceName, err)
	}

	// 1. Load and Attach XDP Load Balancer Objects
	var lbObjs xdplbObjects
	if err := loadXdplbObjects(&lbObjs, nil); err != nil {
		log.Fatalf("Failed to load XDP LB objects: %v", err)
	}
	defer lbObjs.Close()

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   lbObjs.XdpLoadBalancer,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP Load Balancer to %s: %v", iface.Name, err)
	}
	defer xdpLink.Close()
	log.Printf("[XDP] Attached Load Balancer program to %s (index %d)\n", iface.Name, iface.Index)

	// 2. Load and Attach TC Egress Classifier Objects
	var tcObjs tcegressObjects
	if err := loadTcegressObjects(&tcObjs, nil); err != nil {
		log.Fatalf("Failed to load TC Egress objects: %v", err)
	}
	defer tcObjs.Close()

	// Modern Linux Kernels (>= 6.6) support link.AttachTCX. If TCX is unsupported,
	// we inform the operator gracefully while maintaining monitoring.
	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   tcObjs.TcEgressProg,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[TC] Note: AttachTCX not available on this kernel (%v). Falling back to XDP-only or legacy TC mode.\n", err)
	} else {
		defer tcLink.Close()
		log.Printf("[TC] Attached Egress Classifier (TCX) to %s (index %d)\n", iface.Name, iface.Index)
	}

	// 3. Configure Load Balancer VIP & Identity
	var cfgKey uint32 = 0
	lbCfg := xdplbLbConfigT{
		Vip:   parseIPv4(*vipStr),
		LbMac: parseMac(*lbMacStr),
	}
	if err := lbObjs.LbConfig.Put(&cfgKey, &lbCfg); err != nil {
		log.Fatalf("Failed to write lb_config: %v", err)
	}

	// 4. Populate Backend Servers
	backends := []struct {
		ID  uint32
		IP  string
		MAC string
	}{
		{0, *b0IPStr, *b0MacStr},
		{1, *b1IPStr, *b1MacStr},
	}

	for _, b := range backends {
		bCfg := xdplbBackendConfig{
			Ip:  parseIPv4(b.IP),
			Mac: parseMac(b.MAC),
		}
		if err := lbObjs.Backends.Put(&b.ID, &bCfg); err != nil {
			log.Fatalf("Failed to populate backend %d: %v", b.ID, err)
		}
		log.Printf("[LB Config] Backend #%d registered: IP=%s MAC=%s\n", b.ID, b.IP, b.MAC)
	}

	log.Printf("[LB Config] VIP: %s (MAC: %s) active.\n\n", *vipStr, *lbMacStr)

	// 5. Signal handling & Real-time Metrics Dashboard
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			renderDashboard(&lbObjs, &tcObjs, iface.Name, *vipStr)

		case sig := <-stopper:
			fmt.Printf("\nReceived signal '%s'. Detaching XDP and TC hooks...\n", sig)
			renderDashboard(&lbObjs, &tcObjs, iface.Name, *vipStr)
			fmt.Println("Cleanup complete. Load Balancer and TC Egress stopped.")
			return
		}
	}
}

// renderDashboard displays live XDP forwarding counters and TC egress telemetry
func renderDashboard(lbObjs *xdplbObjects, tcObjs *tcegressObjects, iface, vip string) {
	fmt.Printf("\033[H\033[2J") // Clear terminal screen
	fmt.Println("=================================================================================")
	fmt.Printf(" eBPF XDP Load Balancer & TC Monitor | Interface: %s | Time: %s\n",
		iface, time.Now().Format("15:04:05"))
	fmt.Println("=================================================================================")

	// 1. Query XDP LB Stats
	var cfgKey uint32 = 0
	var stats xdplbLbStatsT
	if err := lbObjs.LbStats.Lookup(&cfgKey, &stats); err == nil {
		fmt.Printf(" [ VIP: %s (XDP_TX Hairpin Forwarding) ]\n", vip)
		fmt.Printf("  Total Ingress Packets:       %-12d\n", stats.RxPackets)
		fmt.Printf("  Forwarded to Backend #0:     %-12d\n", stats.ForwardedBackend0)
		fmt.Printf("  Forwarded to Backend #1:     %-12d\n", stats.ForwardedBackend1)
	} else {
		fmt.Printf(" [ VIP: %s ] Waiting for ingress traffic...\n", vip)
	}

	// 2. Query TC Egress Telemetry
	fmt.Println("\n [ TC Egress Port Telemetry (BPF_MAP_TYPE_HASH) ]")
	fmt.Printf("  %-16s  %-16s  %-16s\n", "DEST PORT", "PACKETS", "BYTES")
	fmt.Println("  ----------------------------------------------------")

	var dport uint16
	var estat tcegressEgressStat
	iter := tcObjs.EgressStats.Iterate()
	count := 0

	for iter.Next(&dport, &estat) {
		count++
		fmt.Printf("  Port %-11d  %-16d  %-16d\n", dport, estat.Packets, estat.Bytes)
	}

	if count == 0 {
		fmt.Println("  (No egress traffic observed on interface yet)")
	}

	fmt.Println("=================================================================================")
	fmt.Println(" Press Ctrl+C to terminate and detach hooks.")
}
