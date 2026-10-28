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
	// Keep the 4 bytes in network byte order in memory: reinterpret them in host
	// (native) byte order so the kernel sees exactly the bytes of iph->daddr.
	return binary.NativeEndian.Uint32(parsed)
}

func main() {
	ifaceName := flag.String("iface", "lo", "Target network interface")
	vipStr := flag.String("vip", "10.10.1.100", "Load Balancer Virtual IP (VIP)")
	lbMacStr := flag.String("lb-mac", "", "Load Balancer MAC address (default: MAC of -iface)")
	b0IPStr := flag.String("backend0-ip", "10.10.1.2", "Backend 0 IPv4 address")
	b0MacStr := flag.String("backend0-mac", "02:00:00:00:02:00", "Backend 0 MAC address")
	b1IPStr := flag.String("backend1-ip", "10.10.1.3", "Backend 1 IPv4 address")
	b1MacStr := flag.String("backend1-mac", "02:00:00:00:03:00", "Backend 1 MAC address")
	xdpMode := flag.String("xdp-mode", "auto", "XDP attach mode: auto | native | generic (use generic on veth labs)")
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

	// The LB MAC must be the real MAC of the interface, otherwise the switch/bridge
	// learns a wrong address for us. Default to the interface MAC.
	if *lbMacStr == "" {
		*lbMacStr = iface.HardwareAddr.String()
	}

	// 1. Load XDP Load Balancer + TC Reverse NAT Objects (they share the flows map)
	var lbObjs xdplbObjects
	if err := loadXdplbObjects(&lbObjs, nil); err != nil {
		log.Fatalf("Failed to load XDP LB objects: %v", err)
	}
	defer lbObjs.Close()

	// 2. Configure Load Balancer VIP & Identity (before attaching, so the very
	// first packet already sees a complete configuration)
	var cfgKey uint32 = 0
	lbCfg := xdplbLbConfigT{
		Vip:   parseIPv4(*vipStr),
		LbMac: parseMac(*lbMacStr),
	}
	if err := lbObjs.LbConfig.Put(&cfgKey, &lbCfg); err != nil {
		log.Fatalf("Failed to write lb_config: %v", err)
	}

	// 3. Populate Backend Servers
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

	log.Printf("[LB Config] VIP: %s (MAC: %s) active.\n", *vipStr, *lbMacStr)

	// 4. Attach TC Reverse NAT on TCX ingress (reply path: backend IP -> VIP).
	// Without it the LB has no return path: clients would receive SYN-ACKs from
	// the backend IP and answer with RST. TCX requires Linux >= 6.6, so we fail
	// loudly instead of running a half-working load balancer.
	rnatLink, err := link.AttachTCX(link.TCXOptions{
		Program:   lbObjs.TcReverseNat,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("[TC] Failed to attach reverse NAT via TCX ingress on %s: %v\n"+
			"       TCX needs Linux >= 6.6. On older kernels attach tc_reverse_nat with\n"+
			"       'tc qdisc add dev %s clsact' + 'tc filter add dev %s ingress bpf da obj ...'",
			iface.Name, err, iface.Name, iface.Name)
	}
	defer rnatLink.Close()
	log.Printf("[TC] Attached Reverse NAT (TCX ingress) to %s (index %d)\n", iface.Name, iface.Index)

	// 5. Attach XDP Load Balancer (forward path: VIP -> backend)
	// auto lets the kernel pick (native/driver mode if supported). On veth, native
	// XDP_TX hands the frame to the *peer* veth's NAPI ring, which only works if the
	// peer has an XDP program or GRO enabled; generic (SKB) mode avoids that.
	var xdpFlags link.XDPAttachFlags
	switch *xdpMode {
	case "auto":
	case "native":
		xdpFlags = link.XDPDriverMode
	case "generic":
		xdpFlags = link.XDPGenericMode
	default:
		log.Fatalf("Invalid -xdp-mode %q (want auto, native or generic)", *xdpMode)
	}
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   lbObjs.XdpLoadBalancer,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP Load Balancer to %s: %v", iface.Name, err)
	}
	defer xdpLink.Close()
	log.Printf("[XDP] Attached Load Balancer program to %s (index %d, mode %s)\n", iface.Name, iface.Index, *xdpMode)

	// 6. Load and Attach TC Egress Classifier Objects (optional telemetry)
	var tcObjs tcegressObjects
	if err := loadTcegressObjects(&tcObjs, nil); err != nil {
		log.Fatalf("Failed to load TC Egress objects: %v", err)
	}
	defer tcObjs.Close()

	// The egress marker is only telemetry/QoS, so a failure here is not fatal:
	// we say clearly that it is disabled and keep load balancing.
	egressEnabled := false
	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   tcObjs.TcEgressProg,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[TC] WARNING: TCX egress attach failed (%v). Egress telemetry/QoS marking DISABLED; load balancing continues.\n", err)
	} else {
		defer tcLink.Close()
		egressEnabled = true
		log.Printf("[TC] Attached Egress Classifier (TCX) to %s (index %d)\n\n", iface.Name, iface.Index)
	}

	// 7. Signal handling & Real-time Metrics Dashboard
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			renderDashboard(&lbObjs, &tcObjs, egressEnabled, iface.Name, *vipStr)

		case sig := <-stopper:
			fmt.Printf("\nReceived signal '%s'. Detaching XDP and TC hooks...\n", sig)
			renderDashboard(&lbObjs, &tcObjs, egressEnabled, iface.Name, *vipStr)
			fmt.Println("Cleanup complete. Load Balancer and TC Egress stopped.")
			return
		}
	}
}

// renderDashboard displays live XDP forwarding counters and TC egress telemetry
func renderDashboard(lbObjs *xdplbObjects, tcObjs *tcegressObjects, egressEnabled bool, iface, vip string) {
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
		fmt.Printf("  Replies SNAT'd to VIP (TC):  %-12d\n", stats.ReverseNatPackets)
		fmt.Printf("  Tracked Flows (LRU):         %-12d\n", countFlows(lbObjs))
	} else {
		fmt.Printf(" [ VIP: %s ] Waiting for ingress traffic...\n", vip)
	}

	// 2. Query TC Egress Telemetry
	fmt.Println("\n [ TC Egress Port Telemetry (BPF_MAP_TYPE_HASH) ]")
	if !egressEnabled {
		fmt.Println("  (TC egress program not attached - telemetry disabled)")
	}
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

// countFlows returns the number of entries currently in the flows LRU map
func countFlows(lbObjs *xdplbObjects) int {
	var key xdplbFlowKey
	var val xdplbFlowValue
	n := 0
	iter := lbObjs.Flows.Iterate()
	for iter.Next(&key, &val) {
		n++
	}
	return n
}
