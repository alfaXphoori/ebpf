//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf xsk_kern.c

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Index layout of xsk_stats (must match the enum in xsk_kern.c)
const (
	statRedirected uint32 = iota
	statPassed
	statNoXSK
)

func readStat(m *ebpf.Map, idx uint32) uint64 {
	var v uint64
	if err := m.Lookup(&idx, &v); err != nil {
		return 0
	}
	return v
}

// describePacket parses Ethernet -> IPv4 -> UDP inside the UMEM frame
func describePacket(pkt []byte) string {
	if len(pkt) < 14 {
		return fmt.Sprintf("short frame (%d B)", len(pkt))
	}
	if binary.BigEndian.Uint16(pkt[12:14]) != 0x0800 {
		return fmt.Sprintf("ethertype %#04x", binary.BigEndian.Uint16(pkt[12:14]))
	}
	ip := pkt[14:]
	if len(ip) < 20 {
		return "truncated IPv4 header"
	}
	ihl := int(ip[0]&0x0f) * 4
	src, dst := net.IP(ip[12:16]), net.IP(ip[16:20])
	if ip[9] != 17 || len(ip) < ihl+8 {
		return fmt.Sprintf("%s -> %s proto=%d", src, dst, ip[9])
	}
	udp := ip[ihl:]
	payload := udp[8:]
	if len(payload) > 32 {
		payload = payload[:32]
	}
	return fmt.Sprintf("%s:%d -> %s:%d UDP payload=%s", src, binary.BigEndian.Uint16(udp[0:2]),
		dst, binary.BigEndian.Uint16(udp[2:4]), strconv.Quote(string(payload)))
}

func main() {
	ifaceName := flag.String("iface", "w21-xsk0", "Interface to attach XDP + AF_XDP to (use a veth inside a test netns)")
	queueID := flag.Int("queue", 0, "NIC RX queue to bind the AF_XDP socket to")
	zeroCopy := flag.Bool("zerocopy", false, "Bind with XDP_ZEROCOPY (fails unless the driver supports it)")
	printMax := flag.Int("print", 10, "Print details of the first N received packets")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF AF_XDP Packet Pipeline (XDP -> BPF_MAP_TYPE_XSKMAP -> UMEM)")
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

	// 1. XDP program: decides per packet XDP_REDIRECT (to the socket) or XDP_PASS
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XskRedirectProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to %s: %v", *ifaceName, err)
	}
	defer xdpLink.Close()
	log.Printf("[INFO] Attached XDP program to %s [Index: %d]\n", *ifaceName, iface.Index)

	// 2. AF_XDP socket: UMEM + FILL/COMPLETION/RX rings, bound to (ifindex, queue)
	cfg := DefaultXSKConfig
	cfg.ZeroCopy = *zeroCopy
	xsk, err := NewXSK(iface.Index, *queueID, cfg)
	if err != nil {
		log.Fatalf("Failed to create AF_XDP socket: %v", err)
	}
	defer xsk.Close()

	zc, _ := xsk.IsZeroCopy()
	mode := "XDP_COPY (copy mode: kernel memcpy()s each packet into UMEM)"
	if zc {
		mode = "XDP_ZEROCOPY (driver DMAs straight into UMEM)"
	}
	log.Printf("[INFO] AF_XDP socket fd=%d bound to %s queue %d | UMEM %d x %d B | mode: %s\n",
		xsk.FD(), *ifaceName, *queueID, cfg.NumFrames, cfg.FrameSize, mode)

	// 3. Publish the socket in the XSKMAP: key = queue id, value = socket fd
	key, fd := uint32(*queueID), uint32(xsk.FD())
	if err := objs.XsksMap.Put(&key, &fd); err != nil {
		log.Fatalf("Failed to insert socket into xsks_map: %v", err)
	}
	log.Printf("[INFO] xsks_map[%d] = fd %d -> IPv4/UDP on this queue now bypasses the kernel stack\n\n", key, fd)

	// 4. RX loop in its own goroutine: poll() -> drain RX ring -> refill FILL ring
	var rxPackets, rxBytes atomic.Uint64
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			ready, err := xsk.Poll(200)
			if err != nil {
				log.Printf("[ERROR] poll: %v", err)
				return
			}
			if !ready {
				continue
			}
			xsk.Receive(func(pkt []byte) {
				n := rxPackets.Add(1)
				rxBytes.Add(uint64(len(pkt)))
				if int(n) <= *printMax {
					fmt.Printf("[RX #%d] q=%d len=%-4d %s\n", n, *queueID, len(pkt), describePacket(pkt))
				}
			})
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	printStats := func() {
		st, _ := xsk.Stats()
		fmt.Printf("[%s] XDP: redirected=%-8d passed=%-6d no_xsk=%-4d | AF_XDP RX: %-8d pkts %-10d B | rx_dropped=%d ring_full=%d fill_empty=%d\n",
			time.Now().Format("15:04:05"),
			readStat(objs.XskStats, statRedirected),
			readStat(objs.XskStats, statPassed),
			readStat(objs.XskStats, statNoXSK),
			rxPackets.Load(), rxBytes.Load(),
			st.Rx_dropped, st.Rx_ring_full, st.Rx_fill_ring_empty_descs)
	}

	for {
		select {
		case <-ticker.C:
			printStats()

		case <-stopper:
			fmt.Println("\n[INFO] Stopping RX loop, removing socket from xsks_map and detaching XDP...")
			stop.Store(true)
			<-done
			objs.XsksMap.Delete(&key)
			printStats()
			return
		}
	}
}
