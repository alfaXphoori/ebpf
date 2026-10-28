//go:build linux
// +build linux

package main

// Unit tests for xdp_firewall.c using BPF_PROG_TEST_RUN.
//
// BPF_PROG_TEST_RUN lets the kernel execute an eBPF program against a
// hand-crafted packet buffer, without attaching it to any interface.
// We get back the XDP verdict (XDP_PASS / XDP_DROP / ...) and can inspect maps.
//
// Run with: make test   (equivalent to: go test -exec sudo -v ./...)

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// XDP return codes from <linux/bpf.h>
const (
	xdpAborted = 0
	xdpDrop    = 1
	xdpPass    = 2
	xdpTx      = 3
)

const (
	ethPIPv4 = 0x0800
	ethPIPv6 = 0x86DD
	ethPARP  = 0x0806

	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// ------------------------------------------------------------------------------
// Packet builders (Ethernet / IPv4 / L4) - no external dependencies
// ------------------------------------------------------------------------------

// ethHeader builds a 14-byte Ethernet II header.
func ethHeader(ethType uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], []byte{0x02, 0, 0, 0, 0, 0x20})  // dst MAC
	copy(b[6:12], []byte{0x02, 0, 0, 0, 0, 0x10}) // src MAC
	binary.BigEndian.PutUint16(b[12:14], ethType)
	return b
}

// csum16 computes the Internet checksum (RFC 1071) over b.
func csum16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ipv4Header builds a 20-byte IPv4 header (IHL=5) with a valid header checksum.
func ipv4Header(src, dst string, proto uint8, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(h[2:4], uint16(20+payloadLen))
	h[8] = 64 // TTL
	h[9] = proto
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(h[10:12], csum16(h))
	return h
}

// icmpEcho builds an 8-byte ICMP echo request header plus payload.
func icmpEcho(payload int) []byte {
	b := make([]byte, 8+payload)
	b[0] = 8 // echo request
	binary.BigEndian.PutUint16(b[2:4], csum16(b))
	return b
}

// tcpSyn builds a 20-byte TCP SYN header (checksum not needed by the firewall).
func tcpSyn(sport, dport uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	b[12] = 5 << 4 // data offset = 5 words
	b[13] = 0x02   // SYN
	return b
}

// udpHeader builds an 8-byte UDP header.
func udpHeader(sport, dport uint16, payload int) []byte {
	b := make([]byte, 8+payload)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+payload))
	return b
}

// ipv4Packet assembles Ethernet + IPv4 + L4 bytes.
func ipv4Packet(src, dst string, proto uint8, l4 []byte) []byte {
	pkt := ethHeader(ethPIPv4)
	pkt = append(pkt, ipv4Header(src, dst, proto, len(l4))...)
	return append(pkt, l4...)
}

// ------------------------------------------------------------------------------
// Test fixture
// ------------------------------------------------------------------------------

const (
	blockedIP = "10.10.1.10"
	allowedIP = "10.10.1.11"
	serverIP  = "10.10.1.20"
)

func loadTestObjects(t *testing.T) *bpfObjects {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("BPF_PROG_TEST_RUN requires root (run: make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load eBPF objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })

	key := ipKey(net.ParseIP(blockedIP))
	if err := objs.BlockedIps.Put(&key, &bpfDropStats{}); err != nil {
		t.Fatalf("populate blocked_ips: %v", err)
	}
	return &objs
}

// runXDP executes the XDP program once on pkt and returns the verdict.
func runXDP(t *testing.T, prog *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret
}

func verdictName(v uint32) string {
	switch v {
	case xdpAborted:
		return "XDP_ABORTED"
	case xdpDrop:
		return "XDP_DROP"
	case xdpPass:
		return "XDP_PASS"
	case xdpTx:
		return "XDP_TX"
	}
	return "UNKNOWN"
}

// ------------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------------

func TestFirewallVerdicts(t *testing.T) {
	objs := loadTestObjects(t)

	// Truncated TCP header: IPv4 says TCP but only 4 bytes of L4 follow
	truncTCP := ipv4Packet(blockedIP, serverIP, protoTCP, []byte{0x30, 0x39, 0x00, 0x50})

	// IPv4 header with an invalid IHL (< 5 words)
	badIHL := ipv4Packet(allowedIP, serverIP, protoICMP, icmpEcho(8))
	badIHL[14] = 0x43

	// IPv4 header with IHL=15 (60 bytes) but the packet is shorter than that
	longIHL := ipv4Packet(blockedIP, serverIP, protoICMP, icmpEcho(0))
	longIHL[14] = 0x4f

	// Non-first IP fragment (offset 185*8 bytes): carries payload only, no L4 header
	frag := ipv4Packet(blockedIP, serverIP, protoICMP, []byte{0xde, 0xad, 0xbe, 0xef})
	binary.BigEndian.PutUint16(frag[14+6:14+8], 185)

	// Minimal IPv6 header (40 bytes) + ICMPv6 echo request
	ipv6 := ethHeader(ethPIPv6)
	v6hdr := make([]byte, 40)
	v6hdr[0] = 0x60
	binary.BigEndian.PutUint16(v6hdr[4:6], 8)
	v6hdr[6] = 58 // ICMPv6
	v6hdr[7] = 64
	copy(v6hdr[8:24], net.ParseIP("fd00::10"))
	copy(v6hdr[24:40], net.ParseIP("fd00::20"))
	ipv6 = append(ipv6, v6hdr...)
	ipv6 = append(ipv6, 128, 0, 0, 0, 0, 0, 0, 0)

	// ARP request (28-byte payload)
	arp := append(ethHeader(ethPARP), make([]byte, 28)...)

	cases := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"icmp from blocked ip is dropped", ipv4Packet(blockedIP, serverIP, protoICMP, icmpEcho(56)), xdpDrop},
		{"tcp from blocked ip is dropped", ipv4Packet(blockedIP, serverIP, protoTCP, tcpSyn(40000, 80)), xdpDrop},
		{"udp from blocked ip is dropped", ipv4Packet(blockedIP, serverIP, protoUDP, udpHeader(5353, 53, 16)), xdpDrop},
		{"icmp from allowed ip passes", ipv4Packet(allowedIP, serverIP, protoICMP, icmpEcho(56)), xdpPass},
		{"tcp from allowed ip passes", ipv4Packet(allowedIP, serverIP, protoTCP, tcpSyn(40000, 80)), xdpPass},
		{"udp from allowed ip passes", ipv4Packet(allowedIP, serverIP, protoUDP, udpHeader(5353, 53, 16)), xdpPass},
		{"blocked ip as destination passes", ipv4Packet(serverIP, blockedIP, protoICMP, icmpEcho(56)), xdpPass},
		{"blocked ip with truncated tcp header is still dropped", truncTCP, xdpDrop},
		{"blocked ip with ihl beyond packet end is still dropped", longIHL, xdpDrop},
		{"non-first fragment from blocked ip is dropped", frag, xdpDrop},
		{"ethernet-only frame (truncated ipv4) passes", ethHeader(ethPIPv4), xdpPass},
		{"ipv4 with ihl < 5 passes to kernel", badIHL, xdpPass},
		{"ipv6 passes untouched", ipv6, xdpPass},
		{"arp passes untouched", arp, xdpPass},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runXDP(t, objs.XdpFirewallProg, tc.pkt); got != tc.want {
				t.Fatalf("verdict = %s, want %s", verdictName(got), verdictName(tc.want))
			}
		})
	}
}

func TestDropStatsCounters(t *testing.T) {
	objs := loadTestObjects(t)

	pkt := ipv4Packet(blockedIP, serverIP, protoICMP, icmpEcho(56)) // 14 + 20 + 64 = 98 bytes
	const n = 5
	for i := 0; i < n; i++ {
		if got := runXDP(t, objs.XdpFirewallProg, pkt); got != xdpDrop {
			t.Fatalf("run %d: verdict = %s, want XDP_DROP", i, verdictName(got))
		}
	}

	key := ipKey(net.ParseIP(blockedIP))
	var stats bpfDropStats
	if err := objs.BlockedIps.Lookup(&key, &stats); err != nil {
		t.Fatalf("lookup blocked_ips: %v", err)
	}
	if stats.DroppedPackets != n {
		t.Errorf("dropped_packets = %d, want %d", stats.DroppedPackets, n)
	}
	if want := uint64(n * len(pkt)); stats.DroppedBytes != want {
		t.Errorf("dropped_bytes = %d, want %d", stats.DroppedBytes, want)
	}
}

func TestProtoCounters(t *testing.T) {
	objs := loadTestObjects(t)

	runXDP(t, objs.XdpFirewallProg, ipv4Packet(allowedIP, serverIP, protoICMP, icmpEcho(8)))
	runXDP(t, objs.XdpFirewallProg, ipv4Packet(allowedIP, serverIP, protoTCP, tcpSyn(1234, 80)))
	runXDP(t, objs.XdpFirewallProg, ipv4Packet(allowedIP, serverIP, protoTCP, tcpSyn(1235, 80)))
	runXDP(t, objs.XdpFirewallProg, ipv4Packet(blockedIP, serverIP, protoUDP, udpHeader(53, 53, 0)))

	numCPUs := ebpf.MustPossibleCPU()
	sum := func(proto uint32) uint64 {
		perCPU := make([]uint64, numCPUs)
		if err := objs.ProtoCounters.Lookup(&proto, &perCPU); err != nil {
			t.Fatalf("lookup proto_counters[%d]: %v", proto, err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total
	}

	// Dropped packets are counted too: the counter runs before the blocklist check.
	for proto, want := range map[uint32]uint64{protoICMP: 1, protoTCP: 2, protoUDP: 1} {
		if got := sum(proto); got != want {
			t.Errorf("proto_counters[%d] = %d, want %d", proto, got, want)
		}
	}
}
