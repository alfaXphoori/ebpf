//go:build linux
// +build linux

package main

// Unit tests for xdp_lb.c (XDP forward path + TC reverse NAT) and tc_egress.c
// using BPF_PROG_TEST_RUN: the kernel runs each program on a hand-crafted packet
// and returns the verdict plus the (possibly rewritten) output packet.
//
// Run with: make test   (equivalent to: go test -exec sudo -v ./...)

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Return codes from <linux/bpf.h> and <linux/pkt_cls.h>
const (
	xdpDrop = 1
	xdpPass = 2
	xdpTx   = 3

	tcActOK = 0
)

const (
	ethPIPv4 = 0x0800
	ethPIPv6 = 0x86DD

	protoTCP = 6
	protoUDP = 17
)

// Lab topology used by the tests (same addresses as the README lab)
const (
	vip       = "10.10.1.100"
	clientIP  = "10.10.2.10"
	backend0  = "10.10.1.2"
	backend1  = "10.10.1.3"
	otherIP   = "10.10.1.50"
	svcPort   = 80
	clientMAC = "02:00:00:00:10:00"
	lbMAC     = "02:00:00:00:01:00"
	b0MAC     = "02:00:00:00:02:00"
	b1MAC     = "02:00:00:00:03:00"
)

// ------------------------------------------------------------------------------
// Packet builders and checksum helpers
// ------------------------------------------------------------------------------

func mustMAC(s string) []byte {
	hw, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return hw
}

func ethHeader(dst, src string, ethType uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], mustMAC(dst))
	copy(b[6:12], mustMAC(src))
	binary.BigEndian.PutUint16(b[12:14], ethType)
	return b
}

// csumAdd folds b into a running 32-bit one's complement sum (RFC 1071).
func csumAdd(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func csumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pseudoHeader builds the IPv4 pseudo-header used by the TCP/UDP checksum.
func pseudoHeader(src, dst []byte, proto uint8, l4Len int) []byte {
	p := make([]byte, 12)
	copy(p[0:4], src)
	copy(p[4:8], dst)
	p[9] = proto
	binary.BigEndian.PutUint16(p[10:12], uint16(l4Len))
	return p
}

// tcpSegment builds a TCP header (20 bytes) + payload with a valid checksum.
func tcpSegment(src, dst string, sport, dport uint16, flags uint8, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[4:8], 0x01020304) // seq
	b[12] = 5 << 4                                 // data offset
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], 64240) // window
	copy(b[20:], payload)
	sum := csumAdd(0, pseudoHeader(net.ParseIP(src).To4(), net.ParseIP(dst).To4(), protoTCP, len(b)))
	binary.BigEndian.PutUint16(b[16:18], csumFold(csumAdd(sum, b)))
	return b
}

// ipv4Header builds an IPv4 header with optional options (len must be multiple of 4).
func ipv4Header(src, dst string, proto uint8, payloadLen int, options []byte) []byte {
	hl := 20 + len(options)
	h := make([]byte, hl)
	h[0] = 0x40 | uint8(hl/4)
	binary.BigEndian.PutUint16(h[2:4], uint16(hl+payloadLen))
	binary.BigEndian.PutUint16(h[4:6], 0x1234) // id
	h[8] = 64
	h[9] = proto
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:20], net.ParseIP(dst).To4())
	copy(h[20:], options)
	binary.BigEndian.PutUint16(h[10:12], csumFold(csumAdd(0, h)))
	return h
}

func tcpPacket(dstMAC, srcMAC, src, dst string, sport, dport uint16, flags uint8, payload []byte) []byte {
	seg := tcpSegment(src, dst, sport, dport, flags, payload)
	pkt := ethHeader(dstMAC, srcMAC, ethPIPv4)
	pkt = append(pkt, ipv4Header(src, dst, protoTCP, len(seg), nil)...)
	return append(pkt, seg...)
}

const (
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpPSHACK = 0x18
)

// checkIPv4Checksums verifies both the IPv4 header checksum and the TCP checksum
// of an Ethernet frame by recomputing them from scratch.
func checkIPv4Checksums(t *testing.T, pkt []byte) {
	t.Helper()
	ip := pkt[14:]
	hl := int(ip[0]&0x0f) * 4
	if got := csumFold(csumAdd(0, ip[:hl])); got != 0 {
		t.Errorf("IPv4 header checksum invalid (residual 0x%04x)", got)
	}
	totLen := int(binary.BigEndian.Uint16(ip[2:4]))
	l4 := ip[hl:totLen]
	sum := csumAdd(0, pseudoHeader(ip[12:16], ip[16:20], ip[9], len(l4)))
	if got := csumFold(csumAdd(sum, l4)); got != 0 {
		t.Errorf("TCP checksum invalid (residual 0x%04x)", got)
	}
}

func ip4(pkt []byte, off int) string { return net.IP(pkt[off : off+4]).String() }

// ------------------------------------------------------------------------------
// Test fixtures
// ------------------------------------------------------------------------------

func skipIfNotRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("BPF_PROG_TEST_RUN requires root (run: make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
}

// loadLB loads xdp_lb.c and configures the VIP and both backends.
func loadLB(t *testing.T) *xdplbObjects {
	t.Helper()
	skipIfNotRoot(t)

	var objs xdplbObjects
	if err := loadXdplbObjects(&objs, nil); err != nil {
		t.Fatalf("load xdplb objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })

	var key uint32
	cfg := xdplbLbConfigT{Vip: parseIPv4(vip), LbMac: parseMac(lbMAC)}
	if err := objs.LbConfig.Put(&key, &cfg); err != nil {
		t.Fatalf("put lb_config: %v", err)
	}
	for id, b := range []struct{ ip, mac string }{{backend0, b0MAC}, {backend1, b1MAC}} {
		k := uint32(id)
		v := xdplbBackendConfig{Ip: parseIPv4(b.ip), Mac: parseMac(b.mac)}
		if err := objs.Backends.Put(&k, &v); err != nil {
			t.Fatalf("put backend %d: %v", id, err)
		}
	}
	return &objs
}

// run executes prog once on pkt and returns (verdict, output packet).
func run(t *testing.T, prog *ebpf.Program, pkt []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(pkt)+256)
	opts := ebpf.RunOptions{Data: pkt, DataOut: out}
	ret, err := prog.Run(&opts)
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret, out[:len(opts.DataOut)]
}

func lbStats(t *testing.T, objs *xdplbObjects) xdplbLbStatsT {
	t.Helper()
	var key uint32
	var st xdplbLbStatsT
	if err := objs.LbStats.Lookup(&key, &st); err != nil {
		t.Fatalf("lookup lb_stats: %v", err)
	}
	return st
}

// ------------------------------------------------------------------------------
// XDP forward path
// ------------------------------------------------------------------------------

// flowHash mirrors flow_hash() in xdp_lb.c. Arguments are the raw __be32/__be16
// header fields as the BPF program loads them (native-endian view of the bytes).
func flowHash(saddr uint32, sport, dport uint16) uint32 {
	h := saddr ^ (uint32(sport)<<16 | uint32(dport))
	h ^= h >> 16
	h *= 0x7feb352d
	h ^= h >> 15
	h *= 0x846ca68b
	h ^= h >> 16
	return h
}

// expectedBackend returns the backend index the BPF program must pick.
func expectedBackend(client string, sport, dport uint16) int {
	return int(flowHash(parseIPv4(client), htons(sport), htons(dport)) % 2)
}

// findPort returns the first source port >= start that hashes to backend id.
func findPort(start uint16, id int) uint16 {
	for p := start; ; p++ {
		if expectedBackend(clientIP, p, svcPort) == id {
			return p
		}
	}
}

func TestXDPForwardRewritesToBackend(t *testing.T) {
	objs := loadLB(t)

	cases := []struct {
		name    string
		sport   uint16
		wantIP  string
		wantMAC string
		payload []byte
	}{
		{"flow hashed to backend 0", findPort(40000, 0), backend0, b0MAC, nil},
		{"flow hashed to backend 1", findPort(40000, 1), backend1, b1MAC, nil},
		{"data segment keeps valid checksum", findPort(41000, 0), backend0, b0MAC, []byte("GET / HTTP/1.1\r\n\r\n")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags := uint8(tcpSYN)
			if tc.payload != nil {
				flags = tcpPSHACK
			}
			in := tcpPacket(lbMAC, clientMAC, clientIP, vip, tc.sport, svcPort, flags, tc.payload)
			ret, out := run(t, objs.XdpLoadBalancer, in)
			if ret != xdpTx {
				t.Fatalf("verdict = %d, want XDP_TX (%d)", ret, xdpTx)
			}
			if !bytes.Equal(out[0:6], mustMAC(tc.wantMAC)) {
				t.Errorf("dst MAC = %s, want %s", net.HardwareAddr(out[0:6]), tc.wantMAC)
			}
			if !bytes.Equal(out[6:12], mustMAC(lbMAC)) {
				t.Errorf("src MAC = %s, want %s", net.HardwareAddr(out[6:12]), lbMAC)
			}
			if got := ip4(out, 14+16); got != tc.wantIP {
				t.Errorf("dst IP = %s, want %s", got, tc.wantIP)
			}
			if got := ip4(out, 14+12); got != clientIP {
				t.Errorf("src IP = %s, want %s (must be preserved)", got, clientIP)
			}
			checkIPv4Checksums(t, out)

			// Flow must be recorded for the TC reverse path
			fk := xdplbFlowKey{
				ClientIp:    parseIPv4(clientIP),
				BackendIp:   parseIPv4(tc.wantIP),
				ClientPort:  htons(tc.sport),
				ServicePort: htons(svcPort),
			}
			var fv xdplbFlowValue
			if err := objs.Flows.Lookup(&fk, &fv); err != nil {
				t.Fatalf("flow not recorded: %v", err)
			}
			if fv.Vip != parseIPv4(vip) {
				t.Errorf("flow vip = 0x%08x, want 0x%08x", fv.Vip, parseIPv4(vip))
			}
		})
	}

	st := lbStats(t, objs)
	if st.RxPackets != 3 || st.ForwardedBackend0 != 2 || st.ForwardedBackend1 != 1 {
		t.Errorf("lb_stats = %+v, want rx=3 b0=2 b1=1", st)
	}
}

// Linux connect() prefers even ephemeral ports. A "sport % 2" selector would send
// all of these flows to backend 0; the flow hash must spread them across both.
func TestXDPEvenPortsAreBalanced(t *testing.T) {
	objs := loadLB(t)

	const flows = 1000
	for i := 0; i < flows; i++ {
		sport := uint16(32768 + 2*i) // even ports only, like curl/connect()
		in := tcpPacket(lbMAC, clientMAC, clientIP, vip, sport, svcPort, tcpSYN, nil)
		ret, out := run(t, objs.XdpLoadBalancer, in)
		if ret != xdpTx {
			t.Fatalf("verdict = %d, want XDP_TX", ret)
		}
		want := []string{backend0, backend1}[expectedBackend(clientIP, sport, svcPort)]
		if got := ip4(out, 14+16); got != want {
			t.Fatalf("sport %d: dst IP = %s, want %s", sport, got, want)
		}
	}

	st := lbStats(t, objs)
	t.Logf("%d even-port flows -> backend0=%d backend1=%d", flows, st.ForwardedBackend0, st.ForwardedBackend1)
	if st.ForwardedBackend0 < flows*40/100 || st.ForwardedBackend1 < flows*40/100 {
		t.Errorf("unbalanced distribution: backend0=%d backend1=%d", st.ForwardedBackend0, st.ForwardedBackend1)
	}
}

func TestXDPForwardWithIPOptions(t *testing.T) {
	objs := loadLB(t)

	// IHL=6: 4 bytes of IP options (NOP NOP NOP EOL) shift the TCP header
	seg := tcpSegment(clientIP, vip, findPort(40000, 0), svcPort, tcpSYN, nil)
	in := ethHeader(lbMAC, clientMAC, ethPIPv4)
	in = append(in, ipv4Header(clientIP, vip, protoTCP, len(seg), []byte{1, 1, 1, 0})...)
	in = append(in, seg...)

	ret, out := run(t, objs.XdpLoadBalancer, in)
	if ret != xdpTx {
		t.Fatalf("verdict = %d, want XDP_TX", ret)
	}
	if got := ip4(out, 14+16); got != backend0 {
		t.Errorf("dst IP = %s, want %s", got, backend0)
	}
	checkIPv4Checksums(t, out)
}

func TestXDPPassesNonLBTraffic(t *testing.T) {
	objs := loadLB(t)

	// UDP to the VIP
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	udpPkt := append(ethHeader(lbMAC, clientMAC, ethPIPv4), ipv4Header(clientIP, vip, protoUDP, 8, nil)...)
	udpPkt = append(udpPkt, udp...)

	// TCP to the VIP but the TCP header is cut after 8 bytes
	full := tcpPacket(lbMAC, clientMAC, clientIP, vip, 40000, svcPort, tcpSYN, nil)
	truncated := append([]byte{}, full[:14+20+8]...)

	// Non-first IP fragment addressed to the VIP
	frag := tcpPacket(lbMAC, clientMAC, clientIP, vip, 40000, svcPort, tcpSYN, nil)
	binary.BigEndian.PutUint16(frag[14+6:14+8], 0x2000|10) // MF + offset

	// IPv6 frame (not supported by the LB -> must be passed untouched)
	v6 := ethHeader(lbMAC, clientMAC, ethPIPv6)
	v6hdr := make([]byte, 40)
	v6hdr[0] = 0x60
	binary.BigEndian.PutUint16(v6hdr[4:6], 20)
	v6hdr[6] = protoTCP
	v6hdr[7] = 64
	copy(v6hdr[8:24], net.ParseIP("fd00::10"))
	copy(v6hdr[24:40], net.ParseIP("fd00::100"))
	v6 = append(v6, v6hdr...)
	v6 = append(v6, make([]byte, 20)...)

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"tcp to non-vip address", tcpPacket(lbMAC, clientMAC, clientIP, otherIP, 40000, svcPort, tcpSYN, nil)},
		{"backend reply (handled by TC, not XDP)", tcpPacket(lbMAC, b0MAC, backend0, clientIP, svcPort, 40000, tcpSYNACK, nil)},
		{"udp to vip", udpPkt},
		{"truncated tcp header to vip", truncated},
		{"ip fragment to vip", frag},
		{"ethernet-only frame", ethHeader(lbMAC, clientMAC, ethPIPv4)},
		{"ipv6 frame", v6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ret, out := run(t, objs.XdpLoadBalancer, tc.pkt)
			if ret != xdpPass {
				t.Fatalf("verdict = %d, want XDP_PASS (%d)", ret, xdpPass)
			}
			if !bytes.Equal(out, tc.pkt) {
				t.Errorf("packet was modified on XDP_PASS")
			}
		})
	}

	if st := lbStats(t, objs); st.ForwardedBackend0+st.ForwardedBackend1 != 0 {
		t.Errorf("non-LB traffic was forwarded: %+v", st)
	}
}

// ------------------------------------------------------------------------------
// TC reverse NAT (reply path)
// ------------------------------------------------------------------------------

func TestTCReverseNATRestoresVIP(t *testing.T) {
	objs := loadLB(t)

	// 1. Client SYN through XDP creates the flow (a port that hashes to backend 1)
	sport := findPort(40000, 1)
	syn := tcpPacket(lbMAC, clientMAC, clientIP, vip, sport, svcPort, tcpSYN, nil)
	if ret, _ := run(t, objs.XdpLoadBalancer, syn); ret != xdpTx {
		t.Fatalf("forward verdict = %d, want XDP_TX", ret)
	}

	// 2. Backend 1 replies to the client via the LB (its gateway)
	for _, tc := range []struct {
		name    string
		flags   uint8
		payload []byte
	}{
		{"syn-ack", tcpSYNACK, nil},
		{"http response", tcpPSHACK, []byte("HTTP/1.0 200 OK\r\n\r\nhello")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := tcpPacket(lbMAC, b1MAC, backend1, clientIP, svcPort, sport, tc.flags, tc.payload)
			ret, out := run(t, objs.TcReverseNat, reply)
			if ret != tcActOK {
				t.Fatalf("verdict = %d, want TC_ACT_OK", ret)
			}
			if got := ip4(out, 14+12); got != vip {
				t.Errorf("src IP = %s, want VIP %s", got, vip)
			}
			if got := ip4(out, 14+16); got != clientIP {
				t.Errorf("dst IP = %s, want %s", got, clientIP)
			}
			checkIPv4Checksums(t, out)
		})
	}

	if st := lbStats(t, objs); st.ReverseNatPackets != 2 {
		t.Errorf("reverse_nat_packets = %d, want 2", st.ReverseNatPackets)
	}
}

func TestTCReverseNATIgnoresUnknownFlows(t *testing.T) {
	objs := loadLB(t)

	cases := []struct {
		name string
		pkt  []byte
	}{
		// No SYN was seen for this flow, so the backend's own traffic is untouched
		{"backend traffic without flow entry", tcpPacket(lbMAC, b0MAC, backend0, clientIP, svcPort, 40000, tcpSYNACK, nil)},
		{"unrelated host", tcpPacket(lbMAC, clientMAC, otherIP, clientIP, 22, 50000, tcpPSHACK, []byte("x"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ret, out := run(t, objs.TcReverseNat, tc.pkt)
			if ret != tcActOK {
				t.Fatalf("verdict = %d, want TC_ACT_OK", ret)
			}
			if !bytes.Equal(out, tc.pkt) {
				t.Errorf("packet was modified although flow is unknown")
			}
		})
	}
}

// ------------------------------------------------------------------------------
// TC egress classifier
// ------------------------------------------------------------------------------

func TestTCEgressPortStats(t *testing.T) {
	skipIfNotRoot(t)

	var objs tcegressObjects
	if err := loadTcegressObjects(&objs, nil); err != nil {
		t.Fatalf("load tcegress objects: %v", err)
	}
	defer objs.Close()

	pkt := tcpPacket(clientMAC, lbMAC, vip, clientIP, svcPort, 8080, tcpPSHACK, []byte("payload"))
	for i := 0; i < 3; i++ {
		if ret, _ := run(t, objs.TcEgressProg, pkt); ret != tcActOK {
			t.Fatalf("verdict = %d, want TC_ACT_OK", ret)
		}
	}

	port := uint16(8080) // key is stored in host byte order
	var st tcegressEgressStat
	if err := objs.EgressStats.Lookup(&port, &st); err != nil {
		t.Fatalf("lookup egress_stats[8080]: %v", err)
	}
	if st.Packets != 3 || st.Bytes != uint64(3*len(pkt)) {
		t.Errorf("egress_stats[8080] = %+v, want packets=3 bytes=%d", st, 3*len(pkt))
	}
}

// htons converts a port to the in-memory layout of a __be16 field on this host.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
