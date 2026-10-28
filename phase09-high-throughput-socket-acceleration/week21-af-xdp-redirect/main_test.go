//go:build linux
// +build linux

package main

// BPF_PROG_TEST_RUN tests: the kernel runs xsk_redirect_prog on crafted
// packets (no NIC, no traffic) and we assert the returned XDP verdict and the
// xsk_stats counters.
//
// Run: make test   (= go test -exec sudo -v ./...)

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	xdpPass     = 2 // enum xdp_action
	xdpRedirect = 4
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (run with: go test -exec sudo ./...)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
}

func loadObjects(t *testing.T) *bpfObjects {
	t.Helper()
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load eBPF objects (verifier): %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// craftPacket builds Ethernet + (optional) IPv4 header + L4 bytes.
// ipProto < 0 means "do not append an IPv4 header".
func craftPacket(ethertype uint16, ipProto int, l4 []byte) []byte {
	pkt := make([]byte, 14)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x01})  // dst MAC
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x02}) // src MAC
	binary.BigEndian.PutUint16(pkt[12:14], ethertype)
	if ipProto >= 0 {
		ip := make([]byte, 20)
		ip[0] = 0x45 // version 4, IHL 5
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
		ip[8] = 64
		ip[9] = byte(ipProto)
		copy(ip[12:16], []byte{10, 21, 0, 2})
		copy(ip[16:20], []byte{10, 21, 0, 1})
		pkt = append(pkt, ip...)
	}
	return append(pkt, l4...)
}

func udpPacket() []byte {
	udp := make([]byte, 8, 8+5)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 9999)
	binary.BigEndian.PutUint16(udp[4:6], 8+5)
	return craftPacket(0x0800, unix.IPPROTO_UDP, append(udp, "hello"...))
}

func runXDP(t *testing.T, prog *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret
}

// TestVerdictsWithoutSocket: nothing in xsks_map -> every packet must be XDP_PASS
func TestVerdictsWithoutSocket(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	cases := []struct {
		name string
		pkt  []byte
		stat uint32
	}{
		{"arp", craftPacket(0x0806, -1, make([]byte, 28)), statPassed},
		{"ipv4-tcp", craftPacket(0x0800, unix.IPPROTO_TCP, make([]byte, 20)), statPassed},
		{"ipv4-icmp", craftPacket(0x0800, unix.IPPROTO_ICMP, make([]byte, 8)), statPassed},
		{"ipv4-truncated", craftPacket(0x0800, -1, make([]byte, 10)), statPassed},
		{"ipv4-udp-no-socket", udpPacket(), statNoXSK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := readStat(objs.XskStats, c.stat)
			if got := runXDP(t, objs.XskRedirectProg, c.pkt); got != xdpPass {
				t.Errorf("verdict = %d, want XDP_PASS(%d)", got, xdpPass)
			}
			if after := readStat(objs.XskStats, c.stat); after != before+1 {
				t.Errorf("stat[%d] = %d, want %d", c.stat, after, before+1)
			}
		})
	}
	if n := readStat(objs.XskStats, statRedirected); n != 0 {
		t.Errorf("redirected = %d, want 0", n)
	}
}

// TestRedirectWithSocket: an AF_XDP socket in xsks_map[0] turns IPv4/UDP into
// XDP_REDIRECT while ARP still gets XDP_PASS. (BPF_PROG_TEST_RUN only reports
// the verdict; the frame is not actually delivered to the socket.)
func TestRedirectWithSocket(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatalf("socket(AF_XDP): %v", err)
	}
	defer unix.Close(fd)

	key, val := uint32(0), uint32(fd) // test-run ctx uses rx_queue_index 0
	if err := objs.XsksMap.Put(&key, &val); err != nil {
		t.Fatalf("insert AF_XDP socket into xsks_map: %v", err)
	}

	if got := runXDP(t, objs.XskRedirectProg, udpPacket()); got != xdpRedirect {
		t.Errorf("udp verdict = %d, want XDP_REDIRECT(%d)", got, xdpRedirect)
	}
	if got := runXDP(t, objs.XskRedirectProg, craftPacket(0x0806, -1, make([]byte, 28))); got != xdpPass {
		t.Errorf("arp verdict = %d, want XDP_PASS(%d)", got, xdpPass)
	}
	if n := readStat(objs.XskStats, statRedirected); n != 1 {
		t.Errorf("redirected = %d, want 1", n)
	}
	if n := readStat(objs.XskStats, statNoXSK); n != 0 {
		t.Errorf("no_xsk = %d, want 0", n)
	}
}

// TestDescribePacket: user-space parser used by the RX loop (no root needed)
func TestDescribePacket(t *testing.T) {
	want := `10.21.0.2:40000 -> 10.21.0.1:9999 UDP payload="hello"`
	if got := describePacket(udpPacket()); got != want {
		t.Errorf("describePacket = %q, want %q", got, want)
	}
}
