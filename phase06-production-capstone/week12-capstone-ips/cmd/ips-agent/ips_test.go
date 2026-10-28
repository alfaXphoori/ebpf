package main

// BPF_PROG_TEST_RUN unit tests for the Smart IPS XDP program.
//
// Each test loads a fresh copy of the eBPF objects (fresh maps), feeds
// hand-crafted Ethernet/IPv4 frames to xdp_smart_ips through
// Program.Run (BPF_PROG_TEST_RUN) and checks the verdict, the counters
// and the blacklist. No network interface is touched.
//
// Requires root (CAP_BPF + CAP_NET_ADMIN):  make test
//   = go test -exec sudo -v ./...

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	xdpDrop = 1 // enum xdp_action: XDP_ABORTED=0, XDP_DROP=1, XDP_PASS=2
	xdpPass = 2

	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10

	attackerIP = "198.51.100.66"
	victimIP   = "192.0.2.10"
	benignIP   = "198.51.100.7"
)

// ---------- Packet crafting helpers ----------

func ethIPv4(src, dst string, proto uint8, l4 []byte) []byte {
	var b bytes.Buffer
	// Ethernet: dst MAC, src MAC, EtherType IPv4
	b.Write([]byte{0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01})
	_ = binary.Write(&b, binary.BigEndian, uint16(0x0800))
	// IPv4 header (IHL=5, no options)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8] = 64 // TTL
	ip[9] = proto
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	b.Write(ip)
	b.Write(l4)
	return b.Bytes()
}

func tcpPacket(src string, flags uint8) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000) // source port
	binary.BigEndian.PutUint16(tcp[2:], 80)    // destination port
	tcp[12] = 5 << 4                           // data offset = 5 words
	tcp[13] = flags
	return ethIPv4(src, victimIP, 6, tcp)
}

func icmpPacket(src string, icmpType uint8) []byte {
	icmp := make([]byte, 8+32)
	icmp[0] = icmpType // 8 = Echo Request, 0 = Echo Reply
	return ethIPv4(src, victimIP, 1, icmp)
}

// ---------- Test harness ----------

func loadIPS(t *testing.T, cfg *ipsConfig) *bpfObjects {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF_PROG_TEST_RUN; run: make test (go test -exec sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected program: %+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	if cfg != nil {
		if err := applyConfig(objs.ConfigMap, *cfg); err != nil {
			t.Fatalf("apply config: %v", err)
		}
	}
	return objs
}

func runXDP(t *testing.T, objs *bpfObjects, pkt []byte) uint32 {
	t.Helper()
	ret, err := objs.XdpSmartIps.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret
}

func expectVerdict(t *testing.T, objs *bpfObjects, pkt []byte, want uint32, what string) {
	t.Helper()
	if got := runXDP(t, objs, pkt); got != want {
		t.Fatalf("%s: verdict = %s, want %s", what, verdictName(got), verdictName(want))
	}
}

func verdictName(v uint32) string {
	switch v {
	case xdpDrop:
		return "XDP_DROP"
	case xdpPass:
		return "XDP_PASS"
	default:
		return fmt.Sprintf("XDP(%d)", v)
	}
}

func readMetric(t *testing.T, objs *bpfObjects, idx uint32) uint64 {
	t.Helper()
	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	perCPU := make([]uint64, n)
	if err := objs.IpsMetrics.Lookup(&idx, &perCPU); err != nil {
		t.Fatalf("lookup metric %d: %v", idx, err)
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum
}

func expectMetric(t *testing.T, objs *bpfObjects, idx uint32, want uint64, name string) {
	t.Helper()
	if got := readMetric(t, objs, idx); got != want {
		t.Errorf("metric %s = %d, want %d", name, got, want)
	}
}

func lookupBan(t *testing.T, objs *bpfObjects, ip string) (blockEntry, bool) {
	t.Helper()
	key, err := ipToUint32(ip)
	if err != nil {
		t.Fatal(err)
	}
	var e blockEntry
	if err := objs.BlacklistMap.Lookup(&key, &e); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return e, false
		}
		t.Fatalf("lookup blacklist: %v", err)
	}
	return e, true
}

// drainAlerts reads every alert currently queued in the ring buffer
func drainAlerts(t *testing.T, objs *bpfObjects) []ipsAlert {
	t.Helper()
	rd, err := ringbuf.NewReader(objs.IpsEvents)
	if err != nil {
		t.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	var alerts []ipsAlert
	for {
		rd.SetDeadline(time.Now().Add(50 * time.Millisecond))
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return alerts
			}
			t.Fatalf("ringbuf read: %v", err)
		}
		var a ipsAlert
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &a); err != nil {
			t.Fatalf("decode alert: %v", err)
		}
		alerts = append(alerts, a)
	}
}

// ---------- Tests ----------

func TestNonInspectedTrafficPasses(t *testing.T) {
	objs := loadIPS(t, &ipsConfig{SYNLimit: 2, ICMPLimit: 2, Autoban: true, Window: time.Second})

	arp := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x06}, make([]byte, 28)...)
	expectVerdict(t, objs, arp, xdpPass, "ARP frame")

	// TCP ACK, ICMP Echo Reply and UDP are never rate limited, however many arrive
	for i := 0; i < 50; i++ {
		expectVerdict(t, objs, tcpPacket(benignIP, tcpFlagACK), xdpPass, "TCP ACK")
		expectVerdict(t, objs, icmpPacket(benignIP, 0), xdpPass, "ICMP Echo Reply")
		expectVerdict(t, objs, ethIPv4(benignIP, victimIP, 17, make([]byte, 8)), xdpPass, "UDP")
	}

	// IPv4 TCP packet truncated before the TCP header: bounds check -> pass
	truncated := tcpPacket(benignIP, tcpFlagSYN)[:14+20+4]
	expectVerdict(t, objs, truncated, xdpPass, "truncated TCP header")

	expectMetric(t, objs, MetricPassed, 1+150, "passed")
	expectMetric(t, objs, MetricDroppedRatelimit, 0, "dropped_ratelimit")
	if _, banned := lookupBan(t, objs, benignIP); banned {
		t.Errorf("benign source was blacklisted")
	}
}

func TestSYNFloodAutoBanEnabled(t *testing.T) {
	const limit = 5
	objs := loadIPS(t, &ipsConfig{SYNLimit: limit, ICMPLimit: 50, Autoban: true, Window: time.Second, BanTTL: 30 * time.Second})

	for i := 1; i <= limit; i++ {
		expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpPass, "SYN within limit")
	}
	expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpDrop, "SYN over limit")

	ban, ok := lookupBan(t, objs, attackerIP)
	if !ok {
		t.Fatalf("attacker %s not in blacklist_map after SYN flood", attackerIP)
	}
	if ban.Reason != ReasonSYNFlood {
		t.Errorf("ban reason = %s, want SYN_FLOOD", reasonToString(uint8(ban.Reason)))
	}

	// Once banned, every packet from the source is dropped - even a plain ACK
	expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagACK), xdpDrop, "ACK from banned source")
	// Other sources are unaffected
	expectVerdict(t, objs, tcpPacket(benignIP, tcpFlagSYN), xdpPass, "SYN from other source")

	ban, _ = lookupBan(t, objs, attackerIP)
	if ban.DropCount != 2 {
		t.Errorf("ban drop_count = %d, want 2 (triggering SYN + ACK)", ban.DropCount)
	}
	expectMetric(t, objs, MetricPassed, limit+1, "passed")
	expectMetric(t, objs, MetricDroppedRatelimit, 1, "dropped_ratelimit")
	expectMetric(t, objs, MetricDroppedBlacklist, 1, "dropped_blacklist")

	alerts := drainAlerts(t, objs)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if uint32ToIP(a.SrcIP) != attackerIP || a.Reason != ReasonSYNFlood || a.Action != ActionBanned || a.Pps != limit+1 || a.DstPort != 80 {
		t.Errorf("unexpected alert: src=%s reason=%s action=%s pps=%d dport=%d",
			uint32ToIP(a.SrcIP), reasonToString(a.Reason), actionToString(a.Action), a.Pps, a.DstPort)
	}
}

func TestSYNFloodAutoBanDisabled(t *testing.T) {
	const limit = 5
	objs := loadIPS(t, &ipsConfig{SYNLimit: limit, ICMPLimit: 50, Autoban: false, Window: time.Second})

	for i := 1; i <= limit; i++ {
		expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpPass, "SYN within limit")
	}
	for i := 0; i < 5; i++ {
		expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpDrop, "SYN over limit (rate-limit only)")
	}

	if _, banned := lookupBan(t, objs, attackerIP); banned {
		t.Fatalf("source was blacklisted although CONF_AUTOBAN_EN=0")
	}
	// Not banned: established-connection traffic still flows
	expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagACK), xdpPass, "ACK from rate-limited source")

	expectMetric(t, objs, MetricDroppedRatelimit, 5, "dropped_ratelimit")
	expectMetric(t, objs, MetricDroppedBlacklist, 0, "dropped_blacklist")

	alerts := drainAlerts(t, objs)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want exactly 1 per window in rate-limit-only mode", len(alerts))
	}
	if alerts[0].Action != ActionRateLimited {
		t.Errorf("alert action = %s, want RATE-LIMITED", actionToString(alerts[0].Action))
	}
}

func TestICMPFloodAutoBan(t *testing.T) {
	const limit = 3
	objs := loadIPS(t, &ipsConfig{SYNLimit: 100, ICMPLimit: limit, Autoban: true, Window: time.Second, BanTTL: 30 * time.Second})

	for i := 1; i <= limit; i++ {
		expectVerdict(t, objs, icmpPacket(attackerIP, 8), xdpPass, "Echo Request within limit")
	}
	expectVerdict(t, objs, icmpPacket(attackerIP, 8), xdpDrop, "Echo Request over limit")

	ban, ok := lookupBan(t, objs, attackerIP)
	if !ok || ban.Reason != ReasonICMPFlood {
		t.Fatalf("expected ICMP_FLOOD ban, got present=%v reason=%d", ok, ban.Reason)
	}
	alerts := drainAlerts(t, objs)
	if len(alerts) != 1 || alerts[0].Proto != 1 || alerts[0].Reason != ReasonICMPFlood {
		t.Fatalf("unexpected alerts: %+v", alerts)
	}
}

func TestFixedWindowReset(t *testing.T) {
	const limit = 3
	window := 100 * time.Millisecond
	objs := loadIPS(t, &ipsConfig{SYNLimit: limit, ICMPLimit: 50, Autoban: false, Window: window})

	for i := 1; i <= limit; i++ {
		expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpPass, "SYN within limit")
	}
	expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpDrop, "SYN over limit")

	time.Sleep(window + 50*time.Millisecond)
	// A new window starts: the counter is reset to zero
	for i := 1; i <= limit; i++ {
		expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpPass, "SYN in new window")
	}
	expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpDrop, "SYN over limit in new window")
}

func TestZeroConfigUsesDefaults(t *testing.T) {
	// config_map is a BPF ARRAY: every slot starts at 0. The program must fall
	// back to its defaults (SYN limit 100) instead of treating 0 as the limit.
	objs := loadIPS(t, nil)

	for i := 1; i <= 100; i++ {
		expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpPass, "SYN within default limit")
	}
	expectVerdict(t, objs, tcpPacket(attackerIP, tcpFlagSYN), xdpDrop, "SYN #101")

	// CONF_AUTOBAN_EN = 0 -> rate-limit only
	if _, banned := lookupBan(t, objs, attackerIP); banned {
		t.Errorf("auto-ban fired although CONF_AUTOBAN_EN was never enabled")
	}
}

func TestBanTTLExpiry(t *testing.T) {
	ttl := 200 * time.Millisecond
	objs := loadIPS(t, &ipsConfig{SYNLimit: 2, ICMPLimit: 50, Autoban: true, Window: time.Second, BanTTL: ttl})
	bm := NewBanManager(objs.BlacklistMap, ttl)

	// Ban created in the kernel; nobody consumes the ring buffer, i.e. the
	// alert is "lost" from the agent's point of view.
	for i := 0; i < 3; i++ {
		runXDP(t, objs, tcpPacket(attackerIP, tcpFlagSYN))
	}
	if _, ok := lookupBan(t, objs, attackerIP); !ok {
		t.Fatalf("expected kernel auto-ban")
	}
	// A manual ban stored with the monotonic clock
	if err := bm.ManualBan(benignIP, ReasonManualBan); err != nil {
		t.Fatal(err)
	}
	expectVerdict(t, objs, tcpPacket(benignIP, tcpFlagACK), xdpDrop, "manually banned source")

	// Reaper before the TTL: nothing removed
	if removed, err := bm.ExpireBans(monotonicNowNs()); err != nil || len(removed) != 0 {
		t.Fatalf("ExpireBans before TTL removed %d entries (err=%v)", len(removed), err)
	}

	time.Sleep(ttl + 50*time.Millisecond)

	// Data plane already ignores the expired ban, even before the reaper runs
	expectVerdict(t, objs, tcpPacket(benignIP, tcpFlagACK), xdpPass, "expired ban (not yet reaped)")

	removed, err := bm.ExpireBans(monotonicNowNs())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("ExpireBans removed %d entries, want 2 (kernel ban + manual ban)", len(removed))
	}
	if n := bm.CountActiveBans(); n != 0 {
		t.Errorf("active bans after reaping = %d, want 0", n)
	}
}
