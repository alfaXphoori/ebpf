package main

// BPF_PROG_TEST_RUN unit test for xdp_metrics_prog: feeds crafted frames to the
// program (no interface attached) and checks the per-CPU counters that the
// Prometheus collector exports.
// Requires root: make test  (= go test -exec sudo -v ./...)

import (
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func frame(etherType uint16, ipProto uint8, payload int) []byte {
	pkt := make([]byte, 14+20+payload)
	pkt[12], pkt[13] = byte(etherType>>8), byte(etherType)
	pkt[14] = 0x45 // IPv4, IHL=5
	pkt[14+9] = ipProto
	return pkt
}

func TestXDPMetricsCounting(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF_PROG_TEST_RUN; run: make test (go test -exec sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load: %+v", err)
	}
	defer objs.Close()

	inputs := []struct {
		pkt   []byte
		times int
	}{
		{frame(0x0800, 6, 20), 3},     // TCP  : 3 x 54 bytes
		{frame(0x0800, 17, 8), 2},     // UDP  : 2 x 42 bytes
		{frame(0x0800, 1, 8), 1},      // ICMP : 1 x 42 bytes
		{frame(0x0800, 47, 0), 1},     // GRE  -> other : 34 bytes
		{frame(0x86dd, 0, 26), 1},     // IPv6 -> other : 60 bytes
		{frame(0x0800, 6, 0)[:20], 1}, // truncated IPv4 header: not counted
	}
	for _, in := range inputs {
		for i := 0; i < in.times; i++ {
			ret, err := objs.XdpMetricsProg.Run(&ebpf.RunOptions{Data: in.pkt})
			if err != nil {
				t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
			}
			if ret != 2 { // XDP_PASS
				t.Fatalf("verdict = %d, want XDP_PASS(2): the exporter must never drop traffic", ret)
			}
		}
	}

	// Check through the real Prometheus collector (per-CPU values summed)
	expected := `
# HELP ebpf_xdp_packets_total Total number of packets observed by eBPF XDP hook aggregated across all CPU cores
# TYPE ebpf_xdp_packets_total counter
ebpf_xdp_packets_total{interface="test",protocol="icmp"} 1
ebpf_xdp_packets_total{interface="test",protocol="other"} 2
ebpf_xdp_packets_total{interface="test",protocol="tcp"} 3
ebpf_xdp_packets_total{interface="test",protocol="udp"} 2
# HELP ebpf_xdp_bytes_total Total number of bytes observed by eBPF XDP hook aggregated across all CPU cores
# TYPE ebpf_xdp_bytes_total counter
ebpf_xdp_bytes_total{interface="test",protocol="icmp"} 42
ebpf_xdp_bytes_total{interface="test",protocol="other"} 94
ebpf_xdp_bytes_total{interface="test",protocol="tcp"} 162
ebpf_xdp_bytes_total{interface="test",protocol="udp"} 84
`
	reg := prometheus.NewRegistry()
	reg.MustRegister(newXDPCollector(objs.TrafficMetrics, "test"))
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected)); err != nil {
		t.Fatal(err)
	}
}
