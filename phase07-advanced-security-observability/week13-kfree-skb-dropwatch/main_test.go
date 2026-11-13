//go:build linux
// +build linux

package main

import (
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestDropEventLayoutAndHelpers(t *testing.T) {
	if got := unsafe.Sizeof(dropEvent{}); got != 40 {
		t.Fatalf("dropEvent size = %d, want 40", got)
	}
	if got := protoStr(0x0800); got != "IPv4" {
		t.Fatalf("protoStr(0x0800) = %q, want IPv4", got)
	}
	if got := protoStr(0x86DD); got != "IPv6" {
		t.Fatalf("protoStr(0x86DD) = %q, want IPv6", got)
	}
	syms := []ksym{{addr: 0x1000, name: "tcp_v4_rcv"}, {addr: 0x2000, name: "kfree_skb_reason"}}
	if got := resolveKsym(syms, 0x1020); got != "tcp_v4_rcv+0x20" {
		t.Fatalf("resolveKsym = %q, want tcp_v4_rcv+0x20", got)
	}
	if got := getReasonStr((1 << dropReasonSubsysShift) | 0x58); got != "SUBSYS_1/0x58" {
		t.Fatalf("getReasonStr subsys = %q, want SUBSYS_1/0x58", got)
	}
}

func TestDropwatchLoadsAndAttaches(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF tracepoint test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("LoadKernelSpec: %v", err)
	}
	reasons := map[uint32]string{}
	if err := loadEnumNames(spec, "skb_drop_reason", dropReasonPrefix, reasons); err != nil {
		t.Fatalf("loadEnumNames(skb_drop_reason): %v", err)
	}
	if len(reasons) == 0 {
		t.Fatal("expected non-empty skb_drop_reason enum from kernel BTF")
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects: %+v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceKfreeSkb, nil)
	if err != nil {
		t.Fatalf("attach skb:kfree_skb: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.DropEvents)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	rd.Close()
	t.Logf("dropwatch loaded and attached to skb:kfree_skb (%d BTF drop reasons)", len(reasons))
}
