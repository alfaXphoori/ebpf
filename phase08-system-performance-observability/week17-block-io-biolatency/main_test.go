//go:build linux
// +build linux

package main

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func TestDevNameFormat(t *testing.T) {
	// Device 0:0 won't exist in /sys/dev/block, so devName falls back cleanly
	if got := devName(0); got != "dev 0:0" {
		t.Fatalf("devName(0) = %q, want %q", got, "dev 0:0")
	}
}

func TestBiolatencyLoadsAndAttaches(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF tp_btf test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects: %+v", err)
	}
	defer objs.Close()

	tpIssue, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceRqIssue})
	if err != nil {
		t.Fatalf("AttachTracing block_rq_issue: %v", err)
	}
	defer tpIssue.Close()

	tpComplete, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceRqComplete})
	if err != nil {
		t.Fatalf("AttachTracing block_rq_complete: %v", err)
	}
	defer tpComplete.Close()

	var k0 uint32
	var cnt uint64
	if err := objs.IoTotals.Lookup(&k0, &cnt); err != nil {
		t.Fatalf("IoTotals.Lookup: %v", err)
	}
	t.Logf("biolatency attached to tp_btf/block_rq_{issue,complete}; initial io_totals[0]=%d", cnt)
}
