//go:build linux
// +build linux

package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func TestExecCounterLoadsAndCounts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF tracepoint test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects: %+v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		t.Fatalf("attach sched/sched_process_exec: %v", err)
	}
	defer tp.Close()

	var key uint32
	var before uint64
	if err := objs.ExecCount.Lookup(&key, &before); err != nil {
		t.Fatalf("lookup before: %v", err)
	}

	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Fatalf("run /bin/true: %v", err)
	}

	var after uint64
	if err := objs.ExecCount.Lookup(&key, &after); err != nil {
		t.Fatalf("lookup after: %v", err)
	}
	if after <= before {
		t.Fatalf("exec count did not increase after /bin/true: before=%d after=%d", before, after)
	}
	t.Logf("exec_count incremented: %d -> %d", before, after)
}
