//go:build linux
// +build linux

package main

import (
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestOomWatcherLayoutAndHelpers(t *testing.T) {
	if got := unsafe.Sizeof(oomAlert{}); got != 176 {
		t.Fatalf("oomAlert size = %d, want 176", got)
	}
	if got := unsafe.Sizeof(pfStat{}); got != 16 {
		t.Fatalf("pfStat size = %d, want 16", got)
	}
	if got := kbString(2048); got != "2048 kB (2.00 MB)" {
		t.Fatalf("kbString(2048) = %q, want %q", got, "2048 kB (2.00 MB)")
	}
}

func TestOomWatcherLoadsAndAttaches(t *testing.T) {
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

	tpOOM, err := link.Tracepoint("oom", "mark_victim", objs.OnOomMarkVictim, nil)
	if err != nil {
		t.Fatalf("attach oom:mark_victim: %v", err)
	}
	defer tpOOM.Close()

	if runtime.GOARCH == "amd64" {
		tpPF, err := link.Tracepoint("exceptions", "page_fault_user", objs.OnUserPageFault, nil)
		if err != nil {
			t.Fatalf("attach exceptions:page_fault_user on amd64: %v", err)
		}
		tpPF.Close()
	}

	rd, err := ringbuf.NewReader(objs.OomEvents)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	rd.Close()
	t.Log("oom_watcher loaded and tracepoints attached cleanly")
}
