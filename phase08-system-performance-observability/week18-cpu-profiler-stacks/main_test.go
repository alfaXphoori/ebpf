//go:build linux
// +build linux

package main

import (
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
)

func TestCPUProfilerHelpers(t *testing.T) {
	if got := unsafe.Sizeof(stackKey{}); got != 28 {
		t.Fatalf("stackKey size = %d, want 28", got)
	}
	cpus, err := onlineCPUs()
	if err != nil || len(cpus) == 0 {
		t.Fatalf("onlineCPUs() = (%v, %v), want non-empty slice", cpus, err)
	}
	sym := newUserSymbolizer()
	sym.snapshot(uint32(os.Getpid()))
	if len(sym.maps[uint32(os.Getpid())]) == 0 {
		t.Fatal("expected at least one executable VMA mapping for current test process")
	}
}

func TestPerfSamplerCollectsSamples(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF perf_event test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"targ_pid":     uint32(os.Getpid()),
		"include_idle": uint8(0),
	}); err != nil {
		t.Fatalf("RewriteConstants: %v", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("LoadAndAssign: %+v", err)
	}
	defer objs.Close()

	sampler, err := attachPerfSampler(objs.DoSample, 99)
	if err != nil {
		t.Fatalf("attachPerfSampler: %v", err)
	}
	defer sampler.Close()

	// Burn ~60ms of on-CPU time so 99 Hz sampling captures at least one sample of this PID
	start := time.Now()
	var sink uint64
	for time.Since(start) < 60*time.Millisecond {
		sink++
	}
	_ = sink

	var idx uint32 = statSamples
	var perCPU []uint64
	if err := objs.Stats.Lookup(&idx, &perCPU); err != nil {
		t.Fatalf("Stats.Lookup: %v", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	if total == 0 {
		t.Fatalf("expected >0 perf_event samples during busy loop, got 0")
	}
	t.Logf("captured %d on-CPU samples for PID %d across %d CPUs", total, os.Getpid(), len(perCPU))
}
