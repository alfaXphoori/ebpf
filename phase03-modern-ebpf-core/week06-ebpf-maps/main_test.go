//go:build linux

package main

// Tests for syscall_stats.c that do not need to attach anything:
//   - the program passes the verifier and the map has the expected shape
//   - BPF_PROG_TEST_RUN is NOT available for tracepoint programs, so the map
//     logic itself is tested with an XDP program in ./maps_testrun instead
// Requires root: make test  (= go test -exec sudo -v ./...)

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestSyscallStatsLoads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load eBPF programs; run: make test (go test -exec sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected syscall_stats.c:\n%+v", ve)
		}
		t.Fatal(err)
	}
	defer objs.Close()

	m := objs.SyscallMap
	if m.Type() != ebpf.Hash || m.KeySize() != 4 || m.MaxEntries() != 4096 {
		t.Fatalf("syscall_map = %v key=%dB max_entries=%d, want Hash key=4B max_entries=4096",
			m.Type(), m.KeySize(), m.MaxEntries())
	}
	// C struct proc_stat and Go bpfProcStat must have the same size (section 1.2)
	if got, want := m.ValueSize(), uint32(unsafe.Sizeof(bpfProcStat{})); got != want || got != 24 {
		t.Fatalf("value size: kernel %dB, Go bpfProcStat %dB, want 24B", got, want)
	}
	t.Logf("syscall_map: %v key=%dB value=%dB max_entries=%d", m.Type(), m.KeySize(), m.ValueSize(), m.MaxEntries())

	// A tracepoint program has no test_run implementation in the kernel
	_, err := objs.TrackSyscalls.Run(&ebpf.RunOptions{Context: make([]byte, 64)})
	if !errors.Is(err, ebpf.ErrNotSupported) {
		t.Fatalf("Run on a %v program: err = %v, want ErrNotSupported", objs.TrackSyscalls.Type(), err)
	}
	t.Logf("BPF_PROG_TEST_RUN on %v program: %v", objs.TrackSyscalls.Type(), err)
}
