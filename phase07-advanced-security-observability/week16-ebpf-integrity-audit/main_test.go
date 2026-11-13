//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestAuditEventLayoutAndHelpers(t *testing.T) {
	if got := unsafe.Sizeof(bpfAuditEvent{}); got != 64 {
		t.Fatalf("bpfAuditEvent size = %d, want 64", got)
	}
	label, _, imp := riskOf(cmdProgLoad)
	if label != "PROG_LOAD" || !imp {
		t.Fatalf("riskOf(PROG_LOAD) = (%q, %v), want (PROG_LOAD, true)", label, imp)
	}
	if _, _, imp := riskOf(1); imp {
		t.Fatal("BPF_MAP_LOOKUP_ELEM should not be marked important")
	}
	if got := getCmdName(cmdProgLoad); got != "BPF_PROG_LOAD" {
		t.Fatalf("getCmdName(5) = %q, want BPF_PROG_LOAD", got)
	}
}

func TestIntegrityAuditorCapturesBpfSyscall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF audit test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	coll, prog, hookLink, hookName, err := loadAndAttach("auto")
	if err != nil {
		t.Fatalf("loadAndAttach(auto): %+v", err)
	}
	defer coll.Close()
	defer hookLink.Close()

	if info, err := prog.Info(); err != nil {
		t.Fatalf("prog.Info: %v", err)
	} else if _, ok := info.ID(); !ok {
		t.Fatalf("info.ID() not available")
	}

	rd, err := ringbuf.NewReader(coll.Maps["bpf_audit_events"])
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	timer := time.AfterFunc(3*time.Second, func() { rd.Close() })
	defer timer.Stop()

	// Trigger a real bpf(BPF_MAP_CREATE) syscall from this test process
	probeMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "w16_probe",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("ebpf.NewMap: %v", err)
	}
	probeMap.Close()

	selfPid := uint32(os.Getpid())
	for {
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("timed out waiting for BPF_MAP_CREATE audit event (%s): %v", hookName, err)
		}
		var ev bpfAuditEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			t.Fatalf("decode bpfAuditEvent: %v", err)
		}
		if ev.Pid == selfPid && ev.Cmd == cmdMapCreate {
			t.Logf("captured via %s: pid=%d cmd=%s", hookName, ev.Pid, getCmdName(ev.Cmd))
			break
		}
	}
}
