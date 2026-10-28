//go:build linux
// +build linux

package main

// Runtime test for trampoline.c: attach fentry/fexit to do_sys_openat2,
// open one existing file and one missing file from THIS process,
// and check that fexit reports the correct return value (fd >= 0 / -ENOENT).
//
// Run with: make test   (equivalent to: go test -exec sudo -v ./...)

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestFexitReturnValue(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (run: make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer objs.Close()

	lEntry, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceOpenat2Entry})
	if err != nil {
		t.Fatalf("attach fentry: %v", err)
	}
	defer lEntry.Close()
	lExit, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceOpenat2Exit})
	if err != nil {
		t.Fatalf("attach fexit: %v", err)
	}
	defer lExit.Close()

	rd, err := ringbuf.NewReader(objs.FexitEvents)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	// ใช้ path สั้น ๆ เพราะ filename ใน event ถูกตัดที่ 64 ไบต์
	dir, err := os.MkdirTemp("", "w22")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	okPath := filepath.Join(dir, "exists.txt")
	if err := os.WriteFile(okPath, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	missingPath := filepath.Join(dir, "does-not-exist")

	// Trigger the hooks (os.Open -> openat(2) -> do_sys_openat2)
	f, err := os.Open(okPath)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := os.Open(missingPath); err == nil {
		t.Fatal("expected ENOENT")
	}

	want := map[string]bool{okPath: false, missingPath: false}
	myPid := uint32(os.Getpid())
	rd.SetDeadline(time.Now().Add(3 * time.Second))

	for !(want[okPath] && want[missingPath]) {
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("did not receive both events: %v (got %v)", err, want)
		}
		var ev fexitEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Pid != myPid {
			continue
		}
		name := cString(ev.Filename[:])
		switch name {
		case okPath:
			if ev.Ret < 0 {
				t.Errorf("open(%s): fexit ret=%d, want fd >= 0", name, ev.Ret)
			}
			want[okPath] = true
		case missingPath:
			if ev.Ret != -int32(syscall.ENOENT) {
				t.Errorf("open(%s): fexit ret=%d, want %d (-ENOENT)", name, ev.Ret, -int32(syscall.ENOENT))
			}
			want[missingPath] = true
		default:
			continue
		}
		if ev.DurationNs == 0 || ev.DurationNs > uint64(time.Second) {
			t.Errorf("implausible latency %d ns for %s", ev.DurationNs, name)
		}
		t.Logf("pid=%d ret=%d latency=%.2fus file=%s", ev.Pid, ev.Ret, float64(ev.DurationNs)/1000, name)
	}
}
