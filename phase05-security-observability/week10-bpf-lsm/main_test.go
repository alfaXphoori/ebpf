//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestLsmLayoutAndHelpers(t *testing.T) {
	if got := unsafe.Sizeof(lsmAlert{}); got != 304 {
		t.Fatalf("lsmAlert size = %d, want 304", got)
	}
	if got := unsafe.Sizeof(inodeKey{}); got != 16 {
		t.Fatalf("inodeKey size = %d, want 16", got)
	}
	if got := cStringToString([]byte("/tmp/secret\x00abc")); got != "/tmp/secret" {
		t.Fatalf("cStringToString = %q, want /tmp/secret", got)
	}
}

func TestAuditModeAndOptionalLSMEnforce(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF LSM/fentry test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	target := filepath.Join(t.TempDir(), "guarded_by_inode.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(target, &st); err != nil {
		t.Fatalf("stat target: %v", err)
	}
	key := inodeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}

	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}

	// 1. Test audit mode (fentry/security_file_open) - works even without lsm=...,bpf
	var auditObjs auditObjects
	if err := spec.LoadAndAssign(&auditObjs, nil); err != nil {
		t.Fatalf("LoadAndAssign auditObjects: %+v", err)
	}
	defer auditObjs.bpfMaps.Close()
	defer auditObjs.Prog.Close()

	var polKey, polVal uint32 = 0, 1 // block_all = 1 so root PID triggers alert
	if err := auditObjs.PolicyMap.Put(&polKey, &polVal); err != nil {
		t.Fatalf("PolicyMap.Put: %v", err)
	}
	var one uint8 = 1
	if err := auditObjs.ProtectedInodes.Put(&key, &one); err != nil {
		t.Fatalf("ProtectedInodes.Put: %v", err)
	}

	trLink, err := link.AttachTracing(link.TracingOptions{Program: auditObjs.Prog})
	if err != nil {
		t.Fatalf("AttachTracing audit: %v", err)
	}
	defer trLink.Close()

	rd, err := ringbuf.NewReader(auditObjs.LsmEvents)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	timer := time.AfterFunc(3*time.Second, func() { rd.Close() })
	defer timer.Stop()

	f, err := os.Open(target)
	if err != nil {
		t.Fatalf("audit mode should allow open, got: %v", err)
	}
	f.Close()

	for {
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("expected audit ringbuf event for inode %d: %v", st.Ino, err)
		}
		var alert lsmAlert
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &alert); err != nil {
			t.Fatalf("decode lsmAlert: %v", err)
		}
		if alert.Ino == st.Ino && alert.Reason == matchInode && alert.Ret == 0 {
			t.Logf("audit alert ok: path=%q ino=%d", cStringToString(alert.Path[:]), alert.Ino)
			break
		}
	}

	// 2. Test LSM enforce hook if BPF LSM is enabled on the host
	if !bpfLSMActive() {
		t.Log("BPF LSM not active in /sys/kernel/security/lsm; skipping enforce EPERM check")
		return
	}

	var enfObjs enforceObjects
	if err := spec.LoadAndAssign(&enfObjs, nil); err != nil {
		t.Fatalf("LoadAndAssign enforceObjects: %+v", err)
	}
	defer enfObjs.bpfMaps.Close()
	defer enfObjs.Prog.Close()

	if err := enfObjs.PolicyMap.Put(&polKey, &polVal); err != nil {
		t.Fatalf("PolicyMap.Put enforce: %v", err)
	}
	if err := enfObjs.ProtectedInodes.Put(&key, &one); err != nil {
		t.Fatalf("ProtectedInodes.Put enforce: %v", err)
	}
	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: enfObjs.Prog})
	if err != nil {
		t.Fatalf("AttachLSM: %v", err)
	}
	defer lsmLink.Close()

	f2, err := os.Open(target)
	if err == nil {
		f2.Close()
		t.Fatalf("expected EPERM when BPF LSM is active and block_all=1, but open succeeded")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM, got: %v", err)
	}
	t.Logf("enforce mode blocked protected inode with expected error: %v", err)
}
