//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestDenyEventLayoutAndHelpers(t *testing.T) {
	if got := unsafe.Sizeof(denyEvent{}); got != 28 {
		t.Fatalf("denyEvent size = %d, want 28", got)
	}
	if got := sockTypeStr(1); got != "TCP" {
		t.Fatalf("sockTypeStr(1) = %q, want TCP", got)
	}
	if got := sockTypeStr(2); got != "UDP" {
		t.Fatalf("sockTypeStr(2) = %q, want UDP", got)
	}
	if _, err := prepareCgroup(cgroupRoot, false); err == nil {
		t.Fatal("prepareCgroup on root cgroup without allowRoot must fail")
	}
}

func TestCgroupConnect4BlocksPortAndStreamsEvent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF cgroup/connect4 test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	cgPath := filepath.Join(cgroupRoot, fmt.Sprintf("w14-test-%d", os.Getpid()))
	created, err := prepareCgroup(cgPath, false)
	if err != nil {
		t.Fatalf("prepareCgroup(%s): %v", cgPath, err)
	}
	if created {
		t.Cleanup(func() { _ = os.Remove(cgPath) })
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects: %+v", err)
	}
	defer objs.Close()

	// Pick an unused high port and block it
	const testPort uint16 = 49321
	var zero uint64
	p := testPort
	if err := objs.BlockedPorts.Put(&p, &zero); err != nil {
		t.Fatalf("BlockedPorts.Put: %v", err)
	}

	cgLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4Connect,
	})
	if err != nil {
		t.Fatalf("AttachCgroup: %v", err)
	}
	defer cgLink.Close()

	rd, err := ringbuf.NewReader(objs.DenyEvents)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	timer := time.AfterFunc(3*time.Second, func() { rd.Close() })
	defer timer.Stop()

	// Run a subprocess inside the isolated test cgroup so the Go test runner stays unaffected.
	pyCode := fmt.Sprintf(
		"import socket, errno\ns = socket.socket()\ntry:\n s.connect(('127.0.0.1', %d))\nexcept OSError as e:\n assert e.errno == errno.EPERM, e\nelse:\n raise AssertionError('connect unexpectedly succeeded')\n",
		testPort,
	)
	shellCmd := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec python3 -c \"$1\"", cgPath)
	out, err := exec.Command("sh", "-c", shellCmd, "sh", pyCode).CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess connect inside cgroup failed: %v\n%s", err, out)
	}

	var drops uint64
	if err := objs.BlockedPorts.Lookup(&p, &drops); err != nil {
		t.Fatalf("BlockedPorts.Lookup: %v", err)
	}
	if drops == 0 {
		t.Fatalf("expected BlockedPorts[%d] > 0, got 0", testPort)
	}

	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("expected deny_event in ringbuf: %v", err)
	}
	var ev denyEvent
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
		t.Fatalf("decode denyEvent: %v", err)
	}
	dst := make(net.IP, 4)
	binary.NativeEndian.PutUint32(dst, ev.DstIP)
	if ev.DstPort != testPort || ev.Match != 2 {
		t.Fatalf("unexpected denyEvent: %+v", ev)
	}
	t.Logf("cgroup/connect4 blocked %s:%d (drops=%d)", dst, ev.DstPort, drops)
}
