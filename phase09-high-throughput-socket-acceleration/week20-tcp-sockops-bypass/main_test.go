//go:build linux
// +build linux

package main

// sockops / sk_msg programs do NOT support BPF_PROG_TEST_RUN, so these tests
// load the real objects into the kernel and drive a real loopback TCP
// connection from inside a temporary cgroup.
//
// Run: make test   (= go test -exec sudo -v ./...)

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (run with: go test -exec sudo ./...)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock: %v", err)
	}
}

func loadObjects(t *testing.T) *bpfObjects {
	t.Helper()
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load eBPF objects (verifier): %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// TestLoadPrograms: smoke test - both programs pass the verifier and have the
// expected program types.
func TestLoadPrograms(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	if got := objs.BpfSockopsHandler.Type(); got != ebpf.SockOps {
		t.Errorf("sockops program type = %v, want SockOps", got)
	}
	if got := objs.BpfSkMsgHandler.Type(); got != ebpf.SkMsg {
		t.Errorf("sk_msg program type = %v, want SkMsg", got)
	}
	if got := objs.SockHash.Type(); got != ebpf.SockHash {
		t.Errorf("sock_hash map type = %v, want SockHash", got)
	}
}

// currentCgroup returns the cgroup v2 directory of this process
func currentCgroup(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(line, "0::") {
			return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"))
		}
	}
	t.Fatal("cgroup v2 entry not found in /proc/self/cgroup")
	return ""
}

func moveSelf(t *testing.T, cg string) {
	t.Helper()
	pid := []byte(fmt.Sprint(os.Getpid()))
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), pid, 0); err != nil {
		t.Fatalf("move pid into %s: %v", cg, err)
	}
}

// TestRedirectEndToEnd: attach both programs to a temporary cgroup, move the
// test process into it, open a loopback TCP connection and check that
//  1. both sockets are inserted into sock_hash
//  2. sendmsg() is redirected (redirect counter > 0, fallback == 0)
//  3. the data arrives intact
func TestRedirectEndToEnd(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)

	origCg := currentCgroup(t)
	testCg := fmt.Sprintf("/sys/fs/cgroup/w20-gotest-%d", os.Getpid())
	if err := os.Mkdir(testCg, 0755); err != nil {
		t.Fatalf("create cgroup: %v", err)
	}
	t.Cleanup(func() { os.Remove(testCg) })

	cgLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    testCg,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.BpfSockopsHandler,
	})
	if err != nil {
		t.Fatalf("attach sockops: %v", err)
	}
	defer cgLink.Close()

	attachOpts := link.RawAttachProgramOptions{
		Target:  objs.SockHash.FD(),
		Program: objs.BpfSkMsgHandler,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	if err := link.RawAttachProgram(attachOpts); err != nil {
		t.Fatalf("attach sk_msg: %v", err)
	}
	defer link.RawDetachProgram(link.RawDetachProgramOptions(attachOpts))

	// Sockets inherit the cgroup of the process that creates them
	moveSelf(t, testCg)
	defer moveSelf(t, origCg)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		received <- b
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte("sockmap-redirect-"), 4096) // 68 KiB
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	// Both ends must be registered while the connection is open
	if n := countSockhashEntries(objs.SockHash); n != 2 {
		t.Errorf("sock_hash entries = %d, want 2", n)
	}

	conn.Close()
	got := <-received
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted: got %d bytes, want %d", len(got), len(payload))
	}

	redirMsgs := readStat(objs.BypassStats, statRedirectMsgs)
	redirBytes := readStat(objs.BypassStats, statRedirectBytes)
	fallback := readStat(objs.BypassStats, statFallbackMsgs)
	added := readStat(objs.BypassStats, statSocksAdded)
	t.Logf("socks_added=%d redirect_msgs=%d redirect_bytes=%d fallback_msgs=%d",
		added, redirMsgs, redirBytes, fallback)

	if added != 2 {
		t.Errorf("sockets added = %d, want 2", added)
	}
	if redirMsgs == 0 || redirBytes != uint64(len(payload)) {
		t.Errorf("redirect counters msgs=%d bytes=%d, want >0 and %d", redirMsgs, redirBytes, len(payload))
	}
	if fallback != 0 {
		t.Errorf("fallback msgs = %d, want 0 (key encoding mismatch?)", fallback)
	}
}
