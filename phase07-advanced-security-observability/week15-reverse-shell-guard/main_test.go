//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestThreatAlertLayoutAndHelpers(t *testing.T) {
	if got := unsafe.Sizeof(threatAlert{}); got != 184 {
		t.Fatalf("threatAlert size = %d, want 184", got)
	}
	if _, err := commKey(""); err == nil {
		t.Fatal("commKey(\"\") must error")
	}
	if _, err := commKey("1234567890123456"); err == nil {
		t.Fatal("commKey(>15 bytes) must error")
	}
	if _, sev := classify(fShell | fStdinSock); sev != "CRITICAL-REVSHELL" {
		t.Fatalf("classify(fShell|fStdinSock) = %q, want CRITICAL-REVSHELL", sev)
	}
	if got := stdioStr(fStdinSock | fStderrSock); got != "0-2" {
		t.Fatalf("stdioStr = %q, want 0-2", got)
	}
}

func TestDetectsShellWithInetSocketStdio(t *testing.T) {
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

	fillNames(objs.WatchNames, "sh", nameShell)

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExecThreat, nil)
	if err != nil {
		t.Fatalf("attach sched/sched_process_exec: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.ThreatEvents)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	timer := time.AfterFunc(3*time.Second, func() { rd.Close() })
	defer timer.Stop()

	// Create a real local TCP connection and pass it as stdin of `sh -c true`
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		acceptDone <- c
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()
	if srvConn := <-acceptDone; srvConn != nil {
		defer srvConn.Close()
	}

	tcpConn := conn.(*net.TCPConn)
	sockFile, err := tcpConn.File()
	if err != nil {
		t.Fatalf("tcpConn.File: %v", err)
	}
	defer sockFile.Close()

	cmd := exec.Command("/bin/sh", "-c", "true")
	cmd.Stdin = sockFile
	if err := cmd.Run(); err != nil {
		t.Fatalf("run sh with socket stdin: %v", err)
	}
	targetPid := uint32(cmd.Process.Pid)

	for {
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("timed out waiting for threat_alert for pid %d: %v", targetPid, err)
		}
		var alert threatAlert
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &alert); err != nil {
			t.Fatalf("decode threatAlert: %v", err)
		}
		if alert.Pid == targetPid {
			if alert.Flags&fShell == 0 || alert.Flags&fStdinSock == 0 {
				t.Fatalf("expected F_SHELL|F_STDIN_SOCK flags, got 0x%x", alert.Flags)
			}
			t.Logf("detected shell with socket stdin: pid=%d comm=%q flags=0x%x stdio=%s",
				alert.Pid, cleanStr(alert.Comm[:]), alert.Flags, stdioStr(alert.Flags))
			break
		}
	}
}
