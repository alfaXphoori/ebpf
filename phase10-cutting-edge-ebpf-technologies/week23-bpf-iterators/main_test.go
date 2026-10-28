//go:build linux
// +build linux

package main

// Runtime test for task_iter.c: run the iter/task program and check that
//   - the header is printed once (seq_num == 0)
//   - every process appears exactly once (thread-group leaders only)
//   - our own multi-threaded Go test process is listed with THREADS > 1
//
// Run with: make test   (equivalent to: go test -exec sudo -v ./...)

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func TestTaskIterOneRowPerProcess(t *testing.T) {
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

	it, err := link.AttachIter(link.IterOptions{Program: objs.DumpTask})
	if err != nil {
		t.Fatalf("attach iter: %v", err)
	}
	defer it.Close()

	out, err := readIter(it)
	if err != nil {
		t.Fatal(err)
	}

	headers := 0
	seen := map[int]int{}
	myPid := os.Getpid()
	myThreads := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			t.Fatalf("malformed row: %q", sc.Text())
		}
		if f[0] == "PID" {
			headers++
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			t.Fatalf("bad pid in row %q", sc.Text())
		}
		seen[pid]++
		if pid == myPid {
			myThreads, _ = strconv.Atoi(f[2])
		}
	}

	if headers != 1 {
		t.Errorf("header printed %d times, want 1", headers)
	}
	for pid, n := range seen {
		if n != 1 {
			t.Errorf("pid %d listed %d times, want 1 (thread filter broken?)", pid, n)
		}
	}
	if seen[1] != 1 {
		t.Errorf("pid 1 (init) not listed")
	}
	if seen[myPid] != 1 {
		t.Fatalf("own pid %d not listed", myPid)
	}
	if myThreads < 2 {
		t.Errorf("own process THREADS=%d, want > 1 (Go runtime is multi-threaded)", myThreads)
	}
	t.Logf("%d processes listed; own pid %d has %d threads", len(seen), myPid, myThreads)
}
