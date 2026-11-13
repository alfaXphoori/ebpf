//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestSecEventLayoutAndHelpers(t *testing.T) {
	if got := unsafe.Sizeof(secEvent{}); got != 176 {
		t.Fatalf("secEvent size = %d, want 176 (must match C struct sec_event)", got)
	}
	if got := cStringToString([]byte("curl\x00extra")); got != "curl" {
		t.Fatalf("cStringToString = %q, want %q", got, "curl")
	}
	if got := sanitizePayload([]byte("GET /\r\n\x01"), 8); got != "GET /  ." {
		t.Fatalf("sanitizePayload = %q, want %q", got, "GET /  .")
	}
}

func TestExecTracepointAndUprobeLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("eBPF ringbuf/uprobe test requires root (run with sudo or make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfObjects: %+v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TpSchedProcessExec, nil)
	if err != nil {
		t.Fatalf("attach sched/sched_process_exec: %v", err)
	}
	defer tp.Close()

	if libssl := findLibsslPath(""); libssl != "" {
		ex, err := link.OpenExecutable(libssl)
		if err != nil {
			t.Fatalf("OpenExecutable(%s): %v", libssl, err)
		}
		up, err := ex.Uprobe("SSL_write", objs.UprobeSslWrite, nil)
		if err != nil {
			t.Fatalf("attach SSL_write uprobe on %s: %v", libssl, err)
		}
		up.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	done := make(chan struct{})
	go func() {
		<-time.After(3 * time.Second)
		rd.Close()
		close(done)
	}()

	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Fatalf("run /bin/true: %v", err)
	}

	for {
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("timed out waiting for exec event in ringbuf: %v", err)
		}
		var ev secEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			t.Fatalf("decode secEvent: %v", err)
		}
		if ev.EventType == eventTypeExecve {
			t.Logf("received exec event: pid=%d comm=%q payload=%q",
				ev.Pid, cStringToString(ev.Comm[:]), cStringToString(ev.Payload[:]))
			break
		}
	}
	_ = done
}
