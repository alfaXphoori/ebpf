package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" -target native bpf ringbuf_events.c

// secEvent mirrors the C struct sec_event definition (176 bytes, little-endian)
type secEvent struct {
	TsNs      uint64
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	DataLen   uint32
	EventType uint8
	Pad       [7]byte
	Comm      [16]byte
	Payload   [128]byte
}

const (
	eventTypeExecve       = 1
	eventTypeTLSPlaintext = 2
)

// commonLibsslPaths lists common locations for libssl.so across Linux distributions
var commonLibsslPaths = []string{
	"/lib/x86_64-linux-gnu/libssl.so.3",
	"/usr/lib/x86_64-linux-gnu/libssl.so.3",
	"/usr/lib64/libssl.so.3",
	"/lib64/libssl.so.3",
	"/lib/aarch64-linux-gnu/libssl.so.3",
	"/usr/lib/aarch64-linux-gnu/libssl.so.3",
	"/lib/x86_64-linux-gnu/libssl.so.1.1",
	"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
}

func findLibsslPath(customPath string) string {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath
		}
		log.Printf("[WARN] Specified libssl path %q not found, searching fallback paths...", customPath)
	}

	for _, p := range commonLibsslPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func cStringToString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}

func sanitizePayload(b []byte, length int) string {
	if length <= 0 {
		return ""
	}
	if length > len(b) {
		length = len(b)
	}
	// Replace non-printable characters with periods or spaces for safe terminal display
	var sb strings.Builder
	for i := 0; i < length; i++ {
		c := b[i]
		if c >= 32 && c <= 126 {
			sb.WriteByte(c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte('.')
		}
	}
	return strings.TrimSpace(sb.String())
}

func main() {
	libsslFlag := flag.String("libssl", "", "Explicit path to libssl.so (e.g. /usr/lib/x86_64-linux-gnu/libssl.so.3)")
	execHook := flag.String("exec-hook", "sched", "Exec tracepoint: 'sched' (sched/sched_process_exec) or 'syscall' (syscalls/sys_enter_execve)")
	flag.Parse()

	// Allow current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load pre-compiled eBPF ELF objects into kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 1. Attach exec tracepoint
	var tp link.Link
	var err error
	switch *execHook {
	case "sched":
		tp, err = link.Tracepoint("sched", "sched_process_exec", objs.TpSchedProcessExec, nil)
	case "syscall":
		tp, err = link.Tracepoint("syscalls", "sys_enter_execve", objs.TpSysEnterExecve, nil)
	default:
		log.Fatalf("Unknown -exec-hook %q (use 'sched' or 'syscall')", *execHook)
	}
	if err != nil {
		log.Fatalf("Failed to attach exec tracepoint (%s): %v", *execHook, err)
	}
	defer tp.Close()
	if *execHook == "sched" {
		log.Println("[INFO] Tracepoint attached: sched/sched_process_exec")
	} else {
		log.Println("[INFO] Tracepoint attached: syscalls/sys_enter_execve")
	}

	// 2. Attach uprobes: OpenSSL SSL_write + SSL_write_ex
	// Uprobe ผูกกับ "ไฟล์" library (inode) ไม่ใช่ process: ทุก process ที่ map libssl ไฟล์นี้
	// (curl, python3, ...) จะโดนดักทั้งหมด แต่โปรแกรมที่ link OpenSSL แบบ static หรือใช้
	// TLS stack อื่น (Go crypto/tls, rustls, GnuTLS, BoringSSL) จะมองไม่เห็น
	targetLibssl := findLibsslPath(*libsslFlag)
	if targetLibssl != "" {
		// /lib -> /usr/lib (merged-usr) จึงเป็นไฟล์เดียวกัน
		if resolved, err := filepath.EvalSymlinks(targetLibssl); err == nil && resolved != targetLibssl {
			log.Printf("[INFO] %s resolves to %s", targetLibssl, resolved)
		}
		ex, err := link.OpenExecutable(targetLibssl)
		if err != nil {
			log.Printf("[WARN] Failed to open libssl executable at %s: %v", targetLibssl, err)
		} else {
			probes := []struct {
				symbol string
				prog   *ebpf.Program
			}{
				{"SSL_write", objs.UprobeSslWrite},
				{"SSL_write_ex", objs.UprobeSslWriteEx},
			}
			for _, p := range probes {
				up, err := ex.Uprobe(p.symbol, p.prog, nil)
				if err != nil {
					log.Printf("[WARN] Failed to attach uprobe to %s in %s: %v", p.symbol, targetLibssl, err)
					continue
				}
				defer up.Close()
				log.Printf("[INFO] Uprobe attached: %s on %s", p.symbol, targetLibssl)
			}
		}
	} else {
		log.Println("[WARN] No libssl.so found. SSL_write Uprobes skipped. Only exec tracing will be active.")
	}

	// 3. Open Ring Buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Trap SIGINT and SIGTERM for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("[INFO] Received termination signal. Closing ring buffer reader...")
		rd.Close()
	}()

	log.Println("[INFO] Successfully listening for events from eBPF Ring Buffer (16MB)...")
	fmt.Printf("%-15s %-7s %-7s %-6s %-16s %s\n", "EVENT_TYPE", "PID", "PPID", "UID", "COMM", "DETAILS")
	fmt.Println(strings.Repeat("-", 88))

	var event secEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[INFO] Ringbuf reader closed. Exiting.")
				return
			}
			log.Printf("[ERROR] Reading ringbuf record: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[ERROR] Parsing ringbuf record: %v", err)
			continue
		}

		comm := cStringToString(event.Comm[:])

		switch event.EventType {
		case eventTypeExecve:
			payload := cStringToString(event.Payload[:])
			fmt.Printf("\033[1;32m%-15s\033[0m %-7d %-7d %-6d %-16s binary=%s\n",
				"[EXECVE]", event.Pid, event.Ppid, event.Uid, comm, payload)

		case eventTypeTLSPlaintext:
			payload := sanitizePayload(event.Payload[:], int(event.DataLen))
			fmt.Printf("\033[1;36m%-15s\033[0m %-7d %-7d %-6d %-16s len=%d plaintext=%q\n",
				"[TLS_PLAINTEXT]", event.Pid, event.Ppid, event.Uid, comm, event.DataLen, payload)

		default:
			fmt.Printf("%-15s %-7d %-7d %-6d %-16s unknown event type=%d\n",
				"[UNKNOWN]", event.Pid, event.Ppid, event.Uid, comm, event.EventType)
		}
	}
}
