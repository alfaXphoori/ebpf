//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf revshell_detect.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// threatAlert ต้องมี layout ตรงกับ struct threat_alert ใน revshell_detect.c (184 ไบต์)
type threatAlert struct {
	TsNs     uint64
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Flags    uint8
	Pad      [3]byte
	Comm     [16]byte
	Pcomm    [16]byte
	Filename [128]byte
}

// ค่าเหล่านี้ต้องตรงกับ #define ใน revshell_detect.c
const (
	nameShell   = 1
	nameNetTool = 2

	fShell        = 1 << 0
	fNetTool      = 1 << 1
	fDaemonParent = 1 << 2
	fStdinSock    = 1 << 3
	fStdoutSock   = 1 << 4
	fStderrSock   = 1 << 5
)

const (
	colorRed    = "\033[1;31m"
	colorYellow = "\033[1;33m"
	colorReset  = "\033[0m"
)

func cleanStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(bytes.ToValidUTF8(b[:n], []byte("")))
}

// commKey แปลงชื่อเป็น key 16 ไบต์ (เติม \0) ให้ตรงกับ buffer ของ bpf_get_current_comm()
func commKey(name string) ([16]byte, error) {
	var k [16]byte
	if len(name) == 0 || len(name) > 15 {
		return k, fmt.Errorf("name %q must be 1-15 bytes (TASK_COMM_LEN-1)", name)
	}
	copy(k[:], name)
	return k, nil
}

func fillNames(m *ebpf.Map, csv string, val uint8) []string {
	var added []string
	for _, n := range strings.Split(csv, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		k, err := commKey(n)
		if err != nil {
			log.Fatalf("[ERROR] %v", err)
		}
		if err := m.Put(&k, &val); err != nil {
			log.Fatalf("[ERROR] map put %q: %v", n, err)
		}
		added = append(added, n)
	}
	return added
}

// classify ตัดสินระดับความรุนแรงจาก flags ที่ฝั่งเคอร์เนลส่งมา
func classify(f uint8) (string, string) {
	stdioSock := f&(fStdinSock|fStdoutSock) != 0
	switch {
	case stdioSock && f&(fShell|fNetTool) != 0:
		return colorRed, "CRITICAL-REVSHELL"
	case stdioSock:
		return colorRed, "HIGH-SOCKET-STDIO"
	case f&fDaemonParent != 0 && f&(fShell|fNetTool) != 0:
		return colorRed, "CRITICAL-RCE"
	case f&fNetTool != 0:
		return colorYellow, "WARN-NETTOOL"
	}
	return "", "INFO-SHELL"
}

func stdioStr(f uint8) string {
	s := []byte("---")
	if f&fStdinSock != 0 {
		s[0] = '0'
	}
	if f&fStdoutSock != 0 {
		s[1] = '1'
	}
	if f&fStderrSock != 0 {
		s[2] = '2'
	}
	return string(s)
}

func main() {
	shells := flag.String("shells", "sh,bash,dash,zsh,ksh,mksh,fish,csh,tcsh", "Comma-separated shell names (exact comm match)")
	netTools := flag.String("nettools", "nc,ncat,netcat,nc.openbsd,nc.traditional,socat,telnet", "Comma-separated network tool names (exact comm match)")
	daemons := flag.String("daemons", "nginx,apache2,httpd,php-fpm,node,java,redis-server,mysqld,postgres", "Comma-separated parent names that should never spawn shells (exact comm match)")
	showAll := flag.Bool("all", false, "Also print INFO-SHELL events (ordinary shell starts, very noisy)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Reverse Shell & Interactive Threat Detector (CO-RE + RingBuffer)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	log.Printf("[CONFIG] shells   : %s\n", strings.Join(fillNames(objs.WatchNames, *shells, nameShell), ","))
	log.Printf("[CONFIG] nettools : %s\n", strings.Join(fillNames(objs.WatchNames, *netTools, nameNetTool), ","))
	log.Printf("[CONFIG] daemons  : %s\n", strings.Join(fillNames(objs.DaemonNames, *daemons, 1), ","))

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExecThreat, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.ThreatEvents)
	if err != nil {
		log.Fatalf("Failed to open ringbuf: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Hooked tracepoint 'sched/sched_process_exec'.")
	log.Printf("[INFO] Watching for shells with socket stdio and daemon-spawned shells...\n\n")

	fmt.Printf("%-9s %-18s %-8s %-8s %-5s %-10s %-12s %s\n",
		"TIME", "SEVERITY", "PID", "PPID", "STDIO", "PROCESS", "PARENT", "EXEC FILENAME")
	fmt.Println("----------------------------------------------------------------------------------------------")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n[INFO] Stopping Threat Guard...")
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}

		var alert threatAlert
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &alert); err != nil {
			continue
		}

		color, severity := classify(alert.Flags)
		if severity == "INFO-SHELL" && !*showAll {
			continue
		}
		reset := ""
		if color != "" {
			reset = colorReset
		}

		fmt.Printf("%-9s %s%-18s%s %-8d %-8d %-5s %-10s %-12s %s\n",
			time.Now().Format("15:04:05"),
			color, severity, reset,
			alert.Pid,
			alert.Ppid,
			stdioStr(alert.Flags),
			cleanStr(alert.Comm[:]),
			cleanStr(alert.Pcomm[:]),
			cleanStr(alert.Filename[:]),
		)
	}

	fmt.Println("[SUCCESS] Threat Guard cleanly shutdown.")
}
