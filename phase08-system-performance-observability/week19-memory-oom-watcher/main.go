//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf oom_watcher.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ต้องตรงกับ OOM_HAS_* ใน oom_watcher.c
const (
	oomHasRSS  = 1 << 0
	oomHasUID  = 1 << 1
	oomHasAdj  = 1 << 2
	oomHasComm = 1 << 3
)

// oomAlert ต้องมี layout ตรงกับ struct oom_alert ใน C (ทุกฟิลด์ align แล้ว ไม่มี padding แฝง)
type oomAlert struct {
	TsNs        uint64
	TotalVMKb   uint64
	AnonRSSKb   uint64
	FileRSSKb   uint64
	ShmemRSSKb  uint64
	PgtablesKb  uint64
	CgroupID    uint64
	VictimPid   uint32
	Uid         uint32
	TriggerPid  uint32
	Flags       uint32
	OomScoreAdj int16
	Pad         [3]uint16
	Comm        [16]byte
	TriggerComm [16]byte
	CgroupName  [64]byte
}

// pfStat ต้องตรงกับ struct pf_stat ใน C
type pfStat struct {
	Faults      uint64
	WriteFaults uint64
}

// cgroupPath หา path ของ cgroup v2 จาก cgroup id (= inode number ของไดเรกทอรีใน /sys/fs/cgroup)
func cgroupPath(id uint64) string {
	const root = "/sys/fs/cgroup"
	found := ""
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Ino == id {
			found = strings.TrimPrefix(p, root)
			return fs.SkipAll
		}
		return nil
	})
	if found == "" {
		return "(already removed - transient scope exited with its last process)"
	}
	return found
}

func kbString(kb uint64) string {
	return fmt.Sprintf("%d kB (%.2f MB)", kb, float64(kb)/1024.0)
}

func printAlert(a *oomAlert) {
	victim := string(bytes.TrimRight(a.Comm[:], "\x00"))
	if a.Flags&oomHasComm == 0 {
		victim = "?"
	}
	trigger := string(bytes.TrimRight(a.TriggerComm[:], "\x00"))

	fmt.Printf("\n\033[1;31m[CRITICAL OOM KILLER TRIGGERED]\033[0m %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("  • Victim Process : %s (PID: %d", victim, a.VictimPid)
	if a.Flags&oomHasUID != 0 {
		fmt.Printf(", UID: %d", a.Uid)
	}
	fmt.Println(")")
	fmt.Printf("  • Triggered by   : %s (PID: %d)\n", trigger, a.TriggerPid)
	cgName := string(bytes.TrimRight(a.CgroupName[:], "\x00"))
	fmt.Printf("  • Cgroup (v2)    : %s (id %d)\n", cgName, a.CgroupID)
	fmt.Printf("  • Cgroup path    : %s\n", cgroupPath(a.CgroupID))
	if a.Flags&oomHasRSS != 0 {
		fmt.Printf("  • Total VM Size  : %s\n", kbString(a.TotalVMKb))
		fmt.Printf("  • Anonymous RSS  : %s\n", kbString(a.AnonRSSKb))
		fmt.Printf("  • File RSS       : %s\n", kbString(a.FileRSSKb))
		fmt.Printf("  • Shmem RSS      : %s\n", kbString(a.ShmemRSSKb))
		fmt.Printf("  • Page Tables    : %s\n", kbString(a.PgtablesKb))
	} else {
		fmt.Println("  • Memory sizes   : n/a (this kernel's oom:mark_victim has no RSS fields)")
	}
	if a.Flags&oomHasAdj != 0 {
		fmt.Printf("  • oom_score_adj  : %d\n", a.OomScoreAdj)
	}
	fmt.Println()
}

func main() {
	interval := flag.Duration("interval", 3*time.Second, "ระยะเวลาระหว่างการพิมพ์ Top Page Faults")
	duration := flag.Duration("duration", 0, "หยุดอัตโนมัติหลังเวลาที่กำหนด (0 = รอจนกด Ctrl+C)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Memory Subsystem & OOM Forensics Watcher")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tpOOM, err := link.Tracepoint("oom", "mark_victim", objs.OnOomMarkVictim, nil)
	if err != nil {
		log.Fatalf("Failed to attach oom:mark_victim: %v", err)
	}
	defer tpOOM.Close()

	// exceptions:page_fault_user มีเฉพาะบน x86
	tpPF, err := link.Tracepoint("exceptions", "page_fault_user", objs.OnUserPageFault, nil)
	if err != nil {
		log.Printf("[WARN] exceptions:page_fault_user unavailable (x86-only tracepoint): %v", err)
	} else {
		defer tpPF.Close()
	}

	rd, err := ringbuf.NewReader(objs.OomEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Watching for User Page Faults and OOM Killer events...\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	var timeout <-chan time.Time
	if *duration > 0 {
		timeout = time.After(*duration)
	}

	// Background OOM alert listener
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				if !errors.Is(err, ringbuf.ErrClosed) {
					log.Printf("[WARN] ringbuf read: %v", err)
				}
				return
			}
			var alert oomAlert
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &alert); err == nil {
				printAlert(&alert)
			}
		}
	}()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			type pfEntry struct {
				comm string
				stat pfStat
			}
			var entries []pfEntry

			var (
				k [16]byte
				v pfStat
			)
			iter := objs.PageFaultCounts.Iterate()
			for iter.Next(&k, &v) {
				entries = append(entries, pfEntry{
					comm: string(bytes.TrimRight(k[:], "\x00")),
					stat: v,
				})
			}

			sort.Slice(entries, func(i, j int) bool {
				return entries[i].stat.Faults > entries[j].stat.Faults
			})

			fmt.Printf("[%s] Top Processes by User-Space Page Faults (cumulative):\n", time.Now().Format("15:04:05"))
			limit := 5
			if len(entries) < limit {
				limit = len(entries)
			}
			for i := 0; i < limit; i++ {
				fmt.Printf("   #%d %-16s : %-8d page faults (%d on write)\n",
					i+1, entries[i].comm, entries[i].stat.Faults, entries[i].stat.WriteFaults)
			}
			fmt.Println()

		case <-timeout:
			fmt.Println("\n[INFO] Detaching Memory Watcher...")
			return
		case <-stopper:
			fmt.Println("\n[INFO] Detaching Memory Watcher...")
			return
		}
	}
}
