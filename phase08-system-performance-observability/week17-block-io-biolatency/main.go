//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf biolatency.c

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const maxSlots = 32

var opNames = []string{"READ", "WRITE", "OTHER (flush/discard)"}

// histID ระบุ Histogram หนึ่งชุด: ดิสก์ (dev_t) + ประเภทคำสั่ง
type histID struct {
	dev uint32
	op  uint32
}

// devName แปลง dev_t ของเคอร์เนล (major<<20 | minor) เป็นชื่ออุปกรณ์ เช่น "sda", "nvme0n1"
func devName(dev uint32) string {
	major, minor := dev>>20, dev&((1<<20)-1)
	path := fmt.Sprintf("/sys/dev/block/%d:%d/uevent", major, minor)
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if name, ok := strings.CutPrefix(sc.Text(), "DEVNAME="); ok {
				return fmt.Sprintf("%s (%d:%d)", name, major, minor)
			}
		}
	}
	return fmt.Sprintf("dev %d:%d", major, minor)
}

func renderHistogram(title string, hist [maxSlots]uint64) {
	var maxCount uint64
	last := -1
	for i, v := range hist {
		if v > maxCount {
			maxCount = v
		}
		if v > 0 {
			last = i
		}
	}
	if last < 0 {
		return
	}

	fmt.Printf("\n%s\n", title)
	fmt.Printf("%-24s : %-8s %s\n", "Latency (us)", "Count", "Distribution")
	fmt.Println("----------------------------------------------------------------------------")

	// แสดงตั้งแต่ช่อง 0 จนถึงช่องสุดท้ายที่มีข้อมูล (แบบเดียวกับ bcc/libbpf-tools)
	for i := 0; i <= last; i++ {
		low := uint64(1) << i
		high := (uint64(1) << (i + 1)) - 1
		if i == 0 {
			low = 0 // ช่อง 0 รวม 0 และ 1 us เพราะ log2(0) = log2(1) = 0
		}
		count := hist[i]

		barLen := 0
		if maxCount > 0 {
			barLen = int((count * 40) / maxCount)
		}
		bar := strings.Repeat("*", barLen)

		fmt.Printf("%10d -> %-10d : %-8d |%-40s|\n", low, high, count, bar)
	}
	fmt.Println("----------------------------------------------------------------------------")
}

func main() {
	interval := flag.Duration("interval", 3*time.Second, "ระยะเวลาระหว่างการพิมพ์สรุปยอดสะสม")
	duration := flag.Duration("duration", 0, "หยุดอัตโนมัติหลังเวลาที่กำหนด (0 = รอจนกด Ctrl+C)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Block I/O Latency Analyzer (CO-RE biolatency)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// tp_btf ใช้ link.AttachTracing (BPF_TRACE_RAW_TP) ไม่ใช่ link.Tracepoint
	tpIssue, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceRqIssue})
	if err != nil {
		log.Fatalf("Failed to attach tp_btf/block_rq_issue: %v", err)
	}
	defer tpIssue.Close()

	tpComplete, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceRqComplete})
	if err != nil {
		log.Fatalf("Failed to attach tp_btf/block_rq_complete: %v", err)
	}
	defer tpComplete.Close()

	log.Printf("[INFO] Attached to 'tp_btf/block_rq_issue' & 'tp_btf/block_rq_complete'!")
	log.Printf("[INFO] Tracing disk I/O requests. (Press Ctrl+C to stop and view histogram)\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	var timeout <-chan time.Time
	if *duration > 0 {
		timeout = time.After(*duration)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var k0, k1 uint32 = 0, 1
			var cnt, lat uint64
			objs.IoTotals.Lookup(&k0, &cnt)
			objs.IoTotals.Lookup(&k1, &lat)
			avgLat := uint64(0)
			if cnt > 0 {
				avgLat = lat / cnt
			}
			fmt.Printf("[%s] Total I/O Ops: %-6d | Cumulative: %-8d us | Avg Latency: %-6d us\n",
				time.Now().Format("15:04:05"), cnt, lat, avgLat)

		case <-timeout:
			printFinal(&objs)
			return
		case <-stopper:
			printFinal(&objs)
			return
		}
	}
}

func printFinal(objs *bpfObjects) {
	fmt.Println("\n[INFO] Detaching probes and generating final I/O latency histograms...")

	hists := map[histID]*[maxSlots]uint64{}
	var (
		key bpfHistKey
		val uint64
	)
	iter := objs.IoLatencyHist.Iterate()
	for iter.Next(&key, &val) {
		id := histID{dev: key.Dev, op: key.Op}
		if hists[id] == nil {
			hists[id] = &[maxSlots]uint64{}
		}
		if key.Slot < maxSlots {
			hists[id][key.Slot] += val
		}
	}
	if err := iter.Err(); err != nil {
		log.Printf("[WARN] iterate histogram: %v", err)
	}
	if len(hists) == 0 {
		fmt.Println("(no completed block I/O requests were observed)")
		return
	}

	ids := make([]histID, 0, len(hists))
	for id := range hists {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].dev != ids[j].dev {
			return ids[i].dev < ids[j].dev
		}
		return ids[i].op < ids[j].op
	})

	for _, id := range ids {
		op := "UNKNOWN"
		if int(id.op) < len(opNames) {
			op = opNames[id.op]
		}
		var total uint64
		for _, c := range hists[id] {
			total += c
		}
		renderHistogram(fmt.Sprintf("disk = %s, op = %s, requests = %d", devName(id.dev), op, total), *hists[id])
	}
}
