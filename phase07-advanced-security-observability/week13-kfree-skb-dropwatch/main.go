//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf dropwatch.c

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// dropEvent ต้องมี layout ตรงกับ struct drop_event ใน dropwatch.c (48 ไบต์)
type dropEvent struct {
	Location uint64
	Pid      uint32
	Reason   uint32
	Protocol uint16 // host byte order (tracepoint แปลง ntohs ให้แล้ว)
	HasRxSk  uint8
	RxSkSet  uint8
	Comm     [16]byte
	Pad      [4]byte
}

// ค่า enum skb_drop_reason แต่ละเวอร์ชันเคอร์เนล "ไม่เท่ากัน" (มีการแทรก reason ใหม่
// กลาง enum บ่อยครั้ง) จึงไม่ควร hard-code ตาราง แต่ให้อ่านชื่อจาก Kernel BTF
// (/sys/kernel/btf/vmlinux) ของเครื่องที่รันอยู่จริงแทน
const (
	dropReasonSubsysShift = 16
	dropReasonPrefix      = "SKB_DROP_REASON_"
	dropSubsysPrefix      = "SKB_DROP_REASON_SUBSYS_"
)

var (
	dropReasonNames = map[uint32]string{}
	dropSubsysNames = map[uint32]string{}
)

// loadEnumNames อ่านค่าและชื่อของ enum จาก Kernel BTF แล้วตัด prefix ทิ้ง
func loadEnumNames(spec *btf.Spec, enumName, prefix string, out map[uint32]string) error {
	var enum *btf.Enum
	if err := spec.TypeByName(enumName, &enum); err != nil {
		return err
	}
	for _, v := range enum.Values {
		out[uint32(v.Value)] = strings.TrimPrefix(v.Name, prefix)
	}
	return nil
}

func getReasonStr(r uint32) string {
	subsys := r >> dropReasonSubsysShift
	if subsys != 0 {
		// 16 บิตบนคือ subsystem (เช่น mac80211, openvswitch) ซึ่งมี enum ของตัวเองใน module BTF
		name, ok := dropSubsysNames[subsys]
		if !ok {
			name = fmt.Sprintf("SUBSYS_%d", subsys)
		}
		return fmt.Sprintf("%s/0x%x", name, r&0xffff)
	}
	if name, ok := dropReasonNames[r]; ok {
		return name
	}
	return fmt.Sprintf("REASON_%d", r)
}

// ksym คือ 1 บรรทัดจาก /proc/kallsyms (ต้องรันด้วย root จึงจะเห็น address จริง ไม่ใช่ 0)
type ksym struct {
	addr uint64
	name string
}

// loadKallsyms โหลดตารางสัญลักษณ์เคอร์เนลแล้วเรียงตาม address เพื่อใช้ binary search
func loadKallsyms() []ksym {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil
	}
	defer f.Close()
	var syms []ksym
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		t := fields[1]
		if t != "t" && t != "T" { // เอาเฉพาะสัญลักษณ์ใน text section (โค้ด)
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		syms = append(syms, ksym{addr: addr, name: fields[2]})
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i].addr < syms[j].addr })
	return syms
}

// resolveKsym แปลง instruction pointer เป็น "ชื่อฟังก์ชัน+offset" แบบเดียวกับ %pS ในเคอร์เนล
func resolveKsym(syms []ksym, pc uint64) string {
	i := sort.Search(len(syms), func(i int) bool { return syms[i].addr > pc })
	if i == 0 {
		return fmt.Sprintf("0x%x", pc)
	}
	s := syms[i-1]
	return fmt.Sprintf("%s+0x%x", s.name, pc-s.addr)
}

func protoStr(p uint16) string {
	// tracepoint เก็บค่า ntohs(skb->protocol) ไว้แล้ว จึงเป็น host byte order ใช้ได้ทันที
	switch p {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0x0806:
		return "ARP"
	case 0x0000:
		return "-"
	}
	return fmt.Sprintf("0x%04x", p)
}

func main() {
	ipOnly := flag.Bool("ip-only", false, "แสดงเฉพาะแพ็กเก็ต IPv4/IPv6 (ตัด netlink/ARP/wifi ออกจากหน้าจอ แต่ map ยังนับทุกอย่าง)")
	commFilter := flag.String("comm", "", "แสดงเฉพาะเหตุการณ์ที่ comm ตรงกับค่านี้ (เช่น nc, curl)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Kernel Dropwatch & Packet Loss Diagnostics (kfree_skb)")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	kernelBTF, err := btf.LoadKernelSpec()
	if err != nil {
		log.Fatalf("Failed to load kernel BTF (/sys/kernel/btf/vmlinux): %v", err)
	}
	if err := loadEnumNames(kernelBTF, "skb_drop_reason", dropReasonPrefix, dropReasonNames); err != nil {
		log.Printf("[WARN] enum skb_drop_reason not found in kernel BTF: %v", err)
	}
	_ = loadEnumNames(kernelBTF, "skb_drop_reason_subsys", dropSubsysPrefix, dropSubsysNames)
	log.Printf("[INFO] Loaded %d drop reason names from kernel BTF\n", len(dropReasonNames))

	kallsyms := loadKallsyms()
	log.Printf("[INFO] Loaded %d kernel text symbols from /proc/kallsyms\n", len(kallsyms))

	// ตรวจ layout ของ tracepoint ในเคอร์เนลนี้ (เพื่อการสอน: ฝั่ง eBPF ใช้ bpf_core_field_exists แบบเดียวกัน)
	var tpStruct *btf.Struct
	if err := kernelBTF.TypeByName("trace_event_raw_kfree_skb", &tpStruct); err == nil {
		for _, m := range tpStruct.Members {
			if m.Name == "reason" || m.Name == "rx_sk" {
				log.Printf("[CO-RE] trace_event_raw_kfree_skb.%-6s at byte offset %d\n", m.Name, m.Offset.Bytes())
			}
		}
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceKfreeSkb, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to skb:kfree_skb: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.DropEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Attached to 'skb:kfree_skb'! Monitoring dropped packets live...\n")
	fmt.Printf("%-9s %-7s %-16s %-6s %-26s %-5s %-18s\n", "TIME", "PID", "COMM", "PROTO", "DROP REASON", "RX_SK", "DROP LOCATION")
	fmt.Println("-----------------------------------------------------------------------------------------------")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n[INFO] Received interrupt. Shutting down dropwatch...")
		rd.Close()
	}()

	var totalDrops uint64
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Error reading ringbuf: %v", err)
			continue
		}

		var ev dropEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		totalDrops++
		comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
		if *ipOnly && ev.Protocol != 0x0800 && ev.Protocol != 0x86DD {
			continue
		}
		if *commFilter != "" && comm != *commFilter {
			continue
		}
		rxSk := "n/a" // เคอร์เนลไม่มีฟิลด์ rx_sk (เช่น 6.8)
		if ev.HasRxSk == 1 {
			rxSk = "no"
			if ev.RxSkSet == 1 {
				rxSk = "yes"
			}
		}
		fmt.Printf("%-9s %-7d %-16s %-6s %-26s %-5s %s\n",
			time.Now().Format("15:04:05"),
			ev.Pid,
			comm,
			protoStr(ev.Protocol),
			getReasonStr(ev.Reason),
			rxSk,
			resolveKsym(kallsyms, ev.Location),
		)
	}

	fmt.Printf("\n========== Drop Summary ==========\n")
	fmt.Printf("Total Captured Dropped Packets: %d (ring buffer events, before display filters)\n", totalDrops)
	fmt.Println("Per-reason totals from BPF hash map drop_reason_stats:")

	// Dump drop_reason_stats map
	var (
		reason uint32
		count  uint64
	)
	iter := objs.DropReasonStats.Iterate()
	for iter.Next(&reason, &count) {
		fmt.Printf("  - %-26s : %d packets\n", getReasonStr(reason), count)
	}
	fmt.Println("==================================")
}
