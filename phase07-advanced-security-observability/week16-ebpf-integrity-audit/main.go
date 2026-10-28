//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf bpf_audit.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// bpfAuditEvent ต้องมี layout ตรงกับ struct bpf_audit_event ใน bpf_audit.c (64 ไบต์)
type bpfAuditEvent struct {
	TsNs       uint64
	Pid        uint32
	Uid        uint32
	Cmd        uint32
	ProgType   uint32
	Comm       [16]byte
	ProgName   [16]byte
	Source     uint8
	FromKernel uint8
	Pad        [6]byte
}

// loadAndAttach โหลดโปรแกรมเฉพาะ hook ที่เลือก แล้ว attach
//   - "fentry": fentry/__sys_bpf (หลัก) รันเฉพาะตอนมีการเรียก bpf()
//   - "raw"   : tracepoint raw_syscalls/sys_enter (สำรอง) รันทุก syscall แล้วกรองด้วยหมายเลข syscall
//   - "auto"  : ลอง fentry ก่อน ถ้าไม่ได้ (เช่น เคอร์เนลไม่มี BTF ของ __sys_bpf) จึงใช้ raw
func loadAndAttach(mode string) (*ebpf.Collection, *ebpf.Program, link.Link, string, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, nil, nil, "", err
	}
	// หมายเลข syscall ของ bpf() ขึ้นกับสถาปัตยกรรม: x/sys/unix เลือกค่าให้ตอนคอมไพล์ (amd64=321, arm64=280)
	if err := spec.RewriteConstants(map[string]interface{}{"bpf_syscall_nr": uint32(unix.SYS_BPF)}); err != nil {
		return nil, nil, nil, "", fmt.Errorf("rewrite bpf_syscall_nr: %w", err)
	}

	load := func(keep, drop string) (*ebpf.Collection, *ebpf.Program, error) {
		s := spec.Copy()
		delete(s.Programs, drop) // โหลดเฉพาะโปรแกรมที่ใช้ เพื่อไม่ให้ fentry ที่ไม่รองรับทำให้ทั้ง collection โหลดไม่ได้
		coll, err := ebpf.NewCollection(s)
		if err != nil {
			return nil, nil, err
		}
		return coll, coll.Programs[keep], nil
	}

	tryFentry := func() (*ebpf.Collection, *ebpf.Program, link.Link, error) {
		coll, prog, err := load("audit_sys_bpf", "audit_raw_sys_enter")
		if err != nil {
			return nil, nil, nil, err
		}
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			coll.Close()
			return nil, nil, nil, err
		}
		return coll, prog, l, nil
	}
	tryRaw := func() (*ebpf.Collection, *ebpf.Program, link.Link, error) {
		coll, prog, err := load("audit_raw_sys_enter", "audit_sys_bpf")
		if err != nil {
			return nil, nil, nil, err
		}
		l, err := link.Tracepoint("raw_syscalls", "sys_enter", prog, nil)
		if err != nil {
			coll.Close()
			return nil, nil, nil, err
		}
		return coll, prog, l, nil
	}

	const fentryName = "fentry/__sys_bpf"
	rawName := fmt.Sprintf("tracepoint/raw_syscalls/sys_enter (id == %d)", unix.SYS_BPF)
	switch mode {
	case "fentry":
		coll, prog, l, err := tryFentry()
		return coll, prog, l, fentryName, err
	case "raw":
		coll, prog, l, err := tryRaw()
		return coll, prog, l, rawName, err
	case "auto":
		coll, prog, l, err := tryFentry()
		if err == nil {
			return coll, prog, l, fentryName, nil
		}
		log.Printf("[WARN] %s unavailable (%v); falling back to raw_syscalls", fentryName, err)
		coll, prog, l, err = tryRaw()
		return coll, prog, l, rawName, err
	}
	return nil, nil, nil, "", fmt.Errorf("unknown -hook %q (auto|fentry|raw)", mode)
}

// ค่า enum bpf_cmd ที่ใช้ตัดสินระดับความเสี่ยง (เป็น UAPI ค่าคงที่ ไม่เปลี่ยนข้ามเวอร์ชัน)
const (
	cmdMapCreate         = 0
	cmdProgLoad          = 5
	cmdObjPin            = 6
	cmdProgAttach        = 8
	cmdProgDetach        = 9
	cmdRawTracepointOpen = 17
	cmdBTFLoad           = 18
	cmdLinkCreate        = 28
	cmdLinkUpdate        = 29
	cmdLinkDetach        = 34
	cmdTokenCreate       = 36
)

// ชื่อคำสั่งอ่านจาก enum bpf_cmd ใน Kernel BTF (ค่าเริ่มต้นใช้กรณีอ่าน BTF ไม่ได้)
var bpfCmdNames = map[uint32]string{
	0: "BPF_MAP_CREATE", 1: "BPF_MAP_LOOKUP_ELEM", 2: "BPF_MAP_UPDATE_ELEM",
	3: "BPF_MAP_DELETE_ELEM", 4: "BPF_MAP_GET_NEXT_KEY", 5: "BPF_PROG_LOAD",
	6: "BPF_OBJ_PIN", 7: "BPF_OBJ_GET", 8: "BPF_PROG_ATTACH", 9: "BPF_PROG_DETACH",
	10: "BPF_PROG_TEST_RUN", 11: "BPF_PROG_GET_NEXT_ID", 12: "BPF_MAP_GET_NEXT_ID",
	13: "BPF_PROG_GET_FD_BY_ID", 14: "BPF_MAP_GET_FD_BY_ID", 15: "BPF_OBJ_GET_INFO_BY_FD",
	16: "BPF_PROG_QUERY", 17: "BPF_RAW_TRACEPOINT_OPEN", 18: "BPF_BTF_LOAD",
	28: "BPF_LINK_CREATE", 29: "BPF_LINK_UPDATE", 34: "BPF_LINK_DETACH", 36: "BPF_TOKEN_CREATE",
}

func loadCmdNamesFromBTF() int {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return 0
	}
	var enum *btf.Enum
	if err := spec.TypeByName("bpf_cmd", &enum); err != nil {
		return 0
	}
	for _, v := range enum.Values {
		bpfCmdNames[uint32(v.Value)] = v.Name
	}
	return len(enum.Values)
}

func getCmdName(cmd uint32) string {
	if name, ok := bpfCmdNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("CMD_%d", cmd)
}

// riskOf จัดระดับความเสี่ยงของคำสั่ง: คำสั่งที่ "เปลี่ยนสถานะเคอร์เนล" สำคัญกว่าคำสั่งอ่านข้อมูล
func riskOf(cmd uint32) (label, color string, important bool) {
	switch cmd {
	case cmdProgAttach, cmdLinkCreate, cmdRawTracepointOpen, cmdLinkUpdate:
		return "ATTACH", "\033[1;31m", true
	case cmdProgLoad:
		return "PROG_LOAD", "\033[1;33m", true
	case cmdProgDetach, cmdLinkDetach:
		return "DETACH", "\033[1;33m", true
	case cmdMapCreate, cmdObjPin, cmdBTFLoad, cmdTokenCreate:
		return "NOTICE", "", true
	}
	return "INFO", "", false // lookup / get_next_id / get_info: อ่านอย่างเดียว
}

func readSysctl(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "UNKNOWN"
	}
	return strings.TrimSpace(string(data))
}

func auditHardening() {
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" [1] Host eBPF Security & Hardening Posture Assessment")
	fmt.Println("----------------------------------------------------------------------")

	unpriv := readSysctl("/proc/sys/kernel/unprivileged_bpf_disabled")
	fmt.Printf("  • kernel.unprivileged_bpf_disabled : %s ", unpriv)
	if unpriv == "1" || unpriv == "2" {
		fmt.Printf("[\033[1;32mSECURE / HARDENED\033[0m]\n")
	} else {
		fmt.Printf("[\033[1;31mVULNERABLE: Unprivileged users can load BPF\033[0m]\n")
	}

	jitHarden := readSysctl("/proc/sys/net/core/bpf_jit_harden")
	fmt.Printf("  • net.core.bpf_jit_harden          : %s ", jitHarden)
	if jitHarden == "1" || jitHarden == "2" {
		fmt.Printf("[\033[1;32mSECURE / HARDENED\033[0m]\n")
	} else {
		fmt.Printf("[\033[1;33mDEFAULT / UNHARDENED\033[0m]\n")
	}

	jitEnable := readSysctl("/proc/sys/net/core/bpf_jit_enable")
	fmt.Printf("  • net.core.bpf_jit_enable          : %s\n", jitEnable)

	lsm := readSysctl("/sys/kernel/security/lsm")
	bpfLSM := "NOT ACTIVE"
	for _, l := range strings.Split(lsm, ",") {
		if l == "bpf" {
			bpfLSM = "ACTIVE (can enforce via lsm/bpf hook)"
		}
	}
	fmt.Printf("  • BPF LSM in /sys/kernel/security/lsm : %s\n", bpfLSM)
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println()
}

// inventoryPrograms สแกนโปรแกรม eBPF ทุกตัวที่โหลดอยู่ในเคอร์เนลแล้ว (รวมตัวที่โหลดก่อน auditor เริ่ม)
// เทียบเท่า `bpftool prog list` โดยวน BPF_PROG_GET_NEXT_ID -> BPF_PROG_GET_FD_BY_ID -> BPF_OBJ_GET_INFO_BY_FD
func inventoryPrograms(selfID ebpf.ProgramID) {
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" [2] Startup Inventory: eBPF programs already loaded in the kernel")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf("  %-6s %-15s %-17s %-18s %-5s %s\n", "ID", "TYPE", "NAME", "TAG", "UID", "NOTE")

	byType := map[string]int{}
	total, failed := 0, 0
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break // ไม่มีโปรแกรมถัดไปแล้ว (ENOENT)
		}
		if err != nil {
			log.Printf("[WARN] ProgramGetNextID: %v", err)
			break
		}
		id = next

		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			failed++ // โปรแกรมอาจถูก unload ไประหว่างสแกน (race) หรือไม่มีสิทธิ์
			continue
		}
		info, err := prog.Info()
		prog.Close()
		if err != nil {
			failed++
			continue
		}
		total++
		typ := strings.TrimSuffix(info.Type.String(), "Program")
		byType[typ]++

		uid := "-"
		if u, ok := info.CreatedByUID(); ok {
			uid = fmt.Sprint(u)
		}
		note := ""
		if id == selfID {
			note = "<- this auditor"
		}
		name := info.Name
		if name == "" {
			name = "(no name)"
		}
		fmt.Printf("  %-6d %-15s %-17s %-18s %-5s %s\n", id, typ, name, info.Tag, uid, note)
	}

	var types []string
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	var parts []string
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s=%d", t, byType[t]))
	}
	fmt.Printf("  Total: %d programs (%s)", total, strings.Join(parts, ", "))
	if failed > 0 {
		fmt.Printf(", %d could not be opened", failed)
	}
	fmt.Println()
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println()
}

func main() {
	showAll := flag.Bool("all", false, "Also print read-only bpf() commands (lookups, GET_NEXT_ID, GET_INFO...)")
	hook := flag.String("hook", "auto", "Hook to audit bpf(): auto | fentry (fentry/__sys_bpf) | raw (raw_syscalls/sys_enter)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Integrity Auditor: bpf() syscall monitor + program inventory")
	fmt.Println("======================================================================")

	auditHardening()

	if n := loadCmdNamesFromBTF(); n > 0 {
		log.Printf("[INFO] Loaded %d bpf_cmd names from kernel BTF\n", n)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// หมายเหตุ: เดิมใช้ tracepoint syscalls/sys_enter_bpf แต่บน Linux 7.0.0-38 ของเครื่องทดลอง
	// พบว่า syscalls:sys_enter_* บางตัวทำงานเฉพาะบน CPU 0 จึงเปลี่ยนไปใช้ hook ที่ไม่พึ่ง tracepoint ตระกูลนี้
	coll, prog, hookLink, hookName, err := loadAndAttach(*hook)
	if err != nil {
		log.Fatalf("Failed to load/attach auditor (-hook %s): %v", *hook, err)
	}
	defer coll.Close()
	defer hookLink.Close()

	rd, err := ringbuf.NewReader(coll.Maps["bpf_audit_events"])
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// สแกน "หลัง" attach tracepoint แล้ว: โปรแกรมที่ถูกโหลดระหว่างสแกนจะยังถูกจับได้ด้วย tracepoint
	// (ถ้าสแกนก่อน attach จะมีช่องว่างเวลาที่ไม่มีใครเฝ้าดู)
	var selfID ebpf.ProgramID
	if info, err := prog.Info(); err == nil {
		selfID, _ = info.ID()
	}
	inventoryPrograms(selfID)

	log.Printf("[INFO] Hooked %s\n", hookName)
	log.Printf("[INFO] Auditing state-changing sys_bpf() calls in real time (-all for everything)...\n\n")

	fmt.Printf("%-9s %-7s %-5s %-16s %-24s %-11s %s\n",
		"TIME", "PID", "UID", "COMM", "BPF COMMAND", "RISK", "DETAIL")
	fmt.Println("------------------------------------------------------------------------------------------")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		fmt.Println("\n[INFO] Stopping BPF integrity auditor...")
		rd.Close()
	}()

	selfPid := uint32(os.Getpid())
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}

		var ev bpfAuditEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		if ev.Pid == selfPid {
			continue // ไม่รายงาน bpf() ที่ auditor เรียกเอง
		}

		label, color, important := riskOf(ev.Cmd)
		if !important && !*showAll {
			continue
		}

		detail := ""
		if ev.FromKernel == 1 {
			detail = "[in-kernel caller] "
		}
		if ev.Cmd == cmdProgLoad {
			typ := strings.TrimSuffix(ebpf.ProgramType(ev.ProgType).String(), "Program")
			detail += fmt.Sprintf("type=%s name=%q", typ, string(bytes.TrimRight(ev.ProgName[:], "\x00")))
		}

		risk := fmt.Sprintf("%-11s", label)
		if color != "" {
			risk = color + risk + "\033[0m"
		}
		fmt.Printf("%-9s %-7d %-5d %-16s %-24s %s %s\n",
			time.Now().Format("15:04:05"),
			ev.Pid,
			ev.Uid,
			string(bytes.TrimRight(ev.Comm[:], "\x00")),
			getCmdName(ev.Cmd),
			risk,
			detail,
		)
	}

	fmt.Println("[SUCCESS] BPF Integrity Auditor stopped safely.")
}
