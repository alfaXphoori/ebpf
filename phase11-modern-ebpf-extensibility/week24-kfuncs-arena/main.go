//go:build linux
// +build linux

package main

// bpf2go 3 ชุด: kfunc (โปรแกรมที่ถูกต้อง), broken (โปรแกรมที่ verifier ต้องปฏิเสธ), arena
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" -type task_query kfunc task_kfunc.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" broken task_kfunc_broken.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" -type upsert_args -type peek_args arena arena_list.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// ---------------------------------------------------------------------------
// Part 1: kfuncs
// ---------------------------------------------------------------------------

// queryTask เรียกโปรแกรม SEC("syscall") ด้วย BPF_PROG_TEST_RUN: ctx เข้า = pid, ctx ออก = ผลลัพธ์
func queryTask(prog *ebpf.Program, pid int32) (kfuncTaskQuery, error) {
	q := kfuncTaskQuery{Pid: pid}
	if _, err := prog.Run(&ebpf.RunOptions{Context: &q, ContextOut: &q}); err != nil {
		return q, err
	}
	return q, nil
}

func commString(c [16]int8) string {
	b := make([]byte, 0, len(c))
	for _, v := range c {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

// brokenOrder กำหนดลำดับการแสดงผลของโปรแกรมใน task_kfunc_broken.c
var brokenOrder = []string{"leak_task", "no_null_check", "use_after_release", "wrong_prog_type"}

// loadBrokenProgram โหลดโปรแกรมที่ "ต้องพัง" ทีละตัว แล้วคืน error ของ verifier
func loadBrokenProgram(name string) error {
	spec, err := loadBroken()
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	ps, ok := spec.Programs[name]
	if !ok {
		return fmt.Errorf("program %q not in spec", name)
	}
	prog, err := ebpf.NewProgram(ps)
	if err == nil {
		prog.Close()
	}
	return err
}

// verifierTail คืนบรรทัดท้าย ๆ ของ verifier log (ส่วนที่บอกสาเหตุจริง)
func verifierTail(err error, n int) []string {
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return []string{err.Error()}
	}
	var lines []string
	for _, l := range ve.Log {
		if strings.HasPrefix(l, "processed ") || strings.TrimSpace(l) == "" {
			continue
		}
		lines = append(lines, l)
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// ---------------------------------------------------------------------------
// Part 2: BPF Arena
// ---------------------------------------------------------------------------

// arenaHdr / arenaNode ต้องตรงกับ struct arena_hdr / arena_node ใน arena_list.c ทุกไบต์
// (bpf2go ไม่สร้าง Go type ให้ struct ที่มี pointer field จึงเขียนเอง; pointer = uint64)
type arenaHdr struct {
	Magic     uint64
	Self      uint64 // address ของ header ใน process นี้ = ฐานของ arena mapping
	Head      uint64 // struct arena_node __arena *
	NrNodes   uint64
	Pages     uint64
	BytesUsed uint64
}

type arenaNode struct {
	Next  uint64 // struct arena_node __arena *
	Key   uint64
	Count uint64
	Sum   uint64
}

const arenaMagic = 0x3432454e45524121 // "!ARENE24"

type arenaLab struct {
	objs arenaObjects
	m    *ebpf.Map    // arena map ตัวที่เรา mmap เอง
	mem  *ebpf.Memory // mmap ของ arena (Map.Memory ใน cilium/ebpf v0.22; v0.16 ยังไม่มี)
}

// newArenaLab: ลำดับสำคัญ — ต้องสร้าง map และ mmap() ก่อนโหลดโปรแกรม
// เพราะ verifier/JIT ต้องรู้ address ฝั่ง user (user_vm_start) ตอน BPF_PROG_LOAD
// ถ้าใช้ loadArenaObjects() ตรง ๆ จะได้ "arena's user address must be set via map_extra or mmap()"
func newArenaLab() (*arenaLab, error) {
	spec, err := loadArena()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	m, err := ebpf.NewMap(spec.Maps["arena"])
	if err != nil {
		return nil, fmt.Errorf("create arena map: %w", err)
	}
	mem, err := m.Memory()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("mmap arena: %w", err)
	}
	lab := &arenaLab{m: m, mem: mem}
	err = spec.LoadAndAssign(&lab.objs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{"arena": m},
	})
	if err != nil {
		m.Close()
		if strings.Contains(err.Error(), "BPF_MOV uses reserved fields") {
			err = fmt.Errorf("%w\n(hint: cilium/ebpf v0.22.0 ทำ addr_space_cast เสีย — build ผ่าน `make` ที่ patch vendor/ ให้)", err)
		}
		return nil, err
	}
	return lab, nil
}

func (a *arenaLab) Close() {
	a.objs.Close()
	a.m.Close()
}

func (a *arenaLab) upsert(key, value uint64) (arenaUpsertArgs, error) {
	args := arenaUpsertArgs{Key: key, Value: value}
	if _, err := a.objs.ArenaUpsert.Run(&ebpf.RunOptions{Context: &args, ContextOut: &args}); err != nil {
		return args, err
	}
	if args.Err != 0 {
		return args, fmt.Errorf("arena_upsert: errno %d", -args.Err)
	}
	return args, nil
}

func (a *arenaLab) peek(off uint64) (arenaPeekArgs, error) {
	args := arenaPeekArgs{Off: off}
	if _, err := a.objs.ArenaPeek.Run(&ebpf.RunOptions{Context: &args, ContextOut: &args}); err != nil {
		return args, err
	}
	if args.Err != 0 {
		return args, fmt.Errorf("arena_peek: errno %d", -args.Err)
	}
	return args, nil
}

// readAt อ่าน struct จาก arena mapping โดยตรง (memcpy จาก mmap — ไม่มี syscall)
func (a *arenaLab) readAt(off uint64, v any) error {
	size := uint64(binary.Size(v))
	if off+size > uint64(a.mem.Size()) {
		return fmt.Errorf("offset %#x+%d outside arena (%d bytes)", off, size, a.mem.Size())
	}
	return binary.Read(io.NewSectionReader(a.mem, int64(off), int64(size)), binary.NativeEndian, v)
}

func (a *arenaLab) readU64(off uint64) (uint64, error) {
	var v uint64
	err := a.readAt(off, &v)
	return v, err
}

func (a *arenaLab) header() (arenaHdr, error) {
	var h arenaHdr
	if err := a.readAt(0, &h); err != nil {
		return h, err
	}
	if h.Magic != arenaMagic {
		return h, fmt.Errorf("no header at arena offset 0 (magic %#x)", h.Magic)
	}
	return h, nil
}

type walkedNode struct {
	arenaNode
	Addr uint64 // pointer ตามที่ BPF เขียน (user address)
	Off  uint64 // Addr - base
}

// walk เดิน linked list ที่ BPF สร้าง โดยตาม pointer `next` ใน Go เอง
// pointer ใน arena เป็น user address ของ process นี้ จึงแปลงเป็น offset ด้วย ptr - base
func (a *arenaLab) walk() (arenaHdr, []walkedNode, error) {
	h, err := a.header()
	if err != nil {
		return h, nil, err
	}
	var out []walkedNode
	for p := h.Head; p != 0; {
		if p < h.Self || len(out) > int(h.NrNodes) {
			return h, out, fmt.Errorf("corrupt list at %#x", p)
		}
		var n arenaNode
		if err := a.readAt(p-h.Self, &n); err != nil {
			return h, out, err
		}
		out = append(out, walkedNode{arenaNode: n, Addr: p, Off: p - h.Self})
		p = n.Next
	}
	return h, out, nil
}

// mappingOf ค้นหาบรรทัดใน /proc/self/maps ที่เริ่มตรง addr (พิสูจน์ว่า pointer ที่ BPF เขียนคือ address ใน process เรา)
func mappingOf(addr uint64) string {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return ""
	}
	prefix := fmt.Sprintf("%x-", addr)
	for _, l := range bytes.Split(data, []byte("\n")) {
		if bytes.HasPrefix(l, []byte(prefix)) {
			return string(l)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------

func main() {
	pid := flag.Int("pid", 1, "PID ที่จะให้ kfunc bpf_task_from_pid() ค้นหา (นอกเหนือจาก PID ของตัวเอง)")
	n := flag.Int("n", 1000, "จำนวนครั้งที่เรียก arena_upsert")
	keys := flag.Int("keys", 8, "จำนวน key ที่ไม่ซ้ำกัน (key = i % keys)")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	fmt.Println("======================================================================")
	fmt.Println(" Week 24 Part 1: kfuncs (bpf_task_from_pid / bpf_task_release / bpf_cpumask_*)")
	fmt.Println("======================================================================")

	var kobjs kfuncObjects
	if err := loadKfuncObjects(&kobjs, nil); err != nil {
		log.Fatalf("Failed to load kfunc program: %v", err)
	}
	defer kobjs.Close()

	fmt.Printf("%-8s %-6s %-8s %-8s %-6s %-16s\n", "PID", "FOUND", "TGID", "PPID", "CPUS", "COMM")
	var first kfuncTaskQuery
	for i, p := range []int32{int32(os.Getpid()), int32(*pid), 0x3fffffff} {
		q, err := queryTask(kobjs.QueryTask, p)
		if err != nil {
			log.Fatalf("query_task(%d): %v", p, err)
		}
		if i == 0 {
			first = q
		}
		if q.Found == 0 {
			fmt.Printf("%-8d %-6s (bpf_task_from_pid คืน NULL)\n", p, "no")
			continue
		}
		fmt.Printf("%-8d %-6s %-8d %-8d %-6d %-16s\n", p, "yes", q.Tgid, q.Ppid, q.NrCpusAllowed, commString(q.Comm))
	}
	fmt.Printf("bpf_ksym_exists(bpf_task_from_vpid)       = %d\n", first.HasVpidKfunc)
	fmt.Printf("bpf_ksym_exists(bpf_week24_no_such_kfunc) = %d\n", first.HasFakeKfunc)

	fmt.Println()
	fmt.Println("--- Verifier vs. broken kfunc usage (task_kfunc_broken.c) ---")
	for _, name := range brokenOrder {
		err := loadBrokenProgram(name)
		if err == nil {
			fmt.Printf("[%s] UNEXPECTED: loaded fine\n", name)
			continue
		}
		fmt.Printf("[%s] rejected:\n", name)
		for _, l := range verifierTail(err, 2) {
			fmt.Printf("    %s\n", l)
		}
	}

	fmt.Println()
	fmt.Println("======================================================================")
	fmt.Println(" Week 24 Part 2: BPF Arena (BPF_MAP_TYPE_ARENA + mmap ใน Go)")
	fmt.Println("======================================================================")

	lab, err := newArenaLab()
	if err != nil {
		log.Fatalf("Failed to set up arena: %v", err)
	}
	defer lab.Close()
	fmt.Printf("arena: max %d pages, mmap %d bytes (ReadOnly=%v)\n", lab.m.MaxEntries(), lab.mem.Size(), lab.mem.ReadOnly())

	want := map[uint64][2]uint64{}
	for i := 0; i < *n; i++ {
		k := uint64(i % *keys)
		if _, err := lab.upsert(k, uint64(i)); err != nil {
			log.Fatalf("upsert #%d: %v", i, err)
		}
		w := want[k]
		want[k] = [2]uint64{w[0] + 1, w[1] + uint64(i)}
	}

	h, nodes, err := lab.walk()
	if err != nil {
		log.Fatalf("walk: %v", err)
	}
	fmt.Printf("header @ offset 0: base(self)=%#x nr_nodes=%d pages=%d bytes_used=%d\n",
		h.Self, h.NrNodes, h.Pages, h.BytesUsed)
	if m := mappingOf(h.Self); m != "" {
		fmt.Printf("/proc/self/maps : %s\n", m)
	}
	fmt.Printf("%d upserts with %d keys -> Go walked %d nodes by following arena pointers:\n", *n, *keys, len(nodes))
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Key < nodes[j].Key })
	fmt.Printf("  %-4s %-7s %-9s %-16s %-7s %s\n", "KEY", "COUNT", "SUM", "NODE PTR", "OFFSET", "CHECK")
	for _, nd := range nodes {
		check := "ok"
		if w := want[nd.Key]; w[0] != nd.Count || w[1] != nd.Sum {
			check = fmt.Sprintf("MISMATCH want %v", w)
		}
		fmt.Printf("  %-4d %-7d %-9d %#-16x %#-7x %s\n", nd.Key, nd.Count, nd.Sum, nd.Addr, nd.Off, check)
	}

	fmt.Println()
	fmt.Println("--- Page faults: BPF access ไปยังหน้าที่ยังไม่ได้จอง ---")
	inUse := uint64(4088)       // 8 ไบต์สุดท้ายของหน้า 0: จองแล้วแต่ไม่มี node ใดใช้ (48 + 126*32 = 4080)
	unalloc := uint64(8 * 4096) // หน้า 8: ยังไม่มีใครจอง
	r1, err := lab.peek(inUse)
	if err != nil {
		log.Fatal(err)
	}
	v, _ := lab.readU64(inUse)
	fmt.Printf("BPF  peek off=%#-6x (allocated page)   before=%#x after=%#x | Go reads %#x\n", inUse, r1.Before, r1.After, v)
	r2, err := lab.peek(unalloc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BPF  peek off=%#-6x (unallocated page) before=%#x after=%#x (store dropped)\n", unalloc, r2.Before, r2.After)
	v, _ = lab.readU64(unalloc)
	fmt.Printf("Go   read off=%#-6x -> %#x (user-space fault ทำให้เคอร์เนลจองหน้านี้ให้)\n", unalloc, v)
	r3, err := lab.peek(unalloc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BPF  peek off=%#-6x again              before=%#x after=%#x (หน้าถูกจองแล้ว)\n", unalloc, r3.Before, r3.After)
}
