//go:build linux
// +build linux

package main

// Runtime tests (BPF_PROG_TEST_RUN) สำหรับ Week 24:
//   - kfuncs: bpf_task_from_pid/bpf_task_release + bpf_cpumask_* ให้ผลตรงกับ /proc และ sched_getaffinity
//   - verifier ปฏิเสธการใช้ kfunc ผิดกฎ (ลืม release, ลืมเช็ก NULL, use-after-release, ผิด program type)
//   - arena: linked list ที่ BPF สร้าง ถูกอ่านจาก Go ผ่าน mmap ได้ถูกต้อง, page fault semantics, ขีดจำกัด
//
// Run with: make test   (equivalent to: go test -exec sudo -v ./...)

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (run: make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
}

func mustLoadKfunc(t *testing.T) *kfuncObjects {
	t.Helper()
	requireRoot(t)
	var objs kfuncObjects
	if err := loadKfuncObjects(&objs, nil); err != nil {
		t.Fatalf("load kfunc objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// requireArena ข้ามการทดสอบบนเคอร์เนลที่ไม่มี BPF_MAP_TYPE_ARENA (ต่ำกว่า 6.9)
func requireArena(t *testing.T) {
	t.Helper()
	requireRoot(t)
	if err := features.HaveMapType(ebpf.Arena); err != nil {
		t.Skipf("kernel without BPF arena support: %v", err)
	}
}

func newLab(t *testing.T) *arenaLab {
	t.Helper()
	requireArena(t)
	lab, err := newArenaLab()
	if err != nil {
		t.Fatalf("arena setup: %v", err)
	}
	t.Cleanup(lab.Close)
	return lab
}

// --- kfuncs -----------------------------------------------------------------

func TestQueryTaskSelf(t *testing.T) {
	objs := mustLoadKfunc(t)

	q, err := queryTask(objs.QueryTask, int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if q.Found != 1 {
		t.Fatalf("own pid %d not found", os.Getpid())
	}
	if int(q.Tgid) != os.Getpid() || int(q.Ppid) != os.Getppid() {
		t.Errorf("tgid/ppid = %d/%d, want %d/%d", q.Tgid, q.Ppid, os.Getpid(), os.Getppid())
	}
	comm, _ := os.ReadFile("/proc/self/comm")
	if got, want := commString(q.Comm), strings.TrimSpace(string(comm)); got != want {
		t.Errorf("comm = %q, want %q", got, want)
	}
	if q.HasVpidKfunc != 1 || q.HasFakeKfunc != 0 {
		t.Errorf("bpf_ksym_exists: vpid=%d fake=%d, want 1/0", q.HasVpidKfunc, q.HasFakeKfunc)
	}
	t.Logf("pid %d: tgid=%d ppid=%d comm=%q cpus=%d", os.Getpid(), q.Tgid, q.Ppid, commString(q.Comm), q.NrCpusAllowed)
}

// bpf_task_from_pid รับ TID ได้ด้วย (ในเคอร์เนลทุก thread คือ task) — จำกัด affinity ของ thread นี้ให้เหลือ 1 CPU
// แล้วตรวจว่า bpf_cpumask_copy(t->cpus_ptr) + bpf_cpumask_weight เห็นค่าเดียวกัน
func TestQueryTaskThreadAffinity(t *testing.T) {
	objs := mustLoadKfunc(t)

	type result struct {
		q   kfuncTaskQuery
		tid int
		err error
	}
	ch := make(chan result)
	go func() {
		// ไม่ Unlock: เมื่อ goroutine จบ Go runtime จะทิ้ง thread ที่ถูกแก้ affinity นี้ไปเลย
		runtime.LockOSThread()
		var set unix.CPUSet
		set.Set(0)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			ch <- result{err: err}
			return
		}
		tid := unix.Gettid()
		q, err := queryTask(objs.QueryTask, int32(tid))
		ch <- result{q, tid, err}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.q.Found != 1 || int(r.q.Tgid) != os.Getpid() {
		t.Fatalf("tid %d: found=%d tgid=%d, want found=1 tgid=%d", r.tid, r.q.Found, r.q.Tgid, os.Getpid())
	}
	if r.q.NrCpusAllowed != 1 {
		t.Errorf("tid %d pinned to CPU0: nr_cpus_allowed=%d, want 1", r.tid, r.q.NrCpusAllowed)
	}

	var all unix.CPUSet
	if err := unix.SchedGetaffinity(os.Getpid(), &all); err != nil {
		t.Fatal(err)
	}
	q, err := queryTask(objs.QueryTask, int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if int(q.NrCpusAllowed) != all.Count() {
		t.Errorf("main thread nr_cpus_allowed=%d, sched_getaffinity=%d", q.NrCpusAllowed, all.Count())
	}
}

func TestQueryTaskMissing(t *testing.T) {
	objs := mustLoadKfunc(t)
	q, err := queryTask(objs.QueryTask, 0x3fffffff) // มากกว่า pid_max สูงสุด (4194304)
	if err != nil {
		t.Fatal(err)
	}
	if q.Found != 0 {
		t.Errorf("found=%d for nonexistent pid, want 0", q.Found)
	}
}

func TestBrokenProgramsRejected(t *testing.T) {
	requireRoot(t)
	want := map[string]string{
		"leak_task":         "Unreleased reference",
		"no_null_check":     "invalid mem access 'trusted_ptr_or_null_'",
		"use_after_release": "invalid mem access 'scalar'",
		"wrong_prog_type":   "calling kernel function bpf_task_from_pid is not allowed",
	}
	for _, name := range brokenOrder {
		t.Run(name, func(t *testing.T) {
			err := loadBrokenProgram(name)
			if err == nil {
				t.Fatal("verifier accepted a program that must be rejected")
			}
			var ve *ebpf.VerifierError
			if !errors.As(err, &ve) {
				t.Fatalf("not a verifier error: %v", err)
			}
			if full := fmt.Sprintf("%+v", err); !strings.Contains(full, want[name]) {
				t.Fatalf("verifier log does not contain %q:\n%s", want[name], strings.Join(verifierTail(err, 5), "\n"))
			}
		})
	}
}

// --- arena ------------------------------------------------------------------

func TestArenaUpsertAndWalk(t *testing.T) {
	lab := newLab(t)

	const n, keys = 1000, 8
	want := map[uint64][2]uint64{}
	addr := map[uint64]uint64{}
	for i := 0; i < n; i++ {
		k := uint64(i % keys)
		r, err := lab.upsert(k, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		w := want[k]
		want[k] = [2]uint64{w[0] + 1, w[1] + uint64(i)}
		addr[k] = r.NodeAddr
	}

	h, nodes, err := lab.walk()
	if err != nil {
		t.Fatal(err)
	}
	if h.NrNodes != keys || len(nodes) != keys {
		t.Fatalf("nr_nodes=%d walked=%d, want %d", h.NrNodes, len(nodes), keys)
	}
	if h.Pages != 1 {
		t.Errorf("pages=%d, want 1 (header + %d nodes fit in one page)", h.Pages, keys)
	}
	for _, nd := range nodes {
		w := want[nd.Key]
		if nd.Count != w[0] || nd.Sum != w[1] {
			t.Errorf("key %d: count/sum=%d/%d, want %d/%d", nd.Key, nd.Count, nd.Sum, w[0], w[1])
		}
		// pointer ที่ BPF คืนผ่าน ctx ต้องเป็นค่าเดียวกับที่ Go เดินเจอใน list
		if nd.Addr != addr[nd.Key] {
			t.Errorf("key %d: list ptr %#x != returned ptr %#x", nd.Key, nd.Addr, addr[nd.Key])
		}
	}
}

// pointer ที่ BPF เขียนลง arena คือ address ใน process ของเราเอง: ฐาน (h.Self) ต้องเป็นจุดเริ่มของ mapping
func TestArenaPointersAreUserAddresses(t *testing.T) {
	lab := newLab(t)
	if _, err := lab.upsert(42, 1); err != nil {
		t.Fatal(err)
	}
	h, err := lab.header()
	if err != nil {
		t.Fatal(err)
	}
	m := mappingOf(h.Self)
	if !strings.Contains(m, "bpf-map") {
		t.Fatalf("arena base %#x is not the start of a bpf-map mapping in /proc/self/maps (got %q)", h.Self, m)
	}
	t.Logf("%s", m)
}

func TestArenaPageFaults(t *testing.T) {
	lab := newLab(t)
	if _, err := lab.upsert(1, 1); err != nil { // จองหน้า 0
		t.Fatal(err)
	}

	// หน้า 0 จองแล้ว: BPF เขียนได้ และ Go เห็นค่าทันที (shared memory)
	r, err := lab.peek(4088)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := lab.readU64(4088); r.After != 0xC0FFEE || v != 0xC0FFEE {
		t.Errorf("allocated page: bpf after=%#x go=%#x, want 0xc0ffee", r.After, v)
	}

	// หน้า 8 ยังไม่จอง: load ได้ 0, store ถูกทิ้ง (ไม่มี kernel oops)
	const off = 8 * 4096
	r, err = lab.peek(off)
	if err != nil {
		t.Fatal(err)
	}
	if r.Before != 0 || r.After != 0 {
		t.Errorf("unallocated page: before=%#x after=%#x, want 0/0", r.Before, r.After)
	}

	// Go แตะหน้านั้น -> fault ฝั่ง user ทำให้เคอร์เนลจองหน้าให้ -> BPF เขียนได้แล้ว
	if v, err := lab.readU64(off); err != nil || v != 0 {
		t.Fatalf("go read of fresh page = %#x, %v", v, err)
	}
	r, err = lab.peek(off)
	if err != nil {
		t.Fatal(err)
	}
	if r.After != 0xC0FFEE {
		t.Errorf("after user fault: after=%#x, want 0xc0ffee", r.After)
	}
}

// การที่ Go อ่านหน้าที่ยังไม่จอง "กิน" หน้านั้นไปจาก arena: allocator ของ BPF จะข้ามไปหน้าถัดไป
func TestArenaUserFaultConsumesPage(t *testing.T) {
	const nodesInPage0 = (4096 - 48) / 32 // header 48 B, node 32 B -> 126 nodes ในหน้า 0
	for _, tc := range []struct {
		name     string
		goTouch  bool
		wantPage uint64
	}{{"no user fault", false, 1}, {"go touched page 1", true, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			lab := newLab(t)
			if tc.goTouch {
				if _, err := lab.readU64(4096); err != nil {
					t.Fatal(err)
				}
			}
			var last arenaUpsertArgs
			var err error
			for k := uint64(0); k <= nodesInPage0; k++ { // node ที่ 127 ต้องขึ้นหน้าใหม่
				if last, err = lab.upsert(k, 1); err != nil {
					t.Fatal(err)
				}
			}
			h, err := lab.header()
			if err != nil {
				t.Fatal(err)
			}
			if page := (last.NodeAddr - h.Self) / 4096; page != tc.wantPage {
				t.Errorf("node #%d landed on page %d, want %d", nodesInPage0+1, page, tc.wantPage)
			}
		})
	}
}

func TestArenaWalkLimit(t *testing.T) {
	lab := newLab(t)
	var k uint64
	var err error
	for k = 0; k < 600; k++ {
		if _, err = lab.upsert(k, 1); err != nil {
			break
		}
	}
	if err == nil || !strings.Contains(err.Error(), "errno 7") {
		t.Fatalf("expected E2BIG once the list outgrows MAX_WALK, got %v after %d keys", err, k)
	}
	h, _ := lab.header()
	if h.NrNodes != 513 { // MAX_WALK (512) + 1
		t.Errorf("nr_nodes=%d when E2BIG hit, want 513", h.NrNodes)
	}
}

func TestArenaRequiresMmapBeforeLoad(t *testing.T) {
	requireArena(t)
	var objs arenaObjects
	err := loadArenaObjects(&objs, nil) // โหลดตรง ๆ โดยยังไม่ mmap
	if err == nil {
		objs.Close()
		t.Fatal("expected load to fail before the arena is mmap()ed")
	}
	if !strings.Contains(err.Error(), "arena's user address must be set via map_extra or mmap()") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestArenaCreateLimits(t *testing.T) {
	requireArena(t)
	cases := []struct {
		name  string
		pages uint32
		flags uint32
		ok    bool
	}{
		{"4GiB (1<<20 pages) ok", 1 << 20, unix.BPF_F_MMAPABLE, true},
		{"4GiB + 1 page", 1<<20 + 1, unix.BPF_F_MMAPABLE, false},
		{"without BPF_F_MMAPABLE", 16, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Arena, MaxEntries: c.pages, Flags: c.flags})
			if err == nil {
				m.Close()
			}
			if (err == nil) != c.ok {
				t.Fatalf("NewMap err=%v, want ok=%v", err, c.ok)
			}
			if err != nil {
				t.Logf("%v", err)
			}
		})
	}
}
