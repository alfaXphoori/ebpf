//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf cpu_stacks.c

import (
	"bufio"
	"bytes"
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
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const maxStackDepth = 127 // ต้องตรงกับ MAX_STACK_DEPTH ใน cpu_stacks.c

// ดัชนีของ stats map (ตรงกับ enum ใน cpu_stacks.c)
const (
	statSamples = iota
	statKernEexist
	statUserEexist
	statCountsFull
	statMax
)

// ===========================================================================
// 1) เปิด perf event แบบ CPU clock ทุก CPU แล้วแนบโปรแกรม SEC("perf_event")
// ===========================================================================

// onlineCPUs อ่านรายการ CPU ที่ออนไลน์จาก /sys (รูปแบบ "0-3,6,8-11")
func onlineCPUs() ([]int, error) {
	raw, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	var cpus []int
	for _, part := range strings.Split(strings.TrimSpace(string(raw)), ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		start, err := strconv.Atoi(lo)
		if err != nil {
			return nil, err
		}
		end := start
		if isRange {
			if end, err = strconv.Atoi(hi); err != nil {
				return nil, err
			}
		}
		for c := start; c <= end; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus, nil
}

// perfSampler เก็บ fd ของ perf event และ link ของแต่ละ CPU ไว้ปิดตอนจบ
type perfSampler struct {
	fds   []int
	links []link.Link
}

func (s *perfSampler) Close() {
	for _, l := range s.links {
		l.Close()
	}
	for _, fd := range s.fds {
		unix.Close(fd)
	}
}

func attachPerfSampler(prog *ebpf.Program, freq uint64) (*perfSampler, error) {
	cpus, err := onlineCPUs()
	if err != nil {
		return nil, fmt.Errorf("read online CPUs: %w", err)
	}

	s := &perfSampler{}
	for _, cpu := range cpus {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: freq,             // เมื่อเปิด PerfBitFreq ฟิลด์นี้คือความถี่ (Hz) ไม่ใช่ period
			Bits:   unix.PerfBitFreq, // ไม่ตั้ง PerfBitDisabled => event เริ่มนับทันที
		}
		// pid = -1, cpu = N  => นับ "ทุกงาน" ที่รันบน CPU N (system-wide ต่อ CPU)
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("perf_event_open(cpu=%d): %w", cpu, err)
		}
		s.fds = append(s.fds, fd)

		// ทางหลัก: BPF link (BPF_LINK_CREATE + BPF_PERF_EVENT, Linux >= 5.15)
		l, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  fd,
			Program: prog,
			Attach:  ebpf.AttachPerfEvent,
		})
		if err == nil {
			s.links = append(s.links, l)
			continue
		}
		// ทางสำรองสำหรับเคอร์เนลเก่า: ioctl(PERF_EVENT_IOC_SET_BPF) ผูกโปรแกรมกับ fd ตรง ๆ
		// (โปรแกรมจะหลุดเมื่อ fd ถูกปิดใน Close())
		if ioErr := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); ioErr != nil {
			s.Close()
			return nil, fmt.Errorf("attach perf_event on cpu %d: link: %v, ioctl: %w", cpu, err, ioErr)
		}
	}
	return s, nil
}

// ===========================================================================
// 2) Symbolization: kernel ผ่าน /proc/kallsyms, user ผ่าน /proc/<pid>/maps + ELF
// ===========================================================================

type ksymbol struct {
	addr uint64
	name string
}

var ksymbols []ksymbol

func loadKallsyms() {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 3 {
			continue
		}
		// เก็บเฉพาะสัญลักษณ์ในส่วน text (t/T/w/W) เพื่อไม่ให้ data symbol มาบัง
		switch parts[1] {
		case "t", "T", "w", "W":
		default:
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err == nil && addr != 0 {
			ksymbols = append(ksymbols, ksymbol{addr: addr, name: parts[2]})
		}
	}
	sort.Slice(ksymbols, func(i, j int) bool {
		return ksymbols[i].addr < ksymbols[j].addr
	})
	if len(ksymbols) == 0 {
		log.Printf("[WARN] /proc/kallsyms has no usable addresses (run as root / check kptr_restrict)")
	}
	log.Printf("[INFO] Loaded %d text symbols from /proc/kallsyms\n", len(ksymbols))
}

func resolveKaddr(addr uint64) string {
	idx := sort.Search(len(ksymbols), func(i int) bool {
		return ksymbols[i].addr > addr
	})
	if idx > 0 {
		return ksymbols[idx-1].name
	}
	return fmt.Sprintf("0x%x", addr)
}

// ===========================================================================
// 3) Profiler main
// ===========================================================================

type stackKey struct {
	Pid           uint32
	KernelStackID int32
	UserStackID   int32
	Comm          [16]byte
}

type stackEntry struct {
	key   stackKey
	count uint64
}

func main() {
	freq := flag.Uint64("F", 99, "ความถี่การสุ่มต่อ CPU (Hz)")
	duration := flag.Duration("d", 0, "ระยะเวลาเก็บโปรไฟล์ (0 = จนกว่าจะกด Ctrl+C)")
	pid := flag.Uint("p", 0, "โปรไฟล์เฉพาะ PID (TGID) นี้ (0 = ทั้งระบบ)")
	idle := flag.Bool("idle", false, "นับ Sample ของ idle task (PID 0) ด้วย")
	folded := flag.String("folded", "", "เขียนผลแบบ folded stacks สำหรับ flamegraph.pl ลงไฟล์นี้")
	top := flag.Int("top", 5, "จำนวน Call Chain ที่พิมพ์บนหน้าจอ")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF On-CPU Profiler & Stack Collector (perf_event + Flame Graph)")
	fmt.Println("======================================================================")

	loadKallsyms()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}
	// เขียนค่าตัวกรองลง .rodata ก่อนโหลดเข้าเคอร์เนล
	includeIdle := uint8(0)
	if *idle {
		includeIdle = 1
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"targ_pid":     uint32(*pid),
		"include_idle": includeIdle,
	}); err != nil {
		log.Fatalf("Failed to rewrite constants: %v", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	sampler, err := attachPerfSampler(objs.DoSample, *freq)
	if err != nil {
		log.Fatalf("Failed to attach perf_event sampler: %v", err)
	}
	defer sampler.Close()

	target := "all processes"
	if *pid != 0 {
		target = fmt.Sprintf("PID %d", *pid)
	}
	log.Printf("[INFO] Sampling on-CPU stacks at %d Hz on %d CPUs (%s) via PERF_COUNT_SW_CPU_CLOCK",
		*freq, len(sampler.fds), target)
	log.Printf("[INFO] Profile collecting. Press Ctrl+C to terminate and view top stacks.\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	var timeout <-chan time.Time
	if *duration > 0 {
		timeout = time.After(*duration)
	}

	syms := newUserSymbolizer()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ticker.C:
			var (
				key          stackKey
				val          uint64
				totalSamples uint64
				uniqueChains int
			)
			iter := objs.StackCounts.Iterate()
			for iter.Next(&key, &val) {
				totalSamples += val
				uniqueChains++
				// จำ memory map ของโปรเซสไว้ก่อนที่มันอาจจะจบไป
				syms.snapshot(key.Pid)
			}
			fmt.Printf("[%s] On-CPU Samples: %-8d | Unique Call Chains: %-6d\n",
				time.Now().Format("15:04:05"), totalSamples, uniqueChains)

		case <-timeout:
			break loop
		case <-stopper:
			break loop
		}
	}

	// หยุดการสุ่มก่อนอ่านผล เพื่อให้ตัวเลขนิ่ง
	sampler.Close()
	fmt.Println("\n[INFO] Sampler detached. Rendering top on-CPU call chains...")

	var entries []stackEntry
	var (
		key stackKey
		val uint64
	)
	iter := objs.StackCounts.Iterate()
	for iter.Next(&key, &val) {
		entries = append(entries, stackEntry{key: key, count: val})
		syms.snapshot(key.Pid)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	printStats(&objs, entries)

	limit := *top
	if len(entries) < limit {
		limit = len(entries)
	}

	fmt.Println("\n=================== TOP ON-CPU CALL CHAINS ===================")
	for i := 0; i < limit; i++ {
		e := entries[i]
		comm := string(bytes.TrimRight(e.key.Comm[:], "\x00"))
		fmt.Printf("\n#%d [%s (PID: %d)] - Sample Count: %d\n", i+1, comm, e.key.Pid, e.count)

		kframes := lookupStack(&objs, e.key.KernelStackID)
		for _, ip := range kframes {
			fmt.Printf("    [k] %s\n", resolveKaddr(ip))
		}
		uframes := lookupStack(&objs, e.key.UserStackID)
		for _, ip := range uframes {
			fmt.Printf("    [u] %s\n", syms.resolve(e.key.Pid, ip))
		}
		if len(kframes) == 0 && len(uframes) == 0 {
			fmt.Printf("    (no stack: kernel id %d, user id %d)\n", e.key.KernelStackID, e.key.UserStackID)
		}
	}
	fmt.Println("==============================================================")

	if *folded != "" {
		n, err := writeFolded(*folded, &objs, entries, syms)
		if err != nil {
			log.Fatalf("Failed to write folded stacks: %v", err)
		}
		log.Printf("[INFO] Wrote %d folded stack lines to %s", n, *folded)
		log.Printf("[INFO] Render: ./flamegraph.pl %s > cpu.svg", *folded)
	}
}

// lookupStack คืน IP เรียงจากเฟรมในสุด (leaf) ไปหาเฟรมนอกสุด
// stack id ติดลบ = ไม่มี stack (-EFAULT: kernel thread ไม่มี user stack, -EEXIST: hash ชน)
func lookupStack(objs *bpfObjects, id int32) []uint64 {
	if id < 0 {
		return nil
	}
	var raw [maxStackDepth]uint64
	sid := uint32(id)
	if err := objs.StackTraces.Lookup(&sid, &raw); err != nil {
		return nil
	}
	var ips []uint64
	for _, ip := range raw {
		if ip == 0 {
			break
		}
		ips = append(ips, ip)
	}
	return ips
}

func printStats(objs *bpfObjects, entries []stackEntry) {
	var total [statMax]uint64
	for i := uint32(0); i < statMax; i++ {
		var perCPU []uint64
		if err := objs.Stats.Lookup(&i, &perCPU); err == nil {
			for _, v := range perCPU {
				total[i] += v
			}
		}
	}
	var recorded uint64
	for _, e := range entries {
		recorded += e.count
	}
	fmt.Printf("[STATS] perf samples fired: %d | recorded (after idle/PID filter): %d | unique chains: %d\n",
		total[statSamples], recorded, len(entries))
	fmt.Printf("[STATS] stack-id collisions (-EEXIST): kernel=%d user=%d | stack_counts full: %d\n",
		total[statKernEexist], total[statUserEexist], total[statCountsFull])
	if total[statKernEexist]+total[statUserEexist] > 0 {
		fmt.Println("[STATS] -> some stacks were dropped by hash collisions; raise stack_traces max_entries if this is large")
	}
}

// writeFolded เขียนรูปแบบ "comm;user_root;...;user_leaf;kern_entry_[k];...;kern_leaf_[k] count"
// ซึ่งเป็นอินพุตมาตรฐานของ flamegraph.pl (เฟรมนอกสุดอยู่ซ้าย)
func writeFolded(path string, objs *bpfObjects, entries []stackEntry, syms *userSymbolizer) (int, error) {
	agg := map[string]uint64{}
	for _, e := range entries {
		frames := []string{sanitizeFrame(string(bytes.TrimRight(e.key.Comm[:], "\x00")))}

		uframes := lookupStack(objs, e.key.UserStackID)
		for i := len(uframes) - 1; i >= 0; i-- {
			frames = append(frames, sanitizeFrame(syms.resolve(e.key.Pid, uframes[i])))
		}
		kframes := lookupStack(objs, e.key.KernelStackID)
		for i := len(kframes) - 1; i >= 0; i-- {
			frames = append(frames, sanitizeFrame(resolveKaddr(kframes[i]))+"_[k]")
		}
		if len(uframes) == 0 && len(kframes) == 0 {
			frames = append(frames, "[missing]")
		}
		agg[strings.Join(frames, ";")] += e.count
	}

	lines := make([]string, 0, len(agg))
	for stack, cnt := range agg {
		lines = append(lines, fmt.Sprintf("%s %d", stack, cnt))
	}
	sort.Strings(lines)

	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		w.WriteString(l + "\n")
	}
	return len(lines), errors.Join(w.Flush(), f.Sync())
}

// flamegraph.pl ใช้ ';' คั่นเฟรม และช่องว่างคั่นจำนวน จึงต้องแทนอักขระเหล่านี้
func sanitizeFrame(s string) string {
	return strings.NewReplacer(";", ":", " ", "_").Replace(s)
}
