//go:build linux
// +build linux

package main

// sched.go: โค้ดที่ main.go และ main_test.go ใช้ร่วมกัน
//   - loadScheduler(): โหลด BPF + ตั้งค่าคงที่ + attach struct_ops ผ่าน BPF link
//   - extRun():        เทียบเท่า `chrt --ext 0 <cmd>` (util-linux 2.41 ยังไม่มี --ext)
//   - readStats() / sysfs helpers

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-global-types -type w25_exit_info -cflags "-I../../" bpf scx_w25.c

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// SCHED_EXT = 7 (include/uapi/linux/sched.h); x/sys/unix ยังไม่มีค่าคงที่นี้
const schedExt = 7

// ลำดับต้องตรงกับ enum stat_idx ใน scx_w25.c
const (
	statLocal = iota
	statEnq
	statDispatch
	statRunning
	nrStats
)

var statNames = [nrStats]string{"local", "enqueue", "dispatch", "running"}

// ค่าของ fail_mode ใน scx_w25.c
var failModes = map[string]uint32{"none": 0, "stall": 1, "error": 2}

// scx_exit_kind (เฉพาะที่เจอในแล็บนี้) จาก enum scx_exit_kind ใน BTF
var exitKinds = map[int32]string{
	0:    "NONE",
	1:    "DONE",
	64:   "UNREG",
	65:   "UNREG_BPF",
	66:   "UNREG_KERN",
	67:   "SYSRQ",
	1024: "ERROR",
	1025: "ERROR_BPF",
	1026: "ERROR_STALL",
}

const sysfsDir = "/sys/kernel/sched_ext"

type schedConfig struct {
	vtime     bool
	failMode  uint32
	timeoutMs uint32 // 0 = ใช้ค่าที่เขียนไว้ใน C (.timeout_ms)
}

type scheduler struct {
	objs   bpfObjects
	lnk    link.Link
	closed bool
}

// setOpsU32 แก้ field ชนิด u32 ของตาราง ops (เช่น timeout_ms) ใน MapSpec ก่อนโหลด
// ข้อมูลของ struct_ops map คือ bytes ของ struct sched_ext_ops ที่คอมไพเลอร์วางไว้ใน .struct_ops.link
// เราหา offset ของ field จาก BTF แทนการ hard-code
func setOpsU32(ms *ebpf.MapSpec, field string, val uint32) error {
	st, ok := ms.Value.(*btf.Struct)
	if !ok || len(ms.Contents) != 1 {
		return fmt.Errorf("unexpected struct_ops map spec %s", ms.Name)
	}
	data, ok := ms.Contents[0].Value.([]byte)
	if !ok {
		return fmt.Errorf("struct_ops %s: contents is %T", ms.Name, ms.Contents[0].Value)
	}
	for _, m := range st.Members {
		if m.Name == field {
			off := m.Offset.Bytes()
			binary.NativeEndian.PutUint32(data[off:off+4], val)
			return nil
		}
	}
	return fmt.Errorf("field %s not found in %s", field, st.Name)
}

func loadScheduler(cfg schedConfig) (*scheduler, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	// const volatile -> แก้ใน .rodata ก่อนโหลด (verifier เห็นเป็นค่าคงที่ ตัด branch ที่ไม่ใช้ทิ้งได้)
	if err := spec.Variables["vtime_mode"].Set(cfg.vtime); err != nil {
		return nil, fmt.Errorf("set vtime_mode: %w", err)
	}
	if err := spec.Variables["fail_mode"].Set(cfg.failMode); err != nil {
		return nil, fmt.Errorf("set fail_mode: %w", err)
	}
	if cfg.timeoutMs > 0 {
		if err := setOpsU32(spec.Maps["w25_ops"], "timeout_ms", cfg.timeoutMs); err != nil {
			return nil, err
		}
	}

	s := &scheduler{}
	// โหลดโปรแกรมทั้งหมด + สร้าง struct_ops map (ยังไม่ register กับ sched_ext)
	if err := spec.LoadAndAssign(&s.objs, nil); err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	// BPF_LINK_CREATE บน struct_ops map -> เคอร์เนลเรียก ops.init แล้วเปิดใช้ scheduler
	s.lnk, err = link.AttachStructOps(link.StructOpsOptions{Map: s.objs.W25Ops})
	if err != nil {
		s.objs.Close()
		return nil, fmt.Errorf("attach struct_ops (มี sched_ext scheduler ตัวอื่นโหลดอยู่หรือไม่?): %w", err)
	}
	return s, nil
}

// Close ปิด link (= unregister scheduler) แล้วรอจน state กลับเป็น disabled
func (s *scheduler) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.lnk != nil {
		err = s.lnk.Close()
		s.lnk = nil
	}
	waitState("disabled", 3*time.Second)
	s.objs.Close()
	return err
}

func (s *scheduler) exitInfo() (bpfW25ExitInfo, error) {
	var ei bpfW25ExitInfo
	err := s.objs.ExitInfo.Get(&ei)
	return ei, err
}

// readStats คืนค่า [stat][cpu] จาก PERCPU_ARRAY
func (s *scheduler) readStats() ([nrStats][]uint64, error) {
	var out [nrStats][]uint64
	for i := uint32(0); i < nrStats; i++ {
		if err := s.objs.Stats.Lookup(i, &out[i]); err != nil {
			return out, fmt.Errorf("lookup stat %d: %w", i, err)
		}
	}
	return out, nil
}

func sum(v []uint64) uint64 {
	var t uint64
	for _, x := range v {
		t += x
	}
	return t
}

func cString(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

func readSysfs(name string) string {
	b, err := os.ReadFile(sysfsDir + "/" + name)
	if err != nil {
		return "-"
	}
	return strings.TrimSpace(string(b))
}

func waitState(want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if readSysfs("state") == want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return readSysfs("state") == want
}

// taskPolicy อ่าน policy ของ pid จาก /proc/<pid>/sched (7 = SCHED_EXT)
func taskPolicy(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/sched", pid))
	if err != nil {
		return "?"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.TrimSpace(k) == "policy" {
			return strings.TrimSpace(v)
		}
	}
	return "?"
}

// extRun ตั้ง policy ของ thread ปัจจุบันเป็น SCHED_EXT แล้ว execve คำสั่งที่ให้มา
// policy ถูกเก็บข้าม execve และสืบทอดไปยังลูกที่ fork ภายหลัง (เหมือน chrt)
// ถ้ายังไม่มี BPF scheduler โหลดอยู่ task SCHED_EXT จะรันด้วย fair class ไปก่อน
func extRun(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ext-run <cmd> [args...]")
	}
	runtime.LockOSThread() // ให้ sched_setattr(0) กับ execve เกิดบน thread เดียวกัน
	// อ่าน attr เดิมก่อนเพื่อคงค่า nice ไว้ (ถ้าส่ง Nice=0 ทับ nice 10 จะเป็นการ "ลด nice"
	// ซึ่งต้องมี CAP_SYS_NICE -> EPERM สำหรับผู้ใช้ธรรมดา)
	attr, err := unix.SchedGetAttr(0, 0)
	if err != nil {
		return fmt.Errorf("sched_getattr: %w", err)
	}
	attr.Policy = schedExt
	attr.Flags = 0
	if err := unix.SchedSetAttr(0, attr, 0); err != nil {
		return fmt.Errorf("sched_setattr(SCHED_EXT): %w", err)
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, args, os.Environ())
}

// workloadScript: วน "คำนวณสั้น ๆ แล้วหลับ" -> เกิด wakeup/enqueue/dispatch จำนวนมาก
// `sleep` เป็นโปรเซสลูก จึงได้ SCHED_EXT ต่อจาก sh ด้วย (fork/exec ก็ผ่าน scheduler เรา)
const workloadScript = `while :; do i=0; while [ $i -lt 2000 ]; do i=$((i+1)); done; sleep 0.005; done`

// startWorkload สร้าง n โปรเซส `sh -c workloadScript` ที่เป็น SCHED_EXT ในกลุ่มโปรเซสเดียวกัน
// self = path ของ binary ที่รู้จัก subcommand ext-run (main: /proc/self/exe, test: test binary)
func startWorkload(self string, env []string, n int) ([]*exec.Cmd, error) {
	var cmds []*exec.Cmd
	pgid := 0
	for i := 0; i < n; i++ {
		c := exec.Command(self, "ext-run", "sh", "-c", workloadScript)
		c.Env = env
		// Pgid: kill ทั้งกลุ่มได้ทีเดียว; Pdeathsig: ถ้า loader ตาย workload ตายตาม
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pgid, Pdeathsig: syscall.SIGKILL}
		if err := c.Start(); err != nil {
			stopWorkload(cmds)
			return nil, err
		}
		if pgid == 0 {
			pgid = c.Process.Pid
		}
		cmds = append(cmds, c)
	}
	return cmds, nil
}

func stopWorkload(cmds []*exec.Cmd) {
	if len(cmds) == 0 {
		return
	}
	_ = syscall.Kill(-cmds[0].Process.Pid, syscall.SIGKILL)
	for _, c := range cmds {
		_ = c.Wait()
	}
}
