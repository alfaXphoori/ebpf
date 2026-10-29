//go:build linux
// +build linux

package main

// Runtime tests for scx_w25.c (ต้องใช้ root, รันด้วย: make test == go test -exec sudo -v ./...)
//
// struct_ops ของ sched_ext ทดสอบด้วย BPF_PROG_TEST_RUN ไม่ได้ (เคอร์เนลรองรับ test_run ของ
// struct_ops เฉพาะ bpf_dummy_ops ที่ใช้ใน selftests) จึงต้องทดสอบแบบ "load + attach จริง"
// ในโหมด SCX_OPS_SWITCH_PARTIAL กับ workload ของเราเองเท่านั้น และ detach ทุกครั้ง
//
// Tests ห้ามรันขนานกัน (เคอร์เนลยอมให้มี sched_ext scheduler ได้ทีละ 1 ตัว)

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestMain: ให้ test binary ทำหน้าที่ ext-run ได้ด้วย (startWorkload เรียก <self> ext-run sh -c ...)
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "ext-run" {
		if err := extRun(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func requireSchedExt(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (run: make test)")
	}
	if _, err := os.Stat(sysfsDir); err != nil {
		t.Skip("kernel without CONFIG_SCHED_CLASS_EXT")
	}
	if st := readSysfs("state"); st != "disabled" {
		t.Skipf("another sched_ext scheduler is active (state=%s); not touching it", st)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
}

func mustLoad(t *testing.T, cfg schedConfig) *scheduler {
	t.Helper()
	s, err := loadScheduler(cfg)
	if err != nil {
		t.Fatalf("load/attach: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		if st := readSysfs("state"); st != "disabled" {
			t.Errorf("state after detach = %q, want disabled", st)
		}
	})
	if !waitState("enabled", 2*time.Second) {
		t.Fatalf("state = %q, want enabled", readSysfs("state"))
	}
	return s
}

func mustWorkload(t *testing.T, n int) []int {
	t.Helper()
	cmds, err := startWorkload("/proc/self/exe", os.Environ(), n)
	if err != nil {
		t.Fatalf("start workload: %v", err)
	}
	t.Cleanup(func() { stopWorkload(cmds) })
	time.Sleep(100 * time.Millisecond)
	var pids []int
	for _, c := range cmds {
		if p := taskPolicy(c.Process.Pid); p != strconv.Itoa(schedExt) {
			t.Fatalf("workload pid %d policy=%s, want %d (SCHED_EXT)", c.Process.Pid, p, schedExt)
		}
		pids = append(pids, c.Process.Pid)
	}
	return pids
}

func waitExit(s *scheduler, timeout time.Duration) bpfW25ExitInfo {
	deadline := time.Now().Add(timeout)
	for {
		ei, err := s.exitInfo()
		if (err == nil && ei.Kind != 0) || time.Now().After(deadline) {
			return ei
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func sumExecRuntime(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/sched", pid))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "se.sum_exec_runtime" {
			f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return f
		}
	}
	return -1
}

// FIFO และ vtime: attach -> workload SCHED_EXT -> ต้องเห็น enqueue/dispatch > 0 -> detach สะอาด
func TestSchedulerDispatchesExtTasks(t *testing.T) {
	for _, mode := range []string{"fifo", "vtime"} {
		t.Run(mode, func(t *testing.T) {
			requireSchedExt(t)
			s := mustLoad(t, schedConfig{vtime: mode == "vtime"})

			if ops := readSysfs("root/ops"); ops != "w25_minimal" {
				t.Errorf("root/ops = %q, want w25_minimal", ops)
			}
			if sa := readSysfs("switch_all"); sa != "0" {
				t.Fatalf("switch_all = %q: scheduler must run in SWITCH_PARTIAL mode", sa)
			}

			// 2 x nCPU โปรเซส > จำนวน CPU -> บังคับให้มีคิวรอ (ผ่าน ops.enqueue + ops.dispatch)
			mustWorkload(t, 2*runtime.NumCPU())
			time.Sleep(1500 * time.Millisecond)

			st, err := s.readStats()
			if err != nil {
				t.Fatal(err)
			}
			local, enq, disp, run := sum(st[statLocal]), sum(st[statEnq]), sum(st[statDispatch]), sum(st[statRunning])
			t.Logf("mode=%s local=%d enqueue=%d dispatch=%d running=%d", mode, local, enq, disp, run)
			if enq == 0 || disp == 0 || run == 0 {
				t.Errorf("expected enqueue, dispatch and running > 0")
			}
			if ei, _ := s.exitInfo(); ei.Kind != 0 {
				t.Fatalf("scheduler exited unexpectedly: kind=%d reason=%q msg=%q",
					ei.Kind, cString(ei.Reason[:]), cString(ei.Msg[:]))
			}

			s.Close()
			if ei, _ := s.exitInfo(); ei.Kind != 64 { // SCX_EXIT_UNREG
				t.Errorf("exit kind = %d, want 64 (SCX_EXIT_UNREG)", ei.Kind)
			}
		})
	}
}

// Safety net 1: dispatch ไม่ดึงงานเลย -> watchdog ต้อง eject ภายใน timeout_ms แล้ว workload
// ต้องรันต่อได้ด้วย fair class
func TestWatchdogEjectsStalledScheduler(t *testing.T) {
	requireSchedExt(t)
	s := mustLoad(t, schedConfig{failMode: failModes["stall"], timeoutMs: 1000})
	pids := mustWorkload(t, 2)

	ei := waitExit(s, 6*time.Second)
	if ei.Kind != 1026 { // SCX_EXIT_ERROR_STALL
		t.Fatalf("exit kind = %d, want 1026 (SCX_EXIT_ERROR_STALL)", ei.Kind)
	}
	t.Logf("ejected: reason=%q msg=%q", cString(ei.Reason[:]), cString(ei.Msg[:]))
	if !waitState("disabled", 3*time.Second) {
		t.Fatalf("state = %q after eject, want disabled", readSysfs("state"))
	}

	// หลัง eject task SCHED_EXT ต้องได้ CPU อีกครั้ง (fallback ไป fair class)
	before := sumExecRuntime(pids[0])
	time.Sleep(500 * time.Millisecond)
	after := sumExecRuntime(pids[0])
	t.Logf("pid %d sum_exec_runtime %.1fms -> %.1fms after eject", pids[0], before, after)
	if after <= before {
		t.Errorf("workload did not run after eject (sum_exec_runtime %.1f -> %.1f)", before, after)
	}
}

// Safety net 2: scx_bpf_error() จากโค้ด BPF -> SCX_EXIT_ERROR_BPF พร้อมข้อความของเรา
func TestScxBpfErrorEjects(t *testing.T) {
	requireSchedExt(t)
	s := mustLoad(t, schedConfig{failMode: failModes["error"]})
	mustWorkload(t, 4)

	ei := waitExit(s, 5*time.Second)
	if ei.Kind != 1025 { // SCX_EXIT_ERROR_BPF
		t.Fatalf("exit kind = %d, want 1025 (SCX_EXIT_ERROR_BPF)", ei.Kind)
	}
	if msg := cString(ei.Msg[:]); !strings.Contains(msg, "deliberate scx_bpf_error") {
		t.Errorf("exit msg = %q, want our scx_bpf_error message", msg)
	}
	if !waitState("disabled", 3*time.Second) {
		t.Fatalf("state = %q after scx_bpf_error, want disabled", readSysfs("state"))
	}
}

// ยืนยันข้อจำกัด: BPF_PROG_TEST_RUN ใช้กับ struct_ops ของ sched_ext ไม่ได้
func TestStructOpsHasNoTestRun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (run: make test)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var objs bpfObjects
	// โหลดอย่างเดียว ไม่ attach -> ไม่กระทบ scheduler ของเครื่อง
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer objs.Close()
	_, err := objs.W25Running.Run(&ebpf.RunOptions{})
	if err == nil {
		t.Fatal("BPF_PROG_TEST_RUN unexpectedly succeeded on a sched_ext struct_ops program")
	}
	t.Logf("BPF_PROG_TEST_RUN on struct_ops/w25_running: %v (expected)", err)
}
