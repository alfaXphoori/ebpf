//go:build linux
// +build linux

package main

// Week 25: struct_ops + sched_ext loader
//
//   sudo ./bin/scx-w25                      # FIFO, workload 2 x nCPU, 10 วินาที
//   sudo ./bin/scx-w25 -mode vtime          # weighted vtime
//   sudo ./bin/scx-w25 -fail stall -timeout 2000   # สาธิต watchdog eject
//   ./bin/scx-w25 ext-run <cmd> [args...]   # รันคำสั่งเป็น SCHED_EXT (แทน chrt --ext)

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

func printState(label string) {
	ops := readSysfs("root/ops") // มีเฉพาะตอน scheduler เปิดอยู่
	fmt.Printf("[sysfs] %-14s state=%-9s root/ops=%-12s switch_all=%s enable_seq=%s\n",
		label, readSysfs("state"), ops, readSysfs("switch_all"), readSysfs("enable_seq"))
}

func main() {
	// subcommand ext-run ไม่ต้องใช้ root และไม่โหลด BPF ใด ๆ
	if len(os.Args) > 1 && os.Args[1] == "ext-run" {
		if err := extRun(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	mode := flag.String("mode", "fifo", "fifo | vtime")
	fail := flag.String("fail", "none", "none | stall | error (สาธิต safety net)")
	duration := flag.Duration("duration", 10*time.Second, "ระยะเวลารันสูงสุด (สูงสุด 120s)")
	interval := flag.Duration("interval", time.Second, "ช่วงเวลาพิมพ์สถิติ")
	workers := flag.Int("workload", 2*runtime.NumCPU(), "จำนวนโปรเซส SCHED_EXT ทดสอบที่จะสร้าง (0 = ไม่สร้าง)")
	timeout := flag.Uint("timeout", 0, "watchdog timeout_ms (0 = ค่าใน C คือ 5000; เคอร์เนลรับไม่เกิน 30000)")
	flag.Parse()

	if *duration <= 0 || *duration > 120*time.Second {
		log.Fatalf("-duration must be in (0, 120s]")
	}
	fm, ok := failModes[*fail]
	if !ok {
		log.Fatalf("unknown -fail %q", *fail)
	}
	if *mode != "fifo" && *mode != "vtime" {
		log.Fatalf("unknown -mode %q", *mode)
	}

	fmt.Println("======================================================================")
	fmt.Printf(" Week 25: sched_ext BPF scheduler (mode=%s, fail=%s, SWITCH_PARTIAL)\n", *mode, *fail)
	fmt.Println("======================================================================")

	if _, err := os.Stat(sysfsDir); err != nil {
		log.Fatalf("%s not found: kernel built without CONFIG_SCHED_CLASS_EXT", sysfsDir)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}
	printState("before attach")

	sched, err := loadScheduler(schedConfig{vtime: *mode == "vtime", failMode: fm, timeoutMs: uint32(*timeout)})
	if err != nil {
		log.Fatalf("%v", err)
	}
	// ไม่ว่าจบแบบไหน (timeout / Ctrl+C / ถูก eject) ต้อง detach เสมอ
	defer func() {
		if err := sched.Close(); err != nil {
			log.Printf("detach: %v", err)
		}
		printState("after detach")
		if ei, err := sched.exitInfo(); err == nil && ei.Kind != 0 {
			fmt.Printf("[exit ] kind=%s(%d) reason=%q\n", exitKinds[ei.Kind], ei.Kind, cString(ei.Reason[:]))
		}
	}()
	waitState("enabled", 2*time.Second)
	printState("after attach")

	cmds, err := startWorkload("/proc/self/exe", os.Environ(), *workers)
	if err != nil {
		log.Printf("start workload: %v", err)
		return
	}
	defer func() { stopWorkload(cmds) }() // closure: อ่านค่า cmds ตอนจบ (อาจถูก stop ไปแล้ว)
	if len(cmds) > 0 {
		time.Sleep(50 * time.Millisecond) // ให้ ext-run ทัน execve
		fmt.Printf("[work ] %d x `sh -c <spin+sleep loop>` pgid=%d, policy of pid %d = %s (7 = SCHED_EXT)\n",
			len(cmds), cmds[0].Process.Pid, cmds[0].Process.Pid, taskPolicy(cmds[0].Process.Pid))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	start := time.Now()
	var prev [nrStats]uint64

	fmt.Println("[stats] deltas per interval (รวมทุก CPU); running/CPU = จำนวนครั้งที่ task ของเราขึ้นแต่ละ CPU")
loop:
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				fmt.Printf("[main ] -duration %v reached\n", *duration)
			} else {
				fmt.Println("\n[main ] signal received")
			}
			break loop
		case <-tick.C:
		}
		st, err := sched.readStats()
		if err != nil {
			log.Printf("%v", err)
			break
		}
		var cur [nrStats]uint64
		for i := range cur {
			cur[i] = sum(st[i])
		}
		perCPU := make([]string, len(st[statRunning]))
		for c, v := range st[statRunning] {
			perCPU[c] = fmt.Sprint(v)
		}
		fmt.Printf("[%5.1fs] local=+%-6d enqueue=+%-6d dispatch=+%-6d running=+%-6d | running/CPU: %s\n",
			time.Since(start).Seconds(),
			cur[statLocal]-prev[statLocal], cur[statEnq]-prev[statEnq],
			cur[statDispatch]-prev[statDispatch], cur[statRunning]-prev[statRunning],
			strings.Join(perCPU, " "))
		prev = cur

		// safety net: ถ้าเคอร์เนล eject scheduler (watchdog / scx_bpf_error) ops.exit จะเขียน exit_info
		if ei, err := sched.exitInfo(); err == nil && ei.Kind != 0 {
			fmt.Printf("[eject] kernel disabled the BPF scheduler: kind=%s(%d)\n", exitKinds[ei.Kind], ei.Kind)
			fmt.Printf("[eject] reason=%q\n[eject] msg=%q\n", cString(ei.Reason[:]), cString(ei.Msg[:]))
			fmt.Println("[eject] SCHED_EXT tasks fall back to the fair class; see `sudo dmesg | grep sched_ext`")
			printState("after eject")
			break loop
		}
	}

	// ตารางสรุปต่อ CPU
	if st, err := sched.readStats(); err == nil {
		fmt.Println("----------------------------------------------------------------------")
		fmt.Printf("%-4s %10s %10s %10s %10s\n", "CPU", statNames[0], statNames[1], statNames[2], statNames[3])
		for c := range st[0] {
			fmt.Printf("%-4d %10d %10d %10d %10d\n", c, st[0][c], st[1][c], st[2][c], st[3][c])
		}
		fmt.Printf("%-4s %10d %10d %10d %10d\n", "all", sum(st[0]), sum(st[1]), sum(st[2]), sum(st[3]))
	}
	stopWorkload(cmds)
	cmds = nil
}
