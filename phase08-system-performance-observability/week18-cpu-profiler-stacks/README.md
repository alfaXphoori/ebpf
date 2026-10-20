# สัปดาห์ที่ 18: การทำ CPU Profiling และรวบรวม Call Stack Traces เพื่อสร้าง Flame Graphs ด้วย eBPF

ยินดีต้อนรับสู่ **Week 18** ของหลักสูตร eBPF Noob to Hero!
เมื่อระบบเกิดอาการ CPU Spike หรือ Thread ติดขัด เครื่องมืออย่าง `top` จะบอกได้เพียงแค่ว่า Process ใดกิน CPU แต่ไม่สามารถบอกได้ว่า **"ฟังก์ชันใดในโค้ดหรือในเคอร์เนลกำลังทำงานอยู่"**

ในสัปดาห์นี้ เราจะใช้ **`BPF_MAP_TYPE_STACK_TRACE`** และตัวถอดรหัส Symbol `/proc/kallsyms` เพื่อ:
1. แกะรอย Stack Trace (Kernel Space & User Space) อัตโนมัติในระดับเคอร์เนล
2. สรุปความถี่ของเส้นทางการเรียกฟังก์ชัน (Call Chains) ซึ่งเป็นรากฐานสำคัญของการทำ **CPU Flame Graphs**
3. มี Overhead ต่ำเป็นพิเศษ ไม่กระทบความเร็วของระบบโปรดักชัน

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อสุ่มจับและบันทึก Call Stack Traces
make run
```

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF High-Resolution CPU Profiler & Stack Collector (Flame Graph)
======================================================================
2026/10/20 11:56:37 [INFO] Loaded 359072 symbols from /proc/kallsyms
2026/10/20 11:56:37 [INFO] Sampling CPU stacks via 'sched/sched_switch'...
2026/10/20 11:56:37 [INFO] Profile collecting. Press Ctrl+C to terminate and view top stacks.

[11:56:39] Total CPU Stacks Sampled: 1809     | Unique Call Chains: 173   

[INFO] Detaching profiler and rendering Top Call Stacks...

=================== TOP CPU CALL CHAINS ===================

#1 [agy (PID: 52953)] - Sample Count: 309
    -> perf_trace_sched_switch
    -> __traceiter_sched_switch
    -> __schedule
    -> schedule
    -> do_nanosleep
    -> hrtimer_nanosleep
    -> __x64_sys_nanosleep
    -> x64_sys_call
    -> do_syscall_64
    -> entry_SYSCALL_64_after_hwframe

#2 [agy (PID: 52956)] - Sample Count: 200
    -> perf_trace_sched_switch
    -> __traceiter_sched_switch
    -> __schedule
    -> schedule
    -> schedule_hrtimeout_range_clock
    -> schedule_hrtimeout_range
    -> ep_poll
    -> do_epoll_wait
    -> do_epoll_pwait.part.0
    -> __x64_sys_epoll_pwait
    -> x64_sys_call
    -> do_syscall_64
    -> entry_SYSCALL_64_after_hwframe

#3 [tailscaled (PID: 2105)] - Sample Count: 179
    -> perf_trace_sched_switch
    -> __traceiter_sched_switch
    -> __schedule
    -> schedule
    -> do_nanosleep
    -> hrtimer_nanosleep
    -> __x64_sys_nanosleep
    -> x64_sys_call
    -> do_syscall_64
    -> entry_SYSCALL_64_after_hwframe
===========================================================
```
