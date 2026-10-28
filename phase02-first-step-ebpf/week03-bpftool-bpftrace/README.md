# สัปดาห์ที่ 03: ก้าวแรกสู่ eBPF ด้วย bpftool และ bpftrace

ยินดีต้อนรับสู่ **Week 03** ของหลักสูตร **eBPF Zero to Hero**!
หลังจากที่เราได้เข้าใจโครงสร้างของแพ็กเก็ตและเส้นทางของเคอร์เนลเน็ตเวิร์กสแตกใน Phase 1 แล้ว สัปดาห์นี้ถือเป็น **หมุดหมายสำคัญ** เพราะเราจะก้าวข้ามจากการใช้เครื่องมือแบบดั้งเดิมเข้าสู่โลกของ **eBPF (extended Berkeley Packet Filter)** อย่างแท้จริง!

เราจะเริ่มต้นด้วยการทำความเข้าใจสถาปัตยกรรมภายในของ eBPF และเรียนรู้วิธีการเขียนสคริปต์สืบค้นเคอร์เนลด้วย **`bpftrace`** ซึ่งเป็นภาษาระดับสูงสำหรับการทำ Dynamic Tracing รวมถึงการใช้เครื่องมือคู่ใจวิศวกร eBPF ระดับโลกอย่าง **`bpftool`** เพื่อตรวจสอบ Bytecode, BPF Maps, และ BPF Type Format (BTF) ในหน่วยความจำของเคอร์เนล

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 eBPF คืออะไร? Virtual Machine ภายใน Linux Kernel
ในอดีต หากคุณต้องการสังเกตการณ์หรือแก้ไขพฤติกรรมของ Linux Kernel คุณมีทางเลือกเพียง 2 ทาง:
1. แก้ไข Kernel Source Code แล้วคอมไพล์ใหม่ (ใช้เวลาและเสี่ยงต่อการพังของระบบ)
2. เขียน **Loadable Kernel Module (LKM)** ซึ่งมีความเสี่ยงสูงสุด เพราะหากมี Bug เพียงบรรทัดเดียว (เช่น Null Pointer Dereference) จะทำให้เกิด **Kernel Panic** เครื่องหยุดทำงานทันที

**eBPF** เข้ามาปฏิวัติวงการด้วยการเป็น **In-Kernel Virtual Machine** ที่ปลอดภัยและมีประสิทธิภาพสูง:
- **Registers**: มี 11 Registers ขนาด 64 บิต (`r0` ถึง `r10` โดย `r10` คือ Read-only Frame Pointer)
- **In-Kernel Verifier**: ตรวจสอบโค้ด Bytecode ทุกคำสั่งก่อนอนุญาตให้รัน เพื่อการันตีว่าโปรแกรมไม่มี Infinite Loop, ไม่เข้าถึงหน่วยความจำนอกขอบเขต (Out-of-bounds), และไม่ทำให้เคอร์เนลแครช
- **JIT Compiler (Just-In-Time)**: แปลง eBPF Bytecode ให้เป็น Native Machine Code (x86_64, ARM64) โดยตรง ทำให้ทำงานได้ใกล้เคียงโค้ด native ในเคอร์เนล (เร็วกว่าการตีความ bytecode มาก; บน Ubuntu ตั้ง `CONFIG_BPF_JIT_ALWAYS_ON=y` คือใช้ JIT เสมอ)

```
+-------------------------------------------------------------------+
|                        User Space                                 |
|                                                                   |
|   bpftrace / bpftool / C Application                              |
|           |                                                       |
|           v (LLVM Clang Compiler)                                 |
|      eBPF Bytecode                                                |
|           |                                                       |
|           v sys_bpf(BPF_PROG_LOAD, ...)                           |
+-----------|-------------------------------------------------------+
|           v            Linux Kernel Space                         |
|   +---------------+                                               |
|   |   Verifier    | ---> ปฏิเสธถ้าไม่ปลอดภัย (Out-of-bound / Loop)  |
|   +-------+-------+                                               |
|           | (ผ่านการตรวจสอบความปลอดภัย)                            |
|           v                                                       |
|   +---------------+                                               |
|   |  JIT Compiler | ---> แปลงเป็น Native Machine Instructions      |
|   +-------+-------+                                               |
|           |                                                       |
|           v ผูกเข้ากับ Kernel Event Hook (kprobe, tracepoint)     |
|   +-----------------------------------------------------------+   |
|   | Executed upon: sys_enter_execve / tcp_sendmsg / etc.      |   |
|   +-----------------------------+-----------------------------+   |
|                                 |                                 |
|                                 v (ส่งข้อมูลผ่าน)                 |
|                    +-------------------------+                    |
|                    |        BPF MAPS         |                    |
|                    | (Hash, Array, RingBuf)  |                    |
|                    +-------------------------+                    |
+-------------------------------------------------------------------+
```

---

### 1.2 bpftrace Architecture
**`bpftrace`** เป็น Tracing Tool ระดับสูงที่ได้รับแรงบันดาลใจจาก DTrace ของ Solaris และไวยากรณ์ภาษา AWK:
- ผู้ใช้เขียนโค้ดด้วยรูปแบบง่ายๆ: `probe_name /filter/ { action }`
- `bpftrace` จะแปลงสคริปต์นั้นผ่าน LLVM เป็น eBPF Bytecode และโหลดเข้าสู่เคอร์เนลแบบไดนามิกผ่าน `bpf()` system call ทันที
- เหมาะอย่างยิ่งสำหรับการทำ Ad-hoc Production Debugging, Troubleshooting ปัญหา Latency, และการวิเคราะห์ Root Cause โดยไม่ต้องเขียนภาษา C หรือคอมไพล์โปรแกรมขนาดใหญ่

---

### 1.3 ชนิดของ Probe Types ใน eBPF Tracing

| Probe Type | แหล่งกำเนิด (Source) | ความเสถียรของ ABI | Overhead | กรณีการใช้งานที่เหมาะสม |
| :--- | :--- | :--- | :--- | :--- |
| **`tracepoint`** | จุดที่เคอร์เนลฝังไว้ล่วงหน้า (`/sys/kernel/tracing/events`) | **สูง** (ตั้งใจให้เสถียร แต่ field ยังเพิ่ม/เปลี่ยนได้ เช่น `tcp_retransmit_skb` บน 7.0 มี field `err` เพิ่ม) | ต่ำมาก | ติดตาม Process (`sched:sched_process_exec`), System Calls (`raw_syscalls:sys_enter`, `syscalls:sys_enter_*`), TCP events (`tcp:tcp_retransmit_skb`) |
| **`kprobe`** | จุดเริ่มต้นของฟังก์ชันใดๆ ในเคอร์เนล | **ปานกลาง/ต่ำ** (พารามิเตอร์อาจเปลี่ยนตาม Kernel version) | ต่ำ | ติดตามฟังก์ชันภายในเคอร์เนลที่ไม่มี tracepoint (เช่น `tcp_sendmsg`) |
| **`kretprobe`** | จุดที่ฟังก์ชันเคอร์เนล Return ค่ากลับ | ปานกลาง/ต่ำ | ปานกลาง | วัดเวลา Latency ของฟังก์ชัน หรือตรวจดู Return Code |
| **`uprobe` / `uretprobe`**| ฟังก์ชันใน User Space (เช่น `libc.so`, binary Go/C++) | ขึ้นกับ Application | ปานกลาง | แกะรอย SSL/TLS Decryption, Memory Allocation (`malloc`), HTTP calls |
| **`interval` / `profile`**| ตัวจับเวลา (Timer / Sample Clock) | เสถียร | ต่ำ | รายงานผลสรุปสถิติตามช่วงเวลา (เช่น ทุก 10 วินาที) หรือทำ CPU Flamegraph |

---

### 1.4 การรวมกลุ่มข้อมูล (Built-in Aggregations) ใน bpftrace
แทนที่จะส่งข้อมูลทุกแพ็กเก็ตหรือทุกเหตุการณ์ขึ้นมาที่ User Space (ซึ่งจะทำให้ระบบช้ามาก) eBPF นิยมประมวลผลสรุปข้อมูลเบื้องต้นใน **BPF Map** ภายในเคอร์เนล:
- **`count()`**: นับจำนวนครั้งที่เกิดเหตุการณ์
- **`sum(val)`**: รวมผลรวมของค่าตัวแปร
- **`hist(val)`**: สร้าง Histogram แบบ Logarithmic ฐาน 2 (เช่น 0-1, 2-3, 4-7, 8-15, ...)
- **`lhist(val, min, max, step)`**: สร้าง Linear Histogram

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### สคริปต์สืบค้นเคอร์เนล: `trace_exec_and_tcp.bt`

```c
/*
 * 1. ส่วนเริ่มต้น (BEGIN probe)
 */
BEGIN
{
    printf("Tracing started! Press Ctrl+C to terminate...\n");
    printf("%-9s %-6s %-7s %-16s %s\n", "TIME", "UID", "PID", "PARENT", "FILENAME / EVENT");
}
```
- **คำอธิบาย**: รันครั้งเดียวเมื่อโปรแกรมถูกโหลดเข้าสู่เคอร์เนลสำเร็จ ใช้ในการพิมพ์หัวตารางและคำอธิบาย

```c
/*
 * 2. การดักจับ Process Execution
 */
tracepoint:sched:sched_process_exec
{
    printf("%s  %-6d %-7d %-16s %s\n", strftime("%H:%M:%S", nsecs), uid, pid,
           curtask->real_parent->comm, str(args->filename));
    @process_exec_count[comm] = count();
}
```
- **คำอธิบาย**:
  - `tracepoint:sched:sched_process_exec`: ถูกทริกเกอร์ทุกครั้งที่ `execve()`/`execveat()` **สำเร็จ** และเคอร์เนลโหลดโปรแกรมใหม่เข้ามาแทนที่แล้ว (exec ที่ล้มเหลว เช่นไฟล์ไม่มีอยู่ จะไม่ถูกนับ)
  - **ดู "สัญญา" ของ tracepoint ก่อนเขียนเสมอ**: `sudo cat /sys/kernel/tracing/events/sched/sched_process_exec/format` หรือ `sudo bpftrace -lv tracepoint:sched:sched_process_exec` จะเห็น field `__data_loc char[] filename`, `pid_t pid`, `pid_t old_pid`
  - `str(args->filename)`: field ชนิด `__data_loc` คือสตริงที่เก็บแบบ offset/length อยู่ใน record ของ tracepoint เอง bpftrace ถอดให้อัตโนมัติด้วย `str()`
  - `uid`, `pid`, `comm`: Built-in variables — ณ จุดนี้ `comm` เป็นชื่อโปรแกรม **ใหม่** แล้ว (เช่น `ls`) เราจึงพิมพ์ชื่อโปรเซสแม่จาก `curtask->real_parent->comm` (bpftrace ใช้ BTF เดินไปใน `struct task_struct` ได้โดยตรง)
  - `strftime("%H:%M:%S", nsecs)` อยู่ใน `printf` เดียวกัน: ถ้าใช้ `time()` แยกบรรทัด ข้อความจากหลาย CPU อาจพิมพ์สลับกัน (เห็น timestamp ซ้อนกันสองตัว)
  - `@process_exec_count[comm] = count()`: บันทึกความถี่ของการรันคำสั่งแยกตามชื่อโปรแกรมลงใน BPF Map

> [!WARNING]
> **ทำไมไม่ใช้ `tracepoint:syscalls:sys_enter_execve` (ซึ่งมี `args->argv` ให้ด้วย)?** บน Ubuntu 26.04 / Linux 7.0.0-38 เราพบว่าโปรแกรม BPF ที่ผูกกับ `syscalls:sys_enter_execve` (และ `sys_enter_openat`) **ทำงานเฉพาะเมื่อ syscall เกิดบน CPU 0** — ทดสอบด้วย `for c in 0 1 2 3 4 5 6 7; do taskset -c $c /bin/true; done` ได้ 1/8 ครั้ง ขณะที่ `sched:sched_process_exec` และ `raw_syscalls:sys_enter` (`args->id == 59`) ได้ 8/8 ส่วน `sys_enter_getpid` ไม่มีอาการนี้ (ยังไม่ยืนยันสาเหตุ ดูหัวข้อ Troubleshooting) สคริปต์รุ่นเดิมจึงพลาด exec ส่วนใหญ่โดยไม่มี error ใดๆ — บทเรียนสำคัญคือ **ต้องตรวจสอบความครบถ้วนของ probe ด้วยการทดลองที่รู้คำตอบล่วงหน้าเสมอ**

```c
/*
 * 3. การดักจับขนาด Payload ใน TCP Sendmsg
 */
kprobe:tcp_sendmsg
{
    $size = arg2;
    @tcp_send_bytes = hist($size);
    @tcp_send_calls[comm] = count();
    @tcp_send_total_bytes[comm] = sum($size);
}
```
- **คำอธิบาย**:
  - `tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)` เป็นฟังก์ชันหลักใน Linux TCP Stack เมื่อแอปพลิเคชันสั่งส่งข้อมูล
  - ในสถาปัตยกรรม x86_64 / ARM64 พารามิเตอร์ตัวที่ 3 (`size`) จะถูกส่งผ่านรีจิสเตอร์ ซึ่ง `bpftrace` นำมาให้อัตโนมัติในชื่อ `arg2`
  - `@tcp_send_bytes = hist($size)`: จัดกลุ่มขนาดข้อมูลเป็น Histogram ฐาน 2 ภายใน Kernel Space

```c
/*
 * 4. การดักจับเหตุการณ์ TCP Packet Loss & Retransmission
 */
tracepoint:tcp:tcp_retransmit_skb
{
    time("%H:%M:%S  ");
    printf("%-6d %-6d %-16s [TCP RETRANSMIT] %s:%d -> %s:%d (State: %d)\n",
           uid, pid, comm,
           ntop(args->saddr), args->sport,
           ntop(args->daddr), args->dport,
           args->state);
    @tcp_retransmit_count[comm] = count();
}
```
- **คำอธิบาย**:
  - เมื่อเกิดเน็ตเวิร์กติดขัดหรือแพ็กเก็ตสูญหาย เคอร์เนลจะเรียก `tcp_retransmit_skb` (ในสคริปต์จริงใช้ `strftime()` ใน `printf` เดียวแทน `time()` เหตุผลเดียวกับข้างบน)
  - `args->state` เป็นเลขสถานะ TCP ของเคอร์เนล เช่น `1` = `TCP_ESTABLISHED`, `2` = `TCP_SYN_SENT` (SYN ไม่ได้รับคำตอบ)
  - การ retransmit ส่วนใหญ่เกิดจาก timer ใน softirq ค่า `comm`/`pid` จึงมักเป็นโปรเซสที่บังเอิญรันอยู่บน CPU นั้น (เช่น `swapper/4` = idle task, `pid` 0) **ไม่ใช่** แอปพลิเคชันเจ้าของ socket
  - `ntop(...)`: Built-in function แปลง IP address จากเลขฐานสองเป็นรูปสตริง IP ที่อ่านง่าย
  - โค้ดนี้ทำให้เราทราบทันทีว่าแอปพลิเคชันตัวใดกำลังประสบปัญหา Packet Loss โดยไม่ต้องเปิด Wireshark ดักจับแพ็กเก็ตทั้งหมด

```c
/*
 * 5. การพิมพ์รายงานสรุปทุกๆ 10 วินาที
 */
interval:s:10
{
    printf("\n--- [Periodic Report (every 10s): cumulative since start] ---\n");
    print(@tcp_send_calls);
    print(@tcp_send_bytes);
}
```
- **คำอธิบาย**: เป็น Timer Probe ที่ทริกเกอร์ทุก 10 วินาที ช่วยให้เราเห็นความเคลื่อนไหวของระบบแบบ Real-time โดยไม่ต้องรอจนจบโปรแกรม
  - **ข้อควรระวัง**: `print()` ไม่ได้ล้าง Map ตัวเลขจึงเป็น **ยอดสะสมตั้งแต่เริ่ม** ไม่ใช่ "10 วินาทีล่าสุด" (ถ้าต้องการยอดต่อช่วงให้เรียก `clear(@map)` หลัง `print` — ดูแบบฝึกหัด)
  - ใน `END` สคริปต์เรียก `clear()` ทุก Map หลังพิมพ์สรุป เพราะ bpftrace จะพิมพ์ Map ที่ยังไม่ว่างให้อัตโนมัติตอนออก ทำให้สรุปซ้ำสองรอบ

---

### 2.2 คู่มือการใช้งาน `bpftool` สำหรับการตรวจสอบระดับเคอร์เนล

`bpftool` เป็นเครื่องมือบรรทัดคำสั่งอย่างเป็นทางการที่มาพร้อมกับเคอร์เนล Linux ใช้ตรวจสอบและควบคุมระบบ eBPF:

#### 1. ตรวจสอบขีดความสามารถของเคอร์เนล (eBPF Feature Probing)
```bash
sudo bpftool feature probe
```
- แสดงรายการ Program Types, Map Types, และ Helper Functions ทั้งหมดที่เคอร์เนลปัจจุบันรองรับ

#### 2. แสดงรายการ eBPF Programs ที่โหลดอยู่ในระบบ
```bash
sudo bpftool prog show
```
- แสดง ID, Type, ชื่อโปรแกรม, และ Tag ของ eBPF Programs ทั้งหมดที่กำลังทำงานอยู่ในเคอร์เนล

#### 3. ส่องดู eBPF Bytecode และ JITed Machine Code
```bash
# ดู eBPF Bytecode ที่ผ่านการ Verifier แล้ว (Translated bytecode)
sudo bpftool prog dump xlated id <PROG_ID>

# ดู Machine Code จริงที่ JIT Compiler สร้างขึ้นบน CPU
sudo bpftool prog dump jited id <PROG_ID>
```

#### 4. ส่องดูข้อมูลใน BPF Maps
```bash
# แสดงรายการ Maps ทั้งหมด
sudo bpftool map show

# ดัมพ์ข้อมูลข้างใน Map ออกมาดู
sudo bpftool map dump id <MAP_ID>
```

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ติดตั้ง bpftrace และ bpftool (หากยังไม่มีในระบบ)
บน Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y bpftrace linux-tools-common linux-tools-$(uname -r)
```
ตรวจสอบเวอร์ชันและความพร้อม (เครื่องทดสอบ: bpftrace v0.25.0, bpftool v7.7):
```bash
bpftrace --version
sudo bpftool version
ls -la /sys/kernel/btf/vmlinux        # ต้องมีไฟล์นี้ (BTF ของเคอร์เนล)
sudo bpftrace -l 'tracepoint:sched:sched_process_exec'   # probe ต้องมีอยู่จริง
```

### ขั้นตอนที่ 2: รันสคริปต์ `trace_exec_and_tcp.bt`
รันสคริปต์ด้วยสิทธิ์ `sudo`:
```bash
sudo bpftrace trace_exec_and_tcp.bt
```

**สิ่งที่แสดงบนหน้าจอ** (bpftrace 0.25 พิมพ์ `Attached 6 probes` ก่อน — 6 = BEGIN, END, exec, tcp_sendmsg, retransmit, interval):
```text
====================================================================
  eBPF Zero to Hero - Week 03: Process Execution & TCP Observability
====================================================================
  Active Probes:
    1. tracepoint:sched:sched_process_exec (New process launches)
    2. kprobe:tcp_sendmsg                  (TCP payload histogram)
    3. tracepoint:tcp:tcp_retransmit_skb   (TCP packet drops/retrans)
    4. interval:s:10                       (Periodic live stats report)
--------------------------------------------------------------------
  Tracing started! Press Ctrl+C to terminate and view full summary.

TIME      UID    PID     PARENT           FILENAME / EVENT
--------------------------------------------------------------------
```

---

### ขั้นตอนที่ 3: จำลองการทำงานและทราฟฟิกเครือข่าย
เปิด Terminal ที่ 2 แล้วทดลองรันคำสั่งต่างๆ:
```bash
# 1. รันโปรเซสใหม่
ls -la /tmp
whoami

# 2. ส่งทราฟฟิก TCP ขนาดต่างๆ
curl -s https://example.com > /dev/null
curl -s https://www.google.com > /dev/null
```

---

### ขั้นตอนที่ 4: สังเกตการณ์ผลลัพธ์แบบ Real-Time
ใน Terminal ที่ 1 คุณจะเห็นเหตุการณ์เกิดขึ้นสดๆ (ตัดจากผลจริงในหัวข้อ 4):
```text
22:22:21  1000   107992  bash             /usr/bin/ls
22:22:21  1000   107996  bash             /usr/bin/whoami
22:22:21  1000   107997  bash             /usr/bin/curl

--- [Periodic Report (every 10s): cumulative since start] ---

Top Processes by TCP Transmit Calls:
@tcp_send_calls[curl]: 14
...
```
> บนเครื่องที่มีงานอื่นรันอยู่ (cron, Docker, IDE ฯลฯ) จะเห็น exec ของโปรเซสอื่นปนมาจำนวนมาก ลองกรองด้วย predicate เช่น `/uid == 1000/` (ดูแบบฝึกหัด)

---

### ขั้นตอนที่ 5: ใช้ `bpftool` ตรวจสอบโปรแกรม bpftrace ในเคอร์เนล
เปิด Terminal ที่ 3 ในขณะที่ `bpftrace` กำลังรันอยู่:
```bash
# ตรวจสอบว่าโปรแกรมของ bpftrace ถูกติดตั้งไว้ที่เคอร์เนลจริง
sudo bpftool prog show | grep -A2 -E "tracepoint|kprobe"
```

คุณจะเห็น eBPF Programs ที่ถูก JITed ลงไปทำงานในเคอร์เนล (ผลจริงอยู่ในหัวข้อ 4.2 — ชื่อโปรแกรมที่ bpftrace ตั้งให้มีรูปแบบ `<ชนิด>_<probe>_<ลำดับ>`)

เมื่อคุณกด `Ctrl+C` ใน Terminal ที่ 1 โปรแกรม `bpftrace` จะดึงสถิติสรุปทั้งหมดออกมาแสดง และเคอร์เนลจะ Detach พร้อมคืนหน่วยความจำทันทีโดยไม่มีตกค้าง!

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), bpftrace v0.25.0, bpftool v7.7 — เครื่องทดสอบมีงานอื่นรันพร้อมกันจำนวนมาก (build, Docker, agent อื่นๆ) ผลจึงยาวกว่า 2,000 บรรทัด ด้านล่างเป็นส่วนที่ตัดมาโดยไม่แก้ไขเนื้อหา

### 4.1 ผลลัพธ์การรัน `sudo bpftrace trace_exec_and_tcp.bt` (ประมาณ 12 วินาที) ขณะรัน `ls`, `whoami`, `curl` สองครั้ง และ `bpftool`
```text
Attached 6 probes

====================================================================
  eBPF Zero to Hero - Week 03: Process Execution & TCP Observability
====================================================================
  Active Probes:
    1. tracepoint:sched:sched_process_exec (New process launches)
    2. kprobe:tcp_sendmsg                  (TCP payload histogram)
    3. tracepoint:tcp:tcp_retransmit_skb   (TCP packet drops/retrans)
    4. interval:s:10                       (Periodic live stats report)
--------------------------------------------------------------------
  Tracing started! Press Ctrl+C to terminate and view full summary.

TIME      UID    PID     PARENT           FILENAME / EVENT
--------------------------------------------------------------------
...
22:22:21  0      107991  bash             /usr/bin/sleep
22:22:21  1000   107992  bash             /usr/bin/ls
22:22:21  0      107993  bash             /usr/bin/sleep
22:22:21  0      107994  bash             /usr/bin/sleep
22:22:21  0      107995  bash             /usr/bin/sleep
22:22:21  1000   107996  bash             /usr/bin/whoami
22:22:21  1000   107997  bash             /usr/bin/curl
...
22:22:27  0      0       swapper/4        [TCP RETRANSMIT] <local-ip>:45576 -> 185.125.190.101:80 (State: 2)
...
--- [Periodic Report (every 10s): cumulative since start] ---

Top Processes by TCP Transmit Calls:
@tcp_send_calls[HTTP Client]: 1
@tcp_send_calls[NetworkManager]: 1
@tcp_send_calls[2.1.312]: 1
@tcp_send_calls[curl]: 14
@tcp_send_calls[sshd-session]: 15

TCP Payload Size Distribution (Bytes):
@tcp_send_bytes:
[16, 32)               4 |@@@@@@@@@                                           |
[32, 64)               4 |@@@@@@@@@                                           |
[64, 128)             21 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[128, 256)             0 |                                                    |
[256, 512)             0 |                                                    |
[512, 1K)              0 |                                                    |
[1K, 2K)               2 |@@@@                                                |
[2K, 4K)               0 |                                                    |
[4K, 8K)               1 |@@                                                  |


TCP Retransmissions Observed:
@tcp_retransmit_count[tailscaled]: 1
@tcp_retransmit_count[swapper/2]: 1
@tcp_retransmit_count[swapper/6]: 1
@tcp_retransmit_count[sleep]: 1
@tcp_retransmit_count[swapper/5]: 3
@tcp_retransmit_count[swapper/4]: 16
----------------------------------------------------------
...
====================================================================
                    FINAL OBSERVABILITY SUMMARY                     
====================================================================

[1] Executed Processes Count:
@process_exec_count[...]: ...   (ตัด 18 บรรทัด)
@process_exec_count[git]: 4
@process_exec_count[2.1.312]: 6
@process_exec_count[ps]: 11
@process_exec_count[sed]: 12
@process_exec_count[date]: 129
@process_exec_count[sleep]: 1805

[2] TCP Transmit Calls per Application:
@tcp_send_calls[HTTP Client]: 1
@tcp_send_calls[claude]: 1
@tcp_send_calls[NetworkManager]: 1
@tcp_send_calls[2.1.312]: 1
@tcp_send_calls[tailscaled]: 1
@tcp_send_calls[curl]: 14
@tcp_send_calls[sshd-session]: 16

[3] Total TCP Transmitted Bytes per Application:
@tcp_send_total_bytes[NetworkManager]: 87
@tcp_send_total_bytes[2.1.312]: 89
@tcp_send_total_bytes[tailscaled]: 504
@tcp_send_total_bytes[sshd-session]: 1096
@tcp_send_total_bytes[curl]: 3856
@tcp_send_total_bytes[HTTP Client]: 5325
@tcp_send_total_bytes[claude]: 28780

[4] Overall TCP Send Payload Distribution (Histogram):
@tcp_send_bytes:
[16, 32)               4 |@@@@@@@@@                                           |
[32, 64)               4 |@@@@@@@@@                                           |
[64, 128)             22 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[128, 256)             0 |                                                    |
[256, 512)             1 |@@                                                  |
[512, 1K)              0 |                                                    |
[1K, 2K)               2 |@@@@                                                |
[2K, 4K)               0 |                                                    |
[4K, 8K)               1 |@@                                                  |
[8K, 16K)              0 |                                                    |
[16K, 32K)             1 |@@                                                  |


[5] TCP Retransmissions Encountered:
@tcp_retransmit_count[tailscaled]: 1
@tcp_retransmit_count[swapper/6]: 2
@tcp_retransmit_count[sleep]: 2
@tcp_retransmit_count[swapper/2]: 3
@tcp_retransmit_count[swapper/5]: 5
@tcp_retransmit_count[swapper/4]: 22
====================================================================
Observation complete. All kernel probes detached safely.
```
- บรรทัด `[TCP RETRANSMIT]` (ปิดบัง IP ต้นทาง) มี `State: 2` = `TCP_SYN_SENT` คือ SYN ที่ไม่ได้รับ SYN-ACK และ `comm` เป็น `swapper/4` (idle task) เพราะเกิดจาก retransmit timer ใน softirq
- `@process_exec_count[sleep]` สูงมากเพราะสคริปต์อื่นบนเครื่องรัน `sleep` วนลูป — นี่คือเหตุผลที่ควรกรองด้วย predicate ในงานจริง

### 4.2 การตรวจสอบ eBPF Programs และ Maps ขณะทำงานด้วย `bpftool`
```text
--- sudo bpftool prog show (เฉพาะโปรแกรมของ bpftrace) ---
11038: tracepoint  name tracepoint_sched_sched_process_exec_2  tag 728a8b061c4d55e8  gpl
	loaded_at 2026-10-28T22:22:19+0700  uid 0
	xlated 1584B  jited 882B  memlock 4096B  map_ids 5191,5193,5192,5189,5194,5184
11039: kprobe  name kprobe_tcp_sendmsg_3  tag 9785260b0e69d437  gpl
	loaded_at 2026-10-28T22:22:19+0700  uid 0
	xlated 2320B  jited 1287B  memlock 4096B  map_ids 5186,5189,5191,5194,5187,5188
11040: tracepoint  name tracepoint_tcp_tcp_retransmit_skb_4  tag a01b7a6ebe961729  gpl
	loaded_at 2026-10-28T22:22:19+0700  uid 0
	xlated 2304B  jited 1284B  memlock 4096B  map_ids 5191,5193,5189,5194,5185

--- sudo bpftool map show (เฉพาะ map ของ bpftrace) ---
5184: percpu_hash  name AT_process_exec  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 623488B
	btf_id 5973
5185: percpu_hash  name AT_tcp_retransm  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 623488B
	btf_id 5973
5186: percpu_hash  name AT_tcp_send_byt  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 623488B
	btf_id 5973
5187: percpu_hash  name AT_tcp_send_cal  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 623488B
	btf_id 5973
5188: percpu_hash  name AT_tcp_send_tot  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 623488B
	btf_id 5973
```
- bpftrace สร้าง Map ชนิด `percpu_hash` ให้ `count()`/`sum()`/`hist()` เพื่อหลีกเลี่ยง lock ข้าม CPU แล้วรวมค่าตอนพิมพ์ — `max_entries 4096` มาจากค่าเริ่มต้น `BPFTRACE_MAX_MAP_KEYS`

---

## 5. Milestone Checklist

- [x] **eBPF VM Architecture**: เข้าใจหลักการทำงานของ eBPF Registers, In-Kernel Verifier, และ JIT Compiler
- [x] **Probe Selection Mastery**: เข้าใจความแตกต่าง ข้อดี และข้อจำกัดระหว่าง `tracepoint`, `kprobe`, `kretprobe`, และ `uprobe`
- [x] **bpftrace DSL**: สามารถเขียนสคริปต์ bpftrace ดักจับ System Calls, Kernel Function Arguments, และสร้าง Logarithmic Histogram ด้วย `hist()`
- [x] **bpftool Operations**: สามารถใช้คำสั่ง `bpftool prog show`, `bpftool prog dump`, และ `bpftool map` เพื่อตรวจสอบสถานะ eBPF ในเคอร์เนลได้
- [x] **Network Observability**: สามารถตรวจจับปัญหา TCP Retransmission และวัดขนาด Packet Throughput ได้จากภายในเคอร์เนลโดยตรง

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

ข้อความต่อไปนี้ทดสอบจริงด้วย bpftrace v0.25.0 บน Linux 7.0 (รูปแบบข้อความอาจต่างไปในเวอร์ชันอื่น):

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `ERROR: Failed to open kernel function info: Error reading events from /sys/kernel/tracing/available_events (Permission denied)` | รัน bpftrace โดยไม่ใช้ `sudo` (Ubuntu ตั้ง `kernel.unprivileged_bpf_disabled=2` ผู้ใช้ทั่วไปจึงโหลด BPF ไม่ได้) | `sudo bpftrace ...` |
| `ERROR: No matches for kprobe tcp_sendmsgx.` | ชื่อฟังก์ชันผิด หรือฟังก์ชันถูก **inline** หายไป / ถูก compiler เปลี่ยนชื่อเป็น `xxx.isra.0`, `xxx.constprop.0` (บน 7.0 มีกว่า 2,000 ฟังก์ชันที่มีจุดในชื่อแบบนี้) | ค้นชื่อจริงก่อนด้วย `sudo bpftrace -l 'kprobe:*tcp_send*'` ถ้าไม่พบเลยให้ใช้ tracepoint หรือฟังก์ชันที่เรียกมันแทน |
| `ERROR: Struct/union of type 'struct tracepoint:tcp:tcp_retransmit_skb_args' does not contain a field named 'saddrx'` | อ้างชื่อ field ของ tracepoint ผิด หรือ field เปลี่ยนในเคอร์เนลรุ่นนี้ | `sudo bpftrace -lv tracepoint:tcp:tcp_retransmit_skb` ดูรายชื่อ field จริง |
| **ไม่มี error แต่ `syscalls:sys_enter_execve` จับ exec ได้น้อยผิดปกติ** | บน Ubuntu 26.04 / Linux 7.0.0-38 เราสังเกตว่าโปรแกรม BPF บน `syscalls:sys_enter_execve` และ `sys_enter_openat` ทำงานเฉพาะเมื่อ syscall เกิดบน **CPU 0** (`sys_enter_getpid` ปกติ; `perf stat` ยังนับได้ครบ) — ยังไม่ยืนยันสาเหตุ | ใช้ `tracepoint:sched:sched_process_exec` หรือ `tracepoint:raw_syscalls:sys_enter /args->id == 59/` ซึ่งทำงานครบทุก CPU และตรวจซ้ำด้วยการทดลองด้านล่าง |
| ตัวเลขใน Periodic Report ไม่ลดลงเลย | `print()` ไม่ล้าง map ค่าจึงสะสม | ใส่ `clear(@map)` หลัง `print` ถ้าต้องการยอดต่อช่วง |
| `Lost N events` | perf buffer ของ `printf` เต็ม เพราะ event ถี่เกินกว่า user space จะอ่านทัน | กรองด้วย predicate (`/uid == 1000/`), ใช้ aggregation แทน `printf` หรือเพิ่ม `BPFTRACE_PERF_RB_PAGES` |
| `ls: cannot access '/sys/kernel/btf/vmlinux'` / bpftrace ใช้ `curtask->...` ไม่ได้ | เคอร์เนลไม่ได้คอมไพล์ด้วย `CONFIG_DEBUG_INFO_BTF=y` | ใช้เคอร์เนลของ distro รุ่นใหม่ (Ubuntu 20.10+ เปิดไว้แล้ว) ตรวจด้วย `grep BTF /boot/config-$(uname -r)` |

**วิธีพิสูจน์ว่า probe จับเหตุการณ์ได้ครบทุก CPU** (ควรทำทุกครั้งที่เลือก probe ใหม่):
```bash
sudo timeout -s INT 8 bpftrace -e '
tracepoint:syscalls:sys_enter_execve /comm == "taskset"/ { @sys_enter_execve[cpu] = count(); }
tracepoint:raw_syscalls:sys_enter /args->id == 59 && comm == "taskset"/ { @raw_execve[cpu] = count(); }
tracepoint:sched:sched_process_exec /str(args->filename) == "/bin/true"/ { @sched_exec[cpu] = count(); }' &
sleep 4; for c in 0 1 2 3 4 5 6 7; do taskset -c $c /bin/true; done; wait
```
(ใช้ `timeout -s INT` แทน `pkill bpftrace` เพื่อไม่ไปหยุด bpftrace ของคนอื่นบนเครื่องเดียวกัน; ปรับเลข CPU ตาม `nproc`)
ผลที่ได้บนเครื่องทดสอบ: `@raw_execve` และ `@sched_exec` มีครบ 8 CPU (CPU ละ 1) แต่ `@sys_enter_execve` มีเพียง `[0]: 1`

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **กรองเฉพาะผู้ใช้ของคุณ**: เพิ่ม predicate `/uid == $UID/` (แทนค่าด้วย `id -u`) ให้ probe `sched_process_exec` เพื่อตัด exec ของ root/daemon ออก
   - **สิ่งที่ต้องส่ง**: สคริปต์ที่แก้ + ผลรันที่เห็นเฉพาะคำสั่งที่คุณพิมพ์
   - **วิธีตรวจ**: รันสคริปต์ แล้วพิมพ์ `ls; whoami` ในอีก Terminal ต้องเห็นสองบรรทัดนี้ และไม่เห็นบรรทัดที่ `UID` เป็น 0
2. **สำรวจ probe ด้วย `bpftrace -l`/`-lv`**: หาว่าเคอร์เนลของคุณมี tracepoint ในกลุ่ม `tcp:` กี่ตัว และ `tcp:tcp_retransmit_skb` มี field อะไรบ้าง
   - **สิ่งที่ต้องส่ง**: จำนวน + รายชื่อ field พร้อมอธิบาย `state` และ `err` (field ใหม่บน 7.0)
   - **วิธีตรวจ**: `sudo bpftrace -l 'tracepoint:tcp:*' | wc -l` และ `sudo bpftrace -lv tracepoint:tcp:tcp_retransmit_skb`

### ระดับปานกลาง
3. **Periodic Report แบบต่อช่วงจริง**: แก้ `interval:s:10` ให้พิมพ์ยอดเฉพาะ 10 วินาทีล่าสุด (ใช้ `clear()`) แต่ยังให้ `END` สรุปยอดรวมทั้งหมดได้ถูกต้อง (คำใบ้: ใช้ map คู่ เช่น `@win_calls` กับ `@total_calls`)
   - **สิ่งที่ต้องส่ง**: สคริปต์ + ผลที่รายงานรอบที่ 2 ไม่รวมยอดของรอบแรก
   - **วิธีตรวจ**: รัน `curl -s https://example.com >/dev/null` ในช่วง 10 วินาทีแรกเท่านั้น รายงานรอบที่ 2 ต้องไม่มี `curl` แต่ `END` ยังแสดง `curl`
4. **วัด latency ของ `tcp_sendmsg`**: ใช้ `kprobe` + `kretprobe` (หรือ `fentry`/`fexit` ซึ่งบน 7.0 ชื่อ `fentry:vmlinux:tcp_sendmsg`) เก็บ `nsecs` แล้วทำ `hist()` ของเวลาที่ใช้ในฟังก์ชัน แยกตาม `comm`
   - **สิ่งที่ต้องส่ง**: สคริปต์ + histogram หน่วยไมโครวินาที + อธิบายว่าทำไมต้องใช้ key `tid` ไม่ใช่ `pid`
   - **วิธีตรวจ**: `sudo bpftrace -lv 'fentry:vmlinux:tcp_sendmsg'` ต้องเห็น `retval`; สร้างทราฟฟิกด้วย `curl` แล้วต้องเห็น histogram ของ `curl`

### ระดับท้าทาย
5. **พิสูจน์และรายงานปัญหา `sys_enter_*` บน CPU ≠ 0**: ทำการทดลองแบบในหัวข้อ 6 กับ syscall อย่างน้อย 5 ตัว (เช่น `getpid`, `openat`, `execve`, `read`, `write`) สรุปเป็นตารางว่าตัวใดได้รับผลกระทบ เทียบกับ `perf stat -e syscalls:sys_enter_<name>` และตั้งสมมติฐานว่าเกี่ยวข้องกับ syscall ที่รับ pointer ของ string จาก user space หรือไม่
   - **สิ่งที่ต้องส่ง**: ตารางผล + สคริปต์ทดลองที่ทำซ้ำได้ + สมมติฐาน (ระบุชัดว่าเป็นสมมติฐาน ยังไม่ใช่ข้อสรุป)
   - **วิธีตรวจ**: ผู้ตรวจรันสคริปต์ของคุณซ้ำแล้วได้ตารางเดียวกัน
6. **Exec tracer ที่ได้ argv ครบ**: เขียนสคริปต์ที่แสดง command line เต็ม (argv) ของทุก exec บนทุก CPU โดยไม่พึ่ง `syscalls:sys_enter_execve` (คำใบ้: `raw_syscalls:sys_enter` ที่ `args->id == 59` ให้ pointer `args->args[1]` เป็น `char **argv` ใน user space — ต้องอ่านทีละ element ด้วย `uptr()`/`str()` และระวังกรณีอ่าน user memory ไม่สำเร็จ)
   - **สิ่งที่ต้องส่ง**: สคริปต์ + ผลที่ `taskset -c $c /bin/echo hello-$c` ทั้ง 8 CPU แสดง argv ครบ
   - **วิธีตรวจ**: `for c in 0 1 2 3 4 5 6 7; do taskset -c $c /bin/echo hello-$c >/dev/null; done` ต้องเห็น `hello-0` ถึง `hello-7`
