# สัปดาห์ที่ 03: ก้าวแรกสู่ eBPF ด้วย bpftool และ bpftrace

ยินดีต้อนรับสู่ **Week 03** ของหลักสูตร **eBPF Noob to Hero**!
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
- **JIT Compiler (Just-In-Time)**: แปลง eBPF Bytecode ให้เป็น Native Machine Code (x86_64, ARM64) โดยตรง ทำให้ทำงานด้วยความเร็วสูงสุดระดับฮาร์ดแวร์

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
| **`tracepoint`** | จุดที่เคอร์เนลฝังไว้ล่วงหน้า (`/sys/kernel/debug/tracing/events`) | **สูงมาก** (เสถียรข้ามรุ่นเคอร์เนล) | ต่ำมาก | ติดตาม System Calls (`syscalls:sys_enter_execve`), TCP events (`tcp:tcp_retransmit_skb`) |
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
    printf("%-9s %-6s %-6s %-16s %s\n", "TIME", "UID", "PID", "COMM", "ARGS / EVENT");
}
```
- **คำอธิบาย**: รันครั้งเดียวเมื่อโปรแกรมถูกโหลดเข้าสู่เคอร์เนลสำเร็จ ใช้ในการพิมพ์หัวตารางและคำอธิบาย

```c
/*
 * 2. การดักจับ Process Execution
 */
tracepoint:syscalls:sys_enter_execve
{
    time("%H:%M:%S  ");
    printf("%-6d %-6d %-16s ", uid, pid, comm);
    join(args->argv);
    @process_exec_count[comm] = count();
}
```
- **คำอธิบาย**:
  - `tracepoint:syscalls:sys_enter_execve`: ถูกทริกเกอร์ทุกครั้งที่มีกระบวนการเรียก `execve` เพื่อรันโปรแกรมใหม่
  - `uid`, `pid`, `comm`: Built-in variables แสดง User ID, Process ID, และชื่อโปรเซสสั้นๆ (เช่น `bash`, `curl`)
  - `join(args->argv)`: อ่าน Array ของ Command-line arguments ใน Kernel Memory แล้วรวมเป็นสตริงพิมพ์ออกมา
  - `@process_exec_count[comm] = count()`: บันทึกความถี่ของการรันคำสั่งแยกตามชื่อโปรเซสลงใน BPF Map

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
  - เมื่อเกิดเน็ตเวิร์กติดขัดหรือแพ็กเก็ตสูญหาย เคอร์เนลจะเรียก `tcp_retransmit_skb`
  - `ntop(...)`: Built-in function แปลง IP address จากเลขฐานสองเป็นรูปสตริง IP ที่อ่านง่าย
  - โค้ดนี้ทำให้เราทราบทันทีว่าแอปพลิเคชันตัวใดกำลังประสบปัญหา Packet Loss โดยไม่ต้องเปิด Wireshark ดักจับแพ็กเก็ตทั้งหมด

```c
/*
 * 5. การพิมพ์รายงานสรุปทุกๆ 10 วินาที
 */
interval:s:10
{
    printf("\n--- [Intermediate Periodic Report: Past 10s Activity] ---\n");
    print(@tcp_send_calls);
    print(@tcp_send_bytes);
}
```
- **คำอธิบาย**: เป็น Timer Probe ที่ทริกเกอร์ทุก 10 วินาที ช่วยให้เราเห็นความเคลื่อนไหวของระบบแบบ Real-time โดยไม่ต้องรอจนจบโปรแกรม

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

### ขั้นตอนที่ 2: รันสคริปต์ `trace_exec_and_tcp.bt`
รันสคริปต์ด้วยสิทธิ์ `sudo`:
```bash
sudo bpftrace trace_exec_and_tcp.bt
```

**สิ่งที่แสดงบนหน้าจอ**:
```text
====================================================================
  eBPF Noob to Hero - Week 03: Process Execution & TCP Observability
====================================================================
  Active Probes:
    1. tracepoint:syscalls:sys_enter_execve (New process launches)
    2. kprobe:tcp_sendmsg                  (TCP payload histogram)
    3. tracepoint:tcp:tcp_retransmit_skb   (TCP packet drops/retrans)
    4. interval:s:10                       (Periodic live stats report)
--------------------------------------------------------------------
  Tracing started! Press Ctrl+C to terminate and view full summary.

TIME      UID    PID    COMM             ARGS / EVENT
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
ใน Terminal ที่ 1 คุณจะเห็นเหตุการณ์เกิดขึ้นสดๆ:
```text
21:05:01  1000   48192  bash             ls -la /tmp
21:05:03  1000   48195  bash             whoami
21:05:07  1000   48201  curl             curl -s https://example.com

--- [Intermediate Periodic Report: Past 10s Activity] ---

Top Processes by TCP Transmit Calls:
@tcp_send_calls[curl]: 18

TCP Payload Size Distribution (Bytes):
@tcp_send_bytes: 
[1]                    4 |@@@@@@@@@@@@@@@@@@@@                                |
[2, 4)                 0 |                                                    |
[4, 8)                 0 |                                                    |
[8, 16)                0 |                                                    |
[16, 32)               1 |@@@@@                                               |
[32, 64)               3 |@@@@@@@@@@@@@@@                                     |
[64, 128)              2 |@@@@@@@@@@                                          |
[128, 256)             0 |                                                    |
[256, 512)             8 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            |
```

---

### ขั้นตอนที่ 5: ใช้ `bpftool` ตรวจสอบโปรแกรม bpftrace ในเคอร์เนล
เปิด Terminal ที่ 3 ในขณะที่ `bpftrace` กำลังรันอยู่:
```bash
# ตรวจสอบว่าโปรแกรมของ bpftrace ถูกติดตั้งไว้ที่เคอร์เนลจริง
sudo bpftool prog show | grep -E "tracepoint|kprobe"
```

คุณจะเห็น eBPF Programs ที่ถูก JITed ลงไปทำงานในเคอร์เนล:
```text
412: tracepoint  tag 6de34a2e8c20101b  gpl
	loaded_at 2026-10-17T21:04:58+0700  uid 0
	xlated 288B  jited 184B  memlock 4096B
413: kprobe  tag a711c19b023f81e3  gpl
	loaded_at 2026-10-17T21:04:58+0700  uid 0
	xlated 416B  jited 256B  memlock 4096B
```

เมื่อคุณกด `Ctrl+C` ใน Terminal ที่ 1 โปรแกรม `bpftrace` จะดึงสถิติสรุปทั้งหมดออกมาแสดง และเคอร์เนลจะ Detach พร้อมคืนหน่วยความจำทันทีโดยไม่มีตกค้าง!

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 24.04 LTS (`Linux ebpf-lab 6.8.0-142-generic #142-Ubuntu SMP PREEMPT_DYNAMIC aarch64`)

### 4.1 ผลลัพธ์การรัน `sudo bpftrace trace_exec_and_tcp.bt`
```text
Attaching 6 probes...

====================================================================
  eBPF Noob to Hero - Week 03: Process Execution & TCP Observability
====================================================================
  Active Probes:
    1. tracepoint:syscalls:sys_enter_execve (New process launches)
    2. kprobe:tcp_sendmsg                  (TCP payload histogram)
    3. tracepoint:tcp:tcp_retransmit_skb   (TCP packet drops/retrans)
    4. interval:s:10                       (Periodic live stats report)
--------------------------------------------------------------------
  Tracing started! Press Ctrl+C to terminate and view full summary.

TIME      UID    PID    COMM             ARGS / EVENT
--------------------------------------------------------------------
11:02:31  0      2199   bash             ls -la /tmp
11:02:31  0      2200   bash             whoami
11:02:31  0      2201   bash             curl -4 -s https://example.com
11:02:31  0      2203   bash             curl -4 -s https://www.google.com
11:02:31  0      2205   bash             bpftool prog show
11:02:31  0      2206   bash             grep -E tracepoint|kprobe -A 2
11:02:31  0      2207   bpftool          uname -r
11:02:31  0      2208   bpftool          basename /usr/sbin/bpftool
11:02:31  0      2205   bpftool          /usr/lib/linux-tools/6.8.0-142-generic/bpftool prog show
11:02:31  0      2209   bash             bpftool map show
11:02:31  0      2210   bash             head -n 15
11:02:31  0      2211   bpftool          uname -r
11:02:31  0      2212   bpftool          basename /usr/sbin/bpftool
11:02:31  0      2209   bpftool          /usr/lib/linux-tools/6.8.0-142-generic/bpftool map show
11:02:31  0      2213   bash             sleep 8

--- [Intermediate Periodic Report: Past 10s Activity] ---

Top Processes by TCP Transmit Calls:
@tcp_send_calls[sshd]: 7
@tcp_send_calls[curl]: 13

TCP Payload Size Distribution (Bytes):
@tcp_send_bytes: 
[16, 32)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  |
[32, 64)               3 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[64, 128)              6 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[128, 256)             3 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[256, 512)             1 |@@@@@@@@                                            |
[512, 1K)              3 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |

====================================================================
                    FINAL OBSERVABILITY SUMMARY                     
====================================================================

[1] Executed Processes Count:
@process_exec_count[bpftool]: 6
@process_exec_count[bash]: 9

[2] TCP Transmit Calls per Application:
@tcp_send_calls[sshd]: 7
@tcp_send_calls[curl]: 13

[3] Total TCP Transmitted Bytes per Application:
@tcp_send_total_bytes[curl]: 1636
@tcp_send_total_bytes[sshd]: 1820

[4] Overall TCP Send Payload Distribution (Histogram):
@tcp_send_bytes: 
[16, 32)               4 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                  |
[32, 64)               3 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[64, 128)              6 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[128, 256)             3 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |
[256, 512)             1 |@@@@@@@@                                            |
[512, 1K)              3 |@@@@@@@@@@@@@@@@@@@@@@@@@@                          |

[5] TCP Retransmissions Encountered:
====================================================================
Observation complete. All kernel probes detached safely.
```

### 4.2 การตรวจสอบ eBPF Programs และ Maps ขณะทำงานด้วย `bpftool`
```text
--- sudo bpftool prog show ---
50: tracepoint  name tracepoint_syscalls_sys_enter_execve  tag d37c5749f0076715  gpl
	loaded_at 2026-10-18T11:02:28+0700  uid 0
	xlated 2376B  jited 2096B  memlock 4096B  map_ids 13,14,12,7
51: tracepoint  name tracepoint_tcp_tcp_retransmit_skb  tag 30b4939b5e9ad07a  gpl
	loaded_at 2026-10-18T11:02:28+0700  uid 0
	xlated 1128B  jited 880B  memlock 4096B  map_ids 13,14,8
54: kprobe  name tcp_sendmsg  tag 6c08db3f2218de30  gpl
	loaded_at 2026-10-18T11:02:28+0700  uid 0
	xlated 936B  jited 768B  memlock 4096B  map_ids 9,10,11

--- sudo bpftool map show ---
7: percpu_hash  name AT_process_exec  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 492608B
8: percpu_hash  name AT_tcp_retransm  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 492608B
9: percpu_hash  name AT_tcp_send_byt  flags 0x0
	key 8B  value 8B  max_entries 4096  memlock 459840B
10: percpu_hash  name AT_tcp_send_cal  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 492608B
11: percpu_hash  name AT_tcp_send_tot  flags 0x0
	key 16B  value 8B  max_entries 4096  memlock 492608B
```

---

## 5. Milestone Checklist

- [x] **eBPF VM Architecture**: เข้าใจหลักการทำงานของ eBPF Registers, In-Kernel Verifier, และ JIT Compiler
- [x] **Probe Selection Mastery**: เข้าใจความแตกต่าง ข้อดี และข้อจำกัดระหว่าง `tracepoint`, `kprobe`, `kretprobe`, และ `uprobe`
- [x] **bpftrace DSL**: สามารถเขียนสคริปต์ bpftrace ดักจับ System Calls, Kernel Function Arguments, และสร้าง Logarithmic Histogram ด้วย `hist()`
- [x] **bpftool Operations**: สามารถใช้คำสั่ง `bpftool prog show`, `bpftool prog dump`, และ `bpftool map` เพื่อตรวจสอบสถานะ eBPF ในเคอร์เนลได้
- [x] **Network Observability**: สามารถตรวจจับปัญหา TCP Retransmission และวัดขนาด Packet Throughput ได้จากภายในเคอร์เนลโดยตรง
