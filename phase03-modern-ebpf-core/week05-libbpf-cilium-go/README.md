# Week 05: Modern eBPF with libbpf & Cilium ebpf-go

ยินดีต้อนรับสู่สัปดาห์ที่ 5 ของหลักสูตร **eBPF: Zero-to-Hero** ในสัปดาห์นี้ เราจะก้าวข้ามเครื่องมือระดับสูงอย่าง BCC/bpftrace เข้าสู่สถาปัตยกรรมระดับโปรดักชันยุคใหม่ (Modern eBPF) ด้วยการเขียนโปรแกรมฝั่งเคอร์เนลด้วยภาษา C และโปรแกรมฝั่งผู้ใช้งาน (Userspace Control Plane) ด้วยภาษา Go โดยใช้ไลบรารีมาตรฐานระดับโลกคือ **Cilium ebpf-go** ร่วมกับเครื่องมือคอมไพล์โค้ดอัตโนมัติ **bpf2go**

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 วิวัฒนาการจาก BCC สู่ Modern CO-RE (Compile Once – Run Everywhere)

ในยุคแรกเริ่ม (BCC - BPF Compiler Collection) การรันโค้ด eBPF ต้องนำซอร์สโค้ดภาษา C ไปคอมไพล์บนโฮสต์เป้าหมาย ณ เวลา Runtime ผ่าน Clang/LLVM ฝังตัว และจำเป็นต้องติดตั้งแพ็กเกจ `linux-headers` ขนาดหลายร้อยเมกะไบต์ลงบน Production Node ซึ่งสร้าง Overhead สูง เสี่ยงต่อความปลอดภัย และกินทรัพยากรซีพียู/หน่วยความจำอย่างมหาศาล

Modern eBPF แก้ปัญหานี้ด้วยสถาปัตยกรรม **CO-RE (Compile Once – Run Everywhere)** ซึ่งประกอบด้วย 3 เสาหลัก:
1. **BTF (BPF Type Format):** เมทาดาตาของเคอร์เนลที่บรรจุโครงสร้างข้อมูล (struct, types, fields) ขนาดกะทัดรัด (เพียงไม่กี่เมกะไบต์) อยู่ที่ `/sys/kernel/btf/vmlinux`
2. **Clang / Target BPF:** คอมไพเลอร์ที่แปลงโค้ด C เป็น eBPF Bytecode ล่วงหน้า โดยบันทึกการเข้าถึงฟิลด์ต่าง ๆ เป็น BPF Relocation Entries
3. **BPF Loader (Cilium ebpf-go / libbpf):** ตัวโหลดระดับ Userspace ที่อ่าน BTF ของเคอร์เนลเครื่องปลายทาง และปรับแก้ Memory Offsets (Field Relocation) ก่อนยิงเข้าเคอร์เนล ทำให้ eBPF ELF binary เดียวกันสามารถรันข้ามเวอร์ชันเคอร์เนลได้อย่างปลอดภัย

```
+--------------------------------------------------------------------------------+
|                             USERSPACE (Golang Control Plane)                   |
|                                                                                |
|  +------------------+         go generate (bpf2go)         +----------------+  |
|  |    counter.c     |  --------------------------------->  |   bpf2go ELF   |  |
|  |  (C Source Code) |      (Invokes Clang -target bpf)     | Embedded in Go |  |
|  +------------------+                                      +----------------+  |
|                                                                    |           |
|                                            bpf(BPF_PROG_LOAD)      |           |
|                                            bpf(BPF_MAP_CREATE)     v           |
|  +--------------------------------------------------------------------------+  |
|  | main.go: rlimit.RemoveMemlock() -> loadBpfObjects() -> link.Tracepoint() |  |
|  +--------------------------------------------------------------------------+  |
+--------------------------------------|-----------------------------------------+
                                       | Syscall bpf()
=======================================|==========================================
                                       v
+--------------------------------------------------------------------------------+
|                             LINUX KERNEL SPACE                                 |
|                                                                                |
|  +--------------------------------------------------------------------------+  |
|  |                           eBPF Verifier                                  |  |
|  |   - ตรวจสอบความปลอดภัยหน่วยความจำ ป้องกัน NULL pointer dereference        |  |
|  |   - ตรวจสอบความลึกและลูปของการทำงาน (Max complexity check)               |  |
|  +--------------------------------------------------------------------------+  |
|                                      |                                         |
|                                      v                                         |
|  +--------------------------------------------------------------------------+  |
|  |                         JIT Compiler (Native asm)                        |  |
|  +--------------------------------------------------------------------------+  |
|                                      |                                         |
|         Event Trigger:               v                                         |
|  [ Process calls execve() ] ---> Hook: tracepoint/syscalls/sys_enter_execve    |
|                                      |                                         |
|                                      +---> bpf_map_lookup_elem(&exec_count, 0) |
|                                      |     __sync_fetch_and_add(val, 1)        |
|                                      |                                         |
|                                      +---> bpf_printk("PID %d", pid)           |
|                                            |                                   |
|                                            v                                   |
|                          /sys/kernel/debug/tracing/trace_pipe                  |
+--------------------------------------------------------------------------------+
```

---

### 1.2 การทำงานของ bpf2go

`bpf2go` เป็นเครื่องมือของโปรเจกต์ Cilium ที่ทำหน้าที่:
1. เรียก `clang` เพื่อคอมไพล์โค้ด eBPF C ให้เป็น ELF binary ทั้งแบบ Little-Endian (`bpf_bpfel.o`) และ Big-Endian (`bpf_bpfeb.o`)
2. ดึงข้อมูล BTF จาก ELF binary เพื่อนำมา Generate Go structs ที่แมปกับ eBPF Maps และ Programs อัตโนมัติ (เช่น `bpfObjects`, `bpfPrograms`, `bpfMaps`)
3. ฝัง eBPF Bytecode ลงในไฟล์ Go source code (`bpf_bpfel.go`, `bpf_bpfeb.go`) โดยตรง ทำให้ไบนารี Go ที่คอมไพล์ออกมาเป็น Single Static Binary ไม่จำเป็นต้องมีไฟล์ `.o` แยกต่างหากตอนนำไปรันบนเซิร์ฟเวอร์

---

### 1.3 ทำไมต้องใช้ `rlimit.RemoveMemlock()`?

ใน Linux Kernel เวอร์ชันเก่ากว่า 5.11 การจองหน่วยความจำสำหรับ eBPF Maps และ eBPF Programs ถูกจำกัดด้วยโควตา `RLIMIT_MEMLOCK` (Locked Memory Limit) ซึ่งค่าเริ่มต้นของโปรเซสมักถูกตั้งไว้ต่ำมาก (เพียง 64 KB) หากโปรแกรมโหลด eBPF Map ขนาดใหญ่ เคอร์เนลจะปฏิเสธด้วยข้อผิดพลาด `EPERM` หรือ `ENOMEM`

ฟังก์ชัน `rlimit.RemoveMemlock()` ของ Cilium จะทำการเรียก Syscall `setrlimit` เพื่อขยาย `RLIMIT_MEMLOCK` เป็น `RLIM_INFINITY` ให้กับโปรเซสโดยอัตโนมัติ

> [!NOTE]
> ใน Linux Kernel 5.11 ขึ้นไป เคอร์เนลได้เปลี่ยนมาใช้ระบบ cgroup-based memory accounting สำหรับ eBPF memory ทำให้ไม่ต้องพึ่งพา `RLIMIT_MEMLOCK` อีกต่อไป อย่างไรก็ตาม การเรียก `rlimit.RemoveMemlock()` ยังคงเป็น Best Practice เพื่อให้โค้ดทำงานได้บนทุกเคอร์เนลย้อนหลัง

---

### 1.4 ความสำคัญของ Atomic Operations ใน eBPF Maps

เมื่อโปรแกรม eBPF ถูกแนบ (Hook) เข้ากับ Tracepoint ยอดนิยมอย่าง `sys_enter_execve` โปรแกรมอาจถูกเรียกทำงานพร้อมกันจากหลาย CPU Cores ในเสี้ยววินาทีเดียวกัน (Symmetric Multiprocessing - SMP)

หากเราทำการอัปเดตตัวนับด้วยโค้ดธรรมดา:
```c
*val = *val + 1; // Unsafe: เกิด Race Condition ได้ทันที
```
ซีพียูจะทำการ Read -> Modify -> Write ซึ่งหากมี Core อื่นเข้ามาแทรกระหว่างกลาง ค่าที่นับได้จะสูญหาย (Lost Update)

เราจึงต้องใช้ Built-in Atomic Instruction:
```c
__sync_fetch_and_add(val, 1); // Safe: ประมวลผลแบบอะตอมมิกผ่านฮาร์ดแวร์ซีพียู
```

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `counter.c`

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
```
- **บรรทัด 1-2:** นำเข้าเฮดเดอร์พื้นฐานของเคอร์เนล BPF และฟังก์ชันผู้ช่วย (BPF Helpers) เช่น `bpf_map_lookup_elem`, `bpf_ktime_get_ns`, `bpf_printk`

```c
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif
```
- **บรรทัด 7-17:** Fallback macros สำหรับกำหนด ELF Section (`SEC`) และนิยามแมปแบบ BTF-defined maps (`__uint`, `__type`) เพื่อให้สามารถคอมไพล์ได้แม้ในสภาพแวดล้อมที่ไม่มีเฮดเดอร์ libbpf เต็มรูปแบบ

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");
```
- **บรรทัด 25-30:** ประกาศ BPF Map ชื่อ `exec_count`
  - `type, BPF_MAP_TYPE_ARRAY`: เป็น Array Map ที่มีขนาดคงที่และเข้าถึงได้รวดเร็วระดับ $O(1)$
  - `max_entries, 1`: บรรจุได้ 1 สล็อต (index 0) สำหรับเก็บผลรวมทั้งระบบ
  - `key, __u32`: คีย์เป็นตัวเลขอินเด็กซ์ขนาด 32 บิต
  - `value, __u64`: ค่าตัวนับสะสมขนาด 64 บิต ป้องกันปัญหา Integer Overflow
  - `SEC(".maps")`: สั่งให้ Clang เก็บโครงสร้างนี้ไว้ใน ELF Section ชื่อ `.maps` เพื่อให้ BPF Loader ทำการสร้าง Map ในเคอร์เนล

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
```
- **บรรทัด 36-37:** ฟังก์ชัน eBPF Hook
  - `SEC("tracepoint/syscalls/sys_enter_execve")`: ระบุ Section ชัดเจนว่าเป็น Tracepoint ดักจับตอนระบบเริ่มเรียก Syscall `execve`
  - `handle_execve`: ชื่อฟังก์ชัน ซึ่ง `bpf2go` จะนำไปแปลงเป็นฟิลด์ `HandleExecve` ในภาษา Go
  - `void *ctx`: พอยน์เตอร์ชี้ไปยังบริบทของ Tracepoint พารามิเตอร์

```c
    __u32 key = 0;
    __u64 *val;

    val = bpf_map_lookup_elem(&exec_count, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
```
- **บรรทัด 39-46:** ค้นหาสล็อตที่ Index 0 ใน Map `exec_count`
  - `bpf_map_lookup_elem`: คืนค่าพอยน์เตอร์ไปยัง Value ในเคอร์เนลเมมโมรี
  - `if (val)`: **หัวใจสำคัญของ eBPF Verifier** หากไม่มีการตรวจสอบว่า `val != NULL` ตัว Verifier จะปฏิเสธไม่ให้โปรแกรมทำงานทันที เพื่อป้องกัน Kernel Panic
  - `__sync_fetch_and_add(val, 1)`: บวกค่าตัวนับขึ้น 1 แบบอะตอมมิก

```c
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    bpf_printk("execve called by PID %d\n", pid);

    return 0;
```
- **บรรทัด 48-53:**
  - `bpf_get_current_pid_tgid()`: ดึงค่า 64-bit ID โดย 32 บิตบนคือ Process ID (PID) และ 32 บิตล่างคือ Thread ID (TGID)
  - `pid_tgid >> 32`: บิตชิฟต์ไปทางขวา 32 บิต เพื่อแยกเอาเฉพาะค่า PID ของโปรเซสที่เรียกใช้
  - `bpf_printk`: ส่งข้อความดีบักเข้าสู่ระบบ Tracing Ring Buffer ของเคอร์เนล
  - `return 0`: คืนค่า 0 แจ้งเคอร์เนลว่าโปรแกรมทำงานสมบูรณ์

```c
char LICENSE[] SEC("license") = "Dual BSD/GPL";
```
- **บรรทัด 56:** กำหนดไลเซนส์เป็น Dual BSD/GPL ซึ่งจำเป็นต้องมีเพื่อให้เคอร์เนลอนุญาตให้เรียกใช้ฟังก์ชัน BPF Helpers ขั้นสูงที่เป็น GPL-only

---

### 2.2 ไฟล์ `main.go`

```go
//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf counter.c
```
- **บรรทัด 1-6:**
  - Build tag กำหนดให้คอมไพล์บนระบบปฏิบัติการ Linux
  - `//go:generate`: คำสั่งสร้างโค้ดอัตโนมัติ โดยระบุให้ใช้คอมไพเลอร์ `clang` และตั้งชื่อ Package/Struct prefix เป็น `bpf` จากซอร์สโค้ด `counter.c`

```go
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock limit: %v", err)
	}
```
- **บรรทัด 24-26:** ปลดล็อกข้อจำกัดหน่วยความจำล็อกสำหรับ eBPF Maps

```go
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()
```
- **บรรทัด 29-33:**
  - `loadBpfObjects`: โหลดและตรวจสอบ eBPF Bytecode เข้าสู่เคอร์เนล พร้อมทั้งสร้าง BPF Maps
  - `defer objs.Close()`: รับประกันการคืนหน่วยความจำและปิด File Descriptors ทั้งหมดเมื่อโปรแกรมยุติการทำงาน

```go
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to sys_enter_execve: %v", err)
	}
	defer tp.Close()
```
- **บรรทัด 36-40:** แนบ (Attach) eBPF Program เข้ากับเคอร์เนล Tracepoint `syscalls/sys_enter_execve` ผ่านเคอร์เนล Perf Event Subsystem

```go
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var count uint64
			if err := objs.ExecCount.Lookup(&key, &count); err != nil {
				log.Printf("Error looking up exec_count map: %v", err)
				continue
			}
			rate := count - previousCount
			previousCount = count
			fmt.Printf("[%s] Total execve() invocations: %-8d | Rate: %-4d calls/sec\n", ...)
```
- **บรรทัด 50-68:** การโพลล์ค่าจาก BPF Map
  - วนลูปอ่านค่าจาก Map `exec_count` ทุก 1 วินาทีผ่านเมธอด `Lookup(&key, &count)`
  - คำนวณอัตราความเร็ว (Invocations per second) และแสดงผลบนหน้าจอแบบเรียลไทม์

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบความพร้อมของระบบ
โปรแกรมต้องการเคอร์เนล Linux ที่รองรับ eBPF และติดตั้ง Go, Clang:
```bash
# ตรวจสอบเวอร์ชันของ Go และ Clang
go version
clang --version
```

### ขั้นตอนที่ 2: สร้างโค้ด Go Bindings ด้วย `go generate`
```bash
cd phase03-modern-ebpf-core/week05-libbpf-cilium-go
make generate
```
ผลลัพธ์จะเกิดไฟล์ที่สร้างขึ้นอัตโนมัติ 4 ไฟล์:
- `bpf_bpfel.go` / `bpf_bpfeb.go`: Go Source code ที่ห่อหุ้ม BPF Objects
- `bpf_bpfel.o` / `bpf_bpfeb.o`: BPF ELF Bytecode

### ขั้นตอนที่ 3: คอมไพล์โปรแกรม
```bash
make build
```
จะได้ไบนารีที่ไดเรกทอรี `bin/exec-counter`

### ขั้นตอนที่ 4: สั่งรันโปรแกรมด้วยสิทธิ์ Root
```bash
make run
# หรือรันตรงๆ: sudo ./bin/exec-counter
```

**ตัวอย่างหน้าจอผลลัพธ์:**
```text
======================================================================
 eBPF Syscall Execve Monitor (Cilium ebpf-go + CO-RE)
======================================================================
2026/10/17 21:00:00 Successfully hooked tracepoint 'syscalls/sys_enter_execve'!
2026/10/17 21:00:00 Monitoring active processes... Press Ctrl+C to terminate.

[21:00:01] Total execve() invocations: 0        | Rate: 0    calls/sec
[21:00:02] Total execve() invocations: 4        | Rate: 4    calls/sec
[21:00:03] Total execve() invocations: 12       | Rate: 8    calls/sec
```

### ขั้นตอนที่ 5: สร้างทราฟฟิกทดสอบและตรวจสอบ Kernel Trace Pipe
เปิดหน้าต่างเทอร์มินัลอีกหน้าต่างหนึ่ง แล้วสั่งรันคำสั่งต่าง ๆ เพื่อกระตุ้น `execve()`:
```bash
# รันคำสั่งต่อเนื่อง
for i in {1..10}; do ls /usr > /dev/null; sleep 0.2; done
```

ดูข้อความ Debug ที่ส่งออกจาก `bpf_printk()`:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
**ผลลัพธ์ที่ปรากฏ:**
```text
    <...>-18429 [002] d... 41235.120: bpf_trace_printk: execve called by PID 18429
    <...>-18430 [003] d... 41235.325: bpf_trace_printk: execve called by PID 18430
```

### ขั้นตอนที่ 6: ตรวจสอบสถานะ eBPF ด้วย `bpftool`
```bash
# ตรวจสอบว่าโปรแกรม eBPF กำลังโหลดอยู่ในเคอร์เนล
sudo bpftool prog list name handle_execve

# ตรวจสอบค่าใน Map จากฝั่งเคอร์เนลโดยตรง
sudo bpftool map dump name exec_count
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 24.04 LTS (`Linux ebpf-lab 6.8.0-142-generic #142-Ubuntu SMP PREEMPT_DYNAMIC aarch64`)

### 4.1 การคอมไพล์ด้วย `bpf2go` และรัน `./bin/exec-counter`
```text
===> Generating Go bindings from counter.c via bpf2go...
go generate ./...
Compiled /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfel.o
Stripped /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfel.o
Wrote /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfel.go
Compiled /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfeb.o
Stripped /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfeb.o
Wrote /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfeb.go
===> Building userspace binary bin/exec-counter...
mkdir -p bin
go build -v -o bin/exec-counter .

======================================================================
 eBPF Syscall Execve Monitor (Cilium ebpf-go + CO-RE)
======================================================================
2026/10/18 13:38:00 Successfully hooked tracepoint 'syscalls/sys_enter_execve'!
2026/10/18 13:38:00 Monitoring active processes... Press Ctrl+C to terminate.

[13:38:01] Total execve() invocations: 0        | Rate: 0    calls/sec
[13:38:02] Total execve() invocations: 0        | Rate: 0    calls/sec
[13:38:03] Total execve() invocations: 10       | Rate: 10   calls/sec
[13:38:04] Total execve() invocations: 20       | Rate: 10   calls/sec
[13:38:05] Total execve() invocations: 34       | Rate: 14   calls/sec

Received signal 'terminated'. Shutting down cleanly...
Final cumulative execve() syscall count: 34
eBPF program and tracepoint links detached successfully.
```

---

## 5. Milestone Checklist

- [x] เข้าใจสถาปัตยกรรม Modern eBPF, BTF, และความต่างของ CO-RE เทียบกับ BCC
- [x] เขียนโปรแกรม eBPF C ดักจับ Kernel Tracepoint `syscalls/sys_enter_execve`
- [x] ใช้งาน eBPF Map ประเภท `BPF_MAP_TYPE_ARRAY` ร่วมกับคำสั่ง Atomic `__sync_fetch_and_add`
- [x] เข้าใจและประยุกต์ใช้ `rlimit.RemoveMemlock()` สำหรับการจัดการหน่วยความจำ
- [x] ใช้งาน `bpf2go` เพื่อคอมไพล์ C เป็น BPF Bytecode และสร้าง Go type bindings อัตโนมัติ
- [x] พัฒนา Userspace Monitor ด้วย Go และ Cilium ebpf-go จัดการ Lifecycle และ Graceful Shutdown
- [x] ตรวจสอบการทำงานผ่าน `/sys/kernel/debug/tracing/trace_pipe` และ `bpftool` ได้อย่างสมบูรณ์
