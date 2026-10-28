# Week 05: Modern eBPF with libbpf & Cilium ebpf-go

ยินดีต้อนรับสู่สัปดาห์ที่ 5 ของหลักสูตร **eBPF: Zero-to-Hero** ในสัปดาห์นี้ เราจะก้าวข้ามเครื่องมือระดับสูงอย่าง BCC/bpftrace เข้าสู่สถาปัตยกรรมระดับโปรดักชันยุคใหม่ (Modern eBPF) ด้วยการเขียนโปรแกรมฝั่งเคอร์เนลด้วยภาษา C และโปรแกรมฝั่งผู้ใช้งาน (Userspace Control Plane) ด้วยภาษา Go โดยใช้ไลบรารีมาตรฐานระดับโลกคือ **Cilium ebpf-go** ร่วมกับเครื่องมือคอมไพล์โค้ดอัตโนมัติ **bpf2go**

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 วิวัฒนาการจาก BCC สู่ Modern CO-RE (Compile Once – Run Everywhere)

ในยุคแรกเริ่ม (BCC - BPF Compiler Collection) การรันโค้ด eBPF ต้องนำซอร์สโค้ดภาษา C ไปคอมไพล์บนโฮสต์เป้าหมาย ณ เวลา Runtime ผ่าน Clang/LLVM ฝังตัว และจำเป็นต้องติดตั้งแพ็กเกจ `linux-headers` (บน Ubuntu 26.04 / Linux 7.0 ไดเรกทอรี `/usr/src/linux-headers-7.0.0-38*` ใช้พื้นที่ ~170 MB) ลงบน Production Node ซึ่งเพิ่มภาระการดูแล เพิ่มพื้นที่โจมตี และใช้ CPU/หน่วยความจำตอนคอมไพล์ทุกครั้งที่เริ่มโปรแกรม (Week 04 วัดได้ Max RSS ~180 MB ต่อการรันหนึ่งครั้ง)

Modern eBPF แก้ปัญหานี้ด้วยสถาปัตยกรรม **CO-RE (Compile Once – Run Everywhere)** ซึ่งประกอบด้วย 3 เสาหลัก:
1. **BTF (BPF Type Format):** เมทาดาตาของเคอร์เนลที่บรรจุโครงสร้างข้อมูล (struct, types, fields) ขนาดกะทัดรัด (บนเครื่องทดสอบ Linux 7.0 ไฟล์ `/sys/kernel/btf/vmlinux` มีขนาดราว 7 MB เทียบกับ kernel headers ~170 MB) อยู่ที่ `/sys/kernel/btf/vmlinux`
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
|  [ Process execs program ] ---> Hook: tracepoint/sched/sched_process_exec      |
|                                      |                                         |
|                                      +---> bpf_map_lookup_elem(&exec_count, 0) |
|                                      |     __sync_fetch_and_add(val, 1)        |
|                                      |                                         |
|                                      +---> bpf_printk("exec by PID %d", pid)   |
|                                            |                                   |
|                                            v                                   |
|                          /sys/kernel/tracing/trace_pipe                        |
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

ใน Linux Kernel เวอร์ชันเก่ากว่า 5.11 การจองหน่วยความจำสำหรับ eBPF Maps และ eBPF Programs ถูกจำกัดด้วยโควตา `RLIMIT_MEMLOCK` (Locked Memory Limit) ซึ่งค่าเริ่มต้นมักต่ำ (ระบบเก่าหลายตัวตั้ง 64 KB; systemd รุ่นใหม่ตั้ง 8 MB — เครื่องทดสอบ Ubuntu 26.04 ได้ `ulimit -l` = 8192) หากโปรแกรมโหลด eBPF Map ขนาดใหญ่เกินโควตา เคอร์เนลรุ่นเก่าจะปฏิเสธด้วยข้อผิดพลาด `EPERM` หรือ `ENOMEM`

ฟังก์ชัน `rlimit.RemoveMemlock()` ของ Cilium จะทำการเรียก Syscall `setrlimit` เพื่อขยาย `RLIMIT_MEMLOCK` เป็น `RLIM_INFINITY` ให้กับโปรเซสโดยอัตโนมัติ

> [!NOTE]
> ใน Linux Kernel 5.11 ขึ้นไป เคอร์เนลได้เปลี่ยนมาใช้ระบบ cgroup-based memory accounting สำหรับ eBPF memory ทำให้ไม่ต้องพึ่งพา `RLIMIT_MEMLOCK` อีกต่อไป อย่างไรก็ตาม การเรียก `rlimit.RemoveMemlock()` ยังคงเป็น Best Practice เพื่อให้โค้ดทำงานได้บนทุกเคอร์เนลย้อนหลัง

---

### 1.4 ความสำคัญของ Atomic Operations ใน eBPF Maps

เมื่อโปรแกรม eBPF ถูกแนบ (Hook) เข้ากับ Tracepoint ยอดนิยมอย่าง `sched_process_exec` โปรแกรมอาจถูกเรียกทำงานพร้อมกันจากหลาย CPU Cores ในเสี้ยววินาทีเดียวกัน (Symmetric Multiprocessing - SMP)

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
- **บรรทัด 3-4:** นำเข้าเฮดเดอร์พื้นฐานของเคอร์เนล BPF และฟังก์ชันผู้ช่วย (BPF Helpers) เช่น `bpf_map_lookup_elem`, `bpf_ktime_get_ns`, `bpf_printk`

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
- **บรรทัด 9-19:** Fallback macros สำหรับกำหนด ELF Section (`SEC`) และนิยามแมปแบบ BTF-defined maps (`__uint`, `__type`) เพื่อให้สามารถคอมไพล์ได้แม้ในสภาพแวดล้อมที่ไม่มีเฮดเดอร์ libbpf เต็มรูปแบบ

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");
```
- **บรรทัด 27-32:** ประกาศ BPF Map ชื่อ `exec_count`
  - `type, BPF_MAP_TYPE_ARRAY`: เป็น Array Map ที่มีขนาดคงที่และเข้าถึงได้รวดเร็วระดับ $O(1)$
  - `max_entries, 1`: บรรจุได้ 1 สล็อต (index 0) สำหรับเก็บผลรวมทั้งระบบ
  - `key, __u32`: คีย์เป็นตัวเลขอินเด็กซ์ขนาด 32 บิต
  - `value, __u64`: ค่าตัวนับสะสมขนาด 64 บิต ป้องกันปัญหา Integer Overflow
  - `SEC(".maps")`: สั่งให้ Clang เก็บโครงสร้างนี้ไว้ใน ELF Section ชื่อ `.maps` เพื่อให้ BPF Loader ทำการสร้าง Map ในเคอร์เนล

```c
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
```
- **บรรทัด 45-46:** ฟังก์ชัน eBPF Hook
  - `SEC("tracepoint/sched/sched_process_exec")`: ระบุ Section ว่าเป็น Tracepoint `sched:sched_process_exec` ซึ่งเคอร์เนลเรียกทุกครั้งที่ `execve()`/`execveat()` **สำเร็จ** (field ของมันดูได้ที่ `/sys/kernel/tracing/events/sched/sched_process_exec/format`: `__data_loc char[] filename`, `pid`, `old_pid`)
  - `handle_exec`: ชื่อฟังก์ชัน ซึ่ง `bpf2go` จะนำไปแปลงเป็นฟิลด์ `HandleExec` ในภาษา Go
  - `void *ctx`: พอยน์เตอร์ชี้ไปยัง record ของ Tracepoint (โปรแกรมนี้แค่นับ จึงไม่ได้อ่าน field ใดๆ)

> [!WARNING]
> **ทำไมไม่ใช้ `tracepoint/syscalls/sys_enter_execve` เหมือนเวอร์ชันแรก?** บน Ubuntu 26.04 / Linux 7.0.0-38 เราพบว่าโปรแกรม BPF ที่ผูกกับ `syscalls:sys_enter_execve` **ทำงานเฉพาะเมื่อ syscall เกิดบน CPU 0** บนเครื่อง 8 CPU ตัวนับจึงได้ราว 1/8 ของความจริง (เวอร์ชันเดิมรายงาน ~30 calls/sec ขณะที่ `sched_process_exec` วัดได้ ~190 execs/sec บนเครื่องเดียวกันในเวลาใกล้กัน) โดยไม่มี error ใดๆ — ยังไม่ยืนยันสาเหตุ ส่วน `sched:*` และ `raw_syscalls:*` ทำงานครบทุก CPU (ดูหัวข้อ Troubleshooting) ข้อแตกต่างเชิงความหมาย: `sys_enter_execve` นับทุกความพยายาม exec รวมที่ล้มเหลว ส่วน `sched_process_exec` นับเฉพาะ exec ที่สำเร็จ

```c
    __u32 key = 0;
    __u64 *val;

    val = bpf_map_lookup_elem(&exec_count, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
```
- **บรรทัด 48-56:** ค้นหาสล็อตที่ Index 0 ใน Map `exec_count`
  - `bpf_map_lookup_elem`: คืนค่าพอยน์เตอร์ไปยัง Value ในเคอร์เนลเมมโมรี (หรือ `NULL` ถ้าไม่พบ key)
  - `if (val)`: **หัวใจสำคัญของ eBPF Verifier** โดยทั่วไปหากไม่ตรวจว่า `val != NULL` ตัว Verifier จะปฏิเสธโปรแกรมด้วยข้อความ `R0 invalid mem access 'map_value_or_null'` (ทดสอบจริงบน 7.0 กับ `BPF_MAP_TYPE_HASH`)
  - **ข้อยกเว้นบนเคอร์เนลรุ่นใหม่**: เมื่อทดสอบบน Linux 7.0 กับ `BPF_MAP_TYPE_ARRAY` ที่ใช้ key เป็นค่าคงที่ซึ่งอยู่ในช่วง (`key = 0`, `max_entries = 1`) Verifier รู้ว่า lookup ไม่มีทางคืน `NULL` (log แสดง `R0=map_value(...)` แทน `map_value_or_null`) จึง **ยอมรับ** โปรแกรมแม้ไม่มี `if (val)` — แต่เราควรเขียน NULL check เสมอ เพราะเคอร์เนลรุ่นเก่ายังปฏิเสธ และถ้าเปลี่ยนเป็น Hash Map หรือ key แบบไม่คงที่ก็จะถูกปฏิเสธทันที
  - `__sync_fetch_and_add(val, 1)`: บวกค่าตัวนับขึ้น 1 แบบอะตอมมิก

```c
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    bpf_printk("exec by PID %d\n", pid);

    return 0;
```
- **บรรทัด 59-63:**
  - `bpf_get_current_pid_tgid()`: ดึงค่า 64-bit ID โดย **32 บิตบนคือ TGID** (= Process ID ที่ user space เห็นใน `ps`) และ **32 บิตล่างคือ PID ในมุมเคอร์เนล** (= Thread ID ที่ user space เห็น)
  - `pid_tgid >> 32`: บิตชิฟต์ไปทางขวา 32 บิต เพื่อแยกเอาเฉพาะ TGID (Process ID) ของโปรเซสที่เรียกใช้
  - `bpf_printk`: ส่งข้อความดีบักเข้าสู่ระบบ Tracing Ring Buffer ของเคอร์เนล (อ่านได้จาก `/sys/kernel/tracing/trace_pipe` — เหมาะกับการดีบักเท่านั้น เพราะเป็น buffer รวมของทั้งระบบและช้า)
  - `return 0`: คืนค่า 0 แจ้งเคอร์เนลว่าโปรแกรมทำงานสมบูรณ์

```c
char LICENSE[] SEC("license") = "Dual BSD/GPL";
```
- **บรรทัด 66:** กำหนดไลเซนส์เป็น Dual BSD/GPL ซึ่งจำเป็นต้องมีเพื่อให้เคอร์เนลอนุญาตให้เรียกใช้ฟังก์ชัน BPF Helpers ขั้นสูงที่เป็น GPL-only

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
- **บรรทัด 27-29:** ปลดล็อกข้อจำกัดหน่วยความจำล็อกสำหรับ eBPF Maps (ต้องรันเป็น root — ถ้ารันเป็นผู้ใช้ธรรมดาจะล้มที่บรรทัดนี้ด้วย `failed to set memlock rlimit: operation not permitted`)

```go
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()
```
- **บรรทัด 32-36:**
  - `loadBpfObjects`: โหลดและตรวจสอบ eBPF Bytecode เข้าสู่เคอร์เนล พร้อมทั้งสร้าง BPF Maps
  - `defer objs.Close()`: รับประกันการคืนหน่วยความจำและปิด File Descriptors ทั้งหมดเมื่อโปรแกรมยุติการทำงาน

```go
	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to sched/sched_process_exec: %v", err)
	}
	defer tp.Close()
```
- **บรรทัด 41-45:** แนบ (Attach) eBPF Program เข้ากับเคอร์เนล Tracepoint `sched/sched_process_exec` ผ่านเคอร์เนล Perf Event Subsystem (ชื่อกลุ่ม/ชื่อ event ต้องตรงกับ `SEC()` ในไฟล์ C)

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
			fmt.Printf("[%s] Total exec events: %-8d | Rate: %-4d execs/sec\n", ...)
```
- **บรรทัด 55-74:** การโพลล์ค่าจาก BPF Map
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

**ตัวอย่างหน้าจอผลลัพธ์** (บนเครื่องที่ว่าง ตัวเลขจะต่ำกว่านี้มาก; ผลเต็มอยู่ในหัวข้อ 4):
```text
======================================================================
 eBPF Process Exec Monitor (Cilium ebpf-go + bpf2go)
======================================================================
2026/10/28 22:26:58 Successfully hooked tracepoint 'sched/sched_process_exec'!
2026/10/28 22:26:58 Monitoring active processes... Press Ctrl+C to terminate.

[22:26:59] Total exec events: 187      | Rate: 187  execs/sec
[22:27:00] Total exec events: 377      | Rate: 190  execs/sec
```
> **หมายเหตุเรื่องชื่อ "CO-RE"**: โปรแกรมสัปดาห์นี้ไม่ได้อ่าน field ของ struct เคอร์เนลเลย จึงยังไม่มี CO-RE relocation จริง (ไม่ได้ใช้ `vmlinux.h`/`BPF_CORE_READ`) แต่ได้ประโยชน์จากแนวทางเดียวกัน คือคอมไพล์ล่วงหน้าครั้งเดียวด้วย `bpf2go` แล้วฝัง bytecode ในไบนารี Go โดยไม่ต้องมี Clang/headers บนเครื่องปลายทาง

### ขั้นตอนที่ 5: สร้างทราฟฟิกทดสอบและตรวจสอบ Kernel Trace Pipe
เปิดหน้าต่างเทอร์มินัลอีกหน้าต่างหนึ่ง แล้วสั่งรันคำสั่งต่าง ๆ เพื่อกระตุ้น `execve()`:
```bash
# รันคำสั่งต่อเนื่อง
for i in {1..10}; do ls /usr > /dev/null; sleep 0.2; done
```

ดูข้อความ Debug ที่ส่งออกจาก `bpf_printk()`:
```bash
sudo cat /sys/kernel/tracing/trace_pipe      # หรือ /sys/kernel/debug/tracing/trace_pipe บนระบบเก่า
```
**ผลลัพธ์ที่ปรากฏ** (ผลจริง — สังเกตเลข CPU `[002]`, `[006]`, `[007]` ที่ต่างกัน แปลว่าจับได้ทุก CPU):
```text
           sleep-164613  [002] ...21 646020.521481: bpf_trace_printk: exec by PID 164613
           sleep-164612  [006] ...21 646020.521501: bpf_trace_printk: exec by PID 164612
           sleep-164611  [007] ...21 646020.521517: bpf_trace_printk: exec by PID 164611
```

### ขั้นตอนที่ 6: ตรวจสอบสถานะ eBPF ด้วย `bpftool`
```bash
# ตรวจสอบว่าโปรแกรม eBPF กำลังโหลดอยู่ในเคอร์เนล
sudo bpftool prog list name handle_exec

# ตรวจสอบค่าใน Map จากฝั่งเคอร์เนลโดยตรง
sudo bpftool map dump name exec_count
```
ผลจริง (เพราะ ELF มี BTF ของ map, `bpftool` จึงแสดง key/value เป็น JSON ที่อ่านง่ายแทน hex):
```text
11167: tracepoint  name handle_exec  tag 451e8c09a507ad0f  gpl
	loaded_at 2026-10-28T22:26:58+0700  uid 0
	xlated 200B  jited 120B  memlock 4096B  map_ids 5263,5264
	btf_id 6108
[{
        "key": 0,
        "value": 419
    }
]
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`, 8 CPUs), Go 1.26, clang 21, cilium/ebpf v0.16.0 — เครื่องทดสอบมีงานอื่น (build/script วนลูป) รันอยู่ จึงมี exec ราว 190 ครั้ง/วินาที

### 4.1 การคอมไพล์ด้วย `bpf2go` (`make generate build`) และรัน `sudo timeout -s INT 6 ./bin/exec-counter`
```text
===> Generating Go bindings from counter.c via bpf2go...
go generate ./...
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfel.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfel.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfel.go
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfeb.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfeb.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week05-libbpf-cilium-go/bpf_bpfeb.go
===> Building userspace binary bin/exec-counter...
mkdir -p bin
go build -v -o bin/exec-counter .

======================================================================
 eBPF Process Exec Monitor (Cilium ebpf-go + bpf2go)
======================================================================
2026/10/28 22:26:58 Successfully hooked tracepoint 'sched/sched_process_exec'!
2026/10/28 22:26:58 Monitoring active processes... Press Ctrl+C to terminate.

[22:26:59] Total exec events: 187      | Rate: 187  execs/sec
[22:27:00] Total exec events: 377      | Rate: 190  execs/sec
[22:27:01] Total exec events: 572      | Rate: 195  execs/sec
[22:27:02] Total exec events: 760      | Rate: 188  execs/sec
[22:27:03] Total exec events: 950      | Rate: 190  execs/sec

Received signal 'interrupt'. Shutting down cleanly...
Final cumulative exec event count: 1138
eBPF program and tracepoint links detached successfully.
```

### 4.2 ตรวจสอบว่าจับ exec ได้ครบทุก CPU
```bash
for c in 0 1 2 3 4 5 6 7; do taskset -c $c /bin/true; done
```
นำ PID ของทั้ง 8 โปรเซสไปค้นใน `trace_pipe` (บรรทัด `exec by PID <pid>`) พบครบ **8/8** สำหรับ `sched/sched_process_exec` (ขณะที่ hook เดิม `syscalls/sys_enter_execve` บนเคอร์เนลเดียวกันจับได้เฉพาะตัวที่รันบน CPU 0)

---

## 5. Milestone Checklist

- [x] เข้าใจสถาปัตยกรรม Modern eBPF, BTF, และความต่างของ CO-RE เทียบกับ BCC
- [x] เขียนโปรแกรม eBPF C ดักจับ Kernel Tracepoint `sched/sched_process_exec` และตรวจสอบว่าจับเหตุการณ์ได้ครบทุก CPU
- [x] ใช้งาน eBPF Map ประเภท `BPF_MAP_TYPE_ARRAY` ร่วมกับคำสั่ง Atomic `__sync_fetch_and_add`
- [x] เข้าใจและประยุกต์ใช้ `rlimit.RemoveMemlock()` สำหรับการจัดการหน่วยความจำ
- [x] ใช้งาน `bpf2go` เพื่อคอมไพล์ C เป็น BPF Bytecode และสร้าง Go type bindings อัตโนมัติ
- [x] พัฒนา Userspace Monitor ด้วย Go และ Cilium ebpf-go จัดการ Lifecycle และ Graceful Shutdown
- [x] ตรวจสอบการทำงานผ่าน `/sys/kernel/debug/tracing/trace_pipe` และ `bpftool` ได้อย่างสมบูรณ์

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

ข้อความด้านล่างทดสอบจริงบน Ubuntu 26.04 / Linux 7.0 กับ cilium/ebpf v0.16.0 และ clang 21:

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `fatal error: 'asm/types.h' file not found` (ตอน `make generate`) | `clang -target bpf` ไม่ค้น include ของ multiarch (`/usr/include/x86_64-linux-gnu`) และเครื่องไม่มี symlink `/usr/include/asm` | `sudo apt install gcc-multilib` (เป็นแพ็กเกจที่สร้าง `/usr/include/asm`) หรือเพิ่ม `-cflags "-I/usr/include/x86_64-linux-gnu"` ใน `//go:generate` |
| `fatal error: 'bpf/bpf_helpers.h' file not found` | ไม่มี header ของ libbpf | `sudo apt install libbpf-dev` |
| `Failed to remove memory lock limit: failed to set memlock rlimit: operation not permitted` | รันไบนารีโดยไม่ใช้ `sudo` (การโหลด BPF ต้องใช้ `CAP_BPF`/`CAP_SYS_ADMIN` และ Ubuntu ตั้ง `kernel.unprivileged_bpf_disabled=2`) | `sudo ./bin/exec-counter` หรือ `make run` |
| `Failed to load eBPF objects: field HandleExec: program handle_exec: load program: permission denied: ... R0 invalid mem access 'map_value_or_null'` | Verifier ปฏิเสธเพราะใช้ค่าที่ได้จาก `bpf_map_lookup_elem()` โดยไม่ตรวจ `NULL` (ทดสอบโดยเปลี่ยน map เป็น HASH แล้วลบ `if (val)`) | ใส่ `if (!val) return 0;` ก่อนใช้ pointer เสมอ — อ่าน log เต็มได้ด้วย `errors.As(err, &ve)` กับ `*ebpf.VerifierError` แล้วพิมพ์ `%+v` |
| `Failed to attach tracepoint to sched/...: reading file "/sys/kernel/tracing/events/sched/<name>/id": ... no such file or directory` | ชื่อกลุ่ม/ชื่อ tracepoint ใน `link.Tracepoint()` ผิด หรือไม่มีในเคอร์เนลนี้ | `sudo ls /sys/kernel/tracing/events/sched/` หรือ `sudo bpftrace -l 'tracepoint:sched:*'` |
| ตัวนับต่ำกว่าความจริงหลายเท่า **โดยไม่มี error** เมื่อใช้ `tracepoint/syscalls/sys_enter_execve` | บน Ubuntu 26.04 / Linux 7.0.0-38 พบว่าโปรแกรม BPF บน `syscalls:sys_enter_execve` ทำงานเฉพาะเมื่อ syscall เกิดบน CPU 0 (ยังไม่ยืนยันสาเหตุ; `sched:*` และ `raw_syscalls:*` ไม่มีปัญหา) | ใช้ `tracepoint/sched/sched_process_exec` (แบบที่สัปดาห์นี้ใช้) หรือ `tracepoint/raw_syscalls/sys_enter` แล้วกรอง `id == 59`; ตรวจด้วย `for c in $(seq 0 $(($(nproc)-1))); do taskset -c $c /bin/true; done` |
| `cat: /sys/kernel/debug/tracing/trace_pipe: No such file or directory` | ระบบไม่ได้ mount debugfs | ใช้ `/sys/kernel/tracing/trace_pipe` (tracefs) แทน |
| ไม่มี `/sys/kernel/btf/vmlinux` | เคอร์เนลไม่ได้เปิด `CONFIG_DEBUG_INFO_BTF` | โปรแกรมสัปดาห์นี้ยังรันได้ (ไม่ใช้ CO-RE) แต่สัปดาห์ถัดๆ ไปต้องใช้ — ตรวจด้วย `grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)` |

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **นับแยกตาม CPU ด้วย `BPF_MAP_TYPE_PERCPU_ARRAY`**: เปลี่ยน map เป็น per-CPU แล้วลบ `__sync_fetch_and_add` ออก (ไม่จำเป็นแล้วเพราะแต่ละ CPU มีช่องของตัวเอง) ฝั่ง Go ให้ `Lookup` ใส่ `[]uint64` แล้วรวมค่าเอง
   - **สิ่งที่ต้องส่ง**: diff + ผลลัพธ์ที่พิมพ์ยอดแยกราย CPU และยอดรวม
   - **วิธีตรวจ**: `for c in 0 1 2 3; do taskset -c $c /bin/true; done` ต้องเห็นยอดของ CPU 0-3 เพิ่มขึ้น และ `sudo bpftool map dump name exec_count` แสดงค่าแยกตาม CPU
2. **พิสูจน์ปัญหา hook เดิมด้วยตัวเอง**: เปลี่ยน `SEC()` และ `link.Tracepoint()` กลับเป็น `syscalls/sys_enter_execve` ชั่วคราว รันคู่กับเวอร์ชัน `sched_process_exec` แล้วเทียบตัวเลข Rate
   - **สิ่งที่ต้องส่ง**: ตัวเลขทั้งสองเวอร์ชันในช่วงเวลาเดียวกัน + อัตราส่วน + ข้อสังเกตเทียบกับจำนวน CPU (`nproc`)
   - **วิธีตรวจ**: รันการทดสอบ `taskset` ข้างต้นขณะเปิดทั้งสองโปรแกรม แล้วเทียบยอดที่เพิ่มขึ้น (ถ้าเคอร์เนลของคุณไม่มีปัญหานี้ ทั้งสองควรเท่ากัน — รายงานผลตามจริง)

### ระดับปานกลาง
3. **อ่าน `filename` จาก tracepoint context**: ประกาศ struct ของ `sched_process_exec` ตาม `/sys/kernel/tracing/events/sched/sched_process_exec/format` (header 8 ไบต์ + `__u32 filename_loc` + `pid` + `old_pid`) แล้วใช้ `bpf_probe_read_kernel_str()` อ่านสตริงที่ `(void *)ctx + (filename_loc & 0xFFFF)` พิมพ์ด้วย `bpf_printk`
   - **สิ่งที่ต้องส่ง**: โค้ด C + ผล `trace_pipe` ที่เห็นชื่อไฟล์ เช่น `/usr/bin/true`
   - **วิธีตรวจ**: `taskset -c 3 /bin/true` แล้ว `sudo timeout 2 cat /sys/kernel/tracing/trace_pipe | grep true`
4. **ส่งออกเป็น Prometheus-style text**: เพิ่ม HTTP endpoint `/metrics` ใน Go (ใช้ `net/http` ธรรมดา) ที่คืน `exec_events_total <ค่า>`
   - **สิ่งที่ต้องส่ง**: diff + ผล `curl`
   - **วิธีตรวจ**: `curl -s localhost:9100/metrics` สองครั้งห่างกัน 2 วินาที ค่าต้องเพิ่มขึ้น (เลือกพอร์ตที่ว่าง ตรวจด้วย `ss -ltn`)

### ระดับท้าทาย
5. **ทำให้เป็น CO-RE จริง**: สร้าง `vmlinux.h` (`bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`) แล้วใช้ `BPF_CORE_READ(task, real_parent, tgid)` จาก `bpf_get_current_task_btf()`/`bpf_get_current_task()` เพื่อนับ exec แยกตาม **PPID** ด้วย Hash Map
   - **สิ่งที่ต้องส่ง**: โค้ด + ผลที่ PPID ของ shell คุณ (`echo $$`) มียอดเพิ่มขึ้นตามจำนวนคำสั่งที่พิมพ์ + อธิบายว่า relocation ถูกบันทึกไว้ใน ELF อย่างไร (`bpftool btf dump file bpf_bpfel.o | grep -i core` หรือ `llvm-objdump -r`)
   - **วิธีตรวจ**: พิมพ์ `true` 5 ครั้งใน shell ที่รู้ PID แล้วยอดของ PPID นั้นต้องเพิ่ม 5
6. **Pin map ข้ามการรีสตาร์ต**: ใช้ `ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/w05"}}` และตั้ง `pinning` ให้ `exec_count` เพื่อให้ตัวนับไม่หายเมื่อปิด-เปิดโปรแกรมใหม่ (และเขียนคำสั่งลบ pin ให้เรียบร้อย)
   - **สิ่งที่ต้องส่ง**: diff + ผลรันสองรอบที่รอบที่สองเริ่มจากค่าสุดท้ายของรอบแรก
   - **วิธีตรวจ**: `sudo ls /sys/fs/bpf/w05/` ระหว่างรอบ และ `sudo rm -rf /sys/fs/bpf/w05` เมื่อเสร็จ (ต้องไม่เหลือ pin ค้าง)
