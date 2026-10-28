# สัปดาห์ที่ 16: ตรวจสอบความสมบูรณ์ของ eBPF บนโฮสต์ (eBPF Integrity Audit) และข้อจำกัดของการตรวจจับ eBPF Rootkit

ยินดีต้อนรับสู่ **Week 16** สัปดาห์สุดท้ายของ **Phase 7**!
eBPF เป็นดาบสองคม ความสามารถเดียวกับที่เราใช้สร้างเครื่องมือ observability และ security ตลอดหลักสูตร ถูกนำไปสร้าง **eBPF rootkit** ได้เช่นกัน งานวิจัยและ PoC สาธารณะ (เช่น TripleCross, Boopkit, ebpfkit) แสดงให้เห็นการใช้ eBPF ซ่อนโปรเซส/ไฟล์, ดักข้อมูล, หรือเปิด backdoor ผ่านแพ็กเก็ตพิเศษ

สัปดาห์นี้เราจะสร้าง **eBPF Integrity Auditor** ที่ทำ 3 อย่าง:
1. ประเมินการตั้งค่า hardening ของ eBPF บนโฮสต์ (sysctl และ BPF LSM)
2. **สแกน inventory ของโปรแกรม eBPF ที่โหลดอยู่แล้ว** ตอนเริ่มทำงาน (รวมโปรแกรมที่ถูกโหลดก่อน auditor เริ่ม)
3. เฝ้าดู system call `bpf()` แบบ real-time ผ่าน **`fentry/__sys_bpf`** (สำรองด้วย `tracepoint/raw_syscalls/sys_enter`) และถอดรหัสคำสั่ง (`BPF_PROG_LOAD`, `BPF_LINK_CREATE`, ...) พร้อมชนิดและชื่อโปรแกรมที่ถูกโหลด

และที่สำคัญที่สุด เราจะพูดถึงอย่างตรงไปตรงมาว่า **เครื่องมือแบบนี้ "ป้องกัน" อะไรไม่ได้บ้าง**

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 `bpf()` คือประตูเดียวของ User Space สู่ระบบย่อย eBPF

ทุกการกระทำกับ eBPF จาก User Space (สร้าง map, โหลดโปรแกรม, attach, pin, query) ผ่าน system call เดียว:

```c
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

`cmd` เป็นค่าใน `enum bpf_cmd` (UAPI, ค่าคงที่ข้ามเวอร์ชัน) ภายในเคอร์เนล syscall นี้ส่งต่อไปยังฟังก์ชัน `__sys_bpf(enum bpf_cmd cmd, bpfptr_t uattr, unsigned int size)` ซึ่งเป็นจุดที่ hook หลักของเราเกาะ บนเคอร์เนล 7.0 ของเครื่องทดลองมี 41 ชื่อ (รวม alias) ตัวอย่างที่สำคัญด้านความปลอดภัย:

| ค่า | คำสั่ง | ระดับความเสี่ยงในแล็บนี้ |
|---|---|---|
| 5 | `BPF_PROG_LOAD` | PROG_LOAD (โหลดโค้ดเข้าเคอร์เนล) |
| 8 / 28 / 17 / 29 | `BPF_PROG_ATTACH` / `BPF_LINK_CREATE` / `BPF_RAW_TRACEPOINT_OPEN` / `BPF_LINK_UPDATE` | ATTACH (ทำให้โค้ดเริ่มทำงาน) |
| 9 / 34 | `BPF_PROG_DETACH` / `BPF_LINK_DETACH` | DETACH (อาจเป็นการปิดเครื่องมือป้องกัน) |
| 0 / 6 / 18 / 36 | `BPF_MAP_CREATE` / `BPF_OBJ_PIN` / `BPF_BTF_LOAD` / `BPF_TOKEN_CREATE` | NOTICE |
| 1, 4, 11-16, ... | lookup, `*_GET_NEXT_ID`, `*_GET_FD_BY_ID`, `OBJ_GET_INFO_BY_FD` | INFO (อ่านอย่างเดียว, ซ่อนไว้เว้นแต่ใส่ `-all`) |

### 1.2 บั๊กของเวอร์ชันเดิม: offset ของ `cmd` ผิด

เวอร์ชันเดิมประกาศ struct ของ tracepoint เอง:

```c
struct trace_bpf_args {
    unsigned short common_type; unsigned char common_flags;
    unsigned char common_preempt_count; int common_pid;   /* 0..7  */
    int __syscall_nr;                                      /* 8..11 */
    int cmd;                                               /* 12..15  <-- ผิด! */
    ...
};
```

แต่ format จริงบนเครื่อง (`/sys/kernel/tracing/events/syscalls/sys_enter_bpf/format`) คือ:

```text
	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int cmd;	offset:16;	size:8;	signed:0;
	field:union bpf_attr * uattr;	offset:24;	size:8;	signed:0;
	field:unsigned int size;	offset:32;	size:8;	signed:0;
```

อาร์กิวเมนต์ของ syscall tracepoint ทุกตัวถูกเก็บเป็นช่องขนาด 8 ไบต์ (`unsigned long args[6]`) เริ่มที่ offset 16 โปรแกรมเดิมจึงอ่าน 4 ไบต์ที่ offset 12 ซึ่งเป็น **padding (ค่า 0)** ผลคือ **ทุก event ถูกแสดงเป็น `BPF_MAP_CREATE` (cmd=0)** ดังที่เห็นใน README เวอร์ชันเก่า และตัวจัดระดับความเสี่ยง `PROG_LOAD`/`PROG_ATTACH` ไม่เคยทำงานเลย

**การแก้ขั้นแรก:** ใช้ `struct trace_event_raw_sys_enter` จาก `vmlinux.h` (`ent` + `long id` + `unsigned long args[6]`) แล้วอ่าน `args[0]` เป็น `cmd` และ `args[1]` เป็น pointer `uattr` (layout นี้ยังใช้ใน hook สำรองของเวอร์ชันปัจจุบัน)

### 1.2.1 ปัญหาที่ 2: `syscalls:sys_enter_*` ทำงานไม่ครบทุก CPU บนเครื่องทดลอง

ระหว่างพัฒนา พบพฤติกรรมผิดปกติบน **Linux 7.0.0-38-generic** ของเครื่องทดลอง: tracepoint ตระกูล `syscalls:sys_enter_*` **บางตัว** ทำงานเฉพาะเมื่อ syscall รันบน CPU 0 ทดสอบด้วย bpftrace โดย pin โปรเซสไว้ทีละ CPU (0-7) ด้วย `taskset`:

| Probe | ผลที่วัดได้ |
|---|---|
| `tracepoint:syscalls:sys_enter_execve` | ทำงานเฉพาะ **CPU 0**: นับได้ 15 ครั้งบน CPU 0 และ 0 ครั้งบน CPU 1-7 ขณะที่ `raw_syscalls` นับได้ 15 ครั้งต่อ CPU ครบทั้ง 8 CPU (การทดสอบแยกอีกครั้งได้ 3 จาก 24 exec) |
| `tracepoint:raw_syscalls:sys_enter` (`id == 59`) | ครบทุก CPU |
| `tracepoint:syscalls:sys_enter_bpf` | ครบทุก CPU (22 ครั้งต่อ CPU ในการทดสอบของเรา) |
| `tracepoint:raw_syscalls:sys_enter` (`id == 321`) | ครบทุก CPU |

แม้ `sys_enter_bpf` จะยังทำงานครบในการทดสอบ แต่ **ยังไม่ทราบสาเหตุ** ของอาการนี้ (อาจเป็นบั๊กของเคอร์เนลรุ่นนี้หรือผลจากสถานะของระบบ) และ auditor ด้านความปลอดภัยที่พลาดเหตุการณ์ 7/8 แบบเงียบ ๆ คือช่องโหว่ร้ายแรง เวอร์ชันนี้จึง **เลิกพึ่ง `syscalls:sys_enter_bpf`** แล้วใช้:

| Hook | ข้อดี | ข้อเสีย |
|---|---|---|
| **`fentry/__sys_bpf`** (หลัก, `-hook fentry`) | รันเฉพาะตอนมีการเรียก `bpf()`; ไม่ขึ้นกับหมายเลข syscall ของสถาปัตยกรรม; เห็นทั้ง syscall ปกติ, compat 32-bit และผู้เรียกจากในเคอร์เนล (`uattr.is_kernel`) | `__sys_bpf` เป็นฟังก์ชัน `static` ภายใน (ไม่ใช่ ABI) อาจถูกเปลี่ยนชื่อหรือ inline ในเคอร์เนลอื่น; ต้องมี BTF และ BPF trampoline |
| **`tracepoint/raw_syscalls/sys_enter`** (สำรอง, `-hook raw`) | เป็น tracepoint ที่เสถียร | รันกับ **ทุก syscall ของทั้งเครื่อง** (มี overhead); ต้องรู้หมายเลข syscall ของสถาปัตยกรรม (x86_64 = 321, arm64 = 280); ไม่เห็น compat syscall และผู้เรียกจากในเคอร์เนล |

โหมด `-hook auto` (ค่าเริ่มต้น) ลอง `fentry` ก่อน ถ้าโหลด/attach ไม่ได้จึงถอยไปใช้ `raw` ผลการทดสอบซ้ำบนเครื่องเดียวกันด้วยการโหลดโปรแกรมผ่าน `taskset -c N bpftool prog load` บน CPU 0-7: **ทั้งสอง hook จับได้ 8/8**

### 1.3 ทำไม "ดู syscall อย่างเดียว" ไม่พอ: Startup Inventory

ตัวเฝ้า `bpf()` แบบ real-time เห็นเฉพาะการเรียก **หลังจาก** มันเริ่มทำงาน โปรแกรมที่ถูกโหลดไว้ก่อน (เช่น rootkit ที่ติดตั้งตอนบูต หรือก่อนที่ agent จะ restart) จะมองไม่เห็นเลย เวอร์ชันนี้จึงเพิ่ม **inventory scan** ที่ทำแบบเดียวกับ `bpftool prog list`:

```
 id = 0
 loop:
   BPF_PROG_GET_NEXT_ID(id)   -> next id (ENOENT = หมดแล้ว)     ebpf.ProgramGetNextID()
   BPF_PROG_GET_FD_BY_ID(id)  -> fd ของโปรแกรม                  ebpf.NewProgramFromID()
   BPF_OBJ_GET_INFO_BY_FD(fd) -> type, name, tag, uid, map_ids    prog.Info()
```

ลำดับสำคัญ: auditor **attach hook ก่อน แล้วจึงสแกน** เพื่อปิดช่องว่างเวลา โปรแกรมที่ถูกโหลดระหว่างสแกนจะถูก hook จับได้อยู่ดี (ถ้าสแกนก่อน attach จะมีช่วงที่ไม่มีใครเฝ้า)

`Tag` คือ hash (SHA-1 ตัดสั้น) ของ instruction ของโปรแกรม จึงใช้เป็น **ลายนิ้วมือ** เทียบกับ baseline ได้ เช่น โปรแกรม `sd_fw_egress` ของ systemd ทุกตัวมี tag `772db7720b2728e9` เหมือนกัน หากวันหนึ่ง tag เปลี่ยนโดยไม่มีการอัปเดตระบบ ถือเป็นสัญญาณที่ควรตรวจสอบ

### 1.4 อ่าน `union bpf_attr` จาก User Space (และปัญหา TOCTOU)

สำหรับ `BPF_PROG_LOAD` เราอ่าน `prog_type` และ `prog_name` จากหน่วยความจำของผู้เรียกด้วย `bpf_core_read_user()` (หรือ `bpf_core_read()` เมื่อ `uattr.is_kernel` = 1) ซึ่งเป็น CO-RE relocation บน `union bpf_attr` ข้อควรระวังคือ fentry ทำงาน **ตอนเข้า** `__sys_bpf` ก่อนที่ฟังก์ชันจะ copy attr จริง ผู้โจมตีที่มีหลายเธรดสามารถเปลี่ยนค่าในช่วงเวลานั้นได้ (**Time-Of-Check to Time-Of-Use, TOCTOU**) ข้อมูลนี้จึงเหมาะกับการ **แสดงผล/บันทึก** เท่านั้น ห้ามใช้ตัดสินใจบล็อก การบังคับใช้จริงต้องทำที่ hook ที่เห็นข้อมูล **หลัง** copy แล้ว เช่น BPF LSM `lsm/bpf` หรือ `lsm/bpf_prog_load`

### 1.5 ค่า hardening ที่ auditor ตรวจ

| การตั้งค่า | ค่า | ความหมาย |
|---|---|---|
| `kernel.unprivileged_bpf_disabled` | 0 | ผู้ใช้ทั่วไปโหลดโปรแกรมบางชนิด (socket filter) ได้ |
| | 1 | ปิดถาวรจนกว่าจะรีบูต (เปลี่ยนกลับเป็น 0 ไม่ได้) |
| | 2 | ปิด แต่ admin เปลี่ยนกลับได้ (ค่าเริ่มต้นของ Ubuntu รุ่นใหม่) |
| `net.core.bpf_jit_harden` | 0/1/2 | ปิด / เปิดสำหรับ unprivileged / เปิดทุกโปรแกรม (constant blinding ป้องกัน JIT spraying) |
| `/sys/kernel/security/lsm` มี `bpf` | — | BPF LSM เปิดอยู่ จึงเขียนนโยบาย `lsm/bpf` เพื่อ **บังคับ** ว่าใครโหลดอะไรได้ |

บนเครื่องทดลอง: `unprivileged_bpf_disabled = 2`, `bpf_jit_harden = 0` และ LSM ที่เปิดคือ `lockdown,capability,landlock,yama,apparmor,ima,evm` (**ไม่มี `bpf`**) แปลว่าเครื่องนี้ทำได้เพียง "ตรวจจับ" ยังไม่สามารถใช้ BPF LSM บังคับได้หากไม่แก้ kernel command line

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `bpf_audit.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
```
- **บรรทัด 20-23:** ใช้ `vmlinux.h` เพื่อให้ได้ `struct trace_event_raw_sys_enter`, `union bpf_attr`, `bpfptr_t` และ `enum bpf_cmd` (เช่น `BPF_PROG_LOAD`) โดยไม่ต้องประกาศเอง

```c
struct bpf_audit_event {
    __u64 ts_ns; __u32 pid; __u32 uid; __u32 cmd; __u32 prog_type;
    char comm[TASK_COMM_LEN]; char prog_name[BPF_OBJ_NAME_LEN];
    __u8 source; __u8 from_kernel; __u8 pad[6];
};
```
- **บรรทัด 39-50:** event ขนาด 64 ไบต์ (ไม่มี implicit padding) `source` บอกว่ามาจาก hook ใด และ `from_kernel` บอกว่าผู้เรียกอยู่ในเคอร์เนล

```c
volatile const __u32 bpf_syscall_nr = 321;
```
- **บรรทัด 61:** ค่าคงที่ใน `.rodata` ที่ Go เขียนทับด้วย `unix.SYS_BPF` ก่อนโหลด (`RewriteConstants`) verifier เห็นเป็นค่าคงที่จึง optimize การเปรียบเทียบได้

```c
static __always_inline void emit_event(__u32 cmd, union bpf_attr *attr, __u8 from_kernel, __u8 source)
```
- **บรรทัด 63-97:** ฟังก์ชันร่วมของทั้งสอง hook: จอง ring buffer, เติมข้อมูล, และสำหรับ `BPF_PROG_LOAD` อ่าน `prog_type`/`prog_name` จาก attr (บรรทัด 81-95) โดยเลือก `bpf_core_read` (หน่วยความจำเคอร์เนล) หรือ `bpf_core_read_user` (หน่วยความจำ user) ตาม `from_kernel`

```c
SEC("fentry/__sys_bpf")
int BPF_PROG2(audit_sys_bpf, enum bpf_cmd, cmd, bpfptr_t, uattr, unsigned int, size)
{
    if (uattr.is_kernel) {
        emit_event((__u32)cmd, (union bpf_attr *)uattr.kernel, 1, SRC_FENTRY);
    } else {
        emit_event((__u32)cmd, (union bpf_attr *)uattr.user, 0, SRC_FENTRY);
    }
```
- **บรรทัด 104-113:** hook หลัก `bpfptr_t` (= `sockptr_t`) เป็น struct 16 ไบต์ที่ส่งแบบ **by-value** ผ่าน 2 register มาโคร `BPF_PROG` ปกติรองรับเฉพาะอาร์กิวเมนต์ขนาด register เดียว จึงต้องใช้ **`BPF_PROG2`** (libbpf) ที่ประกอบ struct argument ให้ถูกต้อง

```c
SEC("tracepoint/raw_syscalls/sys_enter")
int audit_raw_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (ctx->id != bpf_syscall_nr) {
        return 0;
    }
    emit_event((__u32)ctx->args[0], (union bpf_attr *)ctx->args[1], 0, SRC_RAW);
```
- **บรรทัด 120-128:** hook สำรอง รันกับทุก syscall จึงต้องกรองหมายเลข syscall เป็นคำสั่งแรก `args[0]`/`args[1]` คือ `cmd`/`uattr` (แก้บั๊ก offset ในข้อ 1.2)

### 2.2 ไฟล์ `main.go`

```go
func loadCmdNamesFromBTF() int {
	spec, err := btf.LoadKernelSpec()
	...
	if err := spec.TypeByName("bpf_cmd", &enum); err != nil {
```
- **บรรทัด 140-153:** อ่านชื่อคำสั่งจาก `enum bpf_cmd` ใน Kernel BTF ตาราง hard-code เดิมมีค่าผิด เช่น map ค่า 14 เป็น `BPF_PROG_QUERY` ทั้งที่จริงคือ `BPF_MAP_GET_FD_BY_ID` (`BPF_PROG_QUERY` = 16)

```go
func riskOf(cmd uint32) (label, color string, important bool) {
```
- **บรรทัด 163-175:** จัดระดับความเสี่ยงตามตารางในข้อ 1.1 และระบุว่าคำสั่งนั้น "เปลี่ยนสถานะเคอร์เนล" หรือไม่

```go
	lsm := readSysctl("/sys/kernel/security/lsm")
```
- **บรรทัด 207-216:** ตรวจว่า BPF LSM เปิดอยู่หรือไม่ (เพิ่มจากเวอร์ชันเดิม)

```go
func inventoryPrograms(selfID ebpf.ProgramID) {
	...
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		...
		prog, err := ebpf.NewProgramFromID(id)
		...
		info, err := prog.Info()
		prog.Close()
```
- **บรรทัด 223-287:** วนสแกนโปรแกรมทุกตัวในเคอร์เนล (ข้อ 1.3) โปรแกรมอาจถูก unload ระหว่างสแกน จึงนับเป็น `failed` แทนการหยุดทำงาน และปิด fd ทันทีหลังอ่าน info เพื่อไม่ให้ auditor ถือ reference ของโปรแกรมอื่นค้างไว้ (ซึ่งจะทำให้โปรแกรมนั้นไม่ถูก unload)

```go
func loadAndAttach(mode string) (*ebpf.Collection, *ebpf.Program, link.Link, string, error) {
	spec, err := loadBpf()
	...
	if err := spec.RewriteConstants(map[string]interface{}{"bpf_syscall_nr": uint32(unix.SYS_BPF)}); err != nil {
	...
		s := spec.Copy()
		delete(s.Programs, drop)
	...
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})        // fentry
	...
		l, err := link.Tracepoint("raw_syscalls", "sys_enter", prog, nil)        // สำรอง
```
- **บรรทัด 48-112:** ใช้ `loadBpf()` (CollectionSpec ที่ bpf2go สร้าง) แทน `loadBpfObjects()` เพื่อ (1) เขียนทับ `bpf_syscall_nr` ด้วยหมายเลขของสถาปัตยกรรมที่คอมไพล์ (`golang.org/x/sys/unix`), (2) **ลบโปรแกรมที่ไม่ใช้ออกจาก spec ก่อนโหลด** เพราะถ้าเคอร์เนลไม่รองรับ fentry บน `__sys_bpf` การโหลดทั้ง collection จะล้มเหลว และ (3) โหมด `auto` ลอง fentry ก่อนแล้วถอยไป raw พร้อม log `[WARN]`

```go
	coll, prog, hookLink, hookName, err := loadAndAttach(*hook)
	...
	if info, err := prog.Info(); err == nil {
		selfID, _ = info.ID()
	}
	inventoryPrograms(selfID)
```
- **บรรทัด 312-331:** attach hook ก่อน แล้วจึงสแกน inventory และทำเครื่องหมาย `<- this auditor` ให้โปรแกรมของตัวเอง

```go
		if ev.Pid == selfPid {
			continue
		}
		label, color, important := riskOf(ev.Cmd)
		if !important && !*showAll {
			continue
		}
```
- **บรรทัด 363-370:** ไม่รายงาน `bpf()` ที่ auditor เรียกเอง และซ่อนคำสั่งอ่านอย่างเดียวเว้นแต่ใส่ `-all`

```go
		if ev.FromKernel == 1 {
			detail = "[in-kernel caller] "
		}
		if ev.Cmd == cmdProgLoad {
			typ := strings.TrimSuffix(ebpf.ProgramType(ev.ProgType).String(), "Program")
			detail += fmt.Sprintf("type=%s name=%q", typ, ...)
		}
```
- **บรรทัด 373-380:** ระบุผู้เรียกจากในเคอร์เนล และแปลง `prog_type` เป็นชื่อด้วย `ebpf.ProgramType.String()` ของ cilium/ebpf

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์ (รวมแล็บ Week 13/14 เพื่อใช้ไฟล์ .o เป็นโปรแกรมทดสอบ)
```bash
cd phase07-advanced-security-observability
make -C week13-kfree-skb-dropwatch all
make -C week14-cgroup-sock-addr all
make -C week16-ebpf-integrity-audit all
```

### ขั้นตอนที่ 2: จำลอง "โปรแกรมที่ถูกโหลดไว้ก่อน" (ก่อนเริ่ม auditor)
```bash
# โหลดและ pin โปรแกรม tracepoint ของ Week 13 (โหลดอย่างเดียว ไม่ attach จึงไม่มีผลต่อระบบ)
sudo bpftool prog load week13-kfree-skb-dropwatch/bpf_bpfel.o /sys/fs/bpf/w16_preloaded
```

### ขั้นตอนที่ 3: เริ่ม auditor (Terminal 1)
```bash
cd week16-ebpf-integrity-audit
sudo ./bin/bpf-audit          # ใส่ -all หากต้องการเห็นคำสั่งอ่านอย่างเดียวด้วย
# บังคับเลือก hook: sudo ./bin/bpf-audit -hook fentry   หรือ   -hook raw
```
ตรวจว่า `trace_kfree_skb` ที่ pin ไว้ปรากฏใน **Startup Inventory**

### ขั้นตอนที่ 4: โหลดโปรแกรมใหม่ขณะ auditor ทำงาน โดย pin ไว้ทีละ CPU (Terminal 2)
```bash
# ยืนยันว่า hook จับได้ "ทุก CPU" (ดูข้อ 1.2.1) ต้องเห็น name="sock4_connect" ครบ 8 ครั้ง (ตามจำนวน CPU)
for c in $(seq 0 $(($(nproc)-1))); do
  sudo taskset -c $c bpftool prog load week14-cgroup-sock-addr/bpf_bpfel.o /sys/fs/bpf/w16_cpu$c
done
sudo bpftool prog show pinned /sys/fs/bpf/w16_cpu7
```

### ขั้นตอนที่ 5: เทียบกับ bpftool
```bash
sudo bpftool prog list | grep -c "^[0-9]*:"     # จำนวนควรใกล้เคียงกับ Total ใน inventory
```

### ขั้นตอนที่ 6: ล้างสภาพแวดล้อม
```bash
sudo sh -c 'rm -f /sys/fs/bpf/w16_*'   # unpin -> โปรแกรมถูก unload เมื่อไม่มี reference
# (ต้องให้ glob ขยายภายใต้ sudo เพราะผู้ใช้ปกติอ่าน /sys/fs/bpf ไม่ได้)
```
แล้วกด `Ctrl+C` ใน Terminal 1

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`, 8 CPUs), clang 21, Go 1.26, cilium/ebpf v0.16.0 (บันทึกเมื่อ 2026-10-28, `-hook auto` เลือก `fentry/__sys_bpf`)
> ตัด ANSI color code ออก

### 4.1 Terminal 2
```text
$ sudo bpftool prog load week13-kfree-skb-dropwatch/bpf_bpfel.o /sys/fs/bpf/w16_preloaded   # ก่อนเริ่ม auditor
loaded
$ for c in 0 1 2 3 4 5 6 7; do sudo taskset -c $c bpftool prog load week14-cgroup-sock-addr/bpf_bpfel.o /sys/fs/bpf/w16_cpu$c; done
$ sudo bpftool prog show pinned /sys/fs/bpf/w16_cpu7
11100: cgroup_sock_addr  name sock4_connect  tag f5482f9a4d336f56  gpl
	loaded_at 2026-10-28T22:22:37+0700  uid 0
	xlated 648B  jited 397B  memlock 4096B  map_ids 5225,5227,5226
	btf_id 6078
```

### 4.2 Auditor (`sudo ./bin/bpf-audit`)
```text
======================================================================
 eBPF Integrity Auditor: bpf() syscall monitor + program inventory
======================================================================
----------------------------------------------------------------------
 [1] Host eBPF Security & Hardening Posture Assessment
----------------------------------------------------------------------
  • kernel.unprivileged_bpf_disabled : 2 [SECURE / HARDENED]
  • net.core.bpf_jit_harden          : 0 [DEFAULT / UNHARDENED]
  • net.core.bpf_jit_enable          : 1
  • BPF LSM in /sys/kernel/security/lsm : NOT ACTIVE
----------------------------------------------------------------------

2026/10/28 22:22:34 [INFO] Loaded 41 bpf_cmd names from kernel BTF
----------------------------------------------------------------------
 [2] Startup Inventory: eBPF programs already loaded in the kernel
----------------------------------------------------------------------
  ID     TYPE            NAME              TAG                UID   NOTE
  57     CGroupSKB       sd_fw_egress      772db7720b2728e9   0     
  58     CGroupSKB       sd_fw_ingress     772db7720b2728e9   0     
  99     CGroupDevice    s_snapd_desktop   5592a8780089fcce   1000  
  9432   CGroupDevice    sd_devices        470479e7b2a42bb5   0     
  9433   CGroupSKB       sd_fw_egress      772db7720b2728e9   0     
  9434   CGroupSKB       sd_fw_ingress     772db7720b2728e9   0     
  9435   CGroupDevice    sd_devices        a97c143260cd9940   0     
  9436   CGroupDevice    sd_devices        99aee04c1c96cc7e   0     
  9437   CGroupSKB       sd_fw_egress      772db7720b2728e9   0     
  9438   CGroupSKB       sd_fw_ingress     772db7720b2728e9   0     
  9439   CGroupDevice    sd_devices        bf0092a65d4c9334   0     
  9440   CGroupSKB       sd_fw_egress      772db7720b2728e9   0     
  9441   CGroupSKB       sd_fw_ingress     772db7720b2728e9   0     
  9442   CGroupDevice    sd_devices        925aa739a35aee81   0     
  9443   CGroupDevice    sd_devices        99aee04c1c96cc7e   0     
  9444   CGroupSKB       sd_fw_egress      772db7720b2728e9   0     
  9445   CGroupSKB       sd_fw_ingress     772db7720b2728e9   0     
  9446   CGroupDevice    sd_devices        99aee04c1c96cc7e   0     
  9447   CGroupSKB       sd_fw_egress      772db7720b2728e9   0     
  9448   CGroupSKB       sd_fw_ingress     772db7720b2728e9   0     
  9449   CGroupDevice    sd_devices        49ba04a7ef7eacb7   0     
  9450   CGroupDevice    sd_devices        9f0126175d483e7a   0     
  9451   CGroupSKB       sd_fw_egress      772db7720b2728e9   0     
  9452   CGroupSKB       sd_fw_ingress     772db7720b2728e9   0     
  10925  CGroupDevice    (no name)         b1e4e8bab2078b38   0     
  11049  TracePoint      trace_kfree_skb   b04867a63be555c2   0     
  11051  Tracing         audit_sys_bpf     a6780ab09f0e2e46   0     <- this auditor
  Total: 27 programs (CGroupDevice=11, CGroupSKB=14, TracePoint=1, Tracing=1)
----------------------------------------------------------------------

2026/10/28 22:22:34 [INFO] Hooked fentry/__sys_bpf
2026/10/28 22:22:34 [INFO] Auditing state-changing sys_bpf() calls in real time (-all for everything)...

TIME      PID     UID   COMM             BPF COMMAND              RISK        DETAIL
------------------------------------------------------------------------------------------
22:22:36  110944  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=SocketFilter name=""
22:22:36  110944  0     bpftool          BPF_TOKEN_CREATE         NOTICE      
22:22:36  110944  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=SocketFilter name=""
22:22:36  110944  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=SocketFilter name=""
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=SocketFilter name="libbpf_nametest"
22:22:36  110944  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=Kprobe name="det_arg_ctx"
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_BTF_LOAD             NOTICE      
22:22:36  110944  0     bpftool          BPF_MAP_CREATE           NOTICE      
22:22:36  110944  0     bpftool          BPF_MAP_CREATE           NOTICE      
22:22:36  110944  0     bpftool          BPF_MAP_CREATE           NOTICE      
22:22:36  110944  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"
22:22:36  110944  0     bpftool          BPF_OBJ_PIN              NOTICE      
(... bpftool อีก 7 โปรเซส (CPU 1-7) แต่ละตัวมี 22 บรรทัดรูปแบบเดียวกัน ตัดออก เหลือเฉพาะบรรทัด PROG_LOAD ของโปรแกรมจริง ...)
22:22:36  110947  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"
22:22:36  110950  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"
22:22:36  110957  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"
22:22:36  110960  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"
22:22:37  110964  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"
22:22:37  110970  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"
22:22:37  110974  0     bpftool          BPF_PROG_LOAD            PROG_LOAD   type=CGroupSockAddr name="sock4_connect"

[INFO] Stopping BPF integrity auditor...
[SUCCESS] BPF Integrity Auditor stopped safely.
```

### 4.3 ยืนยันการจับครบทุก CPU ของแต่ละ hook
```text
[fentry] Hooked fentry/__sys_bpf  -> sock4_connect PROG_LOAD seen: 8/8, OBJ_PIN seen: 8
[raw] Hooked tracepoint/raw_syscalls/sys_enter (id == 321)  -> sock4_connect PROG_LOAD seen: 8/8, OBJ_PIN seen: 8
```
(รัน `sudo ./bin/bpf-audit -hook fentry` และ `-hook raw` แยกกัน แล้วโหลดโปรแกรมด้วย `taskset -c 0..7` เหมือนขั้นตอนที่ 4 แล้วนับบรรทัดด้วย `grep -c`)

**วิเคราะห์ผล:**
- **Inventory จับโปรแกรมที่โหลดก่อนได้:** `11049 TracePoint trace_kfree_skb` คือโปรแกรมที่เรา pin ไว้ในขั้นตอนที่ 2 **ก่อน** auditor เริ่ม ตัวเฝ้า syscall เพียงอย่างเดียวจะไม่มีทางเห็นมัน
- **โปรแกรมของ auditor เอง** แสดงเป็น `Tracing audit_sys_bpf <- this auditor` (ชนิด `Tracing` = fentry)
- **จับได้ครบ 8 CPU:** `BPF_PROG_LOAD ... name="sock4_connect"` ปรากฏ 8 ครั้งจาก bpftool 8 โปรเซส (PID ต่างกัน) ที่ถูก pin คนละ CPU
- **คำสั่งถูกถอดรหัสถูกต้อง:** เห็น `BPF_PROG_LOAD`, `BPF_TOKEN_CREATE`, `BPF_BTF_LOAD`, `BPF_OBJ_PIN` แทนที่จะเป็น `BPF_MAP_CREATE` ทุกบรรทัดแบบเวอร์ชันเดิม
- **`SocketFilter name=""`, `libbpf_nametest`, `det_arg_ctx`** คือการ **probe ความสามารถของเคอร์เนล** ที่ libbpf ใน bpftool โหลดโปรแกรมเล็ก ๆ ทดสอบแล้วทิ้งทันที ระบบตรวจจับจริงต้องแยก noise เหล่านี้ออกจากการโหลดโปรแกรมจริง
- โปรแกรม `sd_fw_*`/`sd_devices` เป็นของ systemd (firewall/device policy ราย service) ส่วน `s_snapd_desktop` ถูกสร้างด้วย UID 1000 ผ่าน snapd เป็นตัวอย่างของ **baseline** ที่ต้องรู้จักก่อนจึงจะแยกสิ่งผิดปกติได้
- ในการบันทึกรอบก่อน (ขณะแล็บ Week 19-20 รันพร้อมกัน) auditor แสดง `BPF_LINK_CREATE`/`BPF_PROG_ATTACH` จาก `sockops-accelerator` และ `xdp-tc-lb` ในระดับ `ATTACH` ด้วย

---

## 5. ข้อจำกัดและ Threat Model (Limitations)

**สมมติฐาน (Threat Model):** auditor นี้มีประโยชน์ต่อการตรวจจับ **ผู้ดูแลระบบหรือซอฟต์แวร์ที่โหลด eBPF โดยไม่ได้รับอนุญาต** และเป็นแหล่ง log สำหรับ forensic แต่ **ไม่สามารถป้องกันผู้โจมตีที่มีสิทธิ์ระดับเดียวกัน** (root / `CAP_SYS_ADMIN` / `CAP_BPF`) ได้

| ข้อจำกัด | รายละเอียด |
|---|---|
| **auditor ถูกปิดได้** | ผู้ที่มี root/`CAP_SYS_ADMIN` สามารถ `kill` โปรเซส auditor (link ถูกปิด hook หายทันที) หรือ detach/แก้ไขโปรแกรมผ่าน `bpf()` โดยตรง เครื่องมือที่รันในเคอร์เนลเดียวกับผู้โจมตีที่มีสิทธิ์เท่ากันจึงไม่ใช่ trust anchor |
| **rootkit ระดับเคอร์เนลบิดเบือนผลได้** | ผู้โจมตีที่ควบคุมเคอร์เนลได้แล้ว (โหลด module หรือใช้ eBPF ที่แก้ค่าคืนของ syscall ได้) อาจกรองผลของ `BPF_PROG_GET_NEXT_ID` หรือ ring buffer ของเรา ผลการสแกนจากภายในเครื่องจึงต้องเทียบกับแหล่งภายนอก (เช่น memory forensics) |
| **เห็นเฉพาะทาง `__sys_bpf`** | hook `fentry` เห็นผู้เรียกจากในเคอร์เนลที่ผ่าน `__sys_bpf` ด้วย (`[in-kernel caller]`) แต่โปรแกรมที่เคอร์เนลสร้างผ่านเส้นทางอื่นไม่ปรากฏใน event stream (ยังปรากฏใน inventory) ส่วน hook `raw` เห็นเฉพาะ syscall native ของสถาปัตยกรรม (ไม่เห็น compat 32-bit) |
| **`syscalls:sys_enter_*` ไม่ครบทุก CPU (Linux 7.0.0-38)** | สังเกตได้บนเครื่องทดลอง สาเหตุยังไม่ยืนยัน (ข้อ 1.2.1) จึงไม่ใช้ tracepoint ตระกูลนี้ เครื่องมือที่ใช้ `sys_enter_*` ควรทดสอบด้วย `taskset` ทุก CPU ก่อนเชื่อผล |
| **`__sys_bpf` ไม่ใช่ ABI** | ฟังก์ชัน static ภายในอาจถูก inline/เปลี่ยนชื่อ ทำให้ `fentry` ใช้ไม่ได้ในเคอร์เนลอื่น (`-hook auto` จะถอยไป `raw` และพิมพ์ `[WARN]`) |
| **Overhead ของ hook สำรอง** | `raw_syscalls/sys_enter` รันกับทุก syscall ของทั้งเครื่อง แม้จะออกจากโปรแกรมทันทีที่ `id` ไม่ตรง |
| **TOCTOU ของ `prog_type`/`prog_name`** | ค่าที่อ่านจาก User Space ปลอมได้ (ข้อ 1.4) ข้อมูลที่เชื่อถือได้กว่าคือ `prog.Info()` หลังโหลดเสร็จ |
| **Event flooding** | โปรแกรม eBPF ส่ง **ทุก** `bpf()` (รวม lookup) เข้า ring buffer แล้วค่อยกรองใน Go ผู้โจมตีจึงเรียก `BPF_MAP_LOOKUP_ELEM` รัว ๆ ให้ ring buffer เต็มแล้วโหลดโปรแกรมในจังหวะที่ event หายได้ |
| **ไม่ตรวจ link/map** | cilium/ebpf v0.16 ไม่มี API สาธารณะสำหรับวน link ID แล็บนี้จึงสแกนเฉพาะโปรแกรม (ใช้ `bpftool link list` / `bpftool map list` เสริม) |
| **ชื่อโปรแกรมปลอมได้** | ชื่อ (สูงสุด 15 ตัวอักษร) ถูกกำหนดโดยผู้โหลด rootkit ตั้งชื่อเลียนแบบ `sd_fw_egress` ได้ ควรเทียบ **tag** กับ baseline แทนชื่อ |

**แนวทางป้องกันที่ควรใช้ร่วมกัน (Defense-in-depth):**
1. **BPF LSM** (`lsm/bpf`, `lsm/bpf_prog_load` ฯลฯ): บังคับนโยบาย ณ จุดที่เคอร์เนลเห็น attr หลัง copy แล้ว เช่น อนุญาตให้เฉพาะ binary ของ agent ที่รู้จักโหลดโปรแกรม (ต้องเปิด `bpf` ใน LSM list ตอนบูต; เครื่องทดลองนี้ยังไม่ได้เปิด)
2. **BPF token** (เคอร์เนลรุ่นใหม่ราว 6.9 ขึ้นไป): มอบสิทธิ์ใช้ eBPF แบบจำกัดคำสั่ง/ชนิดโปรแกรมให้ container แทนการให้ `CAP_SYS_ADMIN`/`CAP_BPF` เต็มรูปแบบ
3. **การลงนามโปรแกรม (BPF program signing):** เป็นงานที่กำลังพัฒนา/เพิ่งเริ่มเข้าสู่ mainline ในรุ่นหลัง ๆ (ควรตรวจสอบสถานะกับเอกสารของเคอร์เนลเวอร์ชันที่ใช้)
4. **ลดผู้มีสิทธิ์:** ตั้ง `kernel.unprivileged_bpf_disabled=1`, ไม่ให้ container มี `CAP_BPF`/`CAP_SYS_ADMIN`, ใช้ kernel lockdown
5. **ส่ง log ออกนอกเครื่องทันที** และใช้ audit subsystem ของเคอร์เนล (เคอร์เนลส่ง audit record ชนิด `BPF` เมื่อโหลด/unload โปรแกรม) เพื่อให้มีหลักฐานแม้ auditor จะถูกปิดภายหลัง

---

## 6. Milestone Checklist

- [x] อธิบายบทบาทของ system call `bpf()` และจัดกลุ่ม `enum bpf_cmd` ตามความเสี่ยง
- [x] วิเคราะห์และแก้บั๊ก offset ของ syscall tracepoint ด้วย `struct trace_event_raw_sys_enter` (`args[0]`)
- [x] ใช้ `fentry/__sys_bpf` + `BPF_PROG2` (struct argument by-value) เป็น hook หลัก พร้อม fallback `raw_syscalls/sys_enter` และยืนยันด้วย `taskset` ว่าจับได้ครบทุก CPU
- [x] อ่าน `union bpf_attr` จาก User Space ด้วย `bpf_core_read_user` และเข้าใจปัญหา TOCTOU
- [x] สร้าง Startup Inventory ด้วย `ebpf.ProgramGetNextID` + `NewProgramFromID` + `Info()` และสแกนหลัง attach เพื่อปิดช่องว่างเวลา
- [x] ใช้ program tag เป็นลายนิ้วมือเทียบกับ baseline
- [x] ประเมิน hardening ของโฮสต์ (sysctl + BPF LSM)
- [x] ระบุข้อจำกัดของการตรวจจับจากภายในเครื่อง และแนวทาง BPF LSM / BPF token / signing / least privilege

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **Baseline แล้ว diff:** แก้ `inventoryPrograms()` ให้บันทึก `(name, type, tag)` ลงไฟล์ JSON ด้วย flag `-save-baseline` และเปรียบเทียบกับไฟล์เดิมด้วย `-baseline`
   - *ส่งงาน:* โค้ด + ผลการรันที่แสดง `NEW` สำหรับโปรแกรมที่ pin เพิ่ม (ขั้นตอนที่ 2)
   - *ตรวจ:* รันซ้ำสองครั้งโดยไม่เปลี่ยนอะไร ต้องไม่มี `NEW`/`MISSING`
2. **ดู audit record ของเคอร์เนล:** ติดตั้ง `auditd` (ถ้ายังไม่มี) แล้วโหลดโปรแกรมด้วย bpftool และค้นหา record ด้วย `sudo ausearch -m BPF -ts recent`
   - *ส่งงาน:* record ที่มี `prog-id=... op=LOAD` และ `op=UNLOAD`
   - *ตรวจ:* `prog-id` ต้องตรงกับ ID ที่ `bpftool prog show` และ auditor แสดง

### ระดับปานกลาง
1. **กรองในเคอร์เนลเพื่อลด flooding:** ย้ายตัวกรองคำสั่งอ่านอย่างเดียวจาก Go ไปไว้ใน `bpf_audit.c` (เช่น ใช้ array map เป็น bitmap ของ `cmd` ที่สนใจ)
   - *ส่งงาน:* โค้ด + การทดลองยิง `BPF_MAP_LOOKUP_ELEM` จำนวนมาก (เช่นด้วย `bpftool map dump` วนซ้ำ) แล้วแสดงว่า `PROG_LOAD` ยังไม่หาย
   - *ตรวจ:* เปรียบเทียบจำนวน event ใน ring buffer ก่อน/หลังแก้
2. **ตรวจ link inventory:** ใช้ `link.NewFromID()` วน ID ตั้งแต่ 1 จนเจอ `ENOENT` ติดกันจำนวนหนึ่ง (หรือเรียก `BPF_LINK_GET_NEXT_ID` ผ่าน `golang.org/x/sys/unix` เอง) แล้วแสดง link type และ program ID ที่ผูกอยู่
   - *ส่งงาน:* ตาราง link ที่ตรงกับ `sudo bpftool link list`
   - *ตรวจ:* โปรแกรมที่ attach ผ่าน link (เช่น Week 14 ขณะรัน) ต้องปรากฏ

### ระดับท้าทาย
1. **บังคับด้วย BPF LSM (ใน VM):** บูต VM ด้วย `lsm=...,bpf` แล้วเขียน `SEC("lsm/bpf")` ที่ปฏิเสธ `BPF_PROG_LOAD` จากทุกโปรเซสยกเว้น `comm` หรือ cgroup ที่กำหนด (ระวังอย่าบล็อกตัวเองจนถอนโปรแกรมไม่ได้: ให้ใช้ link ที่ผูกกับโปรเซสแทนการ pin)
   - *ส่งงาน:* โค้ด + ผล `bpftool prog load` ที่ล้มเหลวด้วย `EPERM`
   - *ตรวจ:* อธิบายว่าทำไมการตรวจที่ `lsm/bpf` ไม่มีปัญหา TOCTOU แบบข้อ 1.4
2. **Red team vs. Blue team:** ในสิทธิ์ root บน VM ทดลองหาวิธีทำให้ auditor "พลาด" การโหลดโปรแกรมอย่างน้อย 2 วิธี (เช่น kill auditor, ทำ ring buffer flood, โหลดก่อน auditor แล้วตั้งชื่อเลียนแบบ systemd) แล้วเสนอการตรวจจับที่ปิดช่องแต่ละวิธี
   - *ส่งงาน:* รายงานสั้นพร้อม output จริงของแต่ละวิธี
   - *ตรวจ:* ทุกวิธีต้องทำใน VM ของตนเอง และอธิบายได้ว่าการป้องกันใดอยู่ "นอก" ขอบเขตของ auditor ตัวนี้
