# สัปดาห์ที่ 25: struct_ops และ sched_ext — เขียน CPU Scheduler ด้วย BPF

ยินดีต้อนรับสู่ **Week 25** ของหลักสูตร eBPF Zero to Hero!

ตลอด 24 สัปดาห์ที่ผ่านมา โปรแกรม eBPF ของเรา "เกาะ" อยู่ที่ hook ที่เคอร์เนลเตรียมไว้ (kprobe, tracepoint, XDP, LSM ...) แล้วสังเกตหรือตัดสิน allow/deny ทีละเหตุการณ์ สัปดาห์นี้ต่างออกไป: เราจะใช้ **struct_ops** เพื่อให้โปรแกรม BPF **เป็นผู้ implement ตาราง function pointer ของ subsystem ในเคอร์เนลทั้งชุด** และตัวอย่างที่ทรงพลังที่สุดของแนวคิดนี้คือ **sched_ext** (Linux 6.12+) ซึ่งเปิดให้เขียน **CPU scheduler ทั้งตัวเป็น BPF** โหลดเข้า-ถอดออกได้ขณะเครื่องรันอยู่ โดยไม่ต้อง reboot หรือคอมไพล์เคอร์เนลใหม่

ในแล็บนี้เราจะ:
1. เขียน scheduler แบบ **global FIFO** แล้วต่อยอดเป็น **weighted vtime** (คิดค่า nice) ใน C ไฟล์เดียว
2. โหลดและ attach ด้วย Go + cilium/ebpf **v0.22** (`link.AttachStructOps`) พร้อมพิมพ์สถิติ enqueue/dispatch ต่อ CPU แบบสด
3. **ความปลอดภัยต้องมาก่อน:** ใช้ `SCX_OPS_SWITCH_PARTIAL` ให้ scheduler ของเราคุมเฉพาะ task ที่เราตั้ง policy เป็น `SCHED_EXT` เอง ไม่แตะ task อื่นในเครื่อง
4. จงใจทำให้ scheduler พัง (stall / `scx_bpf_error`) เพื่อดู **watchdog ดีด scheduler ออก (ejection)** และคืน task ให้ fair class โดยอัตโนมัติ

> **ข้อกำหนดของแล็บ:** เคอร์เนลต้องมี `CONFIG_SCHED_CLASS_EXT=y` (มีใน Ubuntu 26.04 / Linux 7.0) และต้องมี `/sys/kernel/sched_ext/` — Ubuntu 24.04 (Linux 6.8) **ไม่มี sched_ext** จึงรันแล็บนี้ไม่ได้

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 struct_ops: ให้ BPF implement "ops table" ของเคอร์เนล

เคอร์เนล Linux ออกแบบ subsystem จำนวนมากเป็น **ตาราง function pointer** (ops table) เช่น `struct tcp_congestion_ops` (`.ssthresh`, `.cong_avoid`, ...) ใครอยากเพิ่ม algorithm ใหม่ก็เขียนโมดูลที่เติมตารางนี้แล้ว register เข้าไป

**struct_ops** (BPF_PROG_TYPE_STRUCT_OPS, เริ่มใน Linux 5.6 กับ `tcp_congestion_ops`) ทำให้ "ตาราง" นี้เติมด้วยโปรแกรม BPF ได้แทนโมดูลเคอร์เนล:

```
   ฝั่ง BPF (ไฟล์ .c)                                   ฝั่งเคอร์เนล
 SEC(".struct_ops.link")
 struct sched_ext_ops w25_ops = {          BPF_MAP_TYPE_STRUCT_OPS (1 entry)
    .select_cpu = w25_select_cpu, ──┐      ┌───────────────────────────────┐
    .enqueue    = w25_enqueue,    ──┼────▶ │ bpf_struct_ops_sched_ext_ops  │
    .dispatch   = w25_dispatch,   ──┘      │  .data = struct sched_ext_ops │──▶ BPF_LINK_CREATE
    .flags      = SWITCH_PARTIAL,  (data)  │   func ptr -> trampoline ->   │    = register()
    .name       = "w25_minimal",   (data)  │             prog FD           │    ปิด link = unregister()
 };                                        └───────────────────────────────┘
```

- แต่ละ callback คือโปรแกรม `SEC("struct_ops/<name>")` แยกกัน verifier ตรวจตาม **ลายเซ็นของ function pointer ใน BTF** (เช่น `void (*enqueue)(struct task_struct *, u64)`) และอนุญาตเฉพาะ kfunc/การเขียน field ที่ subsystem นั้นประกาศว่าปลอดภัย
- ฟิลด์ที่ไม่ใช่ฟังก์ชัน (`flags`, `timeout_ms`, `name`) เป็น **ข้อมูล** ที่คัดลอกลง map value ตรง ๆ
- `SEC(".struct_ops")` แบบเก่า: register ทันทีที่ update map และอยู่จนกว่าจะลบ map เอง; **`SEC(".struct_ops.link")`** (Linux 6.4+) ผูกอายุ scheduler กับ **BPF link** — ปิด FD หรือโปรเซส loader ตาย = unregister อัตโนมัติ ซึ่งเป็นคุณสมบัติด้านความปลอดภัยที่เราต้องการ
- ตัวอย่าง ops table อื่นที่ BPF implement ได้: `tcp_congestion_ops` (TCP CC เช่น `bpf_cubic` ใน selftests), `hid_bpf_ops` (HID-BPF ย้ายมาใช้ struct_ops ราว Linux 6.11) และ subsystem ใหม่ ๆ ที่ทยอยเพิ่ม — ตรวจได้จาก `bpftool btf dump file /sys/kernel/btf/vmlinux | grep 'bpf_struct_ops_'`

### 1.2 sched_ext อยู่ตรงไหนในเคอร์เนล

Linux จัด scheduler เป็น **sched class** เรียงตามลำดับความสำคัญ (เลือกจาก class บนสุดที่มี task พร้อมรัน) ตรวจลำดับจริงบนเครื่องนี้ได้จากตำแหน่งในหน่วยความจำ:

```text
$ sudo grep -E " (stop|dl|rt|fair|ext|idle)_sched_class$" /proc/kallsyms | sort
ffffffff9c858a40 D stop_sched_class
ffffffff9c858b40 D dl_sched_class
ffffffff9c858c40 D rt_sched_class
ffffffff9c858d40 D fair_sched_class      <- SCHED_NORMAL/BATCH/IDLE (EEVDF)
ffffffff9c858e40 D ext_sched_class       <- SCHED_EXT (policy 7) -> BPF scheduler ของเรา
ffffffff9c858f40 D idle_sched_class
```

`ext_sched_class` อยู่ **ใต้** `fair_sched_class` ผลคือในโหมด partial (หัวข้อ 1.5) task `SCHED_EXT` จะได้ CPU ก็ต่อเมื่อ CPU นั้นไม่มี task ของ fair class รออยู่ — task ปกติของเครื่องจึงไม่ถูกแย่งเวลาโดย scheduler ทดลองของเรา

### 1.3 Dispatch Queues (DSQ) และวงจรชีวิตของ task

sched_ext ไม่ให้ BPF แตะ runqueue ของเคอร์เนลตรง ๆ แต่ให้ทำงานผ่าน **DSQ (dispatch queue)**:

| DSQ | id | ใครสร้าง | ลักษณะ |
|---|---|---|---|
| local DSQ ของแต่ละ CPU | `SCX_DSQ_LOCAL` (หรือ `SCX_DSQ_LOCAL_ON \| cpu`) | เคอร์เนล | CPU **ดึงงานจากที่นี่เท่านั้น** ตอนเลือก task ถัดไป |
| global DSQ | `SCX_DSQ_GLOBAL` | เคอร์เนล | FIFO กลาง ใช้เป็น fallback |
| custom DSQ | เลขที่เราเลือก (แล็บนี้ใช้ `0`) | `scx_bpf_create_dsq()` ใน `ops.init` | เป็น **FIFO** หรือ **priority queue ตาม vtime** ก็ได้ (ห้ามผสมในคิวเดียว) |

```
 task ตื่น (wakeup)
      │
      ▼
 ops.select_cpu(p, prev_cpu)  ── เจอ CPU ว่าง? ──yes──▶ scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL)  ["direct dispatch"]
      │ no                                                       │      (ข้าม ops.enqueue)
      ▼                                                          │
 ops.enqueue(p)  ──▶ scx_bpf_dsq_insert[_vtime](p, SHARED_DSQ)   │
                                │                                │
             CPU ว่าง / local DSQ หมด                             │
                                ▼                                │
 ops.dispatch(cpu, prev) ──▶ scx_bpf_dsq_move_to_local(SHARED_DSQ)
                                │                                │
                                ▼                                ▼
                       ┌──────────── local DSQ ของ CPU ─────────────┐
                       └──────────────────┬─────────────────────────┘
                                          ▼
                  ops.running(p)  ──  รันจน slice หมด/หลับ/ถูก preempt  ──  ops.stopping(p, runnable)
                                          │
                     ยัง runnable และ slice หมด → กลับไป ops.enqueue
```

ชื่อ kfunc เปลี่ยนไปตามรุ่นเคอร์เนล ตรวจได้จาก `vmlinux.h` ของเครื่องตัวเอง (bpftool 7.x ใส่ prototype ของ kfunc ไว้ให้แล้ว):

```bash
grep -nE 'scx_bpf_(dispatch|consume|dsq_insert|dsq_move_to_local)\b' ../../vmlinux.h
```

| หน้าที่ | ชื่อปัจจุบัน (มีใน Linux 7.0 เครื่องนี้) | ชื่อเก่า (ก่อนราว 6.13 — **ไม่มีแล้ว** ใน BTF ของ 7.0) |
|---|---|---|
| ใส่ task ลง DSQ แบบ FIFO | `scx_bpf_dsq_insert()` | `scx_bpf_dispatch()` |
| ใส่ task ลง DSQ แบบ vtime | `scx_bpf_dsq_insert_vtime()` | `scx_bpf_dispatch_vtime()` |
| ย้ายหัวคิว DSQ มา local DSQ | `scx_bpf_dsq_move_to_local()` | `scx_bpf_consume()` |

> เคอร์เนลนี้ยังมี `scx_bpf_dsq_insert___v2()` (คืนค่า bool) และ `__scx_bpf_dsq_insert_vtime()` (รับ args struct) สำหรับ compat header ของ upstream แล็บนี้ใช้ชื่อพื้นฐานด้านบนซึ่งมีอยู่จริงในเคอร์เนลนี้ ถ้าย้ายไปเคอร์เนลอื่นให้ grep `vmlinux.h` ซ้ำเสมอ

### 1.4 Safety net: ทำไมเขียน scheduler ด้วย BPF แล้วเครื่องไม่ค้าง

scheduler ที่ผิดพลาดใน C ธรรมดาอาจทำให้เครื่องค้างทั้งเครื่อง sched_ext จึงมีชั้นป้องกันหลายชั้น:

1. **Verifier:** ตรวจทุก callback ก่อนโหลด (ไม่มี loop ไม่รู้จบ, pointer ปลอดภัย, ใช้ kfunc ตามบริบทที่อนุญาต)
2. **Watchdog:** ถ้า task ที่ runnable ไม่ได้รันนานเกิน `ops.timeout_ms` (ค่าสูงสุด/ค่า default 30 วินาที) เคอร์เนลจะ **disable BPF scheduler** ด้วยเหตุผล `runnable task stall` (`SCX_EXIT_ERROR_STALL`)
3. **`scx_bpf_error()`:** โค้ด BPF ร้องขอให้ถอดตัวเองพร้อมข้อความ (`SCX_EXIT_ERROR_BPF`) และการใช้ kfunc ผิดกติกาขณะรันก็ทำให้ถูก disable เช่นกัน
4. **ผูกกับ BPF link:** loader ตาย/ปิด link → `SCX_EXIT_UNREG`
5. **SysRq-S:** ผู้ดูแลกด `Alt+SysRq+S` (หรือ `echo S > /proc/sysrq-trigger`) เพื่อถอด BPF scheduler ฉุกเฉิน (`SCX_EXIT_SYSRQ`)

ทุกกรณี task `SCHED_EXT` จะถูกย้ายกลับไปรันด้วย **fair class** ทันที (ไม่ถูก kill) เคอร์เนลเรียก `ops.exit(struct scx_exit_info *)` ให้เราบันทึกเหตุผล และพิมพ์ลง `dmesg`

### 1.5 `SCX_OPS_SWITCH_PARTIAL` vs switch-all

| โหมด | task ไหนถูก BPF scheduler คุม | `/sys/kernel/sched_ext/switch_all` | `dmesg` |
|---|---|---|---|
| **partial** (`.flags = SCX_OPS_SWITCH_PARTIAL`) | เฉพาะ task ที่ policy = `SCHED_EXT` (7) | `0` | `... enabled (partial)` |
| switch-all (ไม่ใส่ flag) | **ทุก** task ที่เป็น SCHED_NORMAL/BATCH/IDLE ทั้งเครื่อง | `1` | `... enabled` |

แล็บนี้ **ใช้ partial เท่านั้น** เพราะเครื่องทดลองเป็นเครื่องที่ใช้ร่วมกัน ถ้า scheduler ของเรามีบั๊ก ผลกระทบจำกัดอยู่ที่ workload ทดสอบของเราเอง

การตั้ง policy เป็น `SCHED_EXT` ทำได้ด้วย `sched_setattr(pid, {sched_policy = 7})` โดยไม่ต้องเป็น root (เหมือนเปลี่ยนไป SCHED_BATCH) policy สืบทอดไปยังโปรเซสลูกและคงอยู่ข้าม `execve()` util-linux บางรุ่นมี `chrt --ext` แต่ **util-linux 2.41.3 บนเครื่องนี้ยังไม่มี** แล็บจึงทำ subcommand `ext-run` ที่ทำหน้าที่เดียวกัน ถ้ายังไม่มี BPF scheduler โหลดอยู่ task `SCHED_EXT` จะรันด้วย fair class ไปก่อน

### 1.6 Weighted vtime (ดัดแปลงจาก `scx_simple`)

FIFO ไม่สนใจค่า nice เลย โหมด vtime ให้แต่ละ task มี **virtual time** (`p->scx.dsq_vtime`) และใส่คิวแบบเรียงตาม vtime (น้อยได้ก่อน):

```
ตอน stopping:   dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight
                             └──── เวลาที่ใช้ CPU จริง (ns) ────┘        └─ nice 0 = 100, nice 10 ≈ 11
ตอน enqueue:    vtime = max(dsq_vtime, vtime_now - SCX_SLICE_DFL)    // จำกัดเครดิตของ task ที่หลับนาน
ตอน running:    vtime_now = max(vtime_now, dsq_vtime)
```

task weight สูง (nice ต่ำ) → vtime โตช้า → อยู่หัวคิวบ่อย → ได้ CPU มากกว่า (ผลวัดจริงในหัวข้อ 4.4)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

```
week25-struct-ops-sched-ext/
├── scx_mini.h     # macro ขั้นต่ำ (BPF_STRUCT_OPS, scx_bpf_error, exit info) เขียนใหม่จาก upstream
├── scx_w25.c      # BPF scheduler: select_cpu/enqueue/dispatch/running/stopping/enable/init/exit
├── sched.go       # load + attach struct_ops, ext-run, อ่านสถิติ (ใช้ร่วมกับ test)
├── main.go        # CLI: แสดง sysfs, สร้าง workload, พิมพ์สถิติสด, detach เมื่อหมดเวลา/Ctrl+C/ถูก eject
├── main_test.go   # runtime tests (attach จริงแบบ partial)
├── nice_demo.sh   # เทียบ FIFO vs vtime ด้วย spinner nice 0/10 บน CPU เดียว
└── Makefile
```

### 2.1 ไฟล์ `scx_mini.h`

upstream มี header ชุดใหญ่ใน `linux/tools/sched_ext/include/scx/` (`common.bpf.h`, `compat.bpf.h`, `user_exit_info.h`) เราไม่ vendor ทั้งชุด แต่เขียนเฉพาะที่ใช้:

```c
#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name) BPF_PROG(name, ##args)
#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name) BPF_PROG(name, ##args)
```
- `SEC("struct_ops/...")` ทำให้ loader รู้ว่าเป็น `BPF_PROG_TYPE_STRUCT_OPS`; `BPF_PROG()` จาก libbpf แปลง context (array ของ u64) เป็นอาร์กิวเมนต์ที่มีชนิด
- `struct_ops.s/` = sleepable จำเป็นสำหรับ `ops.init` เพราะ `scx_bpf_create_dsq()` อาจจองหน่วยความจำแบบหลับได้

```c
#define scx_bpf_error(fmt, args...) ({ static char ___fmt[] = fmt; \
	unsigned long long ___param[___bpf_narg(args)]; ___bpf_fill(___param, args); \
	scx_bpf_error_bstr(___fmt, ___param, sizeof(___param)); })
```
- kfunc จริงคือ `scx_bpf_error_bstr(fmt, u64 data[], size)` มาโครแพ็กอาร์กิวเมนต์ลง array แบบเดียวกับ `BPF_SEQ_PRINTF` (ย่อจาก `common.bpf.h`)

`struct w25_exit_info` + `RECORD_EXIT_INFO()` ย่อมาจาก `user_exit_info.h`: ใน `ops.exit` คัดลอก `kind`, `exit_code`, `reason`, `msg` จาก `struct scx_exit_info` ของเคอร์เนลลงตัวแปร global ให้ Go อ่าน (`reason`/`msg` เป็น pointer จึงต้อง `bpf_probe_read_kernel_str`) และเขียน `kind` เป็นอันสุดท้ายเพราะฝั่ง Go ใช้ `kind != 0` เป็นสัญญาณ "จบแล้ว"

> **ทำไมไม่ใช้ `__sync_val_compare_and_swap` แบบ upstream?** bpf2go คอมไพล์ด้วย `-mcpu=v1` เป็นค่า default ซึ่งไม่มีคำสั่ง cmpxchg และใช้ค่าคืนของ `__sync_fetch_and_add` ไม่ได้ (clang 21 จะ error `Invalid usage of the XADD return value`) โค้ดในแล็บจึงเลี่ยงทั้งสองแบบ

### 2.2 ไฟล์ `scx_w25.c`

```c
#include "vmlinux.h"
#include "scx_mini.h"
char _license[] SEC("license") = "GPL";
#define SHARED_DSQ 0
const volatile bool vtime_mode = false;
const volatile u32 fail_mode = FAIL_NONE;
```
- `vmlinux.h` ให้ทั้ง `struct sched_ext_ops`, enum (`SCX_DSQ_LOCAL`, `SCX_SLICE_DFL` = 20 ms, `SCX_OPS_SWITCH_PARTIAL` = 8) และ prototype ของ kfunc ทั้งหมด — **ไม่ต้องประกาศ struct หรือ kfunc เอง** (CO-RE ตามแนวทางของหลักสูตร)
- kfunc ของ sched_ext ส่งออกให้เฉพาะโปรแกรม GPL
- `const volatile` อยู่ใน `.rodata` Go แก้ค่าก่อนโหลด verifier จึงเห็นเป็นค่าคงที่และตัด branch ที่ไม่ใช้ทิ้ง

```c
enum stat_idx { STAT_LOCAL, STAT_ENQ, STAT_DISPATCH, STAT_RUNNING, W25_NR_STATS };
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); ... } stats SEC(".maps");
```
- ตัวนับต่อ CPU ไม่ต้องใช้ atomic (ชื่อ `NR_STATS` ชนกับ enum ใน `vmlinux.h` จึงตั้งชื่อ `W25_NR_STATS`)

```c
s32 BPF_STRUCT_OPS(w25_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && fail_mode != FAIL_STALL) {
		stat_inc(STAT_LOCAL);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
}
```
- `scx_bpf_select_cpu_dfl()` คือ "นโยบายเลือก CPU สำเร็จรูป" ของเคอร์เนล (ใช้ idle tracking ในตัว) ถ้าเจอ CPU ว่างก็ insert ลง local DSQ ของ CPU นั้นเลย (**direct dispatch**) ซึ่งทำให้ **`ops.enqueue` ไม่ถูกเรียก** สำหรับการตื่นครั้งนั้น

```c
void BPF_STRUCT_OPS(w25_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(STAT_ENQ);
	if (vtime_mode) {
		u64 vtime = p->scx.dsq_vtime;
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
	} else {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	}
}
```
- โหมด FIFO ต่อท้ายคิว; โหมด vtime ใส่ priority queue ที่เรียงตาม vtime และจำกัดเครดิตไม่ให้ task ที่หลับนานแซงหน้าเกิน 1 slice
- `enq_flags` ต้องส่งต่อให้ kfunc เสมอ (มี flag ภายในของเคอร์เนลปนอยู่)

```c
void BPF_STRUCT_OPS(w25_dispatch, s32 cpu, struct task_struct *prev)
{
	if (fail_mode == FAIL_STALL)
		return;
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		stat_inc(STAT_DISPATCH);
}
```
- เรียกเมื่อ local DSQ ของ CPU นี้ว่าง: ย้ายหัวคิว `SHARED_DSQ` (ตัวแรกที่รันบน CPU นี้ได้ตาม affinity) มาไว้ใน local DSQ
- `fail_mode == FAIL_STALL` จงใจไม่ดึงงาน — task ค้างในคิวจน watchdog ทำงาน

```c
void BPF_STRUCT_OPS(w25_running, struct task_struct *p)   // นับ STAT_RUNNING, เลื่อน vtime_now, (FAIL_ERROR: scx_bpf_error หลัง 1000 ครั้ง)
void BPF_STRUCT_OPS(w25_stopping, struct task_struct *p, bool runnable)
{
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}
void BPF_STRUCT_OPS(w25_enable, struct task_struct *p) { p->scx.dsq_vtime = vtime_now; }
s32 BPF_STRUCT_OPS_SLEEPABLE(w25_init) { return scx_bpf_create_dsq(SHARED_DSQ, -1); }
void BPF_STRUCT_OPS(w25_exit, struct scx_exit_info *ei) { RECORD_EXIT_INFO(exit_info, ei); }
```
- `p->scx.slice` คือ slice ที่ **เหลือ** จึงได้เวลาที่ใช้ไป = `SCX_SLICE_DFL - slice`; verifier ของ sched_ext อนุญาตให้เขียน `p->scx.dsq_vtime` ตรง ๆ (เคอร์เนลนี้มี kfunc `scx_bpf_task_set_dsq_vtime()` ด้วย)
- `ops.enable` ถูกเรียกเมื่อ task เข้ามาอยู่ใต้ scheduler เรา (เช่น ตอน `sched_setattr` เป็น SCHED_EXT) จึงตั้ง vtime เริ่มต้นเป็นปัจจุบัน
- `ops.init` คืนค่าลบ = โหลดไม่สำเร็จ (scheduler ไม่ถูกเปิด)

```c
SEC(".struct_ops.link")
struct sched_ext_ops w25_ops = {
	.select_cpu = (void *)w25_select_cpu, ... .exit = (void *)w25_exit,
	.flags      = SCX_OPS_SWITCH_PARTIAL,
	.timeout_ms = 5000,
	.name       = "w25_minimal",
};
```
- ตัวแปรนี้กลายเป็น struct_ops map ชื่อ `w25_ops` callback ที่ไม่ใส่ (เช่น `dequeue`, `tick`) เคอร์เนลใช้พฤติกรรม default
- `.name` คือชื่อที่เห็นใน `/sys/kernel/sched_ext/root/ops` และ `dmesg`

### 2.3 ไฟล์ `sched.go` (ใช้ร่วมระหว่าง `main.go` และ `main_test.go`)

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-global-types -type w25_exit_info -cflags "-I../../" bpf scx_w25.c
```
- **`-no-global-types` จำเป็น:** bpf2go v0.22 พยายามสร้าง Go type ให้ value ของทุก map รวมถึง `struct sched_ext_ops` ซึ่งเต็มไปด้วย function pointer แล้วล้มด้วย `field 0: type *btf.Pointer: not supported` เราจึงปิดการสร้าง type อัตโนมัติ และขอเฉพาะ `-type w25_exit_info`

```go
spec.Variables["vtime_mode"].Set(cfg.vtime)
spec.Variables["fail_mode"].Set(cfg.failMode)
setOpsU32(spec.Maps["w25_ops"], "timeout_ms", cfg.timeoutMs)
spec.LoadAndAssign(&s.objs, nil)
s.lnk, err = link.AttachStructOps(link.StructOpsOptions{Map: s.objs.W25Ops})
```
- `CollectionSpec.Variables` (API ของ cilium/ebpf รุ่นใหม่ เช่น v0.22 ที่แล็บนี้ใช้) แก้ค่า `const volatile` ก่อนโหลด
- `setOpsU32` แก้ field ข้อมูลของตาราง ops ใน `MapSpec.Contents` โดยหา offset ของ `timeout_ms` จาก BTF (ไม่ hard-code offset) — ใช้ลด watchdog timeout ตอนสาธิต
- `LoadAndAssign` โหลดโปรแกรมและสร้าง struct_ops map (cilium/ebpf ใส่ FD ของโปรแกรมลงช่อง function pointer และคัดลอกฟิลด์ข้อมูลให้) แต่ยัง **ไม่** register
- `link.AttachStructOps` = `BPF_LINK_CREATE` บน map → เคอร์เนลเรียก `ops.init` และเปิด scheduler; `Close()` ของ link = unregister แบบ synchronous จากนั้นเรารอจน `state` เป็น `disabled`

```go
func extRun(args []string) error {
	runtime.LockOSThread()
	attr, _ := unix.SchedGetAttr(0, 0)
	attr.Policy = schedExt // 7
	unix.SchedSetAttr(0, attr, 0)
	return syscall.Exec(path, args, os.Environ())
}
```
- เทียบเท่า `chrt --ext 0 <cmd>`: ตั้ง policy ของ thread ปัจจุบันแล้ว `execve` (policy ข้าม exec และสืบทอดสู่ลูก)
- อ่าน attr เดิมก่อนเพื่อ **คงค่า nice** — ถ้าส่ง `Nice: 0` ทับโปรเซสที่ nice 10 จะกลายเป็นการลด nice ซึ่งต้องมี `CAP_SYS_NICE` (ผู้ใช้ธรรมดาได้ `EPERM`)

`startWorkload()` สร้าง `n` โปรเซส `<self> ext-run sh -c '<วนคำนวณ 2000 รอบแล้ว sleep 0.005>'` อยู่ใน process group เดียวกัน (`Setpgid`) และตั้ง `Pdeathsig: SIGKILL` เพื่อให้ workload ตายตาม loader เสมอ; `stopWorkload()` ส่ง SIGKILL ทั้งกลุ่ม

### 2.4 ไฟล์ `main.go`

1. `ext-run` subcommand ไม่ต้องใช้ root และไม่โหลด BPF
2. แสดง `/sys/kernel/sched_ext/{state,root/ops,switch_all,enable_seq}` ก่อน attach → หลัง attach → หลัง detach
3. `defer sched.Close()` ทำงานทุกเส้นทางที่จบ (หมด `-duration` (สูงสุด 120 s), Ctrl+C/SIGTERM, หรือถูก eject)
4. ทุก `-interval` อ่าน `stats` (PERCPU_ARRAY → `[]uint64` ต่อ CPU) พิมพ์ส่วนต่าง และอ่าน `exit_info` — ถ้า `kind != 0` แปลว่าเคอร์เนล eject แล้ว จึงพิมพ์ reason/msg และออกจาก loop
5. จบด้วยตารางสรุปต่อ CPU

### 2.5 ไฟล์ `main_test.go` — ทำไมไม่ใช้ `BPF_PROG_TEST_RUN`

แล็บก่อนหน้าทดสอบด้วย `BPF_PROG_TEST_RUN` แต่ **struct_ops ของ sched_ext ไม่รองรับ** (เคอร์เนลมี test_run ของ struct_ops เฉพาะ `bpf_dummy_ops` ที่ใช้ใน selftests) test `TestStructOpsHasNoTestRun` ยืนยันข้อนี้ (ได้ `operation not supported`) เทสต์ที่เหลือจึงเป็น **runtime test แบบ attach จริงในโหมด partial กับ workload ของเราเอง**:

| Test | ตรวจอะไร |
|---|---|
| `TestSchedulerDispatchesExtTasks/{fifo,vtime}` | `state=enabled`, `root/ops=w25_minimal`, `switch_all=0`, workload มี policy 7, ตัวนับ enqueue/dispatch/running > 0, detach แล้ว exit kind = `UNREG` (64) |
| `TestWatchdogEjectsStalledScheduler` | `-fail stall` + `timeout_ms=1000` → kind = `ERROR_STALL` (1026), state กลับเป็น `disabled`, และ workload **ยังได้ CPU ต่อ** (`se.sum_exec_runtime` เพิ่ม) หลัง eject |
| `TestScxBpfErrorEjects` | `-fail error` → kind = `ERROR_BPF` (1025) และ msg เป็นข้อความของเรา |
| `TestStructOpsHasNoTestRun` | โหลดอย่างเดียว (ไม่ attach) แล้วยืนยันว่า `Program.Run` ล้ม |

- `TestMain` ทำให้ test binary รับ subcommand `ext-run` ได้ด้วย
- ทุก test ข้าม (`t.Skip`) ถ้าไม่ใช่ root หรือมี sched_ext scheduler ตัวอื่นเปิดอยู่ (จะไม่ไปยุ่งกับมัน) และ `Makefile` ใช้ `go test -p 1` เพราะเคอร์เนลมี BPF scheduler ได้ทีละตัว

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจว่าเคอร์เนลรองรับ sched_ext

```bash
grep SCHED_CLASS_EXT /boot/config-$(uname -r)     # ต้องได้ CONFIG_SCHED_CLASS_EXT=y
cat /sys/kernel/sched_ext/state                    # ต้องได้ disabled (ไม่มี scheduler อื่นโหลดอยู่)
grep -c 'scx_bpf_dsq_insert\b' ../../vmlinux.h      # ต้อง >= 1 (ไม่มี vmlinux.h: make vmlinux ที่ root)
```

### ขั้นตอนที่ 2: คอมไพล์และรันเทสต์

```bash
cd phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext
make all
make test          # หรือจาก root ของ repo: make week25 && make week25-test
```

### ขั้นตอนที่ 3: ลอง `ext-run` (ไม่ต้องใช้ root)

```bash
./bin/scx-w25 ext-run sh -c 'grep policy /proc/$$/sched'      # policy : 7
```

### ขั้นตอนที่ 4: รัน scheduler แบบ FIFO

```bash
make run                       # = sudo ./bin/scx-w25 (FIFO, workload 2 x nCPU, 10 วินาที)
sudo ./bin/scx-w25 -duration 5s
```

ระหว่างรัน เปิดอีก terminal แล้วสังเกต:

```bash
make state                                      # state / switch_all / root/ops
sudo bpftool struct_ops show                    # เห็น map w25_ops ชนิด sched_ext_ops
sudo bpftool link show | grep struct_ops
./bin/scx-w25 ext-run sh -c 'grep -E "^(policy|ext)" /proc/$$/sched'   # ext.enabled : 1
```

### ขั้นตอนที่ 5: โหมด vtime และผลของค่า nice

```bash
make run-vtime                 # = sudo ./bin/scx-w25 -mode vtime
make demo-nice                 # nice_demo.sh fifo + vtime (spinner 4 ตัวบน CPU 3, 6 วินาที)
```

### ขั้นตอนที่ 6: สาธิต safety net (เฉพาะ workload ของเรา เพราะเป็น partial mode)

```bash
make demo-stall                # -fail stall -timeout 2000 -> watchdog eject
make demo-error                # -fail error             -> scx_bpf_error eject
sudo dmesg | grep -A3 'sched_ext:' | tail
```

### ขั้นตอนที่ 7: ยืนยันว่าเครื่องกลับสู่สภาพเดิม

```bash
cat /sys/kernel/sched_ext/state          # ต้องเป็น disabled
sudo bpftool struct_ops show             # ต้องว่าง
pgrep -f 'ext-run' || echo "no workload left"
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), 12th Gen Intel Core i3-12100 (8 logical CPUs), clang 21.1.8, Go 1.26, cilium/ebpf v0.22.0 — เครื่องมีงานอื่นรันอยู่ระหว่างทดลอง ตัวเลขจึงต่างกันในแต่ละรอบ

### 4.1 `make test`

```text
=== RUN   TestSchedulerDispatchesExtTasks
=== RUN   TestSchedulerDispatchesExtTasks/fifo
    main_test.go:138: mode=fifo local=5569 enqueue=5607 dispatch=5607 running=15001
=== RUN   TestSchedulerDispatchesExtTasks/vtime
    main_test.go:138: mode=vtime local=5962 enqueue=5454 dispatch=5454 running=15082
--- PASS: TestSchedulerDispatchesExtTasks (3.36s)
    --- PASS: TestSchedulerDispatchesExtTasks/fifo (1.69s)
    --- PASS: TestSchedulerDispatchesExtTasks/vtime (1.67s)
=== RUN   TestWatchdogEjectsStalledScheduler
    main_test.go:166: ejected: reason="runnable task stall" msg="exe[78561] failed to run for 1.505s"
    main_test.go:175: pid 78561 sum_exec_runtime 29.5ms -> 254.2ms after eject
--- PASS: TestWatchdogEjectsStalledScheduler (2.10s)
=== RUN   TestScxBpfErrorEjects
--- PASS: TestScxBpfErrorEjects (0.50s)
=== RUN   TestStructOpsHasNoTestRun
    main_test.go:217: BPF_PROG_TEST_RUN on struct_ops/w25_running: run program: operation not supported (expected)
--- PASS: TestStructOpsHasNoTestRun (0.03s)
PASS
ok  	ebpf-noob-to-hero/phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext	5.992s
sched_ext state after tests: disabled
```

### 4.2 `sudo ./bin/scx-w25 -duration 5s` (FIFO)

```text
======================================================================
 Week 25: sched_ext BPF scheduler (mode=fifo, fail=none, SWITCH_PARTIAL)
======================================================================
[sysfs] before attach  state=disabled  root/ops=-            switch_all=0 enable_seq=20
[sysfs] after attach   state=enabled   root/ops=w25_minimal  switch_all=0 enable_seq=21
[work ] 16 x `sh -c <spin+sleep loop>` pgid=54170, policy of pid 54170 = 7 (7 = SCHED_EXT)
[stats] deltas per interval (รวมทุก CPU); running/CPU = จำนวนครั้งที่ task ของเราขึ้นแต่ละ CPU
[  1.0s] local=+3342   enqueue=+4112   dispatch=+4112   running=+13006  | running/CPU: 1569 1665 1602 1672 1583 1672 1629 1614
[  2.0s] local=+2916   enqueue=+4167   dispatch=+4167   running=+14624  | running/CPU: 3251 3586 3345 3668 3205 3628 3523 3424
[  3.0s] local=+3218   enqueue=+3991   dispatch=+3991   running=+13636  | running/CPU: 4923 5467 5338 5292 4879 5389 5118 4860
[  4.0s] local=+2802   enqueue=+4127   dispatch=+4124   running=+14900  | running/CPU: 6690 7230 8348 6805 6705 7113 6800 6475
[  5.0s] local=+2989   enqueue=+4188   dispatch=+4191   running=+13994  | running/CPU: 8504 9036 10125 8681 8316 8907 8504 8087
[main ] -duration 5s reached
----------------------------------------------------------------------
CPU       local    enqueue   dispatch    running
0          1794       2649       2620       8504
1          1836       2613       2642       9036
2          1855       2563       2563      10125
3          1907       2550       2605       8681
4          1897       2492       2558       8316
5          1918       2560       2513       8907
6          2030       2651       2592       8504
7          2030       2507       2492       8088
all       15267      20585      20585      70161
[sysfs] after detach   state=disabled  root/ops=-            switch_all=0 enable_seq=21
[exit ] kind=UNREG(64) reason="unregistered from user space"
```

`dmesg` ของการรันแบบนี้มี 2 บรรทัดต่อรอบ:

```text
[ 1080.712787] sched_ext: BPF scheduler "w25_minimal" enabled (partial)
[ 1084.800147] sched_ext: BPF scheduler "w25_minimal" disabled (unregistered from user space)
```

### 4.3 มุมมองจาก `bpftool` ระหว่าง scheduler ทำงาน (ตัดบางส่วน)

```text
$ sudo bpftool struct_ops show
9672: w25_ops         sched_ext_ops
$ sudo bpftool link show | grep struct_ops
121: struct_ops  map 9672
$ sudo bpftool prog show | grep -A1 struct_ops
3289: struct_ops  name w25_dispatch  tag 504874827a192b67  gpl
	loaded_at 2026-10-28T23:13:40+0700  uid 0
3290: struct_ops  name w25_enable  tag 16edb0ff03828730  gpl
...
3295: struct_ops  name w25_select_cpu  tag 3b2abc63fc1b5638  gpl
$ ./bin/scx-w25 ext-run sh -c 'grep -E "^(policy|ext)" /proc/$$/sched'
policy                                       :                    7
ext.enabled                                  :                    1
```

### 4.4 `make demo-nice`: FIFO vs vtime (spinner 4 ตัว pin บน CPU 3 นาน 6 วินาที)

```text
== mode=fifo: 4 SCHED_EXT spinners pinned to CPU 3 for 6s
pid=67529   nice=0   policy=7 cpu_ms=1496
pid=67530   nice=0   policy=7 cpu_ms=1496
pid=67531   nice=10  policy=7 cpu_ms=1512
pid=67532   nice=10  policy=7 cpu_ms=1497
== mode=vtime: 4 SCHED_EXT spinners pinned to CPU 3 for 6s
pid=67968   nice=0   policy=7 cpu_ms=2737
pid=67969   nice=0   policy=7 cpu_ms=2638
pid=67970   nice=10  policy=7 cpu_ms=320
pid=67971   nice=10  policy=7 cpu_ms=322
```

### 4.5 `make demo-stall`: watchdog eject

```text
======================================================================
 Week 25: sched_ext BPF scheduler (mode=fifo, fail=stall, SWITCH_PARTIAL)
======================================================================
[sysfs] before attach  state=disabled  root/ops=-            switch_all=0 enable_seq=24
[sysfs] after attach   state=enabled   root/ops=w25_minimal  switch_all=0 enable_seq=25
[work ] 4 x `sh -c <spin+sleep loop>` pgid=68307, policy of pid 68307 = 7 (7 = SCHED_EXT)
[stats] deltas per interval (รวมทุก CPU); running/CPU = จำนวนครั้งที่ task ของเราขึ้นแต่ละ CPU
[  1.0s] local=+0      enqueue=+4      dispatch=+0      running=+14     | running/CPU: 3 0 3 5 3 0 0 0
[  2.0s] local=+0      enqueue=+0      dispatch=+0      running=+25     | running/CPU: 4 1 5 6 14 5 3 1
[  3.0s] local=+0      enqueue=+0      dispatch=+0      running=+0      | running/CPU: 4 1 5 6 14 5 3 1
[eject] kernel disabled the BPF scheduler: kind=ERROR_STALL(1026)
[eject] reason="runnable task stall"
[eject] msg="exe[68310] failed to run for 2.028s"
[eject] SCHED_EXT tasks fall back to the fair class; see `sudo dmesg | grep sched_ext`
[sysfs] after eject    state=disabled  root/ops=-            switch_all=0 enable_seq=25
----------------------------------------------------------------------
CPU       local    enqueue   dispatch    running
...
all           0          4          0         39
[sysfs] after detach   state=disabled  root/ops=-            switch_all=0 enable_seq=25
[exit ] kind=ERROR_STALL(1026) reason="runnable task stall"

$ sudo dmesg | grep -A3 'sched_ext:' | tail -n 8
[ 1464.901995] sched_ext: BPF scheduler "w25_minimal" enabled (partial)
[ 1466.958488] sched_ext: BPF scheduler "w25_minimal" disabled (runnable task stall)
[ 1466.958510] sched_ext: w25_minimal: exe[68310] failed to run for 2.028s
[ 1466.958518]    scx_exit+0x50/0x80
[ 1466.958535]    scx_watchdog_workfn+0x160/0x200
[ 1466.958547]    process_one_work+0x1ac/0x3d0
```

### 4.6 `make demo-error`: `scx_bpf_error()` จากโค้ด BPF

```text
[  1.0s] local=+789    enqueue=+0      dispatch=+0      running=+1019   | running/CPU: 154 86 135 107 142 117 157 121
[eject] kernel disabled the BPF scheduler: kind=ERROR_BPF(1025)
[eject] reason="scx_bpf_error"
[eject] msg="w25: deliberate scx_bpf_error after 1000 running events"
[eject] SCHED_EXT tasks fall back to the fair class; see `sudo dmesg | grep sched_ext`
[sysfs] after eject    state=disabled  root/ops=-            switch_all=0 enable_seq=26
...
[exit ] kind=ERROR_BPF(1025) reason="scx_bpf_error"

$ sudo dmesg | grep -A3 'sched_ext:' | tail -n 5
[ 1468.523424] sched_ext: BPF scheduler "w25_minimal" disabled (scx_bpf_error)
[ 1468.523437] sched_ext: w25_minimal: w25: deliberate scx_bpf_error after 1000 running events
[ 1468.523442]    scx_exit+0x50/0x80
[ 1468.523454]    scx_bpf_error_bstr+0x79/0xb0
[ 1468.523461]    bpf_prog_e4dff11fc60b8767_w25_running+0xbe/0xd3
```

หลังทุกการทดลองข้างต้น `/sys/kernel/sched_ext/state` กลับเป็น `disabled`

**การตีความ:**
- **Partial mode ทำงานตามที่ออกแบบ:** `switch_all=0` และ `dmesg` ระบุ `enabled (partial)` ทุกครั้ง; `enable_seq` เพิ่มทีละ 1 ต่อการโหลดหนึ่งครั้ง
- **`enqueue == dispatch` เมื่อรวมทุก CPU** (20,585 = 20,585 ในหัวข้อ 4.2): ทุก task ที่เข้า `SHARED_DSQ` ถูกดึงออกไปรันครบ แต่ **ต่อ CPU ไม่เท่ากัน** เพราะ task ถูก enqueue บน CPU หนึ่งแล้วไปถูก dispatch บนอีก CPU ได้ (คิวเดียวทั้งระบบ = global FIFO); ตัวเลขรายวินาทีที่ dispatch มากกว่า enqueue เล็กน้อยเกิดจากการอ่านตัวนับคนละจังหวะ
- **`local` (direct dispatch)** คือการตื่นที่ `select_cpu` เจอ CPU ว่างจึงข้าม `ops.enqueue` — ในหัวข้อ 4.6 ที่มี workload แค่ 4 โปรเซสบน 8 CPU แทบทุกการตื่นเป็น direct dispatch (`enqueue=+0`) ส่วน 16 โปรเซสในหัวข้อ 4.2 ทำให้ต้องเข้าคิวบ่อยขึ้น
- **`running` มากกว่า `local + enqueue` หลายเท่า:** `ops.running` ถูกเรียกทุกครั้งที่ task ได้ขึ้น CPU ไม่ใช่เฉพาะหลังผ่าน enqueue/dispatch สาเหตุที่น่าจะเป็นคือกรณีที่เคอร์เนลวาง task กลับลง local DSQ เองโดยไม่เรียก `ops.enqueue` เช่น task ถูก task ของ class ที่สูงกว่า (fair) แย่ง CPU ชั่วคราวแล้วได้กลับมารันต่อด้วย slice ที่เหลือ หรือเป็น task สุดท้ายบน CPU ที่ได้ slice ใหม่โดยไม่ต้องเข้าคิว (ไม่ได้ตั้ง `SCX_OPS_ENQ_LAST`) — ลองพิสูจน์เองในแบบฝึกหัดระดับพื้นฐานข้อ 2
- **vtime เคารพ nice:** บน CPU เดียวกัน FIFO แบ่งเวลาเท่ากันทั้ง 4 ตัว (~1.5 s) ไม่สนใจ nice ส่วน vtime ให้ nice 0 ได้ ~2.64–2.74 s และ nice 10 ได้ ~0.32 s อัตราส่วนประมาณ 8.2–8.6 : 1 ใกล้แต่ไม่เท่ากับอัตราส่วน weight 100 : 11 (≈ 9 : 1) ส่วนหนึ่งเพราะ dispatch เกิดก่อนที่ `prev` จะกลับเข้าคิว (ดูข้อจำกัดข้อ 3) และ CPU 3 ยังมี task ของ fair class มาแทรกเป็นระยะ
- **Watchdog:** ตั้ง `timeout_ms=2000` แล้วถูก eject หลัง task ค้าง 2.028 s (ใน test ที่ตั้ง 1000 ms ถูก eject ที่ 1.505 s) — watchdog ตรวจเป็นรอบ เวลาจริงจึงเกิน `timeout_ms` ได้ ไม่ใช่การตัดตรงเป๊ะ; task ที่ค้างชื่อ `exe` เพราะยังอยู่ระหว่าง `ext-run` (`/proc/self/exe`) ก่อน `execve` เป็น `sh`
- ใน 4.5 ตัวนับ `running` ยังขยับเล็กน้อยระหว่าง stall: เป็นจังหวะที่ task กำลังรันอยู่ตอนถูกเปลี่ยน policy หรือช่วงที่เคอร์เนลกำลังถอด scheduler — ไม่ใช่งานที่ถูก dispatch จาก `SHARED_DSQ` (`dispatch=0` ตลอด)
- **หลัง eject workload ไม่ตาย:** test วัดได้ว่า `se.sum_exec_runtime` ของ workload เพิ่มจาก 29.5 ms เป็น 254.2 ms ภายใน 0.5 s หลัง eject = กลับไปรันด้วย fair class

---

## 5. ข้อจำกัด (Limitations)

1. **ต้องใช้เคอร์เนลที่มี sched_ext (6.12+ และ `CONFIG_SCHED_CLASS_EXT=y`)** Ubuntu 24.04 (6.8) ไม่มี; ชื่อ kfunc และ flag เปลี่ยนตามรุ่น (ดูหัวข้อ 1.3) จึงต้องตรวจ `vmlinux.h` ของเครื่องเป้าหมายเสมอ upstream แก้ปัญหานี้ด้วย `compat.bpf.h` ซึ่งแล็บนี้ไม่ได้ทำ
2. **Global FIFO/vtime คิวเดียว:** ทุก CPU แย่ง lock ของ `SHARED_DSQ` เดียวกัน ไม่สนใจ cache locality/NUMA/topology — เหมาะกับการเรียนรู้ ไม่เหมาะกับเครื่องหลายสิบคอร์
3. **ไม่จัดการ `prev` ใน `ops.dispatch`:** เมื่อ slice หมด เคอร์เนลเรียก dispatch ก่อน enqueue(prev) ถ้ามีแค่ 2 task บน CPU เดียว โหมด vtime จะสลับรันแบบ 1:1 ไม่เคารพ nice (เราจึงสาธิตด้วย 4 task) — scheduler จริงตัดสินใจเรื่อง prev ใน dispatch เอง
4. **ไม่มีการ preempt:** task ที่ vtime ต่ำกว่าไม่ได้แย่ง CPU จาก task ที่กำลังรัน ต้องรอ slice 20 ms หมด (ใช้ `scx_bpf_kick_cpu(..., SCX_KICK_PREEMPT)` ได้)
5. **Partial mode = ลำดับต่ำกว่า fair:** task `SCHED_EXT` จะได้ CPU เมื่อไม่มี task ปกติรออยู่ ตัวเลขจึงขึ้นกับ load อื่นของเครื่อง ถ้าเครื่องยุ่งมาก watchdog อาจ eject แม้ scheduler ไม่มีบั๊ก (ปรับ `-timeout` ได้ถึง `SCX_WATCHDOG_MAX_TIMEOUT` = 30000 ms)
6. **ทดสอบด้วย `BPF_PROG_TEST_RUN` ไม่ได้:** ต้อง attach จริงและต้องใช้ root ทั้งระบบมี BPF scheduler ได้ทีละตัว — ถ้ามีตัวอื่นโหลดอยู่ (เช่น `scx_*` จาก distro) แล็บจะ attach ไม่ได้และเทสต์จะ skip
7. **สถิติเป็น snapshot ไม่ atomic:** อ่าน PERCPU_ARRAY ทีละ key ขณะที่ scheduler ยังทำงาน ตัวเลขข้าม key ในรอบเดียวกันจึงคลาดกันเล็กน้อย
8. **การเขียน `p->scx.dsq_vtime` ตรง ๆ** ทำงานบน 7.0 แต่ upstream มี kfunc `scx_bpf_task_set_dsq_vtime()` แล้ว เป็นไปได้ว่ารุ่นหลังจะบังคับให้ใช้ kfunc แทน

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| `/sys/kernel/sched_ext not found` | เคอร์เนลไม่มี `CONFIG_SCHED_CLASS_EXT` (เช่น 6.8) ต้องใช้ 6.12+ |
| `attach StructOps: create link: device or resource busy` | มี BPF scheduler ตัวอื่นเปิดอยู่ (ทดลองจริง: รัน loader 2 ตัวพร้อมกันได้ error นี้) ดู `cat /sys/kernel/sched_ext/root/ops` แล้วหยุดตัวนั้นก่อน |
| bpf2go: `generating bpfSchedExtOps: ... type *btf.Pointer: not supported` | ต้องใส่ `-no-global-types` (และ `-type` เฉพาะ struct ที่ต้องการ) |
| clang: `Invalid usage of the XADD return value` / `unsupported atomic operation` | bpf2go ใช้ `-mcpu=v1` เลี่ยงการใช้ค่าคืนของ atomic และ cmpxchg (หรือเพิ่ม `-mcpu=v3` ใน `-cflags`) |
| `redefinition of enumerator 'NR_STATS'` | ชื่อชนกับ enum ใน `vmlinux.h` ตั้งชื่อ enum ของตัวเองให้มี prefix |
| `sched_setattr(SCHED_EXT): operation not permitted` | ส่ง nice ใหม่ที่ต่ำกว่าค่าเดิม (เช่นใช้ `nice -n 10` แล้วตั้ง Nice=0) ต้องคงค่า nice เดิมไว้ (โค้ดนี้อ่านด้วย `SchedGetAttr` ก่อน) |
| `chrt: unrecognized option '--ext'` | util-linux ยังไม่รองรับ ใช้ `./bin/scx-w25 ext-run <cmd>` |
| `ps` แสดง policy/nice เป็น `-` | procps ไม่รู้จัก policy 7 ดู `/proc/<pid>/sched` (`policy`, `prio`) หรือ `/proc/<pid>/stat` ฟิลด์ 19 แทน |
| scheduler ถูก eject ด้วย `runnable task stall` ทั้งที่ไม่ได้ใช้ `-fail stall` | เครื่องมี load ของ fair class สูงจน task SCHED_EXT ไม่ได้ CPU นานเกิน timeout เพิ่ม `-timeout` หรือลด `-workload` |
| คำเตือน `vmlinux.h:...: warning: declaration does not declare anything` | มาจาก `vmlinux.h` ของเคอร์เนล 7.0 กับ clang 21 ไม่กระทบผลลัพธ์ |
| ต้องการถอด scheduler ฉุกเฉิน | Ctrl+C ที่ loader, `sudo pkill scx-w25` หรือ `echo S | sudo tee /proc/sysrq-trigger` (ถ้าเปิด sysrq ไว้) |

---

## 7. Milestone Checklist

- [x] อธิบายแนวคิด struct_ops (BPF implement ops table, `.struct_ops` vs `.struct_ops.link`) และยกตัวอย่าง subsystem ที่ใช้
- [x] อธิบายตำแหน่งของ `ext_sched_class`, DSQ ทั้ง 3 แบบ และลำดับ callback `select_cpu → enqueue → dispatch → running → stopping`
- [x] ตรวจชื่อ kfunc ที่มีจริงในเคอร์เนลจาก `vmlinux.h` (`scx_bpf_dsq_insert`, `scx_bpf_dsq_move_to_local` แทนชื่อเก่า)
- [x] เขียน scheduler FIFO และ weighted vtime ที่โหลดผ่าน verifier และ attach ด้วย `link.AttachStructOps` (cilium/ebpf v0.22)
- [x] ใช้ `SCX_OPS_SWITCH_PARTIAL` + `sched_setattr(SCHED_EXT)` จำกัดผลกระทบไว้ที่ workload ทดสอบ และตรวจ `switch_all=0`
- [x] อ่านสถิติต่อ CPU จาก PERCPU_ARRAY แบบสด และ detach สะอาดทุกเส้นทาง (timeout / Ctrl+C / eject)
- [x] สาธิต watchdog (`ERROR_STALL`) และ `scx_bpf_error` (`ERROR_BPF`) พร้อมอ่านเหตุผลจาก `ops.exit` และ `dmesg`
- [x] ทดสอบด้วย runtime test (`make test`) และเข้าใจว่าทำไม struct_ops ใช้ `BPF_PROG_TEST_RUN` ไม่ได้

---

## 8. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **นับ `ops.stopping`:** เพิ่ม `STAT_STOPPING` และแยกนับกรณี `runnable == true` (ถูกแย่ง/หมด slice) กับ `false` (หลับ/บล็อก) 
   - **ตรวจสอบ:** ผลรวม stopping ต้องใกล้เคียง running (ต่างกันไม่เกินจำนวน task ที่กำลังรันอยู่ตอนอ่าน) และสัดส่วน `runnable=false` ต้องสูงขึ้นเมื่อเพิ่ม `sleep` ใน workload
2. **พิสูจน์ที่มาของ `running` ที่ไม่ผ่าน enqueue:** รัน `sudo ./bin/scx-w25 -workload 0 -duration 8s` แล้วรัน spinner `taskset -c 3 ./bin/scx-w25 ext-run sh -c 'while :; do :; done'` เพียงตัวเดียว 
   - **ตรวจสอบ:** บันทึกค่า enqueue เทียบ running ของ CPU 3 แล้วอธิบายผลด้วย `SCX_OPS_ENQ_LAST`; จากนั้นเพิ่ม `SCX_OPS_ENQ_LAST` ใน `.flags` แล้วรันซ้ำ ค่า enqueue ต้องเพิ่มขึ้นอย่างชัดเจน

### ระดับปานกลาง
1. **Per-CPU DSQ:** สร้าง DSQ หนึ่งคิวต่อ CPU (`scx_bpf_create_dsq(cpu, -1)` วนใน `ops.init` ด้วย `bpf_for`) ให้ `enqueue` ใส่คิวของ `scx_bpf_task_cpu(p)` และให้ `dispatch` ดึงคิวของตัวเองก่อนแล้วค่อยขโมยจากคิวอื่น (work stealing) 
   - **ตรวจสอบ:** เพิ่มตัวนับ `STAT_STEAL`; รัน workload 16 โปรเซสแล้วตรวจจากตารางสรุปว่า dispatch > 0 ทุก CPU เพิ่ม test case ใน `main_test.go` และอธิบายว่า steal เกิดบ่อยแค่ไหน
2. **Preemption ด้วย `scx_bpf_kick_cpu`:** ในโหมด vtime ถ้า task ที่เพิ่ง enqueue มี vtime ต่ำกว่า task ที่รันอยู่บน CPU ของมันมาก ให้ kick CPU นั้นด้วย `SCX_KICK_PREEMPT` 
   - **ตรวจสอบ:** วัด latency การตื่นของ task nice 0 (เช่น ใช้ `cyclictest` หรือวัดเวลาเองใน Go) ขณะมี spinner nice 10 บน CPU เดียวกัน เทียบก่อน/หลัง พร้อมระบุวิธีวัดและจำนวนรอบ

### ระดับท้าทาย
1. **จัดการ `prev` ใน `ops.dispatch`:** เมื่อ `prev` ยัง runnable ให้เทียบ vtime ของ `prev` กับหัวคิว (`scx_bpf_dsq_peek()` มีในเคอร์เนลนี้) ถ้า `prev` ยังควรได้รันต่อให้เติม slice แทนการปล่อยให้ dispatch ดึงตัวอื่น — ระวังเรื่องการคิด vtime ซ้ำ/ตกหล่นใน `ops.stopping` 
   - **ตรวจสอบ:** `nice_demo.sh` แบบ spinner **2 ตัว** (nice 0 กับ nice 10) ในโหมด vtime ต้องได้อัตราส่วน CPU time ใกล้ 9:1 (โค้ดปัจจุบันได้ ~1:1)
2. **struct_ops ตัวที่สอง: `tcp_congestion_ops`:** เขียน congestion control แบบ Reno ขั้นต่ำ (`ssthresh`, `cong_avoid`, `undo_cwnd`) ด้วย `SEC(".struct_ops.link")` แล้ว attach ด้วยโค้ด Go เดิม 
   - **ตรวจสอบ:** `sysctl net.ipv4.tcp_available_congestion_control` ต้องมีชื่อของเรา และใน netns ทดสอบ (`w25-` prefix ตามธรรมเนียมของหลักสูตร) `ss -ti` ของการเชื่อมต่อที่ใช้ `setsockopt(TCP_CONGESTION)` ต้องแสดงชื่อ algorithm ของเรา

---

## 9. อ่านต่อ (Further Reading)

- เอกสารในเคอร์เนล: `Documentation/scheduler/sched-ext.rst` และตัวอย่างใน `tools/sched_ext/` (`scx_simple`, `scx_qmap`, `scx_central`, ...) ซึ่งแล็บนี้ดัดแปลงแนวคิดมา
- repo `sched-ext/scx` บน GitHub รวม scheduler ระดับใช้งานจริงหลายตัว เช่น **`scx_rusty`** (เขียนส่วน load balancing ฝั่ง userspace ด้วย Rust แบ่ง CPU เป็น domain), **`scx_lavd`** (latency-criticality aware virtual deadline มุ่งงาน interactive/เกม) และ **`scx_bpfland`** (อิง vruntime ให้ความสำคัญกับ task interactive) — รายละเอียดอัลกอริทึมและสถานะของแต่ละตัวเปลี่ยนเร็ว ควรอ่านจาก README ของ repo โดยตรงก่อนอ้างอิง และ **ห้ามรัน scheduler แบบ switch-all บนเครื่องที่ใช้ร่วมกัน**
- struct_ops ฝั่ง TCP: `tools/testing/selftests/bpf/progs/bpf_cubic.c`, `bpf_dctcp.c`
