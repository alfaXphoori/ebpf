# Week 19: Memory Page Faults & OOM Killer Forensics ด้วย CO-RE Tracepoints

ยินดีต้อนรับสู่สัปดาห์ที่ 19 ของหลักสูตร **eBPF: Zero-to-Hero** ในระบบ Cloud Native ปัญหา **OOM (Out-Of-Memory) Kill** เป็นหนึ่งในเหตุการณ์ที่พบบ่อยที่สุด — คอนเทนเนอร์ใช้หน่วยความจำเกิน limit แล้วถูกเคอร์เนลฆ่าทิ้งทันทีด้วย `SIGKILL` โดยแอปพลิเคชันไม่มีโอกาสเขียน log ใด ๆ เลย สิ่งที่เหลืออยู่มักมีแค่ `exit code 137` และบรรทัดเดียวใน `dmesg`

ในบทนี้เราจะสร้าง **Memory & OOM Watcher** ที่:
1. นับ **User-space Page Faults** ต่อโปรเซส (แยก fault จากการ "เขียน") ผ่าน `tracepoint/exceptions/page_fault_user`
2. ดักจับเหตุการณ์ **OOM Killer เลือกเหยื่อ** ผ่าน `tracepoint/oom/mark_victim` แล้วส่งรายละเอียดเชิงนิติวิทยาศาสตร์ (PID, UID, ชื่อโปรเซส, Total VM, Anon/File/Shmem RSS, Page Tables, `oom_score_adj`, ผู้กระตุ้น และ **cgroup** ที่เกิดเหตุ) ขึ้น userspace ทาง **Ring Buffer**
3. ใช้เทคนิค CO-RE ขั้นสูง: `bpf_core_field_exists()` และ **type flavors (`___suffix`)** ทำให้โปรแกรมเดียวรองรับ tracepoint ที่มี layout ต่างกันข้ามเวอร์ชันเคอร์เนล
4. ทดลองกระตุ้น OOM **อย่างปลอดภัย** ภายใน transient cgroup ที่จำกัดแรมไว้ 50 MB ด้วย `systemd-run`

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 Page Fault: แรมไม่ได้ถูกจองตอน `malloc()`

Linux ใช้ **Demand Paging** — `malloc()`/`mmap()` เพียงแค่จองช่วง *virtual address* (เพิ่ม `total_vm`) แต่ยังไม่มีหน้าแรมจริง เมื่อโปรแกรมแตะหน้านั้นครั้งแรก CPU จะเกิด **Page Fault** แล้วเคอร์เนลจึงจัดสรรหน้าแรมจริง (เพิ่ม RSS):

```
 malloc(50 MB)  ──>  VMA ใหม่ใน mm_struct (total_vm += 50 MB, RSS ยังเท่าเดิม)
                         │
 *p = 1 (แตะหน้าแรก)  ──>  #PF exception (x86 vector 14)
                         │
                         v
 +-----------------------------------------------------------------------+
 | exc_page_fault()                                                      |
 |   -> trace_page_fault_user(address, regs, error_code)  <== eBPF hook  |
 |   -> handle_mm_fault()                                                |
 |        -> จัดสรรหน้า 4 KiB (charge เข้า memory cgroup ของโปรเซส)       |
 |             │                                                         |
 |             └─ ถ้า cgroup เกิน memory.max และ reclaim ไม่ได้           |
 |                  -> mem_cgroup_out_of_memory() -> OOM killer (1.2)     |
 +-----------------------------------------------------------------------+
```

`error_code` ของ x86 บอกชนิดของ fault ทีละบิต เช่น bit 1 (`X86_PF_WRITE`) = fault จากการเขียน, bit 0 (`X86_PF_PROT`) = หน้ามีอยู่แล้วแต่สิทธิ์ไม่พอ (เช่น Copy-on-Write) ในแล็บนี้เรานับแยก fault จากการเขียนไว้ด้วย

ผลที่ตามมา: การแตะหน่วยความจำใหม่ 50 MiB ด้วยหน้า 4 KiB จะเกิด page fault ประมาณ 50 × 1024 / 4 = **12,800 ครั้ง** — เราจะใช้ตัวเลขนี้ตรวจผลในหัวข้อ 4

---

### 1.2 OOM Killer และ Memory Cgroup

เมื่อการจัดสรรหน่วยความจำล้มเหลวหลังจาก reclaim แล้ว เคอร์เนลเรียก **OOM Killer** ซึ่ง:
1. คำนวณ `oom_badness()` ของแต่ละโปรเซสในขอบเขต (ทั้งระบบ หรือเฉพาะใน memory cgroup ที่เกิน limit) — โดยหลักคือ RSS + swap + page tables ปรับด้วย `oom_score_adj` (-1000 ถึง 1000)
2. เลือกเหยื่อที่คะแนนสูงสุด แล้วเรียก `mark_oom_victim()` → **`trace_mark_victim()`** ← เรา hook ที่นี่
3. ส่ง `SIGKILL` และพิมพ์ `Killed process ...` ลง kernel log ให้ **OOM reaper** เก็บหน่วยความจำคืน

บนระบบที่ใช้ systemd/คอนเทนเนอร์ ส่วนใหญ่ OOM เกิดในระดับ **memory cgroup** (`memory.max`) ไม่ใช่ทั้งเครื่อง — kernel log จะระบุ `constraint=CONSTRAINT_MEMCG` นี่คือเหตุผลที่เราเก็บ cgroup ของเหตุการณ์ไว้ด้วย

> [!IMPORTANT]
> **ใน context ของ `mark_victim` ตัวแปร `current` คือ task ที่ "กระตุ้น" OOM** (task ที่กำลังจองแรมไม่สำเร็จ) ไม่จำเป็นต้องเป็นเหยื่อ — ในระบบจริงโปรเซส A อาจจองแรมแล้วโปรเซส B ที่ใหญ่กว่าในกลุ่มเดียวกันถูกฆ่า เราจึงรายงานทั้ง "Victim" (จาก `ctx->pid`) และ "Triggered by" (จาก `bpf_get_current_pid_tgid()`)

---

### 1.3 CO-RE กับ Tracepoint Context ที่เปลี่ยนไปตามเวอร์ชัน

ทุก tracepoint มีโครงสร้าง `struct trace_event_raw_<class>` ใน BTF ซึ่ง `vmlinux.h` นำมาให้เราใช้ได้ทันที เทียบกับไฟล์ format ของ tracepoint บนเครื่องทดสอบ (Linux 7.0):

```text
$ sudo cat /sys/kernel/tracing/events/oom/mark_victim/format
	field:int pid;	offset:8;	size:4;	signed:1;
	field:__data_loc char[] comm;	offset:12;	size:4;	signed:0;
	field:unsigned long total_vm;	offset:16;	size:8;	signed:0;
	field:unsigned long anon_rss;	offset:24;	size:8;	signed:0;
	field:unsigned long file_rss;	offset:32;	size:8;	signed:0;
	field:unsigned long shmem_rss;	offset:40;	size:8;	signed:0;
	field:uid_t uid;	offset:48;	size:4;	signed:0;
	field:unsigned long pgtables;	offset:56;	size:8;	signed:0;
	field:short oom_score_adj;	offset:64;	size:2;	signed:1;
print fmt: "pid=%d comm=%s total-vm=%lukB anon-rss=%lukB ..."
```

ปัญหาความเข้ากันได้ 2 ประเภทที่โค้ดนี้รับมือ:

**(ก) ฟิลด์ที่อาจไม่มี** — เดิม `mark_victim` มีแค่ `pid` ฟิลด์ขยาย (`comm`, `total_vm`, `*_rss`, `uid`, `pgtables`, `oom_score_adj`) ถูกเพิ่มเข้ามาภายหลังในซีรีส์ 6.x (เวอร์ชันที่แน่นอนของแต่ละฟิลด์ให้ตรวจจากไฟล์ format บนเครื่องเป้าหมาย) เราจึงห่อทุกการอ่านด้วย:
```c
if (bpf_core_field_exists(ctx->total_vm)) { ... }
```
ตอนโหลด cilium/ebpf จะแทนค่า `bpf_core_field_exists()` เป็นค่าคงที่ 0/1 ตาม BTF ของเคอร์เนลจริง ถ้าเป็น 0 Verifier จะเห็นกิ่งนั้นเป็น dead code และไม่ตรวจ relocation ที่อยู่ข้างใน

**(ข) ชื่อ struct ที่เปลี่ยน** — tracepoint `exceptions:page_fault_user` บนเครื่องทดสอบ (7.0) ใช้ `struct trace_event_raw_exceptions` แต่เคอร์เนลรุ่นเก่า (เช่น 6.8 ของ Ubuntu 24.04 ที่ event class อยู่ใน `arch/x86/include/asm/trace/exceptions.h`) ใช้ชื่อ `trace_event_raw_x86_exceptions` เราจึงใช้ **CO-RE type flavor**:
```c
struct trace_event_raw_x86_exceptions___old { unsigned long error_code; ... } __attribute__((preserve_access_index));
struct trace_event_raw_exceptions___new     { unsigned long error_code; ... } __attribute__((preserve_access_index));
```
loader จะตัดส่วน `___old`/`___new` ทิ้งเมื่อจับคู่กับ BTF ของเคอร์เนล แล้วใช้ `bpf_core_type_exists()` เลือกกิ่งที่ตรงกับเคอร์เนลที่รันอยู่ — บนเครื่องทดสอบ type `___old` **ไม่มีจริง** และโปรแกรมยังโหลดผ่าน ซึ่งพิสูจน์ว่ากลไกตัดกิ่งทำงาน

> [!NOTE]
> ทั้งสองแบบใช้ตัวอักษรใน `vmlinux.h` ของเครื่องที่ **คอมไพล์** แต่ตัดสินผลจาก BTF ของเครื่องที่ **รัน** นี่คือหัวใจของ "Compile Once – Run Everywhere"

---

### 1.4 `__data_loc`: สตริงความยาวแปรผันใน Tracepoint

ฟิลด์ `__data_loc char[] comm` ไม่ได้เก็บสตริงตรง ๆ แต่เก็บตัวเลข 32 บิต:
- **16 บิตล่าง** = offset ของสตริงนับจากต้น record ของ tracepoint
- **16 บิตบน** = ความยาว

ดังนั้นที่อยู่ของสตริงคือ `(void *)ctx + (loc & 0xffff)` แล้วอ่านด้วย `bpf_probe_read_kernel_str()`

---

### 1.5 ทำไมต้องส่ง OOM event ผ่าน Ring Buffer แต่ Page Fault ใช้ Hash Map

| | Page Fault | OOM |
|---|---|---|
| ความถี่ | สูงมาก (หลายแสนครั้ง/วินาทีบนเครื่องที่ยุ่ง) | น้อยมาก แต่ **ห้ามพลาด** |
| สิ่งที่ต้องการ | สถิติรวม | รายละเอียดทุกเหตุการณ์ทันที |
| กลไก | HASH map รวมผลในเคอร์เนล, Go อ่านทุก 3 วินาที | `BPF_MAP_TYPE_RINGBUF` ส่งทีละ event พร้อมลำดับเวลา |

การส่งทุก page fault ขึ้น userspace จะสร้าง overhead มหาศาล ขณะที่ OOM ต้องการความครบถ้วนมากกว่าประสิทธิภาพ

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `oom_watcher.c`

```c
#define X86_PF_WRITE (1UL << 1)
#define OOM_HAS_RSS   (1U << 0)
#define OOM_HAS_UID   (1U << 1)
#define OOM_HAS_ADJ   (1U << 2)
#define OOM_HAS_COMM  (1U << 3)
```
- **บรรทัด 14-20:** `X86_PF_WRITE` เป็น enum/define ของ arch ที่ไม่มีใน `vmlinux.h` จึงประกาศเอง ส่วน `OOM_HAS_*` เป็น bitmask บอก userspace ว่าเคอร์เนลนี้มีฟิลด์ใดบ้าง (แยก "ค่าเป็น 0 จริง" ออกจาก "ไม่มีข้อมูล")

```c
struct oom_alert {
    __u64 ts_ns;
    __u64 total_vm_kb;
    ...
    __s16 oom_score_adj;
    __u16 pad[3];
    char comm[TASK_COMM_LEN];
    char trigger_comm[TASK_COMM_LEN];
    char cgroup_name[CGROUP_NAME_LEN];
};
```
- **บรรทัด 27-44:** เรียงฟิลด์จากใหญ่ไปเล็กและเติม `pad[3]` เองให้ไม่มี padding แฝง struct ฝั่ง Go (`oomAlert`) จึงอ่านด้วย `binary.Read` ได้ตรงทุกไบต์ (ขนาดรวม 176 ไบต์)

```c
struct pf_stat {
    __u64 faults;
    __u64 write_faults;
};
```
- **บรรทัด 54-64:** value ของแมป `page_fault_counts` (key = `comm` 16 ไบต์)

```c
struct trace_event_raw_x86_exceptions___old { ... } __attribute__((preserve_access_index));
struct trace_event_raw_exceptions___new { ... } __attribute__((preserve_access_index));
```
- **บรรทัด 73-83:** type flavors ตามหัวข้อ 1.3 (ข) ประกาศเฉพาะฟิลด์ที่ใช้ก็พอ เพราะ CO-RE จับคู่ด้วย "ชื่อฟิลด์" ไม่ใช่ตำแหน่ง

```c
SEC("tracepoint/oom/mark_victim")
int on_oom_mark_victim(struct trace_event_raw_mark_victim *ctx)
{
    struct oom_alert *alert = bpf_ringbuf_reserve(&oom_events, sizeof(*alert), 0);
    if (!alert) {
        return 0;
    }
    __builtin_memset(alert, 0, sizeof(*alert));
```
- **บรรทัด 85-92:** ctx เป็น type จาก `vmlinux.h` โดยตรง (แทน struct ที่เขียนเองในเวอร์ชันเดิม) จองพื้นที่ใน ring buffer แล้วล้างเป็น 0 เพราะหน่วยความจำที่ reserve ไม่ได้ถูก zero ให้ (กันข้อมูลเก่ารั่วไปยังฟิลด์ที่ไม่ได้เขียน)

```c
    alert->victim_pid = ctx->pid;
    alert->trigger_pid = bpf_get_current_pid_tgid() >> 32;
    alert->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&alert->trigger_comm, sizeof(alert->trigger_comm));
```
- **บรรทัด 95-98:** แยกเหยื่อ (`ctx->pid`) กับผู้กระตุ้น (`current`) ตามหัวข้อ 1.2 และเก็บ cgroup v2 id ของผู้กระตุ้น

```c
    struct task_struct *task = bpf_get_current_task_btf();
    const char *cg_name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    if (cg_name)
        bpf_probe_read_kernel_str(&alert->cgroup_name, sizeof(alert->cgroup_name), cg_name);
```
- **บรรทัด 105-108:** ไล่ pointer `task->cgroups->dfl_cgrp->kn->name` ด้วย `BPF_CORE_READ` เพื่อได้ **ชื่อไดเรกทอรี cgroup** ตั้งแต่ในเคอร์เนล เหตุผล: transient scope ของ systemd ถูกลบทันทีเมื่อโปรเซสสุดท้ายตาย ถ้ารอให้ userspace ไปค้นหาจาก cgroup id จะไม่ทัน (ผลการทดลองในหัวข้อ 4 แสดงให้เห็นจริง)

```c
    if (bpf_core_field_exists(ctx->total_vm)) {
        alert->total_vm_kb = ctx->total_vm;
        alert->anon_rss_kb = ctx->anon_rss;
        ...
        alert->flags |= OOM_HAS_RSS;
    }
```
- **บรรทัด 116-131:** อ่านฟิลด์ขยายแบบมีเงื่อนไขตามหัวข้อ 1.3 (ก) — หน่วยใน tracepoint นี้เป็น kB อยู่แล้ว (ดู `print fmt` ที่ใช้ `%lukB`) ไม่ต้องแปลงจากจำนวนหน้า

```c
    if (bpf_core_field_exists(ctx->__data_loc_comm)) {
        __u32 loc = ctx->__data_loc_comm;
        bpf_probe_read_kernel_str(&alert->comm, sizeof(alert->comm),
                                  (void *)ctx + (loc & 0xffff));
        alert->flags |= OOM_HAS_COMM;
    }

    bpf_ringbuf_submit(alert, 0);
```
- **บรรทัด 132-140:** ถอดรหัส `__data_loc` ตามหัวข้อ 1.4 แล้ว submit ให้ userspace

```c
SEC("tracepoint/exceptions/page_fault_user")
int on_user_page_fault(void *ctx)
{
    unsigned long error_code = 0;

    if (bpf_core_type_exists(struct trace_event_raw_exceptions___new)) {
        error_code = BPF_CORE_READ((struct trace_event_raw_exceptions___new *)ctx, error_code);
    } else if (bpf_core_type_exists(struct trace_event_raw_x86_exceptions___old)) {
        error_code = BPF_CORE_READ((struct trace_event_raw_x86_exceptions___old *)ctx, error_code);
    }
```
- **บรรทัด 144-158:** เลือก flavor ที่มีอยู่จริง ตรงนี้ **ต้องใช้ `BPF_CORE_READ`** (อ่านผ่าน `bpf_probe_read_kernel`) ไม่ใช่ `ctx->error_code` ตรง ๆ — ระหว่างพัฒนาเราลองอ่านตรงแล้ว clang รวมการคำนวณ `ctx + offset` ของสองกิ่งไว้ใน register เดียว ทำให้ Verifier ปฏิเสธด้วยข้อความจริงดังนี้:
  ```text
  load program: permission denied: dereference of modified ctx ptr R1 off=24 disallowed
  ```
  (Verifier ยอมให้อ่าน ctx ด้วย offset คงที่จาก pointer ต้นฉบับเท่านั้น)

```c
    struct pf_stat *val = bpf_map_lookup_elem(&page_fault_counts, &comm);
    if (!val) {
        struct pf_stat zero = {};
        bpf_map_update_elem(&page_fault_counts, &comm, &zero, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&page_fault_counts, &comm);
        if (!val)
            return 0;
    }
    __sync_fetch_and_add(&val->faults, 1);
    if (error_code & X86_PF_WRITE)
        __sync_fetch_and_add(&val->write_faults, 1);
```
- **บรรทัด 163-174:** รูปแบบ lookup-or-init แบบเดียวกับ Week 17 (page fault ของโปรเซสเดียวเกิดพร้อมกันได้หลาย CPU จาก thread ต่าง ๆ) แล้วเพิ่มค่าแบบ atomic

### 2.2 ไฟล์ `main.go`

```go
type oomAlert struct {
	TsNs        uint64
	...
	OomScoreAdj int16
	Pad         [3]uint16
	Comm        [16]byte
	TriggerComm [16]byte
	CgroupName  [64]byte
}
```
- **บรรทัด 38-55:** mirror ของ `struct oom_alert` ทีละฟิลด์ (ถ้าเพิ่มฟิลด์ใน C ต้องแก้ตรงนี้ด้วย ไม่เช่นนั้น `binary.Read` จะคืน error เพราะขนาดไม่พอ)

```go
func cgroupPath(id uint64) string {
	const root = "/sys/fs/cgroup"
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		...
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Ino == id {
```
- **บรรทัด 64-85:** ใน cgroup v2 ค่า `bpf_get_current_cgroup_id()` คือ **inode number** ของไดเรกทอรี cgroup เราจึงเดินหาไดเรกทอรีที่ inode ตรงกันเพื่อได้ path เต็ม (ถ้า cgroup ยังอยู่)

```go
	tpPF, err := link.Tracepoint("exceptions", "page_fault_user", objs.OnUserPageFault, nil)
	if err != nil {
		log.Printf("[WARN] exceptions:page_fault_user unavailable (x86-only tracepoint): %v", err)
	}
```
- **บรรทัด 149-154:** tracepoint นี้มีเฉพาะ x86 ถ้า attach ไม่ได้ (เช่นบน arm64) ให้ทำงานต่อในโหมด OOM อย่างเดียวแทนการล้มทั้งโปรแกรม

```go
			rec, err := rd.Read()
			...
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &alert); err == nil {
				printAlert(&alert)
			}
```
- **บรรทัด 173-188:** goroutine แยกรอ event จาก ring buffer (บล็อกจนมีข้อมูล) และจบเมื่อ `rd.Close()` ถูกเรียกตอนโปรแกรมออก (`ringbuf.ErrClosed`)

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์
```bash
cd phase08-system-performance-observability/week19-memory-oom-watcher
make all
```

### ขั้นตอนที่ 2: ตรวจ tracepoint บนเครื่องของคุณ
```bash
sudo cat /sys/kernel/tracing/events/oom/mark_victim/format          # ดูว่ามีฟิลด์ขยายหรือไม่
sudo cat /sys/kernel/tracing/events/exceptions/page_fault_user/format
grep -c "struct trace_event_raw_exceptions {" ../../vmlinux.h         # 1 = ชื่อใหม่, 0 = ลองหา x86_exceptions
```

### ขั้นตอนที่ 3: รัน Watcher
```bash
sudo ./bin/oom-watcher                   # กด Ctrl+C เพื่อหยุด
sudo ./bin/oom-watcher -duration 10s     # หรือหยุดเองอัตโนมัติ
```

### ขั้นตอนที่ 4: กระตุ้น OOM อย่างปลอดภัยใน cgroup ที่จำกัดแรม (อีกเทอร์มินัล)
```bash
systemd-run --user --scope -p MemoryMax=50M -p MemorySwapMax=0 python3 -c '
blocks = []
for i in range(200):              # safety cap: never more than ~200 MB
    blocks.append(b"\x01" * (1 << 20))
print("allocated", len(blocks), "MB without OOM?!")
'
echo "exit status: $?"            # 137 = 128 + 9 (SIGKILL)
```

คำอธิบายพารามิเตอร์:
- `--user --scope`: สร้าง transient scope ใต้ `user@<uid>.service` ของผู้ใช้เอง (ไม่ต้องใช้ root) ต้องการให้ systemd delegate memory controller ให้ user manager (ตรวจด้วย `cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers` ต้องมีคำว่า `memory`) — ถ้าไม่มี ให้ใช้ `sudo systemd-run --scope ...` แทน
- `MemoryMax=50M`: ตั้ง `memory.max` ของ scope — OOM จะเกิด **เฉพาะใน scope นี้** ไม่กระทบโปรเซสอื่นของเครื่อง
- `MemorySwapMax=0`: **สำคัญมาก** บนเครื่องที่มี swap ถ้าไม่ตั้ง หน้าแรมจะถูก swap ออกแทนที่จะ OOM (ช้าและอาจไม่ถึง OOM เลย)
- `b"\x01" * (1 << 20)`: สร้างข้อมูล 1 MiB ที่ **ถูกเขียนจริง** (ต่างจาก `bytearray(n)` ที่อาจได้หน้าศูนย์จาก `calloc`/`mmap` ซึ่งยังไม่ถูกแตะ จึงไม่เพิ่ม RSS)
- `range(200)`: เพดานความปลอดภัย ถ้า limit ไม่ทำงาน โปรแกรมจะจบเองที่ ~200 MB

> [!WARNING]
> ห้ามทดลอง OOM ระดับทั้งเครื่อง (เช่น `stress-ng --vm` โดยไม่จำกัด cgroup) บนเครื่องที่ใช้งานจริง OOM killer อาจเลือกฆ่า process สำคัญ (เช่น desktop session, database) แทนโปรแกรมทดสอบ

### ขั้นตอนที่ 5: เทียบกับ Kernel Log
```bash
journalctl -k --since "-1min" | grep -i "Killed process"
```
ค่า `total-vm`, `anon-rss`, `UID`, `pgtables` ใน log ควรใกล้เคียงกับที่ watcher รายงาน

### ขั้นตอนที่ 6: ตรวจสอบด้วย `bpftool`
```bash
sudo bpftool prog show name on_oom_mark_victim
sudo bpftool map dump name page_fault_coun | head      # ชื่อแมปถูกตัดเหลือ 15 ตัวอักษร
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`, 8 CPUs, RAM 15 GB, swap 4 GB) — เครื่องทดสอบมีงานพื้นหลังอื่นทำงานอยู่ด้วย จึงเห็นโปรเซสอย่าง `sleep`, `bash`, `bpftrace` ในอันดับ page fault

### 4.1 เทอร์มินัลที่กระตุ้น OOM
```text
Running as unit: run-p4124218-i4141391.scope; invocation ID: fc9f230a0b7c4cf78984dfe9a1e686b5
/bin/bash: line 6: 4124218 Killed                     systemd-run --user --scope -p MemoryMax=50M -p MemorySwapMax=0 python3 -c '
blocks = []
for i in range(200):              # safety cap: never more than ~200 MB
    blocks.append(b"\x01" * (1 << 20))
print("allocated", len(blocks), "MB without OOM?!")
'
exit status: 137
```

### 4.2 ผลลัพธ์ของ `sudo ./bin/oom-watcher -duration 5s`
```text
======================================================================
 eBPF Memory Subsystem & OOM Forensics Watcher
======================================================================
2026/10/28 22:08:01 [INFO] Watching for User Page Faults and OOM Killer events...


[CRITICAL OOM KILLER TRIGGERED] 22:08:03
  • Victim Process : python3 (PID: 4124218, UID: 1000)
  • Triggered by   : python3 (PID: 4124218)
  • Cgroup (v2)    : run-p4124218-i4141391.scope (id 241936)
  • Cgroup path    : (already removed - transient scope exited with its last process)
  • Total VM Size  : 69608 kB (67.98 MB)
  • Anonymous RSS  : 50944 kB (49.75 MB)
  • File RSS       : 6736 kB (6.58 MB)
  • Shmem RSS      : 0 kB (0.00 MB)
  • Page Tables    : 172 kB (0.17 MB)
  • oom_score_adj  : 0

[22:08:04] Top Processes by User-Space Page Faults (cumulative):
   #1 sleep            : 223665   page faults (156929 on write)
   #2 bash             : 29153    page faults (21820 on write)
   #3 bpftrace         : 25910    page faults (23953 on write)
   #4 python3          : 12873    page faults (12736 on write)
   #5 date             : 10520    page faults (7921 on write)


[INFO] Detaching Memory Watcher...
```
(บรรทัดหัวข้อ `[CRITICAL OOM KILLER TRIGGERED]` แสดงเป็นตัวอักษรสีแดงด้วย ANSI escape code ในเทอร์มินัลจริง)

### 4.3 Kernel log ของเหตุการณ์เดียวกัน
```text
Oct 28 22:08:03 ce-desk kernel: Memory cgroup out of memory: Killed process 4124218 (python3) total-vm:69608kB, anon-rss:51000kB, file-rss:6860kB, shmem-rss:0kB, UID:1000 pgtables:172kB oom_score_adj:0
```

### 4.4 การตีความผลลัพธ์
- **OOM เกิดในขอบเขต cgroup เท่านั้น:** `Memory cgroup out of memory` และชื่อ scope `run-p4124218-i4141391.scope` ตรงกับที่ `systemd-run` สร้าง — ไม่มีโปรเซสอื่นของเครื่องถูกฆ่า
- **ค่าจาก eBPF ตรงกับ kernel log:** `total-vm` (69608 kB), `UID` (1000), `pgtables` (172 kB), `oom_score_adj` (0) ตรงกันทุกตัว ส่วน `anon-rss`/`file-rss` ต่างกันเล็กน้อย (50944 vs 51000 kB) เพราะเคอร์เนลอ่านค่าเพื่อพิมพ์ log **หลังจาก** จุด `mark_victim` และตัวนับ RSS ของ `mm` เป็นตัวนับแบบ per-CPU ที่ค่าอ่านได้เป็นค่าประมาณ ณ ขณะนั้น
- **Anonymous RSS ≈ 50 MB = `MemoryMax`:** python ถูกฆ่าตอนข้อมูลที่เขียนเต็ม limit พอดี
- **page fault ของ `python3` = 12873** ใกล้กับค่าที่คำนวณไว้ในหัวข้อ 1.1 (50 MiB / 4 KiB = 12800) และเกือบทั้งหมดเป็น fault จากการเขียน (12736) ตรงกับพฤติกรรมของโปรแกรมที่เขียนข้อมูลลงหน่วยความจำใหม่
- **Cgroup path หาไม่เจอ แต่ชื่อยังอยู่:** scope ถูกลบไปแล้วก่อนที่ Go จะเดินหา inode — นี่คือเหตุผลที่เราอ่าน `kn->name` ตั้งแต่ในเคอร์เนล (เวอร์ชันแรกที่เราทดลองแสดงแค่ cgroup id ที่หา path ไม่ได้)
- อันดับ 1-3 (`sleep`, `bash`, `bpftrace`) มาจากงานอื่นบนเครื่องทดสอบ ตัวเลขบนเครื่องของคุณจะแตกต่างไป

---

## 5. ข้อจำกัด (Limitations)

- **`exceptions:page_fault_user` มีเฉพาะ x86:** บน arm64 ต้องใช้ทางอื่น เช่น software perf event `PERF_COUNT_SW_PAGE_FAULTS` (แบบเดียวกับ Week 18) หรือ `fentry/handle_mm_fault`
- **Page fault ≠ การใช้หน่วยความจำ:** fault จากไฟล์ที่อยู่ใน page cache แล้ว (minor fault), CoW หลัง `fork()` หรือหน้าที่ถูก swap กลับเข้ามา ล้วนนับเป็น fault เหมือนกัน และการใช้ Huge Pages (THP) ทำให้หนึ่ง fault ได้หน้า 2 MiB จึงนับได้น้อยกว่าที่คาด
- **Key เป็น `comm`:** โปรเซสคนละตัวที่ชื่อเหมือนกันถูกรวมกัน, ชื่อยาวเกิน 15 ตัวอักษรถูกตัด และแมปจำกัด 1024 ชื่อ (ชื่อใหม่ที่เกินจะไม่ถูกนับ)
- **Overhead:** page fault เกิดบ่อยมากบนเครื่องที่ยุ่ง การเปิด tracepoint นี้ตลอดเวลาใน production มีต้นทุน ควรวัดผลกระทบก่อนใช้งานจริง
- **ได้ข้อมูล ณ จุดเลือกเหยื่อเท่านั้น:** ไม่รู้ว่าหน่วยความจำโตขึ้นมาอย่างไร (ต้องเก็บ time series ของ RSS/`memory.current` แยก) และไม่ครอบคลุมการฆ่าโดย userspace OOM daemon เช่น `systemd-oomd` ซึ่งส่ง `SIGKILL` เองโดยไม่ผ่าน `mark_victim`
- **Cgroup ที่บันทึกคือของผู้กระตุ้น** ไม่ใช่ของเหยื่อเสมอไป (ในกรณีทั่วไปอยู่ cgroup เดียวกัน แต่ global OOM อาจต่างกัน)
- **ฟิลด์ขยายของ `mark_victim` อาจไม่มีบนเคอร์เนลรุ่นเก่า:** โปรแกรมยังโหลดได้แต่จะแสดง `n/a` สำหรับขนาดหน่วยความจำ

---

## 6. Milestone Checklist

- [x] อธิบาย Demand Paging และความสัมพันธ์ระหว่าง `total_vm`, RSS และ page fault
- [x] อธิบายขั้นตอนของ OOM killer, `oom_score_adj` และความต่างระหว่าง global OOM กับ memory cgroup OOM
- [x] แยก "เหยื่อ" ออกจาก "ผู้กระตุ้น" ใน context ของ `mark_victim`
- [x] ใช้ `struct trace_event_raw_*` จาก `vmlinux.h` แทน struct ที่เขียนเอง
- [x] ใช้ `bpf_core_field_exists()` และ type flavors (`___old/___new`) + `bpf_core_type_exists()` รองรับหลายเวอร์ชันเคอร์เนล
- [x] ถอดรหัสฟิลด์ `__data_loc` ของ tracepoint
- [x] อ่านชื่อ cgroup ด้วย `BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name)`
- [x] กระตุ้น OOM อย่างปลอดภัยใน transient scope (`MemoryMax` + `MemorySwapMax=0`) และยืนยันผลกับ kernel log

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **ทดลอง `oom_score_adj`:** รันโปรเซส 2 ตัวใน scope เดียวกัน (เช่นใช้ `bash -c 'python3 hog.py & python3 hog.py; wait'`) โดยตั้ง `echo 1000 > /proc/self/oom_score_adj` ให้ตัวหนึ่งก่อนเริ่มจองแรม
   - *Deliverable:* output ของ watcher และคำอธิบายว่าทำไมเหยื่อคือตัวนั้น
   - *Verification:* `oom_score_adj : 1000` ต้องปรากฏใน alert และ PID ตรงกับตัวที่ตั้งค่า
2. **ตัวกรองชื่อโปรเซส:** เพิ่ม flag `-comm <name>` ให้แสดงเฉพาะบรรทัด page fault ของชื่อนั้น
   - *Deliverable:* โค้ด `main.go` ที่แก้ไข
   - *Verification:* รัน `-comm python3` ระหว่างขั้นตอนที่ 4 แล้วต้องเห็นเฉพาะ `python3` และจำนวน fault ใกล้ 12,800

### ระดับปานกลาง
1. **แยกตาม PID และประเภท fault:** เปลี่ยน key เป็น `{tgid, comm}` และนับเพิ่มอีก 2 ช่อง: fault แบบ protection (`X86_PF_PROT`, bit 0) และ fault จาก instruction fetch (`X86_PF_INSTR`, bit 4)
   - *Deliverable:* โค้ด + ผลการรัน `python3` ที่ `fork()` แล้วลูกเขียนทับข้อมูลของพ่อ
   - *Verification:* ลูกต้องมี protection fault (Copy-on-Write) จำนวนมาก ขณะที่โปรเซสที่จองหน่วยความจำใหม่ล้วน ๆ มีน้อย
2. **Memory pressure ก่อนเกิด OOM:** เพิ่มการ hook `tracepoint/vmscan/mm_vmscan_memcg_reclaim_begin` (หรือ `..._end`) นับจำนวนครั้งที่ memcg พยายาม reclaim ต่อ cgroup id
   - *Deliverable:* โค้ด + ผลที่แสดงว่ามี reclaim เกิดขึ้นก่อน OOM ใน scope เดียวกัน
   - *Verification:* รันขั้นตอนที่ 4 โดยใช้ `MemoryHigh=40M MemoryMax=50M` แล้วจำนวน reclaim ต้องเพิ่มขึ้นก่อนเห็น OOM alert (ตรวจชื่อ tracepoint บนเครื่องด้วย `ls /sys/kernel/tracing/events/vmscan/` ก่อน)

### ระดับท้าทาย
1. **OOM Post-mortem Stack:** เมื่อเกิด `mark_victim` ให้เก็บ kernel stack ของผู้กระตุ้นด้วย `bpf_get_stack()` ลงใน alert เพื่อดูว่า OOM ถูกกระตุ้นจากเส้นทางใด (page fault, `mmap`, การอ่านไฟล์ ฯลฯ)
   - *Deliverable:* โค้ด + stack ที่ symbolize แล้ว (ใช้ kallsyms resolver จาก Week 18)
   - *Verification:* สำหรับ workload ในขั้นตอนที่ 4 stack ควรผ่าน `exc_page_fault` -> `handle_mm_fault` -> ... -> `mem_cgroup_out_of_memory` (ชื่อฟังก์ชันอาจต่างตามเวอร์ชันเคอร์เนล ให้รายงานตามที่เห็นจริง)
2. **Prometheus Exporter:** ต่อยอดจาก Week 11 เปิด endpoint `/metrics` ที่มี `oom_kills_total{cgroup,comm}` และ `page_faults_total{comm,kind}`
   - *Deliverable:* โค้ด + ภาพ query ใน Prometheus/Grafana หรือ output ของ `curl localhost:<port>/metrics`
   - *Verification:* รันขั้นตอนที่ 4 สามครั้ง ค่า `oom_kills_total` ของ cgroup ที่มีชื่อขึ้นต้นด้วย `run-` ต้องเพิ่มขึ้นรวม 3 (แต่ละครั้ง scope ใหม่จะได้ชื่อใหม่)
