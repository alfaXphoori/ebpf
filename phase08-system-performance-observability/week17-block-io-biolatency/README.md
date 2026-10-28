# Week 17: Block I/O Latency Histogram ด้วย CO-RE biolatency (tp_btf)

ยินดีต้อนรับสู่สัปดาห์ที่ 17 ของหลักสูตร **eBPF: Zero-to-Hero** และเป็นสัปดาห์แรกของ **Phase 8: System Performance Observability** ในระบบฐานข้อมูลและระบบจัดเก็บข้อมูล ปัญหา "ค่าเฉลี่ยดูดี แต่ผู้ใช้บ่นว่าช้า" มักมาจาก **Tail Latency** ของดิสก์ — คำสั่ง I/O ส่วนน้อยที่ช้ากว่าปกติหลายสิบเท่า ซึ่งค่าเฉลี่ยจาก `iostat` มองไม่เห็น

ในบทนี้เราจะสร้างเครื่องมือ **`biolatency`** ฉบับ CO-RE ของเราเอง (แนวคิดเดียวกับ `biolatency` ใน BCC/libbpf-tools) ที่:
1. จับเวลาตั้งแต่ Request ถูกส่งให้ไดรเวอร์ (`block_rq_issue`) จนฮาร์ดแวร์ตอบกลับ (`block_rq_complete`)
2. ใช้ **`tp_btf` (BTF-enabled tracepoint)** เพื่อได้พอยน์เตอร์ `struct request *` ตัวจริงมาเป็น Key จับคู่ issue/complete อย่างแม่นยำ
3. สรุปผลเป็น **Power-of-two (log2) Histogram** หน่วยไมโครวินาที แยกตาม **ดิสก์** และ **ประเภทคำสั่ง (READ / WRITE / OTHER)**
4. อ่านโครงสร้างเคอร์เนลผ่าน `vmlinux.h` + `BPF_CORE_READ` ทำให้ไบนารีเดียวรันได้บนหลายเวอร์ชันเคอร์เนล

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 เส้นทางของ Block I/O ใน Linux (blk-mq)

เมื่อแอปพลิเคชันเรียก `read()`/`write()` ข้อมูลไม่ได้วิ่งตรงไปที่ดิสก์ แต่ผ่านหลายชั้น:

```
+------------------------------------------------------------------------------+
|  Application:  read() / write() / fsync()                                    |
+-------------------------------------|----------------------------------------+
                                      v
+------------------------------------------------------------------------------+
|  VFS -> Page Cache (ถ้า Cache hit จะไม่เกิด Block I/O เลย!)                   |
|      -> Filesystem (ext4/xfs/btrfs) แปลง offset ของไฟล์ -> sector บนดิสก์     |
+-------------------------------------|----------------------------------------+
                                      v  struct bio
+------------------------------------------------------------------------------+
|  Block Layer (blk-mq)                                                        |
|    bio ถูกรวม/แบ่ง (merge/split ตาม max_sectors_kb) -> struct request          |
|                                                                              |
|    [block_rq_insert] -> I/O Scheduler queue (mq-deadline / none / bfq)       |
|                                      |                                       |
|    [block_rq_issue]  <---------------+  blk_mq_start_request()  (t0)         |
+-------------------------------------|----------------------------------------+
                                      v
+------------------------------------------------------------------------------+
|  Device Driver (nvme / ahci-scsi / virtio-blk) -> Hardware Queue -> Disk     |
+-------------------------------------|----------------------------------------+
                                      v  IRQ / completion
+------------------------------------------------------------------------------+
|    [block_rq_complete] <- blk_update_request()  (t1)                         |
|                                                                              |
|    latency = t1 - t0  => เวลาที่ Request อยู่ใน "ไดรเวอร์ + ฮาร์ดแวร์"          |
+------------------------------------------------------------------------------+
```

ข้อสังเกตสำคัญ:
- เครื่องมือนี้วัด **issue -> complete** (เรียกว่า *device latency*) ไม่รวมเวลาที่รออยู่ใน I/O Scheduler (insert -> issue) หากต้องการวัดรวมคิวด้วย ต้องจับเวลาที่ `block_rq_insert` แทน (เทียบกับ `biolatency -Q` ของ BCC) — เป็นแบบฝึกหัดท้ายบท
- I/O ที่อ่านจาก Page Cache **ไม่ผ่าน Block Layer** ดังนั้นการทดสอบต้องใช้ `O_DIRECT` (`iflag=direct`/`oflag=direct`) หรือ `fsync` เพื่อบังคับให้เกิด I/O จริง
- ไฟล์บน `tmpfs` (เช่น `/tmp` ของหลายดิสโทร) อยู่ในแรม จึง **ไม่เกิด Block I/O** — ต้องทดสอบบนไฟล์ที่อยู่บนดิสก์จริง

---

### 1.2 เลือก Hook: `tracepoint/` vs `tp_btf/` vs `fentry/`

| Hook | ctx ที่ได้ | ข้อดี | ข้อเสีย |
|---|---|---|---|
| `tracepoint/block/block_rq_issue` | สำเนาฟิลด์ตาม `format` (`dev`, `sector`, `nr_sector`, `rwbs` ...) | รองรับเคอร์เนลเก่ามาก, ABI ของ format ค่อนข้างนิ่ง | **ไม่ได้พอยน์เตอร์ `struct request`** ต้องจับคู่ด้วย (dev, sector) ซึ่งไม่แม่นยำ (ดู 1.3) |
| `tp_btf/block_rq_issue` | อาร์กิวเมนต์จริงของ `trace_block_rq_issue(struct request *rq)` | ได้ `rq` ตัวจริง อ่านฟิลด์ใดก็ได้ผ่าน BTF, overhead ต่ำ (raw tracepoint ไม่ต้อง copy ฟิลด์) | ต้องมี `CONFIG_DEBUG_INFO_BTF=y` (Ubuntu 24.04/26.04 เปิดไว้แล้ว) |
| `fentry/blk_mq_start_request` | อาร์กิวเมนต์ของฟังก์ชันเคอร์เนล | ยืดหยุ่นที่สุด | ฟังก์ชันภายในอาจถูก inline / เปลี่ยนชื่อ / เปลี่ยน signature ข้ามเวอร์ชัน (ไม่ใช่ ABI) |

เราเลือก **`tp_btf`** เพราะได้ทั้ง *ความเสถียรของ tracepoint* (จุด hook ถูกประกาศโดยเจตนาในเคอร์เนล) และ *พอยน์เตอร์ตัวจริง* แบบ fentry ตรวจสอบ prototype ที่เคอร์เนลประกาศไว้ได้จาก BTF:

```bash
$ grep -n "btf_trace_block_rq_issue\|btf_trace_block_rq_complete)" vmlinux.h
typedef void (*btf_trace_block_rq_complete)(void *, struct request *, blk_status_t, unsigned int);
typedef void (*btf_trace_block_rq_issue)(void *, struct request *);
```

> [!NOTE]
> Prototype `block_rq_issue(struct request *rq)` แบบอาร์กิวเมนต์เดียวใช้มาตั้งแต่ราว Linux 5.11 (ก่อนหน้านั้นมี `struct request_queue *q` นำหน้า) จึงครอบคลุมทั้ง Ubuntu 24.04 (6.8) และ 26.04 (7.0) ที่หลักสูตรนี้รองรับ — ถ้าต้องใช้กับเคอร์เนลเก่ากว่านั้น ควรตรวจ typedef ข้างบนบนเครื่องเป้าหมายก่อน

---

### 1.3 ทำไม Key ต้องเป็น `struct request *` ไม่ใช่ (dev, sector)

เวอร์ชันแรกของแล็บนี้ใช้ `tracepoint/` แบบเดิมและจับคู่ด้วย `(dev, sector)` ซึ่งมีจุดอ่อนอย่างน้อย 3 ข้อ:
1. **คำสั่งที่ไม่มีข้อมูล (เช่น FLUSH)** ไม่มี sector ที่มีความหมาย (มักเป็น 0) — ถ้ามี FLUSH ค้างพร้อมกันหลายตัวบนดิสก์เดียวกัน key จะซ้ำกันและเขียนทับเวลาเริ่มต้นของกันและกัน
2. **Partial completion**: ไดรเวอร์บางตัวรายงาน `block_rq_complete` ทีละช่วง sector ของ request เดียว ช่วงหลัง ๆ จะมี sector ไม่ตรงกับตอน issue (จับคู่ไม่เจอ) ส่วนช่วงแรกจะจับคู่ได้และลบ entry ทิ้งก่อน request จะเสร็จจริง
3. **Stacked devices / remap** (dm, md, partition) อาจทำให้ dev/sector ในสองฝั่งอยู่คนละมุมมอง

ขณะที่ `struct request *` เป็น **ตัวตนเดียวกันตลอดอายุของ request** ตั้งแต่ issue จน complete (เคอร์เนลจะ reuse ที่อยู่นี้ได้ก็ต่อเมื่อ request เดิมจบไปแล้ว และเราลบ entry ทิ้งทันทีตอน complete) — นี่คือวิธีเดียวกับที่ `libbpf-tools/biolatency.bpf.c` ใช้

ผลการทดลองในหัวข้อ 4 ยืนยันการจับคู่: เราอ่าน `/dev/sda` แบบ O_DIRECT ไป **5000 บล็อก** และ Histogram ของ `sda READ` นับได้ **5000 requests พอดี**

---

### 1.4 Power-of-two Histogram และ log2 แบบ Branch-free

Latency ของดิสก์กระจายตัวกว้างมาก (ไม่กี่ µs สำหรับ NVMe cache hit ไปจนถึงหลายร้อย ms เมื่อดิสก์ติดขัด) การแบ่งช่องแบบ **ยกกำลังสอง** ทำให้ใช้เพียง 32 ช่องก็ครอบคลุมได้ถึง 2^31 µs และยังเห็น "หาง" ของการกระจายชัดเจน ช่องที่ `i` เก็บค่าในช่วง `[2^i, 2^(i+1) - 1]` (ช่อง 0 รวม 0 และ 1)

โค้ดเดิมใช้ลูป 31 รอบที่ถูก `#pragma unroll` ซึ่งทำให้ Bytecode ยาวและ Verifier ต้องไล่ทุกกิ่ง เราเปลี่ยนมาใช้เทคนิค **binary search บนบิต** แบบเดียวกับ `bits.bpf.h` ของ libbpf-tools:

```c
r = (v > 0xFFFF) << 4; v >>= r;                 // ครึ่งบนมีบิตไหม? ถ้ามี r += 16
shift = (v > 0xFF) << 3; v >>= shift; r |= shift; // ... r += 8
shift = (v > 0xF) << 2;  v >>= shift; r |= shift; // ... r += 4
shift = (v > 0x3) << 1;  v >>= shift; r |= shift; // ... r += 2
r |= (v >> 1);                                    // ... r += 1
```

ตัวอย่าง `v = 300` (0b1_0010_1100):
- `300 > 0xFFFF`? ไม่ → r = 0
- `300 > 0xFF`? ใช่ → shift 8, v = 1, r = 8
- `1 > 0xF`? ไม่, `1 > 0x3`? ไม่, `r |= 1 >> 1` = 8 → **log2(300) = 8** (ช่วง 256–511 ✓)

ทุกขั้นเป็นการเปรียบเทียบ + shift ไม่มี loop และไม่มี branch จึงเหลือคำสั่งเพียงไม่กี่สิบคำสั่ง (ค่า 64 บิตแบ่งเป็นครึ่งบน/ล่างใน `log2l()`)

> [!TIP]
> ทำไมไม่ใช้ `__builtin_clzll()`? BPF ISA ไม่มีคำสั่ง count-leading-zeros ในตัว คอมไพเลอร์จะต้องขยายเป็นชุดคำสั่งเองซึ่งแล้วแต่เวอร์ชัน clang การเขียนเทคนิคข้างบนเองจึงคาดเดาผลได้แน่นอนกว่า

---

### 1.5 CO-RE กับ `vmlinux.h`

แทนที่จะประกาศ struct ของ tracepoint เองด้วยมือ (ซึ่งพังทันทีเมื่อ layout เปลี่ยน) เรา `#include "vmlinux.h"` ที่สร้างจาก BTF ของเคอร์เนล (`scripts/setup_env.sh` สร้างไว้ที่รากของ repo) แล้วอ่านฟิลด์ผ่าน `BPF_CORE_READ()`:

```c
__u32 opf = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
hkey.dev  = MKDEV(BPF_CORE_READ(rq, q, disk, major),
                  BPF_CORE_READ(rq, q, disk, first_minor));
```

ตอนคอมไพล์ clang บันทึก **CO-RE relocation** ("ต้องการฟิลด์ `cmd_flags` ของ `struct request`") ไว้ใน ELF ตอนโหลด cilium/ebpf จะเทียบกับ BTF ของเคอร์เนลที่รันอยู่จริง แล้วแก้ offset ให้ถูกต้องอัตโนมัติ

ข้อควรระวัง: `vmlinux.h` มีแค่ **type และ enum** — ค่าที่เป็น `#define` ในเคอร์เนล (เช่น `REQ_OP_MASK`, `MINORBITS`) จะไม่อยู่ในนั้น ต้องประกาศเองในไฟล์ `.c` และห้าม include `<linux/*.h>` ปนกับ `vmlinux.h` เพราะ type จะชนกัน

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `biolatency.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
```
- **บรรทัด 4-7:** ใช้ `vmlinux.h` แทน `<linux/bpf.h>` (path มาจาก `-cflags "-I../../"` ใน `go:generate`) และ `bpf_core_read.h` สำหรับ `BPF_CORE_READ`

```c
#define REQ_OP_MASK ((1U << 8) - 1)
#define MINORBITS   20
#define MKDEV(ma, mi) (((__u32)(ma) << MINORBITS) | (__u32)(mi))
```
- **บรรทัด 13-15:** ค่าคงที่ที่ BTF ไม่มี: `cmd_flags` 8 บิตล่างคือ opcode (`REQ_OP_READ = 0`, `REQ_OP_WRITE = 1`, ... ซึ่งเป็น `enum req_op` จึงมีใน vmlinux.h) และสูตร `dev_t` ภายในเคอร์เนล (major 12 บิต, minor 20 บิต)

```c
struct hist_key {
    __u32 dev;
    __u32 op;
    __u32 slot;
};
```
- **บรรทัด 27-31:** Key ของ Histogram เป็น 3 มิติ ทำให้แยกผลของ `nvme0n1` กับ `sda` และแยก READ/WRITE ได้ในแมปเดียว

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u64);
} start_times SEC(".maps");
```
- **บรรทัด 37-42:** เก็บ `rq pointer -> timestamp (ns)` ของ request ที่กำลัง in-flight; 16384 ช่องเพียงพอสำหรับ queue depth ของดิสก์ทั่วไป (NVMe หนึ่งตัวอาจมีหลาย hardware queue — ถ้าแมปเต็ม `bpf_map_update_elem` จะล้มเหลวและ request นั้นจะไม่ถูกนับ)

```c
static __always_inline __u32 log2_u32(__u32 v) { ... }
static __always_inline __u32 log2l(__u64 v)
{
    __u32 hi = v >> 32;
    if (hi)
        return log2_u32(hi) + 32;
    return log2_u32((__u32)v);
}
```
- **บรรทัด 70-89:** log2 แบบ branch-free ตามหัวข้อ 1.4 ค่า 64 บิตแบ่งเป็นครึ่งบน/ครึ่งล่าง

```c
SEC("tp_btf/block_rq_issue")
int BPF_PROG(trace_rq_issue, struct request *rq)
{
    __u64 key = (__u64)rq;
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
    return 0;
}
```
- **บรรทัด 95-103:** `SEC("tp_btf/<ชื่อ tracepoint>")` บอก loader ให้หา `btf_trace_block_rq_issue` ใน BTF; มาโคร `BPF_PROG()` แกะอาร์กิวเมนต์จาก `u64 ctx[]` ให้เป็นพารามิเตอร์ที่มี type จริง เราใช้ "ที่อยู่" ของ request เป็น key และ `BPF_ANY` เพื่อเขียนทับกรณี request ถูก requeue แล้ว issue ใหม่

```c
SEC("tp_btf/block_rq_complete")
int BPF_PROG(trace_rq_complete, struct request *rq, int error, unsigned int nr_bytes)
{
    __u64 key = (__u64)rq;
    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
    if (!start_ts) {
        return 0; /* Request เริ่มก่อนที่เราจะ Attach */
    }

    __u64 delta_us = (bpf_ktime_get_ns() - *start_ts) / 1000;
    bpf_map_delete_elem(&start_times, &key);
```
- **บรรทัด 105-115:** หา timestamp ด้วย pointer เดียวกัน ถ้าไม่เจอแปลว่า request ถูก issue ก่อนโปรแกรมเราจะ attach (ข้ามไป) คำนวณ latency เป็น µs แล้ว **ลบ entry ทันที** ป้องกันแมปรั่ว และป้องกันกรณี pointer ถูก reuse

```c
    __u32 opf = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
    struct hist_key hkey = {};
    hkey.op = opf == REQ_OP_READ ? OP_READ : (opf == REQ_OP_WRITE ? OP_WRITE : OP_OTHER);
    hkey.dev = MKDEV(BPF_CORE_READ(rq, q, disk, major),
                     BPF_CORE_READ(rq, q, disk, first_minor));
```
- **บรรทัด 118-122:** อ่าน `rq->cmd_flags` และไล่ pointer `rq->q->disk->major` ด้วย `BPF_CORE_READ` (แต่ละขั้นคือ `bpf_probe_read_kernel` ที่ offset ถูก relocate ตาม BTF) ถ้าไล่ไม่สำเร็จ (เช่น passthrough request ไม่มี disk) จะได้ 0

```c
    __u32 slot = log2l(delta_us);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
```
- **บรรทัด 124-126:** หา bucket และ clamp ไม่ให้เกิน 31 (Verifier ไม่ได้บังคับเพราะเป็น HASH key แต่ฝั่ง Go ใช้อาร์เรย์ 32 ช่อง)

```c
    __u64 *hist_val = bpf_map_lookup_elem(&io_latency_hist, &hkey);
    if (!hist_val) {
        __u64 zero = 0;
        bpf_map_update_elem(&io_latency_hist, &hkey, &zero, BPF_NOEXIST);
        hist_val = bpf_map_lookup_elem(&io_latency_hist, &hkey);
    }
    if (hist_val) {
        __sync_fetch_and_add(hist_val, 1);
    }
```
- **บรรทัด 134-141:** รูปแบบ **lookup-or-init** ที่ปลอดภัยต่อ race: ถ้าสอง CPU สร้าง bucket เดียวกันพร้อมกัน ตัวหนึ่งจะได้ `-EEXIST` แต่ทั้งคู่ lookup ซ้ำแล้ว `__sync_fetch_and_add` ได้ ไม่มี sample หาย (ต่างจากการ `update(..., &one)` ตรง ๆ ที่อาจเขียนทับกัน)

```c
    __u32 key_cnt = 0;
    __u64 *tot_cnt = bpf_map_lookup_elem(&io_totals, &key_cnt);
    if (tot_cnt) __sync_fetch_and_add(tot_cnt, 1);
```
- **บรรทัด 145-151:** ตัวนับสะสมจำนวน request และ latency รวม เพื่อให้ Go คำนวณค่าเฉลี่ยแบบ real-time

---

### 2.2 ไฟล์ `main.go`

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf biolatency.c
```
- **บรรทัด 6:** `-I../../` ทำให้ clang หา `vmlinux.h` ที่รากของ repo (แบบเดียวกับ Week 22-23)

```go
func devName(dev uint32) string {
	major, minor := dev>>20, dev&((1<<20)-1)
	path := fmt.Sprintf("/sys/dev/block/%d:%d/uevent", major, minor)
```
- **บรรทัด 35-48:** แปลง `dev_t` ภายในเคอร์เนลกลับเป็น major:minor แล้วอ่าน `DEVNAME=` จาก sysfs ได้ชื่อเช่น `nvme0n1`

```go
	tpIssue, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceRqIssue})
```
- **บรรทัด 108-119:** โปรแกรมชนิด `tp_btf` เป็น `BPF_PROG_TYPE_TRACING` (attach type `BPF_TRACE_RAW_TP`) จึงใช้ `link.AttachTracing` — ชื่อ tracepoint ถูกระบุไว้แล้วใน `SEC()` ไม่ต้องบอกซ้ำ (ต่างจาก `link.Tracepoint("block", "block_rq_issue", ...)` ของ tracepoint แบบเดิม)

```go
	iter := objs.IoLatencyHist.Iterate()
	for iter.Next(&key, &val) {
		id := histID{dev: key.Dev, op: key.Op}
		...
		hists[id][key.Slot] += val
	}
```
- **บรรทัด 159-207 (`printFinal`):** วนอ่าน HASH map ทั้งหมด (type `bpfHistKey` ถูกสร้างอัตโนมัติโดย bpf2go จาก `struct hist_key`) จัดกลุ่มตาม (ดิสก์, op) แล้วเรียง dev/op ก่อนพิมพ์

```go
	for i := 0; i <= last; i++ {
		low := uint64(1) << i
		high := (uint64(1) << (i + 1)) - 1
		if i == 0 {
			low = 0
		}
```
- **บรรทัด 50-87 (`renderHistogram`):** พิมพ์ทุกช่องตั้งแต่ 0 จนถึงช่องสุดท้ายที่มีข้อมูล (เวอร์ชันเดิมพิมพ์แค่ 30 ช่องและซ่อนช่องว่างกลาง ๆ ทำให้อ่านหางผิด) ความยาวแท่ง `*` เทียบสัดส่วนกับช่องที่มีค่ามากสุด (40 ตัวอักษร)

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: เตรียม `vmlinux.h` และคอมไพล์
```bash
# ถ้ายังไม่มี vmlinux.h ที่รากของ repo (scripts/setup_env.sh สร้างให้)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../../vmlinux.h

cd phase08-system-performance-observability/week17-block-io-biolatency
make all
```

### ขั้นตอนที่ 2: ตรวจว่าเคอร์เนลรองรับ tp_btf ของ block layer
```bash
ls /sys/kernel/btf/vmlinux                                   # ต้องมี (CONFIG_DEBUG_INFO_BTF=y)
grep -c "btf_trace_block_rq_issue" ../../vmlinux.h           # ต้องได้ >= 1
lsblk -e7 -o NAME,ROTA,MODEL                                 # ดูว่ามีดิสก์อะไรบ้าง
```

### ขั้นตอนที่ 3: รัน biolatency
```bash
sudo ./bin/biolatency                    # กด Ctrl+C เพื่อดู Histogram
sudo ./bin/biolatency -duration 10s      # หรือหยุดเองอัตโนมัติหลัง 10 วินาที
```

### ขั้นตอนที่ 4: สร้าง Disk I/O ที่รู้จำนวนแน่นอน (อีกเทอร์มินัล)
```bash
# (ก) อ่านดิสก์ดิบแบบ O_DIRECT 5000 บล็อก ขนาด 4 KiB -- อ่านอย่างเดียว ไม่เขียนลงดิสก์
#     Ubuntu 26.04: dd เริ่มต้นคือ uutils (Rust) ซึ่งบนเครื่องทดสอบคืน EINVAL กับ iflag=direct บน /dev/sda
#     จึงใช้ gnudd (GNU coreutils) แทน; Ubuntu 24.04 ใช้ dd ได้ตามปกติ
sudo gnudd if=/dev/sda of=/dev/null bs=4k count=5000 iflag=direct

# (ข) เขียนไฟล์ชั่วคราวบนดิสก์จริง (/var/tmp อยู่บน root fs; /tmp อาจเป็น tmpfs ซึ่งไม่เกิด Block I/O)
TMPF=$(mktemp -p /var/tmp biolat.XXXXXX)
dd if=/dev/zero of=$TMPF bs=1M count=64 oflag=direct conv=fsync
rm -f $TMPF
```

> [!WARNING]
> ใช้ `/dev/sdX` เป็น **`if=` (อินพุต) เท่านั้น** อย่าใส่อุปกรณ์ดิสก์เป็น `of=` เด็ดขาด เพราะจะเขียนทับข้อมูลทั้งดิสก์

### ขั้นตอนที่ 5: ตรวจสอบด้วย `bpftool`
```bash
sudo bpftool prog show name trace_rq_issue     # type ต้องเป็น "tracing"
sudo bpftool map dump name io_totals           # [0]=จำนวน request, [1]=latency รวม (us)
```

### ขั้นตอนที่ 6: เปรียบเทียบกับเครื่องมือมาตรฐาน (ถ้ามี)
```bash
sudo biolatency-bpfcc -D 10 1      # BCC (แพ็กเกจ bpfcc-tools) แยกตามดิสก์
iostat -x 1                         # ค่า r_await / w_await เป็นค่าเฉลี่ย (รวมเวลาในคิว)
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`, 8 CPUs), ดิสก์ `nvme0n1` = WDC WDS250G2B0C (NVMe, scheduler `none`), `sda` = WD Green 240GB (SATA SSD, scheduler `mq-deadline`)
>
> เครื่องทดสอบมีงานอื่นทำงานอยู่ด้วย (เช่น การคอมไพล์) จึงมี request พื้นหลังปนอยู่ในผล

### 4.1 Workload ที่ใช้ (รันระหว่าง biolatency ทำงาน)
```text
$ sudo gnudd if=/dev/sda of=/dev/null bs=4k count=5000 iflag=direct
20480000 bytes (20 MB, 20 MiB) copied, 0.841663 s, 24.3 MB/s
$ dd if=/dev/zero of=$TMPF bs=1M count=64 oflag=direct conv=fsync
67108864 bytes (67 MB, 64 MiB) copied, 0.0722628 s, 932 MB/s
```

### 4.2 ผลลัพธ์ของ `sudo ./bin/biolatency -duration 10s`
```text
======================================================================
 eBPF Block I/O Latency Analyzer (CO-RE biolatency)
======================================================================
2026/10/28 22:00:50 [INFO] Attached to 'tp_btf/block_rq_issue' & 'tp_btf/block_rq_complete'!
2026/10/28 22:00:50 [INFO] Tracing disk I/O requests. (Press Ctrl+C to stop and view histogram)

[22:00:53] Total I/O Ops: 5627   | Cumulative: 978053   us | Avg Latency: 173    us
[22:00:56] Total I/O Ops: 5632   | Cumulative: 979314   us | Avg Latency: 173    us
[22:00:59] Total I/O Ops: 5640   | Cumulative: 982925   us | Avg Latency: 174    us

[INFO] Detaching probes and generating final I/O latency histograms...

disk = sda (8:0), op = READ, requests = 5000
Latency (us)             : Count    Distribution
----------------------------------------------------------------------------
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 669      |******                                  |
       128 -> 255        : 4308     |****************************************|
       256 -> 511        : 8        |                                        |
       512 -> 1023       : 3        |                                        |
      1024 -> 2047       : 4        |                                        |
      2048 -> 4095       : 6        |                                        |
      4096 -> 8191       : 2        |                                        |
----------------------------------------------------------------------------

disk = sda (8:0), op = WRITE, requests = 8
Latency (us)             : Count    Distribution
----------------------------------------------------------------------------
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 5        |****************************************|
        64 -> 127        : 1        |********                                |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 1        |********                                |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 1        |********                                |
----------------------------------------------------------------------------

disk = sda (8:0), op = OTHER (flush/discard), requests = 4
Latency (us)             : Count    Distribution
----------------------------------------------------------------------------
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 2        |****************************************|
       256 -> 511        : 0        |                                        |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 1        |********************                    |
      2048 -> 4095       : 1        |********************                    |
----------------------------------------------------------------------------

disk = nvme0n1 (259:0), op = READ, requests = 19
Latency (us)             : Count    Distribution
----------------------------------------------------------------------------
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 5        |*********************************       |
       128 -> 255        : 4        |**************************              |
       256 -> 511        : 6        |****************************************|
       512 -> 1023       : 4        |**************************              |
----------------------------------------------------------------------------

disk = nvme0n1 (259:0), op = WRITE, requests = 725
Latency (us)             : Count    Distribution
----------------------------------------------------------------------------
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 1        |                                        |
        32 -> 63         : 92       |*************                           |
        64 -> 127        : 272      |****************************************|
       128 -> 255        : 124      |******************                      |
       256 -> 511        : 132      |*******************                     |
       512 -> 1023       : 89       |*************                           |
      1024 -> 2047       : 7        |*                                       |
      2048 -> 4095       : 1        |                                        |
      4096 -> 8191       : 7        |*                                       |
----------------------------------------------------------------------------

disk = nvme0n1 (259:0), op = OTHER (flush/discard), requests = 3
Latency (us)             : Count    Distribution
----------------------------------------------------------------------------
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 1        |****************************************|
       256 -> 511        : 1        |****************************************|
       512 -> 1023       : 1        |****************************************|
----------------------------------------------------------------------------
```

### 4.3 การตีความผลลัพธ์
- **`sda READ = 5000` ตรงกับ `count=5000` ของ gnudd พอดี** ยืนยันว่าการจับคู่ issue/complete ด้วย `struct request *` ไม่ตกหล่นและไม่นับซ้ำ (การอ่านแบบ O_DIRECT ขนาด 4 KiB หนึ่งครั้ง = หนึ่ง request)
- SATA SSD (`sda`) ตอบสนองการอ่าน 4 KiB ส่วนใหญ่ในช่วง 128–255 µs แต่มี **หาง** ไปถึงช่วง 4–8 ms อยู่ 2 ครั้ง — ถ้าดูแค่ค่าเฉลี่ย (~173 µs) จะไม่เห็นหางนี้เลย
- การเขียน 64 MiB ลง NVMe ด้วย `bs=1M` ถูกแบ่งเป็นหลาย request เพราะ `max_sectors_kb` ของ `nvme0n1` บนเครื่องนี้คือ 128 (64 MiB / 128 KiB = 512 request) ส่วนที่เกิน 512 ใน `WRITE = 725` คือ I/O พื้นหลังของระบบ (ตรวจค่าบนเครื่องคุณด้วย `cat /sys/block/nvme0n1/queue/max_sectors_kb`)
- `OTHER` คือ FLUSH ที่เกิดจาก `conv=fsync` และ journal ของ filesystem — กรณีนี้เองที่การจับคู่ด้วย (dev, sector) แบบเดิมเสี่ยงชนกัน
- ตัวเลขทั้งหมดขึ้นกับฮาร์ดแวร์ เฟิร์มแวร์ และโหลดขณะทดสอบ ใช้เปรียบเทียบ "รูปร่าง" ของการกระจาย ไม่ใช่ benchmark

---

## 5. ข้อจำกัด (Limitations)

- **วัดเฉพาะ issue -> complete:** ไม่รวมเวลาในคิวของ I/O Scheduler และไม่รวมเวลาที่แอปรอใน Page Cache/Filesystem (latency ที่แอปเห็นจริงอาจสูงกว่ามาก) ถ้าต้องการวัดฝั่งแอปให้ดู syscall latency หรือ `fentry` ของ VFS
- **ไม่รู้ว่าโปรเซสไหนเป็นเจ้าของ I/O:** ณ จุด complete (มักอยู่ใน IRQ/softirq) `current` ไม่ใช่โปรเซสที่สั่ง I/O; write-back ของ Page Cache ก็ถูกสั่งโดย kworker ไม่ใช่แอป ถ้าต้องการต้องเก็บ PID/comm ตั้งแต่ตอน insert/issue
- **Request ที่ issue ก่อน attach จะถูกข้าม** และ request ที่ค้างอยู่ตอน detach จะไม่ถูกนับ
- **Stacked devices (LVM/dm-crypt/mdraid):** request ถูกนับที่ดิสก์จริงชั้นล่าง (เช่น `nvme0n1`) ไม่ใช่ `dm-0` เพราะ dm แบบ bio-based ไม่ผ่าน blk-mq request
- **ต้องมี BTF ของเคอร์เนล** (`/sys/kernel/btf/vmlinux`) สำหรับ `tp_btf` และ CO-RE; เคอร์เนลที่ไม่มี BTF ต้องย้อนไปใช้ `tracepoint/` + (dev, sector) พร้อมยอมรับความไม่แม่นยำในหัวข้อ 1.3
- **`start_times` มีขนาดจำกัด (16384):** ระบบที่มี in-flight I/O สูงมาก (ดิสก์จำนวนมาก × queue depth สูง) อาจทำให้แมปเต็มและนับตกหล่นโดยไม่มีการแจ้งเตือน (ดูแบบฝึกหัด)
- **ความละเอียดของ Histogram:** แต่ละช่องกว้าง 2 เท่า จึงบอกได้แค่ช่วง ไม่ใช่ค่า percentile ที่แม่นยำ

---

## 6. Milestone Checklist

- [x] อธิบายเส้นทาง bio -> request -> driver -> completion ของ blk-mq และตำแหน่งของ `block_rq_insert/issue/complete`
- [x] เปรียบเทียบ `tracepoint/`, `tp_btf/`, `fentry/` และให้เหตุผลการเลือก `tp_btf`
- [x] อธิบายได้ว่าทำไม key แบบ (dev, sector) ไม่แม่นยำ และ `struct request *` แก้ปัญหาอย่างไร
- [x] เขียน log2 แบบ branch-free และคำนวณ bucket ด้วยมือได้
- [x] ใช้ `vmlinux.h` + `BPF_CORE_READ` และประกาศ `#define` ที่ BTF ไม่มีเอง
- [x] ใช้ lookup-or-init (`BPF_NOEXIST`) เพื่อนับแบบไม่สูญหายเมื่อมีหลาย CPU
- [x] Attach `tp_btf` ด้วย `link.AttachTracing` ใน cilium/ebpf
- [x] สร้าง Disk I/O ที่ควบคุมจำนวนได้ด้วย O_DIRECT และยืนยันจำนวน request ที่วัดได้

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **ทดลอง Page Cache:** รัน `dd if=$TMPF of=/dev/null bs=1M` สองครั้ง (ไม่ใส่ `iflag=direct`) บนไฟล์ขนาด 256 MiB ใน `/var/tmp`
   - *Deliverable:* ภาพ Histogram ของการอ่านครั้งแรกและครั้งที่สอง พร้อมคำอธิบาย
   - *Verification:* ครั้งที่สองควรแทบไม่มี READ request บนดิสก์นั้น (ข้อมูลอยู่ใน Page Cache แล้ว) ล้าง cache ด้วย `sync; echo 1 | sudo tee /proc/sys/vm/drop_caches` แล้วอ่านใหม่จะกลับมาเห็น request
2. **เพิ่ม flag `-disk`:** ให้ Go พิมพ์เฉพาะ Histogram ของดิสก์ที่ระบุชื่อ (เช่น `-disk sda`)
   - *Deliverable:* โค้ด `main.go` ที่แก้ไข
   - *Verification:* รัน `-disk sda` ระหว่าง workload ในขั้นตอนที่ 4 แล้วต้องไม่เห็นบรรทัด `disk = nvme0n1`

### ระดับปานกลาง
1. **วัดเวลาในคิว (Queue latency):** เพิ่มโปรแกรม `tp_btf/block_rq_insert` และเพิ่ม flag `-queued` ที่ให้เริ่มจับเวลาตอน insert แทน issue
   - *Deliverable:* `biolatency.c` + `main.go` ที่รองรับทั้งสองโหมด (ใช้ `const volatile` + `RewriteConstants` เลือกโหมด)
   - *Verification:* บนดิสก์ที่ใช้ `mq-deadline` (เช่น `sda` ในเครื่องทดสอบ) ภายใต้ I/O พร้อมกันหลายตัว (`fio --iodepth=32` หรือ `gnudd` หลาย process) ค่าในโหมด `-queued` ต้องมากกว่าหรือเท่ากับโหมดปกติ
2. **นับ Request ตกหล่น:** เพิ่ม PERCPU_ARRAY นับกรณี `bpf_map_update_elem(&start_times, ...)` ล้มเหลว และกรณี complete โดยไม่เจอ start
   - *Deliverable:* โค้ดและบรรทัดสรุปใหม่ตอนจบ เช่น `missed starts: N, unmatched completes: M`
   - *Verification:* ลด `max_entries` ของ `start_times` เหลือ 4 แล้วรัน workload แบบ parallel ต้องเห็น `missed starts > 0`

### ระดับท้าทาย
1. **Per-process attribution:** เก็บ `pid`/`comm` ของ task ตอน `block_rq_insert` (หรือ issue) ลงใน value ของ `start_times` แล้วสร้าง Histogram แยกตาม comm
   - *Deliverable:* โค้ด + บทวิเคราะห์ว่าทำไม I/O ส่วนหนึ่งถูกนับให้ `kworker/*` หรือ `jbd2/*` แทนแอปที่เขียนไฟล์
   - *Verification:* รัน `dd ... oflag=direct` (ควรเห็นเป็นของ `dd`) เทียบกับ `dd` แบบไม่ direct ตามด้วย `sync` (ควรเห็นเป็นของ kworker/flush)
2. **Fallback สำหรับเคอร์เนลที่ไม่มี BTF:** เขียนโปรแกรมชุดที่สองด้วย `SEC("tracepoint/block/block_rq_issue")` ใช้ `struct trace_event_raw_block_rq` (และ `trace_event_raw_block_rq_completion` สำหรับ complete) จับคู่ด้วย (dev, sector) แล้วรันคู่กับเวอร์ชัน tp_btf
   - *Deliverable:* ตารางเปรียบเทียบจำนวน request และจำนวนที่จับคู่ไม่ได้ของทั้งสองวิธีภายใต้ workload ที่มี `fsync` บ่อย ๆ
   - *Verification:* อธิบายความต่างที่พบโดยอ้างอิงหัวข้อ 1.3 (อย่าเดาตัวเลข — ใช้ผลที่วัดได้จริงบนเครื่องของคุณ)
