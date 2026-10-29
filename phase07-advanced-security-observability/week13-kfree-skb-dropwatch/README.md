# สัปดาห์ที่ 13: ตรวจจับและวิเคราะห์แพ็กเก็ตสูญหายในเคอร์เนลด้วย eBPF Dropwatch (kfree_skb)

ยินดีต้อนรับสู่ **Week 13** ของหลักสูตร eBPF Zero to Hero และเป็นสัปดาห์แรกของ **Phase 7: Advanced Security & Observability**
ในระบบเครือข่ายโปรดักชัน คำถามที่ตอบยากที่สุดข้อหนึ่งคือ **"แพ็กเก็ตหายไปไหน เคอร์เนลทิ้งมันที่ฟังก์ชันใด และด้วยเหตุผลอะไร?"** ตัวนับอย่าง `netstat -s` หรือ `ip -s link` บอกได้เพียงว่า "มีการดรอป" แต่ไม่บอกว่าดรอปที่ไหน

สัปดาห์นี้เราจะสร้างเครื่องมือ **Kernel Dropwatch** ด้วย eBPF แบบ **CO-RE (Compile Once – Run Everywhere)** ที่เกาะ Tracepoint `skb:kfree_skb` เพื่อดึง **`enum skb_drop_reason`** และตำแหน่งในโค้ดเคอร์เนล (`location`) ของทุกแพ็กเก็ตที่ถูกทิ้ง แล้วส่งขึ้น User Space ผ่าน BPF Ring Buffer โดยโค้ดชุดเดียวกันโหลดได้ทั้งบน Linux 6.8 (Ubuntu 24.04) และ Linux 7.0 (Ubuntu 26.04) แม้ layout ของ tracepoint จะต่างกัน

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 วงจรชีวิตของ `sk_buff` และจุดที่แพ็กเก็ต "ตาย"

ทุกแพ็กเก็ตในเคอร์เนลถูกแทนด้วย `struct sk_buff` (skb) เมื่อแพ็กเก็ตสิ้นสุดชีวิต เคอร์เนลจะคืนหน่วยความจำด้วยฟังก์ชันหนึ่งในสองกลุ่ม:

| ฟังก์ชัน | ความหมาย | Tracepoint |
|---|---|---|
| `consume_skb()` | แพ็กเก็ตถูกใช้งานสำเร็จ (เช่น ส่งถึง socket แล้ว) | `skb:consume_skb` |
| `kfree_skb()` / `kfree_skb_reason(skb, reason)` | แพ็กเก็ตถูก **ทิ้ง** ระหว่างทาง | `skb:kfree_skb` |

ตั้งแต่ราว Linux 5.17 เคอร์เนลเริ่มส่ง **เหตุผลการดรอป** (`enum skb_drop_reason`) ไปพร้อมกับ `kfree_skb_reason()` ทำให้เรารู้ได้ว่าแพ็กเก็ตถูกทิ้งเพราะไม่มี socket รอรับ (`NO_SOCKET`), checksum ผิด (`TCP_CSUM`), ถูก Netfilter ทิ้ง (`NETFILTER_DROP`) ฯลฯ

```
[ NIC / veth / lo ] --> [ ip_rcv ] --> [ Netfilter ] --> [ tcp_v4_rcv / __udp4_lib_rcv ] --> [ Socket ]
         |                  |                |                       |                            |
         | (ring full)      | (bad hdr)      | (DROP rule)           | (no listener)              | consume_skb()
         v                  v                v                       v                            v
   +--------------------------------------------------------------------------+         skb:consume_skb
   |      kfree_skb_reason(skb, SKB_DROP_REASON_xxx)                          |
   |        └──> tracepoint skb:kfree_skb  (skbaddr, location, rx_sk,         |
   |                                         protocol, reason)                |
   +-----------------------------------|--------------------------------------+
                                       v
                        [ eBPF: trace_kfree_skb (dropwatch.c) ]
                          |  1) อัปเดตตัวนับใน BPF_MAP_TYPE_HASH (ต่อ reason)
                          |  2) ส่ง event รายแพ็กเก็ตผ่าน BPF_MAP_TYPE_RINGBUF
                          v
                        [ Go Control Plane: แปลง reason ด้วย Kernel BTF,
                          แปลง location ด้วย /proc/kallsyms ]
```

### 1.2 `enum skb_drop_reason` ไม่ใช่ ABI ที่คงที่ และมี "subsystem" ซ่อนอยู่

ค่าตัวเลขของ `enum skb_drop_reason` อยู่ใน header ภายในเคอร์เนล (`include/net/dropreason-core.h`) **ไม่ใช่ UAPI** นักพัฒนาเคอร์เนลแทรก reason ใหม่เข้ากลาง enum ได้ในแต่ละรุ่น ตัวเลขเดียวกันจึงอาจหมายถึงคนละเหตุผลบนเคอร์เนลคนละเวอร์ชัน บนเครื่องทดลองนี้ (Linux 7.0) enum มีถึง 132 ค่า (ดูได้จาก `print fmt` ใน `/sys/kernel/tracing/events/skb/kfree_skb/format`)

ดังนั้นเวอร์ชันนี้ของแล็บ **เลิก hard-code ตาราง** และให้ Go อ่านชื่อจาก **Kernel BTF** (`/sys/kernel/btf/vmlinux`) ของเครื่องที่รันจริงด้วย `btf.LoadKernelSpec()` แทน

นอกจากนี้ 16 บิตบนของค่า reason ใช้ระบุ **subsystem** (`SKB_DROP_REASON_SUBSYS_SHIFT = 16`) เช่น `MAC80211_UNUSABLE` หรือ `OPENVSWITCH` ซึ่งมี enum ของตัวเองอยู่ใน BTF ของ kernel module นั้น ๆ ตัวอย่างจริง: README เวอร์ชันก่อนแสดง `REASON_65624` ซึ่งดูเหมือนค่าขยะ แต่ `65624 = 0x10058` คือ subsystem 1 (`MAC80211_UNUSABLE`) รหัส `0x58` ซึ่งเป็นการดรอปเฟรมของไดรเวอร์ Wi-Fi (mac80211) ตามปกติ เวอร์ชันนี้จึงแสดงเป็น `MAC80211_UNUSABLE/0x58`

### 1.3 Tracepoint context: ทำไมห้าม hand-roll struct

โปรแกรมชนิด `tracepoint` ได้รับ pointer ไปยัง buffer ที่เคอร์เนลจัด layout ตาม `TP_STRUCT__entry` ของ tracepoint นั้น เวอร์ชันเดิมของแล็บประกาศ struct เองดังนี้:

```c
struct kfree_skb_args {            /* hand-rolled: ผูกกับ layout ของ 7.0 เท่านั้น */
    unsigned short common_type; unsigned char common_flags;
    unsigned char common_preempt_count; int common_pid;
    void *skbaddr; void *location; void *rx_sk;
    unsigned short protocol; unsigned int reason;
};
```

ปัญหาคือ layout เปลี่ยนตามเวอร์ชันเคอร์เนล:

| ฟิลด์ | Linux 6.8 (Ubuntu 24.04) | Linux 7.0 (Ubuntu 26.04, วัดจริง) |
|---|---|---|
| `skbaddr` | offset 8 | offset 8 |
| `location` | offset 16 | offset 16 |
| `rx_sk` | **ไม่มี** | offset 24 |
| `protocol` | offset 24 | offset 32 |
| `reason` | offset 28 | offset 36 |

ฟิลด์ `rx_sk` ถูกเพิ่มเข้ามาในเคอร์เนลรุ่นหลัง 6.8 (ราว 6.11; ควรตรวจสอบกับประวัติ commit ของ `include/trace/events/skb.h` หากต้องการอ้างอิงเวอร์ชันที่แน่นอน) ถ้านำ struct ของ 7.0 ไปรันบน 6.8 โปรแกรมจะอ่าน `reason` จาก offset 36 ซึ่งเลยขอบข้อมูลจริง ได้ค่าขยะหรือถูก verifier ปฏิเสธ

> [!WARNING]
> บั๊กลักษณะเดียวกันเกิดขึ้นจริงใน Week 16 เวอร์ชันเดิม: struct ของ `sys_enter_bpf` ที่ประกาศเองวาง `cmd` ไว้ที่ offset 12 แต่เคอร์เนลวางไว้ที่ offset 16 ทำให้อ่านได้ 0 (`BPF_MAP_CREATE`) ทุกครั้ง บทเรียนคือ **อย่าเดา layout ให้ใช้ BTF**

### 1.4 CO-RE: `vmlinux.h` + `preserve_access_index` + `bpf_core_field_exists`

วิธีแก้แบบ CO-RE มี 3 ส่วน:

1. **`vmlinux.h`**: สร้างจาก BTF ของเคอร์เนลด้วย `bpftool btf dump file /sys/kernel/btf/vmlinux format c` (สคริปต์ `scripts/setup_env.sh` สร้างไว้ที่รากของ repo) ภายในมี `struct trace_event_raw_kfree_skb` ซึ่งคือ layout จริงของ tracepoint
2. **`preserve_access_index`**: `vmlinux.h` ครอบทุก struct ด้วย `#pragma clang attribute push (__attribute__((preserve_access_index)), ...)` ทำให้ clang บันทึก **CO-RE relocation** ("อ่านฟิลด์ชื่อ `reason` ของ struct ชื่อ `trace_event_raw_kfree_skb`") แทนการฝัง offset ตายตัว ตอนโหลด cilium/ebpf จะเทียบกับ Kernel BTF ของเครื่องปลายทางแล้วแก้ offset ในคำสั่ง BPF ให้ถูกต้อง
3. **`bpf_core_field_exists(ctx->rx_sk)`**: ถูกแทนด้วยค่าคงที่ 1 หรือ 0 ตอนโหลด หากเป็น 0 verifier จะตัดโค้ดในบล็อก `if` ทิ้งทั้งหมด (dead code elimination) โปรแกรมจึงโหลดผ่านบนเคอร์เนลที่ไม่มีฟิลด์นั้น

**การทดลองยืนยัน (ทำบนเครื่อง 7.0):** เราโหลด `bpf_bpfel.o` ชุดเดียวกันสองครั้ง ครั้งแรกใช้ Kernel BTF จริง ครั้งที่สองใช้ BTF ที่ดัดแปลงให้ `trace_event_raw_kfree_skb` มี layout แบบ 6.8 (ลบ `rx_sk`, `reason` อยู่ที่ 28) ผ่าน `ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: spec}}` แล้วอ่านคำสั่งที่ถูก relocate จริงจาก `prog.Info().Instructions()`:

```text
== Linux 7.0 BTF (real): loaded OK, 59 xlated insns; ctx(r1) loads:
   [1] LdXMemW dst: r1 src: r6 off: 36 imm: 0      <- reason
   [38] LdXMemH dst: r1 src: r6 off: 32 imm: 0     <- protocol
   [46] LdXMemDW dst: r2 src: r6 off: 24 imm: 0    <- rx_sk
== Simulated 6.8 layout (no rx_sk, reason@28): loaded OK, 52 xlated insns; ctx(r1) loads:
   [1] LdXMemW dst: r1 src: r6 off: 28 imm: 0      <- reason ถูกย้ายเป็น 28
   [38] LdXMemH dst: r1 src: r6 off: 24 imm: 0     <- protocol ถูกย้ายเป็น 24
                                                     (บล็อก rx_sk หายไป: 59 -> 52 คำสั่ง)
```

> [!NOTE]
> นี่คือการ **จำลอง** layout ของ 6.8 ด้วย BTF ที่ดัดแปลง ไม่ใช่การรันบนเคอร์เนล 6.8 จริง ผลยืนยันว่ากลไก relocation ทำงานถูกต้อง แต่ควรทดสอบบน Ubuntu 24.04 จริงอีกครั้ง (เช่นบน VM) ก่อนนำไปใช้งาน

### 1.5 PID/COMM ใน dropwatch "ไม่ใช่เจ้าของแพ็กเก็ตเสมอไป"

`bpf_get_current_pid_tgid()` และ `bpf_get_current_comm()` คืนค่าของ task ที่ **กำลังรันบน CPU ขณะที่ `kfree_skb` ถูกเรียก** ฝั่ง RX ส่วนใหญ่ประมวลผลใน **softirq (NET_RX)** ซึ่งอาจ "ยืม" context ของโปรเซสใดก็ได้ที่บังเอิญรันอยู่ (`swapper/N` เมื่อ CPU ว่าง, `ksoftirqd/N`, หรือโปรเซสที่ไม่เกี่ยวข้องเลย) ในผลลัพธ์จริงด้านล่างจะเห็น `avahi-daemon`, `kworker/3:0` ฯลฯ ดังนั้น:
- ใช้ `COMM` เป็น "เบาะแส" เท่านั้น ห้ามสรุปว่าโปรเซสนั้นเป็นต้นเหตุ
- กรณี `nc`/`python3` ในแล็บนี้ตรงกับผู้ส่ง เพราะบน loopback โดยทั่วไป softirq ฝั่งรับจะถูกประมวลผลต่อทันทีใน context ของโปรเซสผู้ส่ง (ตอน `local_bh_enable()` หลัง `loopback_xmit()`) แต่ไม่รับประกันเสมอไป
- หากต้องการเจ้าของจริง ให้ดูจาก `skb->sk` (ฝั่งส่ง) หรือ `rx_sk` (ฝั่งรับ, Linux รุ่นใหม่) แทน

### 1.6 ต้นทุนของการ trace ทุกแพ็กเก็ต

`kfree_skb` อาจถูกเรียกหลายพันครั้งต่อวินาที บนเครื่องทดลองที่มีแล็บอื่นรันพร้อมกัน เราวัดได้ **2,270 events ใน ~6 วินาที** (ส่วนใหญ่เป็น `NOT_SPECIFIED`) การส่งทุก event ขึ้น User Space ผ่าน Ring Buffer มีต้นทุนจริง แล็บนี้จึงเก็บ **ตัวนับรวมใน Hash Map ในเคอร์เนล** คู่กันไป แนวปฏิบัติในโปรดักชันคือ aggregate ในเคอร์เนลเป็นหลัก แล้วส่งรายละเอียดเฉพาะ reason ที่สนใจ หรือสุ่มตัวอย่าง (sampling)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `dropwatch.c`

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
```
- **บรรทัด 13-16:** ใช้ `vmlinux.h` เพียงอย่างเดียว (ไม่ผสมกับ `<linux/*.h>` เพราะจะเกิด type ซ้ำซ้อน) ไฟล์นี้อยู่ที่รากของ repo และ `main.go` ส่ง `-cflags "-I../../"` ให้ clang หาเจอ

```c
#define DROP_REASON_FIRST_REAL_DROP 2
```
- **บรรทัด 23:** reason 0 = `NOT_DROPPED_YET`, 1 = `SKB_CONSUMED` ไม่ใช่การดรอปผิดปกติ ค่าตั้งแต่ 2 (`NOT_SPECIFIED`) ขึ้นไปจึงนับ

```c
struct drop_event {
    __u64 location;
    __u32 pid;
    __u32 reason;
    __u16 protocol;
    __u8 has_rx_sk;
    __u8 rx_sk_set;
    char comm[TASK_COMM_LEN];
    __u8 pad[4];
};
```
- **บรรทัด 29-38:** event ขนาด 48 ไบต์ เรียงฟิลด์ 8 ไบต์ไว้ก่อนและเติม `pad` เองเพื่อ **ไม่ให้มี implicit padding** ฝั่ง Go (`dropEvent`) จึง decode ด้วย `binary.Read` ได้ตรงทุกไบต์

```c
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } drop_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
         __type(key, __u32); __type(value, __u64); } drop_reason_stats SEC(".maps");
```
- **บรรทัด 43-56:** Ring Buffer ขนาด 4MB สำหรับ event รายแพ็กเก็ต และ Hash Map สำหรับนับสะสมต่อ reason

```c
SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    __u32 reason = ctx->reason;
```
- **บรรทัด 63-66:** ชนิดของ `ctx` มาจาก `vmlinux.h` การอ่าน `ctx->reason` ถูกคอมไพล์เป็น CO-RE relocation (ดูข้อ 1.4)

```c
    __u64 *count = bpf_map_lookup_elem(&drop_reason_stats, &reason);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&drop_reason_stats, &reason, &init_val, BPF_NOEXIST);
    }
```
- **บรรทัด 74-80:** นับแบบ atomic ถ้ายังไม่มี key ให้สร้างด้วย `BPF_NOEXIST` (หาก CPU อื่นสร้างตัดหน้าไปแล้ว การ update จะล้มเหลวแทนการเขียนทับ ทำให้เสีย count ได้สูงสุด 1 ครั้ง ซึ่งยอมรับได้)

```c
    struct drop_event *event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    ...
    event->location = (__u64)ctx->location;
    event->protocol = ctx->protocol;
```
- **บรรทัด 83-91:** จองพื้นที่ใน Ring Buffer แล้วเติมข้อมูล `protocol` ในเทรซพอยต์นี้เคอร์เนลเก็บเป็น `ntohs(skb->protocol)` แล้ว (host byte order) ฝั่ง Go จึงเทียบกับ `0x0800` ได้ตรง ๆ

```c
    if (bpf_core_field_exists(ctx->rx_sk)) {
        event->has_rx_sk = 1;
        event->rx_sk_set = ctx->rx_sk != NULL;
    }
```
- **บรรทัด 101-104:** CO-RE field existence: บน 6.8 บล็อกนี้ถูกตัดทิ้ง และคอลัมน์ `RX_SK` จะแสดง `n/a`

```c
    bpf_ringbuf_submit(event, 0);
```
- **บรรทัด 108:** ส่ง event ให้ User Space (ใช้ได้ทันทีโดยไม่ต้อง copy ซ้ำ)

### 2.2 ไฟล์ `main.go`

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf dropwatch.c
```
- **บรรทัด 6:** `-I../../` ชี้ไปยังรากของ repo ที่มี `vmlinux.h`

```go
func loadEnumNames(spec *btf.Spec, enumName, prefix string, out map[uint32]string) error {
	var enum *btf.Enum
	if err := spec.TypeByName(enumName, &enum); err != nil {
```
- **บรรทัด 57-66:** อ่าน `enum skb_drop_reason` และ `enum skb_drop_reason_subsys` จาก Kernel BTF แล้วตัด prefix `SKB_DROP_REASON_` ออก ได้ชื่อที่ตรงกับเคอร์เนลที่รันจริงเสมอ

```go
func getReasonStr(r uint32) string {
	subsys := r >> dropReasonSubsysShift
```
- **บรรทัด 68-82:** ถ้า 16 บิตบนไม่เป็น 0 จะแสดงเป็น `SUBSYS/0xCODE` (เช่น `MAC80211_UNUSABLE/0x58`)

```go
func loadKallsyms() []ksym { ... }
func resolveKsym(syms []ksym, pc uint64) string { ... }
```
- **บรรทัด 91-126:** โหลด `/proc/kallsyms` (ต้องเป็น root จึงเห็น address จริง) เรียงตาม address แล้ว binary search หา symbol ที่ใกล้ที่สุดซึ่งอยู่ก่อนหน้า `location` แปลง `0xffffffffadb3e73c` เป็น `tcp_v4_rcv+0x9c` เหมือน `%pS` ของเคอร์เนล

```go
	var tpStruct *btf.Struct
	if err := kernelBTF.TypeByName("trace_event_raw_kfree_skb", &tpStruct); err == nil {
```
- **บรรทัด 170-177:** พิมพ์ offset จริงของ `rx_sk`/`reason` จาก BTF เพื่อให้เห็นว่าเคอร์เนลนี้ใช้ layout ไหน (เพื่อการสอนเท่านั้น CO-RE ทำงานเองโดยไม่ต้องใช้โค้ดนี้)

```go
	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceKfreeSkb, nil)
	...
	rd, err := ringbuf.NewReader(objs.DropEvents)
```
- **บรรทัด 185-195:** attach tracepoint และเปิด reader ของ Ring Buffer

```go
		if *ipOnly && ev.Protocol != 0x0800 && ev.Protocol != 0x86DD {
			continue
		}
```
- **บรรทัด 228-233:** ตัวกรอง `-ip-only` / `-comm` ทำงานใน **User Space** (กรองเฉพาะการแสดงผล) ส่วนตัวนับใน map ยังนับทุกแพ็กเก็ต

```go
	iter := objs.DropReasonStats.Iterate()
	for iter.Next(&reason, &count) {
```
- **บรรทัด 261-264:** ตอนจบโปรแกรม dump สรุปจาก Hash Map ในเคอร์เนล

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: เตรียม `vmlinux.h` และคอมไพล์
```bash
# (ครั้งแรกครั้งเดียว) สร้าง vmlinux.h ที่รากของ repo
ls ../../vmlinux.h || sudo ../../scripts/setup_env.sh

cd phase07-advanced-security-observability/week13-kfree-skb-dropwatch
make all
```

### ขั้นตอนที่ 2: ดู layout จริงของ tracepoint ในเครื่องตัวเอง
```bash
sudo cat /sys/kernel/tracing/events/skb/kfree_skb/format | head -12
```
บน Linux 7.0 จะเห็น `field:void * rx_sk; offset:24` และ `field:enum skb_drop_reason reason; offset:36`

### ขั้นตอนที่ 3: รัน dropwatch (Terminal 1)
```bash
sudo ./bin/dropwatch -ip-only        # แสดงเฉพาะ IPv4/IPv6
# หรือ sudo ./bin/dropwatch -comm nc   # แสดงเฉพาะ event ที่ comm = nc
```

### ขั้นตอนที่ 4: สร้างการดรอปที่รู้สาเหตุแน่นอน (Terminal 2)
```bash
nc -z -w1 127.0.0.1 9999                 # TCP SYN ไปพอร์ตที่ไม่มีใครฟัง -> NO_SOCKET ที่ tcp_v4_rcv
echo hi | nc -u -w1 127.0.0.1 9998       # UDP ไปพอร์ตที่ไม่มีใครฟัง   -> NO_SOCKET ที่ __udp4_lib_rcv
python3 -c "import socket; s=socket.socket(socket.AF_INET6); s.connect(('::1', 9997))"  # -> NO_SOCKET ที่ tcp_v6_rcv
```
ทุกคำสั่งใช้ loopback เท่านั้น ไม่มีแพ็กเก็ตออกนอกเครื่อง

### ขั้นตอนที่ 5: ตรวจสอบโปรแกรมด้วย bpftool
```bash
sudo bpftool prog show name trace_kfree_skb
```

### ขั้นตอนที่ 6: หยุดโปรแกรม
กด `Ctrl+C` ใน Terminal 1 โปรแกรมจะพิมพ์สรุปจาก `drop_reason_stats` และ detach tracepoint อัตโนมัติ (link ถูกปิดเมื่อโปรเซสจบ)

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), clang 21, Go 1.26, cilium/ebpf v0.16.0
> บันทึกเมื่อ 2026-10-28 ขณะที่มีแล็บอื่นรันอยู่บนเครื่องเดียวกัน จึงมี event พื้นหลังปนอยู่

### 4.1 การคอมไพล์ (`make all`)
```text
===> Generating Go bindings from dropwatch.c via bpf2go...
go generate ./...
In file included from /mnt/sda/ebpf/phase07-advanced-security-observability/week13-kfree-skb-dropwatch/dropwatch.c:13:
5 warnings generated.
Compiled /mnt/sda/ebpf/phase07-advanced-security-observability/week13-kfree-skb-dropwatch/bpf_bpfel.o
Stripped /mnt/sda/ebpf/phase07-advanced-security-observability/week13-kfree-skb-dropwatch/bpf_bpfel.o
Wrote /mnt/sda/ebpf/phase07-advanced-security-observability/week13-kfree-skb-dropwatch/bpf_bpfel.go
...
===> Building userspace binary bin/dropwatch...
mkdir -p bin
go build -v -o bin/dropwatch .
```
> warning 5 รายการมาจาก `vmlinux.h` (`declaration does not declare anything`) เป็นเรื่องปกติของ header ที่ bpftool สร้าง ไม่กระทบการทำงาน

### 4.2 คำสั่งทดสอบ (Terminal 2)
```text
$ nc -z -w1 127.0.0.1 9999
exit=1
$ echo hi | nc -u -w1 127.0.0.1 9998
$ python3 -c "...connect(("::1", 9997))"
[Errno 111] Connection refused
```

### 4.3 ผลลัพธ์ dropwatch (`sudo ./bin/dropwatch -ip-only`)
```text
======================================================================
 eBPF Kernel Dropwatch & Packet Loss Diagnostics (kfree_skb)
======================================================================
2026/10/28 22:01:11 [INFO] Loaded 132 drop reason names from kernel BTF
2026/10/28 22:01:11 [INFO] Loaded 265374 kernel text symbols from /proc/kallsyms
2026/10/28 22:01:11 [CO-RE] trace_event_raw_kfree_skb.rx_sk  at byte offset 24
2026/10/28 22:01:11 [CO-RE] trace_event_raw_kfree_skb.reason at byte offset 36
2026/10/28 22:01:11 [INFO] Attached to 'skb:kfree_skb'! Monitoring dropped packets live...
TIME      PID     COMM             PROTO  DROP REASON                RX_SK DROP LOCATION     
-----------------------------------------------------------------------------------------------
22:01:13  4026949 nc               IPv4   NO_SOCKET                  no    tcp_v4_rcv+0x9c
22:01:13  4026951 nc               IPv4   NO_SOCKET                  no    __udp4_lib_rcv+0x4b1
22:01:13  4026952 python3          IPv6   NO_SOCKET                  no    tcp_v6_rcv+0x31a
22:01:13  4026141 dds.ev.0         IPv4   NOT_SPECIFIED              no    ip_rcv_finish_core+0x233
22:01:14  4026141 python3          IPv4   NOT_SPECIFIED              no    dst_discard+0x13
22:01:14  4026141 python3          IPv4   NOT_SPECIFIED              no    ip_rcv_finish_core+0x233
22:01:14  4026141 python3          IPv4   NOT_SPECIFIED              no    ip_rcv_finish_core+0x233
22:01:14  4026141 python3          IPv4   NOT_SPECIFIED              no    dst_discard+0x13
22:01:14  1844    avahi-daemon     IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361
22:01:14  55      ksoftirqd/5      IPv4   NOT_SPECIFIED              no    dst_discard+0x13
22:01:14  3873298 kworker/3:0      IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361
22:01:14  3873298 kworker/3:0      IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361
22:01:14  3295491 kworker/3:2      IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361
22:01:14  3784738 kworker/6:2      IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361
22:01:14  3873298 kworker/3:0      IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361
22:01:15  3534437 kworker/u32:1    IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361
(... ตัด event IPV6DISABLED พื้นหลังที่ซ้ำกันออก 11 บรรทัด ...)
22:01:17  1844    avahi-daemon     IPv6   IPV6DISABLED               no    ip6_rcv_core+0x361

[INFO] Received interrupt. Shutting down dropwatch...

========== Drop Summary ==========
Total Captured Dropped Packets: 2270 (ring buffer events, before display filters)
Per-reason totals from BPF hash map drop_reason_stats:
  - IPV6DISABLED               : 19 packets
  - QUEUE_PURGE                : 2 packets
  - NO_SOCKET                  : 3 packets
  - NOT_SPECIFIED              : 2246 packets
==================================
```

**วิเคราะห์ผล:**
- 3 บรรทัดแรกคือแพ็กเก็ตที่เราสร้างเอง ได้ `NO_SOCKET` ตรงตามคาด และ location ชี้ไปยังฟังก์ชันรับของแต่ละโปรโตคอล (`tcp_v4_rcv`, `__udp4_lib_rcv`, `tcp_v6_rcv`)
- PID `4026141` แสดงทั้ง `dds.ev.0` และ `python3` เพราะ `comm` เป็นค่า **ต่อเธรด** ขณะที่ PID ที่เราเก็บคือ TGID (ต่อโปรเซส)
- `Total 2270` แต่แสดงบนจอเพียงราว 30 บรรทัด เพราะ `-ip-only` ตัด event ที่ไม่ใช่ IP (เช่น netlink ที่เกิดจาก `udev-worker` ตอนแล็บอื่นสร้าง interface) ออกจากการแสดงผล แต่ Hash Map ยังนับครบ
- ใน run ก่อนหน้าที่ไม่ใส่ `-ip-only` บนเครื่องเดียวกัน พบ `MAC80211_UNUSABLE/0x58` จาก `swapper/7` (ไดรเวอร์ Wi-Fi) ซึ่งเป็นค่าที่ README เวอร์ชันเก่าแสดงเป็น `REASON_65624`

---

## 5. ข้อจำกัดและ Threat Model (Limitations)

| ข้อจำกัด | ผลกระทบ | แนวทางแก้/บรรเทา |
|---|---|---|
| ไม่ใช่ทุกจุดดรอปที่เรียก `kfree_skb_reason()` | ดรอปบางแบบ (เช่น `XDP_DROP`, การทิ้งในไดรเวอร์/ฮาร์ดแวร์, NIC ring เต็ม) **ไม่ผ่าน** tracepoint นี้ | ใช้ตัวนับ `ethtool -S`, `ip -s link`, และ trace XDP แยก |
| `NOT_SPECIFIED` มีสัดส่วนสูง | หลายเส้นทางในเคอร์เนลยังเรียก `kfree_skb()` แบบไม่มีเหตุผล | ใช้คอลัมน์ `DROP LOCATION` ประกอบการวิเคราะห์ |
| PID/COMM อาจไม่ใช่เจ้าของแพ็กเก็ต | วิเคราะห์ผิดว่าโปรเซสใดทำให้ดรอป (ข้อ 1.5) | ดู `skb->sk`, `rx_sk` หรือ 5-tuple จาก header ของแพ็กเก็ตแทน |
| Overhead ภายใต้ drop storm | ในช่วง DDoS อาจมีหลักแสน event/วินาที ring buffer เต็ม (event หาย) และกิน CPU | aggregate ในเคอร์เนล, กรอง reason ในเคอร์เนล, sampling |
| ตัวกรอง `-ip-only`/`-comm` อยู่ใน User Space | ทุก event ยังถูกส่งข้าม ring buffer | ย้ายตัวกรองไปไว้ในโปรแกรม eBPF (แบบฝึกหัด) |
| ต้องใช้สิทธิ์ root | `/proc/kallsyms` จะคืน address เป็น 0 ถ้าไม่ใช่ root และโหลด BPF ไม่ได้ | รันด้วย `sudo` หรือ capability `CAP_BPF`+`CAP_PERFMON`+`CAP_SYSLOG` |
| การยืนยัน 6.8 ในแล็บนี้เป็นการจำลองด้วย BTF | ยังไม่ได้รันบน 6.8 จริง | ทดสอบบน Ubuntu 24.04 VM |

ในมุม **Threat Model**: dropwatch เป็นเครื่องมือ observability ไม่ใช่กลไกป้องกัน ผู้ที่มี root สามารถ detach โปรแกรมหรือ flood drop event เพื่อกลบสัญญาณได้ ข้อมูลจึงเหมาะกับการ debug และ monitoring มากกว่าการเป็นหลักฐานด้านความปลอดภัย

---

## 6. Milestone Checklist

- [x] อธิบายความต่างของ `kfree_skb` กับ `consume_skb` และบทบาทของ `enum skb_drop_reason`
- [x] อ่าน format ของ tracepoint จาก `/sys/kernel/tracing/events/.../format` และเข้าใจว่า layout เปลี่ยนตามเวอร์ชันเคอร์เนล
- [x] แปลงโปรแกรม tracepoint ให้ใช้ `vmlinux.h` + `struct trace_event_raw_*` (CO-RE) แทน struct ที่ประกาศเอง
- [x] ใช้ `bpf_core_field_exists()` จัดการฟิลด์ที่มีเฉพาะบางเวอร์ชัน (`rx_sk`)
- [x] แปลงค่า enum เป็นชื่อด้วย Kernel BTF แทนตาราง hard-code และเข้าใจ subsystem bits
- [x] แปลง instruction pointer เป็นชื่อฟังก์ชันด้วย `/proc/kallsyms`
- [x] ใช้ Ring Buffer สำหรับ event และ Hash Map สำหรับสถิติรวมในเคอร์เนล
- [x] ตีความ PID/COMM ในบริบท softirq ได้อย่างระมัดระวัง

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **ดรอปด้วย Netfilter ใน namespace ทดลอง:** สร้าง network namespace (`sudo ip netns add w13`) ตั้ง `lo up` แล้วเพิ่มกฎ `nft`/`iptables` ให้ DROP พอร์ต 8080 **ภายใน namespace นั้นเท่านั้น** จากนั้นรัน `nc` ใน namespace เดียวกัน
   - *ส่งงาน:* ผลลัพธ์ dropwatch ที่มี reason `NETFILTER_DROP` พร้อมคอลัมน์ `DROP LOCATION`
   - *ตรวจ:* reason ต้องเป็น `NETFILTER_DROP` (ไม่ใช่ `NO_SOCKET`) และลบ namespace หลังทดลอง
2. **อ่าน layout เอง:** เขียนคำสั่ง `bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A8 'STRUCT .trace_event_raw_kfree_skb'` แล้วเทียบ offset กับไฟล์ `format`
   - *ส่งงาน:* ตาราง offset ของทุกฟิลด์จากทั้งสองแหล่ง
   - *ตรวจ:* offset ต้องตรงกันทุกฟิลด์

### ระดับปานกลาง
1. **ย้ายตัวกรองเข้าเคอร์เนล:** เพิ่ม `volatile const __u32 filter_reason` ใน `dropwatch.c` (ตั้งค่าจาก Go ด้วย `spec.RewriteConstants`) ให้ส่ง event ขึ้น ring buffer เฉพาะ reason ที่กำหนด แต่ยังนับทุก reason ใน map
   - *ส่งงาน:* โค้ด + ผลการรันที่ `Total Captured` ลดลงชัดเจนเมื่อเทียบกับไม่กรอง
   - *ตรวจ:* ยอดใน `drop_reason_stats` ยังเท่าเดิม (ไม่ได้ลดตามตัวกรอง)
2. **ดึง 5-tuple จาก skb:** ใช้ `BPF_CORE_READ` อ่าน `skb->head`, `skb->network_header` แล้วอ่าน IPv4 header ด้วย `bpf_probe_read_kernel` เพื่อแสดง src/dst IP และพอร์ต
   - *ส่งงาน:* คอลัมน์ `SRC -> DST` ในผลลัพธ์
   - *ตรวจ:* ทดสอบด้วย `nc -z 127.0.0.1 9999` แล้วต้องเห็น `127.0.0.1:xxxxx -> 127.0.0.1:9999`

### ระดับท้าทาย
1. **พิสูจน์ CO-RE ข้ามเวอร์ชันด้วยตัวเอง:** เขียนโปรแกรม Go ที่โหลด `bpf_bpfel.o` พร้อม `ebpf.ProgramOptions{KernelTypes: ...}` ที่ดัดแปลง `trace_event_raw_kfree_skb` ให้เป็น layout 6.8 (แบบในข้อ 1.4) แล้วพิมพ์คำสั่งที่ถูก relocate
   - *ส่งงาน:* โค้ดและผลลัพธ์ที่แสดง offset 36 -> 28
   - *ตรวจ:* จำนวนคำสั่งต้องลดลงเพราะบล็อก `rx_sk` ถูกตัดทิ้ง; คะแนนพิเศษถ้ารันบน Ubuntu 24.04 จริงได้
2. **เปลี่ยนไปใช้ `tp_btf/kfree_skb`:** เขียนโปรแกรมแบบ BTF-enabled tracepoint (`SEC("tp_btf/kfree_skb")` + `BPF_PROG(...)`) ซึ่งได้ argument ของฟังก์ชันโดยตรง (`struct sk_buff *skb, void *location, enum skb_drop_reason reason, ...`) แล้วเปรียบเทียบข้อดีข้อเสียกับ tracepoint แบบเดิม
   - *ส่งงาน:* โค้ด + ตารางเปรียบเทียบ (การเข้าถึง `skb` โดยตรง, ความเข้ากันได้ข้ามเวอร์ชันเมื่อ signature ของ tracepoint เปลี่ยน, overhead)
   - *ตรวจ:* ผลลัพธ์ของสองเวอร์ชันต้องได้ reason เดียวกันสำหรับแพ็กเก็ตทดสอบชุดเดียวกัน
