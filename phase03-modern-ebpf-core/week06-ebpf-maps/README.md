# Week 06: eBPF Maps & State Management (BPF_MAP_TYPE_HASH)

ยินดีต้อนรับสู่สัปดาห์ที่ 6 ของหลักสูตร **eBPF: Zero-to-Hero** สัปดาห์นี้เราจะเจาะลึกกลไกการจัดเก็บสถานะและการสื่อสารข้อมูลระหว่าง Kernel Space และ Userspace ผ่านโครงสร้างข้อมูลหลักของ eBPF นั่นคือ **BPF Maps** โดยมุ่งเน้นที่การใช้งาน `BPF_MAP_TYPE_HASH` เพื่อสร้างเครื่องมือมอนิเตอร์ระดับระบบ: **Syscall Top Monitor** ที่ตรวจจับความถี่การเรียกใช้งาน System Call ของทุกโปรเซสแบบเรียลไทม์

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 สถาปัตยกรรมภายในของ BPF_MAP_TYPE_HASH

`BPF_MAP_TYPE_HASH` เป็นตารางแฮช (Generic Hash Table) ในหน่วยความจำเคอร์เนลที่อนุญาตให้เก็บ Key-Value ที่มีความยาวตายตัว (Arbitrary fixed-size key and value) เหมาะอย่างยิ่งสำหรับกรณีที่คีย์เป็นค่าสุ่มหรือไม่เรียงลำดับ เช่น Process ID (PID), IP Address, หรือ File Descriptor

```
+-----------------------------------------------------------------------------------------+
|                                    LINUX KERNEL SPACE                                   |
|                                                                                         |
|  Tracepoint: raw_syscalls/sys_enter                                                     |
|  (Triggered on EVERY system call)                                                       |
|                     |                                                                   |
|                     v                                                                   |
|       Extract PID: bpf_get_current_pid_tgid() >> 32                                     |
|                     |                                                                   |
|                     +---------------------+                                             |
|                                           |                                             |
|                                           v                                             |
|                            [ Kernel Hash Function: jhash (Jenkins) ]                    |
|                                           |                                             |
|                                           v                                             |
|   BPF_MAP_TYPE_HASH: syscall_map (max_entries = 4096, buckets = 4096)                   |
|   +----------------------------------------------------------------------------------+  |
|   | Bucket 0   -> [ PID: 1042 | Count: 521 | Comm: "node" ]                          |  |
|   | Bucket 1   -> NULL                                                               |  |
|   | ...                                                                              |  |
|   | Bucket 58  -> [ PID: 1    | Count: 18  | Comm: "systemd" ] -> [ PID: 89 | ... ]  |  |
|   | ...                                                                              |  |
|   | Bucket 4095-> [ PID: 4521 | Count: 94  | Comm: "bash" ]                          |  |
|   +----------------------------------------------------------------------------------+  |
|                                           ^                                             |
+-------------------------------------------|---------------------------------------------+
                                            |
                         Syscall bpf(BPF_MAP_GET_NEXT_KEY)
                         Syscall bpf(BPF_MAP_LOOKUP_ELEM)
                                            |
+-------------------------------------------|---------------------------------------------+
|                                           v                                             |
|  USERSPACE (Golang Daemon):                                                             |
|                                                                                         |
|  objs.SyscallMap.Iterate()                                                              |
|        |                                                                                |
|        v                                                                                |
|  [ PID 1042, "node",    521 ]                                                           |
|  [ PID 4521, "bash",     94 ]                                                           |
|  [ PID 1,    "systemd",  18 ]                                                           |
|        |                                                                                |
|        v sort.Slice(descending by Count)                                                |
|  +-----------------------------------------------------------------------------------+  |
|  | #1  PID: 1042  COMM: node     SYSCALLS: 521   SHARE: 82.3%                        |  |
|  | #2  PID: 4521  COMM: bash     SYSCALLS: 94    SHARE: 14.8%                        |  |
|  | #3  PID: 1     COMM: systemd  SYSCALLS: 18    SHARE:  2.9%                        |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

#### คุณสมบัติสำคัญของ Hash Map ในเคอร์เนล:
1. **Pre-allocation vs On-demand:** ตามค่าเริ่มต้น เคอร์เนลจะ Pre-allocate หน่วยความจำสำหรับจำนวน Elements ทั้งหมด (`max_entries = 4096`) ทันทีที่ Map ถูกสร้างขึ้น เพื่อป้องกันปัญหาหน่วยความจำเคอร์เนลไม่พอตอนรันและลด Latency (หากต้องการประหยัดหน่วยความจำสามารถใส่ Flag `BPF_F_NO_PREALLOC`)
2. **Hash Collisions:** เคอร์เนลจัดการการชนกันของแฮช (Collision) ผ่าน Linked-list Chaining ภายในแต่ละ Bucket (ฟังก์ชันแฮชคือ `jhash` และจำนวน bucket = `max_entries` ปัดขึ้นเป็นเลขยกกำลัง 2)
4. **Map เต็มแล้วไม่ลบเอง:** `BPF_MAP_TYPE_HASH` ไม่มีการ evict อัตโนมัติ เมื่อครบ `max_entries` การ `bpf_map_update_elem()` ของ key ใหม่จะล้มเหลว (`-E2BIG`) — ถ้าต้องการให้ลบรายการเก่าที่ไม่ได้ใช้ออกเองให้ใช้ `BPF_MAP_TYPE_LRU_HASH`
3. **Atomic Updates:** การเข้าถึงสล็อตผ่าน `bpf_map_lookup_elem()` จะได้ Pointer ตรงไปยังสล็อตในหน่วยความจำเคอร์เนล เราจึงสามารถใช้ `__sync_fetch_and_add()` ได้ทันที

---

### 1.2 กฎการจัดวางหน่วยความจำและการเรียงตัว (Memory Layout & Struct Padding)

หนึ่งในสาเหตุยอดนิยมที่ทำให้โปรแกรม eBPF แสดงผลข้อมูลใน Userspace ผิดเพี้ยน คือ **Memory Padding และ Alignment ไม่ตรงกันระหว่างภาษา C และภาษา Go**

พิจารณาโครงสร้างข้อมูลของเรา:
```c
struct proc_stat {
    __u64 count;     // 8 bytes (Offset 0)
    __u8 comm[16];   // 16 bytes (Offset 8)
};
```
- ในสถาปัตยกรรม 64-bit ซีพียูต้องการให้ข้อมูลประเภท 64 บิต (`__u64`) เริ่มต้นที่ตำแหน่งหน่วยความจำที่หารด้วย 8 ลงตัว
- `count` ใช้ขนาด 8 ไบต์ (Offsets 0 ถึง 7)
- `comm` เป็นอาร์เรย์ของ char 16 ไบต์ (Offsets 8 ถึง 23)
- ขนาดรวมของ `struct proc_stat` คือ $8 + 16 = 24$ ไบต์ ซึ่งหารด้วย 8 ลงตัวพอดี จึงไม่มี Silent Padding ต่อท้าย
- ในฝั่ง Go เมื่อใช้ `bpf2go` โค้ด Go จะสร้าง Type `bpfProcStat`:
```go
type bpfProcStat struct {
    Count uint64
    Comm  [16]uint8 // __u8 -> uint8 (= byte) จึงใช้ bytes.TrimRight ได้ทันที
}
```
(ถ้าประกาศเป็น `char comm[16]` bpf2go จะสร้างเป็น `[16]int8` ซึ่งใช้กับแพ็กเกจ `bytes` ตรงๆ ไม่ได้ นี่คือเหตุผลที่โค้ดเลือก `__u8`)
ทำให้การถ่ายโอนข้อมูลผ่าน Syscall ไม่เกิดการบิดเบือนของ Memory Offset

---

### 1.3 กลไกการวนซ้ำ (Map Iteration) ใน Go ด้วย Cilium ebpf

ในระดับเคอร์เนล การอ่านข้อมูลทั้งหมดใน Hash Map ไม่สามารถทำได้ในการเรียก Syscall ครั้งเดียว เคอร์เนลอาศัยคำสั่ง:
1. `bpf(BPF_MAP_GET_NEXT_KEY)`: ส่ง Key ปัจจุบันเข้าไปเพื่อขอ Key ถัดไป
2. `bpf(BPF_MAP_LOOKUP_ELEM)`: ส่ง Key ถัดไปเพื่อดึง Value

ไลบรารี Cilium ebpf-go ห่อหุ้มกลไกนี้ไว้ใน Interface ที่สง่างามผ่าน `Map.Iterate()`:
```go
iter := objs.SyscallMap.Iterate()
for iter.Next(&pid, &stat) {
    // Process entry
}
if err := iter.Err(); err != nil {
    // Handle read error
}
```
ซึ่งจะทำการดึงข้อมูลทีละคู่ Key/Value อย่างมีประสิทธิภาพและปลอดภัย

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `syscall_stats.c`

```c
struct proc_stat {
    __u64 count;
    __u8 comm[16];
};
```
- **บรรทัด 29-32:** กำหนดโครงสร้างข้อมูลสำหรับเก็บสถิติของแต่ละโปรเซส:
  - `count`: จำนวนครั้งสะสมที่โปรเซสนี้เรียก System Call ใด ๆ
  - `comm[16]`: ชื่อโปรแกรมหรือคำสั่งที่รัน (ความยาวสูงสุดตามที่ Linux Kernel เก็บใน `TASK_COMM_LEN` คือ 16 ไบต์ รวม Null-terminator)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct proc_stat);
} syscall_map SEC(".maps");
```
- **บรรทัด 40-45:** ประกาศ Hash Map ชื่อ `syscall_map`
  - `type, BPF_MAP_TYPE_HASH`: กำหนดประเภทเป็น Hash Map
  - `max_entries, 4096`: จองพื้นที่สำหรับรองรับโปรเซสสูงสุด 4,096 ตัวพร้อมกัน
  - `key, __u32`: คีย์คือ PID (32-bit integer)
  - `value, struct proc_stat`: ค่าคือสถิติที่เรานิยามไว้

```c
SEC("tracepoint/raw_syscalls/sys_enter")
int track_syscalls(void *ctx)
```
- **บรรทัด 51-52:** แนบฟังก์ชัน `track_syscalls` เข้ากับ `raw_syscalls/sys_enter` ซึ่งเป็นจุดตัดที่เคอร์เนลรับคำขอ Syscall ทุกคำขอจากทุกโปรเซสในระบบ ก่อนจะกระจายไปยัง Handler เฉพาะของแต่ละ Syscall

```c
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
```
- **บรรทัด 56-57:** สกัดค่า PID ออกจาก 64-bit ID: 32 บิตบนคือ **TGID** (= Process ID ที่ `ps` แสดง) ส่วน 32 บิตล่างคือ Thread ID — การ shift ขวา 32 บิตจึงได้ Process ID และทำให้ทุก thread ของโปรเซสเดียวกันถูกนับรวมกัน

```c
    struct proc_stat *stat = bpf_map_lookup_elem(&syscall_map, &pid);
    if (stat) {
        __sync_fetch_and_add(&stat->count, 1);
        bpf_get_current_comm(&stat->comm, sizeof(stat->comm));
    } else {
        struct proc_stat init_stat = {};
        init_stat.count = 1;
        bpf_get_current_comm(&init_stat.comm, sizeof(init_stat.comm));
        bpf_map_update_elem(&syscall_map, &pid, &init_stat, BPF_ANY);
    }
```
- **บรรทัด 60-76:** การจัดการสถานะใน Map:
  - `bpf_map_lookup_elem`: ตรวจสอบว่าเคยบันทึก PID นี้ไว้ใน Map หรือยัง
  - **กรณีมีอยู่แล้ว (`if (stat)`):** ใช้ Atomic instruction `__sync_fetch_and_add(&stat->count, 1)` เพื่อเพิ่มตัวนับโดยตรงในเคอร์เนลเมมโมรี ไม่ต้องเขียนทับทั้งโครงสร้าง
  - **อัปเดต `comm` ทุกครั้ง (บั๊กที่แก้แล้ว)**: โปรเซสที่ถูก `fork()` จาก bash จะเริ่มเรียก syscall ตั้งแต่ก่อน `execve()` ขณะนั้น `comm` ยังเป็น `bash` ถ้าบันทึกชื่อเฉพาะครั้งแรก โปรแกรม `python3` ในขั้นตอนที่ 4 จะถูกแสดงเป็น `bash` ตลอด (ผลลัพธ์รุ่นเดิมในเอกสารนี้แสดงอาการนี้: แถวอันดับ 1 ที่เรียก ~50,000 syscalls ขึ้นชื่อ `bash`) การเรียก `bpf_get_current_comm()` ซ้ำมีต้นทุนต่ำมากแต่ทำให้ชื่อถูกต้องหลัง exec
  - **กรณีเพิ่งพบครั้งแรก (`else`):**
    - กำหนดค่าเริ่มต้น `count = 1`
    - เรียก `bpf_get_current_comm` เพื่อดึงชื่อโปรแกรมจากโครงสร้าง `task_struct` ของเคอร์เนล
    - เรียก `bpf_map_update_elem` ด้วย Flag `BPF_ANY` เพื่อแทรกข้อมูลคู่ใหม่เข้า Map
    - **ข้อสังเกตเรื่อง Race**: ถ้าสอง thread ของโปรเซสเดียวกันเข้ามาที่ `else` พร้อมกันบนคนละ CPU ทั้งคู่จะเขียน `count = 1` ทับกัน (นับหายไป 1) — แก้ได้ด้วย `BPF_NOEXIST` แล้ว lookup ซ้ำเมื่อ insert ไม่สำเร็จ (ดูแบบฝึกหัด)

---

### 2.2 ไฟล์ `main.go`

```go
type ProcessRecord struct {
	PID   uint32
	Comm  string
	Count uint64
}
```
- **บรรทัด 23-27:** Data Model สำหรับ Userspace ที่แปลง `Comm` จาก Byte Array ใน C ให้เป็น `string` ใน Go เพื่อง่ายต่อการจัดเรียงและพิมพ์ผล

```go
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TrackSyscalls, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to raw_syscalls/sys_enter: %v", err)
	}
	defer tp.Close()
```
- **บรรทัด 47-51:** เชื่อมต่อ eBPF bytecode เข้ากับ Tracepoint ในระบบเคอร์เนล

```go
func renderTopSyscalls(objs *bpfObjects) {
	var records []ProcessRecord
	var totalSyscalls uint64

	var pid uint32
	var stat bpfProcStat

	iter := objs.SyscallMap.Iterate()
	for iter.Next(&pid, &stat) {
		commStr := string(bytes.TrimRight(stat.Comm[:], "\x00"))
...
```
- **บรรทัด 79-106:**
  - สร้าง Iterator เพื่อวนลูปอ่านทุก Record จาก `objs.SyscallMap`
  - ใช้ `bytes.TrimRight(stat.Comm[:], "\x00")` เพื่อลบตัวอักษร Null Byte ใน C string ออก ทำให้ได้ข้อความที่ถูกต้องในภาษา Go
  - สะสมจำนวนผลรวม Syscall ทั้งหมดในตัวแปร `totalSyscalls`

```go
	sort.Slice(records, func(i, j int) bool {
		return records[i].Count > records[j].Count
	})
```
- **บรรทัด 109-111:** เรียงลำดับ Record จากโปรเซสที่เรียก Syscall มากที่สุดลงมาหาน้อยที่สุด

```go
	fmt.Printf("\033[H\033[2J") // Clear terminal screen
...
	for i := 0; i < maxDisplay; i++ {
		rec := records[i]
		share := (float64(rec.Count) / float64(totalSyscalls)) * 100.0
		fmt.Printf("#%-4d  %-8d  %-18s  %-16d  %6.2f%%\n",
			i+1, rec.PID, rec.Comm, rec.Count, share)
	}
```
- **บรรทัด 114-143:** ล้างหน้าจอและวาด CLI Dashboard ตาราง Top-10 พร้อมแสดงเปอร์เซ็นต์สัดส่วนการเรียกใช้งาน Syscall

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: สร้าง BPF Bindings
```bash
cd phase03-modern-ebpf-core/week06-ebpf-maps
make generate
```

### ขั้นตอนที่ 2: คอมไพล์โปรแกรม
```bash
make build
```

### ขั้นตอนที่ 3: สั่งรัน Syscall Top Monitor
```bash
make run
# หรือ: sudo ./bin/syscall-top
```

**ตัวอย่างหน้าจอผลลัพธ์ Dashboard** (ผลจริงขณะรันขั้นตอนที่ 4 พร้อมกัน; หน้าจอจะถูกล้างและวาดใหม่ทุก 2 วินาที):
```text
=================================================================================
 eBPF Syscall Monitor | Time: 22:29:26 | Total Invocations: 230233
=================================================================================
RANK   PID       COMM                SYSCALLS          SHARE (%)   
---------------------------------------------------------------------------------
#1     189550    python3             50412              21.90%
#2     190016    pgrep               5482                2.38%
#3     189933    pgrep               5482                2.38%
#4     189352    syscall-top         4259                1.85%
#5     3760745   mi-scavenger        4207                1.83%
#6     183726    bash                3686                1.60%
#7     183728    bash                3667                1.59%
#8     183724    bash                3667                1.59%
#9     183722    bash                3667                1.59%
#10    187858    python3             1726                0.75%
---------------------------------------------------------------------------------
 Tracking 1011 active processes in BPF_MAP_TYPE_HASH
```
> `Tracking N active processes` นับทุก PID ที่เคยเห็นตั้งแต่เริ่ม (รวมโปรเซสที่จบไปแล้ว เพราะไม่มีใครลบ key) บนเครื่องทดสอบที่มีงานอื่นรันอยู่ ตัวเลขนี้ขึ้นไปถึง ~1,000 ภายใน 5 วินาที — หมายความว่า map ขนาด 4,096 จะเต็มภายในไม่ถึงครึ่งนาที (ดู Troubleshooting)

### ขั้นตอนที่ 4: ทดสอบกระตุ้นโหลด Syscall ในเทอร์มินัลอื่น
รันโปรเซสที่เรียก Syscall ถี่ ๆ เช่น การอ่านไฟล์แบบวนลูป:
```bash
# เทอร์มินัล 2: กระตุ้นการอ่านเขียนไฟล์อย่างหนัก
python3 -c "
import os
for _ in range(50000):
    os.getpid()
"
```
จะสังเกตเห็นโปรเซส `python3` พุ่งขึ้นมาสู่อันดับต้น ๆ ของตาราง Top Syscall ภายใน 2 วินาทีทันที! (ราว 50,000+ syscalls จาก `getpid()` วนลูป — ถ้าเห็นชื่อเป็น `bash` แปลว่ายังใช้ `syscall_stats.c` รุ่นเก่าที่ไม่อัปเดต `comm`)

### ขั้นตอนที่ 5: ตรวจสอบ Map ด้วย `bpftool`
```bash
# ค้นหา Map ID ของ syscall_map
sudo bpftool map list name syscall_map

# Dump ข้อมูลดิบจากเคอร์เนล
sudo bpftool map dump name syscall_map
```
ผลจริง (ตัดบางส่วน) — `comm` ถูกแสดงเป็น array ของตัวเลข ASCII เพราะประกาศเป็น `__u8[16]` (`100,97,116,101` = `"date"`):
```text
5287: hash  name syscall_map  flags 0x0
	key 4B  value 24B  max_entries 4096  memlock 394816B
	btf_id 6134
[{
        "key": 189359,
        "value": {
            "count": 277,
            "comm": [100,97,116,101,0,0,0,0,0,0,0,0,0,0,0,0
            ]
        }
    },{
        "key": 189378,
        "value": {
            "count": 133,
            "comm": [115,108,101,101,112,0,0,0,0,0,0,0,0,0,0,0
...
```
สังเกต `memlock 394816B` ซึ่งถูกจองไว้ทั้งก้อนตั้งแต่สร้าง map (pre-allocation) แม้ยังไม่มีข้อมูล

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`, 8 CPUs), Go 1.26, clang 21, cilium/ebpf v0.16.0

### 4.1 การคอมไพล์ (`make generate build`)
```text
===> Generating Go bindings from syscall_stats.c via bpf2go...
go generate ./...
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfel.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfel.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfel.go
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfeb.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfeb.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfeb.go
===> Building userspace binary bin/syscall-top...
mkdir -p bin
go build -v -o bin/syscall-top .
```

### 4.2 ผลลัพธ์การรัน `sudo timeout -s INT 5 ./bin/syscall-top` ขณะรัน Python `getpid()` 50,000 ครั้ง
(แสดงเฉพาะส่วนหัวและรายงานสุดท้าย; รอบกลางถูกล้างหน้าจอด้วย ANSI escape)
```text
======================================================================
 eBPF Syscall Top Monitor (BPF_MAP_TYPE_HASH + Cilium ebpf-go)
======================================================================
2026/10/28 22:29:21 Successfully attached to tracepoint 'raw_syscalls/sys_enter'!
2026/10/28 22:29:21 Collecting syscall frequencies across all processes... (Press Ctrl+C to stop)
...
Received signal 'interrupt'. Rendering final report...

=================================================================================
 eBPF Syscall Monitor | Time: 22:29:26 | Total Invocations: 230233
=================================================================================
RANK   PID       COMM                SYSCALLS          SHARE (%)   
---------------------------------------------------------------------------------
#1     189550    python3             50412              21.90%
#2     190016    pgrep               5482                2.38%
#3     189933    pgrep               5482                2.38%
#4     189352    syscall-top         4259                1.85%
#5     3760745   mi-scavenger        4207                1.83%
#6     183726    bash                3686                1.60%
#7     183728    bash                3667                1.59%
#8     183724    bash                3667                1.59%
#9     183722    bash                3667                1.59%
#10    187858    python3             1726                0.75%
---------------------------------------------------------------------------------
 Tracking 1011 active processes in BPF_MAP_TYPE_HASH

Shutting down eBPF monitor cleanly.
```
- `python3` ขึ้นอันดับ 1 ด้วยชื่อที่ถูกต้อง (50,412 syscalls ≈ 50,000 `getpid()` + syscall ของการเริ่ม interpreter)
- `syscall-top` เองก็ติดอันดับ เพราะการวนอ่าน map ทุก 2 วินาทีใช้ `bpf()` syscall หลายพันครั้ง (`BPF_MAP_GET_NEXT_KEY` + `BPF_MAP_LOOKUP_ELEM` ต่อ 1 entry) — ต้นทุนของการ iterate แบบทีละ key ที่หัวข้อ 1.3 อธิบาย

---

## 5. Milestone Checklist

- [x] เข้าใจโครงสร้างและการทำงานภายในของ `BPF_MAP_TYPE_HASH` ในระดับเคอร์เนล
- [x] ทำความเข้าใจกฎ Struct Padding, Memory Alignment ระหว่าง C และ Go
- [x] เขียน eBPF Program ดักจับ `raw_syscalls/sys_enter` และสกัด Process Metadata
- [x] จัดการข้อมูลใน Map ด้วย `bpf_map_lookup_elem`, `bpf_map_update_elem`, และ Atomic Instructions
- [x] ดึงชื่อโปรแกรมด้วย `bpf_get_current_comm` ได้อย่างถูกต้อง
- [x] พัฒนาตัววนซ้ำอ่านข้อมูลทั้ง Map ใน Userspace ด้วย `Map.Iterate()`
- [x] สร้าง CLI Top-10 Realtime Dashboard พร้อมคำนวณสถิติและสัดส่วนเปอร์เซ็นต์

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `fatal error: 'asm/types.h' file not found` ตอน `make generate` | `clang -target bpf` หา `asm/` ของ multiarch ไม่เจอ | `sudo apt install gcc-multilib` หรือเพิ่ม `-cflags "-I/usr/include/x86_64-linux-gnu"` ใน `//go:generate` |
| `Failed to remove memlock limit: failed to set memlock rlimit: operation not permitted` | รันโดยไม่ใช้ `sudo` | `sudo ./bin/syscall-top` |
| `... load program: permission denied: ... R0 invalid mem access 'map_value_or_null'` | ใช้ pointer จาก `bpf_map_lookup_elem()` ของ **Hash Map** โดยไม่ตรวจ `NULL` (Hash lookup คืน `NULL` ได้เสมอ ต่างจาก Array ที่ key คงที่) | คง `if (stat) { ... }` ไว้ทุกครั้ง |
| COMM แสดงเป็น `bash`/`sh` ทั้งที่เป็นโปรแกรมอื่น | ใช้ `syscall_stats.c` รุ่นเก่าที่บันทึก `comm` แค่ครั้งแรก (ก่อน `execve`) | ใช้รุ่นปัจจุบันที่เรียก `bpf_get_current_comm()` ในกิ่ง `if (stat)` แล้ว `make generate build` ใหม่ |
| ใช้งานไปสักพักแล้วโปรเซสใหม่ **ไม่ขึ้นในตารางเลย** และ `Tracking` ค้างที่ 4096 | Hash Map เต็ม (`max_entries 4096`) และไม่มีใครลบ PID ที่จบไปแล้ว `bpf_map_update_elem()` จึงล้มเหลวเงียบๆ (โค้ดไม่ได้ตรวจค่าที่คืน) | ใช้ `BPF_MAP_TYPE_LRU_HASH`, ลบ key ตอนโปรเซสจบ (`sched_process_exit`) หรือให้ Go ลบ PID ที่ไม่มีใน `/proc` ออก (ดูแบบฝึกหัด) |
| `bpftool map dump` แสดง `comm` เป็นตัวเลข | ฟิลด์ประกาศเป็น `__u8[16]` BTF จึงบอกว่าเป็น array ของตัวเลข | ปกติ ไม่ใช่ error (ถ้าเป็น `char[16]` bpftool จะแสดงเป็นสตริง แต่ bpf2go จะสร้าง `[16]int8`) |
| `syscall-top` ติดอันดับต้นๆ เสียเอง | การ iterate map ทีละ key ใช้ `bpf()` syscall 2 ครั้งต่อ entry | ปกติ; ลดได้ด้วย Batch API (`BatchLookup`) หรือรีเฟรชถี่น้อยลง |

> **หมายเหตุ Linux 7.0**: สัปดาห์นี้ใช้ `raw_syscalls/sys_enter` ซึ่งทดสอบแล้วว่าทำงานครบทุก CPU ต่างจาก `syscalls/sys_enter_execve` ที่พบปัญหาจับได้เฉพาะ CPU 0 บนเครื่องทดสอบ (ดู Week 03/05)

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **เปลี่ยนเป็น `BPF_MAP_TYPE_LRU_HASH`**: แก้ชนิด map แล้วลด `max_entries` เหลือ 256 เพื่อให้เห็นผลเร็ว
   - **สิ่งที่ต้องส่ง**: diff + ผล `Tracking N` ที่ไม่เกิน 256 แต่โปรเซสใหม่ (เช่น `python3` วนลูป) ยังขึ้นตาราง
   - **วิธีตรวจ**: `sudo bpftool map list name syscall_map` ต้องแสดง `lru_hash` และ `max_entries 256`
2. **นับเฉพาะ thread แทน process**: เปลี่ยน key เป็น 32 บิตล่างของ `pid_tgid` (TID) แล้วรันโปรแกรมที่มีหลาย thread
   - **สิ่งที่ต้องส่ง**: ผลเปรียบเทียบ key แบบ TGID vs TID สำหรับโปรแกรมเดียวกัน
   - **วิธีตรวจ**: `python3 -c "import threading,os; [threading.Thread(target=lambda: [os.getpid() for _ in range(20000)]).start() for _ in range(4)]"` — แบบ TID ต้องเห็น 4 แถว (ชื่อ `python3`) แต่ละแถว ~20,000

### ระดับปานกลาง
3. **แก้ Race ตอน insert ครั้งแรก**: ใช้ `bpf_map_update_elem(..., BPF_NOEXIST)` ถ้าคืนค่าไม่ใช่ 0 (มี CPU อื่น insert ไปก่อน) ให้ lookup ใหม่แล้ว `__sync_fetch_and_add`
   - **สิ่งที่ต้องส่ง**: โค้ด + คำอธิบายว่าทำไมแบบเดิมนับหายได้ + ตรวจว่าผ่าน Verifier
   - **วิธีตรวจ**: โปรแกรมโหลดได้ (`make generate build && sudo timeout -s INT 5 ./bin/syscall-top`) และยอดของ `python3` ในแบบฝึกหัดที่ 2 (แบบ TGID) ต้องไม่ต่ำกว่า 80,000
4. **ลบ PID ที่จบแล้ว**: เพิ่มโปรแกรมที่สองบน `tracepoint/sched/sched_process_exit` ที่ `bpf_map_delete_elem()` เมื่อ thread ที่จบคือ thread หลัก (`pid == tgid`)
   - **สิ่งที่ต้องส่ง**: โค้ด C + Go (attach 2 tracepoint) + ผลที่ `Tracking N` คงที่แทนที่จะโตขึ้นเรื่อยๆ
   - **วิธีตรวจ**: รัน `for i in $(seq 200); do /bin/true; done` แล้ว `Tracking N` ต้องไม่เพิ่มขึ้น ~200

### ระดับท้าทาย
5. **นับแยกตามหมายเลข syscall**: เปลี่ยน key เป็น struct `{__u32 pid; __u32 syscall_id;}` (อ่าน `id` จาก context ของ `raw_syscalls/sys_enter`: struct `{__u64 pad; long id; unsigned long args[6];}` ตาม `/sys/kernel/tracing/events/raw_syscalls/sys_enter/format`) แล้วแสดง Top-3 syscall ของแต่ละโปรเซส
   - **สิ่งที่ต้องส่ง**: โค้ด + ผลที่ `python3` ในขั้นตอนที่ 4 มี syscall 39 (`getpid` บน x86_64) เป็นอันดับ 1
   - **วิธีตรวจ**: เทียบกับ `sudo perf stat -e 'syscalls:sys_enter_getpid' python3 -c "import os; [os.getpid() for _ in range(50000)]"` ซึ่งต้องได้ 50,000
6. **อ่านแบบ Batch และวัดผล**: เปลี่ยน `Iterate()` เป็น `BatchLookup` ของ cilium/ebpf แล้ววัดจำนวน `bpf()` syscall ที่ `syscall-top` เรียกต่อรอบ ก่อน/หลัง
   - **สิ่งที่ต้องส่ง**: diff + ตารางจำนวน syscall ต่อรอบ (วัดจริงอย่างน้อย 3 รอบ) เมื่อ map มี ~1,000 entries
   - **วิธีตรวจ**: `sudo strace -c -e trace=bpf -p $(pgrep -f bin/syscall-top) ` ประมาณ 10 วินาที แล้วเทียบ `calls`
