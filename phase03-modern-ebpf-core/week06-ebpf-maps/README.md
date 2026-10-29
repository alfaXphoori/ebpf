# Week 06: eBPF Maps, Verifier Log & BPF_PROG_TEST_RUN Testing

ยินดีต้อนรับสู่สัปดาห์ที่ 6 ของหลักสูตร **eBPF: Zero-to-Hero** สัปดาห์นี้เราจะเจาะลึกกลไกการจัดเก็บสถานะและการสื่อสารข้อมูลระหว่าง Kernel Space และ Userspace ผ่านโครงสร้างข้อมูลหลักของ eBPF นั่นคือ **BPF Maps** โดยมุ่งเน้นที่การใช้งาน `BPF_MAP_TYPE_HASH` เพื่อสร้างเครื่องมือมอนิเตอร์ระดับระบบ: **Syscall Top Monitor** ที่ตรวจจับความถี่การเรียกใช้งาน System Call ของทุกโปรเซสแบบเรียลไทม์

นอกจากนี้สัปดาห์นี้ยังปูทักษะพื้นฐานสองอย่างที่จะใช้ไปตลอดหลักสูตร (ย้ายมาจาก Week 11 เดิม เพื่อให้ฝึกตั้งแต่ต้น):
- **การอ่าน Verifier Log** — แล็บ `verifier_fail/` ที่ตั้งใจเขียนโค้ดผิดให้ Verifier ปฏิเสธ แล้วฝึกไล่ Log ระดับ Instruction ว่าบรรทัดไหนคือสาเหตุ (หัวข้อ 5)
- **การทดสอบด้วย `BPF_PROG_TEST_RUN`** — เขียน Go unit test ที่สั่งให้เคอร์เนลรันโปรแกรม eBPF กับข้อมูลปลอมโดยไม่ต้อง Attach กับ Hook จริง และใช้เปรียบเทียบพฤติกรรมของ `HASH` vs `PERCPU_HASH` vs `LRU_HASH` (หัวข้อ 6)

| ไฟล์ / โฟลเดอร์ | หน้าที่ |
| :--- | :--- |
| `syscall_stats.c`, `main.go` | Syscall Top Monitor (`tracepoint/raw_syscalls/sys_enter` + `BPF_MAP_TYPE_HASH`) |
| `main_test.go` | ทดสอบว่า `syscall_stats.c` ผ่าน Verifier, ขนาด Map ตรงกับ Go struct และแสดงว่า Tracepoint ใช้ test_run ไม่ได้ |
| `verifier_fail/` | โปรแกรม XDP ที่ Verifier ต้องปฏิเสธ 2 ตัว + ตัวที่แก้แล้ว 1 ตัว (`make verifier-demo`) |
| `maps_testrun/` | โปรแกรม XDP เล็กๆ (`map_types.c`) สำหรับทดสอบพฤติกรรมของ Map ด้วย `BPF_PROG_TEST_RUN` (`make test`) |

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

### ขั้นตอนที่ 6: ฝึกอ่าน Verifier Log และรันเทสต์
```bash
make verifier-demo   # โหลดโปรแกรมที่ตั้งใจให้ผิด แล้วพิมพ์ Verifier Log จริง (หัวข้อ 5)
make test            # go generate + go test -exec sudo -v ./...  (หัวข้อ 6)
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`, 8 CPUs), Go 1.26, clang 21, cilium/ebpf v0.16.0

### 4.1 การคอมไพล์ (`make clean && make all`)
`go generate ./...` สร้าง Bindings ให้ทั้ง 3 Package (โฟลเดอร์หลัก, `maps_testrun/`, `verifier_fail/`) — สังเกตว่า `verifier_fail.c` ซึ่งมีบั๊กถูก **คอมไพล์ผ่าน** ตามปกติ บั๊กจะถูกพบตอนโหลดเข้าเคอร์เนลเท่านั้น
```text
===> Generating Go bindings via bpf2go...
go generate ./...
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfel.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfel.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfel.go
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfeb.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfeb.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/bpf_bpfeb.go
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/maps_testrun/maptypes_bpf.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/maps_testrun/maptypes_bpf.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/maps_testrun/maptypes_bpf.go
Compiled /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/verifier_fail/bpf_bpf.o
Stripped /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/verifier_fail/bpf_bpf.o
Wrote /mnt/sda/ebpf/phase03-modern-ebpf-core/week06-ebpf-maps/verifier_fail/bpf_bpf.go
===> Building userspace binaries bin/syscall-top and bin/verifier_fail...
mkdir -p bin
go build -v -o bin/syscall-top .
ebpf-noob-to-hero/phase03-modern-ebpf-core/week06-ebpf-maps
go build -v -o bin/verifier_fail ./verifier_fail
ebpf-noob-to-hero/phase03-modern-ebpf-core/week06-ebpf-maps/verifier_fail
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

## 5. อ่าน Verifier Log (แล็บ `verifier_fail/`)

ทุกครั้งที่โปรแกรม eBPF "โหลดไม่ขึ้น" สิ่งเดียวที่บอกเหตุผลได้คือ **Verifier Log** ทักษะนี้จึงต้องฝึกตั้งแต่สัปดาห์แรกๆ ที่เริ่มใช้ Map (ซึ่งเป็นที่มาของ Error ยอดนิยมอย่าง `map_value_or_null`)

### 5.1 การทำงานภายในของ eBPF Verifier
ก่อนที่ eBPF Bytecode จะได้รับอนุญาตให้รันภายใน Linux Kernel ตัวเคอร์เนลจะนำ Bytecode เข้าสู่กระบวนการ Static Analysis ที่เข้มงวดที่สุดในโลกของระบบปฏิบัติการ เรียกว่า **eBPF Verifier**

```
+-------------------------------------------------------------------------+
|                  การทำงานของ EBPF VERIFIER STATIC ANALYSIS              |
|                                                                         |
|  C Code (.c) ---> Clang/LLVM ---> eBPF Bytecode (.o)                   |
|                                         |                               |
|                                         v                               |
|                     +-----------------------------------+               |
|                     |        eBPF Kernel Verifier       |               |
|                     +-----------------------------------+               |
|                     | 1. ตรวจสอบ Control Flow Graph     |               |
|                     |    - ป้องกัน Infinite Loop        |               |
|                     |    - ตรวจจับ Unreachable Code     |               |
|                     |                                   |               |
|                     | 2. จำลองการทำงานทุก Execution Path|               |
|                     |    - ติดตาม State ของ Registers   |               |
|                     |      (R0 - R10: Type, Bounds, Min/Max)            |
|                     |                                   |               |
|                     | 3. Packet Bounds Checking         |               |
|                     |    - ทุกการอ่าน Memory ต้องพิสูจน์ได้ว่า|             |
|                     |      data + offset <= data_end    |               |
|                     +-----------------------------------+               |
|                                 |           |                           |
|                        ผ่าน      v           v ล้มเหลว                   |
|                  +---------------+   +-----------------------------+    |
|                  | JIT Compiler  |   | ปฏิเสธการโหลดลง Kernel       |    |
|                  | (x86/ARM64)   |   | ส่งกลับ Verifier Log ละเอียด |    |
|                  +---------------+   +-----------------------------+    |
+-------------------------------------------------------------------------+
```

สิ่งสำคัญที่ต้องจำ: **clang ไม่รู้กฎของ Verifier** โค้ดที่คอมไพล์ผ่านโดยไม่มี Warning อาจถูกปฏิเสธตอน `BPF_PROG_LOAD` ได้เสมอ (ดูผล `make all` ในหัวข้อ 4.1 ที่ `verifier_fail.c` คอมไพล์ผ่าน)

### 5.2 เจาะลึก Error ยอดนิยมของ Verifier และวิธีแก้ไข

> ข้อความ Error ด้านล่างเป็นรูปแบบที่พบบ่อย แต่รายละเอียดของ Register State (เช่น `R1=pkt(r=0)`) เปลี่ยนไปตามเวอร์ชันเคอร์เนล ให้ดูตัวอย่าง Log จริงที่จับได้บน Linux 7.0 ในหัวข้อ 5.6

#### 1. `invalid access to packet, off=X size=Y, R1(id=0,off=X,r=0)`
- **สาเหตุ**: โปรแกรมพยายามอ่าน Memory ของ Packet โดยไม่มีการตรวจสอบ Bounds Check หรือตรวจสอบไม่ครอบคลุมขนาดของ Struct ที่อ่าน (`r=0` หมายถึง Verifier พิสูจน์ได้ว่าอ่านได้อย่างปลอดภัย 0 ไบต์)
- **วิธีแก้**: ทุกครั้งก่อนเข้าถึงฟิลด์ใน Header ต้องเขียนเงื่อนไขชัดเจน:
  ```c
  if ((void *)(eth + 1) > data_end)
      return XDP_PASS;
  ```

#### 2. `R1 offset is outside of the packet`
- **สาเหตุ**: มีการบวกค่า Offset ลงใน Pointer แล้วค่าทะลุเกินช่วงที่พิสูจน์ได้ หรือเกิด Integer Overflow ในการคำนวณ `ihl * 4` (ใน Log จริงหัวข้อ 5.6 ข้อความนี้ตามหลัง Error ข้อ 1 ด้วย)
- **วิธีแก้**: ทำการตรวจสอบขอบเขตต่ำสุดและสูงสุดของค่าตัวแปร:
  ```c
  __u32 ip_hdr_len = iph->ihl * 4;
  if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
  if ((void *)iph + ip_hdr_len > data_end) return XDP_PASS;
  ```

#### 3. `R0 invalid mem access 'map_value_or_null'`
- **สาเหตุ**: นำ Pointer ที่ได้จาก `bpf_map_lookup_elem()` ไปใช้ (Dereference) โดยไม่ตรวจสอบ `NULL` ก่อน — Verifier ถือว่าผลลัพธ์อาจเป็น `NULL` เสมอ (ชนิด `map_value_or_null`) นี่คือเหตุผลที่ `syscall_stats.c` ต้องมี `if (stat) { ... }`
- **วิธีแก้**: `if (!val) return XDP_PASS;` ก่อนอ่าน/เขียนผ่าน Pointer
- **ข้อสังเกต**: เคอร์เนลรุ่นใหม่ (ทดสอบแล้วบน Linux 7.0) สามารถพิสูจน์ได้ว่าการ Lookup ใน `ARRAY`/`PERCPU_ARRAY` ด้วย Key ที่เป็นค่าคงที่และอยู่ในช่วง `max_entries` จะไม่มีวันเป็น `NULL` จึงยอม **ผ่าน** โค้ดที่ลืมเช็ก NULL ในกรณีนั้น แต่สำหรับ `HASH` Map จะถูกปฏิเสธเสมอ — อย่าพึ่งพฤติกรรมนี้ ให้เช็ก NULL ทุกครั้ง

#### 4. ลูปที่ Verifier พิสูจน์ไม่ได้ว่าจะจบ
- **สาเหตุ**: ตั้งแต่ Linux 5.3 Verifier รองรับ Bounded Loop แล้ว แต่ถ้าพิสูจน์ไม่ได้ว่าลูปจะจบ จะได้ข้อความประเภท `infinite loop detected at insn X` หรือ `BPF program is too large. Processed 1000001 insn` (ข้อความ `back-edge from insn X to Y` จะพบในเคอร์เนลเก่ากว่า 5.3 หรือกรณีโหลดแบบ Unprivileged)
- **วิธีแก้**: ใช้ขอบเขตลูปเป็นค่าคงที่ขนาดเล็ก (เช่น `for (int i = 0; i < 10; i++)`), ใช้ `#pragma unroll` หรือ Helper `bpf_loop()` (Linux 5.17+)

### 5.3 การอ่าน Verifier Log จาก Go (`ebpf.VerifierError`) และ `bpftool`
เมื่อโหลดโปรแกรมไม่ผ่าน cilium/ebpf จะคืน Error ชนิด `*ebpf.VerifierError` ซึ่งเก็บ Log ของ Verifier ไว้ทีละบรรทัด (`ve.Log`) วิธีพิมพ์ออกมาอ่าน:
```go
var ve *ebpf.VerifierError
if errors.As(err, &ve) {
    fmt.Printf("%+v\n", ve)    // พิมพ์ Log ทั้งหมด
    fmt.Printf("%-20v\n", ve)  // พิมพ์เฉพาะ 20 บรรทัดสุดท้าย (จุดที่ Error มักอยู่)
}
```
> หากพิมพ์ด้วย `%v` หรือ `%s` ธรรมดา จะได้แค่บรรทัดสรุปสั้นๆ ไม่มี Trace ของ Register

วิธีอ่าน Log ทีละบรรทัด (ตัวอย่างจริงจากแล็บ `verifier_fail -case bounds`):
```text
0: (61) r1 = *(u32 *)(r1 +0)          ; R1=pkt(r=0)
1: (71) r2 = *(u8 *)(r1 +12)
invalid access to packet, off=12 size=1, R1(id=0,off=12,r=0)
```
- `0:` คือหมายเลข Instruction, `(61)` คือ Opcode, ส่วนหลัง `;` คือ State ของ Register **หลัง** รันคำสั่งนั้น
- `R1=pkt(r=0)` = R1 เป็น Pointer ชี้เข้า Packet แต่ช่วงที่พิสูจน์แล้วว่าอ่านได้ (`r=`) คือ 0 ไบต์ เพราะยังไม่มีการเทียบกับ `data_end`
- บรรทัดสุดท้ายก่อนสถิติคือ **สาเหตุ** ที่ถูกปฏิเสธ — การอ่านไบต์ที่ offset 12 (`h_proto`) ทั้งที่ `r=0`
- บรรทัด `; ... @ verifier_fail.c:48` คือ Source Line ที่ได้จาก BTF (ต้องคอมไพล์ด้วย `-g` ซึ่ง bpf2go ใส่ให้อัตโนมัติ)
- บรรทัดสถิติท้าย Log: `processed N insns (limit 1000000)` = จำนวน Instruction ที่ Verifier จำลองรวมทุก Path, `stack depth` = ขนาด Stack ที่ใช้ (สูงสุด 512 ไบต์)

ทางเลือกด้วย `bpftool`: เปิด Debug Output ของ libbpf ด้วย `-d` แล้ว libbpf จะพิมพ์ Verifier Log ระหว่าง `-- BEGIN PROG LOAD LOG --` ... `-- END PROG LOAD LOG --` เมื่อโหลดไม่ผ่าน (bpftool โหลดทุกโปรแกรมในไฟล์ `.o` จึงหยุดที่โปรแกรมแรกที่ไม่ผ่าน ในที่นี้คือ `xdp_no_bounds_check`):
```bash
sudo bpftool -d prog load verifier_fail/bpf_bpf.o /sys/fs/bpf/w06_vf_test
sudo rm -f /sys/fs/bpf/w06_vf_test   # ลบ Pin ทิ้ง (กรณีโหลดผ่าน)
```

### 5.4 อธิบายโค้ดทีละบรรทัด (`verifier_fail/`)

ไฟล์ `verifier_fail/verifier_fail.c` มีโปรแกรม XDP 3 ตัว ซึ่ง **clang คอมไพล์ผ่านทั้งหมดโดยไม่มี Warning** — บั๊กจะถูกพบตอนเคอร์เนลรัน Verifier ระหว่าง `BPF_PROG_LOAD` เท่านั้น (ใช้ XDP เพราะเป็นชนิดโปรแกรมที่เห็นบั๊กเรื่อง Packet Bounds ได้ชัดที่สุด และไม่ต้อง Attach กับ Interface ใดเลย — แค่โหลดแล้วปิด):

| `-case` | โปรแกรม | บั๊กที่ใส่ไว้ | ผลลัพธ์ที่คาดหวัง |
| :--- | :--- | :--- | :--- |
| `bounds` | `xdp_no_bounds_check` (บรรทัด 41–52) | อ่าน `eth->h_proto` โดยไม่เทียบ `data_end` | `invalid access to packet` |
| `nullcheck` | `xdp_no_null_check` (บรรทัด 58–68) | ใช้ผลของ `bpf_map_lookup_elem()` บน `HASH` Map โดยไม่เช็ก NULL | `R0 invalid mem access 'map_value_or_null'` |
| `fixed` | `xdp_fixed` (บรรทัด 71–95) | แก้ทั้งสองจุดแล้ว | โหลดผ่าน พร้อมสถิติ `processed N insns` |

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    /* ingress ifindex */
    __type(value, __u64);  /* packets */
    __uint(max_entries, 64);
} pkt_count SEC(".maps");
```
- **`verifier_fail.c` บรรทัด 29–34**: ตั้งใจใช้ `HASH` (ไม่ใช่ `ARRAY`) เพราะ Lookup ใน Hash Map คืน `NULL` ได้เสมอ Verifier จึงต้องปฏิเสธบั๊ก #2 ทุกเวอร์ชัน (ดูข้อสังเกตในหัวข้อ 5.2 ข้อ 3)

```go
spec.Programs = map[string]*ebpf.ProgramSpec{progName: spec.Programs[progName]}
return ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: opts})
```
- **`verifier_fail/main.go` บรรทัด 31–42**: โหลด **เฉพาะโปรแกรมที่เลือก** (พร้อม Map ที่มันอ้างถึง) เพราะถ้าโหลดทั้ง Collection จะหยุดที่โปรแกรมแรกที่ไม่ผ่าน

```go
opts := ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats}
...
var ve *ebpf.VerifierError
if errors.As(err, &ve) {
    fmt.Printf("%+v\n", ve)
}
```
- **`verifier_fail/main.go` บรรทัด 59–83**: ขอ Verifier Log ระดับ Instruction ตั้งแต่ครั้งแรก (`LogLevelBranch`) พร้อมสถิติ (`LogLevelStats`) จากนั้นแยก `*ebpf.VerifierError` ด้วย `errors.As` และพิมพ์ด้วย `%+v` (หรือ `%-Nv` เมื่อใช้ `-lines N` เพื่อดูเฉพาะ N บรรทัดสุดท้าย) ส่วนกรณี `fixed` จะพิมพ์ `prog.VerifierLog` ซึ่งมีเฉพาะสถิติ

```go
for name, want := range map[string]string{
    "bounds":    "invalid access to packet",
    "nullcheck": "invalid mem access 'map_value_or_null'",
} { ... errors.As(err, &ve) ... strings.Contains(log, want) ... }
```
- **`verifier_fail/main_test.go`**: เปลี่ยน "การอ่าน Log ด้วยตา" ให้เป็น **Regression Test** — ตรวจว่าโปรแกรมที่ผิดถูกปฏิเสธด้วยข้อความที่คาดไว้ และ `fixed` ต้องโหลดผ่าน (เทสต์นี้ใช้แค่ `BPF_PROG_LOAD` ยังไม่ได้ใช้ `BPF_PROG_TEST_RUN`)

### 5.5 ขั้นตอนการรัน
```bash
make verifier-demo
# หรือรันทีละกรณี
sudo ./bin/verifier_fail -case bounds
sudo ./bin/verifier_fail -case nullcheck
sudo ./bin/verifier_fail -case nullcheck -lines 3   # ดูเฉพาะ 3 บรรทัดสุดท้าย
sudo ./bin/verifier_fail -case fixed
```
กรณีที่ถูกปฏิเสธจะจบด้วย Exit Code 1 (`make verifier-demo` ตั้งให้ข้าม Error นี้ด้วย `-` หน้าคำสั่ง)

### 5.6 ผลลัพธ์จริง (Verifier Log จริง)

> **Environment**: Ubuntu 26.04.1 LTS (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), clang 21.1.8, Go 1.26, cilium/ebpf v0.16.0

`make verifier-demo` (ตัดบรรทัด `go build` ด้านบนออก):
```text
sudo ./bin/verifier_fail -case bounds
[VERIFIER] program "xdp_no_bounds_check" REJECTED
load program: permission denied:
	0: R1=ctx() R10=fp0
	; void *data = (void *)(long)ctx->data; @ verifier_fail.c:44
	0: (61) r1 = *(u32 *)(r1 +0)          ; R1=pkt(r=0)
	; if (eth->h_proto != bpf_htons(ETH_P_IP)) @ verifier_fail.c:48
	1: (71) r2 = *(u8 *)(r1 +12)
	invalid access to packet, off=12 size=1, R1(id=0,off=12,r=0)
	R1 offset is outside of the packet
	verification time 26 usec
	stack depth 0
	processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
make: [Makefile:33: verifier-demo] Error 1 (ignored)
sudo ./bin/verifier_fail -case nullcheck
[VERIFIER] program "xdp_no_null_check" REJECTED
load program: permission denied:
	0: R1=ctx() R10=fp0
	; __u32 key = ctx->ingress_ifindex; @ verifier_fail.c:61
	0: (61) r1 = *(u32 *)(r1 +12)         ; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
	1: (63) *(u32 *)(r10 -4) = r1         ; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0 fp-8=mmmm????
	2: (bf) r2 = r10                      ; R2=fp0 R10=fp0
	3: (07) r2 += -4                      ; R2=fp-4
	; __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); @ verifier_fail.c:62
	4: (18) r1 = 0xffff8a9b68f41c00       ; R1=map_ptr(map=pkt_count,ks=4,vs=8)
	6: (85) call bpf_map_lookup_elem#1    ; R0=map_value_or_null(id=1,map=pkt_count,ks=4,vs=8)
	7: (b7) r1 = 1                        ; R1=1
	; __sync_fetch_and_add(count, 1); @ verifier_fail.c:65
	8: (db) lock *(u64 *)(r0 +0) += r1
	R0 invalid mem access 'map_value_or_null'
	verification time 37 usec
	stack depth 8
	processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
make: [Makefile:34: verifier-demo] Error 1 (ignored)
sudo ./bin/verifier_fail -case fixed
[VERIFIER] program "xdp_fixed" ACCEPTED
verification time 58 usec
stack depth 16
processed 37 insns (limit 1000000) max_states_per_insn 0 total_states 3 peak_states 3 mark_read 0
```

`-lines 3` (ใช้ `%-3v`) — cilium/ebpf บอกจำนวนบรรทัดที่ถูกตัดทิ้งให้:
```text
$ sudo ./bin/verifier_fail -case nullcheck -lines 3
[VERIFIER] program "xdp_no_null_check" REJECTED
load program: permission denied:
	(13 line(s) omitted)
	verification time 87 usec
	stack depth 8
	processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
> ข้อควรระวัง: 3 บรรทัดสุดท้ายเป็น **สถิติล้วน** ไม่มีสาเหตุของ Error เลย ในทางปฏิบัติให้ใช้ `-lines 8` ขึ้นไป หรืออ่านทั้ง Log

`sudo bpftool -d prog load verifier_fail/bpf_bpf.o /sys/fs/bpf/w06_vf_test` (ตัดเฉพาะส่วน Log ของ libbpf):
```text
libbpf: prog 'xdp_no_bounds_check': -- BEGIN PROG LOAD LOG --
func#0 @0
Live regs before insn:
      0: .1........ (61) r1 = *(u32 *)(r1 +0)
      1: .1........ (71) r2 = *(u8 *)(r1 +12)
      2: .12....... (71) r1 = *(u8 *)(r1 +13)
      3: .12....... (67) r1 <<= 8
      4: .12....... (4f) r1 |= r2
      5: .1........ (b7) r0 = 1
      6: 01........ (15) if r1 == 0x8 goto pc+1
      7: .......... (b7) r0 = 2
      8: 0......... (95) exit
0: R1=ctx() R10=fp0
; void *data = (void *)(long)ctx->data; @ verifier_fail.c:44
0: (61) r1 = *(u32 *)(r1 +0)          ; R1=pkt(r=0)
; if (eth->h_proto != bpf_htons(ETH_P_IP)) @ verifier_fail.c:48
1: (71) r2 = *(u8 *)(r1 +12)
invalid access to packet, off=12 size=1, R1(id=0,off=12,r=0)
R1 offset is outside of the packet
verification time 119 usec
stack depth 0
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
```

ข้อสังเกตจาก Log จริง:
- **กรณี `bounds`**: clang แปลง `eth->h_proto != bpf_htons(ETH_P_IP)` เป็นการอ่านทีละ 1 ไบต์ (`size=1`) ไม่ใช่ 2 ไบต์ตามที่คาดจากซอร์ส — ส่วน `Live regs before insn:` ของ bpftool แสดง Bytecode ทั้งโปรแกรม: คำสั่งที่ 1–4 อ่านไบต์ที่ 12 และ 13 แยกกันแล้วนำมา `<<= 8` / `|=` รวมกัน (เพราะ `struct ethhdr` ประกาศเป็น `__attribute__((packed))` clang จึงสมมติ Alignment ไม่ได้) นี่คือเหตุผลที่ต้องอ่าน Log ระดับ Instruction ไม่ใช่เดาจาก C
- **กรณี `bounds`**: Verifier หยุดที่คำสั่งแรกที่ผิด (`processed 2 insns`) จึงไม่เห็นคำสั่งที่ 2–8 ใน Trace — Error มักอยู่ **ท้าย** Trace เสมอ
- **กรณี `nullcheck`**: ไล่ดูชนิดของ `R0` หลัง `call bpf_map_lookup_elem#1` จะเป็น `map_value_or_null` แล้วคำสั่งที่ 8 ใช้ R0 ทันทีโดยไม่มี `if r0 == 0 goto ...` คั่น (คำสั่ง `4: (18)` เป็นคำสั่ง 16 ไบต์ จึงกินหมายเลข 4–5 และคำสั่งถัดไปคือ 6)
- **กรณี `fixed`**: Verifier ตรวจ 37 Instructions (นับรวมทุก Path ที่จำลอง) — `processed` ที่สูงมากเป็นสัญญาณว่าโปรแกรมใกล้ชนเพดาน 1,000,000 Instructions
- ค่า `r1 = 0xffff...` ในคำสั่งที่ 4 คือ Address ของ Map ในเคอร์เนล และ `verification time` จะเปลี่ยนทุกครั้งที่โหลด

---

## 6. ทดสอบด้วย BPF_PROG_TEST_RUN

### 6.1 หลักการ: ให้เคอร์เนลรันโปรแกรมกับข้อมูลปลอม
`bpf(BPF_PROG_TEST_RUN)` (cilium/ebpf: `Program.Run()`) สั่งให้เคอร์เนลรันโปรแกรม eBPF **ที่โหลดแล้ว** หนึ่งครั้ง (หรือ `Repeat` ครั้ง) โดยใช้ Input ที่เราส่งเข้าไปเอง แล้วคืน Return Code (เช่น `XDP_PASS` = 2) กลับมา — Map ที่โปรแกรมเขียนเป็น Map จริงในเคอร์เนล ฝั่ง Go จึงอ่านผลจาก Map มาตรวจได้ทันที

```
  go test (root)                         LINUX KERNEL
  ---------------                        ---------------------------------------
  loadMaptypesObjects()  --BPF_PROG_LOAD-->  Verifier -> JIT -> count_by_key
  prog.Run(RunOptions{   --BPF_PROG_TEST_RUN--> สร้าง xdp_buff ปลอมจาก Data
     Data:   packet(42),                      รัน count_by_key 1000 ครั้ง
     Repeat: 1000})      <-- ret = 2 (XDP_PASS) --    |
                                                      v  เขียน hash_map / percpu_map / lru_map
  objs.HashMap.Lookup(42) --BPF_MAP_LOOKUP_ELEM--> 1000
  t.Fatalf(...) ถ้าไม่ตรง
```
ข้อดี: ไม่ต้อง Attach กับ Interface/Hook จริง (ไม่กระทบเครื่อง), ผลลัพธ์ Deterministic, รันใน CI ได้ (ยังต้องมีสิทธิ์โหลดโปรแกรม eBPF เช่น root — เทสต์ในสัปดาห์นี้จึง Skip เมื่อไม่ใช่ root)

### 6.2 ชนิดโปรแกรมไหนใช้ test_run ได้บ้าง
เคอร์เนลรองรับ test_run เฉพาะชนิดโปรแกรมที่มี Callback `test_run` (ดู `net/bpf/test_run.c`) — บน Linux 7.0 ของเครื่องทดสอบ `/proc/kallsyms` มีฟังก์ชัน `bpf_prog_test_run_{xdp,skb,flow_dissector,raw_tp,tracing,sk_lookup,syscall,nf}` และ `bpf_struct_ops_test_run`

| ชนิดโปรแกรม (ตัวอย่าง `SEC()`) | test_run | Input ที่ส่งให้ |
| :--- | :---: | :--- |
| XDP (`xdp`) | ได้ | `Data` = แพ็กเก็ต (อย่างน้อย 14 ไบต์ = Ethernet Header) |
| TC / sched_cls, sched_act (`tc`, `classifier`) | ได้ | `Data` = แพ็กเก็ต + `Context` = `struct __sk_buff` (ไม่บังคับ) |
| socket_filter (`socket`), cgroup_skb, lwt_* | ได้ | `Data` = แพ็กเก็ต (ใช้เส้นทาง `test_run_skb` เดียวกับ TC) |
| flow_dissector, sk_lookup, netfilter (`netfilter`, 6.4+) | ได้ | แพ็กเก็ต / Context เฉพาะชนิด |
| raw_tracepoint (`raw_tp/...`) | ได้ | `Context` = อาร์กิวเมนต์ `u64[]`; ระบุ CPU ได้ (`BPF_F_TEST_RUN_ON_CPU`) |
| tracing: fentry/fexit/fmod_ret | ได้แบบจำกัด | เคอร์เนลเรียกฟังก์ชันทดสอบ `bpf_fentry_test*()` ของตัวเอง — ใช้ได้เฉพาะโปรแกรมที่ Attach กับฟังก์ชันเหล่านั้น |
| syscall (`syscall`) | ได้ | `Context` = Struct ที่โปรแกรมกำหนด |
| **tracepoint** (`tracepoint/...`), **kprobe/uprobe**, **perf_event**, LSM, cgroup_sock ฯลฯ | **ไม่ได้** | เคอร์เนลคืน `ENOTSUPP` (524) → cilium/ebpf คืน `ebpf.ErrNotSupported` |

> ตารางนี้สรุปจาก Kernel Source ซึ่งเปลี่ยนได้ตามเวอร์ชัน แถวที่ **ทดสอบจริงในสัปดาห์นี้** คือ XDP (ผ่าน) และ tracepoint (`ErrNotSupported` ดูหัวข้อ 6.6) — ก่อนนำไปใช้กับชนิดอื่นให้ตรวจกับเวอร์ชันเคอร์เนลของคุณ

**ผลต่อสัปดาห์นี้**: `track_syscalls` เป็น `tracepoint/raw_syscalls/sys_enter` จึง **test_run ไม่ได้** (หากต้องการทดสอบ Logic แบบนี้ในอนาคตอาจเขียนเป็น `raw_tp/sys_enter` ซึ่ง test_run ได้) เราจึงแยกเป็น 2 ส่วน:
1. `main_test.go` — โหลด `syscall_stats.c` จริงเพื่อยืนยันว่าผ่าน Verifier + ตรวจรูปร่าง Map + ยืนยันว่า `Run()` คืน `ErrNotSupported`
2. `maps_testrun/` — ย้าย "Logic ของ Map" (lookup → atomic add / insert) ไปไว้ในโปรแกรม XDP เล็กๆ ที่ test_run ได้ แล้วใช้มันเปรียบเทียบ Map 3 ชนิด

### 6.3 อธิบายโค้ดทีละบรรทัด: `maps_testrun/map_types.c`

```c
struct { __uint(type, BPF_MAP_TYPE_HASH);        __uint(max_entries, MAX_KEYS); ... } hash_map   SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, MAX_KEYS); ... } percpu_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH);    __uint(max_entries, MAX_KEYS); ... } lru_map    SEC(".maps");
```
- **บรรทัด 28–47**: Map 3 ชนิด Key/Value เหมือนกัน (`__u32` → `__u64`) และ `max_entries = 8` เท่ากัน ต่างกันแค่ `type` เพื่อให้เทียบพฤติกรรมได้ตรงๆ:
  - `HASH`: ค่า 1 ชุดใช้ร่วมกันทุก CPU — เต็มแล้ว Insert Key ใหม่ไม่ได้
  - `PERCPU_HASH`: Key เดียวมีค่าแยกต่อ CPU — ไม่ต้องใช้ Atomic แต่ User space ต้องรวมเอง
  - `LRU_HASH`: เต็มแล้วเคอร์เนลไล่ Key ที่ไม่ได้ใช้นานที่สุดออกแทน (แก้ปัญหา "Map เต็ม" ของ Syscall Top ในหัวข้อ 1.1)

```c
struct update_err { __u64 count; __s64 last_err; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 3); ... } update_errs SEC(".maps");
```
- **บรรทัด 49–60**: Map สำหรับ "รายงาน Error กลับมาที่ Go" — ช่อง 0/1/2 = hash/percpu/lru เก็บจำนวนครั้งที่ `bpf_map_update_elem()` ล้มเหลวและ errno ล่าสุด (โปรแกรม eBPF พิมพ์ Error ออกมาตรงๆ ไม่ได้ การเขียนลง Map คือวิธีที่เทสต์ตรวจได้)

```c
static __always_inline void bump_shared(void *map, __u32 *key, __u32 err_idx)
{
    __u64 *val = bpf_map_lookup_elem(map, key);
    if (val) { __sync_fetch_and_add(val, 1); return; }
    __u64 one = 1;
    long err = bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    if (err) record_err(err_idx, err);
}
```
- **บรรทัด 72–83**: Logic เดียวกับ `syscall_stats.c` (lookup → มีแล้วบวกแบบ Atomic / ยังไม่มีก็ Insert) แต่ใช้ `BPF_NOEXIST` และ **ตรวจค่าที่คืน** จาก `bpf_map_update_elem()` ซึ่ง `syscall_stats.c` ไม่ได้ตรวจ (จึงไม่รู้ตัวเมื่อ Map เต็ม)
- **บรรทัด 86–97** (`bump_percpu`): เหมือนกันแต่ใช้ `*val += 1` ธรรมดา เพราะแต่ละ CPU เขียนสำเนาของตัวเองเท่านั้น

```c
    if (data + sizeof(__u32) > data_end)
        return XDP_ABORTED;
    __u32 key;
    __builtin_memcpy(&key, data, sizeof(key));
```
- **บรรทัด 106–110**: Bounds Check ก่อนอ่าน 4 ไบต์แรกของ "แพ็กเก็ต" มาเป็น Key (บทเรียนจากหัวข้อ 5 — ถ้าลบ `if` นี้ Verifier จะปฏิเสธด้วย `invalid access to packet`) ใช้ `__builtin_memcpy` เพื่อไม่ต้องสนใจ Alignment ของ Packet
- **บรรทัด 112–116**: บวก Key เดียวกันลงทั้ง 3 Map แล้วคืน `XDP_PASS`

### 6.4 อธิบายโค้ดทีละบรรทัด: `maps_testrun/maps_test.go` และ `main_test.go`

```go
if os.Geteuid() != 0 {
    t.Skip("requires root for BPF_PROG_LOAD/BPF_PROG_TEST_RUN; run: make test (go test -exec sudo)")
}
...
t.Cleanup(func() { objs.Close() })
```
- **`maps_test.go` บรรทัด 32–50** (`load`): Skip เมื่อไม่ใช่ root, โหลด Map ชุดใหม่ (ว่างเปล่า) ให้ **ทุกเทสต์** เพื่อไม่ให้ผลของเทสต์หนึ่งรั่วไปอีกเทสต์ และปิด FD อัตโนมัติด้วย `t.Cleanup`

```go
pkt := make([]byte, ethHLen)                 // 14 bytes
binary.NativeEndian.PutUint32(pkt, key)
ret, err := prog.Run(&ebpf.RunOptions{Data: packet(key), Repeat: repeat})
```
- **บรรทัด 53–69**: สร้าง "แพ็กเก็ต" ขนาด 14 ไบต์ (ขั้นต่ำของ XDP test_run) ใส่ Key ใน 4 ไบต์แรกด้วย Byte Order ของเครื่อง (ตรงกับ `__u32` ที่ C อ่าน) แล้วเรียก `BPF_PROG_TEST_RUN` — `Repeat: 1000` ให้เคอร์เนลรันซ้ำ 1000 รอบในการเรียก Syscall ครั้งเดียว

| เทสต์ | สิ่งที่ตรวจ | บทเรียน |
| :--- | :--- | :--- |
| `TestSameKeyCounts` (บรรทัด 102–137) | Key 42 × 1000 รอบ → `hash_map[42]` = `lru_map[42]` = 1000; `percpu_map[42]` คืน Slice ยาว = จำนวน Possible CPU และผลรวม = 1000 | Lookup Per-CPU Map จาก Go ต้องใช้ `[]uint64` แล้วรวมเอง |
| `TestFullMapHashVsLRU` (บรรทัด 141–179) | Key 1..20 (20 Key) ลง Map ขนาด 8 → HASH/PERCPU_HASH มี 8 Entry, Insert ล้มเหลว 12 ครั้งด้วย `-7` (`-E2BIG`), Key 20 ไม่อยู่; LRU มี ≤ 8 Entry, ไม่มี Error, Key 20 (ใหม่สุด) อยู่ | ทำไม Syscall Top ควรใช้ `LRU_HASH` |
| `TestTooShortPacketRejected` (บรรทัด 184–191) | แพ็กเก็ต 13 ไบต์ → `Run()` คืน `EINVAL` | เคอร์เนลตรวจ Input ของ test_run ก่อนรันโปรแกรมด้วย |
| `TestSyscallStatsLoads` (`main_test.go`) | `syscall_stats.c` ผ่าน Verifier, `syscall_map` เป็น Hash key 4B value 24B (= `unsafe.Sizeof(bpfProcStat{})`) max 4096, และ `Run()` คืน `ErrNotSupported` | ตรวจ Memory Layout ในหัวข้อ 1.2 ได้อัตโนมัติ + tracepoint test_run ไม่ได้ |

```go
var prev interface{} // nil = "give me the first key"
for {
    err := m.NextKey(prev, &next)
    if errors.Is(err, ebpf.ErrKeyNotExist) { return n }
    ...
}
```
- **บรรทัด 71–89** (`countEntries`): นับ Entry ด้วย `BPF_MAP_GET_NEXT_KEY` อย่างเดียว (กลไกเดียวกับ `Iterate()` ในหัวข้อ 1.3 แต่ไม่ดึง Value) — ใช้ได้กับ Per-CPU Map โดยไม่ต้องเตรียม Slice

### 6.5 ขั้นตอนการรันเทสต์
```bash
make test                                   # = go generate ./... + go test -exec sudo -v ./...
go test -exec sudo -v -run TestFullMapHashVsLRU ./maps_testrun/   # รันเทสต์เดียว
go test -v ./maps_testrun/                  # ไม่ใช้ sudo -> ทุกเทสต์ถูก SKIP (ไม่ FAIL)
```
`-exec sudo` ให้ `go test` คอมไพล์ไบนารีเทสต์ด้วยสิทธิ์ผู้ใช้ปกติ แล้วรันไบนารีนั้นผ่าน `sudo` (ไม่ต้องรัน Go toolchain ทั้งหมดเป็น root) — จาก Root ของ Repo ใช้ `make week06-test` ได้เช่นกัน

### 6.6 ผลลัพธ์จริง

> **Environment**: Ubuntu 26.04.1 LTS (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`, 8 CPUs), clang 21.1.8, Go 1.26, cilium/ebpf v0.16.0

`make test` (ตัดบรรทัด `Compiled/Stripped/Wrote` ของ bpf2go ออก):
```text
===> Generating Go bindings via bpf2go...
go generate ./...
go test -exec sudo -v ./...
=== RUN   TestSyscallStatsLoads
    main_test.go:48: syscall_map: Hash key=4B value=24B max_entries=4096
    main_test.go:55: BPF_PROG_TEST_RUN on TracePoint program: run program: kernel doesn't support running TracePoint: not supported
--- PASS: TestSyscallStatsLoads (0.00s)
PASS
ok  	ebpf-noob-to-hero/phase03-modern-ebpf-core/week06-ebpf-maps	0.006s
=== RUN   TestSameKeyCounts
    maps_test.go:131: percpu_map[42] on CPU 1 = 1000
--- PASS: TestSameKeyCounts (0.02s)
=== RUN   TestFullMapHashVsLRU
    maps_test.go:160: hash_map: 8 entries, 12 failed inserts, last_err=-7 (-E2BIG)
    maps_test.go:160: percpu_map: 8 entries, 12 failed inserts, last_err=-7 (-E2BIG)
    maps_test.go:178: lru_map: 8 entries after 20 distinct keys, newest key 20 present, 0 failed inserts
--- PASS: TestFullMapHashVsLRU (0.00s)
=== RUN   TestTooShortPacketRejected
    maps_test.go:190: 13-byte packet: run program: invalid argument
--- PASS: TestTooShortPacketRejected (0.00s)
PASS
ok  	ebpf-noob-to-hero/phase03-modern-ebpf-core/week06-ebpf-maps/maps_testrun	0.029s
=== RUN   TestVerifierRejectsBrokenPrograms
=== RUN   TestVerifierRejectsBrokenPrograms/bounds
=== RUN   TestVerifierRejectsBrokenPrograms/nullcheck
=== RUN   TestVerifierRejectsBrokenPrograms/fixed
--- PASS: TestVerifierRejectsBrokenPrograms (0.00s)
    --- PASS: TestVerifierRejectsBrokenPrograms/bounds (0.00s)
    --- PASS: TestVerifierRejectsBrokenPrograms/nullcheck (0.00s)
    --- PASS: TestVerifierRejectsBrokenPrograms/fixed (0.00s)
PASS
ok  	ebpf-noob-to-hero/phase03-modern-ebpf-core/week06-ebpf-maps/verifier_fail	0.006s
```

รันโดยไม่ใช้ `sudo` (`go test -v ./maps_testrun/`):
```text
=== RUN   TestSameKeyCounts
    maps_test.go:103: requires root for BPF_PROG_LOAD/BPF_PROG_TEST_RUN; run: make test (go test -exec sudo)
--- SKIP: TestSameKeyCounts (0.00s)
=== RUN   TestFullMapHashVsLRU
    maps_test.go:142: requires root for BPF_PROG_LOAD/BPF_PROG_TEST_RUN; run: make test (go test -exec sudo)
--- SKIP: TestFullMapHashVsLRU (0.00s)
=== RUN   TestTooShortPacketRejected
    maps_test.go:185: requires root for BPF_PROG_LOAD/BPF_PROG_TEST_RUN; run: make test (go test -exec sudo)
--- SKIP: TestTooShortPacketRejected (0.00s)
PASS
ok  	ebpf-noob-to-hero/phase03-modern-ebpf-core/week06-ebpf-maps/maps_testrun	0.001s
```

ข้อสังเกตจากผลจริง:
- **`percpu_map[42]` ทั้ง 1000 ครั้งไปตกที่ CPU เดียว** แต่เป็น CPU ไหนก็ได้ (ทดลองรันแยกอีก 3 ครั้งได้ CPU 2, 6, 3) เพราะ `Repeat` ทั้งหมดรันภายใน Syscall เดียวบน CPU ของ Thread ที่เรียก (เคอร์เนลปิดการย้าย CPU ระหว่างรอบ Repeat แต่ถ้า Repeat มากจนต้องหยุดพักให้ Scheduler ก็อาจย้าย CPU ได้) เทสต์จึงตรวจเฉพาะ **ผลรวม** ซึ่ง Deterministic (ทดลอง `go test -count=300` ผ่านทุกครั้ง)
- **`-7` = `-E2BIG`**: เมื่อ `HASH`/`PERCPU_HASH` เต็ม Insert ใหม่ล้มเหลวทันที ไม่มีการลบของเก่า — นี่คือสิ่งที่เกิดกับ `syscall_map` (4096 Entry) แบบเงียบๆ ในหัวข้อ 4.2 / Troubleshooting
- **`LRU_HASH` ไม่มี Insert ล้มเหลวเลย** และ Key ใหม่ล่าสุด (20) อยู่ใน Map เสมอ — แต่ "ใครถูกไล่ออก" ไม่ได้ตรงกับ LRU ทางทฤษฎีเป๊ะ (เคอร์เนลใช้ Free List แยกต่อ CPU) เทสต์จึงไม่ Assert ว่า Key 13..20 ต้องอยู่ครบ (ดูแบบฝึกหัดที่ 10)
- Error ของ test_run แยกได้ 2 แบบ: `ErrNotSupported` (ชนิดโปรแกรมไม่รองรับ) กับ `EINVAL` (รองรับ แต่ Input ผิดรูปแบบ)

---

## 7. Milestone Checklist

- [x] เข้าใจโครงสร้างและการทำงานภายในของ `BPF_MAP_TYPE_HASH` ในระดับเคอร์เนล
- [x] ทำความเข้าใจกฎ Struct Padding, Memory Alignment ระหว่าง C และ Go
- [x] เขียน eBPF Program ดักจับ `raw_syscalls/sys_enter` และสกัด Process Metadata
- [x] จัดการข้อมูลใน Map ด้วย `bpf_map_lookup_elem`, `bpf_map_update_elem`, และ Atomic Instructions
- [x] ดึงชื่อโปรแกรมด้วย `bpf_get_current_comm` ได้อย่างถูกต้อง
- [x] พัฒนาตัววนซ้ำอ่านข้อมูลทั้ง Map ใน Userspace ด้วย `Map.Iterate()`
- [x] สร้าง CLI Top-10 Realtime Dashboard พร้อมคำนวณสถิติและสัดส่วนเปอร์เซ็นต์
- [x] โหลด `verifier_fail` ทั้ง 3 กรณี (`make verifier-demo`) และชี้บรรทัดใน Verifier Log ที่เป็นสาเหตุได้ (`r=0`, `map_value_or_null`)
- [x] อธิบายส่วนประกอบของ Log: หมายเลข Instruction, Opcode, Register State หลัง `;`, Source Line จาก BTF และสถิติ `processed N insns`
- [x] บอกได้ว่าชนิดโปรแกรมใดใช้ `BPF_PROG_TEST_RUN` ได้/ไม่ได้ และทำไม `track_syscalls` (tracepoint) จึงทดสอบด้วย test_run ไม่ได้
- [x] `make test` ผ่านทั้ง `TestSyscallStatsLoads`, `TestSameKeyCounts`, `TestFullMapHashVsLRU`, `TestTooShortPacketRejected` และ `TestVerifierRejectsBrokenPrograms`
- [x] อธิบายความต่างของ `HASH` / `PERCPU_HASH` / `LRU_HASH` เมื่อ Map เต็ม และวิธีอ่าน Per-CPU Value จาก Go ได้ จากผลเทสต์จริง

---

## 8. ข้อจำกัดและ Threat Model (Limitations)

- **Map เต็มแบบเงียบ**: `syscall_stats.c` ไม่ตรวจค่าที่คืนจาก `bpf_map_update_elem()` เมื่อ `syscall_map` เต็ม 4,096 Entry โปรเซสใหม่จะหายจากตารางโดยไม่มี Error (พิสูจน์ด้วย `TestFullMapHashVsLRU` ที่ได้ `-E2BIG`)
- **นับหายได้ตอน Insert ครั้งแรก**: Race ระหว่าง CPU ในกิ่ง `else` (หัวข้อ 2.1) ทำให้ค่าอาจต่ำกว่าจริงเล็กน้อย
- **มองเห็นทุกโปรเซสในเครื่อง**: `raw_syscalls/sys_enter` เห็น Syscall ของทุก Container/ผู้ใช้ ชื่อโปรแกรม (`comm`) และ PID อาจเป็นข้อมูลอ่อนไหว ต้องใช้สิทธิ์ root ในการรัน และไม่ควรเปิดผลให้ผู้ใช้ทั่วไปเห็น
- **Overhead**: โปรแกรมทำงานกับทุก Syscall ของทั้งระบบ ใน Workload ที่เรียก Syscall หลักล้านครั้งต่อวินาทีจะมี Overhead ที่วัดได้ — ไม่ได้วัดตัวเลขไว้ในสัปดาห์นี้
- **Verifier Log ขึ้นกับเวอร์ชันเคอร์เนล**: รูปแบบ Register State, ข้อความ Error, ส่วน `Live regs` ของ bpftool และความสามารถของ Verifier (เช่นการยอมรับ ARRAY Lookup โดยไม่เช็ก NULL ในหัวข้อ 5.2) เปลี่ยนไปตามเวอร์ชัน Log ในหัวข้อ 5.6 จับจาก Linux 7.0 เท่านั้น
- **test_run ไม่ใช่สภาพแวดล้อมจริง**: ทดสอบได้เฉพาะ Logic ของโปรแกรมกับ Input ที่เราสร้าง ไม่ได้ทดสอบการ Attach, ลำดับเหตุการณ์จริง หรือ Concurrency ข้าม CPU (`Repeat` รันบน CPU เดียว) และใช้กับ tracepoint/kprobe ไม่ได้

---

## 9. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `fatal error: 'asm/types.h' file not found` ตอน `make generate` | `clang -target bpf` หา `asm/` ของ multiarch ไม่เจอ | `sudo apt install gcc-multilib` หรือเพิ่ม `-cflags "-I/usr/include/x86_64-linux-gnu"` ใน `//go:generate` |
| `Failed to remove memlock limit: failed to set memlock rlimit: operation not permitted` | รันโดยไม่ใช้ `sudo` | `sudo ./bin/syscall-top` |
| `... load program: permission denied: ... R0 invalid mem access 'map_value_or_null'` | ใช้ pointer จาก `bpf_map_lookup_elem()` ของ **Hash Map** โดยไม่ตรวจ `NULL` (Hash lookup คืน `NULL` ได้เสมอ ต่างจาก Array ที่ key คงที่) | คง `if (stat) { ... }` ไว้ทุกครั้ง (ดู Log จริงหัวข้อ 5.6) |
| `invalid access to packet, off=12 size=1, R1(id=0,off=12,r=0)` | อ่าน Packet ก่อนพิสูจน์ว่า `data + N <= data_end` | เพิ่ม `if ((void *)(eth + 1) > data_end) return XDP_PASS;` ก่อนอ่าน |
| `load program: permission denied` แต่ **ไม่มี Log** ให้อ่าน | พิมพ์ Error ด้วย `%v`/`%s` หรือ `log.Fatalf("%v")` | ใช้ `errors.As(err, &ve)` แล้วพิมพ์ `%+v` หรือ `%-20v` (หัวข้อ 5.3) |
| `make verifier-demo` แสดง `Error 1 (ignored)` | `verifier_fail` คืน Exit Code 1 เมื่อโปรแกรมถูกปฏิเสธ (ตั้งใจ) | ปกติ ไม่ใช่ปัญหา |
| เทสต์ขึ้น `--- SKIP` ทั้งหมด | รัน `go test` โดยไม่ใช้ `sudo` | `make test` หรือ `go test -exec sudo -v ./...` |
| `undefined: loadBpf` / `undefined: loadMaptypesObjects` ตอน `go test`/`go vet` | ยังไม่ได้รัน `go generate` (ไฟล์ `*_bpf.go` ถูก `.gitignore`) | `make generate` หรือ `make test` (ทำ generate ให้ก่อน) |
| `kernel doesn't support running TracePoint: not supported` | เรียก `Program.Run()` กับโปรแกรมชนิดที่ไม่มี test_run (tracepoint/kprobe/perf_event) | ย้าย Logic ไปไว้ในโปรแกรมชนิดที่ test_run ได้ (XDP/raw_tp/...) ตามหัวข้อ 6.2 |
| `run program: invalid argument` ตอน `Run()` โปรแกรม XDP | `Data` สั้นกว่า 14 ไบต์ (Ethernet Header) หรือ Input ผิดรูปแบบ | ส่งแพ็กเก็ตอย่างน้อย 14 ไบต์ |
| `Lookup` ของ `percpu_map` ด้วย `uint64` แล้ว Error / ได้ค่าผิด | Per-CPU Map คืนค่าหนึ่งตัวต่อ Possible CPU | ใช้ `[]uint64` แล้วรวมเอง (`TestSameKeyCounts`) |
| COMM แสดงเป็น `bash`/`sh` ทั้งที่เป็นโปรแกรมอื่น | ใช้ `syscall_stats.c` รุ่นเก่าที่บันทึก `comm` แค่ครั้งแรก (ก่อน `execve`) | ใช้รุ่นปัจจุบันที่เรียก `bpf_get_current_comm()` ในกิ่ง `if (stat)` แล้ว `make generate build` ใหม่ |
| ใช้งานไปสักพักแล้วโปรเซสใหม่ **ไม่ขึ้นในตารางเลย** และ `Tracking` ค้างที่ 4096 | Hash Map เต็ม (`max_entries 4096`) และไม่มีใครลบ PID ที่จบไปแล้ว `bpf_map_update_elem()` จึงล้มเหลวเงียบๆ ด้วย `-E2BIG` (โค้ดไม่ได้ตรวจค่าที่คืน — ดู `TestFullMapHashVsLRU`) | ใช้ `BPF_MAP_TYPE_LRU_HASH`, ลบ key ตอนโปรเซสจบ (`sched_process_exit`) หรือให้ Go ลบ PID ที่ไม่มีใน `/proc` ออก (ดูแบบฝึกหัด) |
| `bpftool map dump` แสดง `comm` เป็นตัวเลข | ฟิลด์ประกาศเป็น `__u8[16]` BTF จึงบอกว่าเป็น array ของตัวเลข | ปกติ ไม่ใช่ error (ถ้าเป็น `char[16]` bpftool จะแสดงเป็นสตริง แต่ bpf2go จะสร้าง `[16]int8`) |
| `syscall-top` ติดอันดับต้นๆ เสียเอง | การ iterate map ทีละ key ใช้ `bpf()` syscall 2 ครั้งต่อ entry | ปกติ; ลดได้ด้วย Batch API (`BatchLookup`) หรือรีเฟรชถี่น้อยลง |

> **หมายเหตุ Linux 7.0**: สัปดาห์นี้ใช้ `raw_syscalls/sys_enter` ซึ่งทดสอบแล้วว่าทำงานครบทุก CPU ต่างจาก `syscalls/sys_enter_execve` ที่พบปัญหาจับได้เฉพาะ CPU 0 บนเครื่องทดสอบ (ดู Week 03/05)

---

## 10. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **เปลี่ยนเป็น `BPF_MAP_TYPE_LRU_HASH`**: แก้ชนิด map แล้วลด `max_entries` เหลือ 256 เพื่อให้เห็นผลเร็ว
   - **สิ่งที่ต้องส่ง**: diff + ผล `Tracking N` ที่ไม่เกิน 256 แต่โปรเซสใหม่ (เช่น `python3` วนลูป) ยังขึ้นตาราง
   - **วิธีตรวจ**: `sudo bpftool map list name syscall_map` ต้องแสดง `lru_hash` และ `max_entries 256` และต้องแก้ `TestSyscallStatsLoads` ให้ตรงกับชนิด/ขนาดใหม่จน `make test` ผ่าน
2. **นับเฉพาะ thread แทน process**: เปลี่ยน key เป็น 32 บิตล่างของ `pid_tgid` (TID) แล้วรันโปรแกรมที่มีหลาย thread
   - **สิ่งที่ต้องส่ง**: ผลเปรียบเทียบ key แบบ TGID vs TID สำหรับโปรแกรมเดียวกัน
   - **วิธีตรวจ**: `python3 -c "import threading,os; [threading.Thread(target=lambda: [os.getpid() for _ in range(20000)]).start() for _ in range(4)]"` — แบบ TID ต้องเห็น 4 แถว (ชื่อ `python3`) แต่ละแถว ~20,000
3. **อ่าน Log แล้วแก้เอง**: แก้ `xdp_no_bounds_check` ใน `verifier_fail/verifier_fail.c` ให้โหลดผ่านโดยเพิ่ม Bounds Check เพียงบรรทัดเดียว
   - **สิ่งที่ต้องส่ง**: Diff ของไฟล์ + ผลลัพธ์ `sudo ./bin/verifier_fail -case bounds` ที่ขึ้น `ACCEPTED`
   - **วิธีตรวจ**: `make test` จะ **FAIL** ที่ `TestVerifierRejectsBrokenPrograms/bounds` (เพราะเทสต์คาดว่าโปรแกรมต้องถูกปฏิเสธ) — อธิบายว่าทำไมนี่คือพฤติกรรมที่ถูกต้องของเทสต์ แล้ว Revert กลับ
4. **ทำให้เทสต์พังโดยตั้งใจ**: ใน `maps_testrun/map_types.c` เปลี่ยน `lru_map` เป็น `BPF_MAP_TYPE_HASH` แล้วรัน `make test`
   - **สิ่งที่ต้องส่ง**: Output ของ `TestFullMapHashVsLRU` ที่ FAIL + อธิบายว่า Assertion ข้อไหนจับความต่างของ LRU ได้
   - **วิธีตรวจ**: ข้อความ FAIL ต้องมี `lru_map update errors` หรือ `want the newest key to be present` แล้ว Revert จน `make test` ผ่าน

### ระดับปานกลาง
5. **แก้ Race ตอน insert ครั้งแรก**: ใช้ `bpf_map_update_elem(..., BPF_NOEXIST)` ถ้าคืนค่าไม่ใช่ 0 (มี CPU อื่น insert ไปก่อน) ให้ lookup ใหม่แล้ว `__sync_fetch_and_add`
   - **สิ่งที่ต้องส่ง**: โค้ด + คำอธิบายว่าทำไมแบบเดิมนับหายได้ + ตรวจว่าผ่าน Verifier
   - **วิธีตรวจ**: โปรแกรมโหลดได้ (`make generate build && sudo timeout -s INT 5 ./bin/syscall-top`) และยอดของ `python3` ในแบบฝึกหัดที่ 2 (แบบ TGID) ต้องไม่ต่ำกว่า 80,000 — ทำแบบเดียวกันใน `bump_shared()` ของ `map_types.c` และแยกนับ `-EEXIST` (-17) ออกจาก `-E2BIG`
6. **ลบ PID ที่จบแล้ว**: เพิ่มโปรแกรมที่สองบน `tracepoint/sched/sched_process_exit` ที่ `bpf_map_delete_elem()` เมื่อ thread ที่จบคือ thread หลัก (`pid == tgid`)
   - **สิ่งที่ต้องส่ง**: โค้ด C + Go (attach 2 tracepoint) + ผลที่ `Tracking N` คงที่แทนที่จะโตขึ้นเรื่อยๆ
   - **วิธีตรวจ**: รัน `for i in $(seq 200); do /bin/true; done` แล้ว `Tracking N` ต้องไม่เพิ่มขึ้น ~200
7. **บั๊กใหม่ของคุณเอง**: เพิ่มกรณีที่ 4 ใน `verifier_fail` เช่น อ่าน IPv4 Header ต่อจาก Ethernet โดยเช็ก `eth + 1` แต่ไม่เช็ก `iph + 1` หรือคำนวณ Offset จาก `iph->ihl * 4` แต่ไม่เช็ก `data_end` หลังบวก Offset
   - **สิ่งที่ต้องส่ง**: โปรแกรม C + Entry ใหม่ใน `cases` + Verifier Log จริงพร้อมคำอธิบายว่าบรรทัดไหนบอกสาเหตุ (ค่า `r=` ของ Register ก่อนคำสั่งที่ผิด)
   - **วิธีตรวจ**: เพิ่มกรณีใน `TestVerifierRejectsBrokenPrograms` ที่ตรวจข้อความ Error ของคุณ และ `make test` ผ่าน
8. **ARRAY vs HASH NULL Elision**: เปลี่ยน `pkt_count` ใน `verifier_fail.c` เป็น `BPF_MAP_TYPE_ARRAY` และใช้ Key คงที่ `0` แล้วรัน `-case nullcheck`
   - **สิ่งที่ต้องส่ง**: ผลลัพธ์จริงบนเครื่องของคุณ (ACCEPTED หรือ REJECTED) + ระบุเวอร์ชันเคอร์เนล (`uname -r`) + อธิบายว่าทำไมผลอาจต่างกันบนเคอร์เนลรุ่นเก่า
   - **วิธีตรวจ**: เทียบชนิดของ `R0` หลัง `call bpf_map_lookup_elem` ใน Log ระหว่างสองแบบ (`map_value` vs `map_value_or_null`)

### ระดับท้าทาย
9. **นับแยกตามหมายเลข syscall**: เปลี่ยน key เป็น struct `{__u32 pid; __u32 syscall_id;}` (อ่าน `id` จาก context ของ `raw_syscalls/sys_enter`: struct `{__u64 pad; long id; unsigned long args[6];}` ตาม `/sys/kernel/tracing/events/raw_syscalls/sys_enter/format`) แล้วแสดง Top-3 syscall ของแต่ละโปรเซส
   - **สิ่งที่ต้องส่ง**: โค้ด + ผลที่ `python3` ในขั้นตอนที่ 4 มี syscall 39 (`getpid` บน x86_64) เป็นอันดับ 1
   - **วิธีตรวจ**: เทียบกับ `sudo perf stat -e 'syscalls:sys_enter_getpid' python3 -c "import os; [os.getpid() for _ in range(50000)]"` ซึ่งต้องได้ 50,000
10. **LRU จริงแค่ไหน**: เขียนเทสต์ใหม่ใน `maps_testrun/` ที่ Insert Key 1..20 แล้ว Dump Key ทั้งหมดที่เหลือใน `lru_map` เทียบกับ LRU ทางทฤษฎี (Key 13..20) จากนั้นทำซ้ำโดยล็อก Thread กับ CPU เดียว (`runtime.LockOSThread()` + `unix.SchedSetaffinity`) และทดลองใส่ Flag `BPF_F_NO_COMMON_LRU` ใน `map_flags`
    - **สิ่งที่ต้องส่ง**: ตาราง Key ที่เหลือของแต่ละแบบ (รันอย่างน้อย 5 ครั้ง) + คำอธิบายว่าทำไมผลไม่ตรงทฤษฎี
    - **วิธีตรวจ**: เทสต์ของคุณต้องผ่านด้วย `go test -exec sudo -count=50` (ห้าม Assert ค่าที่ไม่ Deterministic)
11. **อ่านแบบ Batch และวัดผล**: เปลี่ยน `Iterate()` เป็น `BatchLookup` ของ cilium/ebpf แล้ววัดจำนวน `bpf()` syscall ที่ `syscall-top` เรียกต่อรอบ ก่อน/หลัง
    - **สิ่งที่ต้องส่ง**: diff + ตารางจำนวน syscall ต่อรอบ (วัดจริงอย่างน้อย 3 รอบ) เมื่อ map มี ~1,000 entries
    - **วิธีตรวจ**: `sudo strace -c -e trace=bpf -p $(pgrep -f bin/syscall-top) ` ประมาณ 10 วินาที แล้วเทียบ `calls`
12. **ชน Instruction Limit**: เขียนโปรแกรมใน `verifier_fail` ที่วนลูปโดยใช้ขอบเขตเป็นค่า `__u32` ที่อ่านจาก Packet (ไม่มีขอบเขตบนที่ Verifier พิสูจน์ได้) แล้วสังเกตว่า Verifier ตอบอย่างไร จากนั้นเปรียบเทียบกับการใช้ขอบเขตเป็น `__u8` (สูงสุด 255 รอบ), ขอบเขตคงที่ และ `bpf_loop()`
    - **สิ่งที่ต้องส่ง**: Log ก่อน/หลังแก้ (ใช้ `-lines 20`) + ค่า `processed N insns` ของเวอร์ชันที่ผ่าน
    - **วิธีตรวจ**: อธิบายความสัมพันธ์ระหว่างจำนวน Path ที่ Verifier ต้องจำลองกับค่า `processed` และ `total_states`
