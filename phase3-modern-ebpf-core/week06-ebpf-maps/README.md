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
|                            [ Kernel Hash Function: Jenkins/Murmur ]                     |
|                                           |                                             |
|                                           v                                             |
|   BPF_MAP_TYPE_HASH: syscall_map (max_entries = 4096)                                   |
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
2. **Hash Collisions:** เคอร์เนลจัดการการชนกันของแฮช (Collision) ผ่าน Linked-list Chaining ภายในแต่ละ Bucket
3. **Atomic Updates:** การเข้าถึงสล็อตผ่าน `bpf_map_lookup_elem()` จะได้ Pointer ตรงไปยังสล็อตในหน่วยความจำเคอร์เนล เราจึงสามารถใช้ `__sync_fetch_and_add()` ได้ทันที

---

### 1.2 กฎการจัดวางหน่วยความจำและการเรียงตัว (Memory Layout & Struct Padding)

หนึ่งในสาเหตุยอดนิยมที่ทำให้โปรแกรม eBPF แสดงผลข้อมูลใน Userspace ผิดเพี้ยน คือ **Memory Padding และ Alignment ไม่ตรงกันระหว่างภาษา C และภาษา Go**

พิจารณาโครงสร้างข้อมูลของเรา:
```c
struct proc_stat {
    __u64 count;     // 8 bytes (Offset 0)
    char comm[16];   // 16 bytes (Offset 8)
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
    Comm  [16]int8 // หรือ [16]byte
}
```
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
    char comm[16];
};
```
- **บรรทัด 23-26:** กำหนดโครงสร้างข้อมูลสำหรับเก็บสถิติของแต่ละโปรเซส:
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
- **บรรทัด 34-39:** ประกาศ Hash Map ชื่อ `syscall_map`
  - `type, BPF_MAP_TYPE_HASH`: กำหนดประเภทเป็น Hash Map
  - `max_entries, 4096`: จองพื้นที่สำหรับรองรับโปรเซสสูงสุด 4,096 ตัวพร้อมกัน
  - `key, __u32`: คีย์คือ PID (32-bit integer)
  - `value, struct proc_stat`: ค่าคือสถิติที่เรานิยามไว้

```c
SEC("tracepoint/raw_syscalls/sys_enter")
int track_syscalls(void *ctx)
```
- **บรรทัด 45-46:** แนบฟังก์ชัน `track_syscalls` เข้ากับ `raw_syscalls/sys_enter` ซึ่งเป็นจุดตัดที่เคอร์เนลรับคำขอ Syscall ทุกคำขอจากทุกโปรเซสในระบบ ก่อนจะกระจายไปยัง Handler เฉพาะของแต่ละ Syscall

```c
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
```
- **บรรทัด 48-49:** สกัดค่า PID ออกจาก 64-bit ID โดยตัด 32 บิตล่าง (TGID) ออก

```c
    struct proc_stat *stat = bpf_map_lookup_elem(&syscall_map, &pid);
    if (stat) {
        __sync_fetch_and_add(&stat->count, 1);
    } else {
        struct proc_stat init_stat = {};
        init_stat.count = 1;
        bpf_get_current_comm(&init_stat.comm, sizeof(init_stat.comm));
        bpf_map_update_elem(&syscall_map, &pid, &init_stat, BPF_ANY);
    }
```
- **บรรทัด 52-62:** การจัดการสถานะใน Map:
  - `bpf_map_lookup_elem`: ตรวจสอบว่าเคยบันทึก PID นี้ไว้ใน Map หรือยัง
  - **กรณีมีอยู่แล้ว (`if (stat)`):** ใช้ Atomic instruction `__sync_fetch_and_add(&stat->count, 1)` เพื่อเพิ่มตัวนับโดยตรงในเคอร์เนลเมมโมรี ไม่ต้องเขียนทับทั้งโครงสร้าง
  - **กรณีเพิ่งพบครั้งแรก (`else`):**
    - กำหนดค่าเริ่มต้น `count = 1`
    - เรียก `bpf_get_current_comm` เพื่อดึงชื่อโปรแกรมจากโครงสร้าง `task_struct` ของเคอร์เนล
    - เรียก `bpf_map_update_elem` ด้วย Flag `BPF_ANY` เพื่อแทรกข้อมูลคู่ใหม่เข้า Map

---

### 2.2 ไฟล์ `main.go`

```go
type ProcessRecord struct {
	PID   uint32
	Comm  string
	Count uint64
}
```
- **บรรทัด 20-24:** Data Model สำหรับ Userspace ที่แปลง `Comm` จาก Byte Array ใน C ให้เป็น `string` ใน Go เพื่อง่ายต่อการจัดเรียงและพิมพ์ผล

```go
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TrackSyscalls, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to raw_syscalls/sys_enter: %v", err)
	}
	defer tp.Close()
```
- **บรรทัด 43-47:** เชื่อมต่อ eBPF bytecode เข้ากับ Tracepoint ในระบบเคอร์เนล

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
- **บรรทัด 71-89:**
  - สร้าง Iterator เพื่อวนลูปอ่านทุก Record จาก `objs.SyscallMap`
  - ใช้ `bytes.TrimRight(stat.Comm[:], "\x00")` เพื่อลบตัวอักษร Null Byte ใน C string ออก ทำให้ได้ข้อความที่ถูกต้องในภาษา Go
  - สะสมจำนวนผลรวม Syscall ทั้งหมดในตัวแปร `totalSyscalls`

```go
	sort.Slice(records, func(i, j int) bool {
		return records[i].Count > records[j].Count
	})
```
- **บรรทัด 97-99:** เรียงลำดับ Record จากโปรเซสที่เรียก Syscall มากที่สุดลงมาหาน้อยที่สุด

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
- **บรรทัด 102-120:** ล้างหน้าจอและวาด CLI Dashboard ตาราง Top-10 พร้อมแสดงเปอร์เซ็นต์สัดส่วนการเรียกใช้งาน Syscall

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: สร้าง BPF Bindings
```bash
cd phase3-modern-ebpf-core/week06-ebpf-maps
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

**ตัวอย่างหน้าจอผลลัพธ์ Dashboard:**
```text
=================================================================================
 eBPF Syscall Monitor | Time: 21:15:30 | Total Invocations: 85210
=================================================================================
RANK   PID       COMM                SYSCALLS          SHARE (%)   
---------------------------------------------------------------------------------
#1     1042      node                52410                61.51%
#2     3180      dockerd             18902                22.18%
#3     1         systemd              6410                 7.52%
#4     4510      chrome               4820                 5.66%
#5     19204     syscall-top          1840                 2.16%
#6     821       redis-server          450                 0.53%
#7     992       sshd                  210                 0.25%
#8     2891      code                  112                 0.13%
#9     3401      bash                   54                 0.06%
#10    3412      ps                      2                 0.00%
---------------------------------------------------------------------------------
 Tracking 42 active processes in BPF_MAP_TYPE_HASH
```

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
จะสังเกตเห็นโปรเซส `python3` พุ่งขึ้นมาสู่อันดับต้น ๆ ของตาราง Top Syscall ภายใน 2 วินาทีทันที!

### ขั้นตอนที่ 5: ตรวจสอบ Map ด้วย `bpftool`
```bash
# ค้นหา Map ID ของ syscall_map
sudo bpftool map list name syscall_map

# Dump ข้อมูลดิบจากเคอร์เนล
sudo bpftool map dump name syscall_map
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 24.04 LTS (`Linux ebpf-lab 6.8.0-142-generic #142-Ubuntu SMP PREEMPT_DYNAMIC aarch64`)

### 4.1 ผลลัพธ์การรัน `./bin/syscall-top` ขณะจำลอง Syscall Load
```text
======================================================================
 eBPF Syscall Top Monitor (BPF_MAP_TYPE_HASH + Cilium ebpf-go)
======================================================================
2026/10/18 13:38:52 Successfully attached to tracepoint 'raw_syscalls/sys_enter'!
2026/10/18 13:38:52 Collecting syscall frequencies across all processes... (Press Ctrl+C to stop)

=================================================================================
 eBPF Syscall Monitor | Time: 13:38:54 | Total Invocations: 50934
=================================================================================
RANK   PID       COMM                SYSCALLS          SHARE (%)   
---------------------------------------------------------------------------------
#1     4062      bash                50547              99.24%
#2     4063      bash                117                 0.23%
#3     996       containerd          106                 0.21%
#4     4054      syscall-top         79                  0.16%
#5     3917      bash                45                  0.09%
#6     359       multipathd          16                  0.03%
#7     886       rootlesskit         9                   0.02%
#8     3542      gmain               6                   0.01%
#9     725       gmain               4                   0.01%
#10    4055      sleep               3                   0.01%
---------------------------------------------------------------------------------
 Tracking 11 active processes in BPF_MAP_TYPE_HASH

Received signal 'terminated'. Rendering final report...
=================================================================================
 eBPF Syscall Monitor | Time: 13:38:56 | Total Invocations: 53064
=================================================================================
RANK   PID       COMM                SYSCALLS          SHARE (%)   
---------------------------------------------------------------------------------
#1     4062      bash                50547              95.26%
#2     4068      bash                403                 0.76%
#3     4065      bash                347                 0.65%
#4     996       containerd          239                 0.45%
#5     4054      syscall-top         235                 0.44%
#6     723       lima-guestagent     159                 0.30%
#7     4069      bash                152                 0.29%
#8     4070      bpftool             149                 0.28%
#9     4066      bpftool             148                 0.28%
#10    4071      bpftool             148                 0.28%
---------------------------------------------------------------------------------
 Tracking 21 active processes in BPF_MAP_TYPE_HASH

Shutting down eBPF monitor cleanly.
```

---

## 5. Milestone Checklist

- [x] เข้าใจโครงสร้างและการทำงานภายในของ `BPF_MAP_TYPE_HASH` ในระดับเคอร์เนล
- [x] ทำความเข้าใจกฎ Struct Padding, Memory Alignment ระหว่าง C และ Go
- [x] เขียน eBPF Program ดักจับ `raw_syscalls/sys_enter` และสกัด Process Metadata
- [x] จัดการข้อมูลใน Map ด้วย `bpf_map_lookup_elem`, `bpf_map_update_elem`, และ Atomic Instructions
- [x] ดึงชื่อโปรแกรมด้วย `bpf_get_current_comm` ได้อย่างถูกต้อง
- [x] พัฒนาตัววนซ้ำอ่านข้อมูลทั้ง Map ใน Userspace ด้วย `Map.Iterate()`
- [x] สร้าง CLI Top-10 Realtime Dashboard พร้อมคำนวณสถิติและสัดส่วนเปอร์เซ็นต์
