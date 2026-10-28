# สัปดาห์ที่ 23: การสำรวจเคอร์เนลด้วย BPF Iterators (`iter/task`) แทนการเดิน `/proc`

ยินดีต้อนรับสู่ **Week 23** ของหลักสูตร eBPF Zero to Hero!

ถ้าเราต้องการรายชื่อโปรเซสทั้งหมดพร้อม UID และขนาดหน่วยความจำ เครื่องมืออย่าง `ps` หรือ `top` ต้อง `getdents()` ไดเรกทอรี `/proc` แล้ว `open()` + `read()` + `close()` ไฟล์ `/proc/<pid>/status` (หรือ `stat`) **ทีละโปรเซส** เคอร์เนลต้องจัดรูปข้อความทุกฟิลด์ของทุกไฟล์ แม้เราจะใช้แค่ 3–4 ฟิลด์ก็ตาม

ในสัปดาห์นี้ เราจะใช้ **BPF Iterators (`bpf_iter`, Linux 5.8+)**:
1. ให้โปรแกรม eBPF ถูกเรียก **1 ครั้งต่อ 1 object** ในเคอร์เนล (ในที่นี้คือ `task_struct`) ขณะเคอร์เนลเดินรายการให้เอง
2. โปรแกรมเลือกเฉพาะฟิลด์ที่ต้องการ แล้วจัดรูปด้วย `BPF_SEQ_PRINTF()` ลงใน **seq_file** เดียว
3. Userspace อ่านผลลัพธ์ทั้งหมดผ่าน file descriptor เดียว เหมือนอ่านไฟล์ข้อความธรรมดา

แล้วเราจะ **วัดเปรียบเทียบจริง** กับการเดิน `/proc` แบบที่ `ps` ทำ

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 ปัญหาของ procfs

```
ps / top (userspace)                          Kernel
---------------------                         ---------------------------------
getdents64("/proc")            ----------->   list PIDs
for each pid:
   openat("/proc/<pid>/status") ---------->   lookup task, alloc file
   read(...)                    ---------->   format ~60 lines เป็นข้อความ
   close(...)                   ---------->   free
parse text -> เลือก 4 ฟิลด์
```
จำนวน syscall โตตามจำนวนโปรเซส (O(N) ครั้ง × 3+ syscall) และงานจัดรูปข้อความส่วนใหญ่ถูกทิ้ง ในการทดลองของเรา (หัวข้อ 4.3) การเดิน `/proc` ใช้ **321 `openat()` + 1,089 `read()`** เพื่อให้ได้ข้อมูล ~160 โปรเซส

### 1.2 BPF Iterator ทำงานอย่างไร

```
Userspace (Go)                      Kernel
-----------------                   ----------------------------------------------------------
BPF_PROG_LOAD (iter/task) -------> verifier ตรวจ: ctx = struct bpf_iter__task (BTF)
BPF_LINK_CREATE ----------------->  สร้าง iter link (ยังไม่ทำงาน)
BPF_ITER_CREATE -----------------> สร้าง anon file + seq_file (1 fd)    <-- link.Iter.Open()
read(fd) ------------------------>  seq_file ->start/next: เดิน task ถัดไป
                                     -> เรียก dump_task(ctx{meta, task})  ทีละ task
                                     -> BPF_SEQ_PRINTF() เขียนลง seq buffer
                     <-------------  คืนข้อความใน buffer
read(fd) ... จนได้ 0 (EOF)          -> สุดท้ายเรียกโปรแกรมอีกครั้งด้วย task == NULL
```

จุดสำคัญ:
- **ไม่มีอะไรรันเบื้องหลัง:** iterator ทำงาน **เฉพาะตอนที่มีคน `read()`** และทุกครั้งที่ `Open()` ใหม่ (`BPF_ITER_CREATE`) เคอร์เนลจะเริ่มเดินตั้งแต่ต้นอีกรอบ — จึงใช้ link เดิม `Open()` ซ้ำเพื่อ "รีเฟรช" ได้
- **ยังมี syscall และ context switch:** การอ่านยังต้องผ่าน `read()` หลายครั้ง (ในการทดลองคือ 16 ครั้ง เพราะ `io.ReadAll` เริ่มด้วยบัฟเฟอร์ 512 ไบต์) แต่จำนวนไม่ขึ้นกับจำนวนโปรเซส ขึ้นกับขนาดข้อความเท่านั้น ชื่อเดิมของแล็บที่ว่า "Zero-Context-Switch" จึงไม่ถูกต้องตามตัวอักษร
- **`ctx->meta->seq_num`** คือลำดับการเรียกในรอบนั้น (เริ่มที่ 0) เราใช้พิมพ์หัวตารางครั้งเดียว
- **ตอนจบ** เคอร์เนลเรียกโปรแกรมอีกครั้งด้วย `ctx->task == NULL` เพื่อให้มีโอกาสพิมพ์สรุป/footer — โปรแกรมต้องเช็ก NULL ก่อนใช้เสมอ (verifier บังคับ เพราะ BTF ระบุว่า field นี้เป็น `PTR_TO_BTF_ID_OR_NULL`)

### 1.3 `iter/task` เดินทุก thread ไม่ใช่ทุก process

ใน Linux ทุก thread คือ `task_struct` หนึ่งตัว `iter/task` จึงเรียกโปรแกรม **ต่อ thread** โปรเซส Go ที่มี 11 threads จะถูกเรียก 11 ครั้ง ด้วย `task->tgid` เดียวกัน

เวอร์ชันแรกของแล็บนี้ไม่ได้กรองจุดนี้ ผลคือ PID เดียวกันซ้ำหลายสิบบรรทัด (วัดได้ 603 แถวสำหรับเพียง 159 PID บนเครื่องทดสอบ บาง PID ซ้ำถึง 24 ครั้ง) วิธีแก้คือเลือกเฉพาะ **thread group leader** (`task->pid == task->tgid`) แล้วอ่านจำนวน thread จาก `task->signal->nr_threads`

> [!NOTE]
> เคอร์เนลรุ่นใหม่ (6.1+) รองรับ option ตอนสร้าง iterator ให้เดินเฉพาะ thread ของ PID/TID ที่ระบุ (`bpf_iter_link_info.task`) แต่ไม่มีโหมด "เฉพาะ leader" การกรองในโปรแกรมจึงยังจำเป็น

### 1.4 ประเภทของ iterator อื่น ๆ

| Target | เดินอะไร | ใช้ทำอะไร |
|---|---|---|
| `iter/task` | ทุก `task_struct` | process table, ตรวจ credential |
| `iter/task_file` | ทุก fd ของทุก task | หา socket/ไฟล์ที่เปิดค้าง (แบบ `lsof`) |
| `iter/task_vma` | ทุก VMA ของทุก task | แผนที่หน่วยความจำ (แบบ `/proc/pid/maps`) |
| `iter/tcp`, `iter/udp`, `iter/unix` | ทุก socket | แทน `ss` / `/proc/net/tcp` |
| `iter/bpf_map_elem` | ทุก element ของ map | dump map ในรูปแบบที่กำหนดเอง |
| `iter/bpf_prog`, `iter/bpf_map`, `iter/bpf_link` | object ของ BPF | audit ว่ามีโปรแกรม BPF อะไรโหลดอยู่ (เชื่อมกับ Week 16) |

ดูรายการทั้งหมดบนเครื่องได้ด้วย `sudo bpftool btf dump file /sys/kernel/btf/vmlinux | grep -o 'bpf_iter__[a-z0-9_]*' | sort -u` (บน Linux 7.0 ได้ 18 target เช่น `cgroup`, `kmem_cache`, `ksym`, `dmabuf`, `netlink` — ไม่นับ `bpf_iter__task__safe_trusted` ซึ่งเป็น type ภายในของ verifier)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `task_iter.c`

```c
#define PF_KTHREAD 0x00200000
```
- **บรรทัด 9:** `vmlinux.h` มีเฉพาะ **type** จาก BTF ไม่มี `#define` ของเคอร์เนล จึงต้องประกาศค่าแฟล็ก `PF_KTHREAD` เอง (ค่าจาก `include/linux/sched.h`)

```c
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
```
- **บรรทัด 17-21:** `SEC("iter/task")` = โปรแกรมชนิด `BPF_PROG_TYPE_TRACING` attach type `BPF_TRACE_ITER` ไปยัง target `task` ตัว `ctx` เป็น `struct bpf_iter__task` ซึ่งมี `meta` (มี `seq` และ `seq_num`) และ `task`

```c
    if (ctx->meta->seq_num == 0) {
        BPF_SEQ_PRINTF(seq, "%-8s %-8s %-8s %-12s %-16s\n",
                       "PID", "UID", "THREADS", "VM_SIZE_KB", "COMM");
    }
```
- **บรรทัด 24-27:** พิมพ์หัวตารางครั้งเดียวในการเรียกแรก ทำให้ไฟล์ iterator ที่ pin ไว้ (`bpftool iter pin`) อ่านด้วย `cat` แล้วได้ตารางสมบูรณ์โดยไม่ต้องมีโปรแกรม Go

```c
    if (!task) {
        return 0;
    }
    if (task->pid != task->tgid) {
        return 0;
    }
    if ((task->flags & PF_KTHREAD) || !task->mm) {
        return 0;
    }
```
- **บรรทัด 30-45:**
  - `task == NULL` คือการเรียกปิดท้าย iteration
  - กรองให้เหลือเฉพาะ thread group leader (แก้บั๊ก PID ซ้ำ)
  - ข้าม kernel threads (`PF_KTHREAD`) และ task ที่ไม่มี `mm` (เช่น zombie ที่ `exit_mm()` ไปแล้ว) — เวอร์ชันเดิมเช็กแค่ `!task->mm` ซึ่งพลาดกรณี kernel thread ที่ยืม mm ชั่วคราวผ่าน `kthread_use_mm()`

```c
    __u32 pid = task->tgid;
    __u32 uid = task->real_cred->uid.val;
    int nr_threads = task->signal->nr_threads;
    unsigned long vm_size_kb = task->mm->total_vm << (12 - 10);
```
- **บรรทัด 47-52:** อ่าน field ผ่านพอยน์เตอร์ได้ตรง ๆ (`task->real_cred->uid.val`) เพราะ `task` เป็น trusted BTF pointer — verifier แปลงเป็น load แบบ "probe" ที่ไม่ทำให้เคอร์เนลล่มแม้พอยน์เตอร์ระหว่างทางเป็น NULL (ได้ค่า 0 แทน)
  - `uid` คือ kuid ในมุมมองของ init user namespace (ถ้าโปรเซสอยู่ใน user namespace ค่าจะต่างจากที่มันเห็นเอง)
  - `total_vm` เป็นจำนวน **หน้า** — คูณเป็น KiB โดยสมมติหน้า 4 KiB (ถูกบน x86-64; arm64 ที่ใช้หน้า 16K/64K จะผิด) ค่านี้ตรงกับ `VSZ` ของ `ps` ไม่ใช่ RSS

```c
    BPF_SEQ_PRINTF(seq, "%-8u %-8u %-8d %-12lu %-16s\n",
                   pid, uid, nr_threads, vm_size_kb, task->comm);
```
- **บรรทัด 58-59:** `BPF_SEQ_PRINTF` เป็นมาโครห่อ helper `bpf_seq_printf()`: อาร์กิวเมนต์ทั้งหมดถูกจัดเป็นอาร์เรย์ `u64` (สูงสุด 12 ตัว) และ `%s` ถูกอ่านแบบปลอดภัยจากหน่วยความจำเคอร์เนล ใช้ `%u` กับ `__u32` ให้ตรงชนิด

### 2.2 ไฟล์ `main.go`

```go
func readIter(it *link.Iter) ([]byte, error) {
	rd, err := it.Open()
	...
	return io.ReadAll(rd)
}
```
- **บรรทัด 25-32:** `it.Open()` เรียก `BPF_ITER_CREATE` ได้ fd ใหม่ (= iteration ใหม่) แล้วอ่านจน EOF

```go
func procfsWalk() (procs int, files int, err error) {
	entries, err := os.ReadDir("/proc")
	...
		data, err := os.ReadFile("/proc/" + name + "/status")
```
- **บรรทัด 36-58:** baseline สำหรับเปรียบเทียบ ทำแบบเดียวกับ `ps`: อ่าน `/proc/<pid>/status` ทุกโปรเซส นับเฉพาะโปรเซสที่มีบรรทัด `VmSize:` (kernel thread ไม่มี) เพื่อให้จำนวนเทียบกับ iterator ได้

```go
	it, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTask,
	})
```
- **บรรทัด 90-92:** สร้าง iter link (`BPF_LINK_CREATE`) ยังไม่มีการเดิน task จนกว่าจะ `Open()` + `read()`

```go
	for i := 0; i < *runs; i++ {
		start := time.Now()
		out, err := readIter(it)
```
- **บรรทัด 100-124:** จับเวลาทั้งสองวิธี `-runs` รอบ (ค่าเริ่มต้น 5) แล้วรายงานค่า **best-of-N** เพื่อลดผลจาก noise; รอบแรกของ procfs มัก cold กว่า

### 2.3 ไฟล์ `main_test.go` (runtime test)

รัน iterator จริงแล้วตรวจว่า: หัวตารางมี 1 ครั้ง, **ทุก PID ปรากฏครั้งเดียว** (ป้องกันบั๊ก thread ซ้ำกลับมา), มี PID 1 และพบ PID ของ process เทสต์เองที่ `THREADS > 1` (Go runtime มีหลาย thread เสมอ)

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจว่าเคอร์เนลรองรับ `iter/task`
```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep "STRUCT 'bpf_iter__task'"
```

### ขั้นตอนที่ 2: คอมไพล์และรันเทสต์
```bash
cd phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators
make generate && make build
make test          # = go test -exec sudo -v ./...
```

### ขั้นตอนที่ 3: รันโปรแกรม
```bash
sudo ./bin/task-iter              # ตาราง + สรุปเวลา
sudo ./bin/task-iter -quiet       # สรุปเวลาอย่างเดียว
sudo ./bin/task-iter -runs 20     # จับเวลา 20 รอบ
```

### ขั้นตอนที่ 4: เทียบความถูกต้องกับ `ps`
```bash
sudo ./bin/task-iter | grep -w systemd | head -3
ps -o pid,uid,nlwp,vsz,comm -p 1
```
ค่า `THREADS` ต้องตรงกับ `NLWP` และ `VM_SIZE_KB` ต้องตรงกับ `VSZ`

### ขั้นตอนที่ 5: Pin iterator เป็นไฟล์ แล้วอ่านด้วย `cat` (ไม่ต้องใช้ Go)
```bash
sudo bpftool iter pin bpf_bpfel.o /sys/fs/bpf/w23_tasks
sudo head -4 /sys/fs/bpf/w23_tasks       # ทุกครั้งที่อ่าน = iteration ใหม่
sudo rm /sys/fs/bpf/w23_tasks            # ถอด pin (โปรแกรมถูก unload เมื่อไม่มีใครอ้างถึง)
```

### ขั้นตอนที่ 6 (ทางเลือก): นับ syscall ของสองวิธี
```bash
sudo strace -f -c -e trace=bpf,openat,read ./bin/task-iter -quiet -runs 1
```
`-c` ให้ผลรวมของทั้งสองวิธี (รวม syscall ตอน Go runtime เริ่มทำงานด้วย) ถ้าต้องการแยก ให้ใช้ `strace -f -o trace.txt ...` แล้วนับ `read(` ระหว่างบรรทัด `BPF_ITER_CREATE` กับบรรทัด `openat(AT_FDCWD, "/proc"` แรก (ช่วง iterator) และหลังจากนั้น (ช่วง procfs) ซึ่งเป็นวิธีที่ใช้ได้ตัวเลขในหัวข้อ 4.3

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), Intel Core i3-12100 — เครื่องมีงานอื่นรันอยู่ระหว่างทดลอง

### 4.1 `make test`
```text
=== RUN   TestTaskIterOneRowPerProcess
    main_test.go:90: 161 processes listed; own pid 4117181 has 11 threads
--- PASS: TestTaskIterOneRowPerProcess (0.10s)
PASS
ok  	ebpf-noob-to-hero/phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators	0.104s
```

### 4.2 `sudo ./bin/task-iter` (ตัดแถวกลางออก)
```text
======================================================================
 eBPF Kernel Task Iterator (iter/task) vs procfs walk
======================================================================
PID      UID      THREADS  VM_SIZE_KB   COMM            
1        0        1        27192        systemd         
1844     103      1        6888         avahi-daemon    
1845     0        1        2888         chronyd-starter 
1846     995      1        12312        dbus-daemon     
1852     0        1        49444        networkd-dispat 
1854     979      4        383560       polkitd         
1868     0        4        312132       accounts-daemon 
1870     0        1        9660         cron            
1871     0        4        310580       switcheroo-cont 
1876     0        1        19608        systemd-logind  
...
4120881  0        1        16112        sleep           
4120882  0        1        16112        sleep           
----------------------------------------------------------------------
[iter/task ]  164 processes,    9405 bytes in 1 seq_file, best of 5: 120.236µs
[procfs    ]  163 processes,  330 x /proc/<pid>/status files, best of 5: 2.672497ms
(ตัวเลขขึ้นกับจำนวนโปรเซสและ load ของเครื่อง; procfs อ่านข้อมูลมากกว่าที่ iterator พิมพ์)
```

### 4.3 รันซ้ำ 3 ครั้ง (`-quiet`) และนับ syscall

```text
[iter/task ]  168 processes,    9633 bytes in 1 seq_file, best of 5: 167.526µs
[procfs    ]  164 processes,  333 x /proc/<pid>/status files, best of 5: 2.551551ms
[iter/task ]  166 processes,    9519 bytes in 1 seq_file, best of 5: 145.925µs
[procfs    ]  166 processes,  333 x /proc/<pid>/status files, best of 5: 2.462723ms
[iter/task ]  166 processes,    9519 bytes in 1 seq_file, best of 5: 131.742µs
[procfs    ]  166 processes,  333 x /proc/<pid>/status files, best of 5: 2.632362ms
```

จาก `strace -f` ของการรัน `-runs 1` หนึ่งครั้ง (นับแยกช่วง):

| วิธี | syscall ที่ใช้ |
|---|---|
| iterator | `bpf(BPF_ITER_CREATE)` 1 ครั้ง + `read()` 16 ครั้ง |
| procfs walk | `openat()` 321 ครั้ง + `read()` 1,089 ครั้ง (+ `close()`, `getdents64()`) |

**การตีความ:**
- บนเครื่องนี้ iterator เร็วกว่าการเดิน `/proc/<pid>/status` ราว **15–22 เท่า** (~120–170 µs เทียบ ~2.5–2.7 ms สำหรับ ~165 โปรเซส) — แต่ **ไม่ใช่การเปรียบเทียบงานที่เท่ากันทุกประการ**: `status` มีหลายสิบฟิลด์ (~60 บรรทัด) ที่เคอร์เนลต้องจัดรูป (รวมการนับหน่วยความจำบางส่วน) ขณะที่ iterator พิมพ์แค่ 5 ฟิลด์ ข้อได้เปรียบส่วนใหญ่จึงมาจาก "เลือกเฉพาะสิ่งที่ต้องการ + ไม่ต้อง open/close ไฟล์ต่อโปรเซส"
- จำนวนโปรเซสของสองวิธีต่างกัน 1–4 เพราะวัดคนละจังหวะเวลา (โปรเซสอายุสั้นเกิด/ตายระหว่างวัด) — iterator ไม่ใช่ snapshot แบบ atomic ของทั้งระบบ
- 309 µs ในผลลัพธ์ฉบับก่อนของ README เป็นการวัดครั้งเดียว (cold) ด้วยโค้ดเดิมที่ยังพิมพ์ทุก thread (ข้อความยาวกว่า ~3 เท่า) ตัวเลขชุดนี้ใช้ best-of-5 ของโค้ดที่แก้แล้ว จึงเทียบกันตรง ๆ ไม่ได้

---

## 5. ข้อจำกัด (Limitations)

1. **ไม่ใช่ snapshot แบบ atomic:** เคอร์เนลเดิน task list ภายใต้ RCU ทีละตัว โปรเซสที่เกิด/ตายระหว่างเดินอาจถูกนับหรือไม่ถูกนับ (เหมือน `/proc`)
2. **`iter/task` = ต่อ thread:** ต้องกรอง leader เองถ้าต้องการต่อโปรเซส ระบบที่มี thread มาก ๆ (เช่น JVM หลายพัน thread) โปรแกรมจะถูกเรียกหลายพันครั้งแม้แสดงผลแถวเดียว
3. **ผูกกับ layout ภายในเคอร์เนล:** ฟิลด์อย่าง `task->signal->nr_threads`, `mm->total_vm` ไม่ใช่ ABI; CO-RE ช่วยเรื่อง offset แต่ถ้าฟิลด์ถูกลบหรือเปลี่ยนความหมาย โปรแกรมจะโหลดไม่ผ่าน (ต่างจาก `/proc` ที่เป็น ABI เสถียร)
4. **สมมติหน้า 4 KiB:** `<< (12 - 10)` ผิดบนสถาปัตยกรรมที่ page size ต่างไป
5. **UID เป็นมุมมองของ init user namespace** และไม่ได้แสดง RSS (ต้องรวม `mm->rss_stat` ซึ่งเป็น per-CPU counter ซับซ้อนกว่า)
6. **ต้องการสิทธิ์ root:** (`CAP_BPF` + `CAP_PERFMON` เป็นอย่างน้อย) — เครื่องมือแบบ `ps` สำหรับผู้ใช้ทั่วไปจึงยังต้องใช้ `/proc`
7. **`BPF_SEQ_PRINTF` จำกัด 12 อาร์กิวเมนต์ต่อบรรทัด** และ output ทั้งหมดเป็นข้อความ ถ้าต้องการข้อมูลแบบ binary ให้ใช้ `bpf_seq_write()` แทน
8. ตัวเลขเวลาวัดบนเครื่องเดียวที่มี load อื่น ควรวัดซ้ำบนเครื่องของตัวเองก่อนอ้างอิง

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| PID เดียวกันซ้ำหลายบรรทัด | ลืมกรอง `task->pid != task->tgid` (`iter/task` เดินทุก thread) |
| `load program: permission denied: ... R7 invalid mem access 'trusted_ptr_or_null_'` | ใช้ `ctx->task` โดยไม่เช็ก NULL ก่อน (การเรียกสุดท้ายของ iteration ส่ง NULL) |
| `fatal error: 'vmlinux.h' file not found` | `make vmlinux` ที่ root ของ repo |
| `use of undeclared identifier 'PF_KTHREAD'` | macro ไม่อยู่ใน `vmlinux.h` ต้อง `#define` เอง |
| `ls: cannot open directory '/sys/fs/bpf/': Permission denied` | bpffs อ่านได้เฉพาะ root ใช้ `sudo ls /sys/fs/bpf` |
| คำเตือน `vmlinux.h:...: warning: declaration does not declare anything` ตอน `make generate` | มาจาก `vmlinux.h` ที่ dump จากเคอร์เนล 7.0 กับ clang 21 ไม่กระทบผลลัพธ์ |

---

## 7. Milestone Checklist

- [x] อธิบายต้นทุนของการเดิน `/proc` และหลักการของ BPF iterator (seq_file, `BPF_ITER_CREATE`, ทำงานเมื่อ `read()` เท่านั้น)
- [x] เขียนโปรแกรม `iter/task` ที่จัดการ `seq_num == 0` (header) และ `task == NULL` (จบ iteration)
- [x] เข้าใจว่า `iter/task` เดินทุก thread และกรองให้เหลือ 1 แถวต่อโปรเซส
- [x] อ่านฟิลด์ใน `task_struct` ผ่าน BTF pointer (`real_cred`, `signal`, `mm`) ได้ถูกต้อง
- [x] ใช้ `link.AttachIter` + `Open()` ซ้ำเพื่อรีเฟรชข้อมูล และ pin iterator เป็นไฟล์ด้วย `bpftool iter pin`
- [x] วัดเวลาและจำนวน syscall เทียบกับ procfs พร้อมระบุข้อจำกัดของการเปรียบเทียบ
- [x] ตรวจความถูกต้องด้วย runtime test (`make test`)

---

## 8. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **เพิ่มคอลัมน์ PPID:** อ่าน `task->real_parent->tgid` แล้วพิมพ์เป็นคอลัมน์ใหม่ 
   - **ตรวจสอบ:** เปรียบเทียบกับ `ps -o pid,ppid -p <pid>` สำหรับ 3 โปรเซสใดก็ได้ ต้องตรงกันทุกตัว
2. **กรองตาม UID:** แสดงเฉพาะโปรเซสของผู้ใช้ที่ UID = 1000 (ใช้ `const volatile __u32 target_uid` ตั้งค่าจาก Go ก่อนโหลด) 
   - **ตรวจสอบ:** จำนวนแถวต้องเท่ากับ `ps -u 1000 --no-headers | wc -l` (คลาดได้ ±2 จากโปรเซสอายุสั้น)

### ระดับปานกลาง
1. **นับ fd ต่อโปรเซสด้วย `iter/task_file`:** เขียนโปรแกรมใหม่ที่นับจำนวนไฟล์ที่เปิดอยู่ของแต่ละโปรเซส (ระวัง: target นี้ก็เรียกต่อ fd ของทุก thread) แล้วพิมพ์ 10 อันดับแรกฝั่ง Go 
   - **ตรวจสอบ:** เทียบกับ `sudo ls /proc/<pid>/fd | wc -l` ของโปรเซสอันดับ 1
2. **ทำให้การเปรียบเทียบยุติธรรมขึ้น:** เปลี่ยน baseline ให้อ่าน `/proc/<pid>/stat` (ไฟล์บรรทัดเดียว) แทน `status` แล้วรายงานเวลาทั้งสองแบบ 
   - **ตรวจสอบ:** ตารางผลที่มีค่า best-of-10 ของ iterator, `/proc/*/stat`, `/proc/*/status` และอธิบายว่าอัตราส่วนเปลี่ยนไปเท่าไรและเพราะอะไร

### ระดับท้าทาย
1. **`ss` ฉบับ eBPF ด้วย `iter/tcp`:** พิมพ์ socket TCP ทุกตัว (local/remote address:port, state, uid) ในรูปแบบคล้าย `ss -tan` 
   - **ตรวจสอบ:** เปิด `python3 -m http.server 8099` แล้วต้องเห็นแถว LISTEN บนพอร์ต 8099 และจำนวน socket ใกล้เคียง `ss -tan | tail -n +2 | wc -l`
2. **Audit โปรแกรม BPF ด้วย `iter/bpf_prog`:** เขียน iterator ที่แสดงโปรแกรม BPF ทุกตัวที่โหลดอยู่ (id, type, name) เชื่อมโยงกับแนวคิด integrity audit ของ Week 16 
   - **ตรวจสอบ:** รายการต้องตรงกับ `sudo bpftool prog show` (ยกเว้นโปรแกรมที่ถูกโหลด/ถอดระหว่างวัด) และต้องเห็นโปรแกรม iterator ของตัวเองในรายการด้วย
