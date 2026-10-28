# Week 18: On-CPU Profiler ด้วย perf_event + Stack Traces และการสร้าง Flame Graph

ยินดีต้อนรับสู่สัปดาห์ที่ 18 ของหลักสูตร **eBPF: Zero-to-Hero** เมื่อระบบเกิดอาการ CPU พุ่ง เครื่องมืออย่าง `top` บอกได้เพียงว่า "โปรเซสไหน" กิน CPU แต่ไม่บอกว่า **"ฟังก์ชันไหน และถูกเรียกมาจากเส้นทางใด"** คำตอบของคำถามนี้คือ **Sampling Profiler** และภาพที่นักวิเคราะห์ประสิทธิภาพทั่วโลกใช้อ่านผลคือ **Flame Graph**

ในบทนี้เราจะสร้าง On-CPU Profiler แบบเดียวกับ `profile` ของ BCC/libbpf-tools โดย:
1. เปิด **`perf_event_open(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK)`** ที่ความถี่ 99 Hz บน **ทุก CPU** จากฝั่ง Go
2. แนบโปรแกรม eBPF ชนิด **`SEC("perf_event")`** ที่ถูกเรียกทุกครั้งที่นาฬิกาครบรอบ แล้วเก็บ **kernel stack + user stack** ด้วย `bpf_get_stackid()` ลงใน `BPF_MAP_TYPE_STACK_TRACE`
3. รวมจำนวน sample ต่อ call chain ในเคอร์เนล (ไม่ต้องส่งทุก sample ขึ้น userspace)
4. แปลงที่อยู่เป็นชื่อฟังก์ชัน (kernel ผ่าน `/proc/kallsyms`, user ผ่าน `/proc/<pid>/maps` + ELF symbol table)
5. ส่งออกเป็น **folded stacks** (`-folded out.txt`) ที่ป้อนเข้า `flamegraph.pl` ได้ทันที

> [!IMPORTANT]
> เวอร์ชันก่อนหน้าของแล็บนี้ hook ที่ `tracepoint/sched/sched_switch` ซึ่ง **ไม่ใช่ On-CPU profiling** (ดูหัวข้อ 1.2) — เวอร์ชันนี้เขียนใหม่ให้สุ่มด้วย perf_event จริงตามที่ชื่อบทเรียนสัญญาไว้

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 Sampling Profiler ทำงานอย่างไร

แทนที่จะจับเวลาทุกฟังก์ชัน (instrumentation ซึ่งแพงมาก) Sampling Profiler จะ "ถ่ายภาพ" สิ่งที่ CPU กำลังทำอยู่เป็นระยะ ๆ:

```
 CPU 0 timeline  ──┬──────────┬──────────┬──────────┬──────────┬──>  (ทุก ~10.1 ms ที่ 99 Hz)
                   │          │          │          │          │
            hrtimer interrupt (PERF_COUNT_SW_CPU_CLOCK ครบรอบ)
                   │
                   v
 +-------------------------------------------------------------------------+
 | perf_event overflow  ->  เรียกโปรแกรม eBPF SEC("perf_event")              |
 |                                                                         |
 |   ctx->regs = register ของงานที่ "กำลังรันอยู่" ตอนถูกขัดจังหวะ             |
 |                                                                         |
 |   bpf_get_stackid(ctx, &stack_traces, 0)                 -> kernel stack |
 |   bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK)  -> user stack   |
 |        (เคอร์เนลเดิน frame pointer / ORC แล้วเก็บ IP ลง STACK_TRACE map)   |
 |                                                                         |
 |   stack_counts[{pid, kstack_id, ustack_id, comm}] += 1                  |
 +-------------------------------------------------------------------------+
                   │  (ทุกอย่างรวมผลในเคอร์เนล)
                   v
 Userspace (Go): อ่าน stack_counts + stack_traces -> symbolize -> folded -> flamegraph.pl
```

ถ้าฟังก์ชัน `A` ใช้ CPU 30% ของเวลา โดยเฉลี่ยจะมี sample ประมาณ 30% ที่ตกอยู่ใน `A` — ยิ่งเก็บนาน ค่าประมาณยิ่งแม่น (ความคลาดเคลื่อนเชิงสถิติลดลงตามรากที่สองของจำนวน sample)

**ทำไม 99 Hz ไม่ใช่ 100 Hz?** เพื่อหลีกเลี่ยง *lockstep sampling* — ถ้างานในระบบมีจังหวะเป็นรอบ 10 ms พอดี (timer ของเคอร์เนลหรือแอปจำนวนมากทำงานเป็นจังหวะ 100/250/1000 Hz) การสุ่มที่ 100 Hz อาจเจอจังหวะเดิมซ้ำ ๆ ทำให้ผลเบี้ยว ตัวเลขคี่อย่าง 99 ลดโอกาสนี้ (เป็นธรรมเนียมเดียวกับ `perf record -F 99` และ `profile` ของ BCC)

---

### 1.2 On-CPU vs Off-CPU: ทำไม `sched_switch` จึงผิดสำหรับงานนี้

| | On-CPU profiling | Off-CPU analysis |
|---|---|---|
| คำถาม | "CPU กำลังทำอะไร?" | "ทำไมเธรดถึง **ไม่ได้** รันอยู่บน CPU?" (รอ I/O, lock, sleep) |
| จุด hook | timer/perf_event ที่สุ่มตามเวลา | `sched_switch` ตอนเธรดถูกสลับออก + วัดเวลาจนกว่าจะกลับมา |
| น้ำหนักของแต่ละ stack | จำนวน sample (∝ เวลา CPU) | **ระยะเวลาที่ถูกบล็อก** (ns) |

โปรแกรมเดิมเก็บ stack ทุกครั้งที่เกิด `sched_switch` แล้วนับ +1 ผลคือ:
- เห็นแต่ stack ที่ลงท้ายด้วย `__schedule -> schedule -> do_nanosleep / ep_poll` ซึ่งคือ "จุดที่เธรดเลิกใช้ CPU" ไม่ใช่จุดที่ใช้ CPU
- เธรดที่ใช้ CPU 100% แต่แทบไม่ถูกสลับออก (เช่น busy loop) จะแทบไม่ปรากฏเลย ขณะที่เธรดที่ sleep สั้น ๆ บ่อย ๆ จะดูเหมือน "ตัวการ"
- นับเป็น "จำนวนครั้งที่สลับ" ไม่ใช่ "เวลา" จึงไม่ใช่ทั้ง On-CPU และ Off-CPU ที่ถูกต้อง

ตัวอย่างผลจากเวอร์ชันเดิม (อยู่ในประวัติ git ของ repo) — สังเกตว่าทุก stack คือเส้นทางการ "หลับ":
```text
#1 [agy (PID: 52953)] - Sample Count: 309
    -> perf_trace_sched_switch
    -> __traceiter_sched_switch
    -> __schedule
    -> schedule
    -> do_nanosleep
    ...
```

Off-CPU analysis ที่ถูกต้องต้องบันทึก timestamp ตอนสลับออก แล้วคำนวณ delta ตอนเธรดถูกสลับกลับเข้ามา — เราเก็บไว้เป็นแบบฝึกหัดระดับท้าทาย แทนที่จะใส่โหมดที่ครึ่ง ๆ กลาง ๆ ไว้ในโค้ดหลัก

---

### 1.3 `perf_event_open` + BPF link

ฝั่ง Go เปิด perf event แบบ software clock **หนึ่ง fd ต่อหนึ่ง CPU** (`pid = -1, cpu = N` หมายถึง "ทุกงานบน CPU N"):

```go
attr := unix.PerfEventAttr{
    Type:   unix.PERF_TYPE_SOFTWARE,
    Config: unix.PERF_COUNT_SW_CPU_CLOCK,
    Sample: 99,               // เป็นความถี่ (Hz) เพราะตั้งบิต PerfBitFreq
    Bits:   unix.PerfBitFreq,
}
fd, _ := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
```

จากนั้นผูกโปรแกรมเข้ากับ fd นั้น ซึ่งมี 2 วิธี:
1. **BPF link** (`BPF_LINK_CREATE` + attach type `BPF_PERF_EVENT`, Linux 5.15+): cilium/ebpf v0.16.0 ไม่มีฟังก์ชันระดับสูงสำหรับ perf event ที่เราเปิดเอง แต่มี `link.AttachRawLink(link.RawLinkOptions{Target: fd, Program: prog, Attach: ebpf.AttachPerfEvent})` ซึ่งเรียก syscall เดียวกันนี้ตรง ๆ ข้อดีคือดูได้ใน `bpftool link show`
2. **ioctl แบบเก่า** `PERF_EVENT_IOC_SET_BPF`: ใช้เป็นทางสำรองในโค้ดสำหรับเคอร์เนลที่ยังไม่รองรับ perf link

> [!NOTE]
> `PERF_COUNT_SW_CPU_CLOCK` เป็น software event ที่ขับเคลื่อนด้วย hrtimer จึงใช้ได้แม้ใน VM ที่ไม่มี hardware PMU (ต่างจาก `PERF_COUNT_HW_CPU_CYCLES`) ข้อแลกเปลี่ยนคือ ถ้า CPU กำลังปิด interrupt อยู่ (เช่นในบางส่วนของเคอร์เนล) sample จะถูกเลื่อนไปเกิดหลังเปิด interrupt ทำให้ kernel profile คลาดเคลื่อนได้เล็กน้อย

---

### 1.4 `BPF_MAP_TYPE_STACK_TRACE` และปัญหา Hash Collision

`bpf_get_stackid()` คำนวณ hash ของ IP ทั้งชุด แล้วใช้เป็น index ของ bucket ใน STACK_TRACE map (จำนวน bucket = `max_entries` ปัดขึ้นเป็นกำลังสอง) พฤติกรรมขึ้นกับ flags:

| flags | ถ้า bucket ว่าง | ถ้า bucket มี stack เดียวกัน | ถ้า bucket มี **stack อื่น** |
|---|---|---|---|
| `0` (ที่เราใช้) | เก็บ, คืน id | คืน id เดิม (เทียบ IP ทุกตัว) | คืน **`-EEXIST`** (stack นี้สูญหาย) |
| `BPF_F_FAST_STACK_CMP` | เก็บ, คืน id | เทียบแค่ hash 32 บิต | คืน `-EEXIST` ถ้า hash ต่าง (ถ้า hash ชนกันพอดีจะคืน id ของ stack อื่น = **นับผิดตัว**) |
| `BPF_F_REUSE_STACKID` | เก็บ, คืน id | คืน id เดิม | **เขียนทับ** bucket แล้วคืน id เดิม |

ทำไมไม่ใช้ `BPF_F_REUSE_STACKID`? เพราะ profiler ของเราเก็บ stack id ไว้ใน `stack_counts` แล้วค่อยอ่าน stack ตอนจบ ถ้า bucket ถูกเขียนทับ id เก่าที่นับไว้แล้วจะ **ชี้ไปที่ stack ใหม่** ทำให้ flame graph ผิดอย่างเงียบ ๆ การยอมทิ้ง sample ที่ชน (`-EEXIST`) แล้ว **นับและรายงาน** จึงปลอดภัยกว่า — นี่คือแนวทางเดียวกับ `profile.py` ของ BCC ที่เตือนเรื่อง "stack hash collisions"

ค่าที่ไม่ใช่ข้อผิดพลาดแต่ต้องเข้าใจ: user stack ได้ **`-EFAULT`** สำหรับ kernel thread (เช่น `kworker`, `ksoftirqd`) เพราะไม่มี user context

ขนาดหน่วยความจำ: STACK_TRACE map จองพื้นที่ล่วงหน้าประมาณ `max_entries × 127 × 8` ไบต์ (16384 × 1016 ≈ 16 MB) การเพิ่ม `max_entries` ลด collision ได้แต่ใช้แรมมากขึ้นตามสัดส่วน

---

### 1.5 การ Unwind Stack และ Frame Pointer

เคอร์เนลเดิน **kernel stack** ด้วย unwinder ของเคอร์เนลเอง (บน x86_64 ปกติคือ ORC) จึงได้ผลครบเสมอ แต่ **user stack** ถูกเดินด้วย **frame pointer** (`rbp` chain) เท่านั้น — ถ้าโปรแกรม/ไลบรารีคอมไพล์ด้วย `-fomit-frame-pointer` stack จะขาดหรือมั่ว

- Ubuntu เริ่มคอมไพล์แพ็กเกจด้วย frame pointer เป็นค่าเริ่มต้นบน amd64 ตั้งแต่ 24.04 ทำให้ stack ของ `libc` และโปรแกรมระบบส่วนใหญ่เดินได้ (ดังจะเห็น `__libc_start_main` ในผล)
- Go ใช้ frame pointer มาตลอด จึง profile โปรแกรม Go ได้ดี
- โปรแกรมของเราเองควรคอมไพล์ด้วย `-fno-omit-frame-pointer` (ดู `workload/busy.c`)
- **Tail call optimization** ทำให้เฟรมหายได้: ถ้า `hot_path_a()` จบด้วย `jmp spin` แทน `call spin` เฟรมของ `hot_path_a` จะไม่อยู่บน stack เลย — เราพบปัญหานี้จริงระหว่างทดสอบ และแก้ด้วย compiler barrier ใน `busy.c`

---

### 1.6 Symbolization และ Folded Stacks

**Kernel:** `/proc/kallsyms` ให้ (ที่อยู่, ชนิด, ชื่อ) ของทุกสัญลักษณ์ เราเก็บเฉพาะ text symbol (`t/T/w/W`) เรียงตามที่อยู่ แล้วใช้ binary search หา "สัญลักษณ์ที่อยู่ก่อนหน้าใกล้ที่สุด" (ต้องรันเป็น root ไม่เช่นนั้น `kptr_restrict` จะซ่อนที่อยู่เป็น 0)

**User:** ขั้นตอนแปลง IP ของโปรเซสเป็นชื่อฟังก์ชัน:
```
IP 0x5581c2a3b17e
  └─ /proc/<pid>/maps: 5581c2a3b000-5581c2a3c000 r-xp 00001000 ... /path/busy
       file offset = IP - start + offset
  └─ ELF program header PT_LOAD ที่ครอบ offset นี้ -> vaddr = offset - p.Off + p.Vaddr
  └─ .symtab / .dynsym: หาฟังก์ชัน (STT_FUNC) ที่ addr <= vaddr < addr+size
       => "hot_path_a"
```

**Folded format** คือหนึ่งบรรทัดต่อหนึ่ง stack เรียงจาก **เฟรมนอกสุด (root) ไปในสุด (leaf)** คั่นด้วย `;` ตามด้วยจำนวน sample:
```
busy;_start;__libc_start_main;main;run_workload;hot_path_a;spin 389
```
`flamegraph.pl` แปลงแต่ละบรรทัดเป็นกล่องซ้อนกัน **ความกว้าง = สัดส่วน sample** (ไม่ใช่ลำดับเวลา) เราเติม `_[k]` ท้ายเฟรมของเคอร์เนลตามธรรมเนียมของ BCC เพื่อให้ `flamegraph.pl --color=java` ระบายสีแยก kernel/user ได้

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `cpu_stacks.c`

```c
#define EEXIST 17
#define MAX_STACK_DEPTH 127
```
- **บรรทัด 12-16:** `errno` เป็น `#define` จึงไม่อยู่ใน `vmlinux.h` ต้องประกาศเอง ส่วน `BPF_F_USER_STACK` เป็น enum ใน `vmlinux.h` แล้ว **ห้าม** `#define` ซ้ำ (เวอร์ชันเดิมทำแบบนั้นเพราะใช้ `<linux/bpf.h>`)

```c
const volatile __u32 targ_pid = 0;
const volatile __u8 include_idle = 0;
```
- **บรรทัด 22-23:** ตัวแปรใน `.rodata` ที่ Go เขียนค่าด้วย `RewriteConstants()` ก่อนโหลด Verifier มองเป็นค่าคงที่ จึงตัดกิ่ง `if (targ_pid && ...)` ทิ้งได้ถ้าไม่ได้กรอง PID

```c
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 16384);
} stack_traces SEC(".maps");
```
- **บรรทัด 36-41:** value คืออาร์เรย์ IP 127 ช่อง (ช่องที่เหลือเป็น 0) ใช้ร่วมกันทั้ง kernel และ user stack

```c
enum { STAT_SAMPLES, STAT_KERN_EEXIST, STAT_USER_EEXIST, STAT_COUNTS_FULL, STAT_MAX };
```
- **บรรทัด 60-75:** PERCPU_ARRAY สำหรับตัวนับสถานะ เพิ่มค่าได้ด้วย `(*v)++` ธรรมดาเพราะแต่ละ CPU มีช่องของตัวเอง (ไม่มี cache-line bouncing)

```c
SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 tid = (__u32)id;

    stat_inc(STAT_SAMPLES);

    if (tid == 0 && !include_idle)
        return 0;
    if (targ_pid && tgid != targ_pid)
        return 0;
```
- **บรรทัด 81-94:** `SEC("perf_event")` ทำให้เป็น `BPF_PROG_TYPE_PERF_EVENT` ซึ่ง ctx คือ `struct bpf_perf_event_data` (มี `regs` ของงานที่ถูกขัดจังหวะ) `tid == 0` คือ idle task (`swapper/N`) ซึ่งหมายถึง CPU ว่าง เราข้ามไปเป็นค่าเริ่มต้นเพื่อไม่ให้ flame graph เต็มไปด้วย `cpuidle`

```c
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    if (key.kernel_stack_id == -EEXIST)
        stat_inc(STAT_KERN_EEXIST);

    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (key.user_stack_id == -EEXIST)
        stat_inc(STAT_USER_EEXIST);
```
- **บรรทัด 107-116:** flags = 0 ตามเหตุผลในหัวข้อ 1.4 และนับ collision แยก kernel/user เพื่อรายงานผู้ใช้ (เวอร์ชันเดิมใช้ `BPF_F_FAST_STACK_CMP` และไม่ตรวจค่าที่คืนกลับเลย)

```c
    __u64 *val = bpf_map_lookup_elem(&stack_counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 one = 1;
        if (bpf_map_update_elem(&stack_counts, &key, &one, BPF_NOEXIST)) {
            val = bpf_map_lookup_elem(&stack_counts, &key);
            if (val)
                __sync_fetch_and_add(val, 1);
            else
                stat_inc(STAT_COUNTS_FULL);
        }
    }
```
- **บรรทัด 118-131:** ถ้า insert ไม่สำเร็จ แยกให้ออกว่าเป็นเพราะ CPU อื่นเพิ่ง insert key เดียวกัน (lookup ซ้ำแล้วเจอ) หรือแมปเต็มจริง (นับไว้รายงาน)

### 2.2 ไฟล์ `main.go`

```go
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: freq,
			Bits:   unix.PerfBitFreq,
		}
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
```
- **บรรทัด 94-102:** ต้องกำหนด `Size` ให้เคอร์เนลรู้เวอร์ชันของ struct; ไม่ตั้ง `PerfBitDisabled` จึงเริ่มนับทันที; วนทำทุก CPU จาก `/sys/devices/system/cpu/online` (ฟังก์ชัน `onlineCPUs` บรรทัด 46-70)

```go
		l, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  fd,
			Program: prog,
			Attach:  ebpf.AttachPerfEvent,
		})
		...
		if ioErr := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); ioErr != nil {
```
- **บรรทัด 108-126:** วิธีผูกโปรแกรมตามหัวข้อ 1.3 พร้อมทางสำรอง ioctl; `perfSampler.Close()` ปิด link ก่อนแล้วจึงปิด fd

```go
	spec, err := loadBpf()
	...
	if err := spec.RewriteConstants(map[string]interface{}{
		"targ_pid":     uint32(*pid),
		"include_idle": includeIdle,
	}); err != nil {
```
- **บรรทัด 218-233:** โหลด `CollectionSpec` ก่อน แก้ค่าคงที่ แล้วจึง `LoadAndAssign` (ชนิดของค่าต้องตรงกับใน C: `__u32` -> `uint32`, `__u8` -> `uint8`)

```go
			for iter.Next(&key, &val) {
				...
				syms.snapshot(key.Pid)
			}
```
- **บรรทัด 274-284:** ทุก 2 วินาทีพิมพ์ความคืบหน้า และ **จำ `/proc/<pid>/maps`** ของทุก PID ที่เห็นไว้ก่อน เพราะโปรเซสอายุสั้นอาจจบก่อนเราจะ symbolize ตอนท้าย

```go
	sampler.Close()
```
- **บรรทัด 294:** หยุดการสุ่มก่อนอ่านผล ตัวเลขจะได้ไม่ขยับระหว่างพิมพ์

```go
		frames := []string{sanitizeFrame(string(bytes.TrimRight(e.key.Comm[:], "\x00")))}
		uframes := lookupStack(objs, e.key.UserStackID)
		for i := len(uframes) - 1; i >= 0; i-- { ... }
		kframes := lookupStack(objs, e.key.KernelStackID)
		for i := len(kframes) - 1; i >= 0; i-- {
			frames = append(frames, sanitizeFrame(resolveKaddr(kframes[i]))+"_[k]")
		}
```
- **บรรทัด 394-430 (`writeFolded`):** STACK_TRACE เก็บ IP จาก leaf -> root จึงต้อง **วนกลับด้าน** ให้ได้ root -> leaf; ลำดับคือ comm -> user frames -> kernel frames (เพราะ kernel ถูกเรียกจาก user ผ่าน syscall/interrupt) จากนั้นรวมบรรทัดที่ symbolize ออกมาเหมือนกัน (stack id ต่างกันแต่ชื่อเหมือนกัน เช่น IP ต่างตำแหน่งในฟังก์ชันเดียวกัน)

### 2.3 ไฟล์ `usersyms.go`
- **บรรทัด 53-87 (`snapshot`):** เก็บเฉพาะ mapping ที่มีสิทธิ์ execute (`r-xp`) และตัด ` (deleted)` ออกจาก path
- **บรรทัด 89-130 (`loadELF`):** เปิด ELF ผ่าน `/proc/<pid>/root/<path>` ก่อน (ใช้ได้กับโปรเซสใน container) อ่าน `PT_LOAD` และ `STT_FUNC` จากทั้ง `.symtab` และ `.dynsym` แล้ว cache ต่อ path
- **บรรทัด 132-176 (`resolve`):** แปลง IP -> file offset -> ELF vaddr -> ชื่อฟังก์ชัน ถ้าหาชื่อไม่ได้คืน `[module+0xoffset]` (offset นี้เป็น **file offset** — ถ้าจะใช้ `addr2line -e <module>` ต้องแปลงเป็น vaddr ตาม `PT_LOAD` ก่อน ดู `readelf -l <module>`) หรือ `0xaddr` ถ้าไม่มีข้อมูล maps

### 2.4 ไฟล์ `workload/busy.c`
- โปรแกรมที่ "รู้คำตอบ": `hot_path_a` ทำงาน 2 ส่วน `hot_path_b` ทำงาน 1 ส่วน จึงควรได้สัดส่วน sample ≈ 2:1
- `barrier()` (asm volatile ว่าง ๆ) หลังเรียก `spin()` บังคับให้เป็น `call` + `ret` ไม่ใช่ tail call — ตรวจได้ด้วย `objdump -d bin/busy | grep -A6 "<hot_path_a>:"` ต้องเห็น `call ... <spin>`

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์ (eBPF + Go + workload)
```bash
cd phase08-system-performance-observability/week18-cpu-profiler-stacks
make all          # generate + build + workload (bin/cpu-profiler และ bin/busy)
```

### ขั้นตอนที่ 2: ตรวจ workload ว่ามี frame pointer และไม่ tail call
```bash
objdump -d bin/busy --no-show-raw-insn | grep -A6 "<hot_path_a>:"
# ต้องเห็น: push %rbp / mov %rsp,%rbp / ... / call <spin> / pop %rbp / ret
```

### ขั้นตอนที่ 3: Profile เฉพาะ PID ของ workload
```bash
./bin/busy 10 &                                  # เผา CPU 1 core เป็นเวลา 10 วินาที
sudo ./bin/cpu-profiler -p $! -d 6s -folded out.txt
```

### ขั้นตอนที่ 4: Profile ทั้งระบบ
```bash
sudo ./bin/cpu-profiler -d 5s -top 3 -folded all.txt
# ตัวเลือกอื่น: -F 49 (ลดความถี่), -idle (นับ idle ด้วย), กด Ctrl+C เพื่อหยุดก่อนกำหนด
```

### ขั้นตอนที่ 5: สร้าง Flame Graph
```bash
git clone --depth 1 https://github.com/brendangregg/FlameGraph
./FlameGraph/flamegraph.pl --title "busy on-CPU" out.txt > cpu.svg
./FlameGraph/flamegraph.pl --color=java --title "system on-CPU" all.txt > all.svg   # _[k] = สีของ kernel
xdg-open cpu.svg     # เปิดด้วยเบราว์เซอร์: คลิกเพื่อ zoom, Ctrl+F เพื่อค้นหาฟังก์ชัน
```
ทางเลือกอื่นที่อ่านไฟล์ folded ได้เหมือนกัน: <https://www.speedscope.app> (ลากไฟล์ `out.txt` ใส่) หรือ `inferno-flamegraph` (Rust)

### ขั้นตอนที่ 6: ตรวจสอบด้วย `bpftool` (ระหว่าง profiler ทำงาน)
```bash
sudo bpftool prog show name do_sample        # type ต้องเป็น perf_event
sudo bpftool link show | grep -A1 perf_event # ต้องมี 1 link ต่อ 1 CPU
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`, 8 CPUs) — เครื่องทดสอบมีงานอื่นทำงานพร้อมกัน (เช่น การคอมไพล์ของผู้ใช้อื่น)
>
> หมายเหตุ: path ของไฟล์ `-folded` ในบรรทัด `Wrote ...`/`Render: ...` ถูกย่อจากไดเรกทอรีชั่วคราวบนเครื่องทดสอบให้เหลือแค่ชื่อไฟล์ ส่วนอื่นเป็นผลลัพธ์จริงทั้งหมด

### 4.1 Profile เฉพาะ PID (`./bin/busy 10 &` แล้ว `sudo ./bin/cpu-profiler -p $! -d 6s -folded out.txt`)
```text
busy: pid=4077337, burning one CPU for 10 s (hot_path_a:hot_path_b = 2:1)
======================================================================
 eBPF On-CPU Profiler & Stack Collector (perf_event + Flame Graph)
======================================================================
2026/10/28 22:04:41 [INFO] Loaded 266310 text symbols from /proc/kallsyms
2026/10/28 22:04:41 [INFO] Sampling on-CPU stacks at 99 Hz on 8 CPUs (PID 4077337) via PERF_COUNT_SW_CPU_CLOCK
2026/10/28 22:04:41 [INFO] Profile collecting. Press Ctrl+C to terminate and view top stacks.

[22:04:43] On-CPU Samples: 198      | Unique Call Chains: 4     
[22:04:45] On-CPU Samples: 396      | Unique Call Chains: 5     

[INFO] Sampler detached. Rendering top on-CPU call chains...
[STATS] perf samples fired: 4752 | recorded (after idle/PID filter): 594 | unique chains: 6
[STATS] stack-id collisions (-EEXIST): kernel=0 user=0 | stack_counts full: 0

=================== TOP ON-CPU CALL CHAINS ===================

#1 [busy (PID: 4077337)] - Sample Count: 388
    [u] spin
    [u] hot_path_a
    [u] run_workload
    [u] main
    [u] [libc.so.6+0x2a601]
    [u] __libc_start_main
    [u] _start

#2 [busy (PID: 4077337)] - Sample Count: 201
    [u] spin
    [u] hot_path_b
    [u] run_workload
    [u] main
    [u] [libc.so.6+0x2a601]
    [u] __libc_start_main
    [u] _start

#3 [busy (PID: 4077337)] - Sample Count: 2
    [u] spin
    [u] hot_path_b
    [u] run_workload
    [u] main
    [u] [libc.so.6+0x2a601]
    [u] __libc_start_main
    [u] _start

#4 [busy (PID: 4077337)] - Sample Count: 1
    [u] spin
    [u] hot_path_a
    [u] run_workload
    [u] main
    [u] [libc.so.6+0x2a601]
    [u] __libc_start_main
    [u] _start

#5 [busy (PID: 4077337)] - Sample Count: 1
    [k] build_detached_freelist
    [k] __kmem_cache_free_bulk.part.0
    [k] rcu_free_sheaf
    [k] rcu_do_batch
    [k] rcu_core
    [k] rcu_core_si
    [k] handle_softirqs
    [k] __irq_exit_rcu
    [k] irq_exit_rcu
    [k] sysvec_apic_timer_interrupt
    [k] asm_sysvec_apic_timer_interrupt
    [u] spin
    [u] hot_path_a
    [u] run_workload
    [u] main
    [u] [libc.so.6+0x2a601]
    [u] __libc_start_main
    [u] _start
==============================================================
2026/10/28 22:04:47 [INFO] Wrote 4 folded stack lines to out.txt
2026/10/28 22:04:47 [INFO] Render: ./flamegraph.pl out.txt > cpu.svg
```

ไฟล์ `out.txt` ที่ได้ (อินพุตของ `flamegraph.pl`):
```text
busy;_start;__libc_start_main;[libc.so.6+0x2a601];main;run_workload;hot_path_a;spin 389
busy;_start;__libc_start_main;[libc.so.6+0x2a601];main;run_workload;hot_path_a;spin;asm_sysvec_apic_timer_interrupt_[k];sysvec_apic_timer_interrupt_[k];irq_exit_rcu_[k];__irq_exit_rcu_[k];handle_softirqs_[k] 1
busy;_start;__libc_start_main;[libc.so.6+0x2a601];main;run_workload;hot_path_a;spin;asm_sysvec_apic_timer_interrupt_[k];sysvec_apic_timer_interrupt_[k];irq_exit_rcu_[k];__irq_exit_rcu_[k];handle_softirqs_[k];rcu_core_si_[k];rcu_core_[k];rcu_do_batch_[k];rcu_free_sheaf_[k];__kmem_cache_free_bulk.part.0_[k];build_detached_freelist_[k] 1
busy;_start;__libc_start_main;[libc.so.6+0x2a601];main;run_workload;hot_path_b;spin 203
```

> ผู้จัดทำไม่ได้แนบไฟล์ SVG ที่เรนเดอร์จากเครื่องทดสอบ ให้ผู้เรียนรันขั้นตอนที่ 5 เองแล้วตรวจว่า `hot_path_a` กว้างประมาณ 2 เท่าของ `hot_path_b`

### 4.2 การตีความผลลัพธ์ (4.1)
- **ความถี่ถูกต้อง:** `perf samples fired: 4752` ≈ 8 CPUs × 99 Hz × 6 s (= 4752) และ `busy` ซึ่งใช้ 1 core เต็มได้ 594 samples ≈ 99 Hz × 6 s
- **สัดส่วนตรงกับที่ออกแบบไว้:** `hot_path_a` = 389 + 1 + 1 = 391, `hot_path_b` = 203 → อัตราส่วน ≈ 1.93 : 1 ใกล้ 2 : 1 ตามที่ออกแบบใน `busy.c` (ความคลาดเคลื่อนเกิดจากธรรมชาติของการสุ่ม)
- **#1 กับ #4 symbolize ออกมาเหมือนกัน** แต่เป็นคนละ stack id เพราะ IP ของ leaf อยู่คนละตำแหน่งในลูป `spin` — ไฟล์ folded รวมให้เป็นบรรทัดเดียวแล้ว
- **#5 มี kernel frames บน user stack:** timer interrupt เข้ามาตอน `spin` รัน แล้วเคอร์เนลทำงาน RCU softirq ต่อในบริบทของ `busy` — On-CPU profiler นับเวลานี้ให้ `busy` เพราะเป็นงานที่อยู่บน CPU จริง
- `[libc.so.6+0x2a601]` คือฟังก์ชันภายในของ glibc (เช่น `__libc_start_call_main`) ที่ไม่อยู่ใน `.dynsym` และไฟล์ libc ของดิสโทรถูก strip `.symtab` ออก ต้องใช้ debug symbols (`debuginfod`/`libc6-dbg`) จึงจะได้ชื่อ

### 4.3 Profile ทั้งระบบ (`sudo ./bin/cpu-profiler -d 5s -top 3 -folded all.txt` ขณะ `busy` ทำงาน)
```text
======================================================================
 eBPF On-CPU Profiler & Stack Collector (perf_event + Flame Graph)
======================================================================
2026/10/28 22:04:59 [INFO] Loaded 266306 text symbols from /proc/kallsyms
2026/10/28 22:04:59 [INFO] Sampling on-CPU stacks at 99 Hz on 8 CPUs (all processes) via PERF_COUNT_SW_CPU_CLOCK
2026/10/28 22:04:59 [INFO] Profile collecting. Press Ctrl+C to terminate and view top stacks.

[22:05:02] On-CPU Samples: 327      | Unique Call Chains: 132   
[22:05:04] On-CPU Samples: 695      | Unique Call Chains: 302   

[INFO] Sampler detached. Rendering top on-CPU call chains...
[STATS] perf samples fired: 3960 | recorded (after idle/PID filter): 845 | unique chains: 353
[STATS] stack-id collisions (-EEXIST): kernel=0 user=3 | stack_counts full: 0
[STATS] -> some stacks were dropped by hash collisions; raise stack_traces max_entries if this is large

=================== TOP ON-CPU CALL CHAINS ===================

#1 [busy (PID: 4082145)] - Sample Count: 333
    [u] spin
    [u] hot_path_a
    [u] run_workload
    [u] main
    [u] [libc.so.6+0x2a601]
    [u] __libc_start_main
    [u] _start

#2 [busy (PID: 4082145)] - Sample Count: 161
    [u] spin
    [u] hot_path_b
    [u] run_workload
    [u] main
    [u] [libc.so.6+0x2a601]
    [u] __libc_start_main
    [u] _start

#3 [link (PID: 4082907)] - Sample Count: 1
    [u] 0x4206a0
    [u] 0x421305
    [u] 0x54ea26
    [u] 0x5d8606
    [u] 0x64b56c
    [u] 0x511dcb
    [u] 0x5e1a2f
    [u] 0x5e666b
    [u] 0x5e8ad8
    [u] 0x5e89ff
    [u] 0x48b501
==============================================================
2026/10/28 22:05:05 [INFO] Wrote 330 folded stack lines to all.txt
2026/10/28 22:05:05 [INFO] Render: ./flamegraph.pl all.txt > cpu.svg
```

สรุปจำนวน sample ต่อโปรเซสจาก `all.txt` (คำนวณด้วย `awk '{c=$NF; split($1,a,";"); n[a[1]]+=c} END{for(k in n) print n[k], k}' all.txt | sort -rn | head -5`):
```text
495 busy
127 sleep
63 clang
29 bash
25 claude
```

### 4.4 การตีความผลลัพธ์ (4.3)
- 3960 samples ≈ 8 × 99 × 5 แต่ถูกบันทึกเพียง 845 เพราะ CPU ส่วนใหญ่ว่าง (idle ถูกกรองทิ้ง) — `busy` ครอง ~59% ของ sample ที่ไม่ใช่ idle
- **#3 `link`** (ตัว linker ของ Go จากงาน build อื่นบนเครื่อง) จบไปก่อนที่ profiler จะทันอ่าน `/proc/<pid>/maps` จึงเหลือแต่ที่อยู่ดิบ — นี่คือข้อจำกัดของ symbolization ฝั่ง userspace ที่ต้องเข้าใจ
- มี user stack collision 3 ครั้ง (จาก ~353 unique chains) — โปรแกรมรายงานให้เห็นแทนที่จะทิ้งเงียบ ๆ

---

## 5. ข้อจำกัด (Limitations)

- **User stack ต้องมี frame pointer:** โค้ดที่คอมไพล์ด้วย `-fomit-frame-pointer` (ซึ่งยังเป็นค่าเริ่มต้นของ gcc/clang ที่ `-O2` บนหลายดิสโทร) จะได้ stack สั้นหรือผิด; เครื่องมือระดับ production ใช้ DWARF/`.eh_frame` unwinding หรือ SFrame แทน
- **Symbolization แบบง่าย:** ไม่มี DWARF (ไม่มีชื่อไฟล์/บรรทัด, ไม่เห็นฟังก์ชันที่ถูก inline), ไม่ demangle C++/Rust (เห็นชื่อแบบ `_ZNSt...`), ไม่รองรับ JIT (Java/Node/Python ต้องใช้ perf map หรือ agent เฉพาะภาษา), และโปรเซสที่จบก่อนการ snapshot จะเหลือแค่ที่อยู่ดิบ
- **Stack ลึกเกิน 127 เฟรมถูกตัด** (ค่า `kernel.perf_event_max_stack` ปกติ); stack ที่ลึกมากใน Java/recursion จะไม่ครบ
- **Hash collision** ทำให้ sample หายได้ (รายงานใน `[STATS]`) การเพิ่ม `max_entries` ลดปัญหาได้แต่ใช้แรมเพิ่ม (~1 KB ต่อ entry)
- **Software clock** ถูกเลื่อนเมื่อ interrupt ถูกปิด ทำให้ส่วนของเคอร์เนลที่ปิด IRQ ถูก under-sample; hardware PMU event (`PERF_COUNT_HW_CPU_CYCLES`) แม่นกว่าแต่อาจไม่มีใน VM
- **เวลาของ idle/การรอไม่ถูกนับ:** ถ้าแอปช้าเพราะรอ I/O หรือ lock เครื่องมือนี้จะไม่เห็น (ต้องใช้ Off-CPU analysis)
- **ไม่ได้รองรับ CPU hotplug:** CPU ที่ออนไลน์ภายหลังจะไม่ถูกสุ่ม

---

## 6. Milestone Checklist

- [x] อธิบายหลักการของ Sampling Profiler และเหตุผลของความถี่ 99 Hz
- [x] แยกความต่างระหว่าง On-CPU และ Off-CPU และอธิบายว่าทำไม `sched_switch` + นับครั้งจึงไม่ใช่ทั้งสองแบบ
- [x] เปิด `perf_event_open` ต่อ CPU จาก Go และแนบโปรแกรม `SEC("perf_event")` ด้วย `link.AttachRawLink` (+ ทางสำรอง ioctl)
- [x] ใช้ `BPF_MAP_TYPE_STACK_TRACE` และเข้าใจผลของ flags `0` / `BPF_F_FAST_STACK_CMP` / `BPF_F_REUSE_STACKID` รวมถึงการนับ `-EEXIST`
- [x] ใช้ `const volatile` + `RewriteConstants` ทำตัวกรอง PID
- [x] Symbolize kernel stack (kallsyms) และ user stack (maps + ELF)
- [x] สร้างไฟล์ folded stack และอธิบายวิธีอ่าน Flame Graph
- [x] ยืนยันความถูกต้องของ profiler ด้วย workload ที่รู้สัดส่วนล่วงหน้า (2:1)

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **ผลของ frame pointer:** คอมไพล์ `workload/busy.c` ใหม่ด้วย `clang -O2 -fomit-frame-pointer` แล้ว profile ซ้ำ
   - *Deliverable:* ผล TOP CALL CHAINS ก่อน/หลัง และคำอธิบายว่าเฟรมใดหายไป
   - *Verification:* `objdump -d` ของ `hot_path_a` ต้องไม่มี `push %rbp`; stack ในผลจะไม่ครบ/ไม่ถูกต้อง
2. **เปลี่ยนความถี่:** รัน `-F 49` และ `-F 199` บน workload เดิม 6 วินาที
   - *Deliverable:* ตารางจำนวน sample ที่ได้กับค่าที่คาดไว้ (F × วินาที × จำนวน core ที่ busy)
   - *Verification:* ค่าที่วัดได้ควรใกล้ค่าคาดหมาย และอัตราส่วน `hot_path_a : hot_path_b` ยังคงประมาณ 2:1

### ระดับปานกลาง
1. **แยกตาม thread:** เพิ่ม `tid` ลงใน `stack_key` และ flag `-per-thread` ที่ใส่ `comm-tid` เป็นเฟรมแรกของ folded output
   - *Deliverable:* โค้ด + flame graph ของโปรแกรม multi-thread (เช่น `stress-ng --cpu 2` หรือโปรแกรม Go ที่มี goroutine หลายตัว)
   - *Verification:* flame graph ต้องมีรากแยกตามจำนวน thread ที่ใช้ CPU
2. **ลด collision:** ทดลอง `max_entries` ของ `stack_traces` = 1024, 16384, 65536 บนการ profile ทั้งระบบขณะ build โปรเจกต์ขนาดใหญ่
   - *Deliverable:* ตารางจำนวน `-EEXIST` และหน่วยความจำของแมป (`sudo bpftool map show name stack_traces` ดูค่า `memlock`)
   - *Verification:* collision ต้องลดลงเมื่อเพิ่ม `max_entries` และ memlock เพิ่มขึ้นตามสัดส่วน

### ระดับท้าทาย
1. **Off-CPU profiler ที่ถูกต้อง:** เขียนโหมด `-offcpu` ใช้ `tp_btf/sched_switch` บันทึก timestamp + stack ของ `prev` ตอนถูกสลับออก แล้วตอน task นั้นถูกสลับกลับเข้า (เป็น `next`) ให้บวก **ระยะเวลา (µs)** เข้า `stack_counts` แทนการ +1
   - *Deliverable:* โค้ด + flame graph ของ `sleep 1` วนซ้ำ และของ `gnudd ... iflag=direct` (ดู Week 17)
   - *Verification:* stack ของ `sleep` ต้องลงท้ายด้วย `do_nanosleep` และผลรวมเวลาของมันใกล้กับเวลาจริงที่ sleep; ระบุชัดเจนในผลว่าหน่วยเป็นเวลาไม่ใช่จำนวน sample
2. **Symbolize ด้วย DWARF / Build ID:** ใช้ `bpf_get_stack()` กับ `BPF_F_USER_BUILD_ID` หรือเรียก `addr2line` สำหรับเฟรมแบบ `[module+0xoffset]` เพื่อให้ได้ชื่อไฟล์และบรรทัด
   - *Deliverable:* output ที่แสดง `busy.c:<line>` ข้างชื่อฟังก์ชัน
   - *Verification:* บรรทัดที่แสดงสำหรับ `spin` ต้องชี้ไปที่ลูป `for` ใน `busy.c`
