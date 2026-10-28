# สัปดาห์ที่ 22: สถาปัตยกรรม BPF Trampoline (fentry & fexit) และการวัด Overhead ของ Tracing อย่างเป็นธรรม

ยินดีต้อนรับสู่ **Week 22** ของหลักสูตร eBPF Zero to Hero! และเป็นสัปดาห์แรกของ **Phase 10: Cutting-Edge eBPF Technologies**

ในสัปดาห์ก่อน ๆ เราใช้ `kprobe` / `kretprobe` เป็นหลักในการแอบดูฟังก์ชันในเคอร์เนล สัปดาห์นี้เราจะเปลี่ยนมาใช้ **BPF Trampoline (`fentry` และ `fexit`)** ซึ่งเป็นกลไกรุ่นใหม่ (Linux 5.5+) ที่:
1. ให้เคอร์เนล **patch จุด ftrace ที่ต้นฟังก์ชันให้เป็นคำสั่ง `call` ตรงไปยัง trampoline** ที่ JIT สร้างขึ้นเฉพาะ แทนการผ่าน `pt_regs` และ handler กลางของ kprobe
2. ใน `fexit` สามารถอ่าน **ทั้งอาร์กิวเมนต์ขาเข้าเดิม และค่า return ของฟังก์ชัน** ได้ในโปรแกรมเดียว โดยมีชนิดข้อมูล (type) ตาม BTF ของเคอร์เนล
3. Verifier รู้ชนิดของพอยน์เตอร์ทุกตัวผ่าน BTF ทำให้อ่าน field ของ struct ในเคอร์เนลได้โดยตรง (ไม่ต้องใช้ `bpf_probe_read_kernel()` ทุกครั้ง)

และที่สำคัญที่สุด เราจะ **วัด overhead จริง** ของ `kprobe` / `kretprobe` / `fentry` / `fexit` บนฟังก์ชันเดียวกัน แทนการเชื่อตัวเลขโฆษณาลอย ๆ อย่าง "zero overhead" หรือ "< 5ns"

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 kprobe ทำงานอย่างไรบนเคอร์เนลสมัยใหม่

ตำราเก่ามักอธิบายว่า kprobe ทำงานโดยเขียนคำสั่ง breakpoint `int3` ทับคำสั่งแรกของฟังก์ชัน เมื่อ CPU วิ่งมาถึงก็เกิด trap → kprobe handler → เรียกโปรแกรม eBPF นั่นยังจริงอยู่ **ถ้า probe อยู่กลางฟังก์ชัน** (`kprobe:func+offset`) แต่สำหรับ probe ที่ **ต้นฟังก์ชัน** (offset 0) บนเคอร์เนลที่เปิด `CONFIG_KPROBES_ON_FTRACE=y` (Ubuntu เปิดไว้) เคอร์เนลจะใช้จุด ftrace แทน `int3`:

```bash
# ขณะมี kprobe + kretprobe ติดอยู่บน do_sys_openat2 (Linux 7.0.0-38-generic)
$ sudo cat /sys/kernel/debug/kprobes/list | grep openat
ffffffffacee2440  k  do_sys_openat2+0x0    [FTRACE]
ffffffffacee2440  r  do_sys_openat2+0x0    [FTRACE]
```

แฟล็ก `[FTRACE]` บอกว่า kprobe ตัวนี้ **ไม่ได้ใช้ int3** แต่ผ่าน `ftrace_regs_caller` ซึ่งต้องสร้าง `struct pt_regs` เต็มชุดแล้วค่อยเรียก handler ของ kprobe → `trace_call_bpf()` → โปรแกรม eBPF

ส่วน **kretprobe** ต้อง "แอบเปลี่ยน return address" บน stack ของฟังก์ชันให้ชี้ไปยัง trampoline ของ rethook เมื่อฟังก์ชัน return จึงเด้งเข้า handler อีกครั้ง ทุกการเรียกต้องดึง/คืน node จาก pool ของ rethook และผ่าน handler สองรอบ (ขาเข้าเพื่อแก้ return address + ขาออก) กลไกนี้จึงแพงที่สุดในกลุ่ม (เห็นได้ชัดในผลวัดหัวข้อ 4.4–4.5)

### 1.2 BPF Trampoline ทำงานอย่างไร

เมื่อเราแนบ `fentry`/`fexit` เคอร์เนลจะ:
1. หา BTF ID ของฟังก์ชันเป้าหมาย (`do_sys_openat2`) เพื่อรู้จำนวนและชนิดอาร์กิวเมนต์
2. ให้ JIT สร้างโค้ดเครื่องชิ้นใหม่เรียกว่า **BPF trampoline** (`arch_prepare_bpf_trampoline()`) ซึ่งรู้แน่ชัดว่าต้องเซฟรีจิสเตอร์อาร์กิวเมนต์กี่ตัว
3. Patch คำสั่ง `nop` 5 ไบต์ที่ต้นฟังก์ชัน (จุดที่คอมไพเลอร์ใส่ไว้ให้ ftrace ด้วย `-mfentry`) ให้กลายเป็น `call bpf_trampoline_XXXX` แบบ **direct call**

```bash
# ขณะมี fentry ติดอยู่บน do_sys_openat2
$ sudo cat /sys/kernel/tracing/enabled_functions
do_sys_openat2 (1) R   D   M 	tramp: ftrace_regs_caller+0x0/0x77 (call_direct_funcs+0x0/0x30)
	direct-->bpf_trampoline_6442561261+0x0/0xb4
```

บรรทัด `direct-->bpf_trampoline_...` ยืนยันว่า call site ถูกชี้ไปยัง trampoline ของ BPF โดยตรง (แฟล็ก `D` = direct)

```
        do_sys_openat2:                         bpf_trampoline_XXXX (JIT-generated):
   +--> call bpf_trampoline_XXXX  ---------->   save args (rdi, rsi, rdx) -> stack (u64 ctx[])
   |    push rbp                                __bpf_prog_enter()   (rcu, migrate_disable, [stats])
   |    ...  (เนื้อฟังก์ชันเดิม)                   call fentry prog(ctx)
   |    ret                                     __bpf_prog_exit()
   |                                            ---- ถ้ามี fexit: ----
   |                                            call ต่อจากจุด patch ของฟังก์ชันจริง
   |                                            save return value (rax) -> ctx[nr_args]
   |                                            call fexit prog(ctx)
   +------------------------------------------- ret
```

ข้อสังเกตสำคัญ:
- **fentry** ไม่มี `pt_regs` — โปรแกรมได้ `ctx` เป็นอาร์เรย์ `u64` ของอาร์กิวเมนต์ตามลำดับ
- **fexit** ไม่ต้องแก้ return address แบบ kretprobe เพราะ trampoline เป็นผู้ **เรียกฟังก์ชันจริงเอง** แล้วเก็บค่า `rax` ต่อท้ายอาร์กิวเมนต์ใน `ctx[]`
- แผนภาพย่อเส้นทางขากลับไว้: ถ้ามีแค่ fentry trampoline จะ `ret` กลับเข้าไปทำเนื้อฟังก์ชันต่อ แต่ถ้ามี fexit trampoline เรียกเนื้อฟังก์ชันเองแล้ว (หลังรัน fexit) จึงกลับไปยัง **ผู้เรียก** `do_sys_openat2` โดยข้ามเนื้อฟังก์ชันรอบสอง
- ถ้ามีหลายโปรแกรม (fentry + fexit) บนฟังก์ชันเดียวกัน เคอร์เนลจะรวมไว้ใน trampoline เดียว

### 1.3 Overhead ไม่ใช่ศูนย์: อะไรบ้างที่มีต้นทุน

ไม่ว่าจะเป็น kprobe หรือ fentry ทุกการเรียกฟังก์ชันจะมีต้นทุนอย่างน้อย:
1. **กลไกการเข้า (attach mechanism)**: ftrace + `pt_regs` (kprobe), return-address hijack (kretprobe) หรือ direct call + เซฟอาร์กิวเมนต์ (trampoline)
2. **ส่วนหัว/ท้ายของการรันโปรแกรม BPF**: `rcu_read_lock`, `migrate_disable`, ตรวจ recursion
3. **ตัวโปรแกรม BPF เอง**: map lookup/update, helper call ฯลฯ — ในการวัดของเรา โปรแกรมเล็กที่สุดที่ทำแค่ `@c = count()` ใช้เวลารันเฉลี่ยราว **20 ns** แล้ว (วัดด้วย `bpf_stats`) ซึ่งมากกว่าตัวเลข "< 5ns" ที่มักพูดกันเสียอีก

ดังนั้นคำกล่าวที่ถูกต้องกว่าคือ "trampoline มี overhead **ต่ำกว่า** kprobe/kretprobe โดยเฉพาะฝั่งขา return" ไม่ใช่ "ไม่มี overhead"

### 1.4 สองวิธีวัด overhead และสิ่งที่แต่ละวิธีมองไม่เห็น

| วิธี | วัดอะไร | สิ่งที่ **ไม่** รวม |
|---|---|---|
| **End-to-end** (load generator) — จับเวลา `openat()+close()` ล้านครั้ง เทียบ มี/ไม่มี probe | ต้นทุนรวมทั้งหมดที่ workload จริงรู้สึก | แยกไม่ได้ว่าส่วนไหนแพง; มี noise จากระบบ |
| **`bpf_stats`** (`sysctl kernel.bpf_stats_enabled=1` แล้วอ่าน `run_time_ns / run_cnt` จาก `bpftool prog show`) | เวลารันเฉลี่ยของ **ตัวโปรแกรม BPF** | ต้นทุนของ ftrace/`pt_regs`/return hijack/การเซฟอาร์กิวเมนต์ ซึ่งเป็นจุดที่ kprobe กับ fentry ต่างกันจริง |

> [!IMPORTANT]
> `bpf_stats_enabled` เองก็มี overhead (อ่านนาฬิกา 2 ครั้งต่อการรัน + อัปเดต per-CPU stats) จึงปิดเป็นค่าเริ่มต้น เปิดเฉพาะตอนวัด แล้ว **ต้องปิดกลับ** เสมอ (`sudo sysctl kernel.bpf_stats_enabled=0`) สคริปต์ `bench/run_bench.sh` คืนค่าเดิมให้อัตโนมัติด้วย `trap`

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `trampoline.c`

```c
struct fexit_event {
    __u64 duration_ns;
    __u32 pid;
    __s32 ret;
    char comm[TASK_COMM_LEN];
    char filename[64];
};
```
- **บรรทัด 15-21:** โครงสร้าง event ที่ส่งผ่าน ring buffer ขึ้น userspace: เวลาที่ใช้ใน `do_sys_openat2`, PID (tgid), ค่า return (fd หรือ `-errno`), ชื่อโปรเซส และชื่อไฟล์ (ตัดที่ 64 ไบต์) ฝั่ง Go มี struct `fexitEvent` ที่ layout ตรงกันทุกไบต์

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} start_map SEC(".maps");
```
- **บรรทัด 31-36:** เก็บ timestamp ตอนเข้าฟังก์ชัน โดยใช้ `pid_tgid` (ระดับ thread) เป็น key เพราะหลาย thread ของโปรเซสเดียวกันอาจเปิดไฟล์พร้อมกันได้

```c
SEC("fentry/do_sys_openat2")
int BPF_PROG(trace_openat2_entry, int dfd, const char *filename, struct open_how *how)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_map, &pid_tgid, &ts, BPF_ANY);
    return 0;
}
```
- **บรรทัด 44-52:**
  - `SEC("fentry/do_sys_openat2")` บอก libbpf/cilium-ebpf ว่าเป็นโปรแกรมชนิด `BPF_PROG_TYPE_TRACING` attach type `BPF_TRACE_FENTRY` ไปยังฟังก์ชันชื่อนี้ (ค้น BTF ID ตอนโหลด)
  - มาโคร `BPF_PROG()` (จาก `bpf_tracing.h`) แปลง `ctx` ที่เป็น `u64 *` ให้กลายเป็นพารามิเตอร์ที่มีชื่อและชนิดตามที่เราประกาศ ลำดับต้องตรงกับฟังก์ชันจริงในเคอร์เนล
  - บันทึกเวลาเริ่มต้นลง `start_map`

```c
SEC("fexit/do_sys_openat2")
int BPF_PROG(trace_openat2_exit, int dfd, const char *filename, struct open_how *how, int ret)
```
- **บรรทัด 61-62:** โปรแกรม fexit ได้อาร์กิวเมนต์เดิมทั้ง 3 ตัว **บวกค่า return เป็นตัวสุดท้าย** ชนิดของ `ret` ต้องตรงกับ BTF: บน Linux 7.0 ฟังก์ชันนี้คือ `static int do_sys_openat2(...)` จึงประกาศเป็น `int` (เวอร์ชันก่อนหน้าของแล็บนี้ประกาศเป็น `long` ซึ่งอ่าน 64 บิตจาก slot ที่ค่าจริงมีแค่ 32 บิต — ใช้งานได้เพราะถูก cast ทิ้งภายหลัง แต่ไม่ถูกต้องตามชนิด) ตรวจ signature ได้ด้วย:
  ```bash
  sudo bpftrace -lv 'fexit:do_sys_openat2'
  ```

```c
    __u64 *start_ts = bpf_map_lookup_elem(&start_map, &pid_tgid);
    if (!start_ts) {
        return 0;
    }
    __u64 duration_ns = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&start_map, &pid_tgid);
```
- **บรรทัด 65-71:** หา timestamp ขาเข้า ถ้าไม่เจอ (เช่น ฟังก์ชันเริ่มทำงานก่อนเรา attach fentry) ให้ข้าม แล้วลบ entry ทิ้งเพื่อไม่ให้ map เต็ม

```c
    struct fexit_event *e = bpf_ringbuf_reserve(&fexit_events, sizeof(*e), 0);
    ...
    e->ret = ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    bpf_ringbuf_submit(e, 0);
```
- **บรรทัด 73-84:** จองพื้นที่ใน ring buffer เติมข้อมูลแล้ว submit
  - `filename` เป็นพอยน์เตอร์ **user space** (`const char __user *`) จึงต้องอ่านผ่าน `bpf_probe_read_user_str()` ซึ่งเขียน NUL ปิดท้ายให้ แต่ **ไบต์หลัง NUL ไม่ถูกล้าง** (หน่วยความจำ ring buffer อาจมีข้อมูลเก่าค้างอยู่) ฝั่ง Go จึงต้องตัดสตริงที่ NUL ตัวแรก

### 2.2 ไฟล์ `main.go`

```go
	commFilter := flag.String("comm", "", "show only events whose process name (comm) equals this value, e.g. -comm cat")
```
- **บรรทัด 34:** แฟล็ก `-comm` สำหรับกรองเฉพาะโปรเซสที่สนใจ (กรองฝั่ง userspace) เพราะบนเครื่องจริงมี daemon เปิดไฟล์ตลอดเวลา

```go
	linkEntry, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TraceOpenat2Entry,
	})
```
- **บรรทัด 51-67:** `link.AttachTracing()` ใช้ syscall `BPF_LINK_CREATE` สร้าง BPF link สำหรับ fentry และ fexit (ชื่อฟังก์ชันเป้าหมายมาจาก section name ตอนโหลดแล้ว จึงไม่ต้องระบุซ้ำ) เมื่อ `Close()` link เคอร์เนลจะถอด trampoline และคืน `nop` ให้ฟังก์ชัน

```go
		comm := cString(ev.Comm[:])
		if *commFilter != "" && comm != *commFilter {
			continue
		}
		filename := cString(ev.Filename[:])
```
- **บรรทัด 107-111:** แปลง C string เป็น Go string ด้วย `cString()` (ตัดที่ NUL ตัวแรก) — เวอร์ชันก่อนใช้ `bytes.TrimRight(..., "\x00")` ซึ่งตัดเฉพาะ NUL ท้ายสุด ทำให้ชื่อไฟล์สั้นที่ตามหลังชื่อไฟล์ยาวอาจมีเศษข้อมูลเก่าติดมา

```go
		retStr := fmt.Sprintf("%d", ev.Ret)
		if ev.Ret < 0 {
			retStr = fmt.Sprintf("ERR(%d)", ev.Ret)
		}
```
- **บรรทัด 113-116:** ค่า return ติดลบคือ `-errno` เช่น `-2` = `ENOENT` (ไม่พบไฟล์)

### 2.3 ไฟล์ `main_test.go` (runtime test)

- attach fentry/fexit จริง แล้วให้ process ของเทสต์เอง `os.Open()` ไฟล์ที่มีอยู่ 1 ไฟล์ และไฟล์ที่ไม่มีอยู่ 1 ไฟล์
- อ่าน ring buffer กรองเฉพาะ PID ของตัวเอง แล้วตรวจว่า fexit เห็น `ret >= 0` (fd) และ `ret == -2` (`-ENOENT`) ตามลำดับ — เป็นการพิสูจน์ว่าการอ่าน return value ใน fexit ถูกต้อง

### 2.4 ไฟล์ `bench/openbench.c` และ `bench/run_bench.sh` (การวัด overhead)

- `openbench.c`: load generator ภาษา C วน `openat("/dev/null")` + `close()` N รอบ (ค่าเริ่มต้น 1,000,000) พิมพ์เวลาเฉลี่ยต่อรอบ (ns/op) ใช้ C แทน Python/Go เพื่อไม่ให้ overhead ของ runtime กลบสิ่งที่เราวัด
- `run_bench.sh`:
  1. คอมไพล์ `openbench` และจำค่า `kernel.bpf_stats_enabled` เดิมไว้ (คืนค่าด้วย `trap ... EXIT` แม้สคริปต์ล้มกลางทาง)
  2. **End-to-end:** สำหรับแต่ละชนิด probe — วัด baseline ใหม่ → รัน `bpftrace -e '<probe>:do_sys_openat2 { @c = count(); }'` เบื้องหลัง → วัดซ้ำ → ปิด bpftrace ทุกการวัดตรึง CPU ด้วย `taskset` และรายงานค่า **best-of-N** (ค่าน้อยสุด) เพื่อลดผลของ noise
  3. **bpf_stats:** เปิด `kernel.bpf_stats_enabled=1` รันโหลดใหม่ แล้วอ่าน `run_cnt`/`run_time_ns` ของโปรแกรมที่ bpftrace โหลด (ชื่อขึ้นต้นด้วย `kprobe_`, `kretprobe_`, `fentry_`, `fexit_`) ผ่าน `bpftool prog show -j | jq`
  - ทุก probe ใช้ body เดียวกัน (`count()` บน per-CPU map) ขนาดโปรแกรมหลัง verifier เท่ากัน (xlated 480B) จึงเปรียบเทียบได้ยุติธรรม

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจความพร้อมของเคอร์เนล
```bash
# ต้องมี BTF ของเคอร์เนล และ direct-call trampoline
ls -l /sys/kernel/btf/vmlinux
grep -E "CONFIG_DEBUG_INFO_BTF=|CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=" /boot/config-$(uname -r)

# ฟังก์ชันเป้าหมายต้องมีใน BTF และ trace ได้ (ไม่ถูก inline)
sudo bpftrace -lv 'fentry:do_sys_openat2'
```

### ขั้นตอนที่ 2: คอมไพล์และรันเทสต์
```bash
cd phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline
make generate && make build
make test          # = go test -exec sudo -v ./...
```

### ขั้นตอนที่ 3: รัน tracer แล้วสร้างเหตุการณ์
```bash
# หน้าต่างที่ 1: กรองเฉพาะโปรเซสชื่อ cat
sudo ./bin/trampoline-tracer -comm cat

# หน้าต่างที่ 2
cat /etc/hosts > /dev/null
```
> [!NOTE]
> บน Ubuntu 26.04 คำสั่ง `cat` เป็น Rust uutils ซึ่งตรวจไฟล์ด้วย `statx()` ก่อน ดังนั้น `cat /nonexistent_file` จะ **ไม่** เรียก `openat()` และไม่ปรากฏในตาราง ถ้าต้องการเห็น `ERR(-2)` ให้ใช้ `python3 -c 'open("/nonexistent_file")'` กับ `-comm python3` แทน (ในผลจริงด้านล่าง `cat` เองก็พยายามเปิดไฟล์ locale ที่ไม่มี จึงเห็น `ERR(-2)` อยู่แล้ว)

### ขั้นตอนที่ 4: ดู trampoline ที่เคอร์เนลสร้าง (ระหว่างที่ tracer ยังรันอยู่)
```bash
sudo bpftool prog show name trace_openat2_entry
sudo bpftool link show | grep -A1 tracing
sudo cat /sys/kernel/tracing/enabled_functions | grep -A1 openat2
```

### ขั้นตอนที่ 5: วัด overhead ของ kprobe / kretprobe / fentry / fexit
```bash
make bench                         # = ./bench/run_bench.sh
# ปรับได้: ITER=2000000 REPS=9 CPU=3 ./bench/run_bench.sh
sysctl kernel.bpf_stats_enabled    # ต้องกลับเป็น 0 หลังจบ
```
ควรปิดโปรแกรมหนัก ๆ อื่นก่อนวัด และรันซ้ำอย่างน้อย 3 ครั้ง

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), Intel Core i3-12100 (8 threads), CPU governor `powersave`, bpftrace v0.25.0 — เครื่องมีงานอื่นรันอยู่ระหว่างวัด (load average ~2)

### 4.1 `make test`
```text
=== RUN   TestFexitReturnValue
    main_test.go:113: pid=4102186 ret=14 latency=6.54us file=/tmp/w222918798131/exists.txt
    main_test.go:113: pid=4102186 ret=14 latency=0.90us file=/tmp/w222918798131/exists.txt
    main_test.go:113: pid=4102186 ret=-2 latency=1.58us file=/tmp/w222918798131/does-not-exist
--- PASS: TestFexitReturnValue (0.23s)
PASS
ok  	ebpf-noob-to-hero/phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline	0.239s
```
(`exists.txt` ปรากฏ 2 ครั้งเพราะเทสต์เปิดไฟล์นี้ทั้งตอน `os.WriteFile` และ `os.Open`)

### 4.2 `sudo ./bin/trampoline-tracer -comm cat` + `cat /etc/hosts` (2 ครั้ง ตัดแสดงเฉพาะรอบแรก)
```text
======================================================================
 eBPF Trampoline (fentry & fexit) do_sys_openat2 Latency Tracer
======================================================================
2026/10/28 22:06:26 [INFO] Attached BPF Trampoline fentry to 'do_sys_openat2'
2026/10/28 22:06:26 [INFO] Attached BPF Trampoline fexit to 'do_sys_openat2'
2026/10/28 22:06:26 [INFO] Filtering events: comm == "cat" (filter applied in userspace)
2026/10/28 22:06:26 [INFO] Tracing do_sys_openat2 latency (fentry -> fexit). Press Ctrl+C to stop.

TIME      PID      COMM             FD / RET   LATENCY    FILENAME
---------------------------------------------------------------------------------------------------
22:06:28  4102636  cat              3          2.18us     /etc/ld.so.cache
22:06:28  4102636  cat              3          1.65us     /usr/lib/x86_64-linux-gnu/libsystemd.so.0
22:06:28  4102636  cat              3          0.80us     /usr/lib/x86_64-linux-gnu/libselinux.so.1
22:06:28  4102636  cat              3          0.70us     /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
22:06:28  4102636  cat              3          0.79us     /usr/lib/x86_64-linux-gnu/libm.so.6
22:06:28  4102636  cat              3          0.77us     /usr/lib/x86_64-linux-gnu/libc.so.6
22:06:28  4102636  cat              3          1.40us     /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0
22:06:28  4102636  cat              3          3.98us     /proc/filesystems
22:06:28  4102636  cat              3          10.05us    /proc/self/maps
22:06:28  4102636  cat              3          1.31us     /usr/share/coreutils/locales/uucore/en-US.ftl
22:06:28  4102636  cat              ERR(-2)    1.08us     /usr/share/coreutils/locales/cat/en-US.ftl
22:06:28  4102636  cat              3          0.85us     /etc/hosts
...

[INFO] Detaching trampoline links...
[SUCCESS] BPF Trampoline detached safely.
```

### 4.3 ตรวจ trampoline ขณะ tracer รัน (ขั้นตอนที่ 4)
```text
$ sudo bpftool prog show name trace_openat2_entry
10434: tracing  name trace_openat2_entry  tag ce50c9874ea1917c  gpl
	loaded_at 2026-10-28T22:11:58+0700  uid 0
	xlated 112B  jited 73B  memlock 4096B  map_ids 4730
$ sudo bpftool link show | grep -A1 tracing
3968: tracing  prog 10434  
	prog_type tracing  attach_type trace_fentry  
	target_obj_id 1  target_btf_id 110317  
3969: tracing  prog 10435  
	prog_type tracing  attach_type trace_fexit  
	target_obj_id 1  target_btf_id 110317  
$ sudo cat /sys/kernel/tracing/enabled_functions | grep -A1 openat2
do_sys_openat2 (1) R   D   M 	tramp: ftrace_regs_caller+0x0/0x77 (call_direct_funcs+0x0/0x30)
	direct(jmp)-->bpf_trampoline_6442561261+0x0/0x124
```
- `target_btf_id 110317` คือ BTF ID ของ `FUNC 'do_sys_openat2'` ใน `/sys/kernel/btf/vmlinux` (`target_obj_id 1` = vmlinux)
- fentry + fexit ทั้งสองใช้ trampoline เดียวกัน (`bpf_trampoline_6442561261`) ขนาดใหญ่ขึ้นจากตอนมีแค่ fentry (0xb4 → 0x124 ไบต์) เพราะต้องมีโค้ดเรียกฟังก์ชันจริงและส่วนของ fexit
- หลัง Ctrl+C บรรทัด `do_sys_openat2` หายไปจาก `enabled_functions` (นับได้ 0)

### 4.4 ผลวัด overhead (`bench/run_bench.sh`, `REPS=9`) — รอบที่ noise ต่ำที่สุด
```text
== (1) End-to-end: openat()+close() on /dev/null, 1000000 iters, best of 9, pinned CPU 2 ==
probe          baseline   with-probe      delta
kprobe         594.6 ns     639.4 ns   +44.8 ns
kretprobe      595.9 ns     744.3 ns  +148.4 ns
fentry         592.9 ns     605.7 ns   +12.8 ns
fexit          587.3 ns     623.5 ns   +36.2 ns

== (2) bpf_stats: average BPF program run time (run_time_ns / run_cnt) ==
kprobe_	kprobe	run_cnt=1045108	run_time_ns=21670211	avg=20.7 ns
kretprobe_	kprobe	run_cnt=1048148	run_time_ns=21749414	avg=20.7 ns
fentry_	tracing	run_cnt=1016291	run_time_ns=23113427	avg=22.7 ns
fexit_	tracing	run_cnt=1025165	run_time_ns=22806309	avg=22.2 ns

kernel.bpf_stats_enabled restored to 0
```

### 4.5 สรุปจาก 4 รอบการวัด (หน่วย ns ต่อการเรียก)

รอบ 1–3 ใช้ `REPS=9` (รอบ 3 คือผลในหัวข้อ 4.4) รอบ 4 คือ `make bench` ค่าเริ่มต้น (`REPS=5`)

| Probe | delta รอบ 1 | delta รอบ 2 | delta รอบ 3 | delta รอบ 4 | `bpf_stats` avg (รอบ 1 / 2 / 3 / 4) |
|---|---|---|---|---|---|
| kprobe | +44.2 | −9.6 * | +44.8 | +49.7 | 20.3 / 20.1 / 20.7 / 21.1 |
| kretprobe | −67.1 * | +159.3 | +148.4 | +143.4 | 28.2 / 20.6 / 20.7 / 21.2 |
| fentry | +25.6 | −19.5 * | +12.8 | +17.5 | 28.3 / 22.5 / 22.7 / 23.3 |
| fexit | +34.0 | +84.1 | +36.2 | +43.9 | 39.1 / 22.5 / 22.2 / 22.8 |

\* ค่าติดลบเกิดเมื่อ baseline รอบนั้นถูกรบกวน (baseline พุ่งเป็น 637–802 ns จากปกติ ~590 ns) จึงไม่ควรนำมาตีความ

**การตีความ (อย่างระมัดระวัง):**
- **kretprobe แพงที่สุดอย่างชัดเจนและสม่ำเสมอ** (~+145–160 ns ต่อการเรียกเมื่อ baseline นิ่ง) ขณะที่ **fexit** ซึ่งให้ข้อมูลเดียวกัน (ค่า return) ใช้ราว +35–45 ns → นี่คือข้อได้เปรียบที่ชัดที่สุดของ trampoline
- **fentry vs kprobe** ที่ต้นฟังก์ชัน: fentry ต่ำกว่า (~+13–26 ns เทียบ ~+45–50 ns) แต่ส่วนต่างอยู่ในระดับเดียวกับ noise ของเครื่องที่วัด เพราะ kprobe บนเคอร์เนลนี้ใช้ ftrace (`[FTRACE]`) ไม่ใช่ `int3` แล้ว
- **`bpf_stats`** แสดงว่าตัวโปรแกรม BPF เองใช้เวลาใกล้เคียงกันทุกชนิด (~20–23 ns ในรอบที่นิ่ง; รอบ 1 สูงกว่าเพราะ noise) ความต่างจริงจึงอยู่ที่ **กลไกการเข้า/ออก** ซึ่ง `bpf_stats` มองไม่เห็น
- **ไม่มีกลไกใดเป็น "zero overhead" หรือ "< 5ns"** — แค่ตัวโปรแกรม BPF ที่เล็กที่สุดก็ใช้ ~20 ns แล้ว

**ข้อควรระวังของตัวเลขชุดนี้:** วัดบนเครื่องเดียว, CPU governor `powersave` (ความถี่ไม่คงที่), มีงานอื่นรันพร้อมกัน, ฟังก์ชันเดียว (`do_sys_openat2`) และ body เดียว (`count()`) ตัวเลขจะเปลี่ยนตาม CPU, เคอร์เนล config (เช่น mitigations), และชนิดงานในโปรแกรม BPF ควรวัดซ้ำบนเครื่องของตัวเองก่อนนำไปอ้างอิง

---

## 5. ข้อจำกัด (Limitations)

1. **ต้องมี BTF และ direct-call trampoline:** ต้องมี `/sys/kernel/btf/vmlinux` และ `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS` (x86-64, arm64 รุ่นใหม่) ถ้าไม่มี การ attach จะล้มเหลวและต้องถอยกลับไปใช้ kprobe
2. **ฟังก์ชันต้อง trace ได้:** ฟังก์ชันที่ถูก inline, ถูกทำเครื่องหมาย `notrace`, หรือไม่มีใน BTF จะ attach ไม่ได้ (เช็กด้วย `bpftrace -l 'fentry:<func>'`) และชื่อ/signature ของฟังก์ชันภายในเคอร์เนลอาจเปลี่ยนข้ามเวอร์ชัน (เช่น `do_sys_openat2` เคยคืน `long` ในบางเวอร์ชัน) — ต่างจาก tracepoint ที่เป็น ABI ค่อนข้างเสถียร
3. **จำนวนอาร์กิวเมนต์จำกัด:** trampoline รองรับอาร์กิวเมนต์ได้จำนวนจำกัดตามสถาปัตยกรรม (x86-64 เคอร์เนลรุ่นใหม่รองรับได้ถึง 12 ตัว แต่ struct ที่ส่งแบบ by-value มีข้อจำกัดเพิ่ม — ตรวจกับเอกสารของเคอร์เนลที่ใช้)
4. **ต้องเป็น GPL:** โปรแกรม tracing ต้องประกาศ `LICENSE` เป็น GPL-compatible
5. **ข้อมูลใน event ถูกตัด:** `filename` ตัดที่ 64 ไบต์, `comm` ที่ 16 ไบต์ และการอ่าน user memory ใน fexit อ่านค่า ณ ตอนที่ฟังก์ชัน return ซึ่ง thread อื่นในโปรเซสเดียวกันอาจแก้บัฟเฟอร์ไปแล้ว (TOCTOU) — สำหรับงาน security ควรอ่านจากโครงสร้างในเคอร์เนลที่ copy แล้วแทน
6. **การกรองอยู่ฝั่ง userspace:** `-comm` ไม่ลดภาระของเคอร์เนล ทุกการเปิดไฟล์ในเครื่องยังถูกส่งขึ้น ring buffer (บนเครื่องที่ยุ่งควรกรองในโปรแกรม BPF แทน — ดูแบบฝึกหัด)
7. **ผลวัด overhead มี noise สูง:** ส่วนต่างระหว่าง kprobe กับ fentry เล็กกว่า noise ของการวัดบนเครื่องที่มีงานอื่น ข้อสรุปที่มั่นใจได้มีแค่ "kretprobe แพงกว่า fexit ชัดเจน" และ "ไม่มีตัวใด overhead เป็นศูนย์"

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ | สาเหตุ / วิธีแก้ |
|---|---|
| `program trace_openat2_entry: attach Tracing/TraceFEntry: fentry do_sys_openat2_nope not supported` | ชื่อฟังก์ชันไม่มีใน BTF ของเคอร์เนล (สะกดผิด ถูก inline หรือเปลี่ยนชื่อในเวอร์ชันนี้) ตรวจด้วย `sudo bpftrace -l 'fentry:*openat*'` แล้วเปลี่ยนเป้าหมาย |
| `load program: permission denied: func 'do_sys_openat2' doesn't have 5-th argument: invalid bpf_context access off=32 size=8` | ประกาศอาร์กิวเมนต์ใน `BPF_PROG()` เกินจำนวนจริง (fexit มีได้ = จำนวนอาร์กิวเมนต์ + 1 สำหรับ ret) ตรวจ signature ด้วย `sudo bpftrace -lv 'fexit:do_sys_openat2'` |
| `operation not permitted` | ไม่ได้รันด้วย `sudo` (ต้องมี `CAP_BPF` + `CAP_PERFMON`) |
| `fatal error: 'vmlinux.h' file not found` | สร้างด้วย `make vmlinux` ที่ root ของ repo (หรือ `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`) |
| ไม่เห็นบรรทัด `ERR(-2)` ของ `cat /nonexistent_file` | Rust `cat` เช็ก `statx()` ก่อนเปิดไฟล์ ดูหมายเหตุในขั้นตอนที่ 3 |
| `make bench` ได้ค่าติดลบ/แกว่งมาก | เครื่องมี noise สูง ปิดงานอื่น เพิ่ม `REPS`/`ITER` หรือเปลี่ยน governor เป็น `performance` ชั่วคราว |

---

## 7. Milestone Checklist

- [x] อธิบายได้ว่า kprobe ที่ต้นฟังก์ชันบนเคอร์เนลสมัยใหม่ใช้ ftrace (`[FTRACE]`) และ kretprobe ใช้การแก้ return address
- [x] อธิบายการทำงานของ BPF trampoline: patch nop → direct call → เซฟอาร์กิวเมนต์ → เรียก fentry → เรียกฟังก์ชันจริง → fexit
- [x] เขียน `fentry`/`fexit` ด้วย `BPF_PROG()` และประกาศชนิดของค่า return ให้ตรงกับ BTF
- [x] วัดเวลาใน `do_sys_openat2` ต่อการเรียกและส่งผลขึ้น userspace ผ่าน ring buffer
- [x] ทดสอบความถูกต้องของค่า return ใน fexit ด้วย runtime test (`make test`)
- [x] วัด overhead ของ kprobe/kretprobe/fentry/fexit ด้วย load generator และ `bpf_stats` พร้อมคืนค่า sysctl
- [x] ตีความผลวัดอย่างระมัดระวัง แยก signal ออกจาก noise และไม่อ้างตัวเลขที่ไม่ได้วัด

---

## 8. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **เปลี่ยนเป้าหมายเป็นฟังก์ชันอื่น:** แก้ `trampoline.c` ให้ trace `vfs_read` แทน (ดู signature ด้วย `sudo bpftrace -lv 'fexit:vfs_read'`) แสดงจำนวนไบต์ที่อ่านได้ (ค่า return) 
   - **ตรวจสอบ:** รัน tracer ด้วย `-comm dd` แล้วสั่ง `dd if=/dev/zero of=/dev/null bs=4096 count=5` ต้องเห็นบรรทัดที่ค่า return = `4096` อย่างน้อย 5 บรรทัด (บรรทัดอื่นมาจาก dynamic loader อ่านไฟล์ library)
2. **ส่องโปรแกรมที่โหลดอยู่:** ขณะ tracer รัน ใช้ `bpftool prog show`, `bpftool link show` และ `/sys/kernel/tracing/enabled_functions` ระบุ prog ID, link ID และชื่อ `bpf_trampoline_*` 
   - **ตรวจสอบ:** หลัง Ctrl+C แล้ว `enabled_functions` ต้องไม่มี `do_sys_openat2` เหลืออยู่

### ระดับปานกลาง
1. **ย้ายการกรองเข้าเคอร์เนล:** เพิ่ม global variable `const volatile char target_comm[16]` ใน C แล้วตั้งค่าจาก Go ผ่าน `spec.RewriteConstants()` (หรือ `spec.Variables` ใน cilium/ebpf รุ่นใหม่) ก่อนโหลด ให้โปรแกรม fexit ไม่ส่ง event ถ้า comm ไม่ตรง 
   - **ตรวจสอบ:** เปิด `bpf_stats` ชั่วคราวแล้วเทียบจำนวน event ที่ userspace ได้รับกับ `run_cnt` ของ fexit — event ต้องน้อยกว่ามาก
2. **Histogram แทน event รายตัว:** เปลี่ยนจาก ring buffer เป็น `BPF_MAP_TYPE_ARRAY` ที่นับ latency แบบ log2 bucket (แนว `biolatency` ของ Week 17) แล้วพิมพ์ histogram ทุก 5 วินาที 
   - **ตรวจสอบ:** รัน `find /usr -type f > /dev/null` ระหว่างวัด แล้ว histogram ต้องมีค่าใน bucket ช่วง 1–8 µs เพิ่มขึ้นชัดเจน

### ระดับท้าทาย
1. **ทำซ้ำการวัด overhead ด้วยโปรแกรมของตัวเอง:** เขียนโปรแกรม C/Go 4 ตัว (kprobe, kretprobe, fentry, fexit) ที่ทำงานเหมือนกันทุกประการ (เช่น `__sync_fetch_and_add` บน array map) แทน bpftrace แล้ววัดด้วย `openbench` เพิ่มเงื่อนไข "probe ว่าง (return 0 ทันที)" เพื่อแยกต้นทุนของกลไกออกจากต้นทุนของ body 
   - **ตรวจสอบ:** รายงานตาราง delta (mean ± stddev จากอย่างน้อย 10 รอบ) และอธิบายว่าผลสอดคล้องหรือขัดกับหัวข้อ 4.5 อย่างไร
2. **fexit บนโปรแกรม BPF:** fentry/fexit สามารถ attach กับ **โปรแกรม BPF อื่น** ได้ (ใน cilium/ebpf ตั้ง `ProgramSpec.AttachTarget` เป็น `*ebpf.Program` ปลายทาง และ `AttachTo` เป็นชื่อฟังก์ชันของโปรแกรมนั้น ก่อนโหลด แล้วใช้ `link.AttachTracing`) ลองเขียน fexit ที่ไปเกาะโปรแกรม XDP ของ Week 07 (ที่รันใน netns ทดสอบ) เพื่อนับว่า XDP คืนค่า `XDP_DROP` กี่ครั้ง 
   - **ตรวจสอบ:** ตัวนับของคุณต้องเท่ากับ `dropped_packets` ใน map `blocked_ips` ของ Week 07 หลังยิง ping 5 ครั้ง
