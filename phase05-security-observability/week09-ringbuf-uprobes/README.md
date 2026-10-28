# Week 09: Ring Buffer & Uprobes Security Observability

คู่มือการศึกษาเชิงลึกเกี่ยวกับการสตรีมข้อมูลความเร็วสูงผ่าน **eBPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`)** และการดักจับพฤติกรรมในระดับ User-space ด้วย **Uprobes (`SSL_write`)** ร่วมกับ Tracepoint (`sched_process_exec` / `sys_enter_execve`) โดยใช้ **CO-RE** (`vmlinux.h` + `BPF_CORE_READ`)

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 วิวัฒนาการจาก BPF Perf Buffer สู่ BPF Ring Buffer
ในยุคแรกเริ่มของ eBPF การส่งข้อมูล Event จาก Kernel space กลับมายัง User space มักพึ่งพา `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (Perf Buffer) ซึ่งออกแบบมาบนโครงสร้างแบบ **Per-CPU Circular Buffer** โดยแต่ละ CPU Core จะมี Memory Buffer แยกอิสระจากกัน

```
+------------------------------------------------------------------------+
|                      ปัญหาของ BPF PERF BUFFER                           |
|                                                                        |
|  CPU 0  [==== Event 1 ====] [==== Event 4 ====]  ---> User Reader 0    |
|  CPU 1  [==== Event 2 ====]                      ---> User Reader 1    |
|  CPU 2  [==== Event 3 ====] [==== Event 5 ====]  ---> User Reader 2    |
|                                                                        |
|  1. ลำดับเวลา (Ordering): Event 1-5 สลับลำดับกันข้าม Core              |
|  2. Memory Fragmentation: CPU ที่งานหนัก Buffer เต็ม/Drop               |
|     ขณะที่ CPU ว่าง มี Memory เหลือทิ้ง                                |
+------------------------------------------------------------------------+
```

ข้อจำกัดสำคัญของ Perf Buffer:
1. **Memory Inefficiency**: หากเรามีระบบที่มี 128 Cores และจัดสรรบัฟเฟอร์ขนาด 4MB ต่อ Core ระบบจะต้องเสียหน่วยความจำไปถึง `128 x 4MB = 512MB` ทั้งๆ ที่ส่วนใหญ่ของคอร์อาจไม่มี Event เกิดขึ้นเลย
2. **Event Re-ordering**: หากโปรเซสสลับการทำงานข้าม CPU core เหตุการณ์ที่เกิดขึ้นก่อน-หลังจะถูกเขียนลงต่างบัฟเฟอร์กัน ส่งผลให้ User space ได้รับ Event สลับลำดับเวลา
3. **Double Copy**: Perf Buffer บังคับให้โปรแกรม eBPF สร้าง Struct บน eBPF stack ก่อน แล้วจึงเรียกฟังก์ชันคัดลอกข้อมูลซ้ำไปยัง Perf Buffer

ใน Linux Kernel 5.8 เป็นต้นมา จึงมีการแนะนำ **`BPF_MAP_TYPE_RINGBUF`**:
- **Multi-Producer Single-Consumer (MPSC)**: เป็นบัฟเฟอร์หน่วยความจำก้อนเดียวที่แชร์ร่วมกันทุก CPU Cores โดย Kernel space เป็น Producers และ User space ตัวเดียวเป็น Consumer
- **Ordering ข้าม CPU**: Event ถูกต่อคิวตามลำดับที่ `bpf_ringbuf_reserve()` สำเร็จ (ไม่ใช่ timestamp จริงของเหตุการณ์) จึงเรียงลำดับได้ดีกว่า Perf Buffer มาก แต่ถ้าต้องการลำดับเวลาที่แม่นยำให้ใช้ field `ts_ns` ประกอบ
- **Reserve-Commit (ไม่ต้อง copy ซ้ำ)**: เขียนข้อมูลลงพื้นที่ที่จองไว้ใน buffer โดยตรงผ่าน `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()` (ฝั่ง user space อ่านผ่าน memory-mapped pages)

```
+-------------------------------------------------------------------------+
|                  สถาปัตยกรรม BPF RING BUFFER (MPSC)                     |
|                                                                         |
|   eBPF Probe (CPU 0) ---\                                               |
|   eBPF Probe (CPU 1) ----+--> [ bpf_ringbuf_reserve() ]                 |
|   eBPF Probe (CPU 2) ---/            |                                  |
|                                      v                                  |
|                 +--------------------------------------+                |
|                 | Shared Single Ring Buffer (16 MB)    |                |
|                 | [Header][Event 1][Header][Event 2].. |                |
|                 +--------------------------------------+                |
|                                      |                                  |
|                                      v epoll / ringbuf.Reader           |
|                          +-----------------------+                      |
|                          | User-space Controller |                      |
|                          | (main.go Agent)       |                      |
|                          +-----------------------+                      |
+-------------------------------------------------------------------------+
```

### 1.2 วงจรชีวิต Reserve-Commit Pattern
ในการส่งข้อมูลด้วย Ring Buffer จะมี 3 ขั้นตอน (2 helper call):
1. **`bpf_ringbuf_reserve(map, size, flags)`**: จัดสรรหน่วยความจำล่วงหน้าใน Ring Buffer ขนาดที่ต้องการ หากพื้นที่เต็ม ฟังก์ชันจะคืนค่า `NULL` ทันที ทำให้เรา Drop เหตุการณ์ได้อย่างปลอดภัยโดยไม่บล็อกเคอร์เนล (แต่ event นั้นหายไป -- ดูหัวข้อ Limitations)
2. เขียนข้อมูลลงใน Pointer ที่ได้รับโดยตรง (Direct Memory Access) โดยไม่ต้องผ่าน eBPF Stack
3. **`bpf_ringbuf_submit(ptr, flags)`**: ทำการ Commit บันทึก Header ขนาดและสถานะของ Event เพื่อส่งสัญญาณแจ้งเตือน User space ผ่านระบบ Notification

### 1.3 ทฤษฎี Uprobes (User-Space Probes)
Uprobe คือกลไกของ Linux Tracing Infrastructure ที่อนุญาตให้ใส่จุด Breakpoint ลงไปใน Binary ที่รันอยู่ใน User space เช่น Executable ELF หรือ Shared Libraries (`.so`) จุดสำคัญคือ uprobe ผูกกับ **ไฟล์ (inode) + offset ของฟังก์ชัน** ไม่ได้ผูกกับ process ใด process หนึ่ง ดังนั้นเมื่อเราวาง uprobe บน `libssl.so.3` ทุก process ที่ map ไฟล์นี้ (curl, python3, ...) จะถูกดักทั้งหมด

```
+-------------------------------------------------------------------------+
|                    กลไกการทำงานของ UPROBE BREAKPOINT                    |
|                                                                         |
|  User Process (เช่น curl, python3)                                      |
|  |                                                                      |
|  +---> เรียกใช้งาน SSL_write(ssl, buf, num)                             |
|        |                                                                |
|        | [ 0xCC (int3) ถูกเขียนทับคำสั่งแรกของฟังก์ชันใน page ของ process ] |
|        v                                                                |
|  #BP exception เข้าสู่ Linux Kernel (uprobes subsystem จัดการเอง          |
|  ไม่มี SIGTRAP ส่งถึง process)                                         |
|        |                                                                |
|        v                                                                |
|  Kernel เรียก eBPF Handler: uprobe_ssl_write(struct pt_regs *ctx)       |
|        | BPF_UPROBE() แกะ arg2 (buf = %rsi), arg3 (num = %rdx)          |
|        | คัดลอก Plaintext payload ด้วย bpf_probe_read_user()            |
|        v                                                                |
|  Kernel จำลอง/single-step คำสั่งเดิมที่ถูกแทนที่ แล้วให้ OpenSSL ทำงานต่อ  |
+-------------------------------------------------------------------------+
```

> **ต้นทุน (Overhead)**: ทุกครั้งที่ฟังก์ชันถูกเรียกจะเกิด exception เข้า kernel 1 รอบ (ระดับไมโครวินาที ขึ้นกับ CPU/kernel) ไม่ใช่ "zero-overhead" ถ้าวางบนฟังก์ชันที่ถูกเรียกถี่มากๆ จะเห็นผลกระทบชัดเจน ควรวัดผลบนเครื่องจริงก่อนใช้งาน production

### 1.4 การดักจับ Plaintext ก่อนเข้ารหัส (SSL/TLS Interception)
ในกระบวนการทำงานของ OpenSSL เมื่อแอปพลิเคชันต้องการส่งข้อมูลผ่านช่องทางปลอดภัย จะเรียกใช้ฟังก์ชันใดฟังก์ชันหนึ่งต่อไปนี้:
```c
int SSL_write(SSL *ssl, const void *buf, int num);                       /* curl ใช้ตัวนี้ */
int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written); /* CPython ใช้ตัวนี้ */
```
- `buf` คือพอยน์เตอร์ไปยังข้อมูล Plaintext ก่อนถูกเข้ารหัสด้วย Symmetric Key ของ TLS session
- `num` คือจำนวนไบต์ของ Plaintext

การวาง Uprobe ที่จุดเริ่มต้นของทั้งสองฟังก์ชันทำให้ eBPF มองเห็น Payload ที่ยังไม่ได้ถูกเข้ารหัส (สูงสุด 127 ไบต์แรกต่อการเรียก 1 ครั้งในแล็บนี้) โดยไม่ต้องทำ Man-in-the-Middle (MITM) หรือติดตั้ง Certificate ปลอม

> **ทำไมต้องดักทั้ง `SSL_write` และ `SSL_write_ex`?** เวอร์ชันก่อนหน้าของแล็บดักแค่ `SSL_write` ผลที่ทดสอบจริงบนเครื่อง lab คือ `curl` ถูกดักได้ แต่ `python3 urllib` **มองไม่เห็นเลย** เพราะ CPython เรียก `SSL_write_ex` (ทั้งสองเป็น exported symbol แยกกันใน `libssl.so.3` ตรวจได้ด้วย `readelf -Ws --dyn-syms /usr/lib/x86_64-linux-gnu/libssl.so.3 | grep -w SSL_write_ex`) หลังเพิ่ม uprobe ตัวที่สอง จึงเห็น request ของ Python ด้วย และ curl ไม่ได้ถูกนับซ้ำ (ดูผลในหัวข้อ 4)

### 1.5 ข้อควรระวังด้านจริยธรรมและกฎหมาย (Ethics & Consent)

> **คำเตือน**: เครื่องมือในสัปดาห์นี้อ่านข้อมูลที่ **ผู้ใช้ตั้งใจเข้ารหัส** ได้ เช่น HTTP header, cookie, token, รหัสผ่านใน request body ของ **ทุก process ทุก user บนเครื่อง** ที่ใช้ `libssl` ตัวที่ถูก probe
> - รันได้เฉพาะบน **เครื่องที่คุณเป็นเจ้าของ** หรือได้รับ **อนุญาตเป็นลายลักษณ์อักษร** ให้ทำการทดสอบ/เฝ้าระวังเท่านั้น (เช่น VM ของตัวเองสำหรับแล็บ)
> - ห้ามใช้บนเครื่องที่มีผู้ใช้อื่นโดยที่เขาไม่ทราบ การดักข้อมูลการสื่อสารของผู้อื่นโดยไม่ได้รับอนุญาตอาจผิดกฎหมาย (เช่น พ.ร.บ.ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ และ พ.ร.บ.คุ้มครองข้อมูลส่วนบุคคล (PDPA)) และผิดนโยบายของหน่วยงาน -- หากไม่แน่ใจให้ปรึกษาฝ่ายกฎหมาย/IT security ของหน่วยงานก่อน
> - ในงานจริง (EDR / observability) ควรกรองหรือ mask ข้อมูลอ่อนไหวตั้งแต่ใน kernel/agent และเก็บ log ให้น้อยที่สุดเท่าที่จำเป็น
> - ทดสอบด้วยเว็บสาธารณะที่ไม่มีข้อมูลส่วนตัว เช่น `https://example.com` เท่านั้น

### 1.6 ขอบเขตการมองเห็นของ Uprobe บน `libssl` (What it can and cannot see)

`main.go` ค้นหาไฟล์ `libssl.so` ตามลำดับใน `commonLibsslPaths` และใช้ **ไฟล์แรกที่พบ** (หรือไฟล์ที่ระบุด้วย `-libssl`) บน Ubuntu 26.04 x86_64 คือ `/lib/x86_64-linux-gnu/libssl.so.3` ซึ่งเป็น symlink ของ merged-usr ชี้ไปที่ `/usr/lib/x86_64-linux-gnu/libssl.so.3` (ไฟล์เดียวกัน; โปรแกรมพิมพ์ path ที่ resolve แล้วให้ดูตอนเริ่มทำงาน)

| โปรแกรม / TLS stack | มองเห็นหรือไม่ | เหตุผล |
| :--- | :---: | :--- |
| `curl` (Ubuntu: libcurl + OpenSSL 3) | เห็น | เรียก `SSL_write` ใน `libssl.so.3` แบบ dynamic link (ทดสอบแล้ว) |
| `python3` (`ssl` / `urllib`) | เห็น | `_ssl` module link กับ `libssl.so.3` และเรียก `SSL_write_ex` (ทดสอบแล้ว) |
| `wget` (Ubuntu) | **ไม่เห็น** | link กับ **GnuTLS** (`libgnutls.so.30`) ไม่ใช่ OpenSSL (ทดสอบแล้ว: เห็นแค่ exec) |
| โปรแกรม Go (`crypto/tls`) | **ไม่เห็น** | Go implement TLS เองใน binary ไม่เรียก libssl เลย |
| Rust `rustls` | **ไม่เห็น** | TLS stack ของตัวเอง ไม่ใช้ OpenSSL |
| binary ที่ link OpenSSL แบบ **static** / BoringSSL (เช่น Chrome, Envoy บาง build) | **ไม่เห็น** | ฟังก์ชันอยู่ใน binary ของโปรแกรมเอง ไม่ได้อยู่ในไฟล์ `libssl.so.3` ที่เรา probe (ต้อง probe ที่ binary นั้นและต้องมี symbol) |
| โปรแกรมใน container ที่ใช้ `libssl` ของ image ตัวเอง | **ไม่เห็น** | เป็นไฟล์/inode คนละตัวกับ libssl ของ host |
| แอปที่ใช้ `libssl.so.1.1` หรือ OpenSSL ที่ติดตั้งใน path อื่น | ไม่เห็น (ยกเว้นระบุ `-libssl`) | uprobe ติดเฉพาะไฟล์ที่เลือก 1 ไฟล์ |
| kTLS (`SSL_sendfile` / kernel TLS offload) | ไม่เห็นบางส่วน | ข้อมูลอาจไม่ผ่าน `SSL_write*` เลย |

### 1.7 เลือก Hook สำหรับ Process Execution: `sched_process_exec` vs `sys_enter_execve`

แล็บนี้มี exec tracepoint ให้เลือก 2 แบบ (เลือกด้วย `-exec-hook`):

| | `sched/sched_process_exec` (ค่าเริ่มต้น) | `syscalls/sys_enter_execve` (`-exec-hook=syscall`) |
| :--- | :--- | :--- |
| ยิงเมื่อไร | หลัง execve **สำเร็จ** และ binary ใหม่ถูกโหลดแล้ว | ตอน **เข้า** syscall (ยังไม่รู้ว่าจะสำเร็จไหม) |
| filename อ่านจาก | หน่วยความจำ kernel (`__data_loc` ใน tracepoint record) | pointer ใน user space (`args[0]`) |
| TOCTOU | ไม่มี: เป็นชื่อที่เคอร์เนลใช้ exec จริง | มี: thread อื่นแก้ buffer หลังเราอ่านได้ |
| `comm` | ชื่อโปรแกรมใหม่ (เช่น `curl`) | ชื่อโปรแกรมเดิม (เช่น `bash`) |
| ครอบคลุม `execveat()` | ใช่ | ไม่ (ต้อง hook `sys_enter_execveat` เพิ่ม) |

> **ข้อสังเกตจริงบน Linux 7.0.0-38-generic (เครื่อง lab นี้)**: เมื่อ attach BPF program กับ `syscalls/sys_enter_*` tracepoint (ทั้งผ่าน cilium/ebpf `link.Tracepoint` และ `bpftrace`) program ถูกเรียก **เฉพาะเมื่อ syscall เกิดบน CPU 0** เท่านั้น ทดสอบด้วย `taskset -c 0 /usr/bin/true` x30 และ `taskset -c 3 /usr/bin/true` x30: `sys_enter_execve` นับได้ 30 ครั้งบน CPU 0 และ **0 ครั้ง** บน CPU 3 ขณะที่ `sched_process_exec` นับได้ครบ 30/30 ทั้งสอง CPU (เครื่อง 8 cores จึงเห็นเพียง ~1/8 ของ exec ทั้งหมด) ผู้เขียนยังไม่ได้ยืนยันสาเหตุใน kernel source -- อาจเป็น regression เฉพาะเวอร์ชัน ให้ตรวจสอบกับ kernel ของคุณเองด้วยแบบฝึกหัดข้อ 7.3 ด้วยเหตุนี้แล็บจึงใช้ `sched_process_exec` เป็นค่าเริ่มต้น ซึ่งดีกว่าในเชิง security อยู่แล้ว (ไม่มี TOCTOU และรายงานเฉพาะ exec ที่สำเร็จ)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 eBPF C Program (`ringbuf_events.c`)

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
```
- **บรรทัด 9–12**: ใช้ **CO-RE** -- `vmlinux.h` (สร้างจาก BTF ของเคอร์เนลด้วย `bpftool btf dump file /sys/kernel/btf/vmlinux format c` ผ่าน `scripts/setup_env.sh` วางไว้ที่ root ของ repo) ให้ทุก type ของเคอร์เนล เช่น `struct task_struct`, `struct trace_event_raw_sys_enter` โดยไม่ต้องประกาศ struct เองแบบเวอร์ชันก่อน **ห้าม** include `<linux/*.h>` ร่วมกับ `vmlinux.h` เพราะ type จะถูกประกาศซ้ำ (redefinition) ค่าคงที่ที่ต้องใช้ให้ `#define` เอง (เช่น `TASK_COMM_LEN`)

```c
struct sec_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 data_len;
    __u8  event_type;
    __u8  pad[7];
    char  comm[TASK_COMM_LEN];
    char  payload[PAYLOAD_LEN];
};
```
- **บรรทัด 31–41**: โครงสร้าง Event ขนาดคงที่ 176 ไบต์ เรียง field จากใหญ่ไปเล็ก (8 → 4 → 1 ไบต์) และเติม `pad` เองจนครบ 8-byte boundary เพื่อไม่ให้ compiler แทรก padding ที่มองไม่เห็น ซึ่งจะทำให้ Go struct `secEvent` (decode ด้วย `binary.Read`) อ่าน offset ผิด

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");
```
- **บรรทัด 44–47**: ประกาศ eBPF Ring Buffer Map ชื่อ `events` ขนาด $2^{24}$ ไบต์ = 16 MB ขนาดต้องเป็น Power of 2 และเป็นทวีคูณของ page size

```c
static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, real_parent, tgid);
}
```
- **บรรทัด 54–58**: ตัวอย่าง **CO-RE read** ที่แท้จริง: `task_struct` เป็น struct ภายในเคอร์เนลที่ layout เปลี่ยนได้ทุกเวอร์ชัน `BPF_CORE_READ(task, real_parent, tgid)` อ่าน pointer chain `task->real_parent->tgid` ด้วย `bpf_probe_read_kernel()` และบันทึก relocation ไว้ใน `.o` ตอนโหลด cilium/ebpf จะปรับ offset ให้ตรงกับ BTF ของเคอร์เนลที่รันจริง

```c
static __always_inline void fill_common(struct sec_event *e, __u8 type)
```
- **บรรทัด 60–72**: เติม field ร่วม (`ts_ns`, `pid`, `ppid`, `uid`, `comm`) ให้ทั้ง exec และ TLS event เพื่อลดโค้ดซ้ำ

```c
SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    ...
    __u16 off = ctx->__data_loc_filename & 0xFFFF;
    long len = bpf_probe_read_kernel_str(e->payload, sizeof(e->payload), (void *)ctx + off);
```
- **บรรทัด 83–104**: Hook หลักสำหรับ exec (ค่าเริ่มต้น) ใช้ `struct trace_event_raw_sched_process_exec` จาก `vmlinux.h` (ตรงกับ `/sys/kernel/tracing/events/sched/sched_process_exec/format`) field `filename` เป็นชนิด `__data_loc`: 16 บิตล่างคือ offset ของสตริงนับจากต้น record, 16 บิตบนคือความยาว สตริงอยู่ใน **หน่วยความจำเคอร์เนล** จึงอ่านด้วย `bpf_probe_read_kernel_str()`

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    ...
    const char *filename_ptr = (const char *)ctx->args[0];
    long len = bpf_probe_read_user_str(e->payload, sizeof(e->payload), filename_ptr);
```
- **บรรทัด 116–137**: Hook ทางเลือก (`-exec-hook=syscall`) ใช้ `struct trace_event_raw_sys_enter` ซึ่งเป็น layout กลางของทุก `syscalls/sys_enter_*` (`args[0]` = filename, `args[1]` = argv, `args[2]` = envp) แทน struct `trace_event_raw_sys_enter_execve` ที่เวอร์ชันก่อนประกาศเอง filename เป็น pointer ของ **user space** จึงต้องอ่านด้วย `bpf_probe_read_user_str()`

```c
static __always_inline int handle_ssl_write(const void *buf, __u64 num)
{
    ...
    __u32 copy_len = num > PAYLOAD_LEN - 1 ? PAYLOAD_LEN - 1 : (__u32)num;
    copy_len &= 0x7F;
    ...
    if (bpf_probe_read_user(e->payload, copy_len, buf) == 0) {
        e->data_len = copy_len;
    }
```
- **บรรทัด 151–183**: logic ร่วมของทั้งสอง uprobe จำกัดความยาวไม่เกิน 127 ไบต์ และ `&= 0x7F` ให้ verifier เห็นขอบบนชัดเจน จากนั้นอ่านข้อมูลผู้ใช้ด้วย `bpf_probe_read_user()` **ตรวจค่าที่คืน**: ถ้าอ่านไม่สำเร็จ (เช่น page ยังไม่ถูก fault-in) จะรายงาน `data_len = 0` แทนที่จะส่ง buffer ศูนย์ล้วนพร้อมความยาวหลอกแบบเวอร์ชันก่อน `data_len` จึงหมายถึง "จำนวนไบต์ที่จับได้จริง" ไม่ใช่ `num` เต็ม

```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num)

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex, void *ssl, const void *buf, __u64 num)
```
- **บรรทัด 185–199**: Macro `BPF_UPROBE()` จาก `bpf_tracing.h` แกะ argument จาก `struct pt_regs` ให้ตาม calling convention ของสถาปัตยกรรมที่ระบุด้วย `-D__TARGET_ARCH_x86` (bpf2go `-target native` ใส่ให้อัตโนมัติ) บน x86_64: `buf` = `%rsi`, `num` = `%rdx` จึงไม่ต้องเขียน fallback `PT_REGS_PARM2/3` เองแบบเวอร์ชันก่อน `SSL_write` รับ `int` ส่วน `SSL_write_ex` รับ `size_t`

---

### 2.2 Go Control Plane (`main.go`)

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" -target native bpf ringbuf_events.c
```
- **บรรทัด 22**: เรียก `bpf2go` คอมไพล์ C เป็น eBPF bytecode และสร้าง Go bindings (`bpf_x86_bpfel.go` / `.o`) `-cflags "-I../../"` ให้ clang หา `vmlinux.h` ที่ root ของ repo (ต้องรัน `scripts/setup_env.sh` หรือ `bpftool btf dump ...` ก่อน) `-target native` ใส่ `-D__TARGET_ARCH_x86` ให้ macro `BPF_UPROBE` ใช้งานได้ ตอน generate จะเห็น warning `declaration does not declare anything` 5 บรรทัดจาก `vmlinux.h` ซึ่งไม่มีผลต่อการทำงาน

```go
execHook := flag.String("exec-hook", "sched", ...)
switch *execHook {
case "sched":
    tp, err = link.Tracepoint("sched", "sched_process_exec", objs.TpSchedProcessExec, nil)
case "syscall":
    tp, err = link.Tracepoint("syscalls", "sys_enter_execve", objs.TpSysEnterExecve, nil)
```
- **บรรทัด 102 และ 117–135**: เลือก exec tracepoint ที่จะ attach (ทั้งสอง program ถูกโหลดเข้าเคอร์เนล แต่ attach เพียงตัวเดียว เพื่อไม่ให้ event ซ้ำ)

```go
if resolved, err := filepath.EvalSymlinks(targetLibssl); err == nil && resolved != targetLibssl {
    log.Printf("[INFO] %s resolves to %s", targetLibssl, resolved)
}
ex, err := link.OpenExecutable(targetLibssl)
...
probes := []struct{ symbol string; prog *ebpf.Program }{
    {"SSL_write", objs.UprobeSslWrite},
    {"SSL_write_ex", objs.UprobeSslWriteEx},
}
for _, p := range probes {
    up, err := ex.Uprobe(p.symbol, p.prog, nil)
```
- **บรรทัด 138–171**: หา `libssl.so` (หรือใช้ `-libssl`), พิมพ์ path จริงหลัง resolve symlink, เปิด ELF ด้วย `link.OpenExecutable()` แล้วผูก uprobe กับ symbol ทั้งสอง ถ้า symbol ใดไม่มี (เช่น OpenSSL 1.1.0 ที่ไม่มี `SSL_write_ex`) จะเตือนแล้วทำงานต่อ

```go
rd, err := ringbuf.NewReader(objs.Events)
for {
    record, err := rd.Read()
    binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
}
```
- **บรรทัด 173–228**: เปิด Ring Buffer Reader วนลูปบล็อกรอ event (epoll) แล้ว decode เป็น Go struct `secEvent` ซึ่งต้องมี field/ขนาดตรงกับ C struct ทุกไบต์ (176 ไบต์)

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบ Dependencies และคอมไพล์โปรแกรม
```bash
# ต้องมี vmlinux.h ที่ root ของ repo (สร้างโดย scripts/setup_env.sh)
ls ../../vmlinux.h || bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../../vmlinux.h

# ตรวจสอบว่า curl/python ใช้ OpenSSL แบบ dynamic link
ldd $(which curl) | grep libssl

make all        # = go generate + go build -> bin/ringbuf_events
```

### ขั้นตอนที่ 2: รันโปรแกรมในฐานะ Root (บนเครื่อง lab ของคุณเองเท่านั้น -- ดูหัวข้อ 1.5)
```bash
sudo ./bin/ringbuf_events                       # exec hook = sched_process_exec (ค่าเริ่มต้น)
sudo ./bin/ringbuf_events -exec-hook=syscall    # ใช้ sys_enter_execve แทน
sudo ./bin/ringbuf_events -libssl /path/to/libssl.so.3
```

### ขั้นตอนที่ 3: ทดสอบการรันคำสั่ง (Process Execution)
เปิด Terminal หน้าต่างใหม่ แล้วทดลองรันคำสั่ง:
```bash
/bin/echo hello
id
```
ในหน้าต่าง `ringbuf_events` จะเห็น `[EXECVE]` ของแต่ละคำสั่ง โดย `COMM` เป็นชื่อโปรแกรมใหม่ และ `PPID` เป็น PID ของ shell

### ขั้นตอนที่ 4: ทดสอบ Uprobe ดักจับ Plaintext ก่อนเข้ารหัส SSL/TLS
```bash
curl -s --http1.1 -o /dev/null https://example.com   # HTTP/1.1: เห็น request เป็นข้อความ
curl -s -o /dev/null https://example.com             # ค่าเริ่มต้นของ curl = HTTP/2 (ALPN)
python3 -c "import urllib.request; urllib.request.urlopen('https://example.com').read()"
wget -q -O /dev/null https://example.com             # GnuTLS: ไม่ควรเห็น TLS_PLAINTEXT
```
สังเกตว่า **HTTP/2 เป็น binary protocol**: plaintext ที่เห็นคือ connection preface `PRI * HTTP/2.0` ตามด้วย frame และ header ที่ถูกบีบอัดด้วย HPACK จึงอ่านไม่ออกเป็นข้อความ (แต่ยังเป็นข้อมูลที่ "ยังไม่เข้ารหัส TLS")

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04.1 LTS (`Linux ce-desk 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), OpenSSL `libssl.so.3`, curl 8.18.0, Python 3.14, clang 21, Go 1.26, cilium/ebpf v0.16.0

### 4.1 `sudo ./bin/ringbuf_events` (exec hook = `sched_process_exec`) ขณะรันคำสั่งในขั้นตอนที่ 3–4
เครื่อง lab มี process อื่นทำงานอยู่พร้อมกัน จึง **ตัดบรรทัด `[EXECVE]` ของ process อื่นที่ไม่เกี่ยวข้องออก** (บรรทัดที่เหลือไม่ได้แก้ไข)
```text
2026/10/28 22:09:44 [INFO] Tracepoint attached: sched/sched_process_exec
2026/10/28 22:09:44 [INFO] /lib/x86_64-linux-gnu/libssl.so.3 resolves to /usr/lib/x86_64-linux-gnu/libssl.so.3
2026/10/28 22:09:44 [INFO] Uprobe attached: SSL_write on /lib/x86_64-linux-gnu/libssl.so.3
2026/10/28 22:09:44 [INFO] Uprobe attached: SSL_write_ex on /lib/x86_64-linux-gnu/libssl.so.3
2026/10/28 22:09:44 [INFO] Successfully listening for events from eBPF Ring Buffer (16MB)...
EVENT_TYPE      PID     PPID    UID    COMM             DETAILS
----------------------------------------------------------------------------------------
[EXECVE]        4147955 4147720 1000   echo             binary=/bin/echo
[EXECVE]        4147956 4147720 1000   id               binary=/usr/bin/id
[EXECVE]        4147961 4147720 1000   curl             binary=/usr/bin/curl
[TLS_PLAINTEXT] 4147961 4147720 1000   curl             len=75 plaintext="GET / HTTP/1.1  Host: example.com  User-Agent: curl/8.18.0  Accept: */*"
[EXECVE]        4147971 4147720 1000   curl             binary=/usr/bin/curl
[TLS_PLAINTEXT] 4147971 4147720 1000   curl             len=101 plaintext="PRI * HTTP/2.0    SM    ..............d.....................>..............A./..].\\...z.%.P.....S.*/*"
[TLS_PLAINTEXT] 4147971 4147720 1000   curl             len=26 plaintext=".........................."
[TLS_PLAINTEXT] 4147971 4147720 1000   curl             len=9 plaintext="........."
[TLS_PLAINTEXT] 4147971 4147720 1000   curl             len=26 plaintext=".................shutdown."
[EXECVE]        4148006 4147720 1000   python3          binary=/usr/bin/python3
[TLS_PLAINTEXT] 4148006 4147720 1000   python3          len=115 plaintext="GET / HTTP/1.1  Accept-Encoding: identity  Host: example.com  User-Agent: Python-urllib/3.14  Connection: close"
[EXECVE]        4148032 4147720 1000   wget             binary=/usr/bin/wget
2026/10/28 22:10:00 [INFO] Received termination signal. Closing ring buffer reader...
2026/10/28 22:10:00 [INFO] Ringbuf reader closed. Exiting.
```
สิ่งที่ยืนยันได้จากผลนี้:
- exec ทุกคำสั่งของเราถูกจับครบ (`echo`, `id`, `curl` x2, `python3`, `wget`)
- `curl --http1.1` เห็น HTTP request เป็นข้อความ; `curl` ค่าเริ่มต้นเป็น HTTP/2 จึงเห็น binary frame (event สุดท้ายที่มีคำว่า `shutdown` น่าจะเป็น HTTP/2 GOAWAY frame ตอนปิด connection)
- `python3` ถูกจับผ่าน `SSL_write_ex` (ก่อนเพิ่ม probe นี้ไม่เห็นเลย)
- `wget` (GnuTLS) มีแค่ `[EXECVE]` ไม่มี `[TLS_PLAINTEXT]`

### 4.2 `sudo ./bin/ringbuf_events -exec-hook=syscall` + `taskset` ทุก CPU (ข้อสังเกต Linux 7.0)
คำสั่งทดสอบ: `for c in 0 1 2 3 4 5 6 7; do taskset -c $c /bin/echo cpu$c; done` (exec 8 ครั้ง บน 8 CPU) ผลที่กรองเฉพาะ `/bin/echo`:
```text
2026/10/28 22:05:05 [INFO] Tracepoint attached: syscalls/sys_enter_execve
...
EVENT_TYPE      PID     PPID    UID    COMM             DETAILS
----------------------------------------------------------------------------------------
[EXECVE]        4083633 4083501 1000   taskset          binary=/bin/echo
```
จาก 8 ครั้งเห็นเพียง 1 ครั้ง (ครั้งที่รันบน CPU 0; `COMM` = `taskset` เพราะ hook นี้ยิงก่อน exec เปลี่ยนชื่อ process) สอดคล้องกับการวัดด้วย `bpftrace` ในหัวข้อ 1.7 (output ของ build/run ที่ตัดด้วย `...` คือบรรทัด INFO ของ uprobe ที่เหมือนหัวข้อ 4.1)

---

## 5. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **CO-RE / vmlinux.h** | ใช้ `vmlinux.h` + `BPF_CORE_READ(task, real_parent, tgid)` ไม่มี struct เคอร์เนลที่ประกาศเอง | [x] ผ่าน |
| **Ring Buffer Structure** | ประกาศแมป `BPF_MAP_TYPE_RINGBUF` ขนาด 16MB ถูกต้องตาม Power of 2 | [x] ผ่าน |
| **Exec Tracing** | `sched_process_exec` อ่าน `__data_loc` filename ด้วย `bpf_probe_read_kernel_str` จับ exec ได้ครบทุก CPU | [x] ผ่าน |
| **Uprobe SSL_write / SSL_write_ex** | `BPF_UPROBE` แกะ `buf`/`num` คัดลอก Plaintext ก่อนเข้ารหัส (curl + python3) | [x] ผ่าน |
| **Verifier Bounds Check** | `copy_len &= 0x7F` และตรวจค่าคืนของ `bpf_probe_read_user` | [x] ผ่าน |
| **Go Ringbuf Consumer** | วนลูปอ่านข้อมูลผ่าน `ringbuf.NewReader` รองรับ Graceful Shutdown | [x] ผ่าน |
| **Fallback Handling** | ทำงานต่อได้แม้เครื่องไม่มี `libssl.so` โดยยังคงดักจับ exec ตามปกติ | [x] ผ่าน |

---

## 6. ข้อจำกัดและ Threat Model (Limitations)

ถ้ามองเครื่องมือนี้เป็น "sensor" ของระบบ security ต้องถือว่าผู้โจมตีรู้ว่ามันทำงานอย่างไร สิ่งที่ผู้โจมตี (หรือแค่ซอฟต์แวร์ปกติ) ทำได้เพื่อหลบหรือทำให้ข้อมูลผิดเพี้ยน:

**ฝั่ง TLS uprobe**
1. **ใช้ TLS stack อื่น**: Go `crypto/tls`, rustls, GnuTLS, NSS, BoringSSL หรือ OpenSSL ที่ link แบบ static -- มองไม่เห็นเลย (หัวข้อ 1.6) มัลแวร์ที่เขียนด้วย Go จึงหลบได้โดยไม่ต้องทำอะไรเพิ่ม
2. **ใช้ `libssl` ของตัวเอง**: copy `libssl.so.3` ไปไว้ path อื่นแล้วตั้ง `LD_LIBRARY_PATH` หรือรันใน container -- เป็นคนละ inode กับไฟล์ที่เรา probe
3. **เข้ารหัสซ้อนชั้นใน**: เข้ารหัส payload เองก่อนส่งเข้า `SSL_write` (เช่น ส่ง blob ที่เข้ารหัสแล้ว) เราจะเห็นแค่ ciphertext ชั้นใน
4. **ข้อมูลถูกตัด**: เก็บเพียง 127 ไบต์แรกต่อการเรียก ข้อมูลอ่อนไหวที่อยู่หลังไบต์ที่ 127 (เช่น request body ยาวๆ) ไม่ถูกเห็น และ HTTP/2/HTTP/3 เป็น binary/HPACK/QPACK ต้อง decode เพิ่ม
5. **ไม่เห็นขาเข้า**: ดักเฉพาะ `SSL_write*` (ข้อมูลที่ส่งออก) ไม่ได้ดัก `SSL_read*` (response) -- ดูแบบฝึกหัด
6. **การอ่านล้มเหลว**: `bpf_probe_read_user()` อ่าน page ที่ยังไม่ถูก fault-in ไม่ได้ (uprobe ปกติเป็น non-sleepable ต่างจาก `uprobe.s`) จะได้ `len=0`

**ฝั่ง exec tracing**
7. **`sys_enter_execve` (โหมด `syscall`) มี TOCTOU**: thread อื่นในโปรเซสเดียวกันสามารถแก้ string filename หลัง eBPF อ่านไปแล้ว, exec ที่ล้มเหลวก็ถูกรายงาน, และ `execveat()` ไม่ถูกดัก -- โหมด `sched` ปิดช่องโหว่เหล่านี้
8. **ไม่มี exec เลย**: โค้ดที่โหลดเข้าหน่วยความจำโดยไม่ exec ไฟล์ใหม่ (เช่น `memfd_create` + `fexecve` จะยังเห็นเป็น `/dev/fd/N` หรือ `memfd:` ส่วน shellcode / interpreter ที่รันสคริปต์ใน process เดิม เช่น `python3 -c` จะเห็นแค่ `python3`) -- argv ก็ไม่ได้ถูกเก็บในแล็บนี้
9. **ชื่อ binary ไม่ใช่ตัวตน**: copy `/usr/bin/curl` ไปเป็น `/tmp/x` แล้วรัน -- การตรวจจับที่ดูแค่ชื่อจะพลาด ควรใช้ inode/hash ประกอบ

**ฝั่ง pipeline**
10. **Ring buffer เต็ม**: ถ้าสร้าง event ถี่มาก (fork bomb / exec flood) `bpf_ringbuf_reserve()` คืน `NULL` และ event ถูกทิ้งเงียบๆ (แล็บนี้ไม่ได้นับ drop) ผู้โจมตีอาจใช้ "noise" กลบ event จริง
11. **Root ปิด sensor ได้**: ผู้ที่มีสิทธิ์ root / `CAP_BPF`+`CAP_PERFMON` สามารถ kill agent หรือ detach program ได้ (ป้องกันเพิ่มได้ด้วย BPF LSM ใน Week 10, kernel lockdown และการส่ง log ออกนอกเครื่อง)
12. **PID reuse / namespace**: PID ที่รายงานเป็น PID ใน root namespace; process อายุสั้นอาจจบไปก่อน user space จะไปอ่าน `/proc/<pid>` เพิ่มเติม

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
**7.1 นับ event ที่หาย**: เพิ่ม `BPF_MAP_TYPE_ARRAY` (หรือ `PERCPU_ARRAY`) ชื่อ `drops` แล้วเพิ่มค่าทุกครั้งที่ `bpf_ringbuf_reserve()` คืน `NULL` ให้ `main.go` พิมพ์ค่านี้ตอนปิดโปรแกรม
- *ส่งงาน*: diff ของ `ringbuf_events.c` / `main.go` + output
- *ตรวจสอบ*: ลดขนาด ring buffer เหลือ `1 << 12` (4 KB) แล้วรัน `for i in $(seq 1 2000); do /bin/true; done` ค่า drop ต้องมากกว่า 0 และเมื่อคืนเป็น 16 MB ต้องเป็น 0

**7.2 Filter ด้วย UID/COMM**: เพิ่ม flag `-uid` ใน `main.go` ที่เขียนค่าลง map (หรือ `const volatile` global ที่ตั้งค่าก่อนโหลดด้วย `spec.RewriteConstants()`) แล้วให้ eBPF ส่งเฉพาะ event ของ UID นั้น
- *ตรวจสอบ*: รัน `sudo ./bin/ringbuf_events -uid $(id -u)` แล้ว `sudo /bin/true` ต้องไม่ปรากฏ แต่ `/bin/true` (user ปกติ) ปรากฏ

### ระดับปานกลาง
**7.3 ตรวจสอบปัญหา exec tracepoint บนเคอร์เนลของคุณ (อ้างอิงหัวข้อ 1.7)**: รัน
```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve /str(args.filename) == "/usr/bin/true"/ { @tp[cpu] = count(); }
                  tracepoint:sched:sched_process_exec /comm == "true"/ { @sched[cpu] = count(); }'
# อีกหน้าต่าง:
for c in $(seq 0 $(($(nproc)-1))); do for i in $(seq 1 10); do taskset -c $c /usr/bin/true; done; done
```
- *ส่งงาน*: ตาราง count ต่อ CPU ของทั้งสอง tracepoint + `uname -r` และสรุปว่าเคอร์เนลของคุณมีพฤติกรรม "เฉพาะ CPU 0" หรือไม่
- *ตรวจสอบ*: `@sched` ต้องได้ 10 ต่อ CPU; ถ้า `@tp` ได้ไม่ครบ ให้ลองเปลี่ยนเป็น `tracepoint:raw_syscalls:sys_enter` (กรอง `args.id == 59`) แล้วเปรียบเทียบ

**7.4 ดักขาเข้า `SSL_read`**: เพิ่ม `uprobe` ที่ `SSL_read` เก็บ `buf` ไว้ใน `BPF_MAP_TYPE_HASH` (key = `pid_tgid`) และ `uretprobe` ที่อ่านค่า return (จำนวนไบต์ที่อ่านได้จริง) แล้วคัดลอก plaintext ของ response ส่งเข้า ring buffer เป็น event type ใหม่ `TLS_READ`
- *ตรวจสอบ*: `curl -s --http1.1 -o /dev/null https://example.com` ต้องเห็น `HTTP/1.1 200 OK` ใน event `TLS_READ` (ข้อควรรู้: ที่ entry ของ `SSL_read` buffer ยังว่าง จึงต้องอ่านตอน return)

### ระดับท้าทาย
**7.5 ปิดช่องโหว่ libssl คนละไฟล์**: ใช้ `sched_process_exec` + อ่าน `/proc/<pid>/maps` ใน Go เพื่อหา `libssl` ทุกไฟล์ที่ process ใหม่ map อยู่ (รวมถึงใน container ผ่าน `/proc/<pid>/root/...`) แล้ว attach uprobe เพิ่มแบบ dynamic (จำ inode ที่ attach แล้ว เพื่อไม่ attach ซ้ำ)
- *ตรวจสอบ*: `cp /usr/lib/x86_64-linux-gnu/libssl.so.3 /tmp/myssl/ && LD_LIBRARY_PATH=/tmp/myssl curl -s --http1.1 -o /dev/null https://example.com` -- เวอร์ชันเดิมต้องไม่เห็น เวอร์ชันใหม่ต้องเห็น (ข้อควรระวัง: uprobe ที่ attach หลัง process เริ่มส่งข้อมูลไปแล้วจะพลาด request แรก ให้อธิบายใน report)

**7.6 ดัก Go `crypto/tls`**: เขียน HTTPS client ด้วย Go (`net/http`) build แบบมี symbol แล้ว attach uprobe ที่ `crypto/tls.(*Conn).Write` ของ binary นั้น ศึกษาว่า Go ABIInternal (Go ≥ 1.17) ส่ง argument ผ่าน register ใด (`RAX`, `RBX`, `RCX`, ...) และสร้าง slice `[]byte` (ptr, len) จาก register
- *ส่งงาน*: C program ใหม่ + อธิบาย register mapping พร้อมแหล่งอ้างอิง (Go internal ABI spec)
- *ตรวจสอบ*: เห็น `GET / HTTP/1.1` จาก Go client ของคุณ; อธิบายว่าทำไม **ห้าม** ใช้ `uretprobe` กับฟังก์ชัน Go (goroutine stack ถูกย้ายได้)
