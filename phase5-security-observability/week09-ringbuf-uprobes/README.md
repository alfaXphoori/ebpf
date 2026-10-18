# Week 09: Ring Buffer & Uprobes Security Observability

คู่มือการศึกษาเชิงลึกเกี่ยวกับการสตรีมข้อมูลความเร็วสูงผ่าน **eBPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`)** และการดักจับพฤติกรรมในระดับ User-space ด้วย **Uprobes (`SSL_write`)** ร่วมกับ Tracepoint (`sys_enter_execve`)

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
- **Deterministic Ordering**: ข้อมูลทุกเหตุการณ์ถูกต่อคิวเรียงตามลำดับเวลาการจองจริงใน Memory
- **Zero-Copy Reservation**: รองรับรูปแบบ Reserve-Commit ผ่าน `bpf_ringbuf_reserve()` และ `bpf_ringbuf_submit()`

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
ในการส่งข้อมูลด้วย Ring Buffer จะมีขั้นตอน 2 จังหวะ:
1. **`bpf_ringbuf_reserve(map, size, flags)`**: จัดสรรหน่วยความจำล่วงหน้าใน Ring Buffer ขนาดที่ต้องการ หากพื้นที่เต็ม ฟังก์ชันจะคืนค่า `NULL` ทันที ทำให้เรา Drop เหตุการณ์ได้อย่างปลอดภัยโดยไม่กระทบความเร็วของ Kernel
2. เขียนข้อมูลลงใน Pointer ที่ได้รับโดยตรง (Direct Memory Access) โดยไม่ต้องผ่าน eBPF Stack
3. **`bpf_ringbuf_submit(ptr, flags)`**: ทำการ Commit บันทึก Header ขนาดและสถานะของ Event เพื่อส่งสัญญาณแจ้งเตือน User space ผ่านระบบ Notification

### 1.3 ทฤษฎี Uprobes (User-Space Probes)
Uprobe คือกลไกของ Linux Tracing Infrastructure ที่อนุญาตให้ใส่จุด Breakpoint ลงไปใน Binary ที่รันอยู่ใน User space เช่น Executable ELF หรือ Shared Libraries (`.so`)

```
+-------------------------------------------------------------------------+
|                    กลไกการทำงานของ UPROBE BREAKPOINT                    |
|                                                                         |
|  User Process (เช่น curl, python)                                       |
|  |                                                                      |
|  +---> เรียกใช้งาน SSL_write(ssl, buf, num)                             |
|        |                                                                |
|        | [ 0xCC (int3 instruction) แทนที่คำสั่งแรกของฟังก์ชัน ]           |
|        v                                                                |
|  Trap เข้าสู่ Linux Kernel (SIGTRAP -> do_trap)                         |
|        |                                                                |
|        v                                                                |
|  Kernel เรียก eBPF Handler: uprobe_ssl_write(struct pt_regs *ctx)       |
|        | อ่าน Register PT_REGS_PARM2 (buf), PT_REGS_PARM3 (num)         |
|        | คัดลอก Plaintext payload ด้วย bpf_probe_read_user()            |
|        v                                                                |
|  Kernel คืนสิทธิ์ และรันคำสั่งเดิมของ OpenSSL ต่อตามปกติ               |
+-------------------------------------------------------------------------+
```

### 1.4 การดักจับ Plaintext ก่อนเข้ารหัส (SSL/TLS Interception)
ในกระบวนการทำงานของ OpenSSL เมื่อแอปพลิเคชันต้องการส่งข้อมูลผ่านช่องทางปลอดภัย จะเรียกใช้ฟังก์ชัน:
```c
int SSL_write(SSL *ssl, const void *buf, int num);
```
- `buf` คือพอยน์เตอร์ไปยังข้อมูล Plaintext ก่อนถูกกระบวนการ Cryptography เข้ารหัสด้วย Symmetric Key
- `num` คือจำนวนไบต์ของ Plaintext
การวาง Uprobe ที่จุดเริ่มต้นของ `SSL_write` ทำให้ eBPF สามารถมองเห็น Payload ที่ยังไม่ได้ถูกเข้ารหัสได้อย่างสมบูรณ์ โดยไม่ต้องทำการ Man-in-the-Middle (MITM) Certificate Injection ใดๆ ทั้งสิ้น

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 eBPF C Program (`ringbuf_events.c`)

```c
struct sec_event {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    __u8  event_type;
    __u8  pad[3];
    __u32 data_len;
    char  comm[16];
    char  payload[128];
};
```
- **บรรทัด 16–25**: โครงสร้าง `sec_event` ขนาดคงที่ มีการจัดเรียง Memory Alignment 64-bit และ padding 3 ไบต์ถัดจาก `event_type` เพื่อให้ `data_len` วางตรงตำแหน่ง Multiple of 4 ป้องกันข้อผิดพลาดของ Verifier และ Memory Misalignment

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");
```
- **บรรทัด 28–31**: ประกาศ eBPF Ring Buffer Map ชื่อ `events` ขนาด $2^{24}$ ไบต์ = 16,777,216 ไบต์ (16 MB) เป็นขนาดที่ต้องเป็น Power of 2 ตามข้อกำหนดของ Linux Kernel Ring Buffer

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter_execve *ctx)
```
- **บรรทัด 55–56**: กำหนด Hook จุด Tracepoint `syscalls:sys_enter_execve` ซึ่งจะถูกกระตุ้นทุกครั้งที่มีกระบวนการเรียกใช้ `execve()` system call เพื่อรันไบนารีใหม่

```c
    struct sec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
```
- **บรรทัด 64–67**: จองหน่วยความจำขนาด `sizeof(struct sec_event)` ภายใน Ring Buffer หากบัฟเฟอร์เต็ม จะคืนค่า `NULL` และโปรแกรมจะออกจากฟังก์ชันทันทีเพื่อความปลอดภัย

```c
    const char *filename_ptr = (const char *)ctx->args[0];
    long len = bpf_probe_read_user_str(e->payload, sizeof(e->payload), filename_ptr);
    if (len > 0) {
        e->data_len = (__u32)len;
    } else {
        e->payload[0] = '\0';
        e->data_len = 0;
    }
    bpf_ringbuf_submit(e, 0);
```
- **บรรทัด 77–86**: อ่าน Path หรือชื่อไฟล์ไบนารีที่ถูกส่งเข้ามาใน Argument ตัวแรก (`ctx->args[0]`) ผ่าน Helper `bpf_probe_read_user_str()` ไปยัง `e->payload` และทำการ Commit ข้อมูลผ่าน `bpf_ringbuf_submit()`

```c
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
```
- **บรรทัด 91–92**: กำหนด Uprobe Program สำหรับการดักจับฟังก์ชัน `SSL_write` ของ OpenSSL โดยรับพารามิเตอร์ `struct pt_regs *ctx` ของ CPU registers

```c
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
```
- **บรรทัด 94–95**: สกัดพารามิเตอร์ตัวที่ 2 (`buf`) และตัวที่ 3 (`num`) ตามข้อกำหนดของ Calling Convention สถาปัตยกรรม x86_64 (`%rsi` และ `%rdx`)

```c
    __u32 copy_len = (__u32)num;
    if (copy_len > sizeof(e->payload) - 1) {
        copy_len = sizeof(e->payload) - 1;
    }
    e->data_len = copy_len;
    __builtin_memset(e->payload, 0, sizeof(e->payload));
    if (copy_len > 0) {
        bpf_probe_read_user(e->payload, copy_len, buf);
    }
    bpf_ringbuf_submit(e, 0);
```
- **บรรทัด 117–127**: จำกัดขนาดของข้อมูล Plaintext ให้อยู่ภายในขอบเขตของบัฟเฟอร์ `payload` อย่างเข้มงวด เพื่อให้ผ่าน eBPF Verifier จากนั้นอ่านข้อมูลผู้ใช้ด้วย `bpf_probe_read_user()` และส่งข้อมูลเข้า Ring Buffer

---

### 2.2 Go Control Plane (`main.go`)

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf bpf ringbuf_events.c
```
- **บรรทัด 20**: คอมไพเลอร์ Directive สำหรับเรียกใช้ `bpf2go` เพื่อแปลง C source code ให้กลายเป็น eBPF bytecode และสร้าง Go bindings (`bpf_bpfeb.go` / `bpf_bpfel.go`)

```go
tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TpSysEnterExecve, nil)
```
- **บรรทัด 114**: ทำการเชื่อมโยง (Attach) eBPF Tracepoint Program เข้ากับเคอร์เนล Tracepoint

```go
targetLibssl := findLibsslPath(*libsslFlag)
if targetLibssl != "" {
    ex, err := link.OpenExecutable(targetLibssl)
    up, err := ex.Uprobe("SSL_write", objs.UprobeSslWrite, nil)
```
- **บรรทัด 122–129**: ตรวจสอบหาไฟล์ `libssl.so` ในระบบ ทำการเปิด Binary ELF ด้วย `link.OpenExecutable()` และผูก Uprobe เข้ากับสัญลักษณ์ `SSL_write`

```go
rd, err := ringbuf.NewReader(objs.Events)
for {
    record, err := rd.Read()
    binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
}
```
- **บรรทัด 142–175**: เปิด Ring Buffer Reader ที่เชื่อมกับแมป `objs.Events` ภายในลูปจะทำการบล็อกรอเหตุการณ์ใหม่ และถอดรหัส Binary Stream ไปเป็น Go Struct `secEvent`

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบ Dependencies และคอมไพล์โปรแกรม
```bash
# ตรวจสอบการติดตั้ง clang และ llvm
clang --version

# ดึง dependencies และคอมไพล์ Go module
go mod tidy
make generate
make build
```

### ขั้นตอนที่ 2: รันโปรแกรมในฐานะ Root
```bash
sudo ./bin/ringbuf_events
```
ผลลัพธ์ที่ปรากฏเมื่อเริ่มต้น:
```text
[INFO] Tracepoint attached: syscalls/sys_enter_execve
[INFO] Uprobe attached: SSL_write on /lib/x86_64-linux-gnu/libssl.so.3
[INFO] Successfully listening for events from eBPF Ring Buffer (16MB)...
EVENT_TYPE      PID     UID    COMM             DETAILS
--------------------------------------------------------------------------------
```

### ขั้นตอนที่ 3: ทดสอบ Tracepoint การรันคำสั่ง (Process Execution)
เปิด Terminal หน้าต่างใหม่ แล้วทดลองรันคำสั่ง:
```bash
ls -la
whoami
cat /etc/hosts
```
ในหน้าต่างโปรแกรม `ringbuf_events` จะแสดงผลการดักจับแบบ Real-time:
```text
[EXECVE]        14285   1000   bash             binary=/usr/bin/ls
[EXECVE]        14289   1000   bash             binary=/usr/bin/whoami
[EXECVE]        14292   1000   bash             binary=/usr/bin/cat
```

### ขั้นตอนที่ 4: ทดสอบ Uprobe ดักจับ Plaintext ก่อนเข้ารหัส SSL/TLS
ใน Terminal อีกหน้าต่างหนึ่ง ให้ใช้คำสั่ง `curl` ยิง HTTPS Request:
```bash
curl -s https://example.com > /dev/null
```
ในหน้าต่างโปรแกรมจะเห็น Plaintext HTTP Request ที่ OpenSSL กำลังจะส่งออก:
```text
[TLS_PLAINTEXT] 14310   1000   curl             len=78  plaintext="GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n"
```

---

## 4. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **Ring Buffer Structure** | ประกาศแมป `BPF_MAP_TYPE_RINGBUF` ขนาด 16MB ถูกต้องตาม Power of 2 | [x] ผ่าน |
| **Tracepoint Execve** | ดักจับ `sys_enter_execve` อ่าน User pointer filename ผ่าน `bpf_probe_read_user_str` | [x] ผ่าน |
| **Uprobe SSL_write** | สกัด Registers พารามิเตอร์ `buf` และ `num` คัดลอก Plaintext ก่อนเข้ารหัส | [x] ผ่าน |
| **Verifier Bounds Check** | ตรวจสอบขนาดข้อมูล `copy_len` ป้องกัน Out-of-bounds Read/Write | [x] ผ่าน |
| **Go Ringbuf Consumer** | วนลูปอ่านข้อมูลผ่าน `ringbuf.NewReader` รองรับ Graceful Shutdown | [x] ผ่าน |
| **Fallback Handling** | ทำงานต่อได้แม้เครื่องไม่มี `libssl.so` โดยยังคงดักจับ `execve` ตามปกติ | [x] ผ่าน |
