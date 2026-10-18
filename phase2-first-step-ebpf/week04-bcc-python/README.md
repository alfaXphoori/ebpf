# สัปดาห์ที่ 04: การพัฒนาโปรแกรม eBPF ด้วย BCC (BPF Compiler Collection) และ Python

ยินดีต้อนรับสู่ **Week 04** ของหลักสูตร **eBPF Noob to Hero**!
ในสัปดาห์นี้ เราจะก้าวเข้าสู่การเขียนโปรแกรม eBPF เต็มรูปแบบด้วยภาษา C และเชื่อมโยงการควบคุมใน User Space ด้วยภาษา Python ผ่าน **BCC (BPF Compiler Collection)** ซึ่งเป็นเฟรมเวิร์กที่ได้รับความนิยมสูงสุดในยุคบุกเบิกของ eBPF Tracing

เราจะพัฒนาเครื่องมือวัดเวลาความหน่วง (Latency) ในการสร้างการเชื่อมต่อเครือข่าย **TCP IPv4 (`tcp_v4_connect`)** โดยใช้เทคนิคการจับคู่เหตุการณ์ระหว่าง **`kprobe`** (ขาเข้า) และ **`kretprobe`** (ขาออก) ผ่าน **BPF Hash Map** พร้อมส่งสถิติผ่าน **BPF Perf Event Ring Buffer** ขึ้นมาแสดงผลใน Python และวาดกราฟความถี่ (Logarithmic Histogram) ในหน่วยไมโครวินาที!

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 สถาปัตยกรรมของ BCC (BPF Compiler Collection)
BCC เป็น Toolkit ที่ช่วยให้นักพัฒนาสามารถเขียนโค้ด eBPF ภาษา C ฝังไว้เป็นสตริงในสคริปต์ระดับสูง (เช่น Python, Lua, C++) โดยมีกระบวนการทำงานดังนี้:

```
+-----------------------------------------------------------------------------+
|                                User Space                                   |
|                                                                             |
|   Python Script (tcp_v4_latency.py)                                         |
|        |                                                                    |
|        v (ส่ง C Code String ไปยัง BCC Library)                              |
|   Embedded Clang / LLVM Frontend                                            |
|        | 1. Parse C source code & inject Kernel Headers (<linux/sched.h>, etc.)|
|        | 2. ทำการคอมไพล์ ณ ขณะรัน (Runtime JIT compilation)                |
|        v                                                                    |
|   eBPF Bytecode (ELF format)                                                |
|        |                                                                    |
|        v 3. โหลดผ่าน sys_bpf(BPF_PROG_LOAD, ...)                            |
+--------|--------------------------------------------------------------------+
|        v                        Kernel Space                                |
|   +---------------+                                                         |
|   |   Verifier    | ---> ตรวจสอบความปลอดภัยหน่วยความจำและการวนลูป          |
|   +-------+-------+                                                         |
|           | (ผ่าน)                                                          |
|           v                                                                 |
|   +---------------+                                                         |
|   |  JIT Compiler | ---> แปลงเป็น Machine Code ของ CPU สถาปัตยกรรมนั้นๆ    |
|   +-------+-------+                                                         |
|           |                                                                 |
|           v 4. แนบ Probe เข้ากับ Kernel Function Address                     |
|   [ kprobe: tcp_v4_connect ] <======> [ kretprobe: tcp_v4_connect ]         |
|                 \                                 /                         |
|                  \   +-----------------------+   /                          |
|                   -->| BPF_HASH(start_ts)    |<--                           |
|                      | บันทึก Start Timestamp|                              |
|                      +-----------------------+                              |
|                                  |                                          |
|                                  v ส่งต่อ Event เมื่อเสร็จสิ้น               |
|                      +-----------------------+                              |
|                      | BPF_PERF_OUTPUT       |                              |
|                      | (Circular Ring Buffer)|                              |
|                      +-----------------------+                              |
+----------------------------------|------------------------------------------+
                                   v Poll ข้อมูลขึ้น User Space
                          +------------------+
                          | Python Callback  |
                          +------------------+
```

---

### 1.2 ข้อดีและข้อจำกัดของ BCC ในสภาพแวดล้อม Production
แม้ว่า BCC จะมอบความสะดวกสบายอย่างยิ่งสำหรับการทดลองและพัฒนาโปรแกรมต้นแบบ (Prototyping) แต่มันมี **ข้อจำกัดสำคัญ** ในระบบ Production ขนาดใหญ่:

1. **ภาระการคอมไพล์ที่หนักหน่วง (Resource Heavy)**: ทุกครั้งที่รันสคริปต์ BCC จะต้องเรียก Clang/LLVM มาคอมไพล์โค้ด C ซึ่งใช้ CPU พุ่งสูงและกิน RAM มหาศาล (100MB – 300MB+) ณ ขณะเริ่มต้น
2. **การพึ่งพา Kernel Headers (`linux-headers`)**: โฮสต์ทุกตัวที่จะรันสคริปต์ BCC จำเป็นต้องติดตั้ง Package `linux-headers-$(uname -r)` ขนาดหลายร้อยเมกะไบต์ ซึ่งใน Container ที่มีขนาดเล็ก (เช่น Distroless, Alpine) มักไม่มี Header เหล่านี้ ทำให้รันไม่ได้
3. **ปัญหาความไม่เข้ากันของเคอร์เนล (Kernel Version Fragility)**: หากโครงสร้างภายในเคอร์เนลเปลี่ยนไปเพียงเล็กน้อย โค้ดภาษา C อาจคอมไพล์ไม่ผ่านทันที

> [!NOTE]
> **ปัญหานี้เป็นที่มาของเทคโนโลยีใน Phase 3: BPF CO-RE (Compile Once – Run Everywhere)**
> ใน Phase 3 เราจะได้เรียนรู้การข้ามขีดจำกัดของ BCC ด้วยการคอมไพล์เป็น eBPF Binary เพียงครั้งเดียวผ่าน **libbpf + BTF (BPF Type Format)** และรันได้บนทุกเคอร์เนลโดยไม่ต้องติดตั้ง Clang/LLVM หรือ Kernel Headers บนโฮสต์ปลายทางเลย!

---

### 1.3 กลไกการวัด Latency ด้วย `kprobe` และ `kretprobe`
ในการวัดเวลาว่าฟังก์ชันหนึ่งๆ ในเคอร์เนลใช้เวลาทำงานนานเท่าใด เราต้องใช้ Probe 2 จุดร่วมกัน:
- **`kprobe__tcp_v4_connect`**: ดักจับเมื่อโปรเซสเริ่มต้นขอเชื่อมต่อ TCP (ส่งแพ็กเก็ต SYN ออกไป)
  - เราดึงค่าเวลาปัจจุบันในหน่วยนาโนวินาทีจาก Monotonic Clock: `bpf_ktime_get_ns()`
  - บันทึกลงใน BPF Hash Map โดยใช้คู่ ID ของโปรเซสและเธรด (`u64 pid_tgid = bpf_get_current_pid_tgid()`) เป็น Key เพื่อป้องกันไม่ให้ข้อมูลของแต่ละ Thread ตีกัน
- **`kretprobe__tcp_v4_connect`**: ดักจับเมื่อฟังก์ชันทำงานเสร็จและกำลัง Return
  - เคอร์เนลส่งค่า Return Code ผ่านแมโคร `PT_REGS_RC(ctx)`
  - ค้นหา Start Timestamp ใน Hash Map โดยใช้ `pid_tgid` ตัวเดิม
  - คำนวณความต่างของเวลา: `delta_us = (bpf_ktime_get_ns() - info->ts) / 1000`
  - นำค่า Delta บันทึกลงใน BPF Histogram และส่งรายละเอียด Event ขึ้นสู่ User Space ผ่าน Perf Buffer

```
Thread A:  [kprobe entry] ---------------------------> [kretprobe exit]
               |                                            |
               +---> บันทึก: start_ts[TID_A] = t1            +---> คำนวณ: delta = t2 - t1
                                                                  ลบ start_ts[TID_A]
```

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ส่วนของโค้ด eBPF Kernel C

```c
// 1. การประกาศโครงสร้างข้อมูลส่งผ่าน Kernel และ User Space
struct conn_info_t {
    u64 ts;
    struct sock *sk;
    u32 pid;
    u32 daddr;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

struct event_t {
    u64 delta_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};
```
- **คำอธิบาย**:
  - `conn_info_t`: ข้อมูลชั่วคราวที่เก็บในเคอร์เนลระหว่างรอการเชื่อมต่อเสร็จ
  - `event_t`: ข้อมูลสรุปที่ส่งผ่าน Ring Buffer ขึ้นมาให้ Python แสดงผล โดยจัดเรียงฟิลด์ตาม Data Alignment เพื่อป้องกันปัญหา Memory Padding

```c
// 2. การประกาศ BPF Maps
BPF_HASH(start_ts, u64, struct conn_info_t);
BPF_PERF_OUTPUT(events);
BPF_HISTOGRAM(dist, "Latency (us)");
```
- **คำอธิบาย**:
  - `BPF_HASH`: สร้างตาราง Hash Map ใน Kernel Space เก็บ State ชั่วคราว
  - `BPF_PERF_OUTPUT`: สร้าง Ring Buffer เชื่อมโยง Kernel สู่ User Space ประสิทธิภาพสูง
  - `BPF_HISTOGRAM`: สร้าง 64-slot Logarithmic Array สำหรับเก็บความถี่ของตัวเลข Latency

```c
// 3. kprobe ขาเข้า tcp_v4_connect
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct conn_info_t info = {};

    info.ts = bpf_ktime_get_ns();
    info.sk = sk;
    info.pid = pid_tgid >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&info.daddr, sizeof(info.daddr), &usin->sin_addr.s_addr);
    bpf_probe_read_kernel(&info.dport, sizeof(info.dport), &usin->sin_port);

    start_ts.update(&pid_tgid, &info);
    return 0;
}
```
- **คำอธิบาย**:
  - `bpf_get_current_pid_tgid()`: คืนค่า 64-bit integer โดย 32 บิตบนคือ TGID (Process ID ในสายตาผู้ใช้) และ 32 บิตล่างคือ TID (Thread ID ในเคอร์เนล)
  - `bpf_probe_read_kernel()`: ฟังก์ชัน Helper ที่จำเป็นของ eBPF เพื่ออ่านหน่วยความจำใน Kernel Space อย่างปลอดภัยผ่าน Verifier
  - `start_ts.update(&pid_tgid, &info)`: บันทึกข้อมูลลง Hash Map

```c
// 4. kretprobe ขาออก tcp_v4_connect
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct conn_info_t *infop = start_ts.lookup(&pid_tgid);
    if (!infop) return 0;

    if (ret != 0 && ret != -115) { // 0 = Connected, -115 = EINPROGRESS
        start_ts.delete(&pid_tgid);
        return 0;
    }

    u64 delta_us = (bpf_ktime_get_ns() - infop->ts) / 1000;

    struct event_t event = {};
    event.delta_us = delta_us;
    event.pid = infop->pid;
    event.daddr = infop->daddr;
    event.dport = infop->dport;
    __builtin_memcpy(event.comm, infop->comm, sizeof(event.comm));

    struct sock *sk = infop->sk;
    if (sk) {
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    }

    events.perf_submit(ctx, &event, sizeof(event));
    dist.increment(bpf_log2l(delta_us));
    start_ts.delete(&pid_tgid);
    return 0;
}
```
- **คำอธิบาย**:
  - `PT_REGS_RC(ctx)`: ดึงค่า Return Value จาก CPU Register (เช่น `%rax` บน x86_64)
  - หาก `ret == -115` (`-EINPROGRESS`) แปลว่าเป็น Non-blocking Socket ซึ่งเคอร์เนลเริ่มส่ง SYN ออกไปเรียบร้อยแล้ว
  - `events.perf_submit()`: บรรจุข้อมูลใส่ Circular Buffer ปลุก User Space ให้มารับข้อมูล
  - `start_ts.delete(&pid_tgid)`: ลบ Key ออกจาก Map ทันทีเพื่อป้องกันหน่วยความจำรั่วไหล (Memory Leak)

---

### 2.2 ส่วนของโค้ด User Space ภาษา Python

```python
# 1. การจับคู่ C Struct กับ Python ctypes
class Event(ctypes.Structure):
    _fields_ = [
        ("delta_us", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("saddr", ctypes.c_uint),
        ("daddr", ctypes.c_uint),
        ("sport", ctypes.c_ushort),
        ("dport", ctypes.c_ushort),
        ("comm", ctypes.c_char * 16),
    ]
```
- **คำอธิบาย**: กำหนดโครงสร้าง Memory Layout ใน Python ให้ตรงกับ `struct event_t` ในภาษา C ของ eBPF ทุกประการ

```python
# 2. การคอมไพล์และโหลด BPF
b = BPF(text=EBPF_C_PROGRAM)
```
- **คำอธิบาย**: BCC จะเรียก LLVM ในเครื่องมาแปลงสตริงภาษา C ให้เป็น eBPF Bytecode และตรวจสอบฟังก์ชัน `kprobe__...` / `kretprobe__...` เพื่อทำการ Attach เข้ากับฟังก์ชันในเคอร์เนลโดยอัตโนมัติ

```python
# 3. Callback Function และการวน Loop รับเหตุการณ์
def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    timestamp = time.strftime("%H:%M:%S")
    src_ip = socket.inet_ntop(socket.AF_INET, struct.pack("=I", event.saddr))
    dst_ip = socket.inet_ntop(socket.AF_INET, struct.pack("=I", event.daddr))
    dst_port = socket.ntohs(event.dport)
    comm_name = event.comm.decode("utf-8", "replace")
    print(f"{timestamp:<9} {event.pid:<7} {comm_name:<16} {src_ip}:{event.sport:<5} -> {dst_ip}:{dst_port:<5} {event.delta_us} us")

b["events"].open_perf_buffer(handle_event, page_cnt=64)
while True:
    b.perf_buffer_poll()
```
- **คำอธิบาย**: `open_perf_buffer` จะจอง Memory Mapped Ring Buffer และ `perf_buffer_poll()` จะทำการดึงข้อมูลขึ้นมาทริกเกอร์ `handle_event` แบบ Real-time โดยไม่กิน CPU

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ติดตั้งแพ็กเกจ BCC และ Kernel Headers
สำหรับ Ubuntu 22.04 / 24.04 LTS:
```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

สำหรับ RHEL 9 / Fedora:
```bash
sudo dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r)
```

---

### ขั้นตอนที่ 2: รันโปรแกรมติดตาม Latency
รันสคริปต์ด้วยสิทธิ์ `sudo`:
```bash
sudo python3 tcp_v4_latency.py
```

**สิ่งที่แสดงบนหน้าจอเมื่อเริ่มต้น**:
```text
========================================================================
  eBPF Noob to Hero - Week 04: TCP IPv4 Connect Latency Tracker (BCC)   
========================================================================
 Compiling embedded C eBPF code via LLVM/Clang and attaching kprobes...
 JIT compilation & Kernel attach completed in 412.3 ms.

 Tracing active IPv4 TCP outbound connection latency (SYN initiation).
 Hit Ctrl+C to terminate and view microsecond latency histogram.

TIME      PID     COMM             SRC ADDR:PORT          DST ADDR:PORT          LATENCY (us)
--------------------------------------------------------------------------------------------
```

---

### ขั้นตอนที่ 3: สร้างทราฟฟิก TCP ขาออกเพื่อทดสอบ
เปิด Terminal ที่ 2 แล้วทดลองสร้างการเชื่อมต่อไปยังเว็บเซิร์ฟเวอร์ต่างๆ:
```bash
# ทดสอบการเชื่อมต่อ HTTP ไปยังเว็บใกล้และไกล
curl -s http://1.1.1.1 > /dev/null
curl -s https://www.google.com > /dev/null
curl -s https://github.com > /dev/null
```

---

### ขั้นตอนที่ 4: สังเกตผลลัพธ์แบบ Real-Time และ Histogram
ใน Terminal ที่ 1 คุณจะเห็นรายละเอียดการเชื่อมต่อและเวลา Latency แสดงขึ้นมาทันที:
```text
21:12:05  52341   curl             192.168.1.50:49280     1.1.1.1:80             842         
21:12:08  52345   curl             192.168.1.50:51412     142.250.199.110:443    1240        
21:12:12  52350   curl             192.168.1.50:48994     140.82.121.4:443       18530       
```

เมื่อคุณกด `Ctrl+C` โปรแกรมจะหยุดดักจับและแสดง **Histogram** แจกแจงความถี่ของความหน่วง:
```text
^C

[!] Detaching eBPF probes and generating latency distribution...

========================================================================
           TCP Outbound Connection Latency Histogram (usecs)           
========================================================================
     Latency (us)        : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 1        |******                                  |
       512 -> 1023       : 5        |*******************************         |
      1024 -> 2047       : 6        |**************************************  |
      2048 -> 4095       : 2        |************                            |
      4096 -> 8191       : 0        |                                        |
      8192 -> 16383      : 1        |******                                  |
     16384 -> 32767      : 1        |******                                  |
========================================================================
eBPF session concluded safely. All kernel maps freed.
```

---

## 4. Milestone Checklist

- [x] **BCC Architecture In-Depth**: เข้าใจขั้นตอนที่ Python นำโค้ดภาษา C ไปแปลงผ่าน LLVM JIT และโหลดเข้าสู่เคอร์เนล
- [x] **Production Trade-offs**: วิเคราะห์ข้อดีของ BCC ในการทดลอง และข้อจำกัดใน Production (CPU/RAM spike, dependency on kernel headers) จนเข้าใจเหตุผลที่ต้องมี CO-RE ใน Phase 3
- [x] **kprobe & kretprobe Pairing**: ชำนาญการผูกฟังก์ชันคู่เข้า/ออก และการใช้ BPF Hash Map ในการจับคู่ Context ข้ามเธรดด้วย `pid_tgid`
- [x] **Safe Kernel Memory Access**: ใช้งาน `bpf_probe_read_kernel()` เพื่อสกัดฟิลด์ข้อมูลจาก Network Structures ได้อย่างปลอดภัย
- [x] **High-Speed Telemetry Streaming**: ใช้งาน `BPF_PERF_OUTPUT` และการแปลง Data Layout ด้วย Python `ctypes.Structure` ได้อย่างสมบูรณ์แบบ
- [x] **Logarithmic Histogram Analysis**: สร้างและวิเคราะห์กราฟการกระจายตัวของ Latency ด้วย `BPF_HISTOGRAM` และ `print_log2_hist()`
