# สัปดาห์ที่ 04: การพัฒนาโปรแกรม eBPF ด้วย BCC (BPF Compiler Collection) และ Python

ยินดีต้อนรับสู่ **Week 04** ของหลักสูตร **eBPF Zero to Hero**!
ในสัปดาห์นี้ เราจะก้าวเข้าสู่การเขียนโปรแกรม eBPF เต็มรูปแบบด้วยภาษา C และเชื่อมโยงการควบคุมใน User Space ด้วยภาษา Python ผ่าน **BCC (BPF Compiler Collection)** ซึ่งเป็นเฟรมเวิร์กที่ได้รับความนิยมสูงสุดในยุคบุกเบิกของ eBPF Tracing

เราจะพัฒนาเครื่องมือวัดเวลาที่เคอร์เนลใช้ในการ **เริ่ม** การเชื่อมต่อ **TCP IPv4 (`tcp_v4_connect`)** (หมายเหตุ: นี่คือเวลาทำงานของฟังก์ชันฝั่งเครื่องเรา ไม่ใช่ RTT ของ 3-way handshake — ดูหัวข้อ 1.3) โดยใช้เทคนิคการจับคู่เหตุการณ์ระหว่าง **`kprobe`** (ขาเข้า) และ **`kretprobe`** (ขาออก) ผ่าน **BPF Hash Map** พร้อมส่งสถิติผ่าน **BPF Perf Event Ring Buffer** ขึ้นมาแสดงผลใน Python และวาดกราฟความถี่ (Logarithmic Histogram) ในหน่วยไมโครวินาที!

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

1. **ภาระการคอมไพล์ที่หนักหน่วง (Resource Heavy)**: ทุกครั้งที่รันสคริปต์ BCC จะต้องเรียก Clang/LLVM มาคอมไพล์โค้ด C ณ ขณะเริ่มต้น — วัดจริงบนเครื่องทดสอบ (Ubuntu 26.04, BCC 0.35) สคริปต์ของสัปดาห์นี้ใช้เวลาคอมไพล์+attach ราว 0.7–0.8 วินาที และ Max RSS ของโปรเซสราว **180 MB** (`/usr/bin/time -f %M`) ตัวเลขจะมากหรือน้อยกว่านี้ขึ้นกับขนาดโปรแกรม จำนวน header และเวอร์ชัน LLVM
2. **การพึ่งพา Kernel Headers (`linux-headers`)**: โฮสต์ทุกตัวที่จะรันสคริปต์ BCC จำเป็นต้องติดตั้ง Package `linux-headers-$(uname -r)` (บน Ubuntu 26.04 / Linux 7.0 ใช้พื้นที่ราว 170 MB ตาม `du -shc /usr/src/linux-headers-$(uname -r | sed "s/-generic//")*`) ซึ่งใน Container ที่มีขนาดเล็ก (เช่น Distroless, Alpine) มักไม่มี Header เหล่านี้ ทำให้รันไม่ได้
3. **ปัญหาความไม่เข้ากันของเคอร์เนล (Kernel Version Fragility)**: หากโครงสร้างภายในเคอร์เนลเปลี่ยนไปเพียงเล็กน้อย โค้ดภาษา C อาจคอมไพล์ไม่ผ่านทันที — **เกิดขึ้นจริงบน Linux 7.0**: BCC 0.35 (แพ็กเกจของ Ubuntu 26.04) คอมไพล์โปรแกรมที่ `#include <net/sock.h>` ไม่ผ่าน (เช่น `error: use of undeclared identifier 'BPF_F_CPU'`) และเครื่องมือสำเร็จรูปอย่าง `tcpconnlat-bpfcc` ก็รันไม่ได้ (`error: no member named 'ns_id' in 'struct ns_common'`) สคริปต์ของเราจึงต้องนิยาม `struct sock_common` เองแบบย่อ ซึ่งมีความเสี่ยงของมันเอง (ดูหัวข้อ 2.1)

> [!NOTE]
> **ปัญหานี้เป็นที่มาของเทคโนโลยีใน Phase 3: BPF CO-RE (Compile Once – Run Everywhere)**
> ใน Phase 3 เราจะได้เรียนรู้การข้ามขีดจำกัดของ BCC ด้วยการคอมไพล์เป็น eBPF Binary เพียงครั้งเดียวผ่าน **libbpf + BTF (BPF Type Format)** และรันได้บนทุกเคอร์เนลโดยไม่ต้องติดตั้ง Clang/LLVM หรือ Kernel Headers บนโฮสต์ปลายทางเลย!

---

### 1.3 กลไกการวัด Latency ด้วย `kprobe` และ `kretprobe`
ในการวัดเวลาว่าฟังก์ชันหนึ่งๆ ในเคอร์เนลใช้เวลาทำงานนานเท่าใด เราต้องใช้ Probe 2 จุดร่วมกัน:
- **`kprobe__tcp_v4_connect`**: ดักจับเมื่อโปรเซสเริ่มต้นขอเชื่อมต่อ TCP (ก่อนที่ฟังก์ชันจะเลือก route/source port และส่งแพ็กเก็ต SYN ออกไป)
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

> [!IMPORTANT]
> **สิ่งที่วัดได้คือ "เวลาที่ใช้ในฟังก์ชัน `tcp_v4_connect()`" ไม่ใช่ Network Latency**: สำหรับ socket ปกติ `connect()` แบบ blocking จะไปรอ SYN-ACK ภายหลังใน `inet_wait_for_connect()` ซึ่งอยู่ **นอก** `tcp_v4_connect()` ส่วน socket แบบ non-blocking (เช่นที่ `curl` ใช้) ฟังก์ชันคืน `-EINPROGRESS` ทันที ผลที่ได้จึงอยู่ในหลักสิบไมโครวินาที (หาค่า route, จอง source port, ส่ง SYN) ไม่ว่าเซิร์ฟเวอร์จะอยู่ใกล้หรือไกล — ถ้าต้องการ RTT ของ handshake จริง ต้องจับเวลาจาก `tcp_v4_connect` ถึงตอนที่ socket เปลี่ยนเป็น `ESTABLISHED` (แนวทางเดียวกับเครื่องมือ `tcpconnlat` ของ BCC; ดูแบบฝึกหัด)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ส่วนของโค้ด eBPF Kernel C

```c
// 0. นิยาม struct sock_common แบบย่อ (แทน #include <net/sock.h> ที่คอมไพล์ไม่ผ่านบน 7.0)
struct sock_common {
    union { struct { __be32 skc_daddr; __be32 skc_rcv_saddr; }; };   // offset 0, 4
    union { unsigned int skc_hash; __u16 skc_u16hashes[2]; };        // offset 8
    union { struct { __be16 skc_dport; __u16 skc_num; }; };          // offset 12, 14
};
struct sock { struct sock_common __sk_common; };
```
- **คำอธิบาย**: BCC ใช้ offset ตามที่เราประกาศตรงๆ (ไม่มี CO-RE relocation) ดังนั้น layout ต้องตรงกับเคอร์เนลจริงทุกไบต์ ตรวจได้ด้วย `sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A 20 '^struct sock_common {'`
- **บั๊กที่พบและแก้แล้ว**: สคริปต์รุ่นก่อนไม่มี union `skc_hash` ทำให้ `skc_dport`/`skc_num` เลื่อนไป 4 ไบต์ และ **source port ที่แสดงเป็นค่าขยะ** (ทดสอบ: socket จริงได้ port 55746 แต่โปรแกรมแสดง 55543) — นี่คือตัวอย่างที่ชัดเจนที่สุดว่าทำไมเราต้องการ BTF/CO-RE ใน Phase 3

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
BPF_HISTOGRAM(dist);
```
- **คำอธิบาย**:
  - `BPF_HASH`: สร้างตาราง Hash Map ใน Kernel Space เก็บ State ชั่วคราว
  - `BPF_PERF_OUTPUT`: สร้าง Ring Buffer เชื่อมโยง Kernel สู่ User Space ประสิทธิภาพสูง
  - `BPF_HISTOGRAM`: สร้าง Array (ค่าเริ่มต้น 64 slot) สำหรับเก็บความถี่ของตัวเลข Latency เมื่อใช้คู่กับ `bpf_log2l()` จะได้ Logarithmic Histogram — ข้อความ `"Latency (us)"` เป็นหัวคอลัมน์ที่ส่งให้ `print_log2_hist()` ฝั่ง Python ไม่ใช่พารามิเตอร์ของ `BPF_HISTOGRAM`

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
สำหรับ Ubuntu 22.04 / 24.04 / 26.04 (เครื่องทดสอบ Ubuntu 26.04 ใช้ `python3-bpfcc` / `bpfcc-tools` เวอร์ชัน 0.35.0 และ `linux-headers-7.0.0-38-generic`):
```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

สำหรับ RHEL 9 / Fedora:
```bash
sudo dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r)
```

ตรวจสอบความพร้อม:
```bash
python3 -c "import bcc; print(bcc.__file__)"   # ต้อง import ได้
ls /lib/modules/$(uname -r)/build              # ต้องมี kernel headers ตรงกับเคอร์เนลที่รันอยู่
sudo bpftrace -l 'kprobe:tcp_v4_connect'       # ฟังก์ชันเป้าหมายต้องมีอยู่จริง
```
> [!WARNING]
> บน Linux 7.0 + BCC 0.35 เครื่องมือสำเร็จรูปใน `/usr/sbin/*-bpfcc` หลายตัว (เช่น `tcpconnlat-bpfcc`) **คอมไพล์ไม่ผ่าน** เพราะ header ของเคอร์เนลใหม่เกินกว่าที่ BCC รุ่นนี้รองรับ สคริปต์ของสัปดาห์นี้ยังรันได้เพราะหลีกเลี่ยง header ภายในเคอร์เนลที่มีปัญหา (ดูหัวข้อ Troubleshooting)

---

### ขั้นตอนที่ 2: รันโปรแกรมติดตาม Latency
รันสคริปต์ด้วยสิทธิ์ `sudo`:
```bash
sudo python3 tcp_v4_latency.py
```

**สิ่งที่แสดงบนหน้าจอเมื่อเริ่มต้น**:
```text
========================================================================
  eBPF Zero to Hero - Week 04: TCP IPv4 Connect Latency Tracker (BCC)   
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
ใน Terminal ที่ 1 คุณจะเห็นรายละเอียดการเชื่อมต่อและเวลาแสดงขึ้นมาทันที (ผลจริง; ตัวเลขทั้งหมดอยู่ในหลักสิบไมโครวินาทีแม้ปลายทางจะอยู่ต่างประเทศ เพราะวัดเฉพาะเวลาในฟังก์ชัน ไม่ใช่ RTT):
```text
22:25:10  140391  curl             192.168.31.249:36346   1.1.1.1:80             42          
22:25:10  140396  curl             192.168.31.249:39440   104.20.23.154:443      26          
22:25:10  140410  curl             192.168.31.249:48330   142.251.151.119:443    20          
22:25:10  140440  curl             192.168.31.249:57934   20.205.243.166:443     23          
22:25:11  139404  python3          127.0.0.1:55002        127.0.0.1:22           47          
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
        16 -> 31         : 3        |****************************************|
        32 -> 63         : 2        |**************************              |
========================================================================
eBPF session concluded safely. All kernel maps freed.
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), BCC / python3-bpfcc 0.35.0, linux-headers-7.0.0-38-generic

### 4.1 ผลลัพธ์การรัน `sudo python3 tcp_v4_latency.py` และสร้าง Outbound TCP Connections
คำสั่งทดสอบใน Terminal 2: `curl` ไปยัง `http://1.1.1.1`, `https://example.com`, `https://www.google.com`, `https://github.com` และ Python เชื่อมต่อ `127.0.0.1:22` พร้อมพิมพ์ `getsockname()` ออกมาเทียบ (`ACTUAL local ('127.0.0.1', 55002)` — ตรงกับ SRC port ที่ eBPF รายงาน)
```text
========================================================================
  eBPF Zero to Hero - Week 04: TCP IPv4 Connect Latency Tracker (BCC)   
========================================================================
 Compiling embedded C eBPF code via LLVM/Clang and attaching kprobes...
 JIT compilation & Kernel attach completed in 694.2 ms.

 Tracing active IPv4 TCP outbound connection latency (SYN initiation).
 Hit Ctrl+C to terminate and view microsecond latency histogram.

TIME      PID     COMM             SRC ADDR:PORT          DST ADDR:PORT          LATENCY (us)
--------------------------------------------------------------------------------------------
22:25:10  140391  curl             192.168.31.249:36346   1.1.1.1:80             42          
22:25:10  140396  curl             192.168.31.249:39440   104.20.23.154:443      26          
22:25:10  140410  curl             192.168.31.249:48330   142.251.151.119:443    20          
22:25:10  140440  curl             192.168.31.249:57934   20.205.243.166:443     23          
22:25:11  139404  python3          127.0.0.1:55002        127.0.0.1:22           47          


[!] Detaching eBPF probes and generating latency distribution...

========================================================================
           TCP Outbound Connection Latency Histogram (usecs)           
========================================================================
     Latency (us)        : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 3        |****************************************|
        32 -> 63         : 2        |**************************              |
========================================================================
eBPF session concluded safely. All kernel maps freed.
```
- วัดทรัพยากรด้วย `sudo /usr/bin/time -f "MAXRSS_KB=%M" timeout -s INT 11 python3 tcp_v4_latency.py` ได้ `MAXRSS_KB=187508` (~183 MiB) ส่วนใหญ่มาจาก LLVM/Clang ที่ฝังอยู่ใน BCC
- `PID` ของบรรทัด `python3` น้อยกว่า `curl` เพราะ bash ใช้ exec แทนการ fork สำหรับคำสั่งสุดท้ายใน subshell — โปรเซสจึงใช้ PID ของ subshell เดิม

---

## 5. Milestone Checklist

- [x] **BCC Architecture In-Depth**: เข้าใจขั้นตอนที่ Python นำโค้ดภาษา C ไปแปลงผ่าน LLVM JIT และโหลดเข้าสู่เคอร์เนล
- [x] **Production Trade-offs**: วิเคราะห์ข้อดีของ BCC ในการทดลอง และข้อจำกัดใน Production (CPU/RAM spike, dependency on kernel headers) จนเข้าใจเหตุผลที่ต้องมี CO-RE ใน Phase 3
- [x] **kprobe & kretprobe Pairing**: ชำนาญการผูกฟังก์ชันคู่เข้า/ออก และการใช้ BPF Hash Map ในการจับคู่ Context ข้ามเธรดด้วย `pid_tgid`
- [x] **Safe Kernel Memory Access**: ใช้งาน `bpf_probe_read_kernel()` เพื่อสกัดฟิลด์ข้อมูลจาก Network Structures ได้อย่างปลอดภัย
- [x] **High-Speed Telemetry Streaming**: ใช้งาน `BPF_PERF_OUTPUT` และการแปลง Data Layout ด้วย Python `ctypes.Structure` ได้อย่างสมบูรณ์แบบ
- [x] **Logarithmic Histogram Analysis**: สร้างและวิเคราะห์กราฟการกระจายตัวของ Latency ด้วย `BPF_HISTOGRAM` และ `print_log2_hist()`

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `[ERROR] The 'bcc' Python module is not installed or not found.` | ไม่ได้ติดตั้ง `python3-bpfcc` หรือรันใน **virtualenv** ที่มองไม่เห็น system `dist-packages` | `sudo apt install python3-bpfcc` และรันด้วย `/usr/bin/python3` (หรือสร้าง venv ด้วย `--system-site-packages`) |
| `[ERROR] Root privileges required to load eBPF programs.` | รันโดยไม่ใช้ `sudo` | `sudo python3 tcp_v4_latency.py` |
| `include/linux/bpf.h:...: error: use of undeclared identifier 'BPF_F_CPU'` ตามด้วย `Exception: Failed to compile BPF module <text>` | (ทดสอบจริงบน 7.0) โปรแกรม BCC ที่ `#include <net/sock.h>` หรือ header ภายในอื่นๆ ดึง `linux/bpf.h` ของเคอร์เนล 7.0 ซึ่งต้องการนิยามใหม่ที่ BCC 0.35 ไม่มี | หลีกเลี่ยง header ภายในเคอร์เนล (ประกาศ struct เองแบบในสัปดาห์นี้ — ต้องตรวจ offset กับ BTF) อัปเกรด BCC เป็นรุ่นที่รองรับเคอร์เนลนี้ หรือย้ายไปใช้ libbpf/CO-RE (Phase 3) |
| `tcpconnlat-bpfcc` ฯลฯ ล้มเหลวด้วย `error: no member named 'ns_id' in 'struct ns_common'` | (ทดสอบจริง) เครื่องมือสำเร็จรูปของ BCC 0.35 ไม่เข้ากับ header ของ Linux 7.0 | ใช้ bpftrace หรือเครื่องมือจาก libbpf-tools แทนจนกว่า BCC จะอัปเดต |
| BCC แจ้งว่าหา kernel headers ไม่พบ (`Unable to find kernel headers...`) | ไม่มี `linux-headers-$(uname -r)` หรือบูตเคอร์เนลใหม่แต่ headers ยังเป็นรุ่นเก่า | `sudo apt install linux-headers-$(uname -r)` แล้วตรวจ `ls /lib/modules/$(uname -r)/build` |
| attach kprobe ไม่สำเร็จ (`Failed to attach BPF program ... to kprobe ...`) | ชื่อฟังก์ชันไม่มี/ถูก inline หรือเปลี่ยนชื่อในเคอร์เนลรุ่นนี้ | `sudo bpftrace -l 'kprobe:tcp_v4_connect'` หรือ `grep -w tcp_v4_connect /proc/kallsyms` |
| SRC port เป็นเลขแปลกๆ ไม่ตรงกับ `ss -tnp` | offset ของ struct ที่ประกาศเองไม่ตรงกับเคอร์เนล (บั๊กที่เพิ่งแก้ในสัปดาห์นี้) | เทียบ layout กับ `bpftool btf dump file /sys/kernel/btf/vmlinux format c` และทดสอบกับ socket ที่รู้ port ล่วงหน้า |
| `Possibly lost N samples` | Perf buffer เต็มเพราะ event ถี่เกินไป | เพิ่ม `page_cnt` ใน `open_perf_buffer()` หรือสรุปผลใน kernel ด้วย histogram แทนการส่งทุก event |

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **พิสูจน์ว่าเราไม่ได้วัด RTT**: รันโปรแกรมแล้วเชื่อมต่อไปยังพอร์ตที่ปิดอยู่ (`curl -s http://127.0.0.1:1`) และเว็บไซต์ต่างประเทศ เทียบกับ `ping -c 3` ไปยังปลายทางเดียวกัน
   - **สิ่งที่ต้องส่ง**: ตารางเทียบ LATENCY ของโปรแกรม vs RTT จาก ping พร้อมอธิบายว่าทำไมการเชื่อมต่อที่ถูกปฏิเสธ (RST) ยังถูกรายงานว่า "สำเร็จ"
   - **วิธีตรวจ**: บรรทัดของ `127.0.0.1:1` ต้องปรากฏในผลลัพธ์ และค่าทุกบรรทัดอยู่ในหลักสิบไมโครวินาทีแม้ RTT จริงจะเป็นมิลลิวินาที
2. **กรองตามชื่อโปรเซส**: เพิ่ม argument `--comm curl` ให้สคริปต์ แล้วแทนค่าลงในโค้ด C ก่อนคอมไพล์ (BCC รับโค้ดเป็นสตริง จึงใช้ `.replace()` หรือ `cflags=["-DFILTER_COMM=..."]` ได้)
   - **สิ่งที่ต้องส่ง**: diff + ผลลัพธ์ที่แสดงเฉพาะ `curl`
   - **วิธีตรวจ**: รัน `curl` และ `python3 -c "import socket; socket.create_connection(('127.0.0.1',22))"` สลับกัน ต้องเห็นเฉพาะบรรทัด `curl`

### ระดับปานกลาง
3. **รองรับ IPv6 (`tcp_v6_connect`)**: เพิ่ม kprobe/kretprobe สำหรับ `tcp_v6_connect` และอ่าน `skc_v6_daddr` (หา offset ที่ถูกต้องจาก BTF ของเครื่องคุณเอง ห้ามเดา)
   - **สิ่งที่ต้องส่ง**: โค้ด + ตาราง offset ที่ได้จาก `bpftool btf dump ... format c` + ผลลัพธ์ที่ปลายทางเป็น IPv6
   - **วิธีตรวจ**: `python3 -c "import socket; s=socket.socket(socket.AF_INET6); s.connect(('::1',22)); print(s.getsockname())"` port ที่พิมพ์ต้องตรงกับ SRC port ที่โปรแกรมรายงาน
4. **เปลี่ยนจาก Perf Buffer เป็น Ring Buffer**: ใช้ `BPF_RINGBUF_OUTPUT(events, 8)` + `events.ringbuf_output()` ฝั่ง C และ `open_ring_buffer()` / `ring_buffer_poll()` ฝั่ง Python
   - **สิ่งที่ต้องส่ง**: diff + คำอธิบายข้อดีของ ring buffer (buffer เดียวแชร์ทุก CPU, ลำดับ event ข้าม CPU ถูกต้อง)
   - **วิธีตรวจ**: ผลลัพธ์ต้องเหมือนเดิม และ `sudo bpftool map show | grep ringbuf` ต้องเห็น map ชนิด `ringbuf` ขณะโปรแกรมรัน

### ระดับท้าทาย
5. **วัด Handshake RTT จริง**: เก็บ timestamp ตอนเข้า `tcp_v4_connect` โดยใช้ **pointer ของ `struct sock`** เป็น key (ไม่ใช่ `pid_tgid` เพราะ SYN-ACK มาถึงใน softirq คนละบริบท) แล้วคำนวณ delta ตอนที่ socket ออกจากสถานะ `SYN_SENT` (เช่น kprobe `tcp_rcv_state_process` และอ่าน `skc_state` — ต้องหา offset จาก BTF)
   - **สิ่งที่ต้องส่ง**: โค้ด + ผลที่ latency ของปลายทางไกลเป็นหลักมิลลิวินาที และอยู่ในระดับใกล้เคียง RTT จาก `ping`
   - **วิธีตรวจ**: เทียบกับ `ping -c 5 <ปลายทาง>` และ `curl -w '%{time_connect}\n' -o /dev/null -s https://<ปลายทาง>` — ค่าควรอยู่ในหลักเดียวกัน (ไม่จำเป็นต้องเท่ากัน)
6. **เขียนใหม่ด้วย bpftrace**: เขียนฟังก์ชันเดียวกับข้อ 5 ด้วย bpftrace (ซึ่งอ่าน `struct sock` ผ่าน BTF ได้โดยไม่ต้องประกาศ struct เอง) แล้วเปรียบเทียบจำนวนบรรทัดโค้ด เวลาเริ่มทำงาน และ Max RSS (`/usr/bin/time -f %M`) กับเวอร์ชัน BCC
   - **สิ่งที่ต้องส่ง**: สคริปต์ `.bt` + ตารางเปรียบเทียบ 3 ด้าน (วัดจริงบนเครื่องคุณ อย่างน้อย 3 รอบ)
   - **วิธีตรวจ**: ทั้งสองเวอร์ชันรายงานการเชื่อมต่อชุดเดียวกันเมื่อรัน `curl` ชุดเดียวกัน
