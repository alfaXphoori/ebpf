# สัปดาห์ที่ 14: ควบคุมการเชื่อมต่อขาออกระดับ Socket ด้วย cgroup/connect4 (Socket Egress Enforcer)

ยินดีต้อนรับสู่ **Week 14** ของหลักสูตร eBPF Zero to Hero!
ในสถาปัตยกรรมคลาวด์เนทีฟ (เช่น Kubernetes + Cilium) เรามักต้องการกำหนดว่า "workload กลุ่มนี้ห้ามเชื่อมต่อไปปลายทางนั้น" วิธีดั้งเดิมคือกรองแพ็กเก็ตด้วย iptables/nftables ซึ่งทำงานกับ **ทุกแพ็กเก็ต** และต้องอาศัย IP ของ workload ที่เปลี่ยนไปเรื่อย ๆ

สัปดาห์นี้เราจะใช้โปรแกรม eBPF ชนิด **`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`** แบบ `cgroup/connect4` เพื่อตัดสินใจ **ณ จังหวะ system call `connect()`** ของโปรเซสใน **cgroup v2 ที่กำหนด** หากปลายทางอยู่ใน blocklist ระบบจะคืน `EPERM` ให้แอปพลิเคชันทันที **ก่อนที่เคอร์เนลจะสร้างแพ็กเก็ต SYN** และเราจะทดสอบช่องโหว่ (bypass) ของนโยบายแบบนี้ไปพร้อมกัน

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 cgroup v2 กับการผูกโปรแกรม eBPF

**cgroup v2** จัดโปรเซสเป็นลำดับชั้นแบบต้นไม้ใต้ `/sys/fs/cgroup` (systemd ใช้จัด service และ user session, container runtime ใช้แยก container) เคอร์เนลอนุญาตให้ผูกโปรแกรม eBPF เข้ากับ cgroup ใดก็ได้ แล้วโปรแกรมนั้นจะมีผลกับ **cgroup นั้นและ cgroup ลูกหลานทั้งหมด**

```
/sys/fs/cgroup                      <- ROOT cgroup: ผูกที่นี่ = มีผลกับทุกโปรเซสบนเครื่อง (อันตราย!)
├── system.slice                    <- systemd services
├── user.slice                      <- login sessions ของผู้ใช้
└── w14-sock-enforce                <- cgroup ทดลองของแล็บนี้ (สร้างและลบโดยโปรแกรม)
        ▲
        └── cgroup/connect4: sock4_connect  (ผูกด้วย BPF link, flag "multi")
```

เวอร์ชันเดิมของแล็บใช้ค่าเริ่มต้น `-cgroup /sys/fs/cgroup` คือผูกกับ **root cgroup** ซึ่งกระทบทุกโปรเซสบนเครื่อง เวอร์ชันนี้แก้ให้:
- ค่าเริ่มต้นเป็น cgroup เฉพาะ `/sys/fs/cgroup/w14-sock-enforce` ซึ่งโปรแกรมสร้างให้อัตโนมัติและ `rmdir` ทิ้งตอนจบ
- **ปฏิเสธ** root cgroup เว้นแต่ใส่ `-allow-root` อย่างจงใจ

### 1.2 จุดที่ hook ทำงานในเส้นทาง `connect()`

```
 แอปพลิเคชันใน cgroup w14-sock-enforce
   connect(fd, {AF_INET, 127.0.0.1, 2323})
            │
            ▼
 __sys_connect() -> inet_stream_connect() / inet_dgram_connect()
            │
            ▼  sk->sk_prot->pre_connect()  (tcp_v4_pre_connect / udp_pre_connect)
 ┌────────────────────────────────────────────────────────────┐
 │ BPF_CGROUP_RUN_PROG_INET4_CONNECT                          │
 │   ctx = struct bpf_sock_addr { user_ip4, user_port, type } │
 │   sock4_connect():  lookup blocked_ips / blocked_ports     │
 │      return 0  ──► connect() = -1, errno = EPERM           │
 │      return 1  ──► ทำงานต่อ                                │
 └────────────────────────────────────────────────────────────┘
            │ (อนุญาต)
            ▼
 tcp_v4_connect(): เลือก source port, ส่ง SYN ...
```

ข้อสังเกตสำคัญ:
- โปรแกรมทำงานใน **process context ของผู้เรียก `connect()`** ดังนั้น `bpf_get_current_pid_tgid()` และ `bpf_get_current_comm()` ให้ค่าของแอปพลิเคชันจริง (ต่างจาก Week 13 ที่ทำงานใน softirq)
- นอกจากปฏิเสธแล้ว โปรแกรมชนิดนี้ยัง **เขียนทับ** `user_ip4`/`user_port` ได้ ซึ่งเป็นหลักการของ socket-level load balancing (เช่น kube-proxy replacement ของ Cilium) ที่แปลง Service IP เป็น Backend IP ตั้งแต่ตอน `connect()`
- ใช้ได้กับทั้ง TCP และ UDP ที่เรียก `connect()` (`ctx->type` บอกว่าเป็น `SOCK_STREAM` หรือ `SOCK_DGRAM`)

### 1.3 "Zero-overhead" จริงหรือ?

README เวอร์ชันก่อนอ้างว่าเป็น "Zero-overhead socket filter / 0% Packet Processing Overhead" ซึ่ง **กล่าวเกินจริง** ข้อเท็จจริงคือ:
- โปรแกรมรัน **ครั้งเดียวต่อการเรียก `connect()`** ไม่ใช่ต่อแพ็กเก็ต แพ็กเก็ตข้อมูลที่ตามมาหลังเชื่อมต่อสำเร็จจึง **ไม่มีต้นทุนเพิ่มจากโปรแกรมนี้**
- แต่ทุก `connect()` ของโปรเซสใน cgroup ยังต้องจ่ายค่ารันโปรแกรม BPF (hash lookup 1-2 ครั้ง) ซึ่งเล็กแต่ **ไม่เป็นศูนย์** และแล็บนี้ไม่ได้วัดตัวเลขจริง
- ถ้าไม่มีโปรแกรม `connect4` ผูกอยู่ที่ cgroup ใดเลย เคอร์เนลข้าม hook ด้วย static key (`cgroup_bpf_enabled()`) ส่วนโปรเซสใน cgroup อื่นที่ไม่มีโปรแกรม จะเสียเพียงการตรวจรายการโปรแกรมที่ว่างเปล่า (ควรตรวจสอบรายละเอียดกับ `kernel/bpf/cgroup.c` ของเวอร์ชันที่ใช้)

สรุปที่ถูกต้องกว่า: **"overhead ต่ำและเกิดเฉพาะตอนสร้างการเชื่อมต่อ ไม่เกิดต่อแพ็กเก็ต"** หากต้องการตัวเลข ให้วัดด้วย `bpftool prog show` (เปิด `sysctl kernel.bpf_stats_enabled=1` เพื่อดู `run_time_ns`/`run_cnt`)

### 1.4 ทำไมแล็บนี้ใช้ `<linux/bpf.h>` ไม่ใช่ `vmlinux.h`

แล็บ tracing อื่นใน Phase 7 ใช้ `vmlinux.h` + CO-RE เพราะ struct ภายในเคอร์เนลเปลี่ยน layout ได้ แต่ context ของ `cgroup/connect4` คือ **`struct bpf_sock_addr` ซึ่งเป็น UAPI** (ABI ที่เคอร์เนลสัญญาว่าจะคงที่) verifier จะ **เขียนคำสั่ง load ใหม่ (context rewrite)** ให้ไปอ่าน `struct bpf_sock_addr_kern` ภายในเคอร์เนลให้เอง จึงไม่จำเป็นต้องใช้ CO-RE และใช้ header มาตรฐานได้อย่างปลอดภัย

### 1.5 Byte order ของ IP และพอร์ตใน `bpf_sock_addr`

| ฟิลด์ | ชนิด | byte order | วิธีจัดการ |
|---|---|---|---|
| `user_ip4` | `__u32` | network order | ฝั่ง Go ใช้ `binary.NativeEndian.Uint32(ip.To4())` ให้ไบต์ในหน่วยความจำเรียงเหมือนกัน (ถูกต้องทั้ง little/big-endian) |
| `user_port` | `__u32` (ใช้ 16 บิตล่าง) | network order | ฝั่ง C แปลงด้วย `bpf_ntohs((__u16)ctx->user_port)` ก่อนใช้เป็น key |

> [!NOTE]
> เวอร์ชันเดิมประกอบ key ของ IP ด้วย `ip[0] | ip[1]<<8 | ...` ซึ่งถูกเฉพาะบนเครื่อง little-endian เวอร์ชันนี้เปลี่ยนเป็น `binary.NativeEndian` เพื่อให้ถูกทุกสถาปัตยกรรม

### 1.6 Socket ผูกกับ cgroup "ตอนถูกสร้าง"

เคอร์เนลบันทึก cgroup ลงใน socket (`sk->sk_cgrp_data`) **ตอนสร้าง socket** และ hook ใช้ cgroup ของ socket ไม่ใช่ของเธรดที่เรียก `connect()` เราทดสอบจริงแล้ว (ข้อ 4.3): socket ที่สร้าง **ก่อน** ย้ายโปรเซสเข้า cgroup จะ **ไม่ถูกบล็อก** ผลที่ตามมาคือ socket ที่ส่งต่อมาจากโปรเซสนอก cgroup (เช่นผ่าน `SCM_RIGHTS` หรือการ fork จาก parent ที่สร้าง socket ไว้แล้ว) จะเลี่ยงนโยบายได้

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `sock_enforce.c`

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
```
- **บรรทัด 13-15:** ใช้ UAPI header (เหตุผลในข้อ 1.4) และ `bpf_endian.h` สำหรับ `bpf_ntohs`

```c
#define VERDICT_DENY  0 /* connect() คืนค่า -1 และ errno = EPERM */
#define VERDICT_ALLOW 1
```
- **บรรทัด 25-26:** ค่าที่คืนจากโปรแกรม cgroup sock_addr มีความหมายเพียง 0 = ปฏิเสธ, 1 = อนุญาต

```c
} blocked_ports SEC(".maps");   /* key: __u16 port (host order) -> value: __u64 deny count */
} blocked_ips SEC(".maps");     /* key: __u32 IPv4 (network order) -> value: __u64 deny count */
```
- **บรรทัด 36-53:** สอง Hash Map ทำหน้าที่ทั้ง blocklist และตัวนับในตัวเดียว (value = จำนวนครั้งที่ถูกปฏิเสธ) User Space เพิ่ม/ลบรายการได้ขณะรันโดยไม่ต้องโหลดโปรแกรมใหม่

```c
struct deny_event {
    __u32 pid;
    __u32 dst_ip;
    __u16 dst_port;
    __u8 sock_type;
    __u8 match;
    char comm[TASK_COMM_LEN];
};
```
- **บรรทัด 58-65:** audit event ขนาด 28 ไบต์ (ไม่มี implicit padding) ส่งผ่าน Ring Buffer ขนาด 64KB (บรรทัด 67-70)

```c
static __always_inline void emit_deny(__u32 dst_ip, __u16 dst_port, __u32 sock_type, __u8 match)
```
- **บรรทัด 72-85:** ส่ง audit event หาก ring buffer เต็ม event จะหาย แต่ **นโยบายยังบล็อกตามปกติ** (การตัดสินใจไม่ขึ้นกับการ log)

```c
SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET) {
        return VERDICT_ALLOW;
    }
```
- **บรรทัด 94-99:** section name `cgroup/connect4` บอก loader ว่าเป็น `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` + attach type `BPF_CGROUP_INET4_CONNECT` การตรวจ `user_family` เป็นการป้องกันเชิงรับ (defensive check)

```c
    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = bpf_ntohs((__u16)ctx->user_port);
```
- **บรรทัด 101-103:** อ่าน IP/พอร์ตปลายทางจาก `sockaddr` ที่แอปพลิเคชันส่งมา (verifier แปลงเป็นการอ่าน struct ภายในเคอร์เนลให้)

```c
    __u64 *ip_drop_count = bpf_map_lookup_elem(&blocked_ips, &dst_ip);
    if (ip_drop_count) {
        __sync_fetch_and_add(ip_drop_count, 1);
        emit_deny(dst_ip, dst_port, ctx->type, MATCH_IP);
        return VERDICT_DENY;
    }
```
- **บรรทัด 106-111:** ตรวจ IP ก่อน ถ้าพบให้นับแบบ atomic, ส่ง audit event แล้วปฏิเสธ (พอร์ตตรวจแบบเดียวกันที่บรรทัด 114-119)

### 2.2 ไฟล์ `main.go`

```go
func prepareCgroup(path string, allowRoot bool) (bool, error) {
	clean := filepath.Clean(path)
	if clean == cgroupRoot && !allowRoot {
		return false, fmt.Errorf("refusing to attach to the ROOT cgroup ...")
```
- **บรรทัด 51-69:** ด่านความปลอดภัย: ปฏิเสธ root cgroup และสร้าง cgroup ใหม่ได้เฉพาะระดับ `/sys/fs/cgroup/<name>` (บรรทัด 65 `os.Mkdir`)

```go
		defer func() {
			if err := os.Remove(*cgroupPath); err != nil {
```
- **บรรทัด 88-96:** ถ้าโปรแกรมเป็นคนสร้าง cgroup จะ `rmdir` ทิ้งตอนจบ (สำเร็จได้ก็ต่อเมื่อไม่มีโปรเซสเหลือใน cgroup) defer นี้ลงทะเบียนก่อน จึงทำงาน **หลังสุด** หลังจาก link และ objects ถูกปิดแล้ว

```go
		ipKey = binary.NativeEndian.Uint32(ip)
```
- **บรรทัด 125:** สร้าง key ของ IP ให้ไบต์เรียงแบบ network order ในหน่วยความจำ (ข้อ 1.5)

```go
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4Connect,
	})
```
- **บรรทัด 134-138:** cilium/ebpf จะใช้ **BPF link** (`BPF_LINK_CREATE`) ถ้าเคอร์เนลรองรับ ข้อดีคือ link ผูกกับ file descriptor ของโปรเซสเรา เมื่อโปรแกรมจบหรือถูก kill โปรแกรม eBPF จะถูก detach อัตโนมัติ ไม่ค้างอยู่ใน cgroup

```go
	for {
		rec, err := rd.Read()
		...
		fmt.Printf("[%s] DENY connect() pid=%-7d comm=%-12s dst=%s:%d/%s (matched %s) -> EPERM\n", ...)
```
- **บรรทัด 162-185:** อ่าน audit event จาก Ring Buffer แล้วแสดงว่าใคร (pid/comm) พยายามเชื่อมต่อไปไหนและถูกบล็อกด้วยกฎใด

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์
```bash
cd phase07-advanced-security-observability/week14-cgroup-sock-addr
make all
```

### ขั้นตอนที่ 2: เปิด listener ทดสอบบน loopback (Terminal 1)
```bash
# ฟังที่ 127.0.0.1:2323 และ 127.0.0.1:8080 เพื่อให้เห็นความต่างระหว่าง "ถูกบล็อก" กับ "เชื่อมต่อได้"
python3 -c "
import socket,time
ls=[]
for p in (2323,8080):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('127.0.0.1',p)); s.listen(16); ls.append(s)
time.sleep(600)"
```

### ขั้นตอนที่ 3: รัน Enforcer (Terminal 2)
```bash
sudo ./bin/sock-enforce                      # ค่าเริ่มต้น: cgroup w14-sock-enforce, พอร์ต 2323, IP 10.99.99.99
sudo bpftool cgroup show /sys/fs/cgroup/w14-sock-enforce   # ต้องเห็น cgroup_inet4_connect
sudo bpftool cgroup show /sys/fs/cgroup                    # root cgroup ต้อง "ว่าง"
```

### ขั้นตอนที่ 4: ทดสอบจาก "นอก" และ "ใน" cgroup (Terminal 3)
สร้างสคริปต์ทดสอบ `client.py` (ทุกปลายทางเป็น loopback หรือ IP ที่ถูกบล็อกก่อนส่ง SYN):
```python
import socket, errno, sys
def tryit(label, fn):
    try: fn(); print(f"  {label:<48} -> OK (not blocked)")
    except OSError as e: print(f"  {label:<48} -> {errno.errorcode.get(e.errno)} ({e.strerror})")
def tcp4(h, p):
    def f():
        s = socket.socket(); s.settimeout(1)
        try: s.connect((h, p))
        finally: s.close()
    return f
def udp4_connect(h, p):
    def f():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect((h, p))
        finally: s.close()
    return f
def udp4_sendto(h, p):
    def f():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.sendto(b"x", (h, p))
        finally: s.close()
    return f
def tcp6_mapped(h, p):
    def f():
        s = socket.socket(socket.AF_INET6); s.settimeout(1)
        try: s.connect(("::ffff:" + h, p))
        finally: s.close()
    return f
print("cgroup of client:", open("/proc/self/cgroup").read().strip())
tryit("TCP  connect 127.0.0.1:2323 (blocked port)", tcp4("127.0.0.1", 2323))
tryit("TCP  connect 127.0.0.1:8080 (allowed port)", tcp4("127.0.0.1", 8080))
if "--in-cgroup" in sys.argv:   # ไม่ทดสอบ IP ภายนอกจากนอก cgroup เพื่อไม่ให้มี SYN ออกไปจริง
    tryit("TCP  connect 10.99.99.99:80 (blocked IP)", tcp4("10.99.99.99", 80))
tryit("UDP  connect 127.0.0.1:2323 (blocked port)", udp4_connect("127.0.0.1", 2323))
if "--bypass" in sys.argv:
    tryit("UDP  sendto 127.0.0.1:2323 without connect()", udp4_sendto("127.0.0.1", 2323))
    tryit("TCP6 connect [::ffff:127.0.0.1]:2323 (v4-mapped)", tcp6_mapped("127.0.0.1", 2323))
```
```bash
# 4.1 นอก cgroup (baseline): ทุกอย่างต้องเชื่อมต่อได้
python3 client.py

# 4.2 ใน cgroup: ย้าย shell ชั่วคราวเข้า cgroup แล้ว exec ไคลเอนต์ (รันในสิทธิ์ผู้ใช้ปกติ)
sudo sh -c "echo \$\$ > /sys/fs/cgroup/w14-sock-enforce/cgroup.procs && exec sudo -u $USER python3 client.py --in-cgroup --bypass"
```

### ขั้นตอนที่ 5: หยุดและล้างสภาพแวดล้อม
กด `Ctrl+C` ใน Terminal 2 (โปรแกรม detach และลบ cgroup ให้เอง) และหยุด listener ใน Terminal 1 ตรวจว่าไม่มี cgroup ค้าง:
```bash
ls -d /sys/fs/cgroup/w14-* 2>/dev/null || echo "clean"
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), clang 21, Go 1.26, cilium/ebpf v0.16.0 (บันทึกเมื่อ 2026-10-28)
> สคริปต์ที่ใช้ตอนบันทึกชื่อ `w14_client.py` ซึ่งเป็นรุ่นก่อนของ `client.py` ในข้อ 3 (ยังไม่มี flag `--in-cgroup` จึงทดสอบ 10.99.99.99 ทุกรอบ) ในรอบ baseline เราตัดบรรทัด 10.99.99.99 ออกจากการแสดงผลด้วย `grep -v` ส่วนเนื้อหาบรรทัดอื่นไม่ได้แก้ไข

### 4.1 ไคลเอนต์ (Terminal 3)
```text
### baseline: client OUTSIDE the test cgroup
cgroup of client: 0::/user.slice/user-1000.slice/user@1000.service/tmux-spawn-9ef4b967-05d2-4658-80c9-513e01e0eaac.scope
  TCP  connect 127.0.0.1:2323 (blocked port)       -> OK (not blocked)
  TCP  connect 127.0.0.1:8080 (allowed port)       -> OK (not blocked)
  UDP  connect 127.0.0.1:2323 (blocked port)       -> OK (not blocked)

### client INSIDE /sys/fs/cgroup/w14-sock-enforce
$ sudo sh -c 'echo $$ > /sys/fs/cgroup/w14-sock-enforce/cgroup.procs && exec sudo -u ce python3 w14_client.py --bypass'
cgroup of client: 0::/w14-sock-enforce
  TCP  connect 127.0.0.1:2323 (blocked port)       -> EPERM (Operation not permitted)
  TCP  connect 127.0.0.1:8080 (allowed port)       -> OK (not blocked)
  TCP  connect 10.99.99.99:80 (blocked IP)         -> EPERM (Operation not permitted)
  UDP  connect 127.0.0.1:2323 (blocked port)       -> EPERM (Operation not permitted)
  UDP  sendto 127.0.0.1:2323 without connect()     -> OK (not blocked)
  TCP6 connect [::ffff:127.0.0.1]:2323 (v4-mapped) -> OK (not blocked)

$ sudo bpftool cgroup show /sys/fs/cgroup/w14-sock-enforce
ID       AttachType      AttachFlags     Name           
9863     cgroup_inet4_connect multi           sock4_connect                  
$ sudo bpftool cgroup show /sys/fs/cgroup
(ไม่มีผลลัพธ์: root cgroup ไม่มีโปรแกรมของเราผูกอยู่)
```

### 4.2 Enforcer (Terminal 2)
```text
======================================================================
 eBPF Socket Egress Enforcer (cgroup/connect4)
======================================================================
2026/10/28 22:02:55 [INFO] Created dedicated test cgroup /sys/fs/cgroup/w14-sock-enforce
2026/10/28 22:02:55 [POLICY] Deny destination port: 2323 (TCP + connected UDP)
2026/10/28 22:02:55 [POLICY] Deny destination IPv4: 10.99.99.99
2026/10/28 22:02:55 [INFO] Attached cgroup/connect4 to /sys/fs/cgroup/w14-sock-enforce
2026/10/28 22:02:55 [INFO] Policy applies ONLY to processes inside this cgroup. Run a client with:
2026/10/28 22:02:55        sudo sh -c 'echo $$ > /sys/fs/cgroup/w14-sock-enforce/cgroup.procs && exec <command>'
2026/10/28 22:02:55 [INFO] Press Ctrl+C to detach and exit.

[22:02:57] DENY connect() pid=4052785 comm=python3      dst=127.0.0.1:2323/TCP (matched port) -> EPERM
[22:02:57] DENY connect() pid=4052785 comm=python3      dst=10.99.99.99:80/TCP (matched ip) -> EPERM
[22:02:57] DENY connect() pid=4052785 comm=python3      dst=127.0.0.1:2323/UDP (matched port) -> EPERM

[INFO] Detaching from cgroup and stopping...
Final denies on port 2323: 2
Final denies on IP 10.99.99.99: 1
2026/10/28 22:03:04 [INFO] Removed test cgroup /sys/fs/cgroup/w14-sock-enforce
```

### 4.3 การทดลองเสริม: socket ที่สร้างก่อนเข้า cgroup
```text
$ sudo python3 w14_precreate.py
now in: 0::/w14-sock-enforce
  socket created BEFORE joining cgroup     -> [Errno 111] Connection refused
  socket created AFTER joining cgroup      -> [Errno 1] Operation not permitted
```
(สคริปต์สร้าง socket หนึ่งตัวก่อนเขียน PID ตัวเองลง `cgroup.procs` และอีกตัวหลังจากนั้น แล้ว `connect()` ไปที่ 127.0.0.1:2323 ขณะที่ไม่มี listener: ตัวแรก "ผ่าน" hook จึงได้ `ECONNREFUSED` จาก TCP ปกติ ตัวที่สองถูกบล็อกด้วย `EPERM`)

### 4.4 ด่านป้องกัน root cgroup
```text
$ sudo ./bin/sock-enforce -cgroup /sys/fs/cgroup
2026/10/28 22:03:16 [ERROR] refusing to attach to the ROOT cgroup /sys/fs/cgroup (affects every process on the host); use a dedicated cgroup or pass -allow-root
```

**วิเคราะห์ผล:**
- นโยบายมีผล **เฉพาะ** โปรเซสใน cgroup ทดลอง (baseline นอก cgroup เชื่อมต่อพอร์ต 2323 ได้ตามปกติ)
- `connect()` ที่ถูกบล็อกล้มเหลวทันทีด้วย `EPERM` ทั้ง TCP และ UDP ส่วนพอร์ตที่ไม่อยู่ใน blocklist (8080) ใช้ได้ปกติ
- ตัวนับ `Final denies on port 2323: 2` (TCP 1 + UDP 1) ตรงกับ audit event
- **พบ bypass จริง 2 ทาง:** `sendto()` ของ UDP โดยไม่ `connect()` และ socket `AF_INET6` ที่ใช้ IPv4-mapped address (`::ffff:127.0.0.1`) ทั้งสองไม่ผ่าน hook `connect4` (ดูข้อ 5)

---

## 5. ข้อจำกัดและ Threat Model (Limitations)

**สมมติฐาน (Threat Model):** ผู้ที่ถูกควบคุมคือโปรเซส **ไม่มีสิทธิ์ root** ที่รันอยู่ใน cgroup เป้าหมาย (เช่น container ของแอปพลิเคชันที่อาจถูกเจาะ) ผู้ดูแลระบบเป็นผู้กำหนดนโยบาย

| ช่องทางเลี่ยง / ข้อจำกัด | ทดสอบในแล็บนี้ | วิธีปิด |
|---|---|---|
| UDP `sendto()`/`sendmsg()` โดยไม่ `connect()` | ✔ เลี่ยงได้จริง | ผูก `cgroup/sendmsg4` เพิ่ม |
| `AF_INET6` socket + IPv4-mapped address (`::ffff:a.b.c.d`) | ✔ เลี่ยงได้จริง | ผูก `cgroup/connect6` (และ `sendmsg6`) แล้วตรวจ `user_ip6` ที่เป็น v4-mapped |
| IPv6 ปกติ | ไม่ครอบคลุมโดยการออกแบบ | `cgroup/connect6` |
| socket ที่สร้างนอก cgroup แล้วส่งเข้ามา (fd passing / fork) | ✔ เลี่ยงได้จริง (ข้อ 4.3) | ผูกนโยบายที่ cgroup ระดับสูงกว่า หรือใช้ `cgroup/sock_create` ร่วมด้วย |
| Raw socket / `AF_PACKET` (ต้องมี `CAP_NET_RAW`) | ไม่ได้ทดสอบ | ตัด capability ออกจาก workload, ใช้ `cgroup/sock_create` ปฏิเสธการสร้าง socket ชนิดนี้ |
| ใช้ proxy / DNS name / IP อื่นของปลายทางเดียวกัน | ไม่ได้ทดสอบ | blocklist แบบ IP ตรวจได้แค่ IP ไม่รู้จักชื่อโดเมน ต้องใช้ allowlist หรือ L7 policy |
| ผู้โจมตีมี root ใน host | ไม่อยู่ในขอบเขต | root ย้ายตัวเองออกจาก cgroup หรือ detach โปรแกรมได้ |
| ปิดโปรแกรม = นโยบายหายทันที | ✔ (ออกแบบให้ link ผูกกับโปรเซส) | ในโปรดักชันให้ pin link ไว้ที่ `/sys/fs/bpf` เพื่อให้นโยบายอยู่ต่อแม้ agent restart |
| `log.Fatalf` หลังสร้าง cgroup จะข้าม defer | cgroup ว่างอาจค้าง | `sudo rmdir /sys/fs/cgroup/w14-sock-enforce` |

> [!IMPORTANT]
> โปรแกรมนี้เป็น **ชั้นป้องกันหนึ่ง (defense-in-depth)** ไม่ใช่ firewall สมบูรณ์ ระบบจริงอย่าง Cilium ผูก hook หลายตัวพร้อมกัน (`connect4/6`, `sendmsg4/6`, `recvmsg4/6`, `getpeername4/6`) และทำงานร่วมกับ policy ระดับแพ็กเก็ตด้วย

---

## 6. Milestone Checklist

- [x] เข้าใจโครงสร้าง cgroup v2 และผลของการผูกโปรแกรม eBPF ที่ cgroup ระดับต่าง ๆ (รวมถึงอันตรายของ root cgroup)
- [x] อธิบายตำแหน่งของ hook `cgroup/connect4` ในเส้นทาง `connect()` และความหมายของค่าที่คืน (0 = EPERM)
- [x] จัดการ byte order ของ `user_ip4`/`user_port` ได้ถูกต้องทุกสถาปัตยกรรม
- [x] ใช้ BPF link เพื่อให้นโยบายถูก detach อัตโนมัติเมื่อ agent จบ
- [x] ส่ง audit event (pid/comm/ปลายทาง) ผ่าน Ring Buffer
- [x] ทดสอบนโยบายจากทั้งนอกและใน cgroup และตรวจสอบด้วย `bpftool cgroup show`
- [x] พิสูจน์ช่องทาง bypass จริง (UDP sendto, IPv4-mapped IPv6, socket ที่สร้างก่อนเข้า cgroup) และระบุวิธีปิด

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **บล็อกหลายพอร์ต:** เปลี่ยน `-block-port` ให้รับหลายค่า (เช่น `-block-ports 23,2323,4444`)
   - *ส่งงาน:* โค้ด `main.go` ที่แก้ + ผลการทดสอบที่ทุกพอร์ตได้ `EPERM`
   - *ตรวจ:* `sudo bpftool map dump name blocked_ports` ต้องแสดงครบทุกพอร์ตพร้อมตัวนับ
2. **วัดต้นทุนจริง:** เปิด `sudo sysctl kernel.bpf_stats_enabled=1` รันไคลเอนต์ใน cgroup ที่ `connect()` 1,000 ครั้ง แล้วอ่าน `run_time_ns`/`run_cnt` จาก `bpftool prog show name sock4_connect`
   - *ส่งงาน:* ค่าเฉลี่ย ns ต่อการเรียก 1 ครั้ง
   - *ตรวจ:* `run_cnt` ต้องเท่ากับจำนวน `connect()` (ไม่ใช่จำนวนแพ็กเก็ต) และปิด `bpf_stats_enabled` กลับหลังทดลอง

### ระดับปานกลาง
1. **ปิด bypass ทาง UDP:** เพิ่มโปรแกรม `SEC("cgroup/sendmsg4")` ที่ใช้ map ชุดเดียวกัน
   - *ส่งงาน:* โค้ด + ผลลัพธ์ที่ `UDP sendto ... without connect()` เปลี่ยนเป็น `EPERM`
   - *ตรวจ:* รัน `client.py --in-cgroup --bypass` อีกครั้ง
2. **ปิด bypass ทาง IPv4-mapped:** เพิ่ม `SEC("cgroup/connect6")` ที่ตรวจว่า `user_ip6` อยู่ในรูป `::ffff:a.b.c.d` แล้วนำ IPv4 ส่วนท้ายไปเทียบกับ `blocked_ips`/`blocked_ports`
   - *ส่งงาน:* โค้ด + ผลลัพธ์ที่บรรทัด `TCP6 connect [::ffff:127.0.0.1]:2323` ได้ `EPERM`
   - *ตรวจ:* การเชื่อมต่อ IPv6 ปกติไปยัง `[::1]:8080` ยังต้องใช้ได้

### ระดับท้าทาย
1. **Transparent redirect (socket-LB):** แทนการปฏิเสธ ให้เขียนทับ `ctx->user_ip4`/`ctx->user_port` เพื่อพาการเชื่อมต่อไป `127.0.0.1:2323` ไปยัง `127.0.0.1:8080` แทน (หลักการเดียวกับ kube-proxy replacement)
   - *ส่งงาน:* โค้ด + หลักฐานจาก listener ว่าได้รับการเชื่อมต่อที่พอร์ต 8080
   - *ตรวจ:* อธิบายได้ว่าทำไม `getpeername()` ฝั่งไคลเอนต์อาจคืนพอร์ต 8080 และ hook `cgroup/getpeername4` ช่วยแก้อย่างไร
2. **Allowlist แบบ default-deny:** เปลี่ยนนโยบายเป็น "อนุญาตเฉพาะปลายทางในรายการ" สำหรับ cgroup ทดลอง และทดสอบว่าการ resolve DNS (UDP 53) ได้รับผลกระทบอย่างไร
   - *ส่งงาน:* โค้ด + ตารางผลการทดสอบ (ปลายทางในรายการ / นอกรายการ / DNS)
   - *ตรวจ:* ยืนยันว่ามีผลเฉพาะโปรเซสใน `w14-*` cgroup และ cgroup ถูกลบหลังทดลอง
