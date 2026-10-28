# Week 20: TCP Socket-to-Socket Bypass ด้วย sockops + sk_msg (SOCKHASH Redirect)

ยินดีต้อนรับสู่สัปดาห์ที่ 20 ของหลักสูตร **eBPF: Zero-to-Hero** และเป็นสัปดาห์แรกของ **Phase 9: High-Throughput Socket Acceleration**

ในระบบ Microservices / Service Mesh ทราฟฟิกจำนวนมากวิ่งอยู่ **บนเครื่องเดียวกัน** (เช่น Application ↔ Sidecar Proxy อย่าง Envoy หรือ Pod ↔ Pod บน Node เดียวกัน) แต่ทุก `send()` ยังต้องเดินผ่าน TCP/IP Stack เต็มรูปแบบ: สร้าง TCP/IP Header, คำนวณ Checksum (บน loopback ถูกข้ามได้บางส่วน), ผ่าน Netfilter Hooks, ส่งผ่าน `lo` แล้ววนกลับขึ้นมาใน softirq ฝั่งรับ และสร้าง ACK กลับ

สัปดาห์นี้เราจะใช้ **`BPF_PROG_TYPE_SOCK_OPS`** เก็บ Socket ที่เชื่อมต่อแล้วลงใน **`BPF_MAP_TYPE_SOCKHASH`** และใช้ **`BPF_PROG_TYPE_SK_MSG`** ย้าย Payload ของ `sendmsg()` ไปใส่ **Receive Queue ของ Socket ปลายทางโดยตรง** ลัดข้าม TCP/IP Stack ทั้งหมด — แล้ว **วัดผลจริง** ว่าเร็วขึ้นเท่าไร

> [!WARNING]
> เวอร์ชันก่อนหน้าของแล็บนี้มีบั๊กเรื่อง Byte Order ของพอร์ต ทำให้คีย์ฝั่ง `sockops` กับ `sk_msg` ไม่มีวันตรงกัน → `bpf_msg_redirect_hash()` ล้มเหลวทุกครั้ง แต่ Dashboard ยังนับว่า "accelerated" เพราะนับก่อน Redirect บทนี้อธิบายบั๊กดังกล่าวในหัวข้อ 1.4 และโค้ดปัจจุบันแก้แล้ว พร้อม Test ที่พิสูจน์ว่า Redirect เกิดขึ้นจริง

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 เส้นทางข้อมูล Localhost TCP: ปกติ vs SOCKHASH Redirect

```
        ปกติ (Loopback TCP)                         SOCKHASH Redirect (สัปดาห์นี้)
 +----------------------------+              +----------------------------------+
 | Client: write()/sendmsg()  |              | Client: write()/sendmsg()        |
 +-------------|--------------+              +----------------|-----------------+
               v                                              v
 +----------------------------+              +----------------------------------+
 | tcp_sendmsg: copy -> skb   |              | tcp_bpf_sendmsg: copy -> sk_msg  |
 | TCP header, seq/ack, cwnd  |              |   +----------------------------+ |
 | IP header, routing         |              |   | SK_MSG prog (bpf_sk_msg_   | |
 | Netfilter OUTPUT/POSTROUTE |              |   | handler): lookup peer key  | |
 | dev_queue_xmit(lo)         |              |   | bpf_msg_redirect_hash(     | |
 +-------------|--------------+              |   |   BPF_F_INGRESS)           | |
               v                             |   +-------------|--------------+ |
 +----------------------------+              +-----------------|----------------+
 | softirq: netif_rx (lo)     |                                |  ย้าย sk_msg ไปยัง
 | IP rcv, Netfilter PREROUTE |                                |  ingress_msg ของ
 | INPUT, tcp_v4_rcv          |                                |  peer socket โดยตรง
 | ส่ง ACK กลับ (อีกรอบ!)        |                                v
 +-------------|--------------+              +----------------------------------+
               v                             | Server: tcp_bpf_recvmsg          |
 +----------------------------+              |   copy sk_msg -> user buffer     |
 | Server: recvmsg() copy     |              +----------------------------------+
 +----------------------------+
```

สิ่งที่ถูกลัดข้าม: การสร้าง/ประมวลผล TCP Segment, ACK, IP Routing, Netfilter, การส่งผ่าน `lo` และ softirq ฝั่งรับ — ส่วน **Handshake (SYN/SYN-ACK/ACK) และ FIN ยังวิ่งผ่าน Stack ปกติ** เพราะ Redirect ทำงานเฉพาะ Payload ของ `sendmsg()` (เราพิสูจน์ด้วย `tcpdump` ในหัวข้อ 4.4)

> [!NOTE]
> **นี่ไม่ใช่ Zero-Copy** — ข้อมูลยังถูก Copy จาก User → Kernel (`sk_msg`) หนึ่งครั้ง และ Kernel → User อีกหนึ่งครั้งตอน `recvmsg()` เท่ากับ TCP ปกติ สิ่งที่ประหยัดคือ **งานประมวลผลโปรโตคอล** ไม่ใช่การ Copy หน่วยความจำ

### 1.2 `BPF_PROG_TYPE_SOCK_OPS`: Hook วงจรชีวิตของ TCP Connection

โปรแกรม `sockops` ถูกแนบกับ **cgroup v2** (`BPF_CGROUP_SOCK_OPS`) และถูกเรียกเมื่อ Socket ของ Process ใน cgroup นั้นเกิดเหตุการณ์ TCP ต่าง ๆ โดย `skops->op` บอกชนิดของเหตุการณ์ เช่น:

| `op` | เกิดเมื่อ |
|------|-----------|
| `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` | ฝั่ง Client (`connect()`) Handshake สำเร็จ |
| `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` | ฝั่ง Server (Socket ที่ได้จาก `accept()`) Handshake สำเร็จ |
| `BPF_SOCK_OPS_STATE_CB`, `RTO_CB`, ... | ต้องเปิดด้วย `bpf_sock_ops_cb_flags_set()` ก่อน |

ทั้งสองฝั่งของ Connection ต้องอยู่ใน cgroup ที่แนบโปรแกรมไว้ ไม่เช่นนั้นจะมีแค่ฝั่งเดียวใน Map และ Redirect จะหาคู่ไม่เจอ

### 1.3 `SOCKHASH` + `SK_MSG`: กลไก Redirect

- `bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST)` — ใส่ Socket ลง Map ด้วยคีย์ 4-tuple ขณะใส่ เคอร์เนลจะสร้าง **psock** และเปลี่ยน `sk->sk_prot` ของ Socket เป็น `tcp_bpf_prots` ทำให้ `sendmsg()`/`recvmsg()` ของ Socket นั้นไหลผ่านโค้ดของ BPF
- โปรแกรม `sk_msg` ไม่ได้แนบกับ cgroup แต่แนบกับ **ตัว Map** (`BPF_SK_MSG_VERDICT`) จึงทำงานกับทุก Socket ที่อยู่ใน Map
- `bpf_msg_redirect_hash(msg, &sock_hash, &key, BPF_F_INGRESS)` — หา Socket ปลายทางด้วย `key` แล้วย้ายข้อมูลไปไว้ใน **Ingress Queue** (`BPF_F_INGRESS`) ของ Socket นั้น ให้แอปฝั่งรับอ่านได้ด้วย `recv()` ตามปกติ คืน `SK_PASS` เมื่อสำเร็จ และ `SK_DROP` เมื่อหาคีย์ไม่เจอ
- เมื่อ Application ปิด Socket เคอร์เนลจะ **ลบ Entry ออกจาก SOCKHASH อัตโนมัติ** (เห็นได้จากคอลัมน์ `live` ใน Dashboard)

### 1.4 กับดัก Byte Order ของพอร์ต (บั๊กที่แก้ในบทนี้)

UAPI ของ `struct bpf_sock_ops` และ `struct sk_msg_md` เก็บพอร์ตสองฝั่ง **ไม่เหมือนกัน**:

| ฟิลด์ | Byte Order | ค่าที่อ่านได้บน x86_64 (พอร์ต 18080 = `0x46a0`) |
|-------|-----------|-------------------------------------------|
| `local_ip4`, `remote_ip4` | Network | `0x0100007f` (127.0.0.1) |
| `local_port` | **Host** | `0x000046a0` |
| `remote_port` | **Network** (อยู่ใน 16 บิตบนบน Little-Endian) | `0xa0460000` |
| `bpf_ntohl(remote_port)` | Host | `0x000046a0` |

โค้ดเดิมเก็บคีย์ฝั่ง `sockops` เป็น `sport = bpf_ntohl(local_port)` (= `0xa0460000`) แต่ฝั่ง `sk_msg` ค้นหาด้วย `sport = remote_port >> 16` (= `0x0000a046`) ค่าต่างกัน → ไม่มีวันเจอ และยัง **นับสถิติก่อน Redirect** ทำให้ Dashboard บอกว่า "Accelerated" ทั้งที่ทุกข้อความวิ่งผ่าน TCP Stack ปกติ

**หลักการแก้:** เลือก Encoding เดียวแล้วใช้ให้ตรงกันทั้งสองโปรแกรม — บทนี้ใช้ **Host Order** สำหรับพอร์ต (`local_port` ตรง ๆ, `bpf_ntohl(remote_port)`) และ **นับเฉพาะเมื่อ Redirect สำเร็จ** แยกจาก Fallback

### 1.5 คีย์กลับด้าน (Reverse 4-tuple)

Socket ฝั่ง Client ลงทะเบียน `{sip=C, dip=S, sport=Cp, dport=Sp}` ส่วน Socket ฝั่ง Server ลงทะเบียน `{sip=S, dip=C, sport=Sp, dport=Cp}` เมื่อ Client ส่งข้อมูล โปรแกรม `sk_msg` (ซึ่งเห็นมุมมองของ Client) ต้อง **สลับ local/remote** เพื่อหา Socket ของ Server:

```
Client sk_msg เห็น: local=C:Cp  remote=S:Sp
คีย์ที่ค้นหา      : sip=S  dip=C  sport=Sp  dport=Cp   ==  คีย์ของ Server socket
```

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `sockops.c`

```c
struct sock_key {
    __u32 sip;
    __u32 dip;
    __u32 sport;
    __u32 dport;
};
```
- **บรรทัด 24-29:** คีย์ 4-tuple ขนาด 16 ไบต์ คอมเมนต์ด้านบน (บรรทัด 12-23) ระบุ Encoding ที่ต้องใช้ให้ตรงกันทั้งสองโปรแกรม: IP เป็น Network Order, พอร์ตเป็น Host Order

```c
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_hash SEC(".maps");
```
- **บรรทัด 34-39:** SOCKHASH เก็บ "การอ้างอิง Socket" ฝั่ง Userspace อ่านค่า Value ได้เป็น Socket Cookie (`__u64`) ซึ่งเห็นได้ใน `bpftool map dump`

```c
enum {
    STAT_REDIRECT_MSGS  = 0,
    STAT_REDIRECT_BYTES = 1,
    STAT_FALLBACK_MSGS  = 2,
    STAT_FALLBACK_BYTES = 3,
    STAT_SOCKS_ADDED    = 4,
    STAT_MAX,
};
```
- **บรรทัด 44-51:** ดัชนีของ `bypass_stats` (Array 5 ช่อง) แยก "Redirect สำเร็จ" ออกจาก "Fallback" ชัดเจน ฝั่ง Go มีค่าคงที่ชุดเดียวกันใน `main.go`

```c
        struct sock_key key = {
            .sip = skops->local_ip4,
            .dip = skops->remote_ip4,
            .sport = skops->local_port,
            .dport = bpf_ntohl(skops->remote_port),
        };
        if (bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST) == 0) {
            stat_add(STAT_SOCKS_ADDED, 1);
        }
```
- **บรรทัด 82-92:** เมื่อ Connection Established (ทั้ง Active/Passive, บรรทัด 81) สร้างคีย์จากมุมมองของ Socket ตัวเอง — `local_port` เป็น Host Order อยู่แล้ว ส่วน `remote_port` ต้อง `bpf_ntohl()` จากนั้นใส่ลง SOCKHASH และนับจำนวน Socket ที่ลงทะเบียนสำเร็จ

```c
    struct sock_key key = {
        .sip = msg->remote_ip4,
        .dip = msg->local_ip4,
        .sport = bpf_ntohl(msg->remote_port),
        .dport = msg->local_port,
    };
```
- **บรรทัด 113-118:** คีย์กลับด้าน (หัวข้อ 1.5) ใช้ Encoding เดียวกับฝั่ง `sockops` ทุกประการ

```c
    long ret = bpf_msg_redirect_hash(msg, &sock_hash, &key, BPF_F_INGRESS);
    if (ret == SK_PASS) {
        stat_add(STAT_REDIRECT_MSGS, 1);
        stat_add(STAT_REDIRECT_BYTES, msg->size);
        return SK_PASS;
    }

    stat_add(STAT_FALLBACK_MSGS, 1);
    stat_add(STAT_FALLBACK_BYTES, msg->size);
    return SK_PASS;
```
- **บรรทัด 127-136:** นับสถิติ **หลัง** ทราบผล Redirect เท่านั้น ถ้าหา Peer ไม่เจอ (เช่น ปลายทางอยู่นอกเครื่อง หรือ Connection เกิดก่อนแนบโปรแกรม) ให้คืน `SK_PASS` เพื่อส่งผ่าน TCP Stack ปกติ — ห้ามคืน `SK_DROP` เพราะจะทำให้ข้อมูลหาย

### 2.2 ไฟล์ `main.go`

```go
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup/w20-sockops-lab", "Target cgroup v2 path (created if missing)")
```
- **บรรทัด 58:** ค่าเริ่มต้นเป็น cgroup ลูกเฉพาะแล็บ **ไม่ใช่** `/sys/fs/cgroup` (root) เพราะถ้าแนบที่ root ทุก TCP Socket ของเครื่อง (SSH, Docker, ฯลฯ) จะถูกเปลี่ยนเส้นทางข้อมูล บรรทัด 70-76 สร้าง cgroup ให้ถ้ายังไม่มี

```go
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.BpfSockopsHandler,
	})
```
- **บรรทัด 85-89:** แนบ `sockops` เข้ากับ cgroup ด้วย BPF Link (ถอดอัตโนมัติเมื่อ Process จบ)

```go
	attachOpts := link.RawAttachProgramOptions{
		Target:  objs.SockHash.FD(),
		Program: objs.BpfSkMsgHandler,
		Attach:  ebpf.AttachSkMsgVerdict,
	}
	if err := link.RawAttachProgram(attachOpts); err != nil {
```
- **บรรทัด 97-102:** แนบ `sk_msg` เข้ากับ **FD ของ Map** (`BPF_PROG_ATTACH` แบบดั้งเดิม เพราะ Program ชนิดนี้ไม่ได้ผูกกับ cgroup/อินเทอร์เฟซ)

```go
func countSockhashEntries(m *ebpf.Map) int {
	var key, next bpfSockKey
	n := 0
	err := m.NextKey(nil, &next)
	for err == nil {
```
- **บรรทัด 43-53:** นับ Entry ที่ยังอยู่ใน SOCKHASH ด้วย `BPF_MAP_GET_NEXT_KEY` (คอลัมน์ `live`) เปรียบเทียบกับ `Sockets:` ที่เป็นยอดสะสม ทำให้เห็นว่าเคอร์เนลลบ Socket ที่ปิดแล้วเอง

```go
	printStats := func() {
		fmt.Printf("[%s] Sockets: %-4d (live %-4d) | Redirected: ... | Fallback: ...\n", ...)
```
- **บรรทัด 117-126:** Dashboard ทุก 2 วินาที แสดง Redirect และ Fallback แยกกัน — ถ้า `Fallback` เพิ่มขึ้นขณะที่ `Redirected` ไม่ขยับ แปลว่าคีย์ไม่ตรงกันหรือ Peer ไม่ได้อยู่ใน cgroup

### 2.3 ไฟล์ `cmd/tcpbench/main.go` (เครื่องมือวัดผล)

- รัน **Server และ Client ใน Process เดียวกัน** เพื่อให้ย้ายเข้า cgroup ทีเดียวแล้วทั้งสองฝั่งถูก `sockops` จับ
- `runThroughput()`: ส่งข้อมูลสุ่มแบบ Seed คงที่ ขนาด `-bytes` ทีละ `-chunk` ไบต์ ถ้า `-verify=true` ทั้งสองฝั่งคำนวณ SHA-256 เพื่อพิสูจน์ว่าข้อมูลที่ถูก Redirect **ครบและไม่เสียหาย** (`-verify=false` สำหรับวัดความเร็วล้วน เพราะ SHA-256 กิน CPU)
- `runLatency()`: Ping-pong ข้อความ `-msg` ไบต์ จำนวน `-iters` รอบ รายงาน avg/p50/p99 ของ Round-Trip Time และตรวจว่า Echo ตรงกับที่ส่ง

### 2.4 ไฟล์ `main_test.go`

Program ชนิด `sockops`/`sk_msg` **ไม่รองรับ `BPF_PROG_TEST_RUN`** จึงทดสอบด้วยเคอร์เนลจริง:
- `TestLoadPrograms`: Smoke Test — ผ่าน Verifier และชนิด Program/Map ถูกต้อง
- `TestRedirectEndToEnd`: สร้าง cgroup ชั่วคราว `w20-gotest-<pid>` แนบทั้งสองโปรแกรม ย้าย Test Process เข้า cgroup เปิด TCP Connection บน `127.0.0.1` ส่ง 68 KiB แล้วตรวจว่า (1) SOCKHASH มี 2 Entry (2) `redirect_bytes` เท่ากับขนาดที่ส่งและ `fallback == 0` (3) ข้อมูลที่รับตรงกันทุกไบต์ จากนั้นย้าย Process กลับและลบ cgroup

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์โปรแกรมและรัน Test
```bash
cd phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass
make all     # bpf2go + build bin/sockops-accelerator และ bin/tcpbench
make test    # go test -exec sudo -v ./...
```

### ขั้นตอนที่ 2: เปิด Agent บน cgroup เฉพาะแล็บ (Terminal 1)
```bash
sudo ./bin/sockops-accelerator -cgroup /sys/fs/cgroup/w20-sockops-lab
```

### ขั้นตอนที่ 3: ย้าย Shell เข้า cgroup แล้วทดสอบด้วย `nc` (Terminal 2)
```bash
sudo bash                                            # shell ที่เป็น root
echo $$ > /sys/fs/cgroup/w20-sockops-lab/cgroup.procs  # ทุก process ลูกจะอยู่ใน cgroup นี้

nc -l 127.0.0.1 18080 &                              # server
(echo "Accelerated TCP Message via BPF SOCKHASH"; sleep 2) | nc -q 1 127.0.0.1 18080
```

### ขั้นตอนที่ 4: ตรวจสอบ SOCKHASH และตัวนับด้วย `bpftool` (ขณะ Connection ยังเปิดอยู่)
```bash
sudo bpftool map dump name sock_hash      # ต้องเห็น 2 entries (client + server)
sudo bpftool map dump name bypass_stats   # key 0 (redirect msgs) > 0, key 2 (fallback) = 0
```

### ขั้นตอนที่ 5: เปรียบเทียบประสิทธิภาพ (ใน shell ที่อยู่ใน cgroup)
```bash
# 1) ตรวจความถูกต้องของข้อมูล
./bin/tcpbench -mode throughput -bytes 268435456 -verify=true
# 2) วัดความเร็ว (รันหลายรอบ แล้วดูค่ากลาง)
./bin/tcpbench -bytes 2147483648 -verify=false -iters 20000
# 3) iperf3 (sudo apt-get install -y iperf3)
iperf3 -s -1 -4 -B 127.0.0.1 -p 15201 & sleep 0.5; iperf3 -4 -c 127.0.0.1 -p 15201 -t 3
```
จากนั้นกด `Ctrl+C` ที่ Agent (Terminal 1) แล้วรันคำสั่งชุดเดิมซ้ำใน cgroup เดิมเพื่อได้ค่า **Baseline** (ไม่มี eBPF)

### ขั้นตอนที่ 6: คืนค่าสภาพแวดล้อม
```bash
exit                                       # ออกจาก shell ที่อยู่ใน cgroup
sudo rmdir /sys/fs/cgroup/w20-sockops-lab  # ลบได้เมื่อไม่มี process เหลือใน cgroup
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), Intel Core i3-12100 (8 threads), clang 21, Go 1.26, cilium/ebpf v0.16.0

### 4.1 `make test`
```text
=== RUN   TestLoadPrograms
--- PASS: TestLoadPrograms (0.02s)
=== RUN   TestRedirectEndToEnd
    main_test.go:171: socks_added=2 redirect_msgs=1 redirect_bytes=69632 fallback_msgs=0
--- PASS: TestRedirectEndToEnd (0.03s)
PASS
ok  	ebpf-noob-to-hero/phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass	0.047s
```

### 4.2 `nc` + `bpftool` ขณะ Connection เปิดอยู่
```text
--- bpftool map dump name sock_hash (connection open) ---
key: 7f 00 00 01 7f 00 00 01  a0 46 00 00 aa 9e 00 00  value: 5b 60 00 00 00 00 00 00
key: 7f 00 00 01 7f 00 00 01  aa 9e 00 00 a0 46 00 00  value: 5c 60 00 00 00 00 00 00
Found 2 elements
--- bpftool map dump name bypass_stats ---
[{
        "key": 0,
        "value": 1
    },{
        "key": 1,
        "value": 41
    },{
        "key": 2,
        "value": 0
    },{
        "key": 3,
        "value": 0
    },{
        "key": 4,
        "value": 2
    }
]
--- server received: ---
Accelerated TCP Message via BPF SOCKHASH
```
สังเกตคีย์: `a0 46 00 00` คือ `0x000046a0` = 18080 (พอร์ต Server ใน Host Order แบบ Little-Endian) และ `aa 9e 00 00` = 40618 (พอร์ตชั่วคราวของ Client) — สองคีย์เป็นภาพสะท้อนของกันและกัน (หัวข้อ 1.5) ส่วน Value คือ Socket Cookie

### 4.3 Dashboard ของ Agent (ระหว่างขั้นตอนที่ 3-5)
```text
======================================================================
 eBPF TCP Sockops & Direct Socket-to-Socket Bypass (Cilium Mesh FastPath)
======================================================================
2026/10/28 22:01:54 [INFO] Attached BPF_PROG_TYPE_SOCK_OPS to cgroup /sys/fs/cgroup/w20-verify
2026/10/28 22:01:54 [INFO] Attached BPF_PROG_TYPE_SK_MSG verdict to BPF_MAP_TYPE_SOCKHASH
2026/10/28 22:01:54 [INFO] Socket bypass active for NEW IPv4 TCP connections inside /sys/fs/cgroup/w20-verify
2026/10/28 22:01:54 [INFO] Move a shell into it: echo $$ | sudo tee /sys/fs/cgroup/w20-verify/cgroup.procs

[22:01:56] Sockets: 2    (live 2   ) | Redirected: 1        msgs 41           B | Fallback: 0      msgs 0          B
[22:01:58] Sockets: 2    (live 0   ) | Redirected: 1        msgs 41           B | Fallback: 0      msgs 0          B
[22:02:00] Sockets: 14   (live 2   ) | Redirected: 155989   msgs 4985069609   B | Fallback: 0      msgs 0          B
[22:02:02] Sockets: 28   (live 4   ) | Redirected: 422255   msgs 18137174262  B | Fallback: 0      msgs 0          B
[22:02:04] Sockets: 28   (live 4   ) | Redirected: 637890   msgs 46400884982  B | Fallback: 0      msgs 0          B
[22:02:06] Sockets: 28   (live 4   ) | Redirected: 850553   msgs 74275049718  B | Fallback: 0      msgs 0          B
[22:02:08] Sockets: 28   (live 0   ) | Redirected: 894073   msgs 79978255244  B | Fallback: 0      msgs 0          B

[INFO] Detaching sockops and sk_msg hooks...
[22:02:09] Sockets: 28   (live 0   ) | Redirected: 894073   msgs 79978255244  B | Fallback: 0      msgs 0          B
```
(`live 4` ระหว่าง iperf3 = Control Connection + Data Connection อย่างละ 2 Socket)

### 4.4 พิสูจน์ด้วย `tcpdump -i lo`: Payload ไม่ผ่าน Loopback อีกต่อไป
ส่ง `hello-sockmap` (14 ไบต์) ด้วย `nc` ใน cgroup เดียวกัน แล้วดักที่ `lo` (`tcpdump -i lo -nn -q "tcp port 18081"`):
```text
== baseline ==
IP 127.0.0.1.51392 > 127.0.0.1.18081: tcp 0
IP 127.0.0.1.18081 > 127.0.0.1.51392: tcp 0
IP 127.0.0.1.51392 > 127.0.0.1.18081: tcp 0
IP 127.0.0.1.51392 > 127.0.0.1.18081: tcp 14
IP 127.0.0.1.18081 > 127.0.0.1.51392: tcp 0
IP 127.0.0.1.51392 > 127.0.0.1.18081: tcp 0
IP 127.0.0.1.18081 > 127.0.0.1.51392: tcp 0
IP 127.0.0.1.51392 > 127.0.0.1.18081: tcp 0

== accelerated ==
IP 127.0.0.1.42998 > 127.0.0.1.18081: tcp 0
IP 127.0.0.1.18081 > 127.0.0.1.42998: tcp 0
IP 127.0.0.1.42998 > 127.0.0.1.18081: tcp 0
IP 127.0.0.1.42998 > 127.0.0.1.18081: tcp 0
IP 127.0.0.1.18081 > 127.0.0.1.42998: tcp 0
IP 127.0.0.1.42998 > 127.0.0.1.18081: tcp 0
```
เมื่อเปิด Agent Segment `tcp 14` (Payload) และ ACK ของมันหายไป เหลือเพียง Handshake และ FIN — **เครื่องมือที่ดักบน `lo` (tcpdump, Netfilter) จะมองไม่เห็นข้อมูลที่ถูก Redirect**

### 4.5 ผลการวัดประสิทธิภาพ (Baseline vs Accelerated)

ทุกค่ารันใน cgroup เดียวกัน (`w20-verify`) บนเครื่องเดียวกัน ต่างกันแค่มี/ไม่มี Agent:

```text
=== tcpbench integrity (accelerated) ===
[throughput] sent=268435456 recv=268435456 chunk=65536 time=153ms rate=14.07 Gbit/s integrity(sha256)=true

=== tcpbench perf (accelerated) ===
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=280ms rate=61.34 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=3.3us p50=3.3us p99=4.9us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=271ms rate=63.40 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=4.0us p50=3.3us p99=5.7us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=253ms rate=67.78 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=3.7us p50=3.3us p99=14.5us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=235ms rate=73.13 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=3.4us p50=3.3us p99=5.4us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=259ms rate=66.34 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=3.4us p50=3.3us p99=5.3us

=== baseline (same cgroup, NO eBPF attached) ===
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=377ms rate=45.61 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=7.0us p50=6.7us p99=17.3us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=317ms rate=54.22 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=6.9us p50=6.7us p99=10.1us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=343ms rate=50.10 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=6.8us p50=6.7us p99=9.4us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=276ms rate=62.25 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=6.8us p50=6.7us p99=10.1us
[throughput] sent=2147483648 recv=2147483648 chunk=65536 time=334ms rate=51.48 Gbit/s integrity(sha256)=skipped
[latency]    iters=20000 msg=64B avg=7.2us p50=6.7us p99=10.2us

=== iperf3 -t 3, 1 stream, 3 รอบ (receiver) ===
baseline   : 66.1 / 65.8 / 66.8 Gbits/sec
accelerated: 114  / 110  / 105  Gbits/sec
```

สรุป (ค่ากลาง/Median):

| ตัวชี้วัด | Baseline (TCP ปกติ) | SOCKHASH Redirect | ต่าง |
|-----------|--------------------|-------------------|------|
| tcpbench throughput (64 KiB writes, 2 GiB × 5 รอบ) | 51.5 Gbit/s (45.6–62.3) | 66.3 Gbit/s (61.3–73.1) | ≈ +29% |
| iperf3 throughput (1 stream, 3 s × 3 รอบ) | 66.1 Gbit/s | 110 Gbit/s | ≈ +66% |
| Latency RTT 64 B p50 (20,000 รอบ × 5) | 6.7 µs | 3.3 µs | ≈ −50% |

> [!IMPORTANT]
> ตัวเลขเหล่านี้มาจาก **เครื่องเดียว, Loopback, Single Stream, CPU Frequency Scaling ไม่ได้ล็อก** มีความแปรปรวนสูง (ดูช่วง min–max) ใช้เพื่อเห็น **แนวโน้ม** เท่านั้น ไม่ใช่ตัวเลขที่ใช้อ้างอิงได้กับทุกระบบ ผลจริงขึ้นกับ CPU, ขนาดข้อความ, จำนวน Connection และรุ่นเคอร์เนล

---

## 5. ข้อจำกัด (Limitations)

- **IPv4 เท่านั้น** (`family != AF_INET` ถูกข้าม) — IPv6 ต้องเพิ่ม `local_ip6`/`remote_ip6` ในคีย์
- **ทั้งสองปลายต้องอยู่บนเครื่องเดียวกันและอยู่ใน cgroup ที่แนบโปรแกรม** ถ้าปลายทางอยู่นอกเครื่อง จะเกิด Fallback (`SK_PASS`) ทุกข้อความ แต่ Socket ก็ยังถูกใส่ใน SOCKHASH และจ่าย Overhead ของ psock อยู่ดี
- **เฉพาะ Connection ที่ Established หลังแนบโปรแกรม** — Connection เดิมไม่ถูกเร่ง
- **ข้ามเครื่องมือ Observability/Policy ระดับ Packet:** tcpdump, Netfilter/iptables, tc บน `lo` มองไม่เห็น Payload ที่ถูก Redirect (หัวข้อ 4.4) — นโยบายความปลอดภัยที่พึ่งพาสิ่งเหล่านี้จะถูกข้ามไป
- **ไม่ใช่ Zero-Copy** (หัวข้อ 1.1) — ยังมี Copy 2 ครั้งเหมือน TCP ปกติ
- **การถอด Agent:** เมื่อ Agent ปิด Map ถูกทำลาย Socket จะกลับไปใช้ TCP ปกติ; ไม่ได้ Pin Map ไว้ใน bpffs จึงไม่ได้ทำงานต่อหลัง Agent ตาย
- **ประวัติในระบบจริง:** Cilium เคยมีฟีเจอร์ sockops/sockmap acceleration (`sockops-enable`) แต่ถูกเลิกใช้/ถอดออกในรุ่นหลัง ๆ — โปรดตรวจสอบเอกสารและ Release Notes ของ Cilium รุ่นที่ใช้ก่อนอ้างอิง

---

## 6. Milestone Checklist

- [x] อธิบายเส้นทางข้อมูล Loopback TCP ปกติ เทียบกับ SOCKHASH Redirect และระบุได้ว่าส่วนใดถูกลัดข้าม (และส่วนใดไม่ถูกลัด)
- [x] แนบ `BPF_PROG_TYPE_SOCK_OPS` กับ cgroup v2 เฉพาะแล็บ และเข้าใจ `ACTIVE/PASSIVE_ESTABLISHED_CB`
- [x] แนบ `BPF_PROG_TYPE_SK_MSG` กับ SOCKHASH และใช้ `bpf_msg_redirect_hash(..., BPF_F_INGRESS)`
- [x] เข้าใจกับดัก Byte Order ของ `local_port` (Host) / `remote_port` (Network) และออกแบบคีย์ให้ตรงกันทั้งสองฝั่ง
- [x] นับสถิติเฉพาะเมื่อ Redirect สำเร็จ และแยกตัวนับ Fallback
- [x] พิสูจน์ด้วย `bpftool`, `tcpdump` และ Test อัตโนมัติว่า Redirect เกิดขึ้นจริงและข้อมูลครบถ้วน
- [x] วัด Throughput/Latency แบบมี Baseline และรายงานตัวเลขพร้อมข้อจำกัด

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **ทำซ้ำบั๊กเดิม:** เปลี่ยน `.sport = skops->local_port` กลับเป็น `bpf_ntohl(skops->local_port)` แล้ว `make all && make test`
   - *Deliverable:* ผลลัพธ์ `make test` และ Dashboard ขณะส่งข้อความด้วย `nc`
   - *Verification:* `TestRedirectEndToEnd` ต้อง FAIL ด้วย `fallback msgs = N, want 0` และ Dashboard แสดง `Redirected: 0` แต่ `Fallback` เพิ่มขึ้น (จากนั้นแก้กลับ)
2. **Connection ข้าม cgroup:** รัน `nc -l` ใน cgroup ของแล็บ แต่รัน Client จาก Shell ที่ **ไม่ได้** อยู่ใน cgroup
   - *Deliverable:* `bpftool map dump name sock_hash` และบรรทัด Dashboard
   - *Verification:* SOCKHASH มีเพียง 1 Entry (ฝั่ง Server) และข้อความจาก Client ไม่ถูกนับเป็น Redirect

### ระดับปานกลาง
1. **Per-socket Statistics:** เปลี่ยน `bypass_stats` เป็น `BPF_MAP_TYPE_PERCPU_ARRAY` (ลด Cache-line Bouncing ตาม Week 07) และรวมค่าใน Go
   - *Deliverable:* โค้ดที่แก้ + ผล tcpbench 5 รอบ
   - *Verification:* `make test` ผ่าน, Dashboard ยังแสดงยอดถูกต้อง และเปรียบเทียบ Throughput กับตาราง 4.5
2. **ผลของขนาดข้อความ:** รัน `tcpbench -chunk` ที่ 64 B, 1 KiB, 16 KiB, 64 KiB ทั้ง Baseline และ Accelerated
   - *Deliverable:* ตารางหรือกราฟ Throughput เทียบขนาด Chunk
   - *Verification:* แต่ละจุดมีอย่างน้อย 3 รอบ พร้อมค่า min/median/max และอธิบายว่าขนาดใดได้ประโยชน์มากที่สุดเพราะอะไร

### ระดับท้าทาย
1. **รองรับ IPv6:** เพิ่ม Map/คีย์สำหรับ `AF_INET6` (`local_ip6[4]`, `remote_ip6[4]`) ทั้งสองโปรแกรม
   - *Deliverable:* โค้ด + Test ใหม่ `TestRedirectEndToEndIPv6` ที่เชื่อมต่อ `[::1]`
   - *Verification:* Test ใหม่ผ่าน และ `redirect_bytes` เท่ากับขนาดข้อมูลที่ส่ง
2. **Policy-aware Redirect:** เพิ่ม `BPF_MAP_TYPE_HASH` เก็บพอร์ตที่ "อนุญาตให้เร่ง" ให้ `sk_msg` Redirect เฉพาะพอร์ตใน Map (ที่เหลือ Fallback) และให้ Agent รับ `-ports 18080,15201`
   - *Deliverable:* โค้ด + Dashboard ที่รัน nc บนพอร์ตที่อนุญาตและไม่อนุญาตพร้อมกัน
   - *Verification:* พอร์ตที่อนุญาตเพิ่ม `Redirected`, พอร์ตอื่นเพิ่ม `Fallback`, และ `tcpdump -i lo` เห็น Payload เฉพาะของพอร์ตที่ไม่อนุญาต
