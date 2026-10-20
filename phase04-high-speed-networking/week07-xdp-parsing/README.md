# Week 07: High-Speed XDP Packet Parsing & Firewall

ยินดีต้อนรับสู่สัปดาห์ที่ 7 ของหลักสูตร **eBPF: Zero-to-Hero** และเป็นสัปดาห์เริ่มต้นของ **Phase 4: High-Speed Networking** ในบทนี้เราจะก้าวเข้าสู่เทคโนโลยีเครือข่ายความเร็วสูงระดับปฏิวัติวงการ นั่นคือ **XDP (eXpress Data Path)** ซึ่งช่วยให้ระบบปฏิบัติการ Linux สามารถประมวลผล ดักจับ และบล็อกแพ็กเก็ตเครือข่ายได้ด้วยความเร็วระดับหลายสิบล้านแพ็กเก็ตต่อวินาที (Wire-speed 10M-40M+ PPS) ก่อนที่แพ็กเก็ตจะถูกจัดสรรหน่วยความจำ `sk_buff` ในเคอร์เนล

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 สถาปัตยกรรมของ XDP เทียบกับ Linux Network Stack เดิม

ในระบบ Linux ดั้งเดิม ทุกแพ็กเก็ตที่มาถึงการ์ดแลน (NIC) จะต้องผ่านกระบวนการอันซับซ้อน:
1. การ์ดแลนยิงฮาร์ดแวร์ Interrupt (IRQ) เข้า CPU
2. เคอร์เนลขับเคลื่อน Network Subsystem (NAPI polling)
3. เคอร์เนลสร้างและจองโครงสร้างข้อมูลขนาดใหญ่ชื่อ **`struct sk_buff`** (ขนาดหลายร้อยไบต์ต่อแพ็กเก็ต)
4. แพ็กเก็ตเดินทางผ่าน Netfilter / IP Tables, Routing Decision, Connection Tracking (Conntrack), และ Socket Buffers

กระบวนการนี้สร้าง Overhead มหาศาล เมื่อเจอกับการโจมตีแบบ Distributed Denial of Service (DDoS) เช่น SYN Flood หรือ UDP Flood ทรัพยากรซีพียูจะหมดไปกับการ Alloc/Free `sk_buff` จนระบบล่ม

**XDP (eXpress Data Path)** ปฏิวัติสถาปัตยกรรมนี้ โดยเปิดโอกาสให้เราประมวลผล eBPF Bytecode ได้ตั้งแต่ในระดับไดรเวอร์ของการ์ดแลน (NIC Driver RX ring buffer) ก่อนที่เคอร์เนลจะจัดสรร `sk_buff`:

```
+-----------------------------------------------------------------------------------------+
|                                    PHYSICAL NETWORK                                     |
|                                [ Incoming Packet Stream ]                               |
+--------------------------------------------|--------------------------------------------+
                                             v
+-----------------------------------------------------------------------------------------+
|                               NETWORK INTERFACE CARD (NIC)                              |
|                          DMA Transfer to Host RX Ring Buffer                            |
+--------------------------------------------|--------------------------------------------+
                                             v
+-----------------------------------------------------------------------------------------+
|                                  NIC DRIVER (RX Path)                                   |
|                                                                                         |
|       +------------------------------------------------------------------------+        |
|       |                        eBPF XDP Hook (Driver Level)                    |        |
|       |                                                                        |        |
|       |  ctx->data                                               ctx->data_end |        |
|       |     |                                                          |       |        |
|       |     v                                                          v       |        |
|       |  [ Ethernet Header ] [ IPv4 Header ] [ L4 TCP/UDP ] [ Payload ]        |        |
|       |                                                                        |        |
|       |  - Verifier Bounds Checking: ((void *)(hdr + 1) > data_end)            |        |
|       |  - Update Per-CPU Protocol Counter (Lock-Free)                         |        |
|       |  - Lookup Source IP in BPF_MAP_TYPE_HASH (blocked_ips)                 |        |
|       +-----------------------------------|------------------------------------+        |
|                                           |                                             |
|                     +---------------------+---------------------+                       |
|                     | Match Blocklist                           | Clean Traffic         |
|                     v                                           v                       |
|               [ XDP_DROP ]                                [ XDP_PASS ]                  |
|          (Zero Memory Overhead!)                                |                       |
|         - Instantly drops packet                                v                       |
|         - Increments drop counter              +---------------------------------+      |
|         - Packet never touches OS              |   Allocate struct sk_buff       |      |
|                                                |   Enter Linux Network Stack     |      |
|                                                |   (Netfilter, Routing, Sockets) |      |
|                                                +---------------------------------+      |
+-----------------------------------------------------------------------------------------+
```

---

### 1.2 โหมดการทำงานของ XDP (XDP Execution Modes)

XDP สามารถทำงานได้ใน 3 โหมด ขึ้นอยู่กับฮาร์ดแวร์และไดรเวอร์:
1. **Offloaded XDP:** โค้ด eBPF ถูก JIT-compile และดาวน์โหลดเข้าไปประมวลผลบนหน่วยประมวลผลของการ์ดแลนอัจฉริยะ (SmartNIC เช่น Netronome, Mellanox BlueField) โดยตรง ซีพียูของเครื่องหลักมี Overhead เป็นศูนย์
2. **Native / Driver XDP:** โปรแกรมรันในไดรเวอร์ของการ์ดแลน (เช่น `ixgbe`, `i40e`, `mlx5`, `virtio_net`) ก่อนสร้าง `sk_buff` ให้ประสิทธิภาพสูงสุดสำหรับ Server ทั่วไป
3. **Generic / SKB XDP:** โหมดจำลองที่รันหลังจากสร้าง `sk_buff` ขึ้นมาแล้ว ออกแบบมาสำหรับการทดสอบ การเรียนรู้ หรือใช้กับการ์ดแลนที่ไม่มีไดรเวอร์รองรับ Native XDP

---

### 1.3 กฎเหล็กของ eBPF Verifier: Pointer Bounds Checking

แพ็กเก็ตเครือข่ายเป็นข้อมูลแบบไดนามิกที่มีขนาดไม่แน่นอน การเข้าถึงหน่วยความจำในแพ็กเก็ตโดยตรง (`ctx->data`) จึงมีความเสี่ยงสูงสุดต่อบั๊ก Memory Corruption

eBPF Verifier จะใช้ขั้นตอนวิธี **Abstract Interpretation & Range Tracking** ในการตรวจสอบทุกพอยน์เตอร์ หากเราไม่พิสูจน์ให้ Verifier เห็นอย่างชัดเจนว่าการเข้าถึงพอยน์เตอร์จะไม่ล้นเกิน `ctx->data_end` โปรแกรมจะถูกปฏิเสธทันที

```c
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

// 1. ตรวจสอบขอบเขต Header L2 (Ethernet)
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS; // ปลอดภัย: บ่งชี้ว่า eth มีพื้นที่ในเมมโมรีอย่างน้อย sizeof(struct ethhdr)

// 2. ตรวจสอบขอบเขต Header L3 (IPv4)
struct iphdr *iph = (void *)(eth + 1);
if ((void *)(iph + 1) > data_end)
    return XDP_PASS;

// 3. ตรวจสอบขนาด Dynamic IP Header (IHL field)
__u32 ip_hdr_len = iph->ihl * 4;
if (ip_hdr_len < sizeof(struct iphdr) || (void *)iph + ip_hdr_len > data_end)
    return XDP_PASS;
```

> [!IMPORTANT]
> สัญลักษณ์ `(void *)(eth + 1)` หมายถึงการนำพอยน์เตอร์ `eth` เลื่อนไปข้างหน้าเท่ากับขนาดของ `sizeof(struct ethhdr)` (14 ไบต์) หากพอยน์เตอร์ปลายทางเกิน `data_end` หมายความว่าแพ็กเก็ตสั้นเกินไปหรือถูกตัดทอน (Malformed / Truncated packet) การคืนค่า `XDP_PASS` จึงเป็นการส่งต่อให้เคอร์เนลจัดการต่อไปโดยไม่เกิดข้อผิดพลาด

---

### 1.4 การจัดการความต่างของ Endianness (Byte Order)

ในระบบเครือข่าย มาตรฐานการส่งข้อมูลบนสายเคเบิลคือ **Big-Endian (Network Byte Order)** ในขณะที่ซีพียู x86_64 และ ARM64 ส่วนใหญ่ทำงานด้วย **Little-Endian (Host Byte Order)**

- ในระดับโปรโตคอลอีเธอร์เน็ต: `eth->h_proto` จะมีค่า `0x0800` (IPv4) แต่เมื่อถูกเก็บในเมมโมรี Big-Endian จะมีค่าเป็น `0x0008` ในมุมมอง Host Little-Endian เราจึงต้องใช้ `bpf_htons(ETH_P_IP)` ในการเปรียบเทียบ
- ในระดับ IP Address: ค่า `iph->saddr` ใน C ถูกอ่านเข้ามาเป็น 4 ไบต์เรียงกัน ในฝั่งภาษา Go เราจึงใช้ `binary.LittleEndian.Uint32(ip.To4())` เพื่อให้บิตแมปในหน่วยความจำตรงกันเป๊ะกับคีย์ที่อยู่ใน BPF Hash Map

---

### 1.5 ข้อดีของ BPF_MAP_TYPE_PERCPU_ARRAY

การนับสถิติความถี่ของแพ็กเก็ต (Traffic Counters) ในระบบเน็ตเวิร์ก 10Gbps/40Gbps จะมีแพ็กเก็ตเข้ามาพร้อมกันหลายสิบล้านแพ็กเก็ตต่อวินาที หากใช้ Array Map ธรรมดาแล้วใช้ `__sync_fetch_and_add` จะเกิดปัญหา **Cache-line Bouncing** ระหว่าง CPU Cores อย่างรุนแรง ทำให้ประสิทธิภาพระบบลดฮวบ

`BPF_MAP_TYPE_PERCPU_ARRAY` แก้ปัญหานี้โดยสร้างสำเนาของ Map แยกเฉพาะสำหรับแต่ละ CPU Core:
- eBPF โปรแกรมอ่านเขียนเฉพาะสล็อตของ CPU ตัวเอง โดยไม่ต้องล็อกและไม่ต้องใช้คำสั่ง Atomic
- ฝั่ง Userspace (Go) ทำการอ่านค่าจากทุก CPU พร้อมกันมาประมวลผลบวกผลรวม (Sum aggregation)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `xdp_firewall.c`

```c
struct drop_stats {
    __u64 dropped_packets;
    __u64 dropped_bytes;
};
```
- **บรรทัด 50-53:** โครงสร้างข้อมูลเก็บสถิติจำนวนแพ็กเก็ตและจำนวนไบต์ทั้งหมดที่ถูกดรอปสำหรับแต่ละไอพี

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct drop_stats);
} blocked_ips SEC(".maps");
```
- **บรรทัด 61-66:** แมปเก็บไอพีที่ต้องการบล็อก สามารถจุได้สูงสุด 10,240 ไอพี และอัปเดตแบบ Dynamic จาก Userspace ได้ตลอดเวลา

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} proto_counters SEC(".maps");
```
- **บรรทัด 74-79:** แมปเก็บตัวนับสถิติโปรโตคอล (เช่น ICMP=1, TCP=6, UDP=17) แยกตาม CPU Core เพื่อลด Latency

```c
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
```
- **บรรทัด 85-90:**
  - กำหนด ELF Section เป็น `"xdp"`
  - สกัดพอยน์เตอร์จุดเริ่มต้น `ctx->data` และจุดสิ้นสุด `ctx->data_end` ของแพ็กเก็ต

```c
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
```
- **บรรทัด 95-103:** ตรวจสอบความปลอดภัยของ Ethernet Header หากแพ็กเก็ตสั้นเกินไปหรือไม่ได้เป็น IPv4 ให้ปล่อยผ่านไปยัง Linux Stack ทันที

```c
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)iph + ip_hdr_len > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 108-117:** เลื่อนพอยน์เตอร์ไปที่ตำแหน่งเริ่มต้นของ IPv4 Header ตรวจสอบขอบเขต และคำนวณความยาวของ IP Options ผ่านฟิลด์ `ihl`

```c
    __u32 proto = iph->protocol;
    if (proto < 256) {
        __u64 *proto_cnt = bpf_map_lookup_elem(&proto_counters, &proto);
        if (proto_cnt) {
            *proto_cnt += 1;
        }
    }
```
- **บรรทัด 122-128:** บันทึกตัวนับของโปรโตคอล L3/L4 ลงใน Per-CPU Array โดยไม่ต้องผ่านคำสั่ง Atomic

```c
    void *l4 = (void *)iph + ip_hdr_len;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) return XDP_PASS;
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = l4;
        if ((void *)(icmph + 1) > data_end) return XDP_PASS;
    }
```
- **บรรทัด 133-146:** ทำการ Bounds Check กับ Transport Layer Header เพื่อให้มั่นใจว่าโครงสร้างแพ็กเก็ตสมบูรณ์

```c
    __u32 saddr = iph->saddr;
    struct drop_stats *stats = bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (stats) {
        __sync_fetch_and_add(&stats->dropped_packets, 1);
        __u64 pkt_len = (__u64)((char *)data_end - (char *)data);
        __sync_fetch_and_add(&stats->dropped_bytes, pkt_len);
        return XDP_DROP;
    }

    return XDP_PASS;
```
- **บรรทัด 151-163:** ตรวจสอบว่า Source IP อยู่ใน Blacklist หรือไม่ หากตรงกัน ให้บันทึกสถิติและสั่ง `XDP_DROP` เพื่อทำลายแพ็กเก็ตทิ้งทันทีที่ระดับ Driver!

---

### 2.2 ไฟล์ `main.go`

```go
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewallProg,
		Interface: iface.Index,
	})
```
- **บรรทัด 45-51:** แนบโปรแกรม XDP เข้ากับการ์ดแลนที่ระบุ (Cilium ebpf จะเลือกใช้ Native Driver Mode หากไดรเวอร์รองรับ และถอยไป Generic Mode อัตโนมัติหากไม่รองรับ)

```go
	ipKey := binary.LittleEndian.Uint32(parsedIP)
	initialStats := bpfDropStats{
		DroppedPackets: 0,
		DroppedBytes:   0,
	}
	objs.BlockedIps.Put(&ipKey, &initialStats)
```
- **บรรทัด 66-74:** แปลงสตริงไอพีให้อยู่ในรูป `uint32` แล้วบันทึกลงใน Map `blocked_ips` ก่อนเริ่มการดักจับ

```go
	for _, p := range protocols {
		var perCpuCounts []uint64 = make([]uint64, numCPUs)
		objs.ProtoCounters.Lookup(&p.Num, &perCpuCounts)
		var totalPkts uint64
		for _, cnt := range perCpuCounts {
			totalPkts += cnt
		}
		fmt.Printf("  %-10s  %-12d  %-16d\n", p.Name, p.Num, totalPkts)
	}
```
- **บรรทัด 132-144:** Userspace ควบรวมค่าจากทุก CPU Core โดยดึง slice ของ uint64 ที่มีขนาดเท่ากับจำนวนซีพียู แล้วหาผลรวมเพื่อแสดงผลบน Dashboard

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์โปรแกรม
```bash
cd phase04-high-speed-networking/week07-xdp-parsing
make generate
make build
```

### ขั้นตอนที่ 2: สร้าง Network Namespace สำหรับทดสอบ (Lab Environment)
เพื่อจำลองการส่งข้อมูลเสมือนจริงระหว่าง Client และ Server โดยไม่รบกวนเน็ตเวิร์กจริงของเครื่องโฮสต์:
```bash
# สร้าง Namespace ns1 (Client) และ ns2 (Server Firewall)
sudo ip netns add ns1
sudo ip netns add ns2

# สร้างคู่สายเสมือน (veth pair)
sudo ip link add veth-c type veth peer name veth-s

# ย้ายอินเทอร์เฟซเข้าสู่ Namespace
sudo ip link set veth-c netns ns1
sudo ip link set veth-s netns ns2

# กำหนดไอพี
sudo ip netns exec ns1 ip addr add 10.10.1.10/24 dev veth-c
sudo ip netns exec ns2 ip addr add 10.10.1.20/24 dev veth-s

# เปิดใช้งาน Interface
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns1 ip link set veth-c up
sudo ip netns exec ns2 ip link set lo up
sudo ip netns exec ns2 ip link set veth-s up
```

### ขั้นตอนที่ 3: สั่งรัน XDP Firewall ภายใน Namespace Server
เราจะสั่งให้ Firewall ทำงานบนการ์ด `veth-s` ภายใน `ns2` และสั่งบล็อกไอพี `10.10.1.10`:
```bash
sudo ip netns exec ns2 ./bin/xdp-firewall -iface veth-s -block-ip 10.10.1.10
```

### ขั้นตอนที่ 4: ยิงทราฟฟิกทดสอบจาก Client (`ns1`)
เปิดเทอร์มินัลอีกหน้าต่างหนึ่ง แล้วทดสอบส่ง Ping:
```bash
# ยิง Ping 5 ครั้ง (ทราฟฟิกนี้จะถูกบล็อก 100%!)
sudo ip netns exec ns1 ping -c 5 -W 1 10.10.1.20
```

**ผลลัพธ์ในหน้าต่าง Client:**
```text
PING 10.10.1.20 (10.10.1.20) 56(84) bytes of data.
--- 10.10.1.20 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4088ms
```

**ผลลัพธ์บน Dashboard ของ XDP Firewall:**
```text
=================================================================================
 eBPF XDP Live Monitor | Interface: veth-s     | Host CPUs: 4 | Time: 21:30:15
=================================================================================
 [ Protocol Activity (Per-CPU Array Sum) ]
  PROTOCOL    CODE          TOTAL PACKETS   
  ---------------------------------------------
  ICMP        1             5               
  TCP         6             0               
  UDP         17            0               

 [ Blocked IP Drop Telemetry (BPF_MAP_TYPE_HASH) ]
  IP ADDRESS          DROPPED PACKETS   DROPPED BYTES   
  -------------------------------------------------------------
  10.10.1.10          5                 420             
=================================================================================
 Press Ctrl+C to detach XDP program and exit.
```

### ขั้นตอนที่ 5: ตรวจสอบด้วย `ip link` และ `bpftool`
```bash
# ตรวจสอบว่าโปรแกรม XDP แนบอยู่บน Interface
sudo ip netns exec ns2 ip link show veth-s

# Dump แมปสถิติด้วย bpftool
sudo ip netns exec ns2 bpftool map dump name blocked_ips
```

### ขั้นตอนที่ 6: คืนค่าและล้างสภาพแวดล้อมทดสอบ
```bash
sudo ip netns del ns1
sudo ip netns del ns2
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 24.04 LTS (`Linux ebpf-lab 6.8.0-142-generic #142-Ubuntu SMP PREEMPT_DYNAMIC aarch64`)

### 4.1 ผลลัพธ์การคอมไพล์และรัน XDP Firewall (`-iface veth-s -block-ip 10.10.1.10`)
```text
===> Generating Go bindings from xdp_firewall.c via bpf2go...
go generate ./...
Compiled /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfel.o
Stripped /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfel.o
Wrote /Volumes/ExDisk/Google Drive Ksu/KSU/Git/EBPF/phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfel.go
===> Building userspace binary bin/xdp-firewall...
mkdir -p bin
go build -v -o bin/xdp-firewall .

--- CLIENT PING TEST (sudo ip netns exec ns1 ping -c 5 -W 1 10.10.1.20) ---
PING 10.10.1.20 (10.10.1.20) 56(84) bytes of data.

--- 10.10.1.20 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 829ms

--- IP LINK SHOW (sudo ip netns exec ns2 ip link show veth-s) ---
34: veth-s@if35: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 96:c6:7f:b5:0b:78 brd ff:ff:ff:ff:ff:ff link-netns ns1
    prog/xdp id 74 name xdp_firewall_pr tag 56de7376c05d858a jited 

--- BPFTOOL MAP DUMP (sudo ip netns exec ns2 bpftool map dump name blocked_ips) ---
[{
        "key": 167840266,
        "value": {
            "dropped_packets": 5,
            "dropped_bytes": 490
        }
    }
]

=================================================================================
 eBPF XDP Live Monitor | Interface: veth-s     | Host CPUs: 4 | Time: 13:42:42
=================================================================================
 [ Protocol Activity (Per-CPU Array Sum) ]
  PROTOCOL    CODE          TOTAL PACKETS   
  ---------------------------------------------
  ICMP        1             5               
  TCP         6             0               
  UDP         17            0               

 [ Blocked IP Drop Telemetry (BPF_MAP_TYPE_HASH) ]
  IP ADDRESS          DROPPED PACKETS   DROPPED BYTES   
  -------------------------------------------------------------
  10.10.1.10          5                 490             
=================================================================================
 Press Ctrl+C to detach XDP program and exit.

Received signal 'terminated'. Detaching XDP link and exiting cleanly...
```

---

## 5. Milestone Checklist

- [x] เข้าใจสถาปัตยกรรมระดับฮาร์ดแวร์และไดรเวอร์ของ XDP เทียบกับ Netfilter/iptables
- [x] แยกความแตกต่างของ 3 โหมดใน XDP (Offloaded, Native Driver, Generic SKB)
- [x] เข้าใจและปฏิบัติตามกฎ Abstract Interpretation ของ eBPF Verifier สำหรับการ Bounds Check พอยน์เตอร์
- [x] ปาร์ส Ethernet (L2), IPv4 (L3), และ Transport Headers (L4: TCP/UDP/ICMP) ได้อย่างปลอดภัย
- [x] จัดการความต่างของสถาปัตยกรรม Big-Endian (Network) และ Little-Endian (Host)
- [x] ใช้งาน `BPF_MAP_TYPE_PERCPU_ARRAY` เพื่อลดปัญหา Cache Bouncing ในระดับซีพียู
- [x] พัฒนา Firewall คัดกรองและ Drop แพ็กเก็ตที่ระดับไดรเวอร์ด้วย `XDP_DROP`
- [x] สร้าง Realtime Dashboard ใน Userspace ด้วย Go และทดสอบผ่าน Network Namespaces
