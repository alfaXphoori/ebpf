# Week 07: High-Speed XDP Packet Parsing & Firewall

ยินดีต้อนรับสู่สัปดาห์ที่ 7 ของหลักสูตร **eBPF: Zero-to-Hero** และเป็นสัปดาห์เริ่มต้นของ **Phase 4: High-Speed Networking** ในบทนี้เราจะก้าวเข้าสู่เทคโนโลยีเครือข่ายความเร็วสูงระดับปฏิวัติวงการ นั่นคือ **XDP (eXpress Data Path)** ซึ่งช่วยให้ระบบปฏิบัติการ Linux สามารถประมวลผล ดักจับ และบล็อกแพ็กเก็ตเครือข่ายได้ตั้งแต่ระดับไดรเวอร์ ก่อนที่แพ็กเก็ตจะถูกจัดสรรหน่วยความจำ `sk_buff` ในเคอร์เนล จึงเร็วกว่าการกรองด้วย iptables/nftables อย่างมีนัยสำคัญ (งานวิจัยต้นฉบับของ XDP โดย Høiland-Jørgensen et al., CoNEXT 2018 รายงานอัตราการ drop ระดับหลายสิบล้านแพ็กเก็ตต่อวินาทีบนการ์ดแลนที่รองรับ Native XDP ในชุดทดสอบของผู้วิจัย — ตัวเลขจริงขึ้นกับ NIC, driver และ CPU ของแต่ละเครื่อง ควรวัดเองก่อนนำไปอ้างอิง)

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
- ในระดับ IP Address: ค่า `iph->saddr` ใน C ถูกอ่านเข้ามาเป็น 4 ไบต์เรียงกันตามลำดับบนสาย (Network Byte Order) โดยไม่มีการแปลง ในฝั่งภาษา Go เราจึงใช้ `binary.NativeEndian.Uint32(ip.To4())` (ฟังก์ชัน `ipKey()` ใน `main.go`) เพื่อให้ "ไบต์ในหน่วยความจำ" ของคีย์ตรงกันเป๊ะกับ `iph->saddr` บนเครื่อง Little-Endian (x86_64/ARM64) ผลลัพธ์จะเท่ากับ `binary.LittleEndian.Uint32(...)` แต่ `NativeEndian` ยังถูกต้องแม้รันบนสถาปัตยกรรม Big-Endian (เช่น s390x) ด้วย
- ตัวอย่าง: `10.10.1.10` = ไบต์ `0a 0a 01 0a` → คีย์ `0x0a010a0a` (167840266) ซึ่งตรงกับที่ `bpftool map dump` แสดงในหัวข้อที่ 4

---

### 1.5 ข้อดีของ BPF_MAP_TYPE_PERCPU_ARRAY

การนับสถิติความถี่ของแพ็กเก็ต (Traffic Counters) ในระบบเน็ตเวิร์กความเร็วสูง แพ็กเก็ตจะถูกประมวลผลพร้อมกันบนหลาย CPU Core (แต่ละ RX queue มักผูกกับคอร์ของตัวเอง) หากทุกคอร์ใช้ `__sync_fetch_and_add` กับตัวนับตัวเดียวกันใน Array Map ธรรมดา จะเกิดปัญหา **Cache-line Bouncing** (cache line ของตัวนับถูกส่งไปมาระหว่างคอร์) ซึ่งยิ่งแพ็กเก็ตเยอะ ยิ่งเป็นคอขวด

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
- **บรรทัด 56-59:** โครงสร้างข้อมูลเก็บสถิติจำนวนแพ็กเก็ตและจำนวนไบต์ทั้งหมดที่ถูกดรอปสำหรับแต่ละไอพี (นับขนาดทั้งเฟรมรวม Ethernet Header เช่น ICMP Echo 84 ไบต์ + 14 = 98 ไบต์)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct drop_stats);
} blocked_ips SEC(".maps");
```
- **บรรทัด 67-72:** แมปเก็บไอพีที่ต้องการบล็อก สามารถจุได้สูงสุด 10,240 ไอพี และอัปเดตแบบ Dynamic จาก Userspace ได้ตลอดเวลา

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} proto_counters SEC(".maps");
```
- **บรรทัด 80-85:** แมปเก็บตัวนับสถิติโปรโตคอล (เช่น ICMP=1, TCP=6, UDP=17) แยกตาม CPU Core เพื่อลด Latency มี 256 ช่องพอดีกับค่าที่เป็นไปได้ทั้งหมดของ `iph->protocol` (ชนิด `__u8`)

```c
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
```
- **บรรทัด 91-96:**
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
- **บรรทัด 101-109:** ตรวจสอบความปลอดภัยของ Ethernet Header หากแพ็กเก็ตสั้นเกินไปหรือไม่ได้เป็น IPv4 (เช่น ARP, **IPv6**) ให้ปล่อยผ่านไปยัง Linux Stack ทันที (มี Unit Test ยืนยันว่า IPv6 และ ARP ได้ `XDP_PASS`)

```c
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 115-118:** เลื่อนพอยน์เตอร์ไปที่ IPv4 Header และตรวจสอบขอบเขตของส่วนหัวขนาดคงที่ 20 ไบต์ เท่านี้ก็เพียงพอให้ Verifier ยอมให้อ่าน `iph->saddr` และ `iph->protocol` ได้แล้ว

```c
    __u32 proto = iph->protocol;
    __u64 *proto_cnt = bpf_map_lookup_elem(&proto_counters, &proto);
    if (proto_cnt) {
        *proto_cnt += 1;
    }
```
- **บรรทัด 124-129:** บันทึกตัวนับของโปรโตคอลลงใน Per-CPU Array โดยไม่ต้องผ่านคำสั่ง Atomic (เวอร์ชันก่อนหน้ามี `if (proto < 256)` ซึ่งเป็นจริงเสมอเพราะ `protocol` เป็น `__u8` จึงถูกตัดออก)

```c
    __u32 saddr = iph->saddr;
    struct drop_stats *stats = bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (stats) {
        __sync_fetch_and_add(&stats->dropped_packets, 1);
        __u64 pkt_len = (__u64)((char *)data_end - (char *)data);
        __sync_fetch_and_add(&stats->dropped_bytes, pkt_len);
        return XDP_DROP;
    }
```
- **บรรทัด 137-147:** ตรวจสอบว่า Source IP อยู่ใน Blacklist หรือไม่ หากตรงกัน ให้บันทึกสถิติและสั่ง `XDP_DROP` เพื่อทำลายแพ็กเก็ตทิ้งทันทีที่ระดับ Driver!

> [!IMPORTANT]
> **ลำดับการตรวจสอบสำคัญมาก (Security Bug ที่แก้ไขแล้ว):** เวอร์ชันก่อนหน้าตรวจ Blocklist *หลัง* การตรวจ IHL และ L4 Header ซึ่งทุกกรณีที่ไม่ผ่านจะ `return XDP_PASS` ผลคือโฮสต์ที่ถูกบล็อกสามารถ **เลี่ยง Firewall** ได้ง่าย ๆ ด้วยการส่งแพ็กเก็ตที่ TCP Header ถูกตัดสั้น, ค่า IHL ผิด หรือ IP Fragment ชิ้นที่ไม่ใช่ชิ้นแรก (ซึ่งไม่มี L4 Header เลย) Unit Test ใน `main_test.go` ยืนยันว่าโค้ดเดิมให้ผล `XDP_PASS` กับแพ็กเก็ตเหล่านี้ หลักการคือ **ตัดสินใจด้วยข้อมูลที่ตรวจสอบแล้วน้อยที่สุดที่จำเป็น (ในที่นี้คือ 20 ไบต์แรกของ IPv4) ให้เร็วที่สุด** แล้วค่อย Parse ส่วนอื่นต่อ

```c
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)iph + ip_hdr_len > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 153-156:** คำนวณความยาวจริงของ IPv4 Header (รวม IP Options) ผ่านฟิลด์ `ihl` และตรวจสอบขอบเขต แพ็กเก็ตที่ผิดรูปแบบจะถูกส่งให้เคอร์เนลจัดการ (เคอร์เนลจะดรอปและนับเป็น `InHdrErrors` เอง)

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

    return XDP_PASS;
```
- **บรรทัด 163-182:** ทำการ Bounds Check กับ Transport Layer Header หลังจากผ่านจุดนี้ Verifier จะยอมให้อ่าน `tcph->dest`, `udph->dest`, `icmph->type` ได้ จึงเป็น "แม่แบบ" สำหรับการเขียนกฎระดับพอร์ต (ดูแบบฝึกหัดท้ายบท) สุดท้ายแพ็กเก็ตที่ไม่ถูกบล็อกจะได้ `XDP_PASS`

---

### 2.2 ไฟล์ `main.go`

```go
func ipKey(ip net.IP) uint32 {
	return binary.NativeEndian.Uint32(ip.To4())
}
```
- **บรรทัด 25-31:** แปลง IPv4 เป็นคีย์ `__u32` ที่มี "ไบต์ในหน่วยความจำ" ตรงกับ `iph->saddr` (ดูหัวข้อ 1.4) ใช้ทั้งตอนเขียนแมปและตอนแสดงผลบน Dashboard

```go
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewallProg,
		Interface: iface.Index,
	})
```
- **บรรทัด 61-64:** แนบโปรแกรม XDP เข้ากับการ์ดแลนที่ระบุ เมื่อไม่ระบุ `Flags` เคอร์เนลจะเลือก Native/Driver Mode หากไดรเวอร์รองรับ (เช่น `veth` ในแล็บนี้ — สังเกตคำว่า `xdp` ใน `ip link show`) และใช้ Generic Mode หากไม่รองรับ

```go
			key := ipKey(parsedIP)
			initialStats := bpfDropStats{
				DroppedPackets: 0,
				DroppedBytes:   0,
			}
			if err := objs.BlockedIps.Put(&key, &initialStats); err != nil {
```
- **บรรทัด 86-91:** แปลงสตริงไอพีให้อยู่ในรูป `uint32` แล้วบันทึกลงใน Map `blocked_ips` ก่อนเริ่มการดักจับ

```go
	for _, p := range protocols {
		var perCpuCounts []uint64 = make([]uint64, numCPUs)
		if err := objs.ProtoCounters.Lookup(&p.Num, &perCpuCounts); err != nil { ... }
		var totalPkts uint64
		for _, cnt := range perCpuCounts {
			totalPkts += cnt
		}
		fmt.Printf("  %-10s  %-12d  %-16d\n", p.Name, p.Num, totalPkts)
	}
```
- **บรรทัด 144-156:** Userspace ควบรวมค่าจากทุก CPU Core โดยดึง slice ของ uint64 ที่มีขนาดเท่ากับจำนวนซีพียู แล้วหาผลรวมเพื่อแสดงผลบน Dashboard

---

### 2.3 ไฟล์ `main_test.go` (Unit Tests ด้วย `BPF_PROG_TEST_RUN`)

`BPF_PROG_TEST_RUN` คือคำสั่งของ `bpf()` syscall ที่ให้เคอร์เนล "รันโปรแกรม eBPF กับบัฟเฟอร์แพ็กเก็ตที่เราสร้างขึ้นเอง" โดยไม่ต้องแนบเข้ากับการ์ดแลนจริง แล้วคืนค่า Verdict (`XDP_PASS`/`XDP_DROP`/...) พร้อมแพ็กเก็ตขาออกกลับมา ใน Cilium ebpf-go เรียกผ่าน `Program.Run()`:

```go
ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
```

ไฟล์ทดสอบประกอบแพ็กเก็ต Ethernet/IPv4/TCP/UDP/ICMP/IPv6/ARP ด้วยมือ (ไม่พึ่งไลบรารีภายนอก) และครอบคลุมกรณี:

| Test | สิ่งที่ตรวจสอบ |
| :--- | :--- |
| `TestFirewallVerdicts` | ICMP/TCP/UDP จาก IP ที่ถูกบล็อก → `XDP_DROP`, จาก IP อื่น → `XDP_PASS`, IP ที่ถูกบล็อกเป็น *ปลายทาง* → `XDP_PASS`, TCP Header ถูกตัด / IHL เกินขนาดแพ็กเก็ต / Non-first Fragment จาก IP ที่ถูกบล็อก → ยังคง `XDP_DROP`, เฟรมสั้น / IHL < 5 / IPv6 / ARP → `XDP_PASS` |
| `TestDropStatsCounters` | `dropped_packets` และ `dropped_bytes` ตรงกับจำนวนครั้งและขนาดแพ็กเก็ตที่ส่งเข้าไป |
| `TestProtoCounters` | ผลรวม Per-CPU ของ `proto_counters` ถูกต้อง (นับทั้งแพ็กเก็ตที่ผ่านและถูกดรอป) |

ทุก Test จะ `t.Skip` อัตโนมัติหากไม่ได้รันด้วยสิทธิ์ root (`os.Geteuid() != 0`)

---

### 2.4 ข้อจำกัดของโปรแกรมในบทนี้ (Limitations)

- **IPv4 เท่านั้น:** แพ็กเก็ต IPv6 (`ETH_P_IPV6`) ถูก `XDP_PASS` ทั้งหมดโดยไม่ตรวจ Blocklist ผู้โจมตีที่มี IPv6 จึงผ่าน Firewall นี้ได้ (ดูแบบฝึกหัด)
- **ไม่รองรับ VLAN (802.1Q/802.1ad):** เฟรมที่มี VLAN Tag มี `h_proto = 0x8100` จึงถูก `XDP_PASS` ทันที แม้ Source IP ข้างในจะอยู่ใน Blocklist
- **บล็อกได้เฉพาะ IP เดี่ยว (Exact Match):** ไม่รองรับ Subnet/CIDR และไม่มีกฎระดับพอร์ต
- **ดรอปเฉพาะขาเข้า (Ingress):** XDP ไม่มี Hook ฝั่ง Egress ทราฟฟิกที่เครื่องเราส่งออกไปหา IP ที่ถูกบล็อกยังออกได้ (แต่คำตอบกลับจะถูกดรอป)
- **`max_entries` คงที่ 10,240:** ใส่เกินกว่านี้ `Put()` จะล้มเหลว
- **ตัวเลขประสิทธิภาพ:** แล็บนี้ใช้ `veth` ภายใน Network Namespace ซึ่งไม่ได้สะท้อนประสิทธิภาพของ Native XDP บนการ์ดแลนจริง หากต้องการตัวเลข PPS ต้องวัดบนฮาร์ดแวร์จริงด้วยเครื่องมืออย่าง `pktgen` หรือ `xdp-bench`

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์โปรแกรม
```bash
cd phase04-high-speed-networking/week07-xdp-parsing
make generate
make build
```

### ขั้นตอนที่ 2: รัน Unit Tests ด้วย `BPF_PROG_TEST_RUN`
```bash
make test   # = go generate + go test -exec sudo -v ./...
```
`-exec sudo` ทำให้ `go test` คอมไพล์ไบนารีทดสอบด้วยสิทธิ์ผู้ใช้ปกติ แล้วรันด้วย `sudo` (จำเป็นสำหรับโหลด eBPF) ผลลัพธ์ที่คาดหวังคือทุกบรรทัดขึ้น `--- PASS` และปิดท้ายด้วย `ok` (ดูผลจริงในหัวข้อ 4.1)

### ขั้นตอนที่ 3: สร้าง Network Namespace สำหรับทดสอบ (Lab Environment)
เพื่อจำลองการส่งข้อมูลเสมือนจริงระหว่าง Client และ Server โดยไม่รบกวนเน็ตเวิร์กจริงของเครื่องโฮสต์ (ทุกชื่อขึ้นต้นด้วย `w07-` เพื่อไม่ชนกับแล็บอื่น):
```bash
# สร้าง Namespace w07-client (Client) และ w07-server (Server Firewall)
sudo ip netns add w07-client
sudo ip netns add w07-server

# สร้างคู่สายเสมือน (veth pair)
sudo ip link add w07-c type veth peer name w07-s

# ย้ายอินเทอร์เฟซเข้าสู่ Namespace
sudo ip link set w07-c netns w07-client
sudo ip link set w07-s netns w07-server

# กำหนดไอพี: Client มี 2 ไอพี (.10 จะถูกบล็อก, .11 ใช้ทดสอบว่าทราฟฟิกปกติยังผ่าน)
sudo ip netns exec w07-client ip addr add 10.10.1.10/24 dev w07-c
sudo ip netns exec w07-client ip addr add 10.10.1.11/24 dev w07-c
sudo ip netns exec w07-server ip addr add 10.10.1.20/24 dev w07-s

# เปิดใช้งาน Interface
sudo ip netns exec w07-client ip link set lo up
sudo ip netns exec w07-client ip link set w07-c up
sudo ip netns exec w07-server ip link set lo up
sudo ip netns exec w07-server ip link set w07-s up
```

### ขั้นตอนที่ 4: สั่งรัน XDP Firewall ภายใน Namespace Server
เราจะสั่งให้ Firewall ทำงานบนการ์ด `w07-s` ภายใน `w07-server` และสั่งบล็อกไอพี `10.10.1.10`:
```bash
sudo ip netns exec w07-server ./bin/xdp-firewall -iface w07-s -block-ip 10.10.1.10
```

### ขั้นตอนที่ 5: ยิงทราฟฟิกทดสอบจาก Client (`w07-client`)
เปิดเทอร์มินัลอีกหน้าต่างหนึ่ง แล้วทดสอบส่ง Ping จากทั้งสองไอพี:
```bash
# จาก IP ที่ถูกบล็อก (ทราฟฟิกนี้จะถูกบล็อก 100%!)
sudo ip netns exec w07-client ping -c 5 -W 1 -I 10.10.1.10 10.10.1.20

# จาก IP ที่ไม่ถูกบล็อก (ต้องได้รับคำตอบปกติ)
sudo ip netns exec w07-client ping -c 3 -W 1 -I 10.10.1.11 10.10.1.20
```
ผลลัพธ์ที่คาดหวัง: ชุดแรก `100% packet loss` ชุดที่สอง `0% packet loss` และ Dashboard แสดง `DROPPED PACKETS = 5`, `DROPPED BYTES = 490` (5 × 98 ไบต์) ส่วนตัวนับ ICMP จะเป็น 8 (Echo Request ขาเข้า 5 + 3 แพ็กเก็ต; Echo Reply เป็นทราฟฟิกขาออกจึงไม่ผ่าน XDP) — ดูผลจริงในหัวข้อ 4.2

### ขั้นตอนที่ 6: ตรวจสอบด้วย `ip link` และ `bpftool`
```bash
# ตรวจสอบว่าโปรแกรม XDP แนบอยู่บน Interface
sudo ip netns exec w07-server ip link show w07-s

# Dump แมปสถิติด้วย bpftool
sudo bpftool map dump name blocked_ips
```

### ขั้นตอนที่ 7: คืนค่าและล้างสภาพแวดล้อมทดสอบ
กด `Ctrl+C` ที่หน้าต่าง Firewall ก่อน แล้วลบ Namespace (veth pair จะถูกลบตามไปด้วย):
```bash
sudo ip netns del w07-client
sudo ip netns del w07-server
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic x86_64`), clang 21, Go 1.26, bpftool 7.7, cilium/ebpf v0.16.0

### 4.1 ผลลัพธ์ Unit Tests (`make test`)
```text
===> Generating Go bindings from xdp_firewall.c via bpf2go...
go generate ./...
Compiled phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfeb.o
Stripped phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfeb.o
Wrote phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfeb.go
Compiled phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfel.o
Stripped phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfel.o
Wrote phase04-high-speed-networking/week07-xdp-parsing/bpf_bpfel.go
===> Running BPF_PROG_TEST_RUN unit tests (main_test.go)...
go test -exec sudo -v ./...
=== RUN   TestFirewallVerdicts
=== RUN   TestFirewallVerdicts/icmp_from_blocked_ip_is_dropped
=== RUN   TestFirewallVerdicts/tcp_from_blocked_ip_is_dropped
=== RUN   TestFirewallVerdicts/udp_from_blocked_ip_is_dropped
=== RUN   TestFirewallVerdicts/icmp_from_allowed_ip_passes
=== RUN   TestFirewallVerdicts/tcp_from_allowed_ip_passes
=== RUN   TestFirewallVerdicts/udp_from_allowed_ip_passes
=== RUN   TestFirewallVerdicts/blocked_ip_as_destination_passes
=== RUN   TestFirewallVerdicts/blocked_ip_with_truncated_tcp_header_is_still_dropped
=== RUN   TestFirewallVerdicts/blocked_ip_with_ihl_beyond_packet_end_is_still_dropped
=== RUN   TestFirewallVerdicts/non-first_fragment_from_blocked_ip_is_dropped
=== RUN   TestFirewallVerdicts/ethernet-only_frame_(truncated_ipv4)_passes
=== RUN   TestFirewallVerdicts/ipv4_with_ihl_<_5_passes_to_kernel
=== RUN   TestFirewallVerdicts/ipv6_passes_untouched
=== RUN   TestFirewallVerdicts/arp_passes_untouched
--- PASS: TestFirewallVerdicts (0.00s)
    --- PASS: TestFirewallVerdicts/icmp_from_blocked_ip_is_dropped (0.00s)
    --- PASS: TestFirewallVerdicts/tcp_from_blocked_ip_is_dropped (0.00s)
    --- PASS: TestFirewallVerdicts/udp_from_blocked_ip_is_dropped (0.00s)
    --- PASS: TestFirewallVerdicts/icmp_from_allowed_ip_passes (0.00s)
    --- PASS: TestFirewallVerdicts/tcp_from_allowed_ip_passes (0.00s)
    --- PASS: TestFirewallVerdicts/udp_from_allowed_ip_passes (0.00s)
    --- PASS: TestFirewallVerdicts/blocked_ip_as_destination_passes (0.00s)
    --- PASS: TestFirewallVerdicts/blocked_ip_with_truncated_tcp_header_is_still_dropped (0.00s)
    --- PASS: TestFirewallVerdicts/blocked_ip_with_ihl_beyond_packet_end_is_still_dropped (0.00s)
    --- PASS: TestFirewallVerdicts/non-first_fragment_from_blocked_ip_is_dropped (0.00s)
    --- PASS: TestFirewallVerdicts/ethernet-only_frame_(truncated_ipv4)_passes (0.00s)
    --- PASS: TestFirewallVerdicts/ipv4_with_ihl_<_5_passes_to_kernel (0.00s)
    --- PASS: TestFirewallVerdicts/ipv6_passes_untouched (0.00s)
    --- PASS: TestFirewallVerdicts/arp_passes_untouched (0.00s)
=== RUN   TestDropStatsCounters
--- PASS: TestDropStatsCounters (0.00s)
=== RUN   TestProtoCounters
--- PASS: TestProtoCounters (0.00s)
PASS
ok  	ebpf-noob-to-hero/phase04-high-speed-networking/week07-xdp-parsing	0.007s
```

### 4.2 ผลลัพธ์การรัน XDP Firewall (`-iface w07-s -block-ip 10.10.1.10`)
```text
--- FIREWALL STARTUP (sudo ip netns exec w07-server ./bin/xdp-firewall -iface w07-s -block-ip 10.10.1.10) ---
======================================================================
 eBPF High-Speed XDP Firewall & Packet Parser
======================================================================
2026/10/28 22:00:57 Successfully attached XDP filter to w07-s [Index: 1548]
2026/10/28 22:00:57 Added 10.10.1.10 (Key: 0x0a010a0a) to XDP blocklist map

--- CLIENT PING FROM BLOCKED IP (ping -c 5 -W 1 -I 10.10.1.10 10.10.1.20) ---
PING 10.10.1.20 (10.10.1.20) from 10.10.1.10 : 56(84) bytes of data.

--- 10.10.1.20 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4111ms


--- CLIENT PING FROM ALLOWED IP (ping -c 3 -W 1 -I 10.10.1.11 10.10.1.20) ---
PING 10.10.1.20 (10.10.1.20) from 10.10.1.11 : 56(84) bytes of data.
64 bytes from 10.10.1.20: icmp_seq=1 ttl=64 time=0.144 ms
64 bytes from 10.10.1.20: icmp_seq=2 ttl=64 time=0.065 ms
64 bytes from 10.10.1.20: icmp_seq=3 ttl=64 time=0.065 ms

--- 10.10.1.20 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2048ms
rtt min/avg/max/mdev = 0.065/0.091/0.144/0.037 ms

--- IP LINK SHOW (sudo ip netns exec w07-server ip link show w07-s) ---
1548: w07-s@if1549: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 86:8e:b7:07:68:ba brd ff:ff:ff:ff:ff:ff link-netns w07-client
    prog/xdp id 9669 name xdp_firewall_pr tag 4d7642a5ffe79977 jited

--- BPFTOOL MAP DUMP (sudo bpftool map dump name blocked_ips) ---
[{
        "key": 167840266,
        "value": {
            "dropped_packets": 5,
            "dropped_bytes": 490
        }
    }
]

--- DASHBOARD AFTER Ctrl+C / SIGTERM ---
Received signal 'terminated'. Detaching XDP link and exiting cleanly...
=================================================================================
 eBPF XDP Live Monitor | Interface: w07-s      | Host CPUs: 8 | Time: 22:01:08
=================================================================================
 [ Protocol Activity (Per-CPU Array Sum) ]
  PROTOCOL    CODE          TOTAL PACKETS
  ---------------------------------------------
  ICMP        1             8
  TCP         6             0
  UDP         17            0

 [ Blocked IP Drop Telemetry (BPF_MAP_TYPE_HASH) ]
  IP ADDRESS          DROPPED PACKETS   DROPPED BYTES
  -------------------------------------------------------------
  10.10.1.10          5                 490
=================================================================================
 Press Ctrl+C to detach XDP program and exit.
```

---

## 5. Milestone Checklist

- [x] เข้าใจสถาปัตยกรรมระดับฮาร์ดแวร์และไดรเวอร์ของ XDP เทียบกับ Netfilter/iptables
- [x] แยกความแตกต่างของ 3 โหมดใน XDP (Offloaded, Native Driver, Generic SKB)
- [x] เข้าใจและปฏิบัติตามกฎ Abstract Interpretation ของ eBPF Verifier สำหรับการ Bounds Check พอยน์เตอร์
- [x] ปาร์ส Ethernet (L2), IPv4 (L3), และ Transport Headers (L4: TCP/UDP/ICMP) ได้อย่างปลอดภัย
- [x] เข้าใจว่าทำไมต้องตัดสินใจ Drop *ก่อน* Parse ส่วนที่ไม่จำเป็น (ป้องกันการเลี่ยง Firewall ด้วยแพ็กเก็ตผิดรูป)
- [x] จัดการความต่างของสถาปัตยกรรม Big-Endian (Network) และ Little-Endian (Host)
- [x] ใช้งาน `BPF_MAP_TYPE_PERCPU_ARRAY` เพื่อลดปัญหา Cache Bouncing ในระดับซีพียู
- [x] พัฒนา Firewall คัดกรองและ Drop แพ็กเก็ตที่ระดับไดรเวอร์ด้วย `XDP_DROP`
- [x] เขียน Unit Test ด้วย `BPF_PROG_TEST_RUN` (`make test`) โดยไม่ต้องแนบโปรแกรมกับการ์ดแลนจริง
- [x] สร้าง Realtime Dashboard ใน Userspace ด้วย Go และทดสอบผ่าน Network Namespaces

---

## 6. แบบฝึกหัดท้ายบท (Exercises)

ทุกข้อให้เพิ่ม Test Case ใน `main_test.go` แล้วรัน `make test` เป็นหลักฐาน (และทดสอบใน Namespace จริงเพิ่มเติมได้)

### ระดับพื้นฐาน
1. **บล็อกตามพอร์ตปลายทาง (Port Blocklist)**
   - *Deliverable:* เพิ่มแมป `blocked_ports` (`BPF_MAP_TYPE_HASH`, key = `__u16` พอร์ตปลายทาง) และใช้ `tcph->dest`/`udph->dest` ในบล็อก L4 (บรรทัด 163-179) ให้ `XDP_DROP` เมื่อพอร์ตตรง เพิ่มแฟล็ก `-block-port` ใน `main.go`
   - *Verify:* Test ที่ส่ง TCP SYN ไปพอร์ต 22 ต้องได้ `XDP_DROP` และพอร์ต 80 ได้ `XDP_PASS`; ระวังเรื่อง Byte Order ของคีย์
2. **นับแพ็กเก็ต IPv6 และ ARP**
   - *Deliverable:* เพิ่มตัวนับ Per-CPU ตาม EtherType (อย่างน้อย IPv4/IPv6/ARP/อื่น ๆ) และแสดงบน Dashboard
   - *Verify:* Test ส่งเฟรม IPv6 2 ครั้งและ ARP 1 ครั้ง แล้วอ่านผลรวมจากแมปให้ได้ 2 และ 1 ตามลำดับ (Verdict ยังเป็น `XDP_PASS`)

### ระดับปานกลาง
3. **รองรับ IPv6 Blocklist**
   - *Deliverable:* Parse `struct ipv6hdr` (`<linux/ipv6.h>`, ขนาดคงที่ 40 ไบต์) เพิ่มแมป `blocked_ips6` ที่ใช้ `struct in6_addr` (16 ไบต์) เป็นคีย์ และให้ `-block-ip` รับได้ทั้ง IPv4/IPv6
   - *Verify:* แก้ Test `ipv6 passes untouched` ให้เป็น 2 กรณี: Source `fd00::10` (ถูกบล็อก) → `XDP_DROP` และ `fd00::11` → `XDP_PASS`; ทดสอบจริงด้วย `ping -6` ระหว่าง Namespace
4. **รองรับ VLAN Tag (802.1Q)**
   - *Deliverable:* หาก `h_proto == ETH_P_8021Q` ให้ข้าม `struct vlan_hdr` (4 ไบต์) แล้วอ่าน EtherType ข้างใน ก่อนตรวจ Blocklist (รองรับอย่างน้อย 1 ชั้น)
   - *Verify:* Test ที่ส่งเฟรม VLAN 100 ที่บรรจุ ICMP จาก IP ที่ถูกบล็อกต้องได้ `XDP_DROP` (โค้ดปัจจุบันให้ `XDP_PASS` — ปิดช่องโหว่ใน Limitations)

### ระดับท้าทาย
5. **CIDR Blocklist ด้วย `BPF_MAP_TYPE_LPM_TRIE`**
   - *Deliverable:* เปลี่ยน/เพิ่มแมปเป็น LPM Trie (key = `{__u32 prefixlen; __u32 addr;}`, ต้องตั้ง `map_flags = BPF_F_NO_PREALLOC`) เพื่อบล็อกทั้ง Subnet เช่น `10.10.0.0/16` และรองรับ `-block-ip 10.10.0.0/16`
   - *Verify:* Test: `10.10.5.5` → `XDP_DROP`, `10.11.0.1` → `XDP_PASS`; เพิ่ม Test ว่า Prefix ที่ยาวกว่าชนะ (Longest Prefix Match) หากเพิ่มกฎ Allow ไว้
6. **SYN Flood Rate Limiter ต่อ Source IP**
   - *Deliverable:* ใช้ `BPF_MAP_TYPE_LRU_HASH` เก็บ Token Bucket ต่อ Source IP (`bpf_ktime_get_ns()` สำหรับเติม Token) ให้ TCP SYN เกิน N แพ็กเก็ต/วินาที ถูก `XDP_DROP` ส่วนแพ็กเก็ตที่ไม่ใช่ SYN ผ่านได้
   - *Verify:* Test ส่ง SYN จาก IP เดียวกันติดกัน N+5 ครั้ง (ใช้ `RunOptions.Repeat` หรือวนลูป) ต้องได้ `XDP_PASS` N ครั้งแรกและ `XDP_DROP` ที่เหลือ; แพ็กเก็ต ACK ต้องยัง `XDP_PASS`
