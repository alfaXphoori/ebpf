# Week 08: Layer-4 Load Balancer with XDP & TC Egress Marker

ยินดีต้อนรับสู่สัปดาห์ที่ 8 ของหลักสูตร **eBPF: Zero-to-Hero** ในสัปดาห์นี้ เราจะผสมผสานสองเสาหลักของระบบเครือข่ายความเร็วสูงในลินุกซ์เข้าด้วยกัน ได้แก่ **XDP (eXpress Data Path)** และ **TC (Traffic Control)** เพื่อสร้าง Layer-4 Load Balancer ที่ทำงานได้จริงแบบ End-to-End:
1. **L4 Load Balancer ขาไป (XDP, Forward Path):** ดักจับทราฟฟิก TCP ที่ส่งมายัง Virtual IP (VIP), เลือก Backend ด้วย Flow Hash, บันทึก Flow ลง Connection Tracking Map, ทำ DNAT (Rewrite MAC/Destination IP), คำนวณ Checksum ใหม่แบบ Incremental และสะท้อนแพ็กเก็ตออกทางเดิมด้วย `XDP_TX` (Hairpin) โดยไม่ผ่าน Routing ของเคอร์เนล
2. **Reverse NAT ขากลับ (TC Ingress, Return Path):** คำตอบจาก Backend ที่วิ่งกลับผ่าน LB จะถูกโปรแกรม TC เปลี่ยน Source IP จาก IP ของ Backend กลับเป็น VIP (SNAT) พร้อมแก้ Checksum ด้วย Helper ของ TC เพื่อให้ Client ยอมรับคำตอบ
3. **TC Egress QoS Classifier & Marker:** ติดตามทราฟฟิกขาออก (Outbound / Egress) จำแนกตาม Destination Port และประทับตรา Packet Priority/Mark (`skb->mark = 0x42`) สำหรับระบบ Traffic Shaping / QoS

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 เปรียบเทียบเชิงลึก: XDP vs TC (Traffic Control)

ทั้ง XDP และ TC เป็นจุดเชื่อมต่อ eBPF ที่ทรงพลังที่สุดในระบบเครือข่ายของลินุกซ์ แต่ถูกออกแบบมาเพื่อวัตถุประสงค์ที่แตกต่างกันอย่างสิ้นเชิง:

| คุณลักษณะ | XDP (eXpress Data Path) | TC (Traffic Control) |
| :--- | :--- | :--- |
| **จุดเกาะเกี่ยว (Hook Point)** | Ingress เท่านั้น (Driver RX ring buffer) | Ingress และ **Egress** (Queueing Discipline - qdisc) |
| **โครงสร้างบริบท (Context)** | `struct xdp_md` (Raw packet memory) | `struct __sk_buff` (Full Socket Buffer metadata) |
| **การจัดสรรหน่วยความจำ** | **ก่อน** สร้าง `sk_buff` (Zero-copy, ไม่กินเมมโมรี) | **หลัง** สร้าง `sk_buff` (เข้าถึง Socket metadata ได้) |
| **Throughput / Latency** | สูงที่สุดในเคอร์เนล (ทำงานก่อนจัดสรร `sk_buff`; ตัวเลข PPS จริงขึ้นกับ NIC/driver/CPU) | ต่ำกว่า XDP เพราะมี Overhead ของ `sk_buff` แต่ได้ Metadata และ Helper ครบกว่า |
| **ความสามารถในการปรับแต่ง** | L2/L3/L4 Parsing, Hairpin (`XDP_TX`), Drop, Redirect | Traffic Shaping, Rate Limiting, QoS Marking, Egress filtering |
| **Action Return Codes** | `XDP_PASS`, `XDP_DROP`, `XDP_TX`, `XDP_REDIRECT` | `TC_ACT_OK`, `TC_ACT_SHOT`, `TC_ACT_PIPE`, `TC_ACT_RECLASSIFY` |

```
+-----------------------------------------------------------------------------------------+
|                                  PACKET INGRESS (RX PATH)                               |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
               +-----------------------------------------------------------+
               |                   NIC Driver RX Buffer                    |
               +-----------------------------------------------------------+
                                             |
                                             v
                        +-----------------------------------------+
                        |           eBPF XDP HOOK                 |
                        |   (ctx: struct xdp_md, Wire-Speed)      |
                        +-----------------------------------------+
                               /             |             \
                              /              |              \
               [ XDP_DROP ]  /        [ XDP_PASS ]           \  [ XDP_TX ]
              (ทำลายทิ้งทันที)       /        |               \ (สะท้อนแพ็กเก็ตกลับสายแลน)
                                    v         v                v
                       +----------------------------------+   Hairpin Out
                       |     Allocate struct sk_buff      |
                       +----------------------------------+
                                             |
                                             v
                        +-----------------------------------------+
                        |        TC Ingress Hook (clsact)         |
                        +-----------------------------------------+
                                             |
                                             v
                        +-----------------------------------------+
                        |     Linux TCP/IP Stack & Routing        |
                        +-----------------------------------------+
                                             |
+--------------------------------------------|--------------------------------------------+
|                                  PACKET EGRESS (TX PATH)                                |
+--------------------------------------------|--------------------------------------------+
                                             v
                        +-----------------------------------------+
                        |         TC Egress Hook (clsact)         |
                        | (ctx: struct __sk_buff, QoS & Marking)  |
                        +-----------------------------------------+
                                             |
                                             v
               +-----------------------------------------------------------+
               |               NIC Driver TX Buffer (Wire)                 |
               +-----------------------------------------------------------+
```

---

### 1.2 กลไกการทำ Load Balancing ด้วย `XDP_TX` (Hairpin Routing)

`XDP_TX` เป็นหนึ่งใน Return Action ที่ทรงอิทธิพลที่สุดของ XDP:
- ปกติแล้ว เมื่อแพ็กเก็ตเข้ามาที่การ์ดแลน หากเคอร์เนลต้องการส่งต่อไปยังโฮสต์อื่น แพ็กเก็ตจะต้องถูกแปลงเป็น `sk_buff` เข้าสู่ Routing Engine ทำการ Forward แล้วส่งออกไปยังคิว TX
- **ด้วย `XDP_TX`:** โปรแกรม eBPF จะแก้ไขข้อมูลในแพ็กเก็ตโดยตรง (เปลี่ยน Destination IP และ Destination MAC เป็นของ Backend) จากนั้นคืนค่า `XDP_TX` ไดรเวอร์จะส่งแพ็กเก็ตนั้นย้อนกลับออกไปทางอินเทอร์เฟซเดิมทันที โดยไม่ผ่าน Routing, Netfilter และ TC Egress ของเคอร์เนล (ในโหมด Native)

> [!NOTE]
> **`XDP_TX` บน `veth` (แล็บนี้):** ใน Native Mode ของ `veth` แพ็กเก็ตที่ `XDP_TX` จะถูกส่งเข้า NAPI ring ของ *veth ฝั่งตรงข้าม (peer)* ซึ่งต้องมีโปรแกรม XDP หรือเปิด GRO อยู่ มิฉะนั้นจะถูกทิ้งและนับเป็น `xdp_tx_errors` (ดูได้จาก `ethtool -S eth0`) จากการทดลองบนเครื่องของเรา (Linux 7.0) Native Mode โดยไม่มีอะไรบน peer ได้ `xdp_tx_errors` ทุกแพ็กเก็ต และเมื่อเปิด GRO บน peer แพ็กเก็ตไปถึง Backend แต่ล่าช้าหลายวินาทีจน `curl` Timeout แล็บนี้จึงใช้ **`-xdp-mode generic`** ซึ่งทำงานหลังสร้าง `sk_buff` (ช้ากว่า แต่ส่งออกทันทีและเหมาะกับการเรียนรู้) ส่วนบนการ์ดแลนจริงที่รองรับ Native XDP ให้ใช้ `auto`/`native`

---

### 1.3 ปัญหา Return Path: ทำไม DNAT อย่างเดียวไม่พอ และทางเลือก NAT vs DSR

ถ้า LB ทำแค่ DNAT (เปลี่ยน `daddr` จาก VIP เป็น IP ของ Backend) Backend จะตอบ SYN-ACK กลับด้วย **Source IP ของตัวเอง** (`10.10.1.2`) แต่ Client กำลังรอคำตอบจาก VIP (`10.10.1.100`) Kernel ของ Client จึงไม่พบ Socket ที่ตรงกันและตอบกลับด้วย **RST** การเชื่อมต่อจึงล้มเหลวทุกครั้ง (เวอร์ชันก่อนหน้าของบทนี้มีปัญหานี้: Dashboard นับแพ็กเก็ตได้ แต่ `curl` ไม่เคยสำเร็จ) ทางแก้มาตรฐานมี 2 แบบ:

| แนวทาง | หลักการ | ข้อดี | ข้อเสีย |
| :--- | :--- | :--- | :--- |
| **NAT (Reverse SNAT)** ← *บทนี้เลือกแบบนี้* | Backend ใช้ LB เป็น Gateway ขากลับ LB เปลี่ยน `saddr` ของคำตอบจาก Backend IP กลับเป็น VIP | Backend ไม่ต้องตั้งค่าพิเศษนอกจาก Route; ได้ฝึก Checksum ทั้งแบบ XDP (คำนวณเอง) และ TC (Helper) | ทราฟฟิกขากลับ (ซึ่งมักใหญ่กว่าขาไป) ต้องผ่าน LB ทั้งหมด LB จึงเป็นคอขวดด้าน Bandwidth และต้องมี State (Flow Table) |
| **DSR (Direct Server Return)** | LB เปลี่ยนแค่ MAC (หรือ Encapsulate เช่น IPIP/GRE) Backend ผูก VIP ไว้ที่ `lo` แล้วตอบ Client โดยตรงด้วย Source = VIP | ขากลับไม่ผ่าน LB เลย รองรับ Throughput สูง (แนวทางที่ LB ขนาดใหญ่ เช่น Katran และ Maglev ใช้ — ควรศึกษาจากเอกสารต้นฉบับประกอบ) | ต้องแก้ทุก Backend (VIP บน `lo`, `arp_ignore`/`arp_announce`) ไม่มีการเปลี่ยน IP จึงไม่ได้ฝึกเรื่อง Checksum |

เราเลือก **NAT** เพราะเข้ากับเป้าหมายของบทนี้ (XDP + TC + Incremental Checksum) และไม่ต้องดัดแปลง Backend ส่วน DSR อยู่ในแบบฝึกหัดท้ายบท

```
        Client 10.10.2.10                     LB (ns w08-lb, eth0)                     Backend 10.10.1.2/.3
              |                       10.10.1.1 + 10.10.2.1, ip_forward=1                     |
              |  SYN  dst=VIP:80             |                                                |
              |----------------------------->| XDP: hash -> backend, flows[...] = VIP         |
              |                              |      DNAT dst=VIP->10.10.1.2, MAC, csum        |
              |                              |      XDP_TX ---------------------------------->|
              |                              |                                                |
              |                              |<---------------------- SYN-ACK src=10.10.1.2  |
              |                              | TCX ingress: flows hit -> SNAT src=..->VIP     |   (route 10.10.2.0/24
              |<-----------------------------| kernel forward (+ TC egress mark/stat)         |    via 10.10.1.1)
              |  SYN-ACK src=VIP:80          |                                                |
```

---

### 1.4 คณิตศาสตร์การคำนวณ Checksum แบบ Incremental (RFC 1624 & `bpf_csum_diff`)

เมื่อเราเปลี่ยนแปลงข้อมูลในส่วนหัวของแพ็กเก็ต เช่น เปลี่ยน Destination IP (`iph->daddr`) เช็กซัมเดิมของ IPv4 Header (`iph->check`) และ TCP Header (`tcph->check`) จะใช้การไม่ได้ทันที หากไม่แก้ไข เครื่องปลายทางจะดรอปแพ็กเก็ตทิ้งเนื่องจาก Checksum Mismatch

การคำนวณเช็กซัมใหม่ทั้งแพ็กเก็ตต้องอ่านทุกไบต์ของ Payload (สิ้นเปลืองและต้องวนลูปซึ่ง Verifier จำกัด) RFC 1624 จึงระบุสูตรการอัปเดตแบบ **Incremental 16-bit 1's Complement Sum** ที่ใช้เฉพาะค่าเก่าและค่าใหม่ของฟิลด์ที่เปลี่ยน:
$$HC' = \sim (\sim HC + \sim m + m')$$
โดยที่:
- $HC$ = เช็กซัมเดิม
- $HC'$ = เช็กซัมใหม่
- $m$ = ค่าเดิม 32-bit (Old IP)
- $m'$ = ค่าใหม่ 32-bit (New IP)

**ขาไป (XDP):** XDP ไม่มี `sk_buff` จึงไม่มี Helper แบบ `bpf_l4_csum_replace` เราต้องคำนวณเองโดยใช้ `bpf_csum_diff()` หาผลต่าง ($\sim m + m'$) แล้วพับ (fold) เป็น 16 บิต:
```c
static __always_inline void csum_replace4_helper(__u16 *csum, __u32 from, __u32 to)
{
    __s64 diff = bpf_csum_diff((__be32 *)&from, sizeof(from),
                               (__be32 *)&to, sizeof(to),
                               (__u16)~(*csum));
    diff = (diff & 0xffff) + (diff >> 16);
    diff = (diff & 0xffff) + (diff >> 16);
    *csum = (__u16)~diff;
}
```
เนื่องจาก TCP Checksum รวม Pseudo-header ซึ่งบรรจุ `saddr`/`daddr` อยู่ด้วย เมื่อเปลี่ยน `iph->daddr` จึงต้องอัปเดตทั้ง `iph->check` และ `tcph->check`

**ขากลับ (TC):** TC มี Helper ที่เข้าใจสถานะ Checksum ของ `sk_buff` (`CHECKSUM_NONE`/`PARTIAL`/`COMPLETE`):
```c
bpf_l4_csum_replace(skb, tcp_csum_off, old_saddr, new_saddr, BPF_F_PSEUDO_HDR | sizeof(new_saddr));
bpf_l3_csum_replace(skb, ip_csum_off,  old_saddr, new_saddr, sizeof(new_saddr));
bpf_skb_store_bytes(skb, ip_saddr_off, &new_saddr, sizeof(new_saddr), 0);
```
แฟล็ก `BPF_F_PSEUDO_HDR` บอกว่าฟิลด์ที่เปลี่ยนอยู่ใน Pseudo-header ซึ่งเคอร์เนลใช้ปรับ `skb->csum` ให้ถูกต้องในกรณี `CHECKSUM_COMPLETE`

> [!WARNING]
> **Checksum Offload บน `veth` ซ่อนบั๊กได้:** เราทดลองลบบรรทัดอัปเดต `tcph->check` ใน XDP ออกโดยเจตนา หาก veth เปิด TX Checksum Offload ไว้ (ค่าเริ่มต้น) `curl` ยังสำเร็จ เพราะแพ็กเก็ตจากสแต็กภายในเครื่องไม่ถูกตรวจ Checksum แบบเต็ม แต่เมื่อสั่ง `ethtool -K eth0 tx off` ทุก Namespace การเชื่อมต่อล้มเหลวทันที แล็บนี้จึงปิด TX Offload และมี Unit Test ที่คำนวณ Checksum ใหม่ทั้งก้อนเพื่อตรวจผลลัพธ์อีกชั้น

---

### 1.5 การวิวัฒนาการสู่ TCX ใน Modern Kernel (Linux 6.6+)

ในอดีต การแนบโปรแกรม eBPF เข้ากับ TC Subsystem ต้องใช้คำสั่ง `tc qdisc add dev eth0 clsact` และแนบ BPF ผ่านคลาส `tc filter add` ซึ่งผูกติดกับ Netlink และ qdisc

ตั้งแต่ **Linux Kernel 6.6** เป็นต้นมา ได้มีการเปิดตัว **TCX (TC eXpress / BPF Link-based TC)** ซึ่งทำให้เราสามารถแนบ eBPF Program เข้ากับ Ingress และ Egress ของ Interface ได้โดยตรงผ่าน BPF Link (File Descriptor) เหมือนกับ XDP ผ่านฟังก์ชัน `link.AttachTCX()` ใน Cilium ebpf-go ข้อดีคือไม่ต้องสร้าง qdisc, Link ถูกถอดออกอัตโนมัติเมื่อโปรเซสปิด และหลายโปรแกรมแนบร่วมกันได้อย่างเป็นระเบียบ

บทนี้ใช้ TCX สองจุดบนอินเทอร์เฟซเดียวกัน: **`tcx/ingress`** สำหรับ Reverse NAT และ **`tcx/egress`** สำหรับ QoS Marker (ตรวจดูได้ด้วย `bpftool net show dev eth0`)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `xdp_lb.c` (XDP Load Balancer + TC Reverse NAT)

```c
struct backend_config {
    __u32 ip;
    unsigned char mac[ETH_ALEN];
    __u16 pad;
};
```
- **บรรทัด 68-72:** โครงสร้างเก็บข้อมูลของเซิร์ฟเวอร์ Backend (IP + MAC Address) พร้อมฟิลด์ `pad` ขนาด 2 ไบต์ เพื่อให้ Struct มีขนาดรวม $4 + 6 + 2 = 12$ ไบต์ ซึ่งลงตัวกับการจัดเรียงแบบ 4-byte alignment

```c
struct flow_key {
    __u32 client_ip;
    __u32 backend_ip;
    __u16 client_port;
    __u16 service_port;
};
struct flow_value {
    __u32 vip;
};
```
- **บรรทัด 99-112:** คีย์/ค่าของ **Connection Tracking** หนึ่ง Flow คือคู่ Client ↔ Backend ค่าที่เก็บคือ VIP ที่ Client เชื่อมต่อมา เพื่อให้ขากลับรู้ว่าต้องเปลี่ยน Source IP เป็นอะไร (พอร์ตเก็บแบบ Network Byte Order ตามที่อ่านจาก TCP Header ตรง ๆ)

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct backend_config);
} backends SEC(".maps");
...
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flows SEC(".maps");
```
- **บรรทัด 117-122:** BPF Array Map เก็บรายการ Backend เซิร์ฟเวอร์ 2 ตัว (Index 0 และ Index 1)
- **บรรทัด 149-154:** แมป `flows` แบบ **LRU Hash** — XDP (ขาไป) เป็นผู้เขียน, TC (ขากลับ) เป็นผู้อ่าน เมื่อเต็ม เคอร์เนลจะไล่ Flow ที่ไม่ได้ใช้นานที่สุดออกเอง จึงไม่ต้องมี Garbage Collector ใน Userspace ทั้งสองโปรแกรมอยู่ในไฟล์ `.c` เดียวกันจึงใช้แมปเดียวกันโดยอัตโนมัติ

```c
static __always_inline __u32 flow_hash(__u32 saddr, __u16 sport, __u16 dport)
{
    __u32 h = saddr ^ (((__u32)sport << 16) | dport);
    h ^= h >> 16;
    h *= 0x7feb352d;
    h ^= h >> 15;
    h *= 0x846ca68b;
    h ^= h >> 16;
    return h;
}
```
- **บรรทัด 177-186:** ฟังก์ชันผสมบิต (Integer Hash "lowbias32") ของ (Client IP, Client Port, Service Port) ทุกบิตของอินพุตมีผลต่อบิตต่ำสุดที่เราใช้ทำ `% 2`

> [!IMPORTANT]
> **บั๊กที่แก้ไขแล้ว: `sport % 2` ส่งทุกอย่างไป Backend 0** — เวอร์ชันก่อนหน้าใช้ `bpf_ntohs(tcph->source) % 2` แต่ตั้งแต่ Linux 4.2 (commit "tcp/dccp: try to not exhaust ip_local_port_range in connect()") `connect()` จะเลือก Ephemeral Port **เลขคู่** ก่อน (เลขคี่สงวนไว้ให้ `bind()`) ในการทดลองจริง พอร์ตของ `curl` เป็นเลขคู่ทุกครั้ง ทำให้ทราฟฟิก 100% ไปที่ Backend #0 Unit Test `TestXDPEvenPortsAreBalanced` ส่ง 1,000 Flow ที่ใช้พอร์ตเลขคู่และตรวจว่าแต่ละ Backend ได้อย่างน้อย 40%

```c
    if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
        return XDP_PASS;
    }

    __u32 cfg_key = 0;
    struct lb_config_t *cfg = bpf_map_lookup_elem(&lb_config, &cfg_key);
    if (!cfg) return XDP_PASS;
    if (iph->daddr != cfg->vip) return XDP_PASS;
```
- **บรรทัด 230-244:** ข้าม IP Fragment (มีแค่ชิ้นแรกที่มี TCP Header จึง Hash ชิ้นอื่นไป Backend เดียวกันไม่ได้) จากนั้นค้นหาการตั้งค่า VIP หากแพ็กเก็ตไม่ได้ส่งมาที่ Virtual IP ให้ปล่อยผ่าน (`XDP_PASS`) — รวมถึงคำตอบจาก Backend ซึ่งจะถูกจัดการโดย TC

```c
    __u32 backend_id = flow_hash(iph->saddr, tcph->source, tcph->dest) % 2;
    struct backend_config *backend = bpf_map_lookup_elem(&backends, &backend_id);
    if (!backend || backend->ip == 0) return XDP_PASS;

    struct flow_key fkey = {
        .client_ip = iph->saddr,
        .backend_ip = backend->ip,
        .client_port = tcph->source,
        .service_port = tcph->dest,
    };
    if (!bpf_map_lookup_elem(&flows, &fkey)) {
        struct flow_value fval = { .vip = iph->daddr };
        bpf_map_update_elem(&flows, &fkey, &fval, BPF_ANY);
    }
```
- **บรรทัด 263-283:**
  - **Flow-aware Hashing:** แพ็กเก็ตทุกตัวใน TCP Connection เดียวกันมี (IP, Port) เหมือนกัน จึงได้ Hash เดียวกันและไปที่ Backend เดิมเสมอ (Session Affinity)
  - บันทึก Flow ลงแมป `flows` สำหรับขากลับ (Lookup ก่อน เพื่อไม่ต้องเขียนแมปทุกแพ็กเก็ตของ Flow ที่มีอยู่แล้ว)

```c
    __builtin_memcpy(eth->h_source, cfg->lb_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, backend->mac, ETH_ALEN);

    __u32 old_daddr = iph->daddr;
    __u32 new_daddr = backend->ip;

    csum_replace4_helper(&iph->check, old_daddr, new_daddr);
    csum_replace4_helper(&tcph->check, old_daddr, new_daddr);
    iph->daddr = new_daddr;

    return XDP_TX;
```
- **บรรทัด 289-316:**
  - สลับ MAC Address ต้นทางเป็น MAC ของ LB และปลายทางเป็น MAC ของ Backend
  - เขียนทับ Destination IP จาก VIP เป็น IP ของ Backend (DNAT) — Source IP ของ Client ไม่ถูกแตะ Backend จึงเห็น IP จริงของ Client
  - อัปเดตเช็กซัมทั้ง IP Header และ TCP Header ด้วย Incremental Checksum Helper
  - คืนค่า `XDP_TX` เพื่อยิงแพ็กเก็ตออกทางการ์ดแลนเดิมทันที

```c
SEC("tc")
int tc_reverse_nat(struct __sk_buff *skb)
{
    ...
    struct flow_key fkey = {
        .client_ip = iph->daddr,
        .backend_ip = iph->saddr,
        .client_port = tcph->dest,
        .service_port = tcph->source,
    };
    struct flow_value *flow = bpf_map_lookup_elem(&flows, &fkey);
    if (!flow) return TC_ACT_OK;
```
- **บรรทัด 329-376:** โปรแกรม TC ที่แนบกับ **TCX Ingress** ของ LB Parse L2/L3/L4 แบบเดียวกับ XDP (บริบทคือ `struct __sk_buff`) แล้วสร้างคีย์โดย **สลับฝั่ง** (daddr ของคำตอบคือ Client, saddr คือ Backend) หากไม่พบ Flow แปลว่าไม่ใช่ทราฟฟิกของ LB ปล่อยผ่านโดยไม่แก้ไข

```c
    __u32 ip_csum_off = ETH_HLEN + offsetof(struct iphdr, check);
    __u32 ip_saddr_off = ETH_HLEN + offsetof(struct iphdr, saddr);
    __u32 tcp_csum_off = ETH_HLEN + ip_hdr_len + offsetof(struct tcphdr, check);

    bpf_l4_csum_replace(skb, tcp_csum_off, old_saddr, new_saddr, BPF_F_PSEUDO_HDR | sizeof(new_saddr));
    bpf_l3_csum_replace(skb, ip_csum_off, old_saddr, new_saddr, sizeof(new_saddr));
    bpf_skb_store_bytes(skb, ip_saddr_off, &new_saddr, sizeof(new_saddr), 0);
    ...
    return TC_ACT_OK;
```
- **บรรทัด 386-410:** **SNAT** เปลี่ยน Source IP จาก Backend กลับเป็น VIP ด้วย Helper ที่ทำงานกับ Offset นับจาก `skb->data` (ต้นเฟรม Ethernet) หลังเรียก Helper เหล่านี้ พอยน์เตอร์แพ็กเก็ตเดิมใช้ไม่ได้อีก (Verifier บังคับ) จึงคำนวณ Offset ทั้งหมดไว้ก่อน จากนั้นคืนค่า `TC_ACT_OK` ให้เคอร์เนล Route แพ็กเก็ตไปหา Client ตามปกติ

---

### 2.2 ไฟล์ `tc_egress.c` (TC QoS Marker & Classifier)

```c
SEC("tc")
int tc_egress_prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
```
- **บรรทัด 71-75:** แนบที่จุดตรวจจับ Egress ของ TC บริบทคือ `struct __sk_buff`

```c
    struct egress_stat *stat = bpf_map_lookup_elem(&egress_stats, &dport);
    if (stat) {
        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, pkt_len);
    } else {
        struct egress_stat init_stat = { .packets = 1, .bytes = pkt_len };
        if (bpf_map_update_elem(&egress_stats, &dport, &init_stat, BPF_NOEXIST) != 0) {
            stat = bpf_map_lookup_elem(&egress_stats, &dport);
            if (stat) { /* add atomically */ }
        }
    }
```
- **บรรทัด 121-144:** บันทึกสถิติทราฟฟิกขาออกแยกตาม Destination Port ลงใน Hash Map `egress_stats` — ใช้ `BPF_NOEXIST` เพื่อแก้ Race Condition ของเวอร์ชันเดิม (`BPF_ANY`) ที่ CPU สองตัวสร้าง Entry ใหม่พร้อมกันแล้วเขียนทับตัวนับของกันและกัน

```c
    skb->mark = 0x42;
    skb->priority = 1;

    return TC_ACT_OK;
```
- **บรรทัด 148-151:**
  - ประทับตรา `skb->mark = 0x42` เพื่อนำไปใช้กับ Policy Routing (`ip rule fwmark`) หรือ Netfilter
  - กำหนดค่า `skb->priority = 1` เพื่อให้ qdisc ที่รองรับ (เช่น `prio`) จัดคิวตามลำดับความสำคัญ
  - คืนค่า `TC_ACT_OK` ให้แพ็กเก็ตส่งออกสู่เครือข่ายตามปกติ

> [!NOTE]
> แพ็กเก็ตที่ออกด้วย `XDP_TX` **ไม่ผ่าน** TC Egress ดังนั้นตาราง Egress บน Dashboard จะเห็นเฉพาะคำตอบขากลับที่เคอร์เนล Forward ไปหา Client (Destination Port = Ephemeral Port ของ Client) ไม่ใช่พอร์ต 80

---

### 2.3 ไฟล์ `main.go`

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdplb xdp_lb.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcegress tc_egress.c
```
- **บรรทัด 6-7:** สั่ง Generate Go Bindings สำหรับไฟล์ eBPF สองไฟล์ (`xdplb` มีทั้ง `xdp_load_balancer` และ `tc_reverse_nat`; `tcegress` มี `tc_egress_prog`)

```go
	if *lbMacStr == "" {
		*lbMacStr = iface.HardwareAddr.String()
	}
```
- **บรรทัด 73-75:** ค่าเริ่มต้นของ `-lb-mac` คือ MAC จริงของอินเทอร์เฟซ (เดิมฮาร์ดโค้ดไว้ ถ้าไม่ตรงกับ MAC จริง Bridge/Switch จะเรียนรู้ตำแหน่งผิด) และเขียนค่า VIP/Backend ลงแมป **ก่อน** แนบโปรแกรม เพื่อให้แพ็กเก็ตแรกเห็น Config ครบ

```go
	rnatLink, err := link.AttachTCX(link.TCXOptions{
		Program:   lbObjs.TcReverseNat,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("[TC] Failed to attach reverse NAT via TCX ingress on %s: %v ...")
	}
```
- **บรรทัด 122-133:** แนบ Reverse NAT ที่ TCX Ingress หากล้มเหลว (เช่น Kernel < 6.6) โปรแกรมจะ **หยุดทำงานพร้อมคำแนะนำ** แทนที่จะรัน LB ที่ทำงานได้ครึ่งเดียว (เวอร์ชันเดิมพิมพ์ว่า "Falling back..." แต่ไม่ได้ Fallback จริง)

```go
	switch *xdpMode {
	case "auto":
	case "native":
		xdpFlags = link.XDPDriverMode
	case "generic":
		xdpFlags = link.XDPGenericMode
	}
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   lbObjs.XdpLoadBalancer,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
```
- **บรรทัด 140-155:** แนบ XDP Load Balancer ตามโหมดที่เลือกด้วย `-xdp-mode` (ดูหัวข้อ 1.2 ว่าทำไมแล็บ veth ใช้ `generic`)

```go
	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   tcObjs.TcEgressProg,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("[TC] WARNING: TCX egress attach failed (%v). Egress telemetry/QoS marking DISABLED; load balancing continues.\n", err)
	}
```
- **บรรทัด 170-182:** แนบ TC Egress Program ผ่าน TCX ส่วนนี้เป็นแค่ Telemetry/QoS จึง **ไม่ Fatal** แต่แจ้งชัดเจนว่าปิดใช้งาน และ Dashboard จะแสดง `(TC egress program not attached - telemetry disabled)`

---

### 2.4 ไฟล์ `main_test.go` (Unit Tests ด้วย `BPF_PROG_TEST_RUN`)

`BPF_PROG_TEST_RUN` ให้เคอร์เนลรันโปรแกรม XDP/TC กับแพ็กเก็ตที่เราประกอบเองแล้วคืน **Verdict + แพ็กเก็ตหลังถูกแก้ไข** (`RunOptions.DataOut`) จึงตรวจได้ทั้ง IP/MAC ที่ถูก Rewrite และความถูกต้องของ Checksum (Test คำนวณ IPv4 Header Checksum และ TCP Checksum ใหม่ทั้งก้อน ต้องได้ Residual = 0)

| Test | สิ่งที่ตรวจสอบ |
| :--- | :--- |
| `TestXDPForwardRewritesToBackend` | SYN/Data ไป VIP → `XDP_TX`, dst IP/MAC = Backend ที่ Hash เลือก, src MAC = LB, src IP คงเดิม, Checksum ถูกต้อง, มี Entry ใน `flows`, ตัวนับ `lb_stats` ถูกต้อง |
| `TestXDPEvenPortsAreBalanced` | 1,000 Flow ที่ใช้พอร์ตเลขคู่ (แบบ `connect()`) กระจายไปทั้งสอง Backend (≥ 40% ต่อตัว) |
| `TestXDPForwardWithIPOptions` | IPv4 ที่มี IP Options (IHL=6) ยัง Rewrite และ Checksum ถูก |
| `TestXDPPassesNonLBTraffic` | TCP ไป IP อื่น, คำตอบจาก Backend, UDP, TCP Header ถูกตัด, IP Fragment, เฟรมสั้น, **IPv6** → `XDP_PASS` และแพ็กเก็ตไม่ถูกแก้ |
| `TestTCReverseNATRestoresVIP` | หลัง SYN ผ่าน XDP แล้ว SYN-ACK/HTTP Response จาก Backend ถูก SNAT เป็น VIP พร้อม Checksum ถูกต้อง |
| `TestTCReverseNATIgnoresUnknownFlows` | ทราฟฟิกที่ไม่มี Flow ในตาราง ไม่ถูกแก้ไข |
| `TestTCEgressPortStats` | `egress_stats` นับแพ็กเก็ต/ไบต์ตาม Destination Port ถูกต้อง |

ทุก Test จะ `t.Skip` อัตโนมัติหากไม่ได้รันด้วยสิทธิ์ root

---

### 2.5 ข้อจำกัดของโปรแกรมในบทนี้ (Limitations)

- **IPv4 + TCP เท่านั้น:** IPv6 และ UDP ที่ส่งมายัง VIP จะถูก `XDP_PASS` (ไม่ถูก Load Balance) ทั้ง XDP และ TC Parse เฉพาะ `ETH_P_IP`
- **ไม่รองรับ IP Fragment และ VLAN Tag:** Fragment ถูกส่งให้เคอร์เนลของ LB ซึ่งไม่มี VIP จึงไม่ถึง Backend
- **Backend คงที่ 2 ตัว และ Hash แบบ `% N`:** หากเพิ่ม/ลด Backend Flow เกือบทั้งหมดจะถูกย้าย (ไม่ใช่ Consistent Hashing) และไม่มี Health Check
- **Flow Table ไม่รู้สถานะ TCP:** Entry ไม่ถูกลบเมื่อ FIN/RST อาศัย LRU ไล่ออกเมื่อเต็ม หาก Flow ถูกไล่ออกกลางการเชื่อมต่อ แพ็กเก็ตถัดไปจาก Client จะสร้าง Entry ใหม่ (ไป Backend เดิมเพราะ Hash เหมือนเดิม) แต่คำตอบจาก Backend ในช่วงนั้นจะไม่ถูก SNAT
- **NAT Mode ต้องให้ LB เป็น Gateway ขากลับ:** Backend ต้องมี Route ไปหา Client ผ่าน LB และทราฟฟิกขากลับทั้งหมดผ่าน LB (ผ่าน Network Stack ปกติ ไม่ใช่ XDP)
- **ตัวเลขประสิทธิภาพ:** แล็บใช้ `veth` + Generic XDP ใน Network Namespace จึงไม่สะท้อนประสิทธิภาพของ Native XDP บนการ์ดแลนจริง หากต้องการตัวเลข PPS ให้วัดบนฮาร์ดแวร์จริง

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์และสร้างไบนารี
```bash
cd phase04-high-speed-networking/week08-tc-loadbalancer
make generate
make build
```

### ขั้นตอนที่ 2: รัน Unit Tests ด้วย `BPF_PROG_TEST_RUN`
```bash
make test   # = go generate + go test -exec sudo -v ./...
```
ไม่ต้องสร้าง Namespace ใด ๆ ผลลัพธ์ที่คาดหวังคือทุก Test ขึ้น `--- PASS` และปิดท้ายด้วย `ok` (ดูผลจริงในหัวข้อ 4.1)

### ขั้นตอนที่ 3: สร้างสภาพแวดล้อมทดสอบ (Client, LB, Backend 0, Backend 1 + Switch)
ทุกอย่างอยู่ใน Network Namespace ที่ขึ้นต้นด้วย `w08-` รวมถึง Bridge ซึ่งอยู่ใน `w08-sw` จึงไม่แตะอินเทอร์เฟซหรือ Routing ของเครื่องโฮสต์เลย Client อยู่คนละ Subnet กับ Backend เพื่อให้คำตอบของ Backend ต้องวิ่งผ่าน LB (Gateway):
```bash
# Namespace ที่ทำหน้าที่เป็น Switch เสมือน (Linux Bridge)
sudo ip netns add w08-sw
sudo ip netns exec w08-sw ip link add br0 type bridge
sudo ip netns exec w08-sw ip link set br0 up

# ฟังก์ชันช่วยสร้าง Node: eth0 อยู่ใน Namespace ของ Node, peer เสียบเข้า br0
add_node() {
    local ns=$1 mac=$2
    sudo ip netns add "$ns"
    sudo ip link add eth0 netns "$ns" type veth peer name "p-${ns#w08-}" netns w08-sw
    sudo ip netns exec w08-sw ip link set "p-${ns#w08-}" master br0 up
    sudo ip netns exec "$ns" ip link set lo up
    sudo ip netns exec "$ns" ip link set eth0 address "$mac"
    sudo ip netns exec "$ns" ip link set eth0 up
    # ปิด TX Checksum Offload เพื่อให้ Checksum ที่ eBPF คำนวณถูกตรวจสอบจริง (ดูหัวข้อ 1.4)
    sudo ip netns exec "$ns" ethtool -K eth0 tx off >/dev/null
}
add_node w08-client 02:00:00:00:10:00
add_node w08-lb     02:00:00:00:01:00
add_node w08-b0     02:00:00:00:02:00
add_node w08-b1     02:00:00:00:03:00

# Client (10.10.2.0/24) ส่งทุกอย่างที่ไป 10.10.1.0/24 (รวม VIP) ผ่าน LB
sudo ip netns exec w08-client ip addr add 10.10.2.10/24 dev eth0
sudo ip netns exec w08-client ip route add 10.10.1.0/24 via 10.10.2.1

# LB มีไอพีทั้งสองฝั่งบน eth0 เดียว และเปิด Forwarding (เฉพาะใน Namespace นี้)
sudo ip netns exec w08-lb ip addr add 10.10.1.1/24 dev eth0
sudo ip netns exec w08-lb ip addr add 10.10.2.1/24 dev eth0
sudo ip netns exec w08-lb sysctl -qw net.ipv4.ip_forward=1
sudo ip netns exec w08-lb sysctl -qw net.ipv4.conf.all.send_redirects=0
sudo ip netns exec w08-lb sysctl -qw net.ipv4.conf.eth0.send_redirects=0

# Backend ส่งคำตอบกลับหา Client ผ่าน LB (จำเป็นสำหรับ Reverse NAT)
for i in 0 1; do
    sudo ip netns exec w08-b$i ip addr add 10.10.1.$((i+2))/24 dev eth0
    sudo ip netns exec w08-b$i ip route add 10.10.2.0/24 via 10.10.1.1
done
```
> ปิด `send_redirects` เพราะ LB Forward แพ็กเก็ตออกทางอินเทอร์เฟซเดียวกับที่รับเข้ามา ซึ่งปกติเคอร์เนลจะส่ง ICMP Redirect บอกให้ Backend คุยกับ Client ตรง ๆ

### ขั้นตอนที่ 4: เปิด HTTP Service บน Backend 0 และ Backend 1
```bash
for i in 0 1; do
    mkdir -p /tmp/w08-www-b$i && echo "Hello from Backend $i" > /tmp/w08-www-b$i/index.html
    sudo ip netns exec w08-b$i python3 -m http.server 80 --bind 10.10.1.$((i+2)) \
        --directory /tmp/w08-www-b$i >/dev/null 2>&1 &
done
```

### ขั้นตอนที่ 5: สั่งรัน eBPF Pipeline (XDP LB + TC Reverse NAT + TC Egress)
รัน Load Balancer ภายใน Namespace `w08-lb` (เปิดเทอร์มินัลแยก):
```bash
sudo ip netns exec w08-lb ./bin/xdp-tc-lb \
  -iface eth0 \
  -xdp-mode generic \
  -vip 10.10.1.100 \
  -backend0-ip 10.10.1.2 \
  -backend0-mac 02:00:00:00:02:00 \
  -backend1-ip 10.10.1.3 \
  -backend1-mac 02:00:00:00:03:00
```

### ขั้นตอนที่ 6: ยิงคำขอจาก Client และสังเกตการกระจายโหลด
```bash
for i in {1..10}; do
  sudo ip netns exec w08-client curl -s --connect-timeout 2 -m 3 http://10.10.1.100/ || echo "request $i FAILED"
done
```
ทุกคำขอต้องได้ข้อความ `Hello from Backend 0` หรือ `Hello from Backend 1` (ไม่มี `FAILED`) ซึ่งพิสูจน์ว่าทั้งขาไป (XDP) และขากลับ (TC Reverse NAT) ทำงาน สัดส่วนระหว่าง Backend ขึ้นกับ Ephemeral Port ที่สุ่มได้ (10 คำขอไม่จำเป็นต้องได้ 50/50 พอดี — การกระจายในระยะยาวตรวจด้วย `TestXDPEvenPortsAreBalanced`)

ตรวจจุดแนบโปรแกรมทั้งสามจุด:
```bash
sudo ip netns exec w08-lb ip link show eth0          # ต้องเห็น xdpgeneric
sudo ip netns exec w08-lb bpftool net show dev eth0  # ต้องเห็น tcx/ingress และ tcx/egress
sudo bpftool map dump name lb_stats
```

### ขั้นตอนที่ 7: คืนค่าและล้างสภาพแวดล้อม
กด `Ctrl+C` ที่หน้าต่าง LB ก่อน แล้ว:
```bash
for ns in w08-client w08-lb w08-b0 w08-b1 w08-sw; do
    sudo ip netns pids $ns 2>/dev/null | xargs -r sudo kill   # หยุด http.server ที่ค้างอยู่
    sudo ip netns del $ns 2>/dev/null
done
rm -rf /tmp/w08-www-b0 /tmp/w08-www-b1
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic x86_64`), clang 21, Go 1.26, bpftool 7.7, cilium/ebpf v0.16.0

### 4.1 ผลลัพธ์ Unit Tests (`make test`)
```text
===> Generating Go bindings from xdp_lb.c and tc_egress.c via bpf2go...
go generate ./...
Compiled phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfel.o
Stripped phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfel.o
Wrote phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfel.go
Compiled phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfeb.o
Stripped phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfeb.o
Wrote phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfeb.go
Compiled phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfel.o
Stripped phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfel.o
Wrote phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfel.go
Compiled phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfeb.o
Stripped phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfeb.o
Wrote phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfeb.go
===> Running BPF_PROG_TEST_RUN unit tests (main_test.go)...
go test -exec sudo -v ./...
=== RUN   TestXDPForwardRewritesToBackend
=== RUN   TestXDPForwardRewritesToBackend/flow_hashed_to_backend_0
=== RUN   TestXDPForwardRewritesToBackend/flow_hashed_to_backend_1
=== RUN   TestXDPForwardRewritesToBackend/data_segment_keeps_valid_checksum
--- PASS: TestXDPForwardRewritesToBackend (0.00s)
    --- PASS: TestXDPForwardRewritesToBackend/flow_hashed_to_backend_0 (0.00s)
    --- PASS: TestXDPForwardRewritesToBackend/flow_hashed_to_backend_1 (0.00s)
    --- PASS: TestXDPForwardRewritesToBackend/data_segment_keeps_valid_checksum (0.00s)
=== RUN   TestXDPEvenPortsAreBalanced
    main_test.go:340: 1000 even-port flows -> backend0=500 backend1=500
--- PASS: TestXDPEvenPortsAreBalanced (0.00s)
=== RUN   TestXDPForwardWithIPOptions
--- PASS: TestXDPForwardWithIPOptions (0.00s)
=== RUN   TestXDPPassesNonLBTraffic
=== RUN   TestXDPPassesNonLBTraffic/tcp_to_non-vip_address
=== RUN   TestXDPPassesNonLBTraffic/backend_reply_(handled_by_TC,_not_XDP)
=== RUN   TestXDPPassesNonLBTraffic/udp_to_vip
=== RUN   TestXDPPassesNonLBTraffic/truncated_tcp_header_to_vip
=== RUN   TestXDPPassesNonLBTraffic/ip_fragment_to_vip
=== RUN   TestXDPPassesNonLBTraffic/ethernet-only_frame
=== RUN   TestXDPPassesNonLBTraffic/ipv6_frame
--- PASS: TestXDPPassesNonLBTraffic (0.00s)
    --- PASS: TestXDPPassesNonLBTraffic/tcp_to_non-vip_address (0.00s)
    --- PASS: TestXDPPassesNonLBTraffic/backend_reply_(handled_by_TC,_not_XDP) (0.00s)
    --- PASS: TestXDPPassesNonLBTraffic/udp_to_vip (0.00s)
    --- PASS: TestXDPPassesNonLBTraffic/truncated_tcp_header_to_vip (0.00s)
    --- PASS: TestXDPPassesNonLBTraffic/ip_fragment_to_vip (0.00s)
    --- PASS: TestXDPPassesNonLBTraffic/ethernet-only_frame (0.00s)
    --- PASS: TestXDPPassesNonLBTraffic/ipv6_frame (0.00s)
=== RUN   TestTCReverseNATRestoresVIP
=== RUN   TestTCReverseNATRestoresVIP/syn-ack
=== RUN   TestTCReverseNATRestoresVIP/http_response
--- PASS: TestTCReverseNATRestoresVIP (0.00s)
    --- PASS: TestTCReverseNATRestoresVIP/syn-ack (0.00s)
    --- PASS: TestTCReverseNATRestoresVIP/http_response (0.00s)
=== RUN   TestTCReverseNATIgnoresUnknownFlows
=== RUN   TestTCReverseNATIgnoresUnknownFlows/backend_traffic_without_flow_entry
=== RUN   TestTCReverseNATIgnoresUnknownFlows/unrelated_host
--- PASS: TestTCReverseNATIgnoresUnknownFlows (0.00s)
    --- PASS: TestTCReverseNATIgnoresUnknownFlows/backend_traffic_without_flow_entry (0.00s)
    --- PASS: TestTCReverseNATIgnoresUnknownFlows/unrelated_host (0.00s)
=== RUN   TestTCEgressPortStats
--- PASS: TestTCEgressPortStats (0.00s)
PASS
ok  	ebpf-noob-to-hero/phase04-high-speed-networking/week08-tc-loadbalancer	0.020s
```

### 4.2 ผลลัพธ์การคอมไพล์และรัน XDP Load Balancer + TC (`./bin/xdp-tc-lb -iface eth0 -xdp-mode generic ...`)
```text
$ make all
===> Generating Go bindings from xdp_lb.c and tc_egress.c via bpf2go...
go generate ./...
Compiled /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfel.o
Stripped /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfel.o
Wrote /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfel.go
Compiled /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfeb.o
Stripped /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfeb.o
Wrote /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/xdplb_bpfeb.go
Compiled /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfel.o
Stripped /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfel.o
Wrote /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfel.go
Compiled /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfeb.o
Stripped /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfeb.o
Wrote /mnt/sda/ebpf/phase04-high-speed-networking/week08-tc-loadbalancer/tcegress_bpfeb.go
===> Building userspace binary bin/xdp-tc-lb...
mkdir -p bin
go build -v -o bin/xdp-tc-lb .
ebpf-noob-to-hero/phase04-high-speed-networking/week08-tc-loadbalancer

--- LB STARTUP (sudo ip netns exec w08-lb ./bin/xdp-tc-lb -iface eth0 -xdp-mode generic -vip 10.10.1.100 ...) ---
======================================================================
 eBPF Dual Pipeline: High-Speed XDP Load Balancer & TC Egress Marker
======================================================================
2026/10/28 22:08:41 [LB Config] Backend #0 registered: IP=10.10.1.2 MAC=02:00:00:00:02:00
2026/10/28 22:08:41 [LB Config] Backend #1 registered: IP=10.10.1.3 MAC=02:00:00:00:03:00
2026/10/28 22:08:41 [LB Config] VIP: 10.10.1.100 (MAC: 02:00:00:00:01:00) active.
2026/10/28 22:08:41 [TC] Attached Reverse NAT (TCX ingress) to eth0 (index 2)
2026/10/28 22:08:41 [XDP] Attached Load Balancer program to eth0 (index 2, mode generic)
2026/10/28 22:08:41 [TC] Attached Egress Classifier (TCX) to eth0 (index 2)

--- CLIENT (10 x curl -s --connect-timeout 2 -m 3 http://10.10.1.100/) ---
Hello from Backend 0
Hello from Backend 1
Hello from Backend 0
Hello from Backend 1
Hello from Backend 0
Hello from Backend 0
Hello from Backend 0
Hello from Backend 0
Hello from Backend 0
Hello from Backend 1

--- BPFTOOL MAP DUMP (sudo bpftool map dump name lb_stats) ---
[{
        "key": 0,
        "value": {
            "rx_packets": 70,
            "forwarded_backend_0": 49,
            "forwarded_backend_1": 21,
            "reverse_nat_packets": 51
        }
    }
]

--- XDP / TCX ATTACHMENTS (ip link show eth0 + bpftool net show dev eth0, in w08-lb) ---
2: eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 02:00:00:00:01:00 brd ff:ff:ff:ff:ff:ff link-netns w08-sw
    prog/xdp id 10350 name xdp_load_balanc tag 61cdf8e14ec46d44 jited
xdp:
eth0(2) generic id 10350

tc:
eth0(2) tcx/ingress tc_reverse_nat prog_id 10349 link_id 3948
eth0(2) tcx/egress tc_egress_prog prog_id 10351 link_id 3950

flow_dissector:

netfilter:

--- DASHBOARD AFTER Ctrl+C / SIGTERM ---
Received signal 'terminated'. Detaching XDP and TC hooks...
=================================================================================
 eBPF XDP Load Balancer & TC Monitor | Interface: eth0 | Time: 22:08:45
=================================================================================
 [ VIP: 10.10.1.100 (XDP_TX Hairpin Forwarding) ]
  Total Ingress Packets:       70
  Forwarded to Backend #0:     49
  Forwarded to Backend #1:     21
  Replies SNAT'd to VIP (TC):  51
  Tracked Flows (LRU):         10

 [ TC Egress Port Telemetry (BPF_MAP_TYPE_HASH) ]
  DEST PORT         PACKETS           BYTES
  ----------------------------------------------------
  Port 58552        5                 544
  Port 58542        6                 610
  Port 58512        5                 544
  Port 58536        5                 544
  Port 58526        5                 544
  Port 58544        5                 544
  Port 58550        5                 544
  Port 58502        5                 544
  Port 58568        5                 544
  Port 58548        5                 544
=================================================================================
 Press Ctrl+C to terminate and detach hooks.
Cleanup complete. Load Balancer and TC Egress stopped.
```
สังเกตว่า:
- `curl` ทั้ง 10 ครั้งสำเร็จ (7 ครั้งไป Backend 0, 3 ครั้งไป Backend 1 — ขึ้นกับพอร์ตที่สุ่มได้ในรอบนั้น)
- `Total Ingress Packets` = 70 คือทุกแพ็กเก็ตจาก Client (SYN, ACK, HTTP GET, FIN ฯลฯ ≈ 7 แพ็กเก็ตต่อการเชื่อมต่อ) และแต่ละการเชื่อมต่อไป Backend เดียวกันตลอด (49 = 7 × 7, 21 = 3 × 7)
- `Replies SNAT'd to VIP (TC)` = 51 คือแพ็กเก็ตขากลับที่ถูกเปลี่ยน Source IP เป็น VIP และ `Tracked Flows` = 10 ตรงกับจำนวนการเชื่อมต่อ
- ตาราง TC Egress แสดงพอร์ตปลายทางเป็น Ephemeral Port ของ Client เพราะแพ็กเก็ต `XDP_TX` ไม่ผ่าน TC Egress มีแต่คำตอบขากลับที่ถูก Forward

---

## 5. Milestone Checklist

- [x] เข้าใจความแตกต่างเชิงสถาปัตยกรรมระหว่าง XDP (`struct xdp_md`) และ TC (`struct __sk_buff`)
- [x] เข้าใจการส่งต่อแพ็กเก็ตความเร็วสูงแบบ Hairpin Routing ด้วยคำสั่ง `XDP_TX` และข้อจำกัดบน `veth`
- [x] อธิบายได้ว่าทำไม DNAT อย่างเดียวไม่พอ และเปรียบเทียบ NAT กับ DSR
- [x] เชี่ยวชาญการคำนวณและอัปเดต Checksum แบบ Incremental ด้วย RFC 1624 และ `bpf_csum_diff` (XDP) เทียบกับ `bpf_l3/l4_csum_replace` (TC)
- [x] พัฒนา L4 Flow-hash Load Balancer พร้อม Connection Tracking (`BPF_MAP_TYPE_LRU_HASH`) ที่แชร์ระหว่าง XDP และ TC
- [x] พัฒนา TC Egress Classifier จำแนกและบันทึกสถิติตาม Destination Port
- [x] ประทับตรา Packet Mark (`skb->mark`) และ QoS Priority ในระดับ Egress
- [x] ใช้งาน `bpf2go` เพื่อคอมไพล์โปรแกรม eBPF หลายตัวในโปรเจกต์เดียว และแนบผ่าน TCX
- [x] เขียน Unit Test ด้วย `BPF_PROG_TEST_RUN` ตรวจทั้ง Verdict, การ Rewrite และ Checksum (`make test`)
- [x] ทดสอบ Load Balancer แบบ End-to-End (`curl` สำเร็จทุกครั้ง) ในเครือข่ายจำลอง 5 Namespaces

---

## 6. แบบฝึกหัดท้ายบท (Exercises)

ทุกข้อให้เพิ่ม Test Case ใน `main_test.go` แล้วรัน `make test` เป็นหลักฐาน และทดสอบ End-to-End ด้วยแล็บในหัวข้อ 3

### ระดับพื้นฐาน
1. **Backend แบบ Dynamic (N ตัว)**
   - *Deliverable:* เพิ่ม `max_entries` ของ `backends` เป็น 16 และเพิ่มแมป `backend_count` (Array 1 ช่อง) ให้ XDP ใช้ `hash % count` แทน `% 2`; เปลี่ยนแฟล็กเป็น `-backend 10.10.1.2=02:00:00:00:02:00` (ใส่ซ้ำได้) และเปลี่ยน Dashboard ให้แสดงตัวนับต่อ Backend (Per-CPU Array)
   - *Verify:* Test ที่ตั้ง 3 Backend แล้วส่ง 3,000 Flow ต้องได้ทุก Backend ≥ 25%; ใส่ `count = 0` ต้องได้ `XDP_PASS`
2. **กรองตาม Service Port**
   - *Deliverable:* เพิ่ม `service_port` ใน `lb_config_t` ให้ LB รับเฉพาะ `VIP:80` ส่วนพอร์ตอื่นที่ส่งมา VIP ให้ `XDP_DROP` และนับใน `lb_stats`
   - *Verify:* Test: SYN ไป `VIP:80` → `XDP_TX`, ไป `VIP:22` → `XDP_DROP`; ในแล็บ `curl http://10.10.1.100:8080/` ต้อง Timeout

### ระดับปานกลาง
3. **รองรับ IPv6 (Dual-stack VIP)**
   - *Deliverable:* Parse `struct ipv6hdr` ทั้งใน XDP และ TC, เพิ่ม VIP/Backend แบบ IPv6 และ `flow_key6` (ที่อยู่ 16 ไบต์); IPv6 ไม่มี Header Checksum แต่ TCP Checksum ยังรวม Pseudo-header ต้องอัปเดตด้วย `bpf_csum_diff` กับที่อยู่ 16 ไบต์ (XDP) และ `bpf_l4_csum_replace` 4 ครั้งหรือ `bpf_csum_diff` + `BPF_F_PSEUDO_HDR` (TC)
   - *Verify:* เปลี่ยน Test `ipv6 frame` ให้คาดหวัง `XDP_TX` และเพิ่มฟังก์ชันตรวจ TCP Checksum แบบ IPv6; ทดสอบจริงด้วย `curl -6 http://[fd00:1::100]/` (อย่าลืม NDP/Route ใน Namespace)
4. **ลบ Flow เมื่อการเชื่อมต่อจบ + Timeout**
   - *Deliverable:* เก็บ `last_seen_ns` (`bpf_ktime_get_ns()`) และสถานะ FIN/RST ใน `flow_value` ให้ TC ลบ Entry เมื่อเห็น FIN จากทั้งสองฝั่งหรือ RST และให้ Go ลบ Flow ที่เงียบเกิน 60 วินาที
   - *Verify:* Test ส่ง SYN → (TC) SYN-ACK → RST แล้วตรวจว่า `flows` ไม่มี Entry นั้น; Dashboard `Tracked Flows` ต้องลดลงหลังจบ `curl`

### ระดับท้าทาย
5. **Consistent Hashing แบบ Maglev**
   - *Deliverable:* สร้างตาราง Lookup ขนาดจำนวนเฉพาะ (เช่น 65537) ใน Go ตามอัลกอริทึมของ Maglev (Eisenbud et al., NSDI 2016) แล้วโหลดลง `BPF_MAP_TYPE_ARRAY`; XDP ใช้ `table[hash % M]` เพื่อเลือก Backend
   - *Verify:* Test ในฝั่ง Go: เมื่อลบ 1 ใน 5 Backend สัดส่วน Flow ที่ "ย้าย Backend" ต้องใกล้ 1/5 (เทียบกับ `% N` ที่ย้ายเกือบทั้งหมด) และใช้ `BPF_PROG_TEST_RUN` ยืนยันว่า XDP เลือก Backend ตรงกับตารางที่คำนวณใน Go
6. **เปลี่ยนเป็น DSR (Direct Server Return) ด้วย IPIP**
   - *Deliverable:* ให้ XDP ห่อแพ็กเก็ตด้วย IPIP Header ใหม่ (`bpf_xdp_adjust_head(ctx, -20)`, outer dst = Backend) โดยไม่แก้ inner `daddr`; Backend สร้าง `ipip` tunnel + ผูก VIP ที่ `lo` + ตั้ง `arp_ignore=1`/`arp_announce=2` แล้วตอบ Client ตรงโดยไม่ผ่าน LB (ตัด `tc_reverse_nat` ออก)
   - *Verify:* Test ตรวจ Outer Header (Protocol 4, IPv4 Checksum ถูก) และ Inner Packet ไม่ถูกแก้; ในแล็บ `tcpdump -i eth0` ใน `w08-lb` ต้อง **ไม่เห็น** แพ็กเก็ตขากลับ แต่ `curl` ยังสำเร็จ
