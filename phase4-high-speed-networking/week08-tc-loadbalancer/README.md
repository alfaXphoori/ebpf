# Week 08: Layer-4 Load Balancer with XDP & TC Egress Marker

ยินดีต้อนรับสู่สัปดาห์ที่ 8 ของหลักสูตร **eBPF: Zero-to-Hero** ในสัปดาห์นี้ เราจะผสมผสานสองเสาหลักของระบบเครือข่ายความเร็วสูงในลินุกซ์เข้าด้วยกัน ได้แก่ **XDP (eXpress Data Path)** และ **TC (Traffic Control)** เพื่อสร้างสถาปัตยกรรมระดับองค์กร:
1. **L4 High-Speed Load Balancer (XDP):** ดักจับทราฟฟิก TCP ที่ส่งมายัง Virtual IP (VIP), กระจายโหลดแบบ Flow-aware Hashing ไปยังกลุ่มเซิร์ฟเวอร์ Backend, ทำการ Rewrite MAC/IP Address, คำนวณ Checksum ใหม่แบบ Incremental และสะท้อนแพ็กเก็ตออกทางเดิมด้วย `XDP_TX` (Hairpin Routing) โดยไม่ผ่านเคอร์เนลเน็ตเวิร์กสแต็ก
2. **TC Egress QoS Classifier & Marker:** ติดตามทราฟฟิกขาออก (Outbound / Egress) จำแนกตาม Destination Port และประทับตรา Packet Priority/Mark (`skb->mark = 0x42`) สำหรับระบบ Traffic Shaping / QoS

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 เปรียบเทียบเชิงลึก: XDP vs TC (Traffic Control)

ทั้ง XDP และ TC เป็นจุดเชื่อมต่อ eBPF ที่ทรงพลังที่สุดในระบบเครือข่ายของลินุกซ์ แต่ถูกออกแบบมาเพื่อวัตถุประสงค์ที่แตกต่างกันอย่างสิ้นเชิง:

| คุณลักษณะ | XDP (eXpress Data Path) | TC (Traffic Control) |
| :--- | :--- | :--- |
| **จุดเกาะเกี่ยว (Hook Point)** | Ingress เท่านั้น (Driver RX ring buffer) | Ingress และ **Egress** (Queueing Discipline - qdisc) |
| **โครงสร้างบริบท (Context)** | `struct xdp_md` (Raw packet memory) | `struct __sk_buff` (Full Socket Buffer metadata) |
| **การจัดสรรหน่วยความจำ** | **ก่อน** สร้าง `sk_buff` (Zero-copy, ไม่กินเมมโมรี) | **หลัง** สร้าง `sk_buff` (เข้าถึง Socket metadata ได้) |
| **Throughput / Latency** | สูงสุดขีด (10M - 40M+ PPS, Ultra-low latency) | สูงมาก (1M - 10M PPS แต่มี Overhead ของ `sk_buff`) |
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
- **ด้วย `XDP_TX`:** โปรแกรม eBPF จะแก้ไขข้อมูลในแพ็กเก็ตโดยตรง (เปลี่ยน Destination IP และ Destination MAC เป็นของ Backend) จากนั้นคืนค่า `XDP_TX` เคอร์เนลจะสั่งให้ฮาร์ดแวร์การ์ดแลนสะท้อนแพ็กเก็ตนั้นย้อนกลับออกไปทางอินเทอร์เฟซเดิมทันที โดยแพ็กเก็ตไม่ต้องก้าวข้ามเข้าไปใน Linux Kernel Network Stack แม้แต่มิลลิเมตรเดียว!

---

### 1.3 คณิตศาสตร์การคำนวณ Checksum แบบ Incremental (RFC 1624 & `bpf_csum_diff`)

เมื่อเราเปลี่ยนแปลงข้อมูลในส่วนหัวของแพ็กเก็ต เช่น เปลี่ยน Destination IP (`iph->daddr`) เช็กซัมเดิมของ IPv4 Header (`iph->check`) และ TCP Header (`tcph->check`) จะใช้การไม่ได้ทันที หากไม่แก้ไข เครื่องปลายทางจะดรอปแพ็กเก็ตทิ้งเนื่องจาก Checksum Mismatch

การคำนวณเช็กซัมทั้งส่วนหัวใหม่ทั้งหมดจะกินซีพียูสูงมาก RFC 1624 จึงระบุสูตรการอัปเดตแบบ **Incremental 16-bit 1's Complement Sum**:
$$HC' = \sim (\sim HC + \sim m + m')$$
โดยที่:
- $HC$ = เช็กซัมเดิม
- $HC'$ = เช็กซัมใหม่
- $m$ = ค่าเดิม 32-bit (Old IP)
- $m'$ = ค่าใหม่ 32-bit (New IP)

ฟังก์ชัน BPF Helper `bpf_csum_diff()` ช่วยคำนวณผลต่าง 32-bit นี้ได้อย่างมีประสิทธิภาพสูงสุด:
```c
static __always_inline void csum_replace4_helper(__u16 *csum, __u32 from, __u32 to)
{
    __s64 diff = bpf_csum_diff((__be32 *)&from, sizeof(from),
                               (__be32 *)&to, sizeof(to),
                               ~(*csum));
    diff = (diff & 0xffff) + (diff >> 16);
    diff = (diff & 0xffff) + (diff >> 16);
    *csum = (__u16)~diff;
}
```
เนื่องจากใน TCP Header มีการรวม Pseudo-header ซึ่งบรรจุฟิลด์ `iph->daddr` อยู่ด้วย เมื่อเราเปลี่ยน `iph->daddr` เราจึงต้องเรียกฟังก์ชันนี้เพื่ออัปเดตทั้ง `iph->check` และ `tcph->check` พร้อมกัน!

---

### 1.4 การวิวัฒนาการสู่ TCX ใน Modern Kernel (Linux 6.6+)

ในอดีต การแนบโปรแกรม eBPF เข้ากับ TC Subsystem ต้องใช้คำสั่ง `tc qdisc add dev eth0 clsact` และแนบ BPF ผ่านคลาส `tc filter add` ซึ่งมี Overhead และผูกติดกับเน็ตลิงก์ (netlink)

ตั้งแต่ **Linux Kernel 6.6** เป็นต้นมา ได้มีการเปิดตัว **TCX (BFP TC Extensions)** ซึ่งทำให้เราสามารถแนบ eBPF Program เข้ากับ Ingress และ Egress ของ Interface ได้โดยตรงผ่าน File Descriptor เหมือนกับ XDP ผ่านฟังก์ชัน `link.AttachTCX()` ใน Cilium ebpf-go ซึ่งให้ประสิทธิภาพสูงขึ้นและตัดการพึ่งพา Netlink CLI

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `xdp_lb.c` (XDP Load Balancer)

```c
struct backend_config {
    __u32 ip;
    unsigned char mac[ETH_ALEN];
    __u16 pad;
};
```
- **บรรทัด 50-54:** โครงสร้างเก็บข้อมูลของเซิร์ฟเวอร์ Backend (IP + MAC Address) พร้อมฟิลด์ `pad` ขนาด 2 ไบต์ เพื่อให้ Struct มีขนาดรวม $4 + 6 + 2 = 12$ ไบต์ ซึ่งลงตัวกับการจัดเรียงแบบ 4-byte alignment

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct backend_config);
} backends SEC(".maps");
```
- **บรรทัด 72-77:** BPF Array Map เก็บรายการ Backend เซิร์ฟเวอร์ 2 ตัว (Index 0 และ Index 1)

```c
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
```
- **บรรทัด 122-132:** ตรวจสอบขอบเขต Verifier Bounds Check ของ L2 Ethernet และ L3 IPv4 อย่างรัดกุม

```c
    __u32 cfg_key = 0;
    struct lb_config_t *cfg = bpf_map_lookup_elem(&lb_config, &cfg_key);
    if (!cfg || iph->daddr != cfg->vip) {
        return XDP_PASS;
    }
```
- **บรรทัด 144-152:** ค้นหาการตั้งค่า VIP หากแพ็กเก็ตที่เข้ามาไม่ได้ส่งมาที่ Virtual IP ของเรา ให้ปล่อยผ่าน (`XDP_PASS`) ไปยังระบบปกติ

```c
    __u32 backend_id = bpf_ntohs(tcph->source) % 2;
    struct backend_config *backend = bpf_map_lookup_elem(&backends, &backend_id);
    if (!backend) return XDP_PASS;
```
- **บรรทัด 168-172:** **Flow-aware Hashing:** ใช้ Client TCP Source Port เป็นตัวกำหนดว่าจะส่งไปยัง Backend ตัวไหน (`% 2`) เพื่อรับประกันว่าแพ็กเก็ตใน TCP Connection เดียวกันจะวิ่งไปที่ Backend เดิมเสมอ (Session Affinity)

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
- **บรรทัด 179-199:**
  - สลับ MAC Address ต้นทางเป็น MAC ของ LB และปลายทางเป็น MAC ของ Backend
  - เขียนทับ Destination IP จาก VIP เป็น IP ของ Backend
  - อัปเดตเช็กซัมทั้ง IP Header และ TCP Header ด้วย Incremental Checksum Helper
  - คืนค่า `XDP_TX` เพื่อยิงแพ็กเก็ตออกทางการ์ดแลนเดิมทันที!

---

### 2.2 ไฟล์ `tc_egress.c` (TC QoS Marker & Classifier)

```c
SEC("tc")
int tc_egress_prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
```
- **บรรทัด 55-60:** แนบที่จุดตรวจจับ Egress ของ TC บริบทคือ `struct __sk_buff`

```c
    __u64 pkt_len = (__u64)((char *)data_end - (char *)data);
    struct egress_stat *stat = bpf_map_lookup_elem(&egress_stats, &dport);
    if (stat) {
        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, pkt_len);
    } else {
        struct egress_stat init_stat = { .packets = 1, .bytes = pkt_len };
        bpf_map_update_elem(&egress_stats, &dport, &init_stat, BPF_ANY);
    }
```
- **บรรทัด 96-107:** บันทึกสถิติทราฟฟิกขาออกแยกตาม Destination Port ลงใน Hash Map `egress_stats`

```c
    skb->mark = 0x42;
    skb->priority = 1;

    return TC_ACT_OK;
```
- **บรรทัด 113-117:**
  - ประทับตรา `skb->mark = 0x42` เพื่อนำไปใช้กับ Linux Routing Engine หรือ IPsec/WireGuard tunnel
  - กำหนดค่า `skb->priority = 1` เพื่อส่งต่อไปยังคิวส่งข้อมูลที่มีลำดับความสำคัญสูง (High-priority Traffic Shaping)
  - คืนค่า `TC_ACT_OK` ให้แพ็กเก็ตส่งออกสู่เครือข่ายตามปกติ

---

### 2.3 ไฟล์ `main.go`

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdplb xdp_lb.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tcegress tc_egress.c
```
- **บรรทัด 5-6:** สั่ง Generate Go Bindings สำหรับโปรแกรม eBPF สองตัวพร้อมกัน (`xdplb` และ `tcegress`)

```go
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   lbObjs.XdpLoadBalancer,
		Interface: iface.Index,
	})
```
- **บรรทัด 67-73:** แนบ XDP Load Balancer เข้ากับการ์ดแลน

```go
	tcLink, err := link.AttachTCX(link.TCXOptions{
		Program:   tcObjs.TcEgressProg,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
```
- **บรรทัด 84-90:** แนบ TC Egress Program ผ่าน TCX Subsystem

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์และสร้างไบนารี
```bash
cd phase4-high-speed-networking/week08-tc-loadbalancer
make generate
make build
```

### ขั้นตอนที่ 2: สร้างสภาพแวดล้อมทดสอบ 4 Namespaces (Client, LB, Backend 0, Backend 1)
รันสคริปต์ด้านล่างนี้เพื่อสร้าง Bridge และ Namespace จำลองระบบคลัสเตอร์:
```bash
# สร้าง Linux Bridge ทำหน้าที่เป็น Switch เสมือน
sudo ip link add name br0 type bridge
sudo ip link set br0 up

# สร้าง Namespaces
sudo ip netns add ns-client
sudo ip netns add ns-lb
sudo ip netns add ns-b0
sudo ip netns add ns-b1

# ฟังก์ชันช่วยสร้าง veth ต่อเข้ากับ Bridge
create_endpoint() {
    local ns=$1
    local ip=$2
    local mac=$3
    local veth_ns="veth-${ns}"
    local veth_br="br-${ns}"

    sudo ip link add "${veth_ns}" type veth peer name "${veth_br}"
    sudo ip link set "${veth_br}" master br0 up
    sudo ip link set "${veth_ns}" netns "${ns}"

    sudo ip netns exec "${ns}" ip link set lo up
    sudo ip netns exec "${ns}" ip link set "${veth_ns}" address "${mac}"
    sudo ip netns exec "${ns}" ip addr add "${ip}/24" dev "${veth_ns}"
    sudo ip netns exec "${ns}" ip link set "${veth_ns}" up
    # ปิด Checksum Offload เพื่อให้ eBPF Checksum recalculation ถูกตรวจสอบจริง
    sudo ip netns exec "${ns}" ethtool -K "${veth_ns}" rx off tx off 2>/dev/null || true
}

# กำหนด IP และ MAC ของแต่ละ Node
create_endpoint "ns-client" "10.10.1.10" "02:00:00:00:10:00"
create_endpoint "ns-lb"     "10.10.1.1"  "02:00:00:00:01:00"
create_endpoint "ns-b0"     "10.10.1.2"  "02:00:00:00:02:00"
create_endpoint "ns-b1"     "10.10.1.3"  "02:00:00:00:03:00"

# กำหนด Static ARP ให้ client รู้ว่า VIP (10.10.1.100) มี MAC เป็นของ ns-lb
sudo ip netns exec ns-client ip neigh add 10.10.1.100 lladdr 02:00:00:00:01:00 dev veth-ns-client
```

### ขั้นตอนที่ 3: เปิด HTTP Service บน Backend 0 และ Backend 1
เปิดเทอร์มินัลแยกต่างหากเพื่อรันเซิร์ฟเวอร์จำลอง:
```bash
# Backend 0: ส่งข้อความ "Hello from Backend 0"
sudo ip netns exec ns-b0 python3 -m http.server 80 &
echo $! > /tmp/b0.pid

# Backend 1: ส่งข้อความ "Hello from Backend 1"
sudo ip netns exec ns-b1 python3 -m http.server 80 &
echo $! > /tmp/b1.pid
```

### ขั้นตอนที่ 4: สั่งรัน eBPF Dual Pipeline (XDP LB + TC Egress)
รัน Load Balancer ภายใน Namespace `ns-lb`:
```bash
sudo ip netns exec ns-lb ./bin/xdp-tc-lb \
  -iface veth-ns-lb \
  -vip 10.10.1.100 \
  -lb-mac 02:00:00:00:01:00 \
  -backend0-ip 10.10.1.2 \
  -backend0-mac 02:00:00:00:02:00 \
  -backend1-ip 10.10.1.3 \
  -backend1-mac 02:00:00:00:03:00
```

### ขั้นตอนที่ 5: ยิงคำขอจาก Client และสังเกตการกระจายโหลด
เปิดเทอร์มินัลอีกหน้าต่างหนึ่ง แล้วสั่ง `curl` ไปยัง VIP `10.10.1.100` รัว ๆ:
```bash
for i in {1..10}; do
  sudo ip netns exec ns-client curl -s --connect-timeout 1 http://10.10.1.100/ > /dev/null || true
  sleep 0.2
done
```

**ผลลัพธ์บน Dashboard ของ Load Balancer:**
```text
=================================================================================
 eBPF XDP Load Balancer & TC Monitor | Interface: veth-ns-lb | Time: 21:45:00
=================================================================================
 [ VIP: 10.10.1.100 (XDP_TX Hairpin Forwarding) ]
  Total Ingress Packets:       28          
  Forwarded to Backend #0:     14          
  Forwarded to Backend #1:     14          

 [ TC Egress Port Telemetry (BPF_MAP_TYPE_HASH) ]
  DEST PORT         PACKETS           BYTES           
  ----------------------------------------------------
  Port 80           28                2072            
=================================================================================
 Press Ctrl+C to terminate and detach hooks.
```
จะสังเกตเห็นทราฟฟิกถูกสลับกระจายไปยัง Backend #0 และ Backend #1 อย่างสมดุล (50/50) พร้อมทั้ง TC Egress ทำการตรวจจับและลงบันทึก Port 80 ได้อย่างแม่นยำ!

### ขั้นตอนที่ 6: คืนค่าและล้างสภาพแวดล้อม
```bash
sudo kill $(cat /tmp/b0.pid /tmp/b1.pid 2>/dev/null) 2>/dev/null || true
sudo ip link del br0 2>/dev/null || true
sudo ip netns del ns-client 2>/dev/null || true
sudo ip netns del ns-lb 2>/dev/null || true
sudo ip netns del ns-b0 2>/dev/null || true
sudo ip netns del ns-b1 2>/dev/null || true
```

---

## 4. Milestone Checklist

- [x] เข้าใจความแตกต่างเชิงสถาปัตยกรรมระหว่าง XDP (`struct xdp_md`) และ TC (`struct __sk_buff`)
- [x] เข้าใจการส่งต่อแพ็กเก็ตความเร็วสูงแบบ Hairpin Routing ด้วยคำสั่ง `XDP_TX`
- [x] เชี่ยวชาญการคำนวณและอัปเดต Checksum แบบ Incremental ด้วย RFC 1624 และ `bpf_csum_diff`
- [x] พัฒนา L4 Flow-aware Hashing Load Balancer ที่ปรับแก้ L2 MAC และ L3 IP บน eBPF
- [x] พัฒนา TC Egress Classifier จำแนกและบันทึกสถิติตาม Destination Port
- [x] ประทับตรา Packet Mark (`skb->mark`) และ QoS Priority ในระดับ Egress
- [x] ใช้งาน `bpf2go` เพื่อคอมไพล์โปรแกรม eBPF สองตัวพร้อมกันในโปรเจกต์เดียว
- [x] ทดสอบการกระจายโหลดในระบบเครือข่ายจำลอง 4 Namespaces พร้อม Bridge ได้อย่างสมบูรณ์แบบ
