# สัปดาห์ที่ 02: เส้นทางของแพ็กเก็ตใน Linux Kernel Stack และ Linux Bridge

ยินดีต้อนรับสู่ **Week 02** ของหลักสูตร **eBPF Zero to Hero**!
ในสัปดาห์นี้ เราจะเจาะลึกเข้าไปใน "เครื่องยนต์ภายใน" ของเคอร์เนล Linux: **เมื่อแพ็กเก็ตเดินทางมาถึงการ์ดแลน (NIC) หรือพอร์ตเสมือน (veth) เคอร์เนลประมวลผลมันอย่างไรตั้งแต่ระดับ Hardware Interrupt จนถึง User Space Socket?**

เราจะสร้างห้องทดลองเครือข่ายที่มี **Linux Bridge (`br0`)** ทำหน้าที่เป็น Virtual L2 Switch เชื่อมต่อ Network Namespaces 3 ชุด (`w02-ns1`, `w02-ns2`, `w02-ns3`) เข้าด้วยกัน โดยตัว Bridge อยู่ใน namespace ของมันเองชื่อ `w02-sw` (ทำหน้าที่แทน "Host/Gateway") เพื่อไม่ให้ Lab ไปแตะ interface, route หรือ sysctl ของเครื่องจริง พร้อมทั้งใช้เครื่องมือวินิจฉัยเคอร์เนล เช่น `strace`, `/proc/net/softnet_stat`, `/proc/softirqs` และ `perf` เพื่อสังเกตการณ์พฤติกรรมของ **`sk_buff`**, **NAPI**, และ **SoftIRQ** ก่อนที่เราจะเข้าใจว่าทำไม **eBPF / XDP** จึงปฏิวัติประสิทธิภาพของระบบเครือข่ายด้วยการบายพาสสแตกเหล่านี้!

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 วงจรชีวิตของแพ็กเก็ต (Packet Lifecycle) ใน Linux Kernel Stack

เมื่อข้อมูลเดินทางเข้าสู่ระบบคอมพิวเตอร์ผ่านทาง NIC (Network Interface Card) เส้นทางการประมวลผลของเคอร์เนลจะแบ่งออกเป็น 2 ช่วงใหญ่ คือ **Top Half (Hardware Interrupt)** และ **Bottom Half (Software Interrupt - SoftIRQ)**:

```
[ Physical Network Wire / veth ]
              |
              v
     +-----------------+
     | NIC Hardware    |  1. รับสัญญาณไฟฟ้า/แสง เขียนข้อมูลลง Host RAM ผ่าน DMA
     +-----------------+     (Direct Memory Access) เข้าสู่ RX Ring Buffer
              |
              v (Hardware Interrupt / Top Half)
     +-----------------+
     | CPU Hard IRQ    |  2. CPU รับสัญญาณขัดจังหวะ (Hard IRQ), สั่งปิด Interrupt บน NIC
     +-----------------+     และสั่ง Schedule NAPI Poll (ส่งต่อให้ Bottom Half)
              |
              v (SoftIRQ: NET_RX_SOFTIRQ)
     +-----------------+
     | NAPI Poll Loop  |  3. เคอร์เนลวนลูปอ่านแพ็กเก็ตจาก RX Ring Buffer ตาม Budget (เช่น 64 pkts)
     +-----------------+     สร้างโครงสร้างข้อมูล "struct sk_buff" ให้กับทุกแพ็กเก็ต
              |
              |---> [ จุดที่ XDP (eBPF) เข้ามาดักจับ! ก่อน sk_buff ถูกสร้าง ]
              v
     +-----------------+
     | L2 Processing   |  4. ถอดรหัส Ethernet Frame, ตรวจสอบว่าเป็น Bridge Interface หรือไม่
     | (br_handle_frame)     (ถ้าเป็น Bridge จะค้นตาราง FDB แล้ว Switch ไปยังพอร์ตปลายทาง)
     +-----------------+
              |
              v
     +-----------------+
     | L3 IP Layer     |  5. ip_rcv() ตรวจสอบ Checksum, ทำ Routing Decision (FORWARD หรือ LOCAL IN)
     | (Netfilter /    |     ผ่าน Netfilter Hooks (PREROUTING, INPUT)
     |  iptables)      |
     +-----------------+
              |
              v
     +-----------------+
     | L4 Transport    |  6. tcp_v4_rcv() / udp_rcv() ตรวจสอบ TCP State Machine, Window, Sequence
     | (TCP / UDP)     |     และนำข้อมูลใส่ลงใน Socket Receive Queue ของโปรเซส
     +-----------------+
              |
              v
     +-----------------+
     | User Space App  |  7. โปรเซสผู้รับตื่นจาก epoll_wait() และเรียก recvmsg() / read()
     | (Socket Read)   |     คัดลอกข้อมูลจาก Kernel Memory สู่ User Memory Buffer (Data Copy)
     +-----------------+
```

---

### 1.2 โครงสร้าง `struct sk_buff` (Socket Buffer) และ Overhead มหาศาล

ใน Linux Kernel แพ็กเก็ตเครือข่ายทุกตัวจะถูกห่อหุ้มด้วยโครงสร้างภาษาซีที่ชื่อว่า **`struct sk_buff`** (นิยามอยู่ใน `<linux/skbuff.h>`):
- **ขนาด Metadata**: `sk_buff` ตัวเปล่าๆ มีขนาด **232 ไบต์** บน Linux 7.0 x86_64 (วัดจริงด้วย `sudo bpftool btf dump file /sys/kernel/btf/vmlinux | grep "STRUCT 'sk_buff'"` -> `size=232`) ไม่รวมพื้นที่เก็บข้อมูลแพ็กเก็ตจริงและ `skb_shared_info` ที่อยู่ท้าย data buffer
- **Headroom & Tailroom**: เคอร์เนลต้องจองพื้นที่ว่างด้านหน้า (`headroom`) และด้านหลัง (`tailroom`) เพื่อให้โปรโตคอลต่างๆ สามารถ push/pop header ได้โดยไม่ต้อง reallocate หน่วยความจำ
- **ปัญหาด้าน Performance**:
  1. การจัดสรร (Allocate) และคืนหน่วยความจำ (Free) `sk_buff` ทุกแพ็กเก็ต ซึ่งบนลิงก์ 10-100 Gbps อาจสูงถึงหลายล้านครั้งต่อวินาที สร้างภาระ Cache-miss และ Memory Bandwidth อย่างมีนัยสำคัญ
  2. การวิ่งผ่านเลเยอร์ Netfilter, Routing Table, และ Socket Lock กินเวลา CPU Cycle มหาศาล

> [!IMPORTANT]
> **ทำไม eBPF / XDP ถึงเร็วกว่า Linux Network Stack ดั้งเดิมได้หลายเท่า (สำหรับงานบางประเภท)?**
> **XDP (eXpress Data Path)** ในโหมด Native ทำงานที่ระดับ Device Driver โดยตรง **ก่อนที่เคอร์เนลจะจัดสรร `sk_buff`**! หาก XDP ตรวจพบว่าเป็น DDoS หรือแพ็กเก็ตที่ไม่ต้องการ มันสามารถสั่ง `XDP_DROP` ทิ้งไปได้ทันทีโดยไม่เสียค่าใช้จ่ายของสแตกที่เหลือ
>
> **ตัวเลขต้องอ่านอย่างระมัดระวัง**: งานวิจัยต้นฉบับของ XDP (Høiland-Jørgensen et al., *"The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel"*, ACM CoNEXT 2018) รายงานอัตรา packet drop ระดับ **หลายสิบล้านแพ็กเก็ตต่อวินาทีต่อคอร์** บน NIC 100G ในการทดลองของผู้วิจัย ซึ่งเร็วกว่าการ drop ด้วย iptables/สแตกปกติ **หลายเท่า** — แต่ตัวเลขนี้ขึ้นกับ CPU, NIC/driver, ขนาดแพ็กเก็ต และงานที่ทำ (drop ล้วนๆ ได้ประโยชน์สูงสุด ส่วนงานที่ต้องส่งต่อขึ้นสแตกหรือใช้ Generic XDP บน `veth` อย่างใน Lab นี้จะได้ประโยชน์น้อยกว่ามาก) ควรตรวจสอบตัวเลขจาก paper ต้นฉบับ และวัดบน workload ของตัวเองเสมอ

---

### 1.3 Linux Bridge (`br0`) และ Forwarding Database (FDB)
- **Linux Bridge** ทำงานเสมือนเป็น **Virtual Layer 2 Switch** ภายในเคอร์เนล
- เมื่อมีเฟรมเข้ามาที่ Bridge Port ฟังก์ชัน `br_handle_frame()` ในเคอร์เนลจะทำงาน:
  1. **MAC Learning**: บันทึก Source MAC Address และพอร์ตที่มาลงในตาราง **FDB (Forwarding Database)**
  2. **FDB Lookup**: ค้นหา Destination MAC Address ใน FDB:
     - หากพบในตาราง: ส่งเฟรมออกไปยังพอร์ตนั้นเพียงพอร์ตเดียว (Unicast Forwarding)
     - หากไม่พบในตาราง (Unknown Unicast) หรือเป็น Broadcast (`ff:ff:ff:ff:ff:ff`): กระจายเฟรมออกไปยังทุกพอร์ตของ Bridge (Flooding)

---

### 1.4 การตรวจสอบเคอร์เนลผ่าน `/proc/net/softnet_stat`
ไฟล์ `/proc/net/softnet_stat` ใน Linux รายงานสถิติการทำงานของ NAPI และ SoftIRQ แยกตามราย CPU Core โดยแต่ละคอลัมน์มีความหมายดังนี้:
1. **คอลัมน์ 1 (Processed)**: จำนวนเฟรมทั้งหมดที่ CPU Core นั้นประมวลผลผ่าน NAPI Loop
2. **คอลัมน์ 2 (Dropped)**: จำนวนแพ็กเก็ตที่ถูกเคอร์เนลทิ้งเนื่องจาก Input Queue (`netdev_max_backlog`) เต็ม
3. **คอลัมน์ 3 (Time Squeeze)**: จำนวนครั้งที่ `net_rx_action()` ต้องหยุดรอบการทำงานทั้งที่ยังมีแพ็กเก็ตค้าง เพราะใช้ **Budget หมด** — คือประมวลผลครบ `net.core.netdev_budget` แพ็กเก็ต (ค่าเริ่มต้น 300) หรือใช้เวลาเกิน `net.core.netdev_budget_usecs` (ค่าเริ่มต้น 2000 µs) ในรอบนั้น เพื่อป้องกันไม่ให้ SoftIRQ ผูกขาด CPU (แยกจาก "weight" ต่อ NAPI instance ซึ่งปกติคือ 64 แพ็กเก็ต / `net.core.dev_weight`) — ตรวจค่าบนเครื่องคุณด้วย `sysctl net.core.netdev_budget net.core.netdev_budget_usecs net.core.dev_weight`
4. **คอลัมน์อื่นๆ**: เคอร์เนลรุ่นใหม่มีคอลัมน์เพิ่มขึ้นเรื่อยๆ (บน Linux 7.0 มี 15 คอลัมน์ โดย **คอลัมน์ 13 คือหมายเลข CPU จริง** — สำคัญเมื่อมี CPU offline เพราะเลขบรรทัดจะไม่ตรงกับเลข CPU)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### สคริปต์จำลองห้องทดลอง: `bridge_router_lab.sh`

```
+-----------------------------------------+
| netns w02-sw   (แทน "Host/Gateway")      |
|   Linux Bridge: br0 (10.20.0.1/24)      |
+---------+-----------+-----------+-------+
          |           |           |
      veth-br1    veth-br2    veth-br3
          |           |           |
      veth-ns1    veth-ns2    veth-ns3
    +---------+ +---------+ +---------+
    | w02-ns1 | | w02-ns2 | | w02-ns3 |
    |   .11   | |   .12   | |   .13   |
    +---------+ +---------+ +---------+
```

> **ทำไม Bridge ไม่อยู่บน Host?** หากสร้าง `br0` ใน Host (root) Namespace สคริปต์จะไปเพิ่ม route `10.20.0.0/24` และแก้ sysctl ของเครื่องจริง และบนเครื่องที่มี Docker ทราฟฟิกที่ผ่าน Bridge อาจถูก `br_netfilter` ส่งเข้า iptables chain `FORWARD` ซึ่ง Docker ตั้ง policy เป็น `DROP` ทำให้ ping ข้าม namespace ไม่ผ่านแบบงงๆ การย้าย Bridge เข้า namespace `w02-sw` จึงทั้งปลอดภัยและได้ผลลัพธ์ที่ทำซ้ำได้ ส่วนแนวคิด L2 Switching ยังเหมือนเดิมทุกประการ

#### การสร้าง Switch Namespace และ Linux Bridge
```bash
ip netns add "${HUB_NS}"                         # w02-sw
hub ip link set lo up                            # hub() = ip netns exec w02-sw ...
hub ip link add name "${BRIDGE}" type bridge
hub ip addr add "${BRIDGE_IP}" dev "${BRIDGE}"
hub ip link set "${BRIDGE}" up
```
- **คำอธิบาย**:
  - `hub()` เป็นฟังก์ชันช่วยที่ห่อ `ip netns exec w02-sw` ทุกคำสั่งที่ขึ้นต้นด้วย `hub` จึงทำงานภายใน Switch Namespace
  - `type bridge`: สั่งให้เคอร์เนลสร้าง Virtual Network Device ชนิด Bridge ชื่อ `br0`
  - `ip addr add 10.20.0.1/24 dev br0`: กำหนด IP Address ให้กับตัว Bridge เพื่อให้ทำหน้าที่เป็น Default Gateway ของวงเครือข่ายเสมือนนี้ได้

#### การผูกพอร์ตเสมือน (`veth`) เข้ากับ Bridge
```bash
ip link add "${veth_ns}" netns "${ns}" type veth peer name "${veth_br}" netns "${HUB_NS}"
hub ip link set "${veth_br}" master "${BRIDGE}"
hub ip link set "${veth_br}" up
```
- **คำอธิบาย**:
  - สร้างท่อเชื่อมต่อ `veth-nsX` <-> `veth-brX` โดยให้แต่ละปลาย "เกิด" ใน namespace ปลายทางทันที (`netns ...` ทั้งสองฝั่ง) จึงไม่มีชื่อ interface โผล่ใน Host เลยแม้ชั่วขณะ
  - `ip link set veth-brX master br0`: ทำการผูก (Enslave) อินเทอร์เฟซ `veth-brX` เข้าเป็นพอร์ตหนึ่งของ Bridge `br0` เสมือนการเสียบสาย LAN เข้ากับสวิตช์
  - `sysctl net.ipv4.ip_forward` เป็นค่า **ต่อ namespace** สคริปต์เปิดไว้เฉพาะใน `w02-sw` (เผื่อทำแบบฝึกหัด routing) โดยไม่กระทบค่าของ Host — สำหรับ L2 bridging ล้วนๆ ไม่จำเป็นต้องเปิด

#### การตรวจสอบตาราง FDB และ Interface Counters
```bash
hub bridge fdb show br "${BRIDGE}"
hub ip -s link show dev "${BRIDGE}"
```
- **คำอธิบาย**:
  - `bridge fdb show br br0`: แสดงตาราง MAC Address ทั้งหมดของ Bridge `br0` (สคริปต์กรองรายการ `permanent` ซึ่งเป็น MAC ของพอร์ตเองออก เหลือเฉพาะที่เรียนรู้มา)
  - `ip -s link`: แสดงสถิติ RX/TX Packets, Bytes, Dropped, และ Errors ของอินเทอร์เฟซในระดับเคอร์เนล

#### การสืบค้นพฤติกรรม System Call ด้วย `strace`
```bash
ip netns exec w02-ns1 strace -f -e trace=socket,sendto,recvmsg,close -T -- ping -c 1 -W 1 10.20.0.12
```
- **คำอธิบาย**:
  - `-e trace=socket,sendto,recvmsg,close`: กรองดูเฉพาะ System Call 4 ตัวนี้ (ถ้าต้องการทุก syscall ที่เกี่ยวกับเครือข่ายใช้ `-e trace=%network`)
  - `-T`: แสดงเวลาที่ใช้ในแต่ละ syscall ต่อท้ายบรรทัดในรูป `<วินาที>` เช่น `<0.000034>` = 34 ไมโครวินาที
  - `-f`: ตามไปยัง child process/thread ด้วย
  - คำสั่งนี้ทำให้เราเห็นว่า Application ร้องขอ Socket Descriptors และส่งข้อมูลผ่าน `sendto()` อย่างไรในระดับ User-Kernel Boundary
  - **ข้อสังเกต**: `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = -1 EACCES` เกิดเพราะ namespace ใหม่มี `net.ipv4.ping_group_range = 1 0` (ไม่อนุญาต unprivileged ICMP socket) `ping` จึงถอยไปใช้ `SOCK_RAW` แทน

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

> **ความปลอดภัยของ Lab**: ทุกอย่างอยู่ใน namespace `w02-sw`, `w02-ns1..3` เท่านั้น ไม่แตะ NIC, route, iptables หรือ sysctl ของ Host และ `clean` จะลบทุกอย่างทิ้งหมด (การอ่าน `/proc/net/softnet_stat` และ `/proc/softirqs` ในโหมด `trace` เป็นการอ่านค่าระดับระบบอย่างเดียว)

### ขั้นตอนที่ 1: ติดตั้งโทโพโลยีเครือข่ายเสมือน 3 Namespaces
รันคำสั่ง setup ด้วยสิทธิ์ `sudo`:
```bash
sudo ./bridge_router_lab.sh setup
```

**ผลลัพธ์ที่ได้** (ส่วนต้น):
```text
===> Building Multi-Namespace Bridge Topology (w02-ns1 w02-ns2 w02-ns3 <-> w02-sw/br0)...

===> Tearing down Bridge and Namespaces...
[SUCCESS] Cleanup finished cleanly.
[INFO] Step 1: Creating switch namespace 'w02-sw' and Linux Bridge 'br0' inside it
[INFO] Step 2: Creating namespaces and interconnecting with veth pairs
[INFO]   - Provisioning w02-ns1 (10.20.0.11/24) connected via veth-ns1 <---> veth-br1
[INFO]   - Provisioning w02-ns2 (10.20.0.12/24) connected via veth-ns2 <---> veth-br2
[INFO]   - Provisioning w02-ns3 (10.20.0.13/24) connected via veth-ns3 <---> veth-br3
[SUCCESS] Bridge topology provisioned successfully!
...
```

---

### ขั้นตอนที่ 2: ทดสอบการเชื่อมต่อและสวิตชิ่งข้าม Namespace
รันคำสั่งทดสอบการส่งแพ็กเก็ต ICMP ข้ามพอร์ตสวิตช์:
```bash
sudo ./bridge_router_lab.sh test
```

**ผลลัพธ์ที่ได้** (ส่วนต้น):
```text
===> Testing Cross-Namespace and Bridge Gateway Connectivity...
[INFO] Testing w02-ns1 -> Bridge Gateway (10.20.0.1)...
[SUCCESS] w02-ns1 -> Bridge Gateway (10.20.0.1) reached!
[INFO] Testing w02-ns1 (10.20.0.11) -> w02-ns2 (10.20.0.12)...
[SUCCESS] w02-ns1 (10.20.0.11) -> w02-ns2 (10.20.0.12) reached!
[INFO] Testing w02-ns2 (10.20.0.12) -> w02-ns3 (10.20.0.13)...
[SUCCESS] w02-ns2 (10.20.0.12) -> w02-ns3 (10.20.0.13) reached!
[INFO] Testing w02-ns3 (10.20.0.13) -> w02-ns1 (10.20.0.11)...
[SUCCESS] w02-ns3 (10.20.0.13) -> w02-ns1 (10.20.0.11) reached!
[SUCCESS] All bridge L2 switching tests succeeded!
```

---

### ขั้นตอนที่ 3: ตรวจสอบตาราง FDB (Forwarding Database)
หลังจากการส่งข้อมูล ตรวจสอบว่า Linux Bridge ได้เรียนรู้ MAC Address ของแต่ละ Namespace หรือไม่:
```bash
sudo ./bridge_router_lab.sh status
# หรือดูตรงๆ: sudo ip netns exec w02-sw bridge fdb show br br0
```

คุณจะเห็นตาราง MAC Address ที่เรียนรู้ผ่าน `veth-br1`, `veth-br2`, และ `veth-br3` (MAC จะสุ่มใหม่ทุกครั้งที่สร้าง veth):
```text
Bridge Forwarding Database (FDB) Entries (learned, non-permanent):
7e:dc:d1:01:6c:66 dev veth-br1 master br0 
1e:0e:11:d8:3a:3d dev veth-br2 master br0 
9a:9a:cd:b4:bc:3c dev veth-br3 master br0 
```
> MAC ที่เรียนรู้แต่ละตัวต้องตรงกับ MAC ของ `veth-nsX` ในแต่ละ namespace — ตรวจด้วย `sudo ip netns exec w02-ns1 ip -br link show veth-ns1` (FDB อาจมีรายการตั้งแต่ก่อน ping เพราะเคอร์เนลส่ง IPv6 Router Solicitation/DAD ออกมาเองเมื่อ interface ขึ้น)

---

### ขั้นตอนที่ 4: รันการวินิจฉัยเคอร์เนลเชิงลึก (Stack Diagnostic Trace)
รันโหมดสืบค้นเคอร์เนล:
```bash
sudo ./bridge_router_lab.sh trace
```

**สิ่งที่ปรากฏในหน้าจอ** (ผลเต็มอยู่ในหัวข้อ 4.2):
1. **สถิติ SoftIRQ จาก `/proc/net/softnet_stat`** — ค่าเป็นเลขฐาน 16 ต่อ CPU และเป็นค่าระดับทั้งระบบ (ไม่แยกตาม namespace)
2. **การขัดจังหวะ SoftIRQ ใน `/proc/softirqs`** — จำนวนครั้งที่ `NET_TX`/`NET_RX` softirq ทำงานบนแต่ละ CPU
3. **Interface Counters ของ `br0`** จาก `ip -s link`
4. **การแกะรอย System Call จาก `strace`** — เห็นลำดับ `socket()` -> `sendto()` -> `recvmsg()` ของ `ping`
5. **การนับ Tracepoint `net:*` ด้วย `perf stat`**

---

### ขั้นตอนที่ 5: ล้างและทำลายสภาพแวดล้อม
```bash
sudo ./bridge_router_lab.sh clean
ip netns list | grep w02 || echo "clean"   # ต้องไม่เหลือ namespace w02-*
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`, 8 CPUs), iproute2, strace, perf (linux-tools-7.0.0-38)

### 4.1 การสร้าง Linux Bridge Topology และตรวจสอบตาราง FDB (`setup`, `test`)
```text
===> Building Multi-Namespace Bridge Topology (w02-ns1 w02-ns2 w02-ns3 <-> w02-sw/br0)...

===> Tearing down Bridge and Namespaces...
[SUCCESS] Cleanup finished cleanly.
[INFO] Step 1: Creating switch namespace 'w02-sw' and Linux Bridge 'br0' inside it
[INFO] Step 2: Creating namespaces and interconnecting with veth pairs
[INFO]   - Provisioning w02-ns1 (10.20.0.11/24) connected via veth-ns1 <---> veth-br1
[INFO]   - Provisioning w02-ns2 (10.20.0.12/24) connected via veth-ns2 <---> veth-br2
[INFO]   - Provisioning w02-ns3 (10.20.0.13/24) connected via veth-ns3 <---> veth-br3
[SUCCESS] Bridge topology provisioned successfully!

===> Current Topology and Bridge Forwarding Database (FDB)
Linux Bridge [br0] in netns w02-sw:
br0              UP             10.20.0.1/24 fe80::bc26:a5ff:fe5e:b3d5/64 

Interfaces attached to br0:
veth-br1@if2     UP             1e:a1:28:90:82:af <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth-br2@if2     UP             ca:0c:0a:dc:27:16 <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth-br3@if2     UP             6a:92:5f:1c:3e:86 <BROADCAST,MULTICAST,UP,LOWER_UP> 

Bridge Forwarding Database (FDB) Entries (learned, non-permanent):
7e:dc:d1:01:6c:66 dev veth-br1 master br0 
1e:0e:11:d8:3a:3d dev veth-br2 master br0 
9a:9a:cd:b4:bc:3c dev veth-br3 master br0 

Namespace Status:
  [w02-ns1]: veth-ns1@if3     UP             10.20.0.11/24 fe80::7cdc:d1ff:fe01:6c66/64 
  [w02-ns2]: veth-ns2@if4     UP             10.20.0.12/24 fe80::1c0e:11ff:fed8:3a3d/64 
  [w02-ns3]: veth-ns3@if5     UP             10.20.0.13/24 fe80::989a:cdff:feb4:bc3c/64 
===> Testing Cross-Namespace and Bridge Gateway Connectivity...
[INFO] Testing w02-ns1 -> Bridge Gateway (10.20.0.1)...
[SUCCESS] w02-ns1 -> Bridge Gateway (10.20.0.1) reached!
[INFO] Testing w02-ns1 (10.20.0.11) -> w02-ns2 (10.20.0.12)...
[SUCCESS] w02-ns1 (10.20.0.11) -> w02-ns2 (10.20.0.12) reached!
[INFO] Testing w02-ns2 (10.20.0.12) -> w02-ns3 (10.20.0.13)...
[SUCCESS] w02-ns2 (10.20.0.12) -> w02-ns3 (10.20.0.13) reached!
[INFO] Testing w02-ns3 (10.20.0.13) -> w02-ns1 (10.20.0.11)...
[SUCCESS] w02-ns3 (10.20.0.13) -> w02-ns1 (10.20.0.11) reached!
[SUCCESS] All bridge L2 switching tests succeeded!

===> Current Topology and Bridge Forwarding Database (FDB)
Linux Bridge [br0] in netns w02-sw:
br0              UP             10.20.0.1/24 fe80::bc26:a5ff:fe5e:b3d5/64 

Interfaces attached to br0:
veth-br1@if2     UP             1e:a1:28:90:82:af <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth-br2@if2     UP             ca:0c:0a:dc:27:16 <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth-br3@if2     UP             6a:92:5f:1c:3e:86 <BROADCAST,MULTICAST,UP,LOWER_UP> 

Bridge Forwarding Database (FDB) Entries (learned, non-permanent):
7e:dc:d1:01:6c:66 dev veth-br1 master br0 
1e:0e:11:d8:3a:3d dev veth-br2 master br0 
9a:9a:cd:b4:bc:3c dev veth-br3 master br0 

Namespace Status:
  [w02-ns1]: veth-ns1@if3     UP             10.20.0.11/24 fe80::7cdc:d1ff:fe01:6c66/64 
  [w02-ns2]: veth-ns2@if4     UP             10.20.0.12/24 fe80::1c0e:11ff:fed8:3a3d/64 
  [w02-ns3]: veth-ns3@if5     UP             10.20.0.13/24 fe80::989a:cdff:feb4:bc3c/64 
```

### 4.2 การตรวจสอบ Kernel Network Stack, SoftIRQ, `strace` และ `perf stat` (`./bridge_router_lab.sh trace`)
```text
===> Diagnostic Tracing: Kernel Network Stack & SoftIRQ Traversal
[1. /proc/net/softnet_stat Inspection]
Values are hex, per CPU (system-wide: /proc/net/softnet_stat is not per-namespace).
Shown: col1=Processed col2=Dropped col3=TimeSqueeze (col13 = CPU id on newer kernels)
------------------------------------------------------------------------------------------------
  CPU  0 : Processed=0x0008b1a4 Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  1 : Processed=0x00052d25 Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  2 : Processed=0x000bc569 Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  3 : Processed=0x00116880 Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  4 : Processed=0x000fadd6 Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  5 : Processed=0x000b8e89 Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  6 : Processed=0x0009a98c Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  7 : Processed=0x0046d260 Dropped=0x00000000 TimeSqueeze=0x00000002
Note: 'TimeSqueeze' increments when net_rx_action() runs out of budget (netdev_budget packets or netdev_budget_usecs) with work still pending.

[2. /proc/softirqs (NET_RX / NET_TX Activity)]
      NET_TX:        823        721        789        686        738        686        704      20695
      NET_RX:     477215     272136     685574    1060882     933840     688529     564919   10937643

[3. Bridge Device Interface Counters (ip -s link, netns w02-sw)]
2: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 1e:a1:28:90:82:af brd ff:ff:ff:ff:ff:ff
    RX:  bytes packets errors dropped  missed   mcast           
          1576      24      0       0       0      18 
    TX:  bytes packets errors dropped carrier collsns           
          1052      12      0       0       0       0 

[4. System Call Tracing with strace (Socket Send & Recv)]
[INFO] Executing strace on a 1-packet ICMP ping from w02-ns1 to w02-ns2...
  [syscall] socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = -1 EACCES (Permission denied) <0.000040>
  [syscall] socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = 3 <0.000032>
  [syscall] socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) = -1 EACCES (Permission denied) <0.000030>
  [syscall] socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) = 4 <0.000028>
  [syscall] socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 5 <0.000028>
  [syscall] sendto(3, "\10\0\311\353\3476\0\0014\22\342j\0\0\0\0d\214\r\0\0\0\0\0\20\21\22\23\24\25\26\27"..., 64, 0, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.20.0.12")}, 16) = 64 <0.000080>
  [syscall] recvmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.20.0.12")}, msg_namelen=128 => 16, msg_iov=[{iov_base="E\0\0T+\267\0\0@\1:\264\n\24\0\f\n\24\0\v\0\0\321\353\3476\0\0014\22\342j"..., iov_len=192}], msg_iovlen=1, msg_control=[{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMP_OLD, cmsg_data={tv_sec=1793200692, tv_usec=888143}}], msg_controllen=32, msg_flags=0}, 0) = 84 <0.000016>

[5. Kernel Tracepoint Inspection (perf stat / trace)]
[INFO] Running perf stat tracking net:* events during cross-bridge traffic...
  [perf]                 12      net:net_dev_queue                                                     
  [perf]                 12      net:net_dev_xmit                                                      
  [perf]                 12      net:netif_rx                                                          
  [perf]                 12      net:netif_receive_skb                                                 
  [perf]        2.030807196 seconds time elapsed
  [perf]        0.000000000 seconds user
  [perf]        0.004558000 seconds sys
[SUCCESS] Diagnostic trace complete.
```

ข้อสังเกตจากผลจริง:
- `perf stat` นับได้ 12 ครั้งต่อ tracepoint สำหรับ `ping -c 3` — ทุก Echo Request/Reply ต้องผ่าน veth และ bridge หลายช่วง แต่ละช่วงคือการ "ส่ง" (`net_dev_queue`/`net_dev_xmit`) และ "รับ" (`netif_rx`/`netif_receive_skb`) หนึ่งครั้ง
- `TimeSqueeze` ส่วนใหญ่เป็น 0 เพราะเครื่องไม่ได้รับโหลดเครือข่ายหนัก

---

## 5. Milestone Checklist

- [x] **Kernel Network Lifecycle**: เข้าใจขั้นตอนครบถ้วนตั้งแต่ Hardware Interrupt -> SoftIRQ -> NAPI Loop -> `sk_buff` -> L2/L3/L4 -> Socket
- [x] **sk_buff Cost Analysis**: ตระหนักถึงความซับซ้อนและภาระ overhead ของ `struct sk_buff` และเข้าใจว่าทำไม eBPF / XDP จึงเร็วกว่า
- [x] **Linux Bridge Switching**: สร้าง Virtual Bridge (`br0`) และสังเกตการเรียนรู้ MAC Address ในตาราง FDB ผ่านคำสั่ง `bridge fdb`
- [x] **Kernel Observability Basics**: อ่านและแปลความหมายของ `/proc/net/softnet_stat` (Time Squeeze, Dropped) และ `/proc/softirqs` ได้
- [x] **System Call Tracing**: ใช้ `strace` ตรวจสอบความสัมพันธ์ระหว่าง Application Socket Calls และ Kernel Transition

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `RTNETLINK answers: Operation not permitted` | สร้าง bridge/veth/namespace โดยไม่มี `CAP_NET_ADMIN` | รันด้วย `sudo` |
| `[ERROR] Lab topology not found. Run: sudo ./bridge_router_lab.sh setup` | สั่ง `test`/`status`/`trace` ก่อน `setup` (หรือหลัง `clean`) | `sudo ./bridge_router_lab.sh setup` |
| `Cannot open network namespace "w02-ns1": No such file or directory` | พิมพ์คำสั่ง `ip netns exec` เองแต่ namespace ไม่มีอยู่/ลืม prefix `w02-` | `ip netns list` ตรวจชื่อ แล้ว `setup` ใหม่ |
| ping ข้าม namespace ไม่ผ่าน ทั้งที่ ARP/FDB ดูปกติ (เมื่อดัดแปลงให้ `br0` อยู่บน Host) | บนเครื่องที่มี Docker โมดูล `br_netfilter` ส่งเฟรมที่ผ่าน bridge เข้า iptables `FORWARD` ซึ่ง Docker ตั้ง policy `DROP` | ให้ Bridge อยู่ใน namespace แยกแบบสคริปต์นี้ หรือตรวจ `lsmod \| grep br_netfilter` และ `sudo iptables -S FORWARD` (ห้ามแก้ firewall ของเครื่องที่ใช้ร่วมกันโดยไม่ได้รับอนุญาต) |
| ส่วน `[4. ... strace]` ว่างเปล่า หรือขึ้น `'strace' command not found` | ไม่ได้ติดตั้ง `strace` | `sudo apt install strace` |
| ส่วน `[5. ... perf stat]` ไม่มีตัวเลข หรือ `perf` บ่นว่าไม่พบเวอร์ชันสำหรับเคอร์เนลนี้ | ไม่มี `linux-tools-$(uname -r)` ที่ตรงกับเคอร์เนลที่รันอยู่ | `sudo apt install linux-tools-$(uname -r)` แล้วทดสอบ `sudo perf list 'net:*'` |
| เห็น `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = -1 EACCES` ใน strace | ไม่ใช่ error: namespace ใหม่มี `net.ipv4.ping_group_range = 1 0` ping จึง fallback ไปใช้ `SOCK_RAW` | ไม่ต้องแก้ ดูค่าได้ด้วย `sudo ip netns exec w02-ns1 sysctl net.ipv4.ping_group_range` |
| เลข CPU ใน softnet_stat ไม่ตรงกับ `/proc/softirqs` | เคอร์เนลข้ามบรรทัดของ CPU ที่ offline | ใช้คอลัมน์ 13 (CPU id) ซึ่งสคริปต์รุ่นนี้ทำให้แล้ว |

> **ทิป**: หลังทดลองเสร็จให้ยืนยันว่าไม่มีอะไรค้างด้วย `ip netns list | grep w02` (ต้องว่าง) และ `ip -br link | grep -E 'br0|veth-br'` บน Host (ต้องว่าง)

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **FDB Ageing**: เปลี่ยน ageing time ของ `br0` เป็น 10 วินาที (`sudo ip netns exec w02-sw ip link set br0 type bridge ageing_time 1000` — หน่วยเป็น centisecond) แล้วสังเกตว่า MAC หายไปจาก FDB เมื่อไม่มีทราฟฟิก
   - **สิ่งที่ต้องส่ง**: ผล `bridge fdb show br br0` ก่อน/หลังรอ 15 วินาที และหลัง ping ใหม่ พร้อมอธิบายว่าเกิด Flooding ตอนไหน
   - **วิธีตรวจ**: `sudo ip netns exec w02-sw bridge fdb show br br0 | grep -v permanent` ต้องว่างหลังรอ และกลับมาหลัง `sudo ip netns exec w02-ns1 ping -c1 10.20.0.12`
2. **อ่าน softnet_stat แบบ Delta**: บันทึกคอลัมน์ Processed ของทุก CPU ก่อนและหลังรัน `sudo ip netns exec w02-ns1 ping -f -c 20000 10.20.0.12`
   - **สิ่งที่ต้องส่ง**: ตาราง delta (ฐาน 10) ต่อ CPU และคำอธิบายว่าทำไมผลรวมไม่เท่ากับ 40,000 พอดี (เครื่องมีทราฟฟิกอื่นด้วย และแพ็กเก็ตหนึ่งตัวอาจผ่าน backlog หลายครั้งเมื่อวิ่งผ่าน veth/bridge)
   - **วิธีตรวจ**: `awk '{print $13, $1}' /proc/net/softnet_stat` ก่อน/หลัง แล้วแปลงด้วย `printf "%d\n" 0x<ค่า>`

### ระดับปานกลาง
3. **นับเฟรมที่ผ่าน `br_handle_frame()`** (ใช้ความรู้ล่วงหน้าจาก Week 03): รัน `sudo bpftrace -e 'kprobe:br_handle_frame { @[comm] = count(); }'` ขณะ ping ข้าม namespace 10 ครั้ง
   - **สิ่งที่ต้องส่ง**: ผลนับ + อธิบายว่าทำไมนับได้มากกว่า 10 (Request + Reply + ARP) และ `comm` ที่เห็นบอกอะไรเรื่องบริบทที่ softirq ทำงาน
   - **วิธีตรวจ**: ตรวจก่อนว่ามี probe จริงด้วย `sudo bpftrace -l 'kprobe:br_handle_frame*'`
4. **เพิ่ม Namespace ที่ 4**: แก้อาร์เรย์ `NAMESPACES`/`NS_IPS`/`RAW_IPS` ให้มี `w02-ns4` (`10.20.0.14/24`) และเพิ่มคู่ทดสอบ ping ใน `test_connectivity`
   - **สิ่งที่ต้องส่ง**: diff ของสคริปต์ + ผล `test` ที่ผ่านทั้งหมด + FDB ที่มี 4 รายการ
   - **วิธีตรวจ**: `sudo ./bridge_router_lab.sh setup && sudo ./bridge_router_lab.sh test` แล้ว `clean` ต้องลบ `w02-ns4` ด้วย

### ระดับท้าทาย
5. **VLAN Isolation บน Bridge**: เปิด `vlan_filtering 1` บน `br0` แล้วกำหนด `veth-br1`/`veth-br2` เป็น VLAN 10 และ `veth-br3` เป็น VLAN 20 (`bridge vlan add dev veth-brX vid N pvid untagged` และลบ VLAN 1 ออก)
   - **สิ่งที่ต้องส่ง**: สคริปต์คำสั่ง + ผลที่ `w02-ns1 -> w02-ns2` ผ่าน แต่ `w02-ns1 -> w02-ns3` ไม่ผ่าน
   - **วิธีตรวจ**: `sudo ip netns exec w02-sw bridge vlan show` และ ping สองคู่ข้างต้น
6. **วัดต้นทุนของสแตกด้วยตัวเอง**: ใช้ `iperf3` (server ใน `w02-ns2`, client ใน `w02-ns1`) วัด throughput เทียบระหว่างเปิดและปิด offload (`ethtool -K ... tso on gso on gro on` vs `off`)
   - **สิ่งที่ต้องส่ง**: ตารางผลอย่างน้อย 3 รอบต่อกรณี (ค่าเฉลี่ย ± ส่วนเบี่ยงเบน) + ข้อสรุปว่าความต่างมาจากจำนวน `sk_buff` ต่อไบต์ที่ลดลงอย่างไร — ห้ามสรุปเป็นตัวเลข "เร็วกว่า X เท่า" แบบทั่วไป เพราะผลขึ้นกับเครื่องและ workload
   - **วิธีตรวจ**: `sudo ip netns exec w02-ns2 iperf3 -s -1 &` แล้ว `sudo ip netns exec w02-ns1 iperf3 -c 10.20.0.12 -t 5`
