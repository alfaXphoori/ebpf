# สัปดาห์ที่ 02: เส้นทางของแพ็กเก็ตใน Linux Kernel Stack และ Linux Bridge

ยินดีต้อนรับสู่ **Week 02** ของหลักสูตร **eBPF Noob to Hero**!
ในสัปดาห์นี้ เราจะเจาะลึกเข้าไปใน "เครื่องยนต์ภายใน" ของเคอร์เนล Linux: **เมื่อแพ็กเก็ตเดินทางมาถึงการ์ดแลน (NIC) หรือพอร์ตเสมือน (veth) เคอร์เนลประมวลผลมันอย่างไรตั้งแต่ระดับ Hardware Interrupt จนถึง User Space Socket?**

เราจะสร้างห้องทดลองเครือข่ายที่มี **Linux Bridge (`br0`)** ทำหน้าที่เป็น Virtual L2 Switch เชื่อมต่อ Network Namespaces 3 ชุดเข้าด้วยกัน พร้อมทั้งใช้เครื่องมือวินิจฉัยเคอร์เนล เช่น `strace`, `/proc/net/softnet_stat`, `/proc/softirqs` และ `perf` เพื่อสังเกตการณ์พฤติกรรมของ **`sk_buff`**, **NAPI**, และ **SoftIRQ** ก่อนที่เราจะเข้าใจว่าทำไม **eBPF / XDP** จึงปฏิวัติประสิทธิภาพของระบบเครือข่ายด้วยการบายพาสสแตกเหล่านี้!

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
- **ขนาด Metadata**: `sk_buff` ตัวเปล่าๆ มีขนาดมากกว่า **200+ ไบต์** ไม่รวมพื้นที่เก็บข้อมูลแพ็กเก็ตจริง!
- **Headroom & Tailroom**: เคอร์เนลต้องจองพื้นที่ว่างด้านหน้า (`headroom`) และด้านหลัง (`tailroom`) เพื่อให้โปรโตคอลต่างๆ สามารถ push/pop header ได้โดยไม่ต้อง reallocate หน่วยความจำ
- **ปัญหาด้าน Performance**:
  1. การจัดสรร (Allocate) และคืนหน่วยความจำ (Free) `sk_buff` เป็นพันล้านครั้งต่อวินาทีสร้างภาระ Cache-miss และ Memory Bandwidth สูงมาก
  2. การวิ่งผ่านเลเยอร์ Netfilter, Routing Table, และ Socket Lock กินเวลา CPU Cycle มหาศาล

> [!IMPORTANT]
> **ทำไม eBPF / XDP ถึงเร็วกว่า Linux Network Stack ดั้งเดิมถึง 10-50 เท่า?**
> **XDP (eXpress Data Path)** ทำงานที่ระดับ Device Driver โดยตรง **ก่อนที่เคอร์เนลจะจัดสรร `sk_buff`**! หาก XDP ตรวจพบว่าเป็น DDoS หรือแพ็กเก็ตที่ไม่ต้องการ มันสามารถสั่ง `XDP_DROP` ทิ้งไปได้ทันทีที่ความเร็วระดับ Wire Speed (มากกว่า 20-40 ล้านแพ็กเก็ตต่อวินาทีต่อคอร์ CPU)

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
3. **คอลัมน์ 3 (Time Squeeze)**: จำนวนครั้งที่ฟังก์ชัน NAPI Poll ถูกบังคับให้หยุดทำงานเนื่องจากใช้ **Budget หมด** (ปกติกำหนดไว้ที่ 64 หรือ 300 แพ็กเก็ตต่อรอบ) หรือกินเวลาในเคอร์เนลนานเกิน 2 Jiffies เพื่อป้องกันไม่ให้ SoftIRQ ผูกขาด CPU นานเกินไป

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### สคริปต์จำลองห้องทดลอง: `bridge_router_lab.sh`

#### การสร้าง Linux Bridge และเปิดการใช้งาน
```bash
ip link add name "${BRIDGE}" type bridge
ip addr add "${BRIDGE_IP}" dev "${BRIDGE}"
ip link set "${BRIDGE}" up
```
- **คำอธิบาย**:
  - `type bridge`: สั่งให้เคอร์เนลสร้าง Virtual Network Device ชนิด Bridge ชื่อ `br0`
  - `ip addr add 10.20.0.1/24 dev br0`: กำหนด IP Address ให้กับตัว Bridge เพื่อให้ทำหน้าที่เป็น Default Gateway ของวงเครือข่ายเสมือนนี้ได้

#### การผูกพอร์ตเสมือน (`veth`) เข้ากับ Bridge
```bash
ip link add "${veth_ns}" type veth peer name "${veth_br}"
ip link set "${veth_br}" master "${BRIDGE}"
ip link set "${veth_br}" up
ip link set "${veth_ns}" netns "${ns}"
```
- **คำอธิบาย**:
  - สร้างท่อเชื่อมต่อ `veth-nsX` และ `veth-brX`
  - `ip link set veth-brX master br0`: ทำการผูก (Enslave) อินเทอร์เฟซ `veth-brX` เข้าเป็นพอร์ตหนึ่งของ Bridge `br0` เสมือนการเสียบสาย LAN เข้ากับสวิตช์
  - ย้ายฝั่ง `veth-nsX` เข้าไปยัง Network Namespace ปลายทาง

#### การตรวจสอบตาราง FDB และ Interface Counters
```bash
bridge fdb show dev "${BRIDGE}"
ip -s link show dev "${BRIDGE}"
```
- **คำอธิบาย**:
  - `bridge fdb show`: แสดงตาราง MAC Address ที่เคอร์เนลเรียนรู้จากการรับแพ็กเก็ตผ่าน Bridge
  - `ip -s link`: แสดงสถิติ RX/TX Packets, Bytes, Dropped, และ Errors ของอินเทอร์เฟซในระดับเคอร์เนล

#### การสืบค้นพฤติกรรม System Call ด้วย `strace`
```bash
ip netns exec ns1 strace -f -e trace=socket,sendto,recvmsg,close -T -- ping -c 1 -W 1 10.20.0.12
```
- **คำอธิบาย**:
  - `-e trace=network`: กรองดูเฉพาะ System Calls ที่เกี่ยวข้องกับเครือข่าย
  - `-T`: แสดงเวลาที่โปรเซสเสียไปในเคอร์เนล (Time spent in syscall) ในหน่วยไมโครวินาที
  - คำสั่งนี้ทำให้เราเห็นว่า Application ร้องขอ Socket Descriptors และส่งข้อมูลผ่าน `sendto()` อย่างไรในระดับ User-Kernel Boundary

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ติดตั้งโทโพโลยีเครือข่ายเสมือน 3 Namespaces
รันคำสั่ง setup ด้วยสิทธิ์ `sudo`:
```bash
sudo ./bridge_router_lab.sh setup
```

**ผลลัพธ์ที่ได้**:
```text
===> Building Multi-Namespace Bridge Topology (ns1, ns2, ns3 <-> br0)...
[INFO] Step 1: Creating Linux Bridge 'br0'
[INFO] Step 2: Creating namespaces and interconnecting with veth pairs
  - Provisioning ns1 (10.20.0.11/24) connected via veth-ns1 <---> veth-br1
  - Provisioning ns2 (10.20.0.12/24) connected via veth-ns2 <---> veth-br2
  - Provisioning ns3 (10.20.0.13/24) connected via veth-ns3 <---> veth-br3
[SUCCESS] Bridge topology provisioned successfully!
```

---

### ขั้นตอนที่ 2: ทดสอบการเชื่อมต่อและสวิตชิ่งข้าม Namespace
รันคำสั่งทดสอบการส่งแพ็กเก็ต ICMP ข้ามพอร์ตสวิตช์:
```bash
sudo ./bridge_router_lab.sh test
```

**ผลลัพธ์ที่ได้**:
```text
===> Testing Cross-Namespace and Host Bridge Connectivity...
[INFO] Testing ns1 -> Bridge Gateway (10.20.0.1)...
[SUCCESS] ns1 -> Bridge Gateway reached!
[INFO] Testing ns1 (10.20.0.11) -> ns2 (10.20.0.12)...
[SUCCESS] ns1 -> ns2 reached!
[INFO] Testing ns2 (10.20.0.12) -> ns3 (10.20.0.13)...
[SUCCESS] ns2 -> ns3 reached!
[INFO] Testing ns3 (10.20.0.13) -> ns1 (10.20.0.11)...
[SUCCESS] ns3 -> ns1 reached!
[SUCCESS] All bridge L2 switching tests succeeded!
```

---

### ขั้นตอนที่ 3: ตรวจสอบตาราง FDB (Forwarding Database)
หลังจากการส่งข้อมูล ตรวจสอบว่า Linux Bridge ได้เรียนรู้ MAC Address ของแต่ละ Namespace หรือไม่:
```bash
sudo ./bridge_router_lab.sh status
```

คุณจะเห็นตาราง MAC Address ที่เรียนรู้ผ่าน `veth-br1`, `veth-br2`, และ `veth-br3`:
```text
Bridge Forwarding Database (FDB) Entries:
52:54:00:aa:01:01 dev veth-br1 master br0 
52:54:00:bb:02:02 dev veth-br2 master br0 
52:54:00:cc:03:03 dev veth-br3 master br0 
```

---

### ขั้นตอนที่ 4: รันการวินิจฉัยเคอร์เนลเชิงลึก (Stack Diagnostic Trace)
รันโหมดสืบค้นเคอร์เนล:
```bash
sudo ./bridge_router_lab.sh trace
```

**สิ่งที่ปรากฏในหน้าจอ**:
1. **สถิติ SoftIRQ จาก `/proc/net/softnet_stat`**:
   ```text
   [1. /proc/net/softnet_stat Inspection]
   Columns: [CPU] [Processed] [Dropped] [TimeSqueeze]
     CPU  0 : Processed=0x0001f3a2 Dropped=0x00000000 TimeSqueeze=0x00000014
     CPU  1 : Processed=0x00021c45 Dropped=0x00000000 TimeSqueeze=0x00000008
   ```
2. **การขัดจังหวะ SoftIRQ ใน `/proc/softirqs`**:
   ```text
   [2. /proc/softirqs (NET_RX / NET_TX Activity)]
   NET_TX:      124050     119230
   NET_RX:     3849120    3901240
   ```
3. **การแกะรอย System Call จาก `strace`**:
   ```text
   [syscall] socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 3 <0.000025>
   [syscall] sendto(3, "\10\0\332\347...", 64, 0, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.20.0.12")}, 16) = 64 <0.000082>
   [syscall] recvmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.20.0.12")}, ...}, 0) = 64 <0.000078>
   ```

---

### ขั้นตอนที่ 5: ล้างและทำลายสภาพแวดล้อม
```bash
sudo ./bridge_router_lab.sh clean
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 24.04 LTS (`Linux ebpf-lab 6.8.0-142-generic #142-Ubuntu SMP PREEMPT_DYNAMIC aarch64`)

### 4.1 การสร้าง Linux Bridge Topology และตรวจสอบตาราง FDB (`setup`, `test`, `status`)
```text
===> Building Multi-Namespace Bridge Topology (ns1, ns2, ns3 <-> br0)...

===> Tearing down Bridge and Namespaces...
[SUCCESS] Cleanup finished cleanly.
[INFO] Step 1: Creating Linux Bridge 'br0'
[INFO] Step 2: Creating namespaces and interconnecting with veth pairs
[INFO]   - Provisioning ns1 (10.20.0.11/24) connected via veth-ns1 <---> veth-br1
[INFO]   - Provisioning ns2 (10.20.0.12/24) connected via veth-ns2 <---> veth-br2
[INFO]   - Provisioning ns3 (10.20.0.13/24) connected via veth-ns3 <---> veth-br3
[SUCCESS] Bridge topology provisioned successfully!

===> Testing Cross-Namespace and Host Bridge Connectivity...
[INFO] Testing ns1 -> Bridge Gateway (10.20.0.1)...
[SUCCESS] ns1 -> Bridge Gateway reached!
[INFO] Testing ns1 (10.20.0.11) -> ns2 (10.20.0.12)...
[SUCCESS] ns1 -> ns2 reached!
[INFO] Testing ns2 (10.20.0.12) -> ns3 (10.20.0.13)...
[SUCCESS] ns2 -> ns3 reached!
[INFO] Testing ns3 (10.20.0.13) -> ns1 (10.20.0.11)...
[SUCCESS] ns3 -> ns1 reached!
[SUCCESS] All bridge L2 switching tests succeeded!

===> Current Topology and Bridge Forwarding Database (FDB)
Linux Bridge [br0]:
br0              UP             10.20.0.1/24 fe80::5484:70ff:fe0a:ea78/64 

Interfaces attached to br0:
veth-br1@if14    UP             be:b3:b8:78:9c:2d <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth-br2@if16    UP             66:47:17:f7:47:d1 <BROADCAST,MULTICAST,UP,LOWER_UP> 
veth-br3@if18    UP             96:83:51:9c:55:56 <BROADCAST,MULTICAST,UP,LOWER_UP> 

Bridge Forwarding Database (FDB) Entries:
a2:c8:f8:14:3a:b0 dev veth-br1 master br0 
72:05:1b:cc:9f:82 dev veth-br2 master br0 
ee:06:cb:92:a2:7e dev veth-br3 master br0 

Namespace Status:
  [ns1]: veth-ns1@if13    UP             10.20.0.11/24 fe80::a0c8:f8ff:fe14:3ab0/64 
  [ns2]: veth-ns2@if15    UP             10.20.0.12/24 fe80::7005:1bff:fecc:9f82/64 
  [ns3]: veth-ns3@if17    UP             10.20.0.13/24 fe80::ec06:cbff:fe92:a27e/64 
```

### 4.2 การตรวจสอบ Kernel Network Stack, SoftIRQ, `strace` และ `perf stat` (`./bridge_router_lab.sh trace`)
```text
===> Diagnostic Tracing: Kernel Network Stack & SoftIRQ Traversal
[1. /proc/net/softnet_stat Inspection]
Columns: [CPU] [Processed] [Dropped] [TimeSqueeze] [CPUCollision] [ReceivedRps] [FlowLimitCount]
------------------------------------------------------------------------------------------------
  CPU  0 : Processed=0x00000247 Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  1 : Processed=0x000000eb Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  2 : Processed=0x000000ce Dropped=0x00000000 TimeSqueeze=0x00000000
  CPU  3 : Processed=0x00000085 Dropped=0x00000000 TimeSqueeze=0x00000000
Note: 'TimeSqueeze' increments when SoftIRQ runs out of budget before draining RX Ring.

[2. /proc/softirqs (NET_RX / NET_TX Activity)]
      NET_TX:          2          4          7          3
      NET_RX:        841        117         98         76

[3. Bridge Device Interface Counters (ip -s link)]
12: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 56:84:70:0a:ea:78 brd ff:ff:ff:ff:ff:ff
    RX:  bytes packets errors dropped  missed   mcast           
          1576      24      0       0       0      18 
    TX:  bytes packets errors dropped carrier collsns           
          2273      22      0       0       0       0 

[4. System Call Tracing with strace (Socket Send & Recv)]
[INFO] Executing strace on a 1-packet ICMP ping from ns1 to ns2...
  [syscall] socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = -1 EACCES (Permission denied) <0.000016>
  [syscall] socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = 3 <0.000011>
  [syscall] socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) = -1 EACCES (Permission denied) <0.000012>
  [syscall] socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) = 4 <0.000010>
  [syscall] socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 5 <0.000026>
  [syscall] sendto(3, "\10\0\n\30\10;\0\1iD\324j\0\0\0\0\341)\10\0\0\0\0\0\20\21\22\23\24\25\26\27"..., 64, 0, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.20.0.12")}, 16) = 64 <0.000032>
  [syscall] recvmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("10.20.0.12")}, msg_namelen=128 => 16, msg_iov=[{iov_base="E\0\0TS\307\0\0@\1\22\244\n\24\0\f\n\24\0\v\0\0\22\30\10;\0\1iD\324j"..., iov_len=192}], msg_iovlen=1, msg_control=[{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMP_OLD, cmsg_data={tv_sec=1792296041, tv_usec=535088}}], msg_controllen=32, msg_flags=0}, 0) = 84 <0.000009>

[5. Kernel Tracepoint Inspection (perf stat / trace)]
[INFO] Running perf stat tracking net:* events during cross-bridge traffic...
  [perf]                 12      net:net_dev_queue                                                     
  [perf]                 12      net:net_dev_xmit                                                      
  [perf]                 12      net:netif_rx                                                          
  [perf]                 12      net:netif_receive_skb                                                 
  [perf]        2.044158437 seconds time elapsed
  [perf]        0.000000000 seconds user
  [perf]        0.001695000 seconds sys
[SUCCESS] Diagnostic trace complete.
```

---

## 5. Milestone Checklist

- [x] **Kernel Network Lifecycle**: เข้าใจขั้นตอนครบถ้วนตั้งแต่ Hardware Interrupt -> SoftIRQ -> NAPI Loop -> `sk_buff` -> L2/L3/L4 -> Socket
- [x] **sk_buff Cost Analysis**: ตระหนักถึงความซับซ้อนและภาระ overhead ของ `struct sk_buff` และเข้าใจว่าทำไม eBPF / XDP จึงเร็วกว่า
- [x] **Linux Bridge Switching**: สร้าง Virtual Bridge (`br0`) และสังเกตการเรียนรู้ MAC Address ในตาราง FDB ผ่านคำสั่ง `bridge fdb`
- [x] **Kernel Observability Basics**: อ่านและแปลความหมายของ `/proc/net/softnet_stat` (Time Squeeze, Dropped) และ `/proc/softirqs` ได้
- [x] **System Call Tracing**: ใช้ `strace` ตรวจสอบความสัมพันธ์ระหว่าง Application Socket Calls และ Kernel Transition
