# สัปดาห์ที่ 01: พื้นฐานระบบเครือข่ายและการดักจับแพ็กเก็ต (Packet Sniffing & Network Namespaces)

ยินดีต้อนรับสู่ **Week 01** ของหลักสูตร **eBPF Noob to Hero**! 
ก่อนที่เราจะเขียนโปรแกรม eBPF และโปรแกรม XDP เพื่อดักจับหรือกรองแพ็กเก็ตด้วยความเร็วระดับ Kernel Space สิ่งแรกที่วิศวกรระบบทุกคนต้องเข้าใจอย่างถ่องแท้คือ: **"แพ็กเก็ตเดินทางใน Linux Kernel อย่างไร และโครงสร้างระดับไบต์ (Byte-level layout) ของ Ethernet, IPv4, TCP, UDP และ ICMP จัดเรียงตัวอย่างไร"**

ในสัปดาห์นี้ เราจะสร้างห้องทดลองเครือข่ายจำลองแบบเสมือนจริงด้วย **Linux Network Namespaces** และพัฒนา **Raw Packet Sniffer ด้วยภาษา Python** โดยไม่พึ่งพา External Library อย่าง Scapy เพื่อแกะไบต์ออกมาทีละฟิลด์ด้วย `struct.unpack`

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 Linux Network Namespaces คืออะไร?
ในระบบปฏิบัติการ Linux, **Network Namespace (`netns`)** เป็นฟีเจอร์ระดับเคอร์เนลที่ทำการแยกส่วน (Isolate) ทรัพยากรเครือข่ายออกจากกันโดยสิ้นเชิง เสมือนว่าคุณมีคอมพิวเตอร์และเราเตอร์แยกกันหลายๆ เครื่องอยู่ในระบบเดียวกัน แต่ละ Namespace จะมี:
- ตาราง Interface ของตนเอง (เช่น `eth0`, `lo`, `veth1`)
- ตารางเส้นทาง (Routing Table) แยกอิสระ
- ตาราง Socket (Listening Ports, Active Connections)
- การตั้งค่า Firewall / Netfilter (iptables, nftables)

นี่คือเทคโนโลยีแกนกลางเบื้องหลัง Container Engine ทั้งหมด เช่น **Docker**, **containerd**, และ **Kubernetes CNI (Cilium, Calico)**

### 1.2 Virtual Ethernet (`veth`) Pair: ท่อเชื่อมต่อระดับ Kernel
เมื่อเราแยก Namespace ออกจากกัน มันจะไม่สามารถคุยกันได้จนกว่าจะมีสายเคเบิลเสมือนเชื่อมหากัน ใน Linux เราใช้ **`veth` pair (Virtual Ethernet Pair)** ซึ่งทำงานเหมือนสาย LAN ที่มีหัวต่อ 2 ด้าน:
- แพ็กเก็ตที่ถูกส่งเข้าไปยังปลายด้านหนึ่ง (`veth1`) จะพุ่งทะลุไปโผล่ที่ปลายอีกด้านหนึ่ง (`veth2`) ทันทีในระดับ Kernel Space โดยไม่มี Physical Hardware มาเกี่ยวข้อง

```
+---------------------------+                      +---------------------------+
|    Namespace: ns1         |                      |    Namespace: ns2         |
|                           |                      |                           |
|   IP: 10.10.1.1/24        |                      |   IP: 10.10.1.2/24        |
|   Interface: [veth1]      |<====================>|   Interface: [veth2]      |
|                           |   Virtual Wire       |                           |
+---------------------------+   (Kernel bypass L1) +---------------------------+
```

---

### 1.3 โครงสร้างแพ็กเก็ตระดับไบต์ (Network Encapsulation & Byte Offsets)

เมื่อข้อมูลถูกส่งออกจาก Application ผ่าน Socket มันจะถูกห่อหุ้ม (Encapsulation) เป็นชั้นๆ ตามโมเดล OSI:

```
+--------------------+---------------------+--------------------+--------------------+
|  Ethernet Header   |     IPv4 Header     |  TCP/UDP/ICMP Hdr  |      Payload       |
|     (14 Bytes)     |     (20+ Bytes)     |   (8 - 20+ Bytes)  |     (N Bytes)      |
+--------------------+---------------------+--------------------+--------------------+
Byte 0              14                    34                   54                  N
```

#### ก. โครงสร้าง Ethernet Frame Header (14 Bytes)
Ethernet II Header มีขนาดตายตัว **14 ไบต์**:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination MAC Address (6 Bytes)            |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  Source MAC Address (6 Bytes) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        EtherType (2B)         | (Payload เริ่มต้นที่ Byte 14) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Destination MAC (ไบต์ 0 - 5)**: Hardware address ของผู้รับ (เช่น `52:54:00:12:34:56`)
- **Source MAC (ไบต์ 6 - 11)**: Hardware address ของผู้ส่ง
- **EtherType (ไบต์ 12 - 13)**: ชนิดของโปรโตคอลใน L3:
  - `0x0800`: IPv4
  - `0x0806`: ARP (Address Resolution Protocol)
  - `0x86DD`: IPv6

#### ข. โครงสร้าง IPv4 Header (20 ไบต์ขั้นต่ำ)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|    Fragment Offset      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (ถ้ามี, ขยาย IHL)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Version (4 บิตแรก)**: สำหรับ IPv4 จะมีค่าเป็น `4` เสมอ
- **IHL (Internet Header Length - 4 บิตถัดมา)**: จำนวนคำขนาด 32 บิต (4 ไบต์) ใน Header ขั้นต่ำคือ `5` (คูณ 4 = 20 ไบต์)
- **Total Length (16 บิต)**: ขนาดรวมทั้งหมดของแพ็กเก็ต (Header + Payload)
- **TTL (Time to Live - 8 บิต)**: ลดลงทีละ 1 เมื่อผ่าน Router เพื่อกัน Packet Loop
- **Protocol (8 บิต)**: ชนิดโปรโตคอล L4:
  - `1`: ICMP (Ping)
  - `6`: TCP
  - `17`: UDP
- **Source IP & Destination IP (32 บิต / 4 ไบต์ต่อช่อง)**: เช่น `10.10.1.1`

#### ค. โครงสร้าง TCP Header (20 ไบต์ขั้นต่ำ)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Data Offset (4 บิต)**: ขนาดของ TCP Header นับเป็นจำนวน block 32 บิต (ปกติคือ 5 = 20 ไบต์)
- **TCP Flags (6 บิตสำคัญ)**:
  - `URG (0x20)`: Urgent pointer valid
  - `ACK (0x10)`: Acknowledgment field valid
  - `PSH (0x08)`: Push function (ส่งข้อมูลขึ้น App ทันที)
  - `RST (0x04)`: Reset connection
  - `SYN (0x02)`: Synchronize sequence numbers (เริ่ม 3-way handshake)
  - `FIN (0x01)`: Finish connection (ตัดการเชื่อมต่อ)

---

### 1.4 ความสำคัญของ Endianness (Network Byte Order vs Host Byte Order)
- อุปกรณ์เครือข่ายและโปรโตคอลมาตรฐานอินเทอร์เน็ตกำหนดให้ส่งข้อมูลแบบ **Big-Endian (Network Byte Order)** กล่าวคือ ไบต์ที่มีนัยสำคัญสูงสุด (Most Significant Byte - MSB) จะถูกส่งออกไปเป็นไบต์แรก
- ทว่า สถาปัตยกรรม CPU คอมพิวเตอร์ส่วนใหญ่ในปัจจุบัน (x86_64 และ ARM64 หลายระบบ) จัดเก็บข้อมูลในหน่วยความจำแบบ **Little-Endian (Host Byte Order)** ซึ่งเก็บ Least Significant Byte (LSB) ไว้ที่ Address ต่ำสุด
- ด้วยเหตุนี้ ในการพัฒนาโปรแกรมอ่าน Packet ด้วย Raw Socket หรือใน eBPF / XDP เราจำเป็นต้องแปลงค่าตัวเลข (เช่น Port, EtherType) ด้วยฟังก์ชันตระกูล `ntohs()` (Network to Host Short) หรือระบุ Format String `!` ในโมดูล `struct` ของ Python เพื่อบังคับให้ตีความเป็น Big-Endian เสมอ

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 สคริปต์จัดการเครือข่ายเสมือน: `lab_netns.sh`

```bash
# 1. การสร้าง Namespace ns1 และ ns2
ip netns add "${NS1}"
ip netns add "${NS2}"
```
- **คำอธิบาย**: ร้องขอให้ Linux Kernel สร้าง Isolated Network Context ใหม่ 2 ตัวชื่อ `ns1` และ `ns2` ซึ่งแต่ละตัวจะมี loopback device (`lo`) อยู่ในสถานะ `DOWN`

```bash
# 2. การสร้างสายเคเบิลเสมือน veth pair
ip link add "${VETH1}" type veth peer name "${VETH2}"
```
- **คำอธิบาย**: สร้าง Driver Interface ชนิด `veth` ในโฮสต์ โดยกำหนดให้อีกฝั่งหนึ่งของท่อชื่อ `veth2`

```bash
# 3. ย้าย interface เข้าสู่ namespace แต่ละฝั่ง
ip link set "${VETH1}" netns "${NS1}"
ip link set "${VETH2}" netns "${NS2}"
```
- **คำอธิบาย**: ย้ายปลายสายฝั่ง `veth1` หลุดออกจาก Host Namespace ไปสถิตอยู่ใน `ns1` และย้าย `veth2` ไปยัง `ns2`

```bash
# 4. กำหนด IP Address และเปิดใช้งาน Interface
ip netns exec "${NS1}" ip addr add "10.10.1.1/24" dev "${VETH1}"
ip netns exec "${NS2}" ip addr add "10.10.1.2/24" dev "${VETH2}"
ip netns exec "${NS1}" ip link set lo up
ip netns exec "${NS1}" ip link set "${VETH1}" up
ip netns exec "${NS2}" ip link set lo up
ip netns exec "${NS2}" ip link set "${VETH2}" up
```
- **คำอธิบาย**: `ip netns exec <ns>` คือคำสั่งให้รันโปรเซสภายใน context ของ namespace นั้นๆ โดยกำหนด IP ให้ `veth1` เป็น `10.10.1.1` และ `veth2` เป็น `10.10.1.2` พร้อมเปิดใช้งาน (`link set ... up`)

```bash
# 5. ปิด Checksum & Segmentation Offload
ip netns exec "${NS1}" ethtool -K "${VETH1}" rx off tx off tso off gso off gro off 2>/dev/null || true
```
- **คำอธิบาย**: ในสภาพแวดล้อมเสมือน เคอร์เนลมักจะทำ Hardware Checksum Offload หลอกๆ (ทำให้ Checksum ในแพ็กเก็ตที่ถูกดักจับกลายเป็น `0x0000` หรือ Invalid) การสั่งปิด offload บังคับให้เคอร์เนลคำนวณ Checksum จริงบนทุกแพ็กเก็ต ทำให้การดักจับแพ็กเก็ตเห็นข้อมูลที่ตรงตามมาตรฐานจริง 100%

---

### 2.2 โปรแกรมดักจับแพ็กเก็ต: `raw_sniffer.py`

#### การเปิด Raw Socket ระดับ Layer 2
```python
raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
```
- **คำอธิบาย**:
  - `socket.AF_PACKET`: ระบุว่าต้องการคุยกับเคอร์เนลที่ระดับ Device Driver Layer (Layer 2 - Data Link Layer) ซึ่งเฉพาะบน Linux เท่านั้น
  - `socket.SOCK_RAW`: รับแพ็กเก็ตดิบๆ รวม Header ทั้งหมด ไม่ผ่านการ strip ออกโดย Transport Layer
  - `socket.ntohs(0x0003)`: `0x0003` คือค่าคงที่ `ETH_P_ALL` ใน Header `<linux/if_ether.h>` หมายถึง "ให้ดักจับ Ethernet Frames ทุกโปรโตคอล" (IPv4, ARP, IPv6 ฯลฯ)

#### การถอดรหัส Ethernet Frame ด้วย `struct.unpack`
```python
dst_mac_raw, src_mac_raw, ether_type = struct.unpack("!6s6sH", packet[:14])
```
- **คำอธิบาย Format String `!6s6sH`**:
  - `!`: สั่งให้อ่านแบบ Big-Endian (Network Byte Order)
  - `6s`: อ่านไบต์จำนวน 6 ไบต์แรก (Destination MAC)
  - `6s`: อ่านไบต์จำนวน 6 ไบต์ถัดมา (Source MAC)
  - `H`: อ่านเลข Unsigned Short (ขนาด 2 ไบต์) สำหรับ EtherType เช่น `0x0800`

#### การสกัดฟิลด์ IPv4 และการจัดการ Bitwise Masking
```python
iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
version_ihl = iph[0]
version = version_ihl >> 4
ihl = (version_ihl & 0x0F) * 4
```
- **คำอธิบาย**:
  - ไบต์ที่ 0 ของ IPv4 Header เก็บทั้ง `Version` (4 บิตบน) และ `IHL` (4 บิตล่าง)
  - `version_ihl >> 4`: เลื่อนบิตไปทางขวา 4 ตำแหน่งเพื่อดึงเฉพาะค่า Version
  - `version_ihl & 0x0F`: ใช้ Bitwise AND กับ Mask `00001111` เพื่อดึงเฉพาะ 4 บิตล่าง (IHL) จากนั้นคูณ 4 เพื่อแปลงจำนวน 32-bit words ให้เป็นจำนวนไบต์จริง
  - `socket.inet_ntoa(iph[8])`: แปลง 4 ไบต์ดิบของ IP Address ให้อยู่ในรูปสตริง `A.B.C.D`

#### การแกะ TCP Flags ด้วย Bitwise AND
```python
tcph = struct.unpack("!HHLLBBHHH", data[:20])
flags = tcph[5]
if flags & 0x02:
    flag_names.append("SYN")
if flags & 0x10:
    flag_names.append("ACK")
```
- **คำอธิบาย**:
  - ไบต์ Flags ใน TCP Header ถูกบิตแมปไว้:
    - SYN คือบิตที่ 1 (`0x02` หรือ `00000010`)
    - ACK คือบิตที่ 4 (`0x10` หรือ `00010000`)
  - การตรวจสอบบิตเหล่านี้เป็นหัวใจสำคัญในการทำ State Machine Monitoring ใน eBPF

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

> **ข้อกำหนดเบื้องต้น**: การรัน Raw Socket และ Linux Network Namespaces ต้องรันบนระบบปฏิบัติการ Linux (Kernel 5.4+) ด้วยสิทธิ์ `root` (หรือ `sudo`)

### ขั้นตอนที่ 1: สร้าง Network Namespaces และ veth Pair
รันสคริปต์ `lab_netns.sh` เพื่อตั้งค่าระบบ:
```bash
sudo ./lab_netns.sh setup
```

**ผลลัพธ์ที่คาดหวัง**:
```text
===> Setting up isolated Network Namespaces (ns1 <-> ns2)...
[INFO] Step 1: Creating network namespaces 'ns1' and 'ns2'
[INFO] Step 2: Creating virtual Ethernet pair 'veth1' <---> 'veth2'
[INFO] Step 3: Moving 'veth1' to namespace 'ns1' and 'veth2' to 'ns2'
[INFO] Step 4: Assigning IP addresses
        ns1:veth1 -> 10.10.1.1/24
        ns2:veth2 -> 10.10.1.2/24
[INFO] Step 5: Bringing up loopback and veth interfaces in both namespaces
[INFO] Step 6: Disabling TX/RX checksum and segment offloading (TSO/GSO/GRO)
[SUCCESS] Lab topology successfully established!

===> Current Network Namespaces & Interface Topology
Active Namespaces:
  - ns2
  - ns1

[Namespace ns1] Interfaces:
lo               UP             127.0.0.1/8 ::1/128 
veth1            UP             10.10.1.1/24 fe80::.../64 

[Namespace ns2] Interfaces:
lo               UP             127.0.0.1/8 ::1/128 
veth2            UP             10.10.1.2/24 fe80::.../64 
```

---

### ขั้นตอนที่ 2: รัน Packet Sniffer ภายใน `ns2`
เปิด Terminal ที่ 1 แล้วรัน `raw_sniffer.py` ภายในบริบทของ Namespace `ns2`:
```bash
sudo ip netns exec ns2 python3 raw_sniffer.py --interface veth2 --verbose
```

โปรแกรมจะแสดงหน้าจอเตรียมพร้อมดักจับแพ็กเก็ต:
```text
======================================================
 eBPF Noob to Hero - Week 01: Low-Level Raw Sniffer   
======================================================
 Capturing on : interface 'veth2'
 Filter       : ALL
 Count limit  : Unlimited
 Verbose dump : Enabled
 Press Ctrl+C at any time to stop and view statistics.
------------------------------------------------------
```

---

### ขั้นตอนที่ 3: ส่งทราฟฟิกทดสอบจาก `ns1`
เปิด Terminal ที่ 2 แล้วส่งคำสั่ง `ping` และส่งข้อมูล TCP/UDP:

#### 3.1 ทดสอบส่ง ICMP Ping:
```bash
sudo ip netns exec ns1 ping -c 2 10.10.1.2
```

#### 3.2 ทดสอบส่ง UDP Packet:
```bash
sudo ip netns exec ns1 bash -c "echo 'Hello eBPF Network!' | nc -u -w1 10.10.1.2 9999"
```

---

### ขั้นตอนที่ 4: สังเกตผลลัพธ์ใน Sniffer
ใน Terminal ที่ 1 คุณจะเห็นการแกะแพ็กเก็ตออกมาอย่างแม่นยำ:
```text
[20:58:12] [ARP] 52:54:00:11:11:11 -> ff:ff:ff:ff:ff:ff | ARP Request: Who has 10.10.1.2? Tell 10.10.1.1
[20:58:12] [ARP] 52:54:00:22:22:22 -> 52:54:00:11:11:11 | ARP Reply: Who has 10.10.1.2? Tell 10.10.1.2
[20:58:12] [ICMP] 10.10.1.1 -> 10.10.1.2 | Echo Request (Code 0) TTL=64 Len=84
    0000:  9f 43 00 00 00 00 00 00 48 b9 02 00 00 00 00 00  |.C......H.......|
    0010:  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f  |................|
    ... (48 more bytes omitted) ...
[20:58:12] [ICMP] 10.10.1.2 -> 10.10.1.1 | Echo Reply (Code 0) TTL=64 Len=84
[20:58:15] [UDP]  10.10.1.1:45123 -> 10.10.1.2:9999 Len=27 Checksum=0x8fa1
    0000:  48 65 6c 6c 6f 20 65 42 50 46 20 4e 65 74 77 6f  |Hello eBPF Netwo|
    0010:  72 6b 21 0a                                      |rk!.|
```

กด `Ctrl+C` เพื่อดูสถิติสรุป:
```text
========== Packet Capture Statistics ==========
  Total Packets Captured : 5
  IPv4 Packets           : 3
    - TCP Packets        : 0
    - UDP Packets        : 1
    - ICMP Packets       : 2
    - Other L4 Protocols : 0
  ARP Packets            : 2
===============================================
```

---

### ขั้นตอนที่ 5: การรันแบบอัตโนมัติ (Automated Capture Test)
คุณสามารถรันการทดสอบครบวงจรด้วยคำสั่งเดียว:
```bash
sudo ./lab_netns.sh capture
```

### ขั้นตอนที่ 6: ล้างทรัพยากรเมื่อทดสอบเสร็จสิ้น
```bash
sudo ./lab_netns.sh clean
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 24.04 LTS (`Linux ebpf-lab 6.8.0-142-generic #142-Ubuntu SMP PREEMPT_DYNAMIC aarch64`)

### 4.1 การตั้งค่า Topology และทดสอบ Connectivity (`./lab_netns.sh setup && ./lab_netns.sh test`)
```text
===> Setting up isolated Network Namespaces (ns1 <-> ns2)...

===> Cleaning up existing Network Namespaces and veth interfaces...
[SUCCESS] Cleanup completed successfully.
[INFO] Step 1: Creating network namespaces 'ns1' and 'ns2'
[INFO] Step 2: Creating virtual Ethernet pair 'veth1' <---> 'veth2'
[INFO] Step 3: Moving 'veth1' to namespace 'ns1' and 'veth2' to 'ns2'
[INFO] Step 4: Assigning IP addresses
[INFO]         ns1:veth1 -> 10.10.1.1/24
[INFO]         ns2:veth2 -> 10.10.1.2/24
[INFO] Step 5: Bringing up loopback and veth interfaces in both namespaces
[INFO] Step 6: Disabling TX/RX checksum and segment offloading (TSO/GSO/GRO)
[SUCCESS] Lab topology successfully established!

===> Current Network Namespaces & Interface Topology
Active Namespaces:
  - ns2 (id: 1)
  - ns1 (id: 0)

[Namespace ns1] Interfaces:
lo               UNKNOWN        127.0.0.1/8 ::1/128 
veth1@if10       UP             10.10.1.1/24 fe80::c03a:e0ff:fe48:8430/64 

[Namespace ns2] Interfaces:
lo               UNKNOWN        127.0.0.1/8 ::1/128 
veth2@if11       UP             10.10.1.2/24 fe80::bc1f:6fff:fead:4f28/64 

===> Testing bidirectional ICMP connectivity...
[INFO] Pinging from ns1 (10.10.1.1) -> ns2 (10.10.1.2)...
PING 10.10.1.2 (10.10.1.2) 56(84) bytes of data.
64 bytes from 10.10.1.2: icmp_seq=1 ttl=64 time=0.024 ms
64 bytes from 10.10.1.2: icmp_seq=2 ttl=64 time=0.040 ms
64 bytes from 10.10.1.2: icmp_seq=3 ttl=64 time=0.056 ms

--- 10.10.1.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2055ms
rtt min/avg/max/mdev = 0.024/0.040/0.056/0.013 ms
[SUCCESS] Ping ns1 -> ns2 succeeded!
[INFO] Pinging from ns2 (10.10.1.2) -> ns1 (10.10.1.1)...
PING 10.10.1.1 (10.10.1.1) 56(84) bytes of data.
64 bytes from 10.10.1.1: icmp_seq=1 ttl=64 time=0.023 ms
64 bytes from 10.10.1.1: icmp_seq=2 ttl=64 time=0.036 ms
64 bytes from 10.10.1.1: icmp_seq=3 ttl=64 time=0.036 ms

--- 10.10.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2041ms
rtt min/avg/max/mdev = 0.023/0.031/0.036/0.006 ms
[SUCCESS] Ping ns2 -> ns1 succeeded!
[SUCCESS] All connectivity tests passed!
```

### 4.2 การดักจับแพ็กเก็ตระดับไบต์ด้วย `raw_sniffer.py`
```text
======================================================
 eBPF Noob to Hero - Week 01: Low-Level Raw Sniffer   
======================================================
 Capturing on : interface 'veth2'
 Filter       : ALL
 Count limit  : 8
 Verbose dump : Enabled
 Press Ctrl+C at any time to stop and view statistics.
------------------------------------------------------

[11:00:36] [ARP] be:1f:6f:ad:4f:28 -> c2:3a:e0:48:84:30 | ARP Request: Who has 10.10.1.1? Tell 10.10.1.2
    0000:  00 01 08 00 06 04 00 01 be 1f 6f ad 4f 28 0a 0a  |..........o.O(..|
    0010:  01 02 00 00 00 00 00 00 0a 0a 01 01              |............|
[11:00:36] [ARP] c2:3a:e0:48:84:30 -> be:1f:6f:ad:4f:28 | ARP Reply: Who has 10.10.1.2? Tell 10.10.1.1
    0000:  00 01 08 00 06 04 00 02 c2 3a e0 48 84 30 0a 0a  |.........:.H.0..|
    0010:  01 01 be 1f 6f ad 4f 28 0a 0a 01 02              |....o.O(....|
[11:00:36] [ICMP] 10.10.1.1 -> 10.10.1.2 | Echo Request (Code 0) TTL=64 Len=84
    0000:  07 96 00 01 64 44 d4 6a 00 00 00 00 25 47 03 00  |....dD.j....%G..|
    0010:  00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b  |................|
    0020:  1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b  |.... !"#$%&'()*+|
    0030:  2c 2d 2e 2f 30 31 32 33 34 35 36 37              |,-./01234567|
[11:00:36] [ICMP] 10.10.1.2 -> 10.10.1.1 | Echo Reply (Code 0) TTL=64 Len=84
    0000:  07 96 00 01 64 44 d4 6a 00 00 00 00 25 47 03 00  |....dD.j....%G..|
    0010:  00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b  |................|
    0020:  1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b  |.... !"#$%&'()*+|
    0030:  2c 2d 2e 2f 30 31 32 33 34 35 36 37              |,-./01234567|
[11:00:36] [L2-Other] EtherType=0x86dd be:1f:6f:ad:4f:28 -> 33:33:00:00:00:02
[11:00:37] [L2-Other] EtherType=0x86dd c2:3a:e0:48:84:30 -> 33:33:00:00:00:02
[11:00:37] [ICMP] 10.10.1.1 -> 10.10.1.2 | Echo Request (Code 0) TTL=64 Len=84
    0000:  07 96 00 02 65 44 d4 6a 00 00 00 00 40 01 04 00  |....eD.j....@...|
    0010:  00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b  |................|
    0020:  1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b  |.... !"#$%&'()*+|
    0030:  2c 2d 2e 2f 30 31 32 33 34 35 36 37              |,-./01234567|
[11:00:37] [ICMP] 10.10.1.2 -> 10.10.1.1 | Echo Reply (Code 0) TTL=64 Len=84
    0000:  07 96 00 02 65 44 d4 6a 00 00 00 00 40 01 04 00  |....eD.j....@...|
    0010:  00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b  |................|
    0020:  1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b  |.... !"#$%&'()*+|
    0030:  2c 2d 2e 2f 30 31 32 33 34 35 36 37              |,-./01234567|

========== Packet Capture Statistics ==========
  Total Packets Captured : 8
  IPv4 Packets           : 4
    - TCP Packets        : 0
    - UDP Packets        : 0
    - ICMP Packets       : 4
    - Other L4 Protocols : 0
  ARP Packets            : 2
===============================================
```

---

## 5. Milestone Checklist

ตรวจเช็คความเข้าใจและทักษะที่คุณได้รับในสัปดาห์นี้ก่อนก้าวเข้าสู่สัปดาห์ถัดไป:

- [x] **Network Namespaces Mastery**: เข้าใจการทำงานและสามารถสร้าง แยกส่วน และเชื่อมต่อ isolated namespace ด้วย `ip netns` และ `veth` pair ได้
- [x] **Frame Encapsulation**: เข้าใจลำดับชั้น L2 (Ethernet) -> L3 (IPv4/ARP) -> L4 (TCP/UDP/ICMP) และสามารถคำนวณตำแหน่ง Byte Offset ได้อย่างแม่นยำ
- [x] **Endianness Awareness**: ทราบเหตุผลว่าทำไมต้องแปลง Network Byte Order (Big-Endian) สู่ Host Byte Order และการใช้งานฟังก์ชัน `ntohs()` / `struct.unpack('!...')`
- [x] **Raw Socket Programming**: สามารถเปิด `socket.AF_PACKET` ดักจับเฟรมดิบโดยตรงจากเคอร์เนล Linux โดยไม่พึ่ง Third-party library
- [x] **Bitwise Manipulation**: สามารถใช้ Bit Shift (`>>`) และ Bitwise AND (`&`) ในการแกะ IPv4 Version/IHL และ TCP Flags ได้อย่างถูกต้อง
