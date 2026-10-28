# สัปดาห์ที่ 01: พื้นฐานระบบเครือข่ายและการดักจับแพ็กเก็ต (Packet Sniffing & Network Namespaces)

ยินดีต้อนรับสู่ **Week 01** ของหลักสูตร **eBPF Zero to Hero**! 
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
- แพ็กเก็ตที่ถูกส่งเข้าไปยังปลายด้านหนึ่ง (`w01-veth1`) จะพุ่งทะลุไปโผล่ที่ปลายอีกด้านหนึ่ง (`w01-veth2`) ทันทีในระดับ Kernel Space โดยไม่มี Physical Hardware มาเกี่ยวข้อง

```
+---------------------------+                      +---------------------------+
|    Namespace: w01-ns1     |                      |    Namespace: w01-ns2     |
|                           |                      |                           |
|   IP: 10.10.1.1/24        |                      |   IP: 10.10.1.2/24        |
|   Interface: [w01-veth1]  |<====================>|   Interface: [w01-veth2]  |
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
# 1. การสร้าง Namespace w01-ns1 และ w01-ns2
ip netns add "${NS1}"
ip netns add "${NS2}"
```
- **คำอธิบาย**: ร้องขอให้ Linux Kernel สร้าง Isolated Network Context ใหม่ 2 ตัวชื่อ `w01-ns1` และ `w01-ns2` ซึ่งแต่ละตัวจะมี loopback device (`lo`) อยู่ในสถานะ `DOWN`
- **ทำไมต้องมี prefix `w01-`?**: ชื่อ namespace (`/run/netns/<name>`) และชื่อ interface ใน Host Namespace เป็นทรัพยากรที่ใช้ร่วมกันทั้งเครื่อง หากหลาย Lab (หรือหลายคน) ใช้ชื่อกลางๆ อย่าง `ns1`/`veth1` พร้อมกัน คำสั่ง `clean` ของ Lab หนึ่งอาจไปลบของอีก Lab ได้ การใส่ prefix ประจำสัปดาห์จึงเป็นนิสัยที่ดี

```bash
# 2. การสร้างสายเคเบิลเสมือน veth pair
ip link add "${VETH1}" type veth peer name "${VETH2}"
```
- **คำอธิบาย**: สร้าง Driver Interface ชนิด `veth` ในโฮสต์ โดยกำหนดให้อีกฝั่งหนึ่งของท่อชื่อ `w01-veth2`

```bash
# 3. ย้าย interface เข้าสู่ namespace แต่ละฝั่ง
ip link set "${VETH1}" netns "${NS1}"
ip link set "${VETH2}" netns "${NS2}"
```
- **คำอธิบาย**: ย้ายปลายสายฝั่ง `w01-veth1` หลุดออกจาก Host Namespace ไปสถิตอยู่ใน `w01-ns1` และย้าย `w01-veth2` ไปยัง `w01-ns2`

```bash
# 4. กำหนด IP Address และเปิดใช้งาน Interface
ip netns exec "${NS1}" ip addr add "10.10.1.1/24" dev "${VETH1}"
ip netns exec "${NS2}" ip addr add "10.10.1.2/24" dev "${VETH2}"
ip netns exec "${NS1}" ip link set lo up
ip netns exec "${NS1}" ip link set "${VETH1}" up
ip netns exec "${NS2}" ip link set lo up
ip netns exec "${NS2}" ip link set "${VETH2}" up
```
- **คำอธิบาย**: `ip netns exec <ns>` คือคำสั่งให้รันโปรเซสภายใน context ของ namespace นั้นๆ โดยกำหนด IP ให้ `w01-veth1` เป็น `10.10.1.1` และ `w01-veth2` เป็น `10.10.1.2` พร้อมเปิดใช้งาน (`link set ... up`)

```bash
# 5. ปิด Checksum & Segmentation Offload
ip netns exec "${NS1}" ethtool -K "${VETH1}" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true
```
- **คำอธิบาย**: อุปกรณ์เสมือนอย่าง `veth` ประกาศว่ารองรับ Checksum/Segmentation Offload โดยค่าเริ่มต้น เคอร์เนลจึงอาจ "เลื่อน" การคำนวณ Checksum ออกไป (สถานะ `CHECKSUM_PARTIAL`) ทำให้ Checksum ที่ Raw Socket ดักได้ฝั่งผู้ส่งยังไม่สมบูรณ์ และอาจเห็นแพ็กเก็ต TCP ขนาดใหญ่กว่า MTU (จาก TSO/GSO/GRO) การสั่งปิด offload บังคับให้เคอร์เนลคำนวณ Checksum และแบ่ง Segment ตามจริง ทำให้ข้อมูลที่ดักได้ตรงกับสิ่งที่วิ่งบนสายจริงมากที่สุด (สคริปต์ส่ง stdout/stderr ของ `ethtool` ทิ้งไปเพื่อไม่ให้รก)

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
>
> **ความปลอดภัยของ Lab**: สคริปต์ทำงานเฉพาะใน namespace `w01-ns1`/`w01-ns2` และ veth `w01-veth1`/`w01-veth2` เท่านั้น ไม่แตะ NIC, route, iptables หรือ sysctl ของ Host อย่าลืมรัน `sudo ./lab_netns.sh clean` ทุกครั้งเมื่อทดลองเสร็จ

### ขั้นตอนที่ 1: สร้าง Network Namespaces และ veth Pair
รันสคริปต์ `lab_netns.sh` เพื่อตั้งค่าระบบ:
```bash
sudo ./lab_netns.sh setup
```

**ผลลัพธ์ที่คาดหวัง** (ผลรันจริง; หมายเลข `@ifNNNN` และ IPv6 link-local จะต่างกันในแต่ละเครื่อง):
```text

===> Cleaning up existing Network Namespaces and veth interfaces...
[SUCCESS] Cleanup completed successfully.
[INFO] Step 1: Creating network namespaces 'w01-ns1' and 'w01-ns2'
[INFO] Step 2: Creating virtual Ethernet pair 'w01-veth1' <---> 'w01-veth2'
[INFO] Step 3: Moving 'w01-veth1' to namespace 'w01-ns1' and 'w01-veth2' to 'w01-ns2'
[INFO] Step 4: Assigning IP addresses
[INFO]         w01-ns1:w01-veth1 -> 10.10.1.1/24
[INFO]         w01-ns2:w01-veth2 -> 10.10.1.2/24
[INFO] Step 5: Bringing up loopback and veth interfaces in both namespaces
[INFO] Step 6: Disabling TX/RX checksum and segment offloading (TSO/GSO/GRO)
[SUCCESS] Lab topology successfully established!

===> Current Network Namespaces & Interface Topology
Active Namespaces:
  - w01-ns2 (id: 2)
  - w01-ns1 (id: 1)

[Namespace w01-ns1] Interfaces:
lo               UNKNOWN        127.0.0.1/8 ::1/128 
w01-veth1@if1620 UP             10.10.1.1/24 fe80::38dc:23ff:fed5:a5/64 

[Namespace w01-ns2] Interfaces:
lo               UNKNOWN        127.0.0.1/8 ::1/128 
w01-veth2@if1621 UP             10.10.1.2/24 fe80::7060:94ff:fe9d:a5f1/64 
```

---

### ขั้นตอนที่ 2: รัน Packet Sniffer ภายใน `w01-ns2`
เปิด Terminal ที่ 1 แล้วรัน `raw_sniffer.py` ภายในบริบทของ Namespace `w01-ns2`:
```bash
sudo ip netns exec w01-ns2 python3 raw_sniffer.py --interface w01-veth2 --verbose
```

โปรแกรมจะแสดงหน้าจอเตรียมพร้อมดักจับแพ็กเก็ต:
```text
======================================================
 eBPF Zero to Hero - Week 01: Low-Level Raw Sniffer   
======================================================
 Capturing on : interface 'w01-veth2'
 Filter       : ALL
 Count limit  : Unlimited
 Verbose dump : Enabled
 Press Ctrl+C at any time to stop and view statistics.
------------------------------------------------------
```

---

### ขั้นตอนที่ 3: ส่งทราฟฟิกทดสอบจาก `w01-ns1`
เปิด Terminal ที่ 2 แล้วส่งคำสั่ง `ping` และส่งข้อมูล TCP/UDP:

#### 3.1 ทดสอบส่ง ICMP Ping:
```bash
sudo ip netns exec w01-ns1 ping -c 2 10.10.1.2
```

#### 3.2 ทดสอบส่ง UDP Packet:
```bash
sudo ip netns exec w01-ns1 bash -c "echo 'Hello eBPF Network!' | nc -u -w1 10.10.1.2 9999"
```

---

### ขั้นตอนที่ 4: สังเกตผลลัพธ์ใน Sniffer
ใน Terminal ที่ 1 คุณจะเห็นการแกะแพ็กเก็ตออกมาอย่างแม่นยำ (ตัดบางส่วนจากผลรันจริงในหัวข้อที่ 4; MAC Address, Port และ Checksum จะต่างไปในแต่ละครั้ง):
```text
[22:14:54] [ARP] 3a:dc:23:d5:00:a5 -> ff:ff:ff:ff:ff:ff | ARP Request: Who has 10.10.1.2? Tell 10.10.1.1
[22:14:54] [ARP] 72:60:94:9d:a5:f1 -> 3a:dc:23:d5:00:a5 | ARP Reply: 10.10.1.2 is at 72:60:94:9d:a5:f1
[22:14:54] [ICMP] 10.10.1.1 -> 10.10.1.2 | Echo Request (Code 0) TTL=64 Len=84
[22:14:54] [ICMP] 10.10.1.2 -> 10.10.1.1 | Echo Reply (Code 0) TTL=64 Len=84
[22:14:54] [UDP]  10.10.1.1:35318 -> 10.10.1.2:9999 Len=28 Checksum=0xce77
    0000:  48 65 6c 6c 6f 20 65 42 50 46 20 4e 65 74 77 6f  |Hello eBPF Netwo|
    0010:  72 6b 21 0a                                      |rk!.|
[22:14:54] [ICMP] 10.10.1.2 -> 10.10.1.1 | Destination Unreachable (Code 3) TTL=64 Len=76
```
- `Len=28` ของ UDP = UDP Header 8 ไบต์ + Payload `"Hello eBPF Network!\n"` 20 ไบต์
- ICMP `Destination Unreachable (Code 3)` = **Port Unreachable** เพราะไม่มีโปรเซสใดฟังอยู่ที่ UDP port 9999 ใน `w01-ns2` (เคอร์เนลของ `w01-ns2` ตอบกลับเอง)

กด `Ctrl+C` เพื่อดูสถิติสรุป (ตัวเลขขึ้นกับทราฟฟิกที่คุณส่ง; Ctrl+C จะพิมพ์สถิติเพียงครั้งเดียว):
```text
========== Packet Capture Statistics ==========
  Total Packets Captured : 18
  IPv4 Packets           : 12
    - TCP Packets        : 8
    - UDP Packets        : 1
    - ICMP Packets       : 3
    - Other L4 Protocols : 0
  ARP Packets            : 4
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

> **Environment**: Ubuntu 26.04 (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), Python 3, iproute2, ethtool

### 4.1 การตั้งค่า Topology และทดสอบ Connectivity (`sudo ./lab_netns.sh setup && sudo ./lab_netns.sh test`)
```text
===> Setting up isolated Network Namespaces (w01-ns1 <-> w01-ns2)...

===> Cleaning up existing Network Namespaces and veth interfaces...
[SUCCESS] Cleanup completed successfully.
[INFO] Step 1: Creating network namespaces 'w01-ns1' and 'w01-ns2'
[INFO] Step 2: Creating virtual Ethernet pair 'w01-veth1' <---> 'w01-veth2'
[INFO] Step 3: Moving 'w01-veth1' to namespace 'w01-ns1' and 'w01-veth2' to 'w01-ns2'
[INFO] Step 4: Assigning IP addresses
[INFO]         w01-ns1:w01-veth1 -> 10.10.1.1/24
[INFO]         w01-ns2:w01-veth2 -> 10.10.1.2/24
[INFO] Step 5: Bringing up loopback and veth interfaces in both namespaces
[INFO] Step 6: Disabling TX/RX checksum and segment offloading (TSO/GSO/GRO)
[SUCCESS] Lab topology successfully established!

===> Current Network Namespaces & Interface Topology
Active Namespaces:
  - w01-ns2 (id: 2)
  - w01-ns1 (id: 1)

[Namespace w01-ns1] Interfaces:
lo               UNKNOWN        127.0.0.1/8 ::1/128 
w01-veth1@if1620 UP             10.10.1.1/24 fe80::38dc:23ff:fed5:a5/64 

[Namespace w01-ns2] Interfaces:
lo               UNKNOWN        127.0.0.1/8 ::1/128 
w01-veth2@if1621 UP             10.10.1.2/24 fe80::7060:94ff:fe9d:a5f1/64 
===> Testing bidirectional ICMP connectivity...
[INFO] Pinging from w01-ns1 (10.10.1.1) -> w01-ns2 (10.10.1.2)...
PING 10.10.1.2 (10.10.1.2) 56(84) bytes of data.
64 bytes from 10.10.1.2: icmp_seq=1 ttl=64 time=0.034 ms
64 bytes from 10.10.1.2: icmp_seq=2 ttl=64 time=0.056 ms
64 bytes from 10.10.1.2: icmp_seq=3 ttl=64 time=0.058 ms

--- 10.10.1.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2033ms
rtt min/avg/max/mdev = 0.034/0.049/0.058/0.010 ms
[SUCCESS] Ping w01-ns1 -> w01-ns2 succeeded!
[INFO] Pinging from w01-ns2 (10.10.1.2) -> w01-ns1 (10.10.1.1)...
PING 10.10.1.1 (10.10.1.1) 56(84) bytes of data.
64 bytes from 10.10.1.1: icmp_seq=1 ttl=64 time=0.046 ms
64 bytes from 10.10.1.1: icmp_seq=2 ttl=64 time=0.023 ms
64 bytes from 10.10.1.1: icmp_seq=3 ttl=64 time=0.074 ms

--- 10.10.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2041ms
rtt min/avg/max/mdev = 0.023/0.047/0.074/0.020 ms
[SUCCESS] Ping w01-ns2 -> w01-ns1 succeeded!
[SUCCESS] All connectivity tests passed!
```

### 4.2 การดักจับแพ็กเก็ตระดับไบต์ด้วย `raw_sniffer.py`
คำสั่งที่ใช้: Terminal 1 รัน `sudo ip netns exec w01-ns2 python3 raw_sniffer.py --interface w01-veth2 --verbose` ส่วน Terminal 2 ล้าง ARP cache แล้วส่ง `ping -c 1`, UDP ไปพอร์ต 9999 (ไม่มีใครฟัง) และ TCP ไปพอร์ต 8080 (มี `nc -l -p 8080` รออยู่ใน `w01-ns2`):
```text
======================================================
 eBPF Zero to Hero - Week 01: Low-Level Raw Sniffer   
======================================================
 Capturing on : interface 'w01-veth2'
 Filter       : ALL
 Count limit  : Unlimited
 Verbose dump : Enabled
 Press Ctrl+C at any time to stop and view statistics.
------------------------------------------------------

[22:14:54] [L2-Other] EtherType=0x86dd 72:60:94:9d:a5:f1 -> 33:33:00:00:00:02
[22:14:54] [ARP] 72:60:94:9d:a5:f1 -> 3a:dc:23:d5:00:a5 | ARP Request: Who has 10.10.1.1? Tell 10.10.1.2
    0000:  00 01 08 00 06 04 00 01 72 60 94 9d a5 f1 0a 0a  |........r`......|
    0010:  01 02 00 00 00 00 00 00 0a 0a 01 01              |............|
[22:14:54] [ARP] 3a:dc:23:d5:00:a5 -> 72:60:94:9d:a5:f1 | ARP Reply: 10.10.1.1 is at 3a:dc:23:d5:00:a5
    0000:  00 01 08 00 06 04 00 02 3a dc 23 d5 00 a5 0a 0a  |........:.#.....|
    0010:  01 01 72 60 94 9d a5 f1 0a 0a 01 02              |..r`........|
[22:14:54] [ARP] 3a:dc:23:d5:00:a5 -> ff:ff:ff:ff:ff:ff | ARP Request: Who has 10.10.1.2? Tell 10.10.1.1
    0000:  00 01 08 00 06 04 00 01 3a dc 23 d5 00 a5 0a 0a  |........:.#.....|
    0010:  01 01 00 00 00 00 00 00 0a 0a 01 02              |............|
[22:14:54] [ARP] 72:60:94:9d:a5:f1 -> 3a:dc:23:d5:00:a5 | ARP Reply: 10.10.1.2 is at 72:60:94:9d:a5:f1
    0000:  00 01 08 00 06 04 00 02 72 60 94 9d a5 f1 0a 0a  |........r`......|
    0010:  01 02 3a dc 23 d5 00 a5 0a 0a 01 01              |..:.#.......|
[22:14:54] [ICMP] 10.10.1.1 -> 10.10.1.2 | Echo Request (Code 0) TTL=64 Len=84
    0000:  43 2f 00 01 6e 11 e2 6a 00 00 00 00 20 11 0a 00  |C/..n..j.... ...|
    0010:  00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b  |................|
    0020:  1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b  |.... !"#$%&'()*+|
    0030:  2c 2d 2e 2f 30 31 32 33 34 35 36 37              |,-./01234567|
[22:14:54] [ICMP] 10.10.1.2 -> 10.10.1.1 | Echo Reply (Code 0) TTL=64 Len=84
    0000:  43 2f 00 01 6e 11 e2 6a 00 00 00 00 20 11 0a 00  |C/..n..j.... ...|
    0010:  00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b  |................|
    0020:  1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b  |.... !"#$%&'()*+|
    0030:  2c 2d 2e 2f 30 31 32 33 34 35 36 37              |,-./01234567|
[22:14:54] [UDP]  10.10.1.1:35318 -> 10.10.1.2:9999 Len=28 Checksum=0xce77
    0000:  48 65 6c 6c 6f 20 65 42 50 46 20 4e 65 74 77 6f  |Hello eBPF Netwo|
    0010:  72 6b 21 0a                                      |rk!.|
[22:14:54] [ICMP] 10.10.1.2 -> 10.10.1.1 | Destination Unreachable (Code 3) TTL=64 Len=76
    0000:  00 00 00 00 45 00 00 30 16 a8 40 00 40 11 0d ff  |....E..0..@.@...|
    0010:  0a 0a 01 01 0a 0a 01 02 89 f6 27 0f 00 1c ce 77  |..........'....w|
    0020:  48 65 6c 6c 6f 20 65 42 50 46 20 4e 65 74 77 6f  |Hello eBPF Netwo|
    0030:  72 6b 21 0a                                      |rk!.|
[22:14:54] [TCP]  10.10.1.1:40068 -> 10.10.1.2:8080 [SYN] Seq=1813799347 Ack=0 Win=64240
[22:14:54] [TCP]  10.10.1.2:8080 -> 10.10.1.1:40068 [ACK|SYN] Seq=3095122178 Ack=1813799348 Win=65160
[22:14:54] [TCP]  10.10.1.1:40068 -> 10.10.1.2:8080 [ACK] Seq=1813799348 Ack=3095122179 Win=63
[22:14:54] [TCP]  10.10.1.1:40068 -> 10.10.1.2:8080 [ACK|PSH] Seq=1813799348 Ack=3095122179 Win=63
    0000:  68 69 0a                                         |hi.|
[22:14:54] [TCP]  10.10.1.2:8080 -> 10.10.1.1:40068 [ACK] Seq=3095122179 Ack=1813799351 Win=64
[22:14:54] [L2-Other] EtherType=0x86dd 3a:dc:23:d5:00:a5 -> 33:33:00:00:00:02
[22:14:55] [TCP]  10.10.1.1:40068 -> 10.10.1.2:8080 [ACK|FIN] Seq=1813799351 Ack=3095122179 Win=63
[22:14:55] [TCP]  10.10.1.2:8080 -> 10.10.1.1:40068 [ACK|FIN] Seq=3095122179 Ack=1813799352 Win=64
[22:14:55] [TCP]  10.10.1.1:40068 -> 10.10.1.2:8080 [ACK] Seq=1813799352 Ack=3095122180 Win=63

[!] Interrupted by user. Exiting...

========== Packet Capture Statistics ==========
  Total Packets Captured : 18
  IPv4 Packets           : 12
    - TCP Packets        : 8
    - UDP Packets        : 1
    - ICMP Packets       : 3
    - Other L4 Protocols : 0
  ARP Packets            : 4
===============================================
```

ข้อสังเกตจากผลจริง:
- **ARP 4 เฟรม** เพราะเราล้าง ARP cache ทั้งสองฝั่ง ทั้งสองฝั่งจึงต่างถามหากัน
- **`[L2-Other] EtherType=0x86dd ... -> 33:33:00:00:00:02`** คือ IPv6 Router Solicitation (multicast `ff02::2`) ที่เคอร์เนลส่งเองเมื่อ interface ขึ้น
- **TCP 3-way handshake** เห็นครบ: `[SYN]` -> `[ACK|SYN]` -> `[ACK]` แล้วตามด้วยข้อมูล `[ACK|PSH]` และการปิด `[ACK|FIN]`
- **`Win=63`** หลัง handshake ไม่ได้แปลว่า Window เล็ก แต่เป็นค่าดิบก่อนคูณ **Window Scale** (TCP option ที่ตกลงกันตอน SYN) — sniffer ของเราไม่ได้ parse TCP options

---

## 5. Milestone Checklist

ตรวจเช็คความเข้าใจและทักษะที่คุณได้รับในสัปดาห์นี้ก่อนก้าวเข้าสู่สัปดาห์ถัดไป:

- [x] **Network Namespaces Mastery**: เข้าใจการทำงานและสามารถสร้าง แยกส่วน และเชื่อมต่อ isolated namespace ด้วย `ip netns` และ `veth` pair ได้
- [x] **Frame Encapsulation**: เข้าใจลำดับชั้น L2 (Ethernet) -> L3 (IPv4/ARP) -> L4 (TCP/UDP/ICMP) และสามารถคำนวณตำแหน่ง Byte Offset ได้อย่างแม่นยำ
- [x] **Endianness Awareness**: ทราบเหตุผลว่าทำไมต้องแปลง Network Byte Order (Big-Endian) สู่ Host Byte Order และการใช้งานฟังก์ชัน `ntohs()` / `struct.unpack('!...')`
- [x] **Raw Socket Programming**: สามารถเปิด `socket.AF_PACKET` ดักจับเฟรมดิบโดยตรงจากเคอร์เนล Linux โดยไม่พึ่ง Third-party library
- [x] **Bitwise Manipulation**: สามารถใช้ Bit Shift (`>>`) และ Bitwise AND (`&`) ในการแกะ IPv4 Version/IHL และ TCP Flags ได้อย่างถูกต้อง

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

ข้อความ error ด้านล่างทดสอบจริงบน Ubuntu 26.04 / Linux 7.0 (ข้อความอาจต่างเล็กน้อยตามเวอร์ชันของ iproute2/Python):

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `RTNETLINK answers: Operation not permitted` | รันคำสั่ง `ip link add` / `ip netns add` โดยไม่มีสิทธิ์ root (ต้องใช้ `CAP_NET_ADMIN`) | รันผ่าน `sudo` เช่น `sudo ./lab_netns.sh setup` |
| `Cannot create namespace file "/run/netns/w01-ns1": File exists` | มี namespace ชื่อนี้ค้างอยู่จากการรันครั้งก่อน (เช่นสคริปต์ถูก Ctrl+C กลางทาง) | `sudo ./lab_netns.sh clean` แล้วค่อย `setup` ใหม่ (ฟังก์ชัน `setup` เรียก `clean` ให้อัตโนมัติอยู่แล้ว) |
| `Cannot open network namespace "w01-ns2": No such file or directory` | ยังไม่ได้สร้าง Topology หรือพิมพ์ชื่อผิด (ลืม prefix `w01-`) | `ip netns list` เพื่อดูชื่อจริง แล้วรัน `sudo ./lab_netns.sh setup` |
| `[ERROR] Failed to bind raw socket: [Errno 19] No such device` | ชื่อ interface ไม่มีอยู่ใน namespace ที่รัน sniffer (เช่น รัน `-i w01-veth2` จาก Host Namespace โดยลืม `ip netns exec w01-ns2`) | `sudo ip netns exec w01-ns2 ip -br link` เพื่อดูชื่อ interface แล้วรัน sniffer ภายใน namespace นั้น |
| `[ERROR] Raw sockets require root privileges!` | `AF_PACKET` + `SOCK_RAW` ต้องใช้ `CAP_NET_RAW` | รันด้วย `sudo` |
| `ping: connect: Network is unreachable` | namespace ไม่มี route ไปยังปลายทาง (ยังไม่ได้ใส่ IP, interface ยัง `DOWN` หรือรันผิด namespace) | ตรวจ `sudo ip netns exec w01-ns1 ip -br addr` และ `ip route` ต้องเห็น `10.10.1.0/24` |
| ping ได้แต่ sniffer ไม่แสดงอะไรเลย | ผูก sniffer กับ interface ผิดฝั่ง หรือใช้ `--protocol` กรองทิ้ง | ลองรันโดยไม่ใส่ `-p` และใช้ `--verbose`; เทียบกับ `sudo ip netns exec w01-ns2 tcpdump -ni w01-veth2` |
| Checksum ของแพ็กเก็ตขาออกดูผิด / เห็น TCP segment ใหญ่กว่า MTU | Offload (TX checksum, TSO/GSO/GRO) ยังเปิดอยู่ | `sudo ip netns exec w01-ns1 ethtool -k w01-veth1 \| grep -E 'checksum\|segmentation'` ต้องเป็น `off` |

> **ทิป**: หาก Lab ค้างหรือรวน ให้เริ่มจาก `sudo ./lab_netns.sh clean` เสมอ — การลบ namespace จะลบ veth ที่อยู่ข้างในให้อัตโนมัติ

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **แยกโปรโตคอลด้วยตัวกรอง**: รัน sniffer ด้วย `--protocol udp` แล้วส่งทั้ง ping และ UDP จาก `w01-ns1`
   - **สิ่งที่ต้องส่ง**: ภาพหน้าจอ/ข้อความผลลัพธ์ที่แสดงเฉพาะบรรทัด `[UDP]` พร้อมอธิบายว่าทำไมสถิติท้ายโปรแกรมยังนับ `ICMP Packets` ด้วย (ดูลำดับการนับ `STATS` เทียบกับ `continue` ในโค้ด)
   - **วิธีตรวจ**: `sudo ip netns exec w01-ns2 python3 raw_sniffer.py -i w01-veth2 -p udp` แล้วใน Terminal 2: `sudo ip netns exec w01-ns1 ping -c 2 10.10.1.2; sudo ip netns exec w01-ns1 bash -c "echo hi | nc -u -w1 10.10.1.2 9999"`
2. **คำนวณ Offset ด้วยมือ**: จาก hexdump ของ ICMP Echo Request ในหัวข้อ 4.2 ระบุว่า ICMP Identifier และ Sequence Number อยู่ไบต์ใดของ ICMP Header และมีค่าเท่าใด
   - **สิ่งที่ต้องส่ง**: ตารางไบต์ -> ฟิลด์ -> ค่า (ฐาน 16 และฐาน 10)
   - **วิธีตรวจ**: เทียบกับ `sudo ip netns exec w01-ns2 tcpdump -ni w01-veth2 -c 2 -vv icmp` ซึ่งพิมพ์ `id` และ `seq` ออกมาให้

### ระดับปานกลาง
3. **เพิ่ม TCP Window Scale**: แก้ `parse_tcp()` ให้อ่าน TCP Options (เมื่อ `header_len > 20`) และพิมพ์ `MSS` กับ `WScale` ของแพ็กเก็ต `[SYN]`
   - **สิ่งที่ต้องส่ง**: diff ของโค้ด + ผลลัพธ์ที่เห็น `MSS=1460` (ค่าจริงขึ้นกับ MTU) และ `WScale=N` บนบรรทัด SYN/SYN-ACK
   - **วิธีตรวจ**: `sudo ip netns exec w01-ns2 nc -l -p 8080 &` แล้ว `sudo ip netns exec w01-ns1 bash -c "echo hi | nc -w1 10.10.1.2 8080"`; เทียบกับ `tcpdump -ni w01-veth2 -c 3 tcp` ซึ่งแสดง `options [mss ...,wscale ...]`
4. **ตรวจ IPv4 Header Checksum**: เขียนฟังก์ชันคำนวณ Internet Checksum (RFC 1071) แล้วพิมพ์ `CHK=OK/BAD` ต่อท้ายบรรทัด IPv4 ทุกบรรทัด
   - **สิ่งที่ต้องส่ง**: โค้ด + ผลลัพธ์ที่ทุกแพ็กเก็ตเป็น `OK` เมื่อปิด offload แล้ว
   - **วิธีตรวจ**: รัน `sudo ./lab_netns.sh capture` (หรือรัน sniffer เอง) ทุกบรรทัดต้องขึ้น `CHK=OK`

### ระดับท้าทาย
5. **Topology 3 โหนดแบบ Router**: เพิ่ม namespace `w01-r` ตรงกลางเป็น Router (`w01-ns1` <-> `w01-r` <-> `w01-ns2` คนละ subnet) เปิด `net.ipv4.ip_forward=1` **ภายใน** `w01-r` เท่านั้น
   - **สิ่งที่ต้องส่ง**: สคริปต์ `setup`/`clean` ที่ปรับปรุงแล้ว + ผล sniffer ที่เห็น `TTL=63` (ลดลง 1 หลังผ่าน Router)
   - **วิธีตรวจ**: `sudo ip netns exec w01-ns1 ping -c 2 <IP ของ w01-ns2>` สำเร็จ และ `sysctl net.ipv4.ip_forward` ของ Host ต้องไม่เปลี่ยน
6. **ลดภาระด้วย Classic BPF**: ใช้ `SO_ATTACH_FILTER` ผูก cBPF ที่ได้จาก `tcpdump -dd icmp` เข้ากับ raw socket เพื่อให้เคอร์เนลกรองเฉพาะ ICMP ก่อนส่งขึ้น User Space (นี่คือบรรพบุรุษของ eBPF!)
   - **สิ่งที่ต้องส่ง**: โค้ด + คำอธิบายว่าแตกต่างจากตัวกรอง `--protocol` เดิมอย่างไร
   - **วิธีตรวจ**: ส่ง UDP และ ping พร้อมกัน — `Total Packets Captured` ต้องนับเฉพาะ ICMP (เพราะแพ็กเก็ตอื่นไม่ถูกส่งขึ้นมาถึง socket เลย)
