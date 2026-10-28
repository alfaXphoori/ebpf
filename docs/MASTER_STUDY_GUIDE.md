# คู่มือวิศวกรรม eBPF ฉบับสมบูรณ์ (Master eBPF Study Guide)
### จากโครงสร้างแพ็กเก็ตระดับฮาร์ดแวร์ สู่การเขียนโปรแกรมเคอร์เนลความเร็วสูงด้วย Modern eBPF, XDP, TC, Ring Buffer, BPF LSM และ Go (Cilium)

---

## สารบัญเนื้อหา (Table of Contents)

1. [บทที่ 1: ผ่าโครงสร้าง Packet และการเดินทางใน Linux Kernel (เฟส 01)](#บทที่-1-ผ่าโครงสร้าง-packet-และการเดินทางใน-linux-kernel-เฟส-1)
   - 1.1 โครงสร้างระดับ Byte ของ Ethernet Frame (Layer 2)
   - 1.2 โครงสร้าง IPv4 Header (Layer 3) และการคำนวณ IHL
   - 1.3 โครงสร้าง TCP และ UDP Headers (Layer 4)
   - 1.4 Big-Endian (Network Byte Order) vs Little-Endian (Host Byte Order)
   - 1.5 เส้นทางชีวิตของ Packet ใน Linux Network Stack แบบครบวงจร (From Wire to Socket)
2. [บทที่ 2: กลไกภายในของ eBPF และด่านตรวจ Verifier (เฟส 02)](#บทที่-2-กลไกภายในของ-ebpf-และด่านตรวจ-verifier-เฟส-2)
   - 2.1 สถาปัตยกรรม eBPF Virtual Machine (Registers R0–R10 และ 512B Stack)
   - 2.2 วงจรการคอมไพล์และโหลดโปรแกรม: จาก C สู่ Clang, ELF และ BPF Syscall
   - 2.3 ด่านตรวจความปลอดภัย eBPF Verifier (Control Flow Graph & Static Analysis)
   - 2.4 กลไก JIT (Just-In-Time) Compiler และ BPF Hardening
3. [บทที่ 3: การเขียน eBPF ยุคใหม่แบบ CO-RE และการใช้ Maps (เฟส 03)](#บทที่-3-การเขียน-ebpf-ยุคใหม่แบบ-co-re-และการใช้-maps-เฟส-3)
   - 3.1 จุดจบของยุค BCC สู่ความเป็นมาตรฐานของ Modern CO-RE (Compile Once – Run Everywhere)
   - 3.2 เจาะลึก BTF (BPF Type Format) และ `vmlinux.h`
   - 3.3 การประกาศและเลือกใช้งาน eBPF Maps (Hash, LRU Hash, Per-CPU Array, Ring Buffer)
   - 3.4 ภาวะแย่งชิงข้อมูล (Race Conditions) และการแก้ปัญหาด้วย Atomic Operations / Per-CPU
4. [บทที่ 4: เจาะลึกการเขียน XDP และการทำ Bounds Checking (เฟส 04)](#บทที่-4-เจาะลึกการเขียน-xdp-และการทำ-bounds-checking-เฟส-4)
   - 4.1 สถาปัตยกรรม XDP และบริบท `struct xdp_md`
   - 4.2 ผลลัพธ์ทั้ง 5 ของ XDP (XDP Actions: DROP, PASS, TX, REDIRECT, ABORTED)
   - 4.3 กฎเหล็ก Pointer Arithmetic & Verifier Bounds Checking ทีละเลเยอร์
   - 4.4 Traffic Control (TC) vs XDP และการทำ Packet Mangling พร้อมคำนวณ Checksum
   - 4.5 บันทึกจากการทดลองจริง (Lab Notes จาก Week 07–08)
5. [บทที่ 5: การสตรีมข้อมูลด้วย Ring Buffer และการบล็อกด้วย BPF LSM (เฟส 05)](#บทที่-5-การสตรีมข้อมูลด้วย-ring-buffer-และการบล็อกด้วย-bpf-lsm-เฟส-5)
   - 5.1 สถาปัตยกรรม Memory-mapped BPF Ring Buffer (MPSC Lockless Architecture)
   - 5.2 วงจรชีวิตของข้อมูล: `bpf_ringbuf_reserve`, `submit` และ `discard`
   - 5.3 การดักฟังสัญญะระดับ User Space ด้วย Uprobes / Uretprobes (TLS Inspection)
   - 5.4 การรักษาความปลอดภัยเชิงรุกด้วย BPF LSM (Linux Security Modules)
   - 5.5 บันทึกจากการทดลองจริง (Lab Notes จาก Week 09–10)
6. [บทที่ 6: โค้ดฝั่ง User Space ด้วยภาษา Go (`cilium/ebpf`) & Cheat Sheet (เฟส 06)](#บทที่-6-โค้ดฝั่ง-user-space-ด้วยภาษา-go-ciliumebpf--cheat-sheet-เฟส-6)
   - 6.1 สถาปัตยกรรม Pure Go eBPF Loader และการใช้งาน `bpf2go`
   - 6.2 พิมพ์เขียว Go Control Plane: การปลดล็อค Memlock, การโหลด, การผูก Hooks และการอ่าน Ring Buffer
   - 6.3 Complete Cheat Sheet: `bpftool`, `ip link`, `tc` และ 20 BPF Helper Functions สำคัญ
   - 6.4 การทดสอบโปรแกรม eBPF อัตโนมัติด้วย `BPF_PROG_TEST_RUN` และการอ่าน Verifier Log
7. [บทที่ 7: ความปลอดภัยและการตรวจจับภัยคุกคามเคอร์เนลระดับ Fleet (เฟส 07)](#บทที่-7-ความปลอดภัยและการตรวจจับภัยคุกคามเคอร์เนลระดับ-fleet-เฟส-7)
   - 7.0 กฎเหล็กของ Tracing แบบ CO-RE: ห้ามเขียน Struct ของเคอร์เนลเอง
   - 7.1 วินิจฉัย Packet Drops ด้วย `tracepoint:skb:kfree_skb`
   - 7.2 Socket Egress Control ด้วย `cgroup/connect4`
   - 7.3 การตรวจจับ Reverse Shell ผ่าน `task_struct`
   - 7.4 eBPF Integrity Auditor: เฝ้าระวังการใช้ `bpf()` Syscall
8. [บทที่ 8: การวัดประสิทธิภาพระบบ การแกะรอย Stack และการวิเคราะห์ฮาร์ดแวร์ (เฟส 08)](#บทที่-8-การวัดประสิทธิภาพระบบ-การแกะรอย-stack-และการวิเคราะห์ฮาร์ดแวร์-เฟส-8)
   - 8.1 การวัด Storage Block I/O Latency ด้วย Log2 Histograms
   - 8.2 On-CPU Profiler ด้วย `perf_event` Sampling และการถอดรหัส Stack
   - 8.3 การเฝ้าระวัง Page Faults และ OOM Killer
9. [บทที่ 9: การเร่งความเร็ว Socket และสถาปัตยกรรม Kernel Bypass (เฟส 09)](#บทที่-9-การเร่งความเร็ว-socket-และสถาปัตยกรรม-kernel-bypass-เฟส-9)
   - 9.1 TCP Sockops และ `sk_msg` Socket Redirect
   - 9.2 AF_XDP: ส่งแพ็กเก็ตจาก XDP ตรงสู่ User Space
10. [บทที่ 10: เทคโนโลยี eBPF ยุคใหม่ระดับแนวหน้า (เฟส 10)](#บทที่-10-เทคโนโลยี-ebpf-ยุคใหม่ระดับแนวหน้า-เฟส-10)
    - 10.1 Modern BPF Trampoline (`fentry` / `fexit`) Low-Overhead Tracing
    - 10.2 BPF Iterators (`iter/task`) การท่องโครงสร้างเคอร์เนลโดยตรง

---

# บทที่ 1: ผ่าโครงสร้าง Packet และการเดินทางใน Linux Kernel (เฟส 01)

การเขียน eBPF เพื่อควบคุมระบบเครือข่ายระดับเคอร์เนล จำเป็นต้องเข้าใจว่าแพ็กเก็ตข้อมูลไม่ใช่ "Object" ในภาษาโปรแกรมระดับสูง แต่เป็นเพียง **ลำดับของไบต์ดิบ (Stream of Raw Bytes)** ที่ถูกส่งผ่านสายเคเบิลหรือคลื่นวิทยุเข้ามายังการ์ดเครือข่าย (NIC) หากเราไม่เข้าใจโครงสร้างหน่วยความจำระดับบิตและไบต์ การเขียน eBPF จะเกิดข้อผิดพลาดที่ eBPF Verifier ไม่อนุญาตให้รันอย่างแน่นอน

---

### 1.1 โครงสร้างระดับ Byte ของ Ethernet Frame (Layer 2)

เมื่อสัญญาณไฟฟ้าหรือคลื่นแสงถูกแปลงเป็นข้อมูลดิจิทัลที่ Physical Layer (L1) ข้อมูลจะถูกจัดกลุ่มเข้าสู่ Layer 2 ในรูปแบบของ **Ethernet II Frame** ซึ่งมีขนาด Header คงที่อยู่ที่ 14 ไบต์ (ไม่รวม Preamble 7 ไบต์, Start Frame Delimiter 1 ไบต์ และ Frame Check Sequence 4 ไบต์ที่มักถูกฮาร์ดแวร์ NIC ตัดทิ้งก่อนส่งให้เคอร์เนล)

```
====================================================================================
                        ETHERNET II FRAME STRUCTURE (14 BYTES)
====================================================================================
Offset (Bytes) : 0        5 6        11 12   13 14                              N
Field          : [ Dest MAC ] [ Src MAC  ] [Type] [ Payload (IPv4 / IPv6 / ARP) ]
Length         :   6 Bytes      6 Bytes    2 Bytes              46 - 1500 Bytes
====================================================================================
```

#### รายละเอียดโครงสร้างฟิลด์:
1. **Destination MAC Address (Offset 0..5, ความยาว 6 ไบต์)**: ที่อยู่ฮาร์ดแวร์ของอุปกรณ์ปลายทางใน Layer 2 โดเมนเดียวกัน
2. **Source MAC Address (Offset 6..11, ความยาว 6 ไบต์)**: ที่อยู่ฮาร์ดแวร์ของโฮสต์ต้นทาง
3. **EtherType (Offset 12..13, ความยาว 2 ไบต์)**: ระบุชนิดของโปรโตคอลใน Layer ถัดไป (Layer 3 Payload):
   - `0x0800` : **IPv4 (Internet Protocol version 4)**
   - `0x0806` : **ARP (Address Resolution Protocol)**
   - `0x86DD` : **IPv6 (Internet Protocol version 6)**
   - `0x8100` : **802.1Q VLAN Tag** (หากมี VLAN Header ขนาดของ Layer 2 จะขยายเพิ่มอีก 4 ไบต์ โดย EtherType เดิมจะถูกแทนที่ด้วย 0x8100 และมี EtherType จริงตามหลัง)

ในภาษา C โครงสร้างนี้ถูกนิยามไว้ใน `<linux/if_ether.h>` ในชื่อ `struct ethhdr`:

```c
struct ethhdr {
    unsigned char   h_dest[6];   /* Destination Ethernet MAC address */
    unsigned char   h_source[6]; /* Source Ethernet MAC address      */
    __be16          h_proto;     /* Packet type ID field (EtherType) */
} __attribute__((packed));
```

> **ข้อควรระวังสำคัญมาก**: ฟิลด์ `h_proto` จะถูกจัดเก็บในรูปแบบ **Big-Endian (Network Byte Order)** เสมอ การตรวจสอบค่าต้องใช้ฟังก์ชันแปลงไบต์ เช่น `bpf_htons(ETH_P_IP)` มิฉะนั้นการเปรียบเทียบค่าจะผิดพลาดทันที

---

### 1.2 โครงสร้าง IPv4 Header (Layer 3) และการคำนวณ IHL

หาก EtherType ใน L2 มีค่าเท่ากับ `0x0800` ข้อมูลที่อยู่ถัดจาก L2 Header ทันที (Offset ที่ 14 เป็นต้นไป) คือ **IPv4 Header** ซึ่งมีขนาดตั้งแต่ **20 ไบต์ขึ้นไป จนถึง 60 ไบต์** ขึ้นอยู่กับว่ามี Options หรือไม่

```
==================================================================================================
                                    IPv4 HEADER STRUCTURE
==================================================================================================
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |  Byte 0 - 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|   Fragment Offset       |  Byte 4 - 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |  Byte 8 - 11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Source Address                        |  Byte 12 - 15
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |  Byte 16 - 19
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |  Byte 20 - 59 (Optional)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### รายละเอียดฟิลด์และการคำนวณ:
1. **Version (4 บิตแรก)**: ต้องมีค่าเท่ากับ `4` เสมอสำหรับ IPv4
2. **IHL (Internet Header Length - 4 บิตหลัง)**: ระบุความยาวของ IPv4 Header โดยมีหน่วยเป็น **คำขนาด 32 บิต (4 ไบต์)**
   $$\text{ความยาว Header จริง (Bytes)} = \text{IHL} \times 4$$
   - ค่าต่ำสุดคือ `5` ซึ่งหมายถึง $5 \times 4 = 20$ ไบต์ (ไม่มี Options)
   - ค่าสูงสุดคือ `15` ซึ่งหมายถึง $15 \times 4 = 60$ ไบต์ (มี Options 40 ไบต์)
   > **กฎเหล็กของ eBPF**: ห้ามทึกทักเอาเองว่า IPv4 Header มีขนาด 20 ไบต์คงที่เสมอไป! หากแพ็กเก็ตมี IP Options แล้วเราคำนวณตำแหน่ง Layer 4 โดยใช้ `ip + 20` เราจะชี้ผิดตำแหน่งและ Verifier อาจไม่อนุญาตให้รัน ต้องอ่านจาก `iph->ihl * 4` เสมอ
3. **Type of Service (TOS / DSCP / ECN) (1 ไบต์)**: ใช้สำหรับกำหนด Quality of Service (QoS)
4. **Total Length (2 ไบต์)**: ความยาวรวมของ IPv4 Packet (รวม IP Header + L4 Payload) หน่วยเป็นไบต์
5. **Identification (2 ไบต์), Flags (3 บิต), Fragment Offset (13 บิต)**: ใช้สำหรับจัดการการแบ่งส่วนแพ็กเก็ต (IP Fragmentation)
6. **Time to Live (TTL) (1 ไบต์)**: จำนวน Hop สูงสุดที่แพ็กเก็ตสามารถเดินทางผ่าน Router ได้ แต่ละ Hop จะลดค่าลง 1 หากเหลือ 0 แพ็กเก็ตจะถูกดรอปทิ้ง
7. **Protocol (1 ไบต์)**: ระบุชนิดของโปรโตคอล L4 ได้แก่:
   - `1`  : `IPPROTO_ICMP` (Internet Control Message Protocol)
   - `6`  : `IPPROTO_TCP` (Transmission Control Protocol)
   - `17` : `IPPROTO_UDP` (User Datagram Protocol)
8. **Header Checksum (2 ไบต์)**: ค่าความถูกต้องของเฉพาะ IP Header
9. **Source IP Address (4 ไบต์, Offset 12..15)**: หมายเลข IP ต้นทาง (เช่น `192.168.1.10`)
10. **Destination IP Address (4 ไบต์, Offset 16..19)**: หมายเลข IP ปลายทาง

ในภาษา C โครงสร้างถูกนิยามใน `<linux/ip.h>` ในชื่อ `struct iphdr`:

```c
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
            version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            ihl:4;
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
};
```

---

### 1.3 โครงสร้าง TCP และ UDP Headers (Layer 4)

Layer 4 เป็นชั้นข้อมูลที่กำหนดการเชื่อมต่อแบบ End-to-End ผ่านหมายเลขพอร์ต (Port Numbers)

#### ก. โครงสร้าง TCP Header (`struct tcphdr`)
TCP เป็นโปรโตคอลแบบ Connection-Oriented และ Reliable มีขนาด Header พื้นฐาน 20 ไบต์ และสามารถขยายได้สูงสุด 60 ไบต์ผ่าน TCP Options

```
==================================================================================================
                                     TCP HEADER STRUCTURE
==================================================================================================
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |  Byte 0 - 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |  Byte 4 - 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |  Byte 8 - 11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |  Byte 12 - 15
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |        Urgent Pointer         |  Byte 16 - 19
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |  Byte 20 - 59 (Optional)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Source Port (2 ไบต์)** / **Destination Port (2 ไบต์)**: หมายเลขพอร์ต (0–65535) จัดเก็บแบบ Big-Endian
- **Sequence Number (4 ไบต์)** / **Acknowledgment Number (4 ไบต์)**: ควบคุมการส่งข้อมูลลำดับของไบต์
- **Data Offset (4 บิต)**: ระบุความยาวของ TCP Header ในหน่วย 32-bit words (คำนวณเช่นเดียวกับ IHL: $\text{TCP Header Length} = \text{doff} \times 4$)
- **Control Flags (9 บิต)**:
  - `SYN` (Synchronize): เริ่มต้นการเชื่อมต่อ Three-way handshake
  - `ACK` (Acknowledge): ยืนยันการรับข้อมูล
  - `FIN` (Finish): ขอปิดการเชื่อมต่ออย่างสงบ
  - `RST` (Reset): ยกเลิกหรือปฏิเสธการเชื่อมต่อกะทันหัน
  - `PSH` (Push): แจ้งให้แอปพลิเคชันส่งข้อมูลขึ้น User Space ทันที
  - `URG` (Urgent): แจ้งข้อมูลเร่งด่วน

#### ข. โครงสร้าง UDP Header (`struct udphdr`)
UDP เป็นโปรโตคอลแบบ Connectionless และ Stateless มีขนาด Header ตายตัวเพียง **8 ไบต์** เท่านั้น

```
==================================================================================================
                                     UDP HEADER STRUCTURE
==================================================================================================
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |  Byte 0 - 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |  Byte 4 - 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Payload                            |  Byte 8 - N
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Source Port (2 ไบต์)** / **Destination Port (2 ไบต์)**
- **Length (2 ไบต์)**: ความยาวรวมของ UDP Header (8 ไบต์) + Payload
- **Checksum (2 ไบต์)**: ผลรวมตรวจสอบความถูกต้อง (หากเป็น 0 ใน IPv4 แปลว่าไม่ได้คำนวณ)

---

### 1.4 Big-Endian (Network Byte Order) vs Little-Endian (Host Byte Order)

ความผิดพลาดอันดับหนึ่งของผู้เริ่มต้นเขียน eBPF คือความเข้าใจผิดเรื่อง **Endianness (การเรียงลำดับไบต์ในหน่วยความจำ)**

1. **Big-Endian (Network Byte Order)**: ไบต์ที่มีนัยสำคัญสูงสุด (Most Significant Byte - MSB) จะถูกจัดเก็บไว้ที่ตำแหน่งหน่วยความจำต่ำสุด (อยู่ซ้ายสุดเมื่อส่งผ่านสายสัญญาณเครือข่าย)
2. **Little-Endian (Host Byte Order)**: ไบต์ที่มีนัยสำคัญต่ำสุด (Least Significant Byte - LSB) จะถูกจัดเก็บไว้ที่ตำแหน่งหน่วยความจำต่ำสุด สถาปัตยกรรม CPU ส่วนใหญ่ในปัจจุบัน เช่น **x86_64** และ **ARM64** ทำงานแบบ Little-Endian

#### ภาพจำลองการจัดเก็บในหน่วยความจำ: ตัวอย่างพอร์ต 80 (HTTP)
หมายเลขพอร์ต 80 ในระบบฐานสิบ เมื่อแปลงเป็นฐานสิบหก 16 บิต (2 ไบต์) คือ:
$$\text{Port } 80 = 0x0050 \quad (\text{MSB} = 0x00, \text{LSB} = 0x50)$$

```
+-----------------------------------------------------------------------------------+
| รูปแบบการจัดเก็บในหน่วยความจำ (Memory Layout)                                           |
+-----------------------------------------------------------------------------------+
| Network Wire (Big-Endian)  :  Address[0] = 0x00  |  Address[1] = 0x50             |
+-----------------------------------------------------------------------------------+
| CPU อ่านตรงๆ (Little-Endian) :  LSB = 0x00, MSB = 0x50                             |
| คำนวณเป็นค่าตัวเลข           :  (0x50 << 8) | 0x00 = 0x5000 = 20,480 ในฐานสิบ !! |
+-----------------------------------------------------------------------------------+
```

> **ผลลัพธ์อันตราย**: หากคุณเขียนโค้ดตรวจสอบพอร์ต 80 ใน eBPF ดังนี้:
> ```c
> if (tcp->dest == 80) // ผิดมหันต์!
> ```
> โค้ดนี้จะไม่ดักจับทราฟฟิกพอร์ต 80 เลยแม้แต่แพ็กเก็ตเดียว! แต่จะไปดักจับทราฟฟิกพอร์ต **20480** แทน!

#### ฟังก์ชันการแปลงที่ต้องใช้เสมอ:
| ฟังก์ชันใน eBPF (`<bpf/bpf_endian.h>`) | การแปลง | วัตถุประสงค์การใช้งาน |
| :--- | :--- | :--- |
| `bpf_htons(val)` | Host to Network Short (16-bit) | แปลงค่าพอร์ตฐานสิบของ Host ให้เป็น Network Byte Order เพื่อเทียบกับค่าในแพ็กเก็ต |
| `bpf_ntohs(val)` | Network to Host Short (16-bit) | แปลงค่าพอร์ตจากแพ็กเก็ตให้อยู่ในรูปแบบที่ Host CPU เข้าใจ |
| `bpf_htonl(val)` | Host to Network Long (32-bit)  | แปลงค่า IPv4 Address หรือ Sequence Number ให้เป็น Network Byte Order |
| `bpf_ntohl(val)` | Network to Host Long (32-bit)  | แปลงค่า IPv4 Address จากแพ็กเก็ตให้อยู่ในรูปแบบ Host CPU |

**รูปแบบการเขียนที่ถูกต้องสมบูรณ์:**
```c
// วิธีที่ 1: แปลงค่าคงที่ 80 ให้อยู่ใน Network Byte Order แล้วเทียบกับแพ็กเก็ต (แนะนำ: ทำงานเร็วสุด)
if (tcp->dest == bpf_htons(80)) {
    // ดักจับ HTTP Port 80 ได้ถูกต้อง 100%
}

// วิธีที่ 2: แปลงค่าในแพ็กเก็ตให้เป็น Host Byte Order แล้วเทียบกับ 80
if (bpf_ntohs(tcp->dest) == 80) {
    // ดักจับ HTTP Port 80 ได้ถูกต้องเช่นกัน
}
```

---

### 1.5 เส้นทางชีวิตของ Packet ใน Linux Network Stack แบบครบวงจร

แผนภาพด้านล่างนี้แสดงเส้นทางการเดินทางของแพ็กเก็ตแบบ Ingress ตั้งแต่วินาทีแรกที่สัญญาณไฟฟ้ากระทบพอร์ต NIC จนถึงวินาทีที่แอปพลิเคชัน User Space เรียก `read()` ได้ข้อมูล:

```
+-----------------------------------------------------------------------------------+
|                        LINUX KERNEL INGRESS PACKET DATA PATH                      |
+-----------------------------------------------------------------------------------+
                                        |
                             [ สัญญาณเคเบิล / ใยแก้วนำแสง ]
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 1. ฮาร์ดแวร์การ์ดเครือข่าย (Physical NIC Hardware)                                 |
|    - ตรวจสอบ Frame Check Sequence (FCS / CRC32) ตัดทิ้งหากพัง                     |
|    - ส่งข้อมูลตรงเข้า RAM โฮสต์ผ่าน DMA (Direct Memory Access)                      |
|    - เขียน Descriptor ลงใน NIC RX Ring Buffer ในหน่วยความจำ RAM                    |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 2. ขัดจังหวะการทำงานของ CPU (Hard IRQ)                                            |
|    - NIC ยิงสัญญาณ Hardware Interrupt ไปยัง CPU Core                              |
|    - Top-Half Interrupt Handler ทำงาน: ปิด IRQ ชั่วคราวเพื่อกันถล่ม (Interrupt Storm) |
|    - สั่งเรียก napi_schedule() แล้วส่งต่องานให้ SoftIRQ ทันที                       |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 3. การประมวลผลช่วงล่าง (SoftIRQ: NET_RX_SOFTIRQ) & NAPI Poll                        |
|    - เธรด ksoftirqd/x หรือ Bottom-Half Context ตื่นขึ้นมา                            |
|    - วนลูปประมวลผลฟังก์ชัน napi_poll() เพื่อดึงแพ็กเก็ตจาก RX Ring แบบ Batch         |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
    =============================================================================
    | [ HOOK POINT 1: XDP (eXpress Data Path) ]                                 |
    | - ทำงานที่ระดับไดรเวอร์การ์ดเครือข่าย (Native Mode) หรือชิป NIC (Offload)        |
    | - ข้อมูลยังเป็น Raw Memory Buffer (ยังไม่ได้จอง sk_buff ให้เปลือง RAM)         |
    | - ทางเลือก 5 อย่าง: XDP_DROP, XDP_TX, XDP_REDIRECT, XDP_PASS, XDP_ABORTED    |
    | * ความเร็วสูงสุดระดับ 40,000,000+ packets/sec สำหรับการบล็อก DDoS            |
    =============================================================================
                                        |
                          (กรณีส่งต่อ: XDP_PASS)
                                        v
+-----------------------------------------------------------------------------------+
| 4. การจองหน่วยความจำระดับเคอร์เนล: Allocate sk_buff (Socket Buffer)               |
|    - เคอร์เนลสร้าง Data Structure ขนาดใหญ่ (ราว 240 ไบต์ + ข้อมูลแพ็กเก็ต)           |
|    - ทำ GRO (Generic Receive Offload) รวมแพ็กเก็ตย่อยเป็นก้อนใหญ่เพื่อลดภาระ CPU   |
|    - เรียกฟังก์ชัน netif_receive_skb()                                            |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
    =============================================================================
    | [ HOOK POINT 2: TC Ingress (Traffic Control / cls_bpf) ]                  |
    | - ทำงานกับ struct __sk_buff (มองเห็น Metadata, VLAN, Socket Mark, cgroups)|
    | - สามารถแก้ไขข้อมูล (Packet Mangling), Redirect, Mirror, หรือ Drop ได้      |
    | - ทำงานได้ทั้งขาเข้า (Ingress) และขาออก (Egress)                            |
    =============================================================================
                                        |
                          (กรณีส่งต่อ: TC_ACT_OK)
                                        v
+-----------------------------------------------------------------------------------+
| 5. Netfilter / Connection Tracking (Conntrack)                                    |
|    - ผ่าน PREROUTING Chain (iptables / nftables nat table)                        |
|    - ตรวจสอบสถานะการเชื่อมต่อ (Stateful Connection Tracking)                      |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 6. การตัดสินใจเชิงเส้นทาง (Routing Decision)                                      |
|    - เคอร์เนลเรียก ip_route_input_noref() เพื่อตรวจปลายทาง                         |
|    - ถ้าปลายทางคือเครื่องอื่น -> ส่งเข้า FORWARD Chain แล้วยิงออกทาง TC Egress    |
|    - ถ้าปลายทางคือเครื่องนี้ (Local) -> ส่งต่อไปยัง Transport Layer               |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 7. Netfilter INPUT Chain                                                          |
|    - ผ่านกฎไฟร์วอลล์ระดับโฮสต์ (iptables -A INPUT ...)                            |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 8. โปรโตคอล Transport Layer (tcp_v4_rcv() / udp_rcv())                            |
|    - ตรวจสอบ Checksum L4                                                          |
|    - ค้นหา Socket ที่เปิดรออยู่ผ่าน 4-Tuple (Src IP, Dst IP, Src Port, Dst Port)  |
|    - บริหารจัดการ Window Size และ TCP State Machine                               |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 9. เข้าสู่คิว Socket Receive Buffer (sk_receive_queue)                            |
|    - แพ็กเก็ตถูกคัดลอกเข้า Buffer ของโปรเซสปลายทาง                                |
|    - ส่งสัญญาณปลุก (Wake up) โปรเซสที่รออยู่ที่ epoll_wait() หรือ select()         |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| 10. แอปพลิเคชันระดับ User Space                                                   |
|    - โปรแกรม (เช่น Nginx, Envoy, Go Web Server) เรียก Syscall read() หรือ recvmsg() |
|    - ข้อมูลถูกคัดลอกข้ามขอบเขต Kernel Space -> User Space RAM                     |
+-----------------------------------------------------------------------------------+
```

---

# บทที่ 2: กลไกภายในของ eBPF และด่านตรวจ Verifier (เฟส 02)

eBPF (Extended Berkeley Packet Filter) ได้เปลี่ยนเคอร์เนลของ Linux จากระบบที่ตายตัว (Monolithic Kernel) ให้กลายเป็นระบบที่สามารถ **ตั้งโปรแกรมได้อย่างปลอดภัยและยืดหยุ่น (Programmable Kernel)** โดยไม่ต้องแก้ไขซอร์สโค้ดเคอร์เนลและไม่ต้องเสี่ยงต่อการเกิด Kernel Panic เหมือนการโหลด Kernel Module (`.ko`) ในอดีต

---

### 2.1 สถาปัตยกรรม eBPF Virtual Machine

eBPF VM เป็นเครื่องจักรเสมือนแบบ Register-Based 64 บิตที่ฝังตัวอยู่ภายในเคอร์เนล ประกอบด้วย:
- **General-Purpose Registers จำนวน 11 ตัว** (ความกว้าง 64 บิต: `R0` ถึง `R10`)
- **Call Frame Stack ขนาด 512 ไบต์**

```
====================================================================================
                        eBPF REGISTER ARCHITECTURE (64-BIT)
====================================================================================
Register | สิทธิ์การเข้าถึง | บทบาทหน้าที่และความสำคัญ
---------+-----------------+--------------------------------------------------------
R0       | Read / Write    | ค่าผลลัพธ์ย้อนกลับ (Return Value) จากฟังก์ชัน eBPF 
         |                 | และค่า Exit Code ของโปรแกรม (เช่น คืนค่า XDP_DROP)
---------+-----------------+--------------------------------------------------------
R1 - R5  | Read / Write    | ใช้ส่งอาร์กิวเมนต์ (Arguments) 5 ตัวแรกให้แก่ฟังก์ชัน BPF Helper
         |                 | หรือ BPF-to-BPF Subprograms (Caller-saved)
---------+-----------------+--------------------------------------------------------
R6 - R9  | Read / Write    | Callee-saved Registers: ข้อมูลในรีจิสเตอร์เหล่านี้จะไม่ถูกลบ
         |                 | หรือเขียนทับเมื่อมีการเรียก Helper Functions
---------+-----------------+--------------------------------------------------------
R10      | READ-ONLY       | Frame Pointer ชี้ไปยังจุดเริ่มต้นของ Call Stack (512 ไบต์)
         |                 | ตัวตรวจ Verifier จะปฏิเสธทันทีหากมีโค้ดพยายามเขียนทับ R10
====================================================================================
```

#### ข้อจำกัดของ Stack 512 ไบต์:
หน่วยความจำ Stack ของ eBPF ถูกออกแบบมาให้ประหยัดอย่างเข้มงวดเพื่อป้องกันปัญหา Kernel Stack Overflow (เพราะ Kernel Stack ทั้งหมดของ Linux มีขนาดเพียง 8KB หรือ 16KB ร่วมกันทั้งระบบ):
- หากคุณประกาศตัวแปร Array ขนาดใหญ่ เช่น `char buffer[1024];` ภายในโปรแกรม eBPF ตัว Verifier จะปฏิเสธการโหลดโปรแกรมทันทีพร้อมข้อผิดพลาด `lookahead stack limit exceeded`
- **แนวทางปฏิบัติที่ดีที่สุด (Best Practice)**: หากต้องการหน่วยความจำขนาดใหญ่ ให้จองผ่าน `BPF_MAP_TYPE_PERCPU_ARRAY` หรือใช้ `BPF_MAP_TYPE_RINGBUF` แทนการประกาศบน Stack เสมอ

---

### 2.2 วงจรการคอมไพล์และโหลดโปรแกรม: จาก C สู่ Clang, ELF และ BPF Syscall

```
+-----------------------------------------------------------------------------------+
|                        eBPF BUILD & LOADING PIPELINE                              |
+-----------------------------------------------------------------------------------+

   [ ซอร์สโค้ด eBPF ภาษา C ] (my_prog.bpf.c)
               |
               v  คำสั่ง: clang -target bpf -O2 -g -c my_prog.bpf.c -o my_prog.bpf.o
   +-----------------------------------------------------------------------------+
   | Clang / LLVM Compiler Backend                                               |
   | - แปลงภาษา C เป็นสถาปัตยกรรมเป้าหมาย BPF (Target BPF)                       |
   | - สร้าง ELF Binary Object (.o)                                              |
   |   - Section .text: เก็บ eBPF Bytecode คำสั่งละ 8 ไบต์                       |
   |   - Section .maps: เก็บนิยาม Map Descriptor                                 |
   |   - Section .BTF & .BTF.ext: เก็บข้อมูล Type Layout และ Relocation Debug Info|
   +-----------------------------------------------------------------------------+
               |
               v  ELF Object File (.o)
   +-----------------------------------------------------------------------------+
   | User Space Loader (Cilium ebpf ในภาษา Go หรือ libbpf ในภาษา C)               |
   | - อ่านไฟล์ ELF และถอดรหัส Maps/Programs                                     |
   | - ทำ BTF Field Relocation ปรับตำแหน่งโครงสร้างข้อมูลให้ตรงกับ Host Kernel   |
   | - ยิง Syscall: bpf(BPF_PROG_LOAD, union bpf_attr *attr, ...)                 |
   +-----------------------------------------------------------------------------+
               |
               v  ยื่นคำร้องเข้า Linux Kernel
   +-----------------------------------------------------------------------------+
   | [ eBPF VERIFIER ] ด่านตรวจความปลอดภัยระดับเคอร์เนล                             |
   | - ตรวจสอบความถูกต้องของหน่วยความจำ, ป้องกันลูปไม่รู้จบ, ตรวจ Pointer Bounds  |
   +-----------------------------------------------------------------------------+
               |
         (ผ่านการอนุมัติ)
               v
   +-----------------------------------------------------------------------------+
   | [ BPF JIT COMPILER ]                                                        |
   | - แปลง eBPF Bytecode เป็น Native Machine Code (x86_64 / ARM64 Assembly)     |
   | - ฝังโค้ดลงใน Kernel Memory แบบ Read-Only Executable                        |
   +-----------------------------------------------------------------------------+
               |
               v
   [ เกาะเข้ากับ Hook Point: XDP, TC, Kprobe, Tracepoint, หรือ BPF LSM ]
```

---

### 2.3 ด่านตรวจความปลอดภัย eBPF Verifier (Control Flow Graph & Static Analysis)

Verifier คือหัวใจสำคัญที่สุดที่ทำให้เคอร์เนลสามารถรันโค้ดที่มาจาก User Space ได้อย่างมั่นใจว่าจะ **ไม่ทำให้ระบบล่ม (Zero Crash Guarantee)** โดยใช้หลักการวิเคราะห์โค้ดสถิต (Static Program Analysis):

```
+-----------------------------------------------------------------------------------+
|                           eBPF VERIFIER 2-STAGE ANALYSIS                          |
+-----------------------------------------------------------------------------------+
| ขั้นตอนที่ 1: สร้าง Directed Acyclic Graph (DAG) และตรวจจับลูป                      |
| - แปลงคำสั่งกระโดด (JMP) ทั้งหมดเพื่อสร้างกราฟเส้นทางการทำงาน                      |
| - ตรวจสอบว่าไม่มีโค้ดส่วนใดที่เข้าไม่ถึง (Unreachable Code)                       |
| - ตรวจจับ Unbounded Loops (ลูปที่จำนวนรอบไม่แน่นอนจะถูกตีตกทันที)                 |
+-----------------------------------------------------------------------------------+
                                        |
                                        v
+-----------------------------------------------------------------------------------+
| ขั้นตอนที่ 2: จำลองการรันเชิงนามธรรม (Symbolic / Abstract Execution)              |
| - ไล่ตรวจทีละคำสั่งและจำลองค่าของ Register ทั้งหมด (R0–R10)                        |
| - บันทึกประเภทของพอยน์เตอร์ (Pointer Types):                                      |
|   PTR_TO_STACK, PTR_TO_PACKET, PTR_TO_MAP_VALUE, SCALAR_VALUE                    |
| - คำนวณช่วงของค่าที่เป็นไปได้ (Min/Max Bound Tracking: smin, smax, umin, umax)    |
| - ทุกการ Dereference พอยน์เตอร์ จะต้องมีคำสั่ง Branch เช็ค Bounds ก่อนเสมอ!        |
+-----------------------------------------------------------------------------------+
```

#### กฎเหล็ก 4 ประการที่ Verifier บังคับใช้:
1. **ห้ามมี Unbounded Loops เด็ดขาด**: หากเขียน `while (1)` หรือลูปที่เคอร์เนลไม่สามารถพิสูจน์จำนวนรอบสูงสุดได้ Verifier จะปฏิเสธการโหลดทันที (สามารถใช้ `#pragma unroll` หรือลูปแบบ Bounded Loop เช่น `for (int i = 0; i < 10; i++)` บนเคอร์เนล 5.3 ขึ้นไปได้)
2. **ห้ามเกิด Null Pointer Dereference**: เมื่อเรียกใช้งาน `bpf_map_lookup_elem()` เคอร์เนลจะมองผลลัพธ์เป็นประเภท `PTR_TO_MAP_VALUE_OR_NULL` เราต้องเขียน `if (!val) return 0;` ตรวจสอบเสมอ หากเข้าถึงค่าทันทีโดยไม่ตรวจ Verifier จะปฏิเสธด้วยข้อผิดพลาด: `R0 invalid mem access 'map_value_or_null'`
3. **การตรวจสอบขอบเขตแพ็กเก็ต (Packet Bounds Checking)**: พอยน์เตอร์ `ctx->data` ใดๆ ต้องถูกพิสูจน์ทางคณิตศาสตร์ว่าไม่เกิน `ctx->data_end` ก่อนการอ่านหรือเขียนข้อมูลแม้แต่ไบต์เดียว
4. **ห้ามใช้ Floating-Point Numbers**: ห้ามใช้ `float` หรือ `double` ภายในโปรแกรม eBPF เด็ดขาด เนื่องจากเคอร์เนลไม่ได้บันทึกหรือสลับบริบท Floating Point Registers (FPU/SSE/AVX) เพื่อรักษาประสิทธิภาพความเร็วสูงสุด หากจำเป็นต้องคำนวณทศนิยม ให้ใช้ **Fixed-Point Arithmetic** หรือแปลงเป็นหน่วยทศนิยมย่อย (เช่น คิดเงินเป็นหน่วยสตางค์ หรือคิดเวลาเป็นนาโนวินาที) แทน

---

### 2.4 กลไก JIT (Just-In-Time) Compiler และ BPF Hardening

เมื่อโปรแกรมผ่านการตรวจของ Verifier ตัวเคอร์เนลจะไม่รันผ่าน Interpreter ที่ช้า แต่จะส่งให้ **BPF JIT Compiler** ทำการแปลคำสั่ง Bytecode ให้กลายเป็น Native Machine Code ของสถาปัตยกรรมฮาร์ดแวร์นั้นๆ (เช่น x86-64 OPCODES หรือ ARM64 Instructions) ส่งผลให้โปรแกรมทำงานได้ด้วยความเร็วใกล้เคียง Native C ภายในเคอร์เนล (ยังมี Overhead เล็กน้อยจากการเรียก Helper และการ Hardening เช่น Constant Blinding เมื่อเปิด `bpf_jit_harden`)

#### กลไกความปลอดภัย BPF JIT Hardening:
เพื่อป้องกันการโจมตีประเภท **JIT Spraying** (การที่ผู้ไม่หวังดีแอบซ่อน Payload ไบนารีอันตรายไว้ในค่าคงที่ของคำสั่ง BPF เพื่อหลอกให้ JIT สร้าง Machine Code ที่เป็นช่องโหว่) Linux Kernel มีระบบ Hardening ที่เปิดใช้งานได้ผ่าน `sysctl`:

```bash
# ตรวจสอบสถานะ JIT Hardening
sysctl net.core.bpf_jit_harden

# กำหนดค่าความปลอดภัยสูงสุด (2 = Hardening สำหรับโปรแกรม eBPF ทุกตัว รวมถึงของ root)
sudo sysctl -w net.core.bpf_jit_harden=2
```
กลไกนี้จะทำการสุ่มบิตคงที่ (Constant Blinding) ทำให้ไม่สามารถคาดเดาตำแหน่ง Memory Address ของ Native Instruction ได้

---

# บทที่ 3: การเขียน eBPF ยุคใหม่แบบ CO-RE และการใช้ Maps (เฟส 03)

การเปลี่ยนผ่านจาก eBPF ยุคเก่า (BCC) เข้าสู่ยุคสมัยใหม่ (Modern eBPF with CO-RE) ถือเป็นการปฏิวัติครั้งสำคัญของระบบสถาปัตยกรรมเคอร์เนล Linux

---

### 3.1 จุดจบของยุค BCC สู่ความเป็นมาตรฐานของ Modern CO-RE

ในยุคแรกเริ่ม เครื่องมืออย่าง **BCC (BPF Compiler Collection)** ใช้วิธีการฝังคอมไพเลอร์ Clang/LLVM ขนาดใหญ่ไว้ใน Python runtime เมื่อต้องการรันโปรแกรม BCC จะดึงไฟล์ C Source Code มาคอมไพล์แบบสดๆ บนเครื่องเป้าหมาย (Production Server)

```
====================================================================================
               เปรียบเทียบสถาปัตยกรรม: BCC (ดั้งเดิม) vs CO-RE (สมัยใหม่)
====================================================================================
คุณสมบัติ                | BCC (Legacy)               | Modern CO-RE (libbpf / Go)
-------------------------+----------------------------+-----------------------------
การคอมไพล์               | คอมไพล์สดบนเครื่อง Production | คอมไพล์ครั้งเดียวบน CI/CD
ขนาดพื้นที่ Dependencies  | หนักมาก (> 150-300 MB)      | เบามาก (ไบนารีเดียว ~10-20 MB)
การใช้ RAM ขณะสตาร์ท      | สูงมาก (Clang กินแรมเป็นร้อย MB)| ต่ำมาก (เพียงไม่กี่เมกะไบต์)
เวลาในการเริ่มต้นรัน     | ช้า (ต้องรอคอมไพล์หลายวินาที) | ทันทีทันใด (หลักมิลลิวินาที)
การพึ่งพา Kernel Headers | บังคับติดตั้ง linux-headers  | ไม่ต้องติดตั้ง ใช้ BTF ในเครื่อง
====================================================================================
```

**CO-RE (Compile Once – Run Everywhere)** เกิดขึ้นได้ด้วยการผสานกันของ 4 เสาหลัก:
1. **Kernel BTF (`/sys/kernel/btf/vmlinux`)**: เคอร์เนลบอก Layout ของโครงสร้างตัวเองในรูปแบบข้อมูลขนาดกะทัดรัด
2. **`vmlinux.h`**: Header file เดียวที่สกัดข้อมูลทุก Struct ของเคอร์เนลมาให้เราเรียกใช้
3. **Clang Compiler Relocation**: Clang บันทึกข้อมูลตำแหน่งฟิลด์ที่โปรแกรมต้องการเข้าถึงไว้ใน ELF Relocation Table
4. **Bpf Loader (libbpf / Cilium Go)**: ตัวโหลดจะเปรียบเทียบ Offset ระหว่างตอนคอมไพล์กับ Kernel ปัจจุบัน แล้วปรับค่าตำแหน่ง Offset ให้ถูกต้องอัตโนมัติก่อนส่งให้ Verifier

---

### 3.2 เจาะลึก BTF (BPF Type Format) และ `vmlinux.h`

ในอดีต หากเราต้องการเข้าถึงตัวแปรภายในเคอร์เนล เช่น `struct task_struct` เราต้อง Include Header files จำนวนมาก ซึ่งมักเกิดปัญหา Header ชนกัน หรือฟิลด์เปลี่ยนตำแหน่งเมื่ออัปเดต Kernel Minor Version

ในยุค CO-RE เราสามารถสร้างไฟล์ `vmlinux.h` ขนาดสมบูรณ์ได้จาก Kernel เครื่องปัจจุบันด้วยคำสั่ง:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

#### การเข้าถึงโครงสร้างข้อมูลข้ามเวอร์ชันด้วย `BPF_CORE_READ()`:
หากเคอร์เนลเวอร์ชัน 5.15 มีโครงสร้างฟิลด์ต่างจากเคอร์เนลเวอร์ชัน 6.8 มาโคร `BPF_CORE_READ()` จะทำการอ่านข้อมูลอย่างปลอดภัยและปรับแก้ Offset ให้อัตโนมัติ:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// ตัวอย่างการอ่าน UID ของผู้ใช้ที่ส่งแพ็กเก็ตผ่าน Task Struct
SEC("kprobe/sys_enter")
int trace_sys_enter(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // BPF_CORE_READ จะทำการอ่าน Pointer ซ้อนพอยน์เตอร์ได้อย่างปลอดภัย
    // พร้อมปรับ Offset ของ real_cred และ uid ตามเคอร์เนลจริงขณะรัน
    unsigned int uid = BPF_CORE_READ(task, real_cred, uid.val);
    
    bpf_printk("Task UID: %d\n", uid);
    return 0;
}
```

---

### 3.3 การประกาศและเลือกใช้งาน eBPF Maps

eBPF Maps คือโครงสร้างข้อมูลหน่วยความจำร่วม (Shared Memory Data Structures) ที่ทำให้:
- โปรแกรม eBPF ใน Kernel สามารถบันทึกสถานะ (Stateful Processing)
- โปรแกรม eBPF สื่อสารส่งผ่านข้อมูลกับโปรแกรมใน User Space
- โปรแกรม eBPF สื่อสารแลกเปลี่ยนข้อมูลข้าม Hook Point กันได้

ในยุคปัจจุบัน เราประกาศ Maps ด้วยรูปแบบ **BTF-Defined Maps** ใน Section `SEC(".maps")`:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// 1. BPF_MAP_TYPE_HASH: เหมาะสำหรับจับคู่ Key-Value ทั่วไป เช่น นับจำนวนแพ็กเก็ตตาม IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);        // IPv4 Address
    __type(value, __u64);      // Packet Count
} ip_packet_count SEC(".maps");

// 2. BPF_MAP_TYPE_LRU_HASH: เหมาะสำหรับ Rate Limiter หรือ IP Blocklist ที่มีหน่วยความจำจำกัด
// หาก Map เต็ม มันจะลบ Entry ที่ไม่ได้ใช้งานนานที่สุดออกอัตโนมัติ (ไม่คืน error -ENOMEM)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);        // Client IP
    __type(value, __u64);      // Last seen timestamp
} connection_tracker SEC(".maps");

// 3. BPF_MAP_TYPE_PERCPU_ARRAY: เหมาะสำหรับ Counter ความเร็วสูงระดับหลายสิบล้านครั้งต่อวินาที
// แต่ละ CPU Core จะมี Array แยกจากกันอย่างเด็ดขาด ไร้ปัญหา Cache Invalidation
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);      // Global Drop Counter
} percpu_drop_stats SEC(".maps");

// 4. BPF_MAP_TYPE_RINGBUF: ส่ง Event Stream ไปยัง User Space อย่างมีประสิทธิภาพสูงสุด
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB Buffer
} events SEC(".maps");
```

---

### 3.4 ภาวะแย่งชิงข้อมูล (Race Conditions) และการแก้ปัญหา

เมื่อรันระบบบนเครื่องแบบ Multi-Core หลายซีพียูอาจรัน eBPF Hook พร้อมกันสำหรับแพ็กเก็ตคนละตัว หากโปรแกรมต้องการแก้ไขค่าตัวเลขใน Map พร้อมกัน อาจเกิดภาวะแย่งชิงข้อมูล (Race Condition) ที่ทำให้ค่าตัวนับผิดเพี้ยน

```
+-----------------------------------------------------------------------------------+
|                            RACE CONDITION SCENARIO                                |
+-----------------------------------------------------------------------------------+
| CPU 0: อ่านค่า Counter (100) -------> คำนวณ (100 + 1 = 101) ------> เขียนค่า (101)  |
|                                                                                   |
| CPU 1:       อ่านค่า Counter (100) ----> คำนวณ (100 + 1 = 101) ---> เขียนค่า (101) |
+-----------------------------------------------------------------------------------+
| ผลลัพธ์: มี 2 แพ็กเก็ตเข้ามา แต่ Counter เพิ่มขึ้นแค่ 1 เท่านั้น! (ข้อมูลสูญหาย)         |
+-----------------------------------------------------------------------------------+
```

#### แนวทางการแก้ไขปัญหา 2 ทางเลือก:

**ทางเลือกที่ 1: การใช้ฟังก์ชัน Built-in แบบ Atomic (`__sync_fetch_and_add`)**
เหมาะสำหรับ HASH Map ที่ต้องการให้ค่าถูกต้อง 100%:
```c
__u32 key = 0;
__u64 *count = bpf_map_lookup_elem(&ip_packet_count, &key);
if (count) {
    // ใช้คำสั่งระดับฮาร์ดแวร์ atomic add ปลอดภัยจาก Race Condition
    __sync_fetch_and_add(count, 1);
}
```

**ทางเลือกที่ 2: เปลี่ยนไปใช้ Per-CPU Map (ประสิทธิภาพสูงสุด)**
การใช้ `BPF_MAP_TYPE_PERCPU_ARRAY` หรือ `BPF_MAP_TYPE_PERCPU_HASH` เป็นการแยกหน่วยความจำตาม CPU Core ทำให้ไม่ต้องล็อกและไม่ต้องพึ่งพา Atomic Instruction ซีพียูแต่ละตัวสามารถบวกเลขในหน่วยความจำของตัวเองได้ทันที จากนั้นฝั่ง User Space จะเป็นผู้ดึงผลรวมของทุก CPU Core ไปสรุปเอง

---

# บทที่ 4: เจาะลึกการเขียน XDP และการทำ Bounds Checking (เฟส 04)

XDP (eXpress Data Path) คือ Hook Point ของ eBPF ที่ทำงานได้เร็วที่สุดในโลกบน Linux Kernel เนื่องจากมันทำงานทันทีที่ฮาร์ดแวร์ NIC ส่งมอบหน่วยความจำ โดยที่เคอร์เนลยังไม่ได้จองโครงสร้าง `sk_buff`

---

### 4.1 สถาปัตยกรรม XDP และบริบท `struct xdp_md`

เมื่อแพ็กเก็ตเข้ามายังไดรเวอร์การ์ดเครือข่าย โปรแกรม XDP จะได้รับบริบทอินพุตเป็น `struct xdp_md` ซึ่งถูกนิยามไว้ดังนี้:

```c
struct xdp_md {
    __u32 data;           // พอยน์เตอร์ชี้จุดเริ่มต้นของข้อมูลแพ็กเก็ต (L2 Ethernet)
    __u32 data_end;       // พอยน์เตอร์ชี้จุดสิ้นสุดของข้อมูลแพ็กเก็ต
    __u32 data_meta;      // พอยน์เตอร์ชี้จุดเริ่มต้นของ Metadata ก่อนหน้าข้อมูล
    __u32 ingress_ifindex;// ดัชนีของการ์ดเครือข่ายที่รับแพ็กเก็ตเข้ามา (Network Interface Index)
    __u32 rx_queue_index; // หมายเลขคิวฮาร์ดแวร์ RX ของการ์ดเครือข่าย
    __u32 egress_ifindex; // ใช้สำหรับการ Redirect แพ็กเก็ต
};
```

> **ข้อสังเกตสำคัญในภาษา C**: ใน `struct xdp_md` ค่า `data` และ `data_end` ถูกเก็บเป็นชนิดข้อมูล `__u32` (Offset) ดังนั้นเมื่อนำไปใช้งานใน C เราต้องทำการ Type Cast ให้เป็นพอยน์เตอร์หน่วยความจำจริงเสมอ:
> ```c
> void *data     = (void *)(long)ctx->data;
> void *data_end = (void *)(long)ctx->data_end;
> ```

---

### 4.2 ผลลัพธ์ทั้ง 5 ของ XDP (XDP Actions)

ฟังก์ชัน eBPF ของ XDP จะต้องคืนค่า (Exit Code) เป็นหนึ่งใน 5 สถานะนี้เสมอ:

```
====================================================================================
                              XDP ACTIONS (RETURN CODES)
====================================================================================
Action Code  | ค่าตัวเลข | พฤติกรรมการทำงานและการนำไปประยุกต์ใช้
-------------+-----------+----------------------------------------------------------
XDP_DROP     | 1         | ทิ้งแพ็กเก็ตทันทีที่ระดับฮาร์ดแวร์/ไดรเวอร์ ไม่ส่งต่อให้เคอร์เนล
             |           | เหมาะอย่างยิ่งสำหรับการทำ Anti-DDoS Firewall ความเร็วระดับ Wire-Speed
-------------+-----------+----------------------------------------------------------
XDP_PASS     | 2         | ส่งแพ็กเก็ตต่อไปยัง Linux Network Stack ปกติ
             |           | เคอร์เนลจะทำการจอง sk_buff และส่งต่อไปยัง TC, IP, TCP/UDP
-------------+-----------+----------------------------------------------------------
XDP_TX       | 3         | สะท้อนแพ็กเก็ตกลับออกไปทาง Network Interface เดิมทันที
             |           | นิยมใช้ทำ Single-NIC Load Balancer หรือ ICMP Ping Responder
-------------+-----------+----------------------------------------------------------
XDP_REDIRECT | 4         | ส่งต่อแพ็กเก็ตข้าม Interface อื่น, ข้าม CPU Core ผ่าน cpumap,
             |           | หรือยิงตรงเข้าสู่ User Space Memory ผ่าน AF_XDP (Zero-Copy)
-------------+-----------+----------------------------------------------------------
XDP_ABORTED  | 0         | ทิ้งแพ็กเก็ตเมื่อเกิดความผิดพลาดในการประมวลผลของโปรแกรม
             |           | จะทำการยิงสัญญาณเข้าสู่ Tracepoint trace_xdp_exception สำหรับ Debug
====================================================================================
```

---

### 4.3 กฎเหล็ก Pointer Arithmetic & Verifier Bounds Checking ทีละเลเยอร์

Verifier ของ eBPF จะติดตามการเข้าถึงหน่วยความจำทุกครั้ง หากเราพยายามอ่านหรือเขียนข้อมูลใดๆ นอกเหนือขอบเขตที่ได้รับการพิสูจน์แล้ว โปรแกรมจะคอมไพล์ไม่ผ่านทันที

#### ตัวอย่างโค้ดสมบูรณ์: การแกะ Packet ทีละเลเยอร์ให้ผ่าน Verifier (ทุกการเข้าถึงมี Bounds Check)

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int parse_and_filter_packets(struct xdp_md *ctx) {
    // 1. แปลง Offset เป็นพอยน์เตอร์
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // =========================================================================
    // LAYER 2: ETHERNET BOUNDS CHECK
    // =========================================================================
    struct ethhdr *eth = data;
    // กฎเหล็ก: ตรวจสอบว่าขนาดของแพ็กเก็ตครอบคลุม Ethernet Header (14 ไบต์) หรือไม่
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // หากแพ็กเก็ตสั้นกว่าขนาด Header ให้ส่งต่อหรือดรอป
    }

    // ตรวจสอบว่าเป็น IPv4 หรือไม่ (0x0800)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // =========================================================================
    // LAYER 3: IPv4 BOUNDS CHECK & VARIABLE HEADER LENGTH (IHL)
    // =========================================================================
    // คำนวณตำแหน่งเริ่มต้นของ IP Header โดยขยับต่อจาก Ethernet Header ทันที
    struct iphdr *iph = (void *)(eth + 1);
    
    // ตรวจสอบขนาดพื้นฐานของ IPv4 Header (20 ไบต์)
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    // ตรวจสอบความถูกต้องของ Version
    if (iph->version != 4) {
        return XDP_PASS;
    }

    // คำนวณความยาวจริงของ IP Header จาก IHL (รองรับ IP Options)
    __u32 ip_hdr_len = iph->ihl * 4;
    
    // ตรวจสอบว่า IHL ต้องไม่ต่ำกว่าขนาดมาตรฐาน 20 ไบต์
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_DROP; // แพ็กเก็ตผิดโครงสร้างมาตรฐาน อาจเป็นการโจมตี
    }

    // ตรวจสอบขอบเขตว่าความยาว IP Header จริง (รวม Options) ไม่ล้นเกิน data_end
    if ((void *)iph + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    // =========================================================================
    // LAYER 4: TRANSPORT (TCP / UDP) BOUNDS CHECK
    // =========================================================================
    void *l4_hdr = (void *)iph + ip_hdr_len;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        // ตรวจสอบขนาด TCP Header (20 ไบต์)
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }

        // ตรวจสอบพอร์ต 80 (HTTP)
        if (tcp->dest == bpf_htons(80)) {
            // บล็อกการเชื่อมต่อ HTTP ด้วย XDP_DROP ความเร็วสูง
            bpf_printk("Blocked HTTP traffic from IP: %pI4\n", &iph->saddr);
            return XDP_DROP;
        }
    } 
    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        // ตรวจสอบขนาด UDP Header (8 ไบต์)
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }

        // ตรวจสอบพอร์ต 53 (DNS)
        if (udp->dest == bpf_htons(53)) {
            bpf_printk("Intercepted DNS query\n");
            return XDP_PASS;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

---

### 4.4 Traffic Control (TC) vs XDP และการทำ Packet Mangling พร้อมคำนวณ Checksum

แม้ XDP จะมีความเร็วสูงสุด แต่ XDP มีข้อจำกัดสำคัญคือ:
- ทำงานได้เฉพาะขาเข้า (Ingress) เท่านั้น (ยกเว้นโหมด XDP_TX ที่สะท้อนกลับ)
- ไม่สามารถเข้าถึง Metadata ระดับสูงของเคอร์เนล เช่น Socket Mark, Netfilter Conn, หรือ cgroup

**Traffic Control (TC / cls_bpf)** เข้ามาเติมเต็มจุดนี้ โดยทำงานร่วมกับโครงสร้าง `struct __sk_buff`:
- รองรับทั้ง **Ingress (ขาเข้า)** และ **Egress (ขาออก)**
- สามารถจัดคิว ปรับแต่ง Bandwidth (Traffic Shaping) และทำ NAT / Packet Mangling ได้สมบูรณ์แบบ

#### การคำนวณ Checksum ใหม่เมื่อแก้ไขข้อมูลในแพ็กเก็ต (Checksum Recalculation):
เมื่อโปรแกรม eBPF ทำการแก้ไขข้อมูลใน Header เช่น แก้ไข Destination IP หรือ Port สำหรับทำ Load Balancer ค่า Checksum เดิมจะผิดพลาดทันที เราต้องอัปเดต Checksum ใหม่ผ่าน Helper Functions:

```c
// ตัวอย่างการเปลี่ยน Destination IP ใน TC Program
__be32 old_ip = iph->daddr;
__be32 new_ip = bpf_htonl(0x0A000001); // 10.0.0.1

// 1. อัปเดต IP Header Checksum
iph->daddr = new_ip;
bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip, new_ip, sizeof(new_ip));

// 2. อัปเดต TCP Header Checksum (เพราะ TCP รวม Pseudo IP Header ใน Checksum ด้วย)
bpf_l4_csum_replace(skb, tcp_offset + offsetof(struct tcphdr, check), old_ip, new_ip, sizeof(new_ip) | BPF_F_PSEUDO_HDR);
```

#### 4.5 บันทึกจากการทดลองจริง (Lab Notes จาก Week 07–08)
- **ลำดับการตรวจสอบสำคัญต่อความปลอดภัย**: Firewall เวอร์ชันแรกตรวจ Blocklist *หลัง* ตรวจ IHL/L4 Header ซึ่ง `return XDP_PASS` เมื่อ Header ผิดรูป ผู้โจมตีจาก IP ที่ถูกบล็อกจึงผ่านได้ด้วยแพ็กเก็ตที่ IHL ผิด, TCP Header สั้น หรือ Fragment ที่ไม่ใช่ชิ้นแรก **ให้ตัดสินใจเรื่อง Policy ทันทีที่มีข้อมูลพอ (หลังอ่าน IPv4 Header 20 ไบต์)**
- **Map Key ที่เป็น IP**: ใช้ `binary.NativeEndian` ฝั่ง Go ให้ตรงกับการอ่าน `__u32` ในเคอร์เนล ไม่ควร Hard-code `LittleEndian`
- **Load Balancer ต้องมีเส้นทางขากลับ**: DNAT ขาเข้าอย่างเดียวทำให้ Backend ตอบกลับด้วย IP ของตัวเองและ Client ส่ง RST แล็บ Week 08 ใช้ Reverse SNAT ที่ TCX Ingress (แชร์ Flow Table แบบ LRU กับ XDP) และคำนวณ Checksum ด้วย `bpf_l3_csum_replace` / `bpf_l4_csum_replace` + `BPF_F_PSEUDO_HDR` อีกทางเลือกคือ DSR (Direct Server Return)
- **การเลือก Backend**: `sport % N` ใช้ไม่ได้จริง เพราะ Linux มักเลือก Ephemeral Port เป็นเลขคู่สำหรับ `connect()` ทุก Request จึงลง Backend เดียว ต้องใช้ Flow Hash
- **XDP บน veth**: โหมด Native `XDP_TX` บน veth จะดรอปแพ็กเก็ต (`xdp_tx_errors`) ถ้า Peer ไม่มีโปรแกรม XDP หรือไม่เปิด GRO แล็บจึงใช้ Generic Mode และแพ็กเก็ตที่ส่งด้วย `XDP_TX` จะไม่ผ่าน TC Egress
- **Checksum Offload ซ่อน Bug**: เมื่อเปิด TX Checksum Offload บน veth Checksum ที่ผิดจะไม่ถูกตรวจพบ ให้ปิดด้วย `ethtool -K <iface> tx off` ระหว่างทดสอบ และตรวจ Checksum ใน Unit Test ด้วย `BPF_PROG_TEST_RUN` (ดูหัวข้อ 6.4)
- แล็บทั้งหมดรองรับเฉพาะ IPv4 การรองรับ IPv6 เป็นแบบฝึกหัดท้ายบท

---

# บทที่ 5: การสตรีมข้อมูลด้วย Ring Buffer และการบล็อกด้วย BPF LSM (เฟส 05)

การติดตามพฤติกรรมความปลอดภัย (Observability & Security) ในเคอร์เนลยุคใหม่จำเป็นต้องใช้การส่งข้อมูลอย่างรวดเร็วไร้การคัดลอกซ้ำซ้อน (Zero-Copy) และการควบคุมสิทธิ์อย่างเฉียบขาดในจุดเกิดเหตุ

---

### 5.1 สถาปัตยกรรม Memory-mapped BPF Ring Buffer

ในอดีต `BPF_MAP_TYPE_PERF_EVENT_ARRAY` มีข้อเสียสำคัญคือ:
- มีการแบ่ง Buffer ย่อยตามแต่ละ CPU Core หากบาง CPU มีงานหนัก Buffer จะล้น (Event Drop) ในขณะที่ CPU ตัวอื่นว่างเปล่า
- ไม่สามารถรับประกันลำดับเวลาของเหตุการณ์ได้ (Event Out-of-Order) เมื่ออ่านจากหลาย Core

**BPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`)** แก้ปัญหาเหล่านี้ด้วยสถาปัตยกรรมแบบ **MPSC (Multi-Producer Single-Consumer)**:
- เป็น Circular Buffer ก้อนเดียวในหน่วยความจำ RAM ที่แชร์ร่วมกันทุก CPU Core
- รับประกันลำดับเหตุการณ์ตามเวลาจริง (Global Ordering)
- ประหยัดหน่วยความจำ และรองรับการจองพื้นที่แบบ Zero-Copy ในตัว

```
+-----------------------------------------------------------------------------------+
|                        BPF RING BUFFER (MPSC ARCHITECTURE)                        |
+-----------------------------------------------------------------------------------+
| Producers (Kernel CPU Cores):                                                     |
|  CPU 0 ---> [ bpf_ringbuf_reserve() ]                                             |
|  CPU 1 ---> [ bpf_ringbuf_reserve() ] ===> [ SHARED CIRCULAR RING BUFFER (RAM) ]  |
|  CPU 2 ---> [ bpf_ringbuf_reserve() ]                                             |
+-----------------------------------------------------------------------------------+
                                                              |
                                                    (Memory Mapped Zero-Copy)
                                                              v
+-----------------------------------------------------------------------------------+
| Consumer (User Space Application / Go):                                           |
|  [ ringbuf.NewReader() ] <--- ดึง Event ตามลำดับการ Reserve (ข้ามทุก CPU)          |
+-----------------------------------------------------------------------------------+
```

---

### 5.2 วงจรชีวิตของข้อมูล: `bpf_ringbuf_reserve`, `submit` และ `discard`

วงจรชีวิตของการส่งข้อมูลผ่าน Ring Buffer ใน C มีกฎเหล็ก 3 ขั้นตอน:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct security_event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // ขนาด 256 KB
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // ขั้นตอนที่ 1: Reserve พื้นที่หน่วยความจำโดยตรงใน Ring Buffer (Zero-Copy)
    struct security_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    
    // กฎเหล็ก: ต้องตรวจสอบ NULL เสมอ (กรณี Ring Buffer เต็ม)
    if (!e) {
        return 0; // Drop event หาก Buffer เต็ม
    }

    // ขั้นตอนที่ 2: กรอกข้อมูลลงใน Pointer โดยตรง
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // ดึงชื่อไฟล์จาก Syscall Argument ตัวที่ 2 (filename)
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // ขั้นตอนที่ 3: สั่ง Submit เพื่อให้ User Space มองเห็นข้อมูล
    // หรือสั่ง bpf_ringbuf_discard(e, 0) หากต้องการยกเลิก
    // ข้อควรระวัง: Verifier บังคับว่าทุก Pointer ที่ reserve สำเร็จ ต้องจบด้วย submit หรือ discard เสมอ!
    bpf_ringbuf_submit(e, 0);

    return 0;
}
```

---

### 5.3 การดักฟังสัญญะระดับ User Space ด้วย Uprobes / Uretprobes (TLS Inspection)

Uprobes (User Probes) คือกลไกที่เคอร์เนลทำการแทรกคำสั่ง Breakpoint (เช่น `int3` บน x86) ลงในหน่วยความจำ Text Segment ของแอปพลิเคชัน User Space หรือ Dynamic Library (`.so`) ทำให้เราสามารถดักจับการเรียกฟังก์ชันระดับ User Space ได้อย่างอิสระ

#### กรณีศึกษา: การดักอ่าน TLS/HTTPS Plaintext จาก OpenSSL (`libssl.so`)
แทนที่จะต้องถอดรหัส SSL เราสามารถเกาะฟังก์ชัน `SSL_write` เพื่ออ่านข้อมูลก่อนที่มันจะถูกเข้ารหัส:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// SSL_write(SSL *ssl, const void *buf, int num);
// Argument 1: SSL * (ผ่านใน Register R1 / DI)
// Argument 2: const void *buf (เนื้อความ Plaintext ผ่านใน Register R2 / SI)
// Argument 3: int num (ความยาวข้อมูล ผ่านใน Register R3 / DX)

SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, const void *buf, int num) {
    char sample[128];
    
    // อ่านข้อมูล Plaintext จากหน่วยความจำของ User Space Process
    int len = bpf_probe_read_user_str(sample, sizeof(sample), buf);
    if (len > 0) {
        bpf_printk("Plaintext TLS Outgoing: %s\n", sample);
    }
    return 0;
}
```

---

### 5.4 การรักษาความปลอดภัยเชิงรุกด้วย BPF LSM (Linux Security Modules)

ในอดีต Kprobes และ Tracepoints ทำได้เพียงแค่อ่านข้อมูล (Observability) แต่ **ไม่สามารถสั่งบล็อกการกระทำที่เป็นอันตรายได้**

**BPF LSM** เปิดตัวใน Linux Kernel 5.7+ ผสานรวมพลังของ eBPF เข้ากับโครงสร้างความปลอดภัยหลักของ Linux (เช่นเดียวกับ SELinux และ AppArmor) ทำให้ eBPF สามารถ **ปฏิเสธและสกัดกั้น Syscall ที่เป็นภัยคุกคามได้ทันทีที่จุดเกิดเหตุ**:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1 // Operation not permitted

// Hook เข้าสู่ฟังก์ชันเปิดไฟล์ระดับ LSM: file_open
SEC("lsm/file_open")
int BPF_PROG(restrict_sensitive_files, struct file *file) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // ดึงชื่อไฟล์ที่กำลังพยายามเปิด
    struct qstr d_name = BPF_CORE_READ(file, f_path.dentry, d_name);
    char filename[32];
    bpf_probe_read_kernel_str(filename, sizeof(filename), d_name.name);

    // ตรวจสอบกฎความปลอดภัย: ป้องกันไม่ให้โปรแกรมที่ไม่ใช่ root อ่านไฟล์ shadow
    if (bpf_strncmp(filename, 7, "shadow") == 0) {
        __u32 uid = bpf_get_current_uid_gid();
        if (uid != 0) {
            bpf_printk("SECURITY ALERT: Blocked unauthorized read of /etc/shadow by %s (UID %d)\n", comm, uid);
            // คืนค่า -EPERM เพื่อปฏิเสธการเปิดไฟล์ทันที Syscall open จะได้ error Permission Denied!
            return -EPERM;
        }
    }

    // คืนค่า 0 เพื่ออนุญาตให้ดำเนินการต่อตามปกติ
    return 0;
}

char _license[] SEC("license") = "GPL";
```

#### 5.5 บันทึกจากการทดลองจริง (Lab Notes จาก Week 09–10)
- **Uprobe บน TLS**: ต้อง Hook ทั้ง `SSL_write` และ `SSL_write_ex` (CPython และ OpenSSL 3 ใช้ `SSL_write_ex`) ใช้ได้เฉพาะโปรแกรมที่ Link กับ `libssl` แบบ Dynamic มองไม่เห็นทราฟฟิกของ Go `crypto/tls`, Rust `rustls`, GnuTLS (เช่น `wget`), BoringSSL และ OpenSSL แบบ Static
- **จริยธรรม**: การดักอ่าน Plaintext ของ TLS ทำได้เฉพาะบนเครื่องของตนเองหรือระบบที่ได้รับอนุญาตเป็นลายลักษณ์อักษร
- **Exec Tracing**: ใช้ `tracepoint/sched/sched_process_exec` เป็นค่าเริ่มต้น (ดูข้อสังเกตเรื่อง `syscalls:sys_enter_*` ในบทที่ 7.4)
- **BPF LSM: Attach สำเร็จ ≠ บังคับใช้จริง** ถ้า `bpf` ไม่อยู่ใน `/sys/kernel/security/lsm` เคอร์เนลจะไม่เรียกโปรแกรม LSM เลย แม้ Attach สำเร็จ วิธีเปิดใช้: เพิ่ม `lsm=<รายการเดิมทั้งหมด>,bpf` ใน `GRUB_CMDLINE_LINUX` แล้ว `update-grub` และรีบูต **ห้ามตัด LSM เดิม (เช่น apparmor, landlock) ออกจากรายการ**
- **ค่าที่คืนจาก LSM Hook**: คืน `-EPERM` (ประกาศ `#define EPERM 1`) แอปพลิเคชันจะได้ errno `EPERM` จาก `open()`
- **การจับคู่ด้วยชื่อไฟล์ (Basename) หลบได้ง่าย** ด้วย Hard link และเกิด False Positive (เช่น `secrets.pyc` ของ Python) การป้องกันที่แม่นยำกว่าคือจับคู่ด้วย (device, inode) และใช้ `bpf_d_path` สำหรับบันทึก Path เต็ม

---

# บทที่ 6: โค้ดฝั่ง User Space ด้วยภาษา Go (`cilium/ebpf`) & Cheat Sheet (เฟส 06)

ในการสร้างระบบ eBPF สำหรับใช้งานจริงบน Production ไลบรารี `github.com/cilium/ebpf` ของทีม Cilium ได้รับการยอมรับสูงสุดในชุมชน Cloud Native เนื่องจากทำงานด้วย **Pure Go (ไม่ต้องพึ่งพา CGO หรือคอมไพเลอร์ C ในขั้นตอน Runtime)**

---

### 6.1 สถาปัตยกรรม Pure Go eBPF Loader และการใช้งาน `bpf2go`

`bpf2go` คือเครื่องมืออัตโนมัติที่แปลงไฟล์โค้ดภาษา C (`.bpf.c`) ให้กลายเป็น Go Package พร้อม Structs ที่ตรงกัน และฝังไฟล์ ELF Bytecode เข้าไปในตัวแปรไบนารีของ Go โดยตรง

#### การตั้งค่าคำสั่ง Code Generation ในไฟล์ Go (`main.go`):
```go
package main

// สั่งให้ bpf2go คอมไพล์ my_xdp.c ออกมาเป็น Go Structs 
// โดยสร้างโค้ดสำหรับทั้ง Little-Endian (el) และ Big-Endian (eb)
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf my_xdp.c -- -I../headers
```

เมื่อสั่งรัน `go generate ./...` ในเทอร์มินัล เครื่องมือจะสร้างไฟล์:
- `bpf_bpfel.go` (สำหรับ Little-Endian เช่น x86_64, ARM64)
- `bpf_bpfel.o` (Compiled eBPF Object)
- ทำให้เราสามารถเรียกใช้งาน `bpfObjects` ในโค้ด Go ได้อย่างสมบูรณ์แบบโดยมี Type-Safety 100%

---

### 6.2 พิมพ์เขียว Go Control Plane ฉบับสมบูรณ์

ตัวอย่างโค้ดโปรแกรม Go ควบคุม eBPF: ปลดล็อกข้อจำกัด Memlock, โหลดโปรแกรม, ผูกเข้ากับ XDP Hook บน Network Interface, และอ่าน Event จาก Ring Buffer อย่างเป็นระบบ:

```go
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// นิยาม Struct ให้ตรงกับ struct security_event ในโค้ด C
type SecurityEvent struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	// 1. จัดการสัญญาณ Graceful Shutdown (Ctrl+C / SIGTERM)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 2. ปลดล็อกเพดานหน่วยความจำ Memlock (สำหรับ Kernel รุ่นเก่าก่อน 5.11)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("ล้มเหลวในการปลดล็อก rlimit memlock: %v", err)
	}

	// 3. โหลดโปรแกรมและ Maps eBPF ที่ถูกฝังไว้เข้าสู่เคอร์เนล
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("ล้มเหลวในการโหลด bpf objects: %v", err)
	}
	defer objs.Close()

	// 4. ค้นหา Network Interface ที่ต้องการผูก XDP (เช่น eth0 หรือ lo)
	ifaceName := "eth0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Printf("ไม่พบ interface %s กำลังสลับไปใช้ lo แทน...", ifaceName)
		iface, err = net.InterfaceByName("lo")
		if err != nil {
			log.Fatalf("ไม่พบ interface lo: %v", err)
		}
	}

	// 5. ผูกโปรแกรม eBPF เข้ากับ XDP Hook
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.ParseAndFilterPackets,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // สำหรับทดสอบ หากฮาร์ดแวร์รองรับให้ใช้ Driver Mode
	})
	if err != nil {
		log.Fatalf("ล้มเหลวในการ Attach XDP: %v", err)
	}
	defer xdpLink.Close()
	fmt.Printf("[+] ผูกโปรแกรม XDP เข้ากับ Interface %s เรียบร้อยแล้ว!\n", iface.Name)

	// 6. เปิดตัวอ่านข้อมูลจาก Ring Buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ล้มเหลวในการสร้าง ringbuf reader: %v", err)
	}
	defer rd.Close()

	// รัน Goroutine สำหรับอ่าน Event จาก Ring Buffer
	go func() {
		var event SecurityEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// Ring Buffer ถูกสั่งปิดตามปกติ
					return
				}
				log.Printf("ข้อผิดพลาดในการอ่าน Ringbuf: %v", err)
				continue
			}

			// แปลงไบต์ดิบเข้าสู่ Go Struct
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("ถอดรหัส Event ผิดพลาด: %v", err)
				continue
			}

			// พิมพ์ข้อมูลสรุป
			commStr := string(bytes.Trim(event.Comm[:], "\x00"))
			fileStr := string(bytes.Trim(event.Filename[:], "\x00"))
			fmt.Printf("[EVENT] PID: %-6d | UID: %-4d | Process: %-12s | File: %s\n",
				event.Pid, event.Uid, commStr, fileStr)
		}
	}()

	fmt.Println("[*] ระบบกำลังทำงาน กด Ctrl+C เพื่อยุติการทำงาน...")
	<-ctx.Done()
	fmt.Println("\n[*] กำลังปลด eBPF Hook และปิดระบบอย่างปลอดภัย...")
}
```

---

### 6.3 Complete Cheat Sheet: คู่มือปฏิบัติการภาคสนาม

#### 1. คำสั่ง `bpftool` ตรวจสอบเคอร์เนลที่สำคัญที่สุด:
```bash
# ตรวจสอบโปรแกรม eBPF ทั้งหมดที่กำลังรันอยู่ในระบบ
sudo bpftool prog show

# ดัมป์ดู Bytecode ที่ผ่านการประมวลผลแล้ว (Translated Instructions)
sudo bpftool prog dump xlated id <PROG_ID>

# ดัมป์ดูคำสั่ง Machine Code แท้ๆ ที่รันบนซีพียู (JIT Instructions)
sudo bpftool prog dump jited id <PROG_ID>

# ตรวจสอบ eBPF Maps ทั้งหมดในระบบ
sudo bpftool map show

# ดัมป์ข้อมูลทั้งหมดที่บันทึกอยู่ใน Map
sudo bpftool map dump id <MAP_ID>

# ดึงข้อมูลจาก Map ตาม Key ที่ระบุ
sudo bpftool map lookup id <MAP_ID> key 0x01 0x00 0x00 0x00

# ตรวจสอบสถานะการ์ดเครือข่ายและ eBPF Hook ที่ผูกอยู่ (XDP/TC)
sudo bpftool net show

# ตรวจสอบฟีเจอร์ eBPF ที่เคอร์เนลเครื่องนี้รองรับทั้งหมด
sudo bpftool feature probe
```

#### 2. คำสั่งจัดการ XDP และ TC ผ่าน `iproute2` CLI:
```bash
# โหลดโปรแกรม XDP เข้าสู่ Interface eth0 ในโหมด Native
sudo ip link set dev eth0 xdp obj my_xdp.o sec xdp

# ปลดโปรแกรม XDP ออกจาก Interface eth0
sudo ip link set dev eth0 xdp off

# สร้าง qdisc แบบ clsact สำหรับรองรับ TC eBPF ทั้ง Ingress และ Egress
sudo tc qdisc add dev eth0 clsact

# ผูกโปรแกรม TC เข้ากับขา Ingress
sudo tc filter add dev eth0 ingress bpf da obj my_tc.o sec tc_ingress

# ตรวจสอบฟิลเตอร์ TC ที่ทำงานอยู่
sudo tc filter show dev eth0 ingress

# ลบฟิลเตอร์ TC ทั้งหมด
sudo tc qdisc del dev eth0 clsact
```

#### 3. สรุป 20 BPF Helper Functions ยอดนิยมสูงสุด:

| ลำดับ | ชื่อฟังก์ชัน BPF Helper | Hook Type ที่อนุญาต | วัตถุประสงค์และการทำงาน |
| :---: | :--- | :--- | :--- |
| 1 | `bpf_map_lookup_elem(map, key)` | ทุกประเภท | ค้นหา Pointer ของข้อมูลใน Map ตาม Key ที่ระบุ (ได้ `NULL` หากไม่พบ) |
| 2 | `bpf_map_update_elem(map, key, val, flags)` | ทุกประเภท | อัปเดตหรือเพิ่มข้อมูลใหม่ลงใน Map |
| 3 | `bpf_map_delete_elem(map, key)` | ทุกประเภท | ลบข้อมูลออกจาก Map ตาม Key ที่ระบุ |
| 4 | `bpf_ringbuf_reserve(ringbuf, size, flags)` | ทุกประเภท | จองพื้นที่หน่วยความจำ Zero-Copy บน Ring Buffer |
| 5 | `bpf_ringbuf_submit(data, flags)` | ทุกประเภท | ยืนยันการส่งข้อมูลบน Ring Buffer สู่ User Space |
| 6 | `bpf_ringbuf_discard(data, flags)` | ทุกประเภท | ยกเลิกการส่งข้อมูลบน Ring Buffer คืนหน่วยความจำ |
| 7 | `bpf_ktime_get_ns()` | ทุกประเภท | คืนค่าเวลาของระบบในหน่วยนาโนวินาที (Monotonic Clock) |
| 8 | `bpf_get_current_pid_tgid()` | Tracing / LSM | ดึงค่า PID และ Thread Group ID ของ Process ปัจจุบัน |
| 9 | `bpf_get_current_uid_gid()` | Tracing / LSM | ดึงค่า UID และ GID ของผู้ใช้งานที่เป็นเจ้าของ Process |
| 10 | `bpf_get_current_comm(buf, size)` | Tracing / LSM | อ่านชื่อโปรแกรมของ Process ปัจจุบัน (เช่น `curl`, `nginx`) |
| 11 | `bpf_printk(fmt, ...)` | ทุกประเภท | พิมพ์ข้อความ Debug เข้าสู่ `/sys/kernel/tracing/trace_pipe` |
| 12 | `bpf_probe_read_user(dst, size, src)` | Tracing / LSM | อ่านหน่วยความจำจาก User Space Process อย่างปลอดภัย |
| 13 | `bpf_probe_read_kernel(dst, size, src)`| Tracing / LSM | อ่านหน่วยความจำจาก Kernel Space Data Structure |
| 14 | `bpf_xdp_adjust_head(ctx, delta)` | XDP | ขยายหรือลดขนาด Packet Header (ใช้เพิ่ม/ตัด VLAN, Encapsulation) |
| 15 | `bpf_redirect(ifindex, flags)` | XDP / TC | ส่งต่อแพ็กเก็ตไปยัง Network Interface อื่นทันที |
| 16 | `bpf_clone_redirect(skb, ifindex, flags)`| TC | โคลนแพ็กเก็ตแล้วยิงสำเนาออก Interface อื่น (ทำ Packet Sniffing/Mirroring) |
| 17 | `bpf_skb_change_proto(skb, proto, flags)`| TC | แปลงโปรโตคอลแพ็กเก็ต (เช่น แปลง IPv4 เป็น IPv6) |
| 18 | `bpf_l3_csum_replace(skb, off, from, to, fl)`| TC | คำนวณและเขียนทับ Checksum ของ Layer 3 (IP Checksum) |
| 19 | `bpf_l4_csum_replace(skb, off, from, to, fl)`| TC | คำนวณและเขียนทับ Checksum ของ Layer 4 (TCP/UDP Checksum) |
| 20 | `bpf_get_smp_processor_id()` | ทุกประเภท | ดึงหมายเลข CPU Core ID ปัจจุบันที่กำลังรันคำสั่ง eBPF |

---

### 6.4 การทดสอบโปรแกรม eBPF อัตโนมัติด้วย `BPF_PROG_TEST_RUN` และการอ่าน Verifier Log

โปรแกรม eBPF ก็เป็นซอฟต์แวร์ที่ต้องมี Unit Test เหมือนโค้ดทั่วไป เคอร์เนลมีคำสั่ง `BPF_PROG_TEST_RUN` (ผ่าน `bpf()` syscall) ให้ป้อนข้อมูลจำลองเข้าโปรแกรมแล้วรับค่า Return Code และข้อมูลขาออกกลับมา **โดยไม่ต้องผูกโปรแกรมกับ Interface จริง** รองรับโปรแกรมประเภท XDP, TC (`sched_cls`), `socket_filter`, `flow_dissector`, `raw_tracepoint` และ `tracing` (fentry/fexit)

```
  Go Test (go test -exec sudo)                Kernel
 +-----------------------------+   bpf(BPF_PROG_TEST_RUN)   +---------------------------+
 | สร้าง Packet จำลอง (bytes)   | -------------------------> | รันโปรแกรม XDP/TC 1..N รอบ |
 | ตรวจ retval == XDP_DROP ?   | <------------------------- | คืน retval + data_out     |
 | ตรวจ Packet ขาออก / Map     |   retval, data_out, duration +---------------------------+
 +-----------------------------+
```

ใน `cilium/ebpf` (v0.16) มี 3 ฟังก์ชันหลัก:

| ฟังก์ชัน | ใช้ทำอะไร |
| :--- | :--- |
| `prog.Run(&ebpf.RunOptions{Data: pkt, DataOut: out})` | รัน 1 ครั้ง ได้ `retval` และ Packet ขาออก (ตรวจว่า Rewrite Header/Checksum ถูกต้อง) |
| `prog.Test(pkt)` | รูปแบบย่อ คืน `(retval, dataOut, err)` |
| `prog.Benchmark(pkt, repeat, reset)` | รันซ้ำ `repeat` รอบในเคอร์เนล คืนเวลาเฉลี่ยต่อรอบ ใช้วัด Overhead ของโปรแกรมแทนการเดาตัวเลข |

ตัวอย่าง Unit Test สำหรับ XDP Firewall:

```go
func TestDropBlockedIP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF_PROG_TEST_RUN ต้องใช้สิทธิ์ root (รันด้วย go test -exec sudo)")
	}
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Fatalf("load: %+v", err) // %+v พิมพ์ Verifier Log ฉบับเต็มเมื่อโหลดไม่ผ่าน
	}
	defer objs.Close()

	// ใส่ IP ที่ต้องการบล็อกลง Map ก่อนทดสอบ (Network Byte Order)
	blocked := binary.LittleEndian.Uint32(net.ParseIP("10.0.0.66").To4())
	if err := objs.BlocklistMap.Put(blocked, uint8(1)); err != nil {
		t.Fatal(err)
	}

	pkt := buildIPv4TCP("10.0.0.66", "10.0.0.1", 12345, 80) // ฟังก์ชันช่วยสร้าง Eth+IPv4+TCP
	ret, err := objs.XdpFirewall.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatal(err)
	}
	if ret != 1 /* XDP_DROP */ {
		t.Fatalf("want XDP_DROP, got %d", ret)
	}
}
```

> ชื่อ `BlocklistMap` / `XdpFirewall` ขึ้นกับชื่อ Map/Program ในไฟล์ C ของแต่ละแล็บ (bpf2go แปลงเป็น CamelCase ให้) ดูตัวอย่างจริงได้ใน `main_test.go` ของแล็บที่มีชุดทดสอบ และรันทั้งหมดได้ด้วย `make test` ที่ Root ของ Repository

**หลักการเขียน Test ที่ดีสำหรับ eBPF:**
1. **Happy path + Negative path**: แพ็กเก็ตปกติต้อง `XDP_PASS` แพ็กเก็ตที่ตรงเงื่อนไขต้อง `XDP_DROP`
2. **Malformed input**: แพ็กเก็ตสั้นกว่า Header, IHL ผิด, ไม่ใช่ IPv4 (เช่น IPv6/ARP) ต้องไม่ทำให้โปรแกรมทำงานผิด
3. **ตรวจ Side effect**: อ่านค่า Map หลังรัน (Counter เพิ่มถูกต้องหรือไม่) และตรวจ `DataOut` เมื่อโปรแกรมแก้ไข Header (เช่น DNAT ต้องคำนวณ Checksum ใหม่ให้ถูก)
4. **อ่าน Verifier Log เมื่อโหลดไม่ผ่าน**: Error ที่ได้จาก `loadBpfObjects` เป็น `*ebpf.VerifierError` ให้พิมพ์ด้วย `%+v` จะได้ Log ทุกบรรทัด บรรทัดท้ายสุดคือสาเหตุ (เช่น `invalid access to packet, off=34 size=2, R1(id=0,off=34,r=34)` หมายถึงลืมตรวจ Bounds ก่อนอ่าน 2 ไบต์ที่ offset 34)

**ข้อสังเกตจากการทดลองจริงบน Linux 7.0 (Week 11–12):**
- Verifier รุ่นใหม่ฉลาดขึ้น: การ Dereference ค่าที่ได้จาก `bpf_map_lookup_elem` บน **ARRAY Map ด้วย Key คงที่** โดยไม่ตรวจ NULL ผ่าน Verifier ได้ (เพราะพิสูจน์ได้ว่า Index อยู่ในช่วง) ตัวอย่าง "ลืมตรวจ NULL" จึงต้องใช้ HASH Map
- ข้อความ Error ของ Bounds Check อาจไม่ตรงกับที่คาด เช่น Clang แยกการอ่าน `h_proto` 2 ไบต์เป็น 1 ไบต์ ทำให้ได้ `off=12 size=1`
- Atomic แบบคืนค่า (`__sync_fetch_and_add` ที่ใช้ค่าที่ได้กลับ, `__sync_val_compare_and_swap`) ต้องคอมไพล์ด้วย `-mcpu=v3` (ใส่ `-cflags "-mcpu=v3"` ใน `go:generate` ของ bpf2go) และเคอร์เนล 5.12+
- ค่าใน Config Map (ARRAY) เริ่มต้นเป็นศูนย์ทุกช่อง โค้ดต้องตีความ 0 เป็น "ใช้ค่า Default" มิฉะนั้น Limit = 0 จะดรอปทุกแพ็กเก็ต (bug จริงที่พบใน Week 12)
- `RunOptions.CPU` ใช้ไม่ได้กับโปรแกรม XDP
- **Auto-ban จาก IP ต้นทางเป็นช่องทาง DoS**: ผู้โจมตีปลอม Source IP ของผู้ใช้จริงเพื่อให้ระบบแบนผู้ใช้จริงได้

**ข้อจำกัด**: `BPF_PROG_TEST_RUN` ไม่ได้จำลองทุกอย่างของเส้นทางจริง เช่น `XDP_REDIRECT` ไปยัง AF_XDP socket, ค่า `ingress_ifindex` จริง หรือพฤติกรรมของ Driver ในโหมด Native จึงยังต้องมีการทดสอบจริงบน veth/netns ควบคู่กัน

---

# บทที่ 7: ความปลอดภัยและการตรวจจับภัยคุกคามเคอร์เนลระดับ Fleet (เฟส 07)

ในระบบปฏิบัติการลินุกซ์ระดับโปรดักชัน ภัยคุกคามและการสูญหายของข้อมูลมักเกิดขึ้นลึกเกินกว่าที่เครื่องมือ User Space ทั่วไปจะตรวจจับได้ เฟสนี้นำเทคนิค eBPF ขั้นสูงมาใช้สร้างเครื่องมือสืบสวนและเฝ้าระวัง พร้อมกับเรียนรู้ **ข้อจำกัดและช่องทางหลบเลี่ยง (Evasion)** ของเครื่องมือเหล่านั้นอย่างตรงไปตรงมา เพราะเครื่องมือความปลอดภัยที่ไม่รู้จุดอ่อนของตัวเองอันตรายกว่าไม่มีเครื่องมือ

### 7.0 กฎเหล็กของ Tracing แบบ CO-RE: ห้ามเขียน Struct ของเคอร์เนลเอง

แล็บเวอร์ชันแรกของเฟสนี้เคยประกาศ Struct ของ Tracepoint เองด้วยมือ (เช่น `struct trace_kfree_skb_args`) ผลที่พบจากการทดลองจริงคือ:
- **Week 13**: Tracepoint `skb:kfree_skb` บนเคอร์เนลใหม่มีฟิลด์ `rx_sk` เพิ่มเข้ามา ทำให้ Offset ของ `reason` เลื่อนจาก 28 เป็น 36 ไบต์ Struct ที่เขียนตายตัวสำหรับเคอร์เนลหนึ่งจะอ่านค่าขยะบนอีกเคอร์เนลหนึ่ง
- **Week 16**: Struct ที่เขียนเองอ่าน `cmd` ของ `sys_enter_bpf` ที่ Offset 12 แต่เคอร์เนลจริงวางไว้ที่ Offset 16 ผลคือทุกอีเวนต์ถูกรายงานเป็น `BPF_MAP_CREATE` ทั้งหมด

แนวทางที่ถูกต้อง:
```c
#include "vmlinux.h"                 // Type ทั้งหมดมาจาก BTF ของเคอร์เนลจริง
#include <bpf/bpf_core_read.h>

SEC("tracepoint/skb/kfree_skb")
int trace_drop(struct trace_event_raw_kfree_skb *ctx)
{
    __u32 reason = BPF_CORE_READ(ctx, reason);        // libbpf ปรับ Offset ให้ตอนโหลด
    if (bpf_core_field_exists(ctx->rx_sk)) {           // ฟิลด์นี้มีเฉพาะเคอร์เนลใหม่
        /* ... */
    }
    return 0;
}
```
ตรวจรูปแบบจริงของ Tracepoint บนเครื่องได้ที่ `/sys/kernel/tracing/events/<subsystem>/<event>/format` ทุกครั้งก่อนเขียนโค้ด

### 7.1 วินิจฉัย Packet Drops ด้วย `tracepoint:skb:kfree_skb`
เมื่อเคอร์เนลทิ้งแพ็กเก็ต จะเรียก `kfree_skb_reason()` และยิง Tracepoint `skb:kfree_skb` พร้อมรหัสสาเหตุ (`enum skb_drop_reason`):
- ชื่อสาเหตุ (เช่น `NO_SOCKET`, `TCP_CSUM`, `NETFILTER_DROP`) ควรแปลงจาก **BTF ของเคอร์เนลที่รันอยู่** ไม่ใช่ตารางที่เขียนตายตัว เพราะค่าตัวเลขเปลี่ยนไปตามเวอร์ชันเคอร์เนล
- **16 บิตบนของ reason คือ Subsystem** เช่นค่า `0x10058` ที่เคยดูเหมือนค่าขยะ จริง ๆ คือสาเหตุจาก Subsystem `mac80211` (Wi-Fi) รหัส `0x58`
- PID/COMM ที่ได้ในอีเวนต์นี้มักเป็นบริบท SoftIRQ (เช่น `swapper/3`, `ksoftirqd`) **ไม่ใช่เจ้าของแพ็กเก็ต** ต้องระวังการตีความ
- ตำแหน่งที่ดรอป (`location`) ควรแสดงเป็น `symbol+offset` โดยเทียบกับ `/proc/kallsyms`

### 7.2 Socket Egress Control ด้วย `cgroup/connect4`
- Hook `cgroup/connect4` ทำงานทุกครั้งที่โพรเซสใน cgroup เรียก `connect()` บน IPv4 ได้รับ `struct bpf_sock_addr` ที่อ่าน `user_ip4`, `user_port` ได้
- คืนค่า `1` = อนุญาต, `0` = ปฏิเสธ (แอปพลิเคชันได้ `EPERM`) โดยไม่มีแพ็กเก็ต SYN ถูกส่งออก
- **ต้องผูกกับ cgroup เฉพาะของแล็บเสมอ** (เช่น `/sys/fs/cgroup/w14-sock-enforce`) การผูกกับ Root cgroup จะกระทบทุกโพรเซสในเครื่อง แล็บเวอร์ชันใหม่จึงปฏิเสธ Root cgroup ถ้าไม่ระบุ `-allow-root`
- Overhead: โปรแกรมรันหนึ่งครั้งต่อการเรียก `connect()` (ไม่ใช่ต่อแพ็กเก็ต) จึงต่ำ แต่ไม่ใช่ศูนย์
- **ช่องทางหลบเลี่ยงที่ยืนยันแล้วจากการทดลอง**: UDP `sendto()` โดยไม่เรียก `connect()` (ต้องเพิ่ม Hook `cgroup/sendmsg4`), การเชื่อมต่อผ่าน IPv6 / IPv4-mapped IPv6 (ต้องเพิ่ม `cgroup/connect6`) และ Socket ที่สร้างก่อนโพรเซสถูกย้ายเข้า cgroup

### 7.3 การตรวจจับ Reverse Shell ผ่าน `task_struct`
- ใช้ `tracepoint/sched/sched_process_exec` (ทำงานครบทุก CPU) อ่าน `task->real_parent->comm` ด้วย `BPF_CORE_READ`
- การจับคู่ชื่อแบบ **Prefix** (`"nc"`, `"pyth"`) ทำให้เกิด False Positive และการเทียบเฉพาะชื่อ `comm` หลบได้ง่ายด้วย `cp /bin/sh /tmp/x` แล็บเวอร์ชันใหม่จึงใช้:
  1. ชื่อแบบ Exact Match จาก Map ที่แก้ไขได้ขณะรัน
  2. **สัญญาณเชิงพฤติกรรม**: ตรวจว่า File Descriptor 0/1/2 ของ Shell เป็น Network Socket หรือไม่ (`task->files->fdt->fd[i]->...->skc_family`) ซึ่งจับ Shell ที่ถูกเปลี่ยนชื่อได้
  3. ข้าม Unix Domain Socket เพราะ Node.js/libuv ใช้เป็น stdio ของโพรเซสลูกตามปกติ (False Positive ที่พบจริง)
- **Evasion ที่ยังหลบได้**: Reverse Shell ที่ใช้ PTY (fd 0/1/2 เป็น `/dev/pts/*` ไม่ใช่ Socket) และสคริปต์ Shebang จะมี `comm` เป็นชื่อสคริปต์แทนชื่อ Interpreter

### 7.4 eBPF Integrity Auditor: เฝ้าระวังการใช้ `bpf()` Syscall
มัลแวร์ยุคใหม่ (เช่น BPFDoor, Symbiote, TripleCross) ใช้ eBPF ซ่อนตัว เครื่องมือตรวจสอบจึงต้องรู้ว่าใครโหลดโปรแกรม BPF อะไร:
- **Hook หลัก**: `fentry/__sys_bpf` อ่าน `cmd` และ `attr` ด้วย CO-RE, **Fallback**: `raw_syscalls/sys_enter` กรอง `id == __NR_bpf`
- **Startup Scan**: ตอนเริ่มทำงานให้ไล่ดูโปรแกรมที่ถูกโหลดไว้ก่อนแล้วด้วย `ebpf.ProgramGetNextID()` + `ebpf.NewProgramFromID()` และต้องทำ **หลัง** Attach Hook แล้ว เพื่อไม่ให้มีช่องว่างที่โปรแกรมหลุดรอดระหว่างสแกน
- **ข้อจำกัดที่ต้องยอมรับ**: ผู้โจมตีที่มีสิทธิ์ root/`CAP_SYS_ADMIN` สามารถ kill หรือ detach ตัว Auditor ได้; การอ่าน `bpf_attr` จาก User Memory มีปัญหา TOCTOU; ถ้าต้องการ "บังคับ" ไม่ใช่แค่ "เฝ้าดู" ต้องใช้ BPF LSM Hook `bpf` / `bpf_prog_load`, BPF Token และ Program Signing ร่วมด้วย

> ⚠️ **ข้อสังเกตจากเคอร์เนลทดลอง (Linux 7.0.0-38-generic, Ubuntu 26.04)**: พบว่าโปรแกรม BPF ที่ผูกกับ Tracepoint `syscalls:sys_enter_*` **บางตัว** ทำงานเฉพาะเมื่อ Syscall เกิดบน CPU 0 (ทดสอบ exec 24 ครั้งกระจายบน 8 CPU: `sys_enter_execve` จับได้ 3 ครั้ง ขณะที่ `raw_syscalls:sys_enter` และ `sched:sched_process_exec` จับได้ครบ 24 ครั้ง) พบอาการเดียวกันกับ `sys_enter_openat` แต่ `sys_enter_bpf` และ `sys_enter_getppid` ทำงานครบทุก CPU ยังไม่ได้ยืนยันสาเหตุในซอร์สโค้ดเคอร์เนล แล็บในหลักสูตรนี้จึงหลีกเลี่ยง `syscalls:sys_enter_*` สำหรับงานที่ต้องการความครบถ้วน และใช้ `sched_process_exec`, `raw_syscalls` หรือ `fentry` แทน **บทเรียนสำคัญ: เครื่องมือความปลอดภัยต้องทดสอบด้วยการกระจายเหตุการณ์ทุก CPU (`taskset -c N`) เสมอ**

---

# บทที่ 8: การวัดประสิทธิภาพระบบ การแกะรอย Stack และการวิเคราะห์ฮาร์ดแวร์ (เฟส 08)

### 8.1 การวัด Storage Block I/O Latency ด้วย Log2 Histograms
- ใช้ `tp_btf/block_rq_issue` และ `tp_btf/block_rq_complete` (BTF-enabled Tracepoint ได้ `struct request *` ตรง ๆ) และ Attach ด้วย `link.AttachTracing`
- **Key ของ Map ที่ถูกต้องคือ Pointer ของ `struct request`** ไม่ใช่ (dev, sector) เพราะ Flush Request ไม่มี Sector จริง และ Partial Completion จะทำให้คู่ Issue/Complete จับคู่ผิด
- คำนวณ Bucket ด้วย log2 แบบ Branch-free (เทคนิคเดียวกับ libbpf-tools) แทนการ Unroll 31 ขั้น
- การเพิ่มค่าใน Histogram ต้องใช้ `__sync_fetch_and_add` และสร้าง Bucket ด้วย `BPF_NOEXIST` เพื่อไม่ให้สอง CPU เขียนทับกัน
- แยก Histogram ตามดิสก์และชนิด I/O (READ / WRITE / OTHER) จะเห็นภาพชัดกว่ารวมกันทั้งหมด
- **ข้อควรระวังเชิงปฏิบัติ**: `/tmp` บน Ubuntu เป็น tmpfs (อยู่ใน RAM) ต้องใช้ `/var/tmp` หรืออุปกรณ์จริงจึงจะเกิด Block I/O และบน Ubuntu 26.04 คำสั่ง `dd` ค่าเริ่มต้นเป็น Rust uutils ที่ล้มเหลวกับ `iflag=direct` บนอุปกรณ์ Block ให้ใช้ `gnudd` แทน

### 8.2 On-CPU Profiler ด้วย `perf_event` Sampling และการถอดรหัส Stack
- **On-CPU vs Off-CPU**: การ Sample ที่ `sched_switch` บอกได้แค่ว่าเธรด "หยุดรันที่ไหน" (Off-CPU / Blocking) **ไม่ได้บอกว่าเวลา CPU หมดไปกับอะไร** Profiler แบบ On-CPU ที่ถูกต้องต้อง Sample ตามเวลา
- ฝั่ง Go เปิด `perf_event_open(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, freq=99Hz)` ทีละ CPU แล้วผูกโปรแกรม `SEC("perf_event")` ด้วย `link.AttachRawLink{Attach: ebpf.AttachPerfEvent}` (มี Fallback เป็น ioctl `PERF_EVENT_IOC_SET_BPF`)
- 99 Hz (ไม่ใช่ 100) เพื่อหลีกเลี่ยงการ Sample พร้อมกับงานที่ทำงานเป็นจังหวะตาม Timer (Lockstep)
- `bpf_get_stackid()` ด้วย flags `0` และ **นับจำนวน Collision (`-EEXIST`) แล้วรายงาน** — การใช้ `BPF_F_REUSE_STACKID` จะเขียนทับ Stack เดิมที่ Hash ชนกันทำให้ตัวเลข Profile ผิดแบบเงียบ ๆ
- Kernel Stack แปลงเป็นชื่อด้วย `/proc/kallsyms` ส่วน User Stack แปลงด้วย `/proc/<pid>/maps` + ตาราง Symbol ใน ELF; User Stack จะสมบูรณ์ได้ต้องคอมไพล์โปรแกรมเป้าหมายด้วย Frame Pointer (`-fno-omit-frame-pointer`) และฟังก์ชันที่ถูก Tail-call จะหายไปจาก Stack
- ส่งออกเป็นรูปแบบ Folded Stack (`-folded out.txt`) สำหรับ `flamegraph.pl` ของ Brendan Gregg
- ผลทดสอบจริง: Workload ที่ออกแบบให้ Hot Path ใช้เวลาสัดส่วน 2:1 วัดได้ ~1.93:1 ที่ 99 Hz

### 8.3 การเฝ้าระวัง Page Faults และ OOM Killer
- `tracepoint:exceptions:page_fault_user` มีเฉพาะบน x86 และชื่อ Struct เปลี่ยนไปตามเวอร์ชัน (`trace_event_raw_exceptions` / `x86_exceptions`) ให้เลือกด้วย CO-RE และอ่านผ่าน `BPF_CORE_READ` (การอ่าน ctx ตรง ๆ ในกรณีนี้ถูก Verifier ปฏิเสธด้วย "modified ctx ptr")
- `tracepoint:oom:mark_victim` ฟิลด์ที่มีขึ้นกับเวอร์ชันเคอร์เนล ต้องตรวจด้วย `bpf_core_field_exists` ขนาดหน่วยความจำในอีเวนต์เป็นหน่วย kB อยู่แล้ว
- **Task ปัจจุบันขณะที่ `mark_victim` ทำงาน คือโพรเซสที่ "ทำให้เกิด" OOM ไม่จำเป็นต้องเป็นโพรเซสที่ถูกฆ่า** ข้อมูลเหยื่อต้องอ่านจากฟิลด์ของอีเวนต์
- ทดลอง OOM อย่างปลอดภัยใน cgroup ที่จำกัดหน่วยความจำ: `systemd-run --user --scope -p MemoryMax=50M -p MemorySwapMax=0 <โปรแกรม>` (ต้องปิด Swap ของ Scope ไม่เช่นนั้นจะไม่ถึง OOM)

---

# บทที่ 9: การเร่งความเร็ว Socket และสถาปัตยกรรม Kernel Bypass (เฟส 09)

### 9.1 TCP Sockops และ `sk_msg` Socket Redirect
- โปรแกรม `sockops` จับ `BPF_SOCK_OPS_{ACTIVE,PASSIVE}_ESTABLISHED_CB` แล้วบันทึก Socket ลง `BPF_MAP_TYPE_SOCKHASH` ด้วย Key เป็น 4-tuple
- โปรแกรม `sk_msg` ทำงานตอน `sendmsg()` สร้าง Key แบบ "กลับด้าน" เพื่อหา Socket ของคู่สนทนา แล้วเรียก `bpf_msg_redirect_hash(..., BPF_F_INGRESS)`
- **กับดัก Byte Order (bug จริงที่เคยมีในแล็บนี้)**: `local_port` เป็น **Host Byte Order** ส่วน `remote_port` เป็น **Network Byte Order อยู่ใน 16 บิตบน** การสร้าง Key ทั้งสองฝั่งต้องใช้การแปลงแบบเดียวกัน (เช่น `local_port` ตรง ๆ และ `bpf_ntohl(remote_port)`) มิฉะนั้น Lookup จะไม่เจอ ทุกข้อความ Fallback ไปทาง Stack ปกติแบบเงียบ ๆ และตัวนับ "accelerated" ต้องเพิ่มเฉพาะเมื่อ Redirect สำเร็จจริง
- สิ่งที่ถูกข้าม: Segment/IP Processing ของ Loopback (Routing, Netfilter, TCP Segmentation) **สิ่งที่ไม่ถูกข้าม**: 3-way Handshake และการปิด Connection ยังผ่าน Stack ปกติ และข้อมูลยังถูก Copy (ไม่ใช่ Zero-copy)
- ผลข้างเคียง: `tcpdump -i lo` และ iptables จะมองไม่เห็น Payload ที่ถูก Redirect (สำคัญต่อการ Debug และ Audit)
- ผลวัดจริง (Intel i3-12100, Loopback, 1 Stream, Median): Throughput จาก tcpbench 51.5 → 66.3 Gbit/s, จาก iperf3 ~66 → 105–114 Gbit/s, Round-trip Latency ข้อความ 64 ไบต์ (p50) 6.7 → 3.3 µs ตัวเลขขึ้นกับ CPU, ขนาดข้อความ และ Workload ให้วัดซ้ำบนเครื่องตนเอง
- โปรแกรม `sockops` / `sk_msg` ไม่รองรับ `BPF_PROG_TEST_RUN` การทดสอบจึงต้องเป็น End-to-end ใน cgroup ทดสอบ

### 9.2 AF_XDP: ส่งแพ็กเก็ตจาก XDP ตรงสู่ User Space
องค์ประกอบที่ต้องมีครบจึงจะรับแพ็กเก็ตได้ (แล็บเวอร์ชันแรกขาดฝั่ง Socket ทำให้ Redirect เป็น 0 ตลอด):
1. **UMEM**: หน่วยความจำที่ User Space จองและลงทะเบียนด้วย `setsockopt(XDP_UMEM_REG)` แบ่งเป็น Frame ขนาดคงที่
2. **4 Ring**: FILL (User ให้ Frame ว่างแก่เคอร์เนล), RX (เคอร์เนลส่ง Frame ที่มีแพ็กเก็ตกลับ), TX และ COMPLETION ทุก Ring ต้อง `mmap` เข้ามา
3. **Bind** Socket เข้ากับ (ifindex, queue_id) แล้วใส่ fd ลง `BPF_MAP_TYPE_XSKMAP` โดยใช้ **RX Queue ID เป็น Key**
4. โปรแกรม XDP เรียก `bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS)` — Flag `XDP_PASS` เป็นค่า Fallback เมื่อไม่มี Socket ในช่องนั้น (เคอร์เนล 5.3+)

**Copy mode vs Zero-copy**: บน veth หรือไดรเวอร์ที่ไม่รองรับ จะทำงานใน `XDP_COPY` (มีการ Copy หนึ่งครั้ง แต่ยังข้าม `sk_buff` และ Network Stack) การขอ `XDP_ZEROCOPY` บน veth ได้ `operation not supported` Zero-copy ต้องการไดรเวอร์ที่รองรับ (เช่น i40e, ice, mlx5) ตรวจโหมดได้ด้วย `ss --xdp` (`zc:0` / `zc:1`) ตัวเลขระดับหลายล้าน PPS ในบทความวิชาการ (เช่น Høiland-Jørgensen et al., CoNEXT 2018) วัดบน NIC จริงในโหมด Native/Zero-copy ไม่ควรนำมาอ้างกับการทดลองบน veth

ผลทดสอบจริงในแล็บ: ส่ง UDP 20,005 แพ็กเก็ตผ่าน veth ระหว่าง netns ถูก Redirect และรับครบ 20,005 แพ็กเก็ต ดรอป 0 โดย UDP Counter ของเคอร์เนลฝั่งรับไม่เพิ่มขึ้นเลย (ยืนยันว่าแพ็กเก็ตไม่ผ่าน Network Stack) ส่วน Ping/ARP ยังทำงานปกติเพราะโปรแกรมเลือกส่งเฉพาะ IPv4/UDP เข้า AF_XDP

---

# บทที่ 10: เทคโนโลยี eBPF ยุคใหม่ระดับแนวหน้า (เฟส 10)

### 10.1 Modern BPF Trampoline (`fentry` / `fexit`) Low-Overhead Tracing
Kprobe ดั้งเดิมทำงานผ่าน Breakpoint (`int3`) หรือผ่าน ftrace เมื่อจุดที่ Probe เป็นต้นฟังก์ชัน (บนเคอร์เนลทดลอง 7.0 Kprobe ที่ต้นฟังก์ชันแสดงสถานะ `[FTRACE]`) แล้วจึงเรียกโปรแกรม BPF ผ่านชั้น `pt_regs` ส่วน Kretprobe ต้องแทรก Trampoline ที่ Return Address ของทุกการเรียก ซึ่งมีต้นทุนสูง

- **BPF Trampoline** ใช้ ftrace NOP (5 ไบต์บน x86-64) ที่ต้นฟังก์ชันเคอร์เนล เคอร์เนลเขียนทับเป็น `call` ไปยัง Trampoline ที่ JIT สร้างขึ้นเฉพาะ ซึ่งเรียกโปรแกรม BPF ตรง ๆ
- โปรแกรม `fentry`/`fexit` เข้าถึงอาร์กิวเมนต์ได้ตรงตาม Signature ใน BTF เช่น `int BPF_PROG(trace_open, int dfd, const char *filename, struct open_how *how)` โดยไม่ต้องใช้ `PT_REGS_PARM`
- `fexit` อ่านได้ทั้งอาร์กิวเมนต์และค่าที่คืน (`ret`) ในบริบทเดียว **ชนิดของ `ret` ต้องตรงกับ BTF** เช่น `do_sys_openat2` บนเคอร์เนล 7.0 คืน `int` ไม่ใช่ `long` (bug จริงที่เคยมีในแล็บ)

**ผลวัดจริง** (Week 22: Probe `count()` ที่เหมือนกันด้วย bpftrace บน `do_sys_openat2`, Workload `openat()+close()` 1 ล้านครั้ง Pin ไว้ 1 CPU, Best-of-9, 4 รอบ, Linux 7.0.0-38, Intel i3-12100):

| ชนิด Probe | เวลาเพิ่มต่อการเรียก (โดยประมาณ) |
| :--- | :--- |
| kprobe | +45–50 ns |
| kretprobe | +143–159 ns |
| fentry | +13–26 ns |
| fexit | +34–44 ns |

- เมื่อเปิด `kernel.bpf_stats_enabled=1` ตัวโปรแกรม BPF เองใช้เวลาเฉลี่ย ~20–23 ns ต่อครั้งในทุกชนิด Probe ส่วนต่างที่เหลือคือต้นทุนของกลไก Attach
- ข้อสรุปที่เชื่อถือได้: **fexit ถูกกว่า kretprobe อย่างชัดเจน** และ fentry ถูกกว่า kprobe แต่ **ไม่มีชนิดใดที่ "Zero-overhead" หรือต่ำกว่า 5 ns**
- ข้อควรระวังในการอ้างตัวเลข: วัดขณะ CPU Governor เป็น `powersave` และมีงานอื่นรันอยู่ บางรอบได้ค่าติดลบจาก Baseline ที่แกว่ง หากจะอ้างในงานวิจัยให้วัดซ้ำบนเครื่องว่างด้วย Governor `performance` (ใช้ `make bench` ใน Week 22)

### 10.2 BPF Iterators (`iter/task`) การท่องโครงสร้างเคอร์เนลโดยตรง
- โปรแกรม `SEC("iter/task")` ถูกเรียกหนึ่งครั้งต่อ Task ฝั่ง User Space สร้าง Iterator ด้วย `BPF_ITER_CREATE` แล้ว `read()` ผลที่โปรแกรมเขียนผ่าน `BPF_SEQ_PRINTF()` (กลไก `seq_file`)
- **`iter/task` วนทุกเธรด ไม่ใช่ทุกโพรเซส** ถ้าต้องการรายการโพรเซสให้กรองเฉพาะ `task->pid == task->tgid` (เวอร์ชันแรกของแล็บแสดง 603 แถวจาก 159 PID เพราะไม่ได้กรอง) แยก Kernel Thread ได้ด้วย Flag `PF_KTHREAD`
- ใช้ `ctx->meta->seq_num == 0` เพื่อพิมพ์ Header เพียงครั้งเดียว
- ผลวัดจริง (Week 23): Iterator ใช้ ~120–170 µs เทียบกับการไล่อ่าน `/proc/*/status` ~2.5–2.7 ms (เร็วกว่าราว 15–22 เท่า) แต่ต้องตีความอย่างระวัง เพราะงานไม่เท่ากัน: Iterator ใช้ `BPF_ITER_CREATE` 1 ครั้ง + `read()` 16 ครั้ง ขณะที่ `/proc` ต้อง `openat` 321 ครั้ง + `read` 1,089 ครั้ง ข้อได้เปรียบหลักคือจำนวน Syscall และการไม่ต้อง Format/Parse ข้อความ **ไม่ใช่ "Zero Context Switch"** เพราะยังมี Syscall อยู่

---

### บทสรุปและแนวทางการศึกษาต่อยอด (Next Steps)
การเรียนรู้ eBPF ให้เชี่ยวชาญต้องอาศัยการลงมือปฏิบัติจริง หลังจากศึกษาเนื้อหาทั้ง 10 บทแล้ว ให้ทำแล็บรายสัปดาห์ใน `phase01` ถึง `phase10` พร้อมแบบฝึกหัดท้ายบท 3 ระดับของแต่ละสัปดาห์ และฝึกนิสัยของวิศวกร eBPF ระดับโปรดักชัน 4 ข้อที่หลักสูตรนี้เน้นย้ำ:
1. **ใช้ CO-RE (`vmlinux.h` + `BPF_CORE_READ`) เสมอ** ห้ามเขียน Struct ของเคอร์เนลเอง
2. **เขียน Unit Test ด้วย `BPF_PROG_TEST_RUN`** (`make test`) และทดสอบ End-to-end บน netns/veth/cgroup ที่แยกจากระบบจริง
3. **วัดก่อนอ้าง**: ทุกตัวเลขประสิทธิภาพต้องมาพร้อมวิธีวัด สภาพแวดล้อม และข้อจำกัด
4. **ระบุ Threat Model และข้อจำกัด** ของเครื่องมือความปลอดภัยทุกครั้ง และทดสอบให้ครอบคลุมทุก CPU

หัวข้อแนะนำสำหรับศึกษาต่อ: kfuncs, BPF Arena, `struct_ops` / sched_ext, BPF Token, netkit, Tail Calls, `bpf_loop` / Open-coded Iterators, `bpf_timer`, USDT และเครื่องมือในระบบนิเวศ เช่น Cilium, Tetragon, Falco
