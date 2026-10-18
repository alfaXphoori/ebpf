# Week 11: Production eBPF Verifier & Prometheus Telemetry Exporter

คู่มือการศึกษาเชิงลึกเกี่ยวกับกลไกการทำงานของ **eBPF Verifier**, การดีบักข้อผิดพลาดของ Verifier ในระดับ Instruction, การเลือกใช้ **`BPF_MAP_TYPE_PERCPU_ARRAY`** เพื่อความเร็วระดับ 10M+ PPS, และการสร้างระบบ Network Telemetry ส่งข้อมูลเข้าสู่ **Prometheus & Grafana**

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 การทำงานภายในของ eBPF Verifier
ก่อนที่ eBPF Bytecode จะได้รับอนุญาตให้รันภายใน Linux Kernel ตัวเคอร์เนลจะนำ Bytecode เข้าสู่กระบวนการ Static Analysis ที่เข้มงวดที่สุดในโลกของระบบปฏิบัติการ เรียกว่า **eBPF Verifier**

```
+-------------------------------------------------------------------------+
|                  การทำงานของ EBPF VERIFIER STATIC ANALYSIS              |
|                                                                         |
|  C Code (.c) ---> Clang/LLVM ---> eBPF Bytecode (.o)                   |
|                                         |                               |
|                                         v                               |
|                     +-----------------------------------+               |
|                     |        eBPF Kernel Verifier       |               |
|                     +-----------------------------------+               |
|                     | 1. ตรวจสอบ Control Flow Graph     |               |
|                     |    - ป้องกัน Infinite Loop        |               |
|                     |    - ตรวจจับ Unreachable Code     |               |
|                     |                                   |               |
|                     | 2. จำลองการทำงานทุก Execution Path|               |
|                     |    - ติดตาม State ของ Registers   |               |
|                     |      (R0 - R10: Type, Bounds, Min/Max)            |
|                     |                                   |               |
|                     | 3. Packet Bounds Checking         |               |
|                     |    - ทุกการอ่าน Memory ต้องพิสูจน์ได้ว่า|             |
|                     |      data + offset <= data_end    |               |
|                     +-----------------------------------+               |
|                                 |           |                           |
|                        ผ่าน      v           v ล้มเหลว                   |
|                  +---------------+   +-----------------------------+    |
|                  | JIT Compiler  |   | ปฏิเสธการโหลดลง Kernel       |    |
|                  | (x86/ARM64)   |   | ส่งกลับ Verifier Log ละเอียด |    |
|                  +---------------+   +-----------------------------+    |
+-------------------------------------------------------------------------+
```

### 1.2 เจาะลึก Error ยอดนิยมของ Verifier และวิธีแก้ไข

#### 1. `invalid access to packet, off=X size=Y, R1_w=pkt(id=0,off=0,r=0,imm=0)`
- **สาเหตุ**: โปรแกรมพยายามอ่าน Memory ของ Packet โดยไม่มีการตรวจสอบ Bounds Check หรือตรวจสอบไม่ครอบคลุมขนาดของ Struct ที่อ่าน
- **วิธีแก้**: ทุกครั้งก่อนเข้าถึงฟิลด์ใน Header ต้องเขียนเงื่อนไขชัดเจน:
  ```c
  if ((void *)(eth + 1) > data_end)
      return XDP_PASS;
  ```

#### 2. `R1 offset is outside of the packet`
- **สาเหตุ**: มีการบวกค่า Offset ลงใน Pointer แล้วค่าทะลุเกินช่วงที่พิสูจน์ได้ หรือเกิด Integer Overflow ในการคำนวณ `ihl * 4`
- **วิธีแก้**: ทำการตรวจสอบขอบเขตต่ำสุดและสูงสุดของค่าตัวแปร:
  ```c
  __u32 ip_hdr_len = iph->ihl * 4;
  if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
  if ((void *)iph + ip_hdr_len > data_end) return XDP_PASS;
  ```

#### 3. `back-edge from insn X to Y`
- **สาเหตุ**: Verifier ตรวจพบลูปแบบไม่จำกัดรอบ (Unbounded Loop)
- **วิธีแก้**: ใช้ `#pragma unroll` หรือระบุเงื่อนไข Break ที่ชัดเจนด้วยตัวแปรคงที่ขนาดเล็ก (เช่น `for (int i = 0; i < 10; i++)`)

### 1.3 การอ่านและดีบัก Verifier Log ด้วย `bpftool`
เมื่อเกิดข้อผิดพลาดในการโหลด สามารถดู Assembly Instruction และ Register State ของ Verifier ได้โดยตรง:
```bash
bpftool prog load metrics_exporter.o /sys/fs/bpf/test -d
```
Verifier จะแสดง Trace ทีละคำสั่ง:
```text
0: (bf) r6 = r1                  ; R6=ctx(id=0,off=0,imm=0)
1: (61) r2 = *(u32 *)(r6 +0)     ; R2=pkt(id=0,off=0,r=0,imm=0)
2: (61) r3 = *(u32 *)(r6 +4)     ; R3=pkt_end(id=0,off=0,imm=0)
3: (bf) r1 = r2
4: (07) r1 += 14                 ; R1=pkt(id=0,off=14,r=0,imm=0)
5: (2d) if r1 > r3 goto pc+18    ; ตรวจสอบ eth + 1 <= data_end
```

### 1.4 ทำไม `BPF_MAP_TYPE_PERCPU_ARRAY` จึงเร็วที่สุดในงาน Telemetry
ในระบบเครือข่ายความเร็วสูงระดับ 10 Gbps ถึง 100 Gbps แพ็กเก็ตจะถูกประมวลผลบนหลาย CPU Core พร้อมๆ กัน:
- หากใช้ `BPF_MAP_TYPE_ARRAY` ทั่วไป: ทุกคอร์จะต้องแย่งกันเขียน Memory ก้อนเดียวกันผ่านคำสั่ง Atomic Lock (`LOCK XADD`) ซึ่งทำให้เกิด **Cache-line Contention / Bouncing** และ Latency สูงขึ้นอย่างมาก
- เมื่อใช้ `BPF_MAP_TYPE_PERCPU_ARRAY`: Linux Kernel จะจัดสรร Array ชุดใหม่แยกตาม CPU Core แต่ละคอร์จะเขียนลง L1/L2 Cache ของตัวเองโดยไม่ต้องพึ่ง Atomic Instructions ใดๆ จากนั้นฝั่ง User-space Go daemon จะทำหน้าที่รวมผล (Aggregation) ตอนที่มีการ Scrape จาก Prometheus เท่านั้น

```
+-------------------------------------------------------------------------+
|                สถาปัตยกรรม EBPF TELEMETRY สู่ PROMETHEUS                 |
|                                                                         |
|  [ Ingress Packet ]                                                     |
|         |                                                               |
|         v                                                               |
|  [ XDP Hook: xdp_metrics_prog ]                                         |
|         |                                                               |
|         +---> CPU 0: traffic_metrics[proto] += (pkts, bytes)            |
|         +---> CPU 1: traffic_metrics[proto] += (pkts, bytes)            |
|         +---> CPU 2: traffic_metrics[proto] += (pkts, bytes)            |
|                                                                         |
|  [ Go Prometheus Collector: xdpCollector ]                              |
|         |                                                               |
|         |-- 1. ดึงข้อมูลจากทุก CPU cores รวมผล (Sum Aggregation)        |
|         \-- 2. สร้าง Prometheus Metrics: ebpf_xdp_packets_total         |
|                                                                         |
|  [ Prometheus Server ] <--- HTTP GET :2112/metrics                      |
|         |                                                               |
|         v                                                               |
|  [ Grafana Dashboard ]                                                  |
+-------------------------------------------------------------------------+
```

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 eBPF C Program (`metrics_exporter.c`)

```c
struct proto_metric {
    __u64 packets;
    __u64 bytes;
};
```
- **บรรทัด 18–21**: ประกาศโครงสร้างสถิติขนาด 16 ไบต์ สำหรับเก็บจำนวนแพ็กเก็ต (`packets`) และปริมาณข้อมูลรวม (`bytes`)

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct proto_metric);
    __uint(max_entries, 4);
} traffic_metrics SEC(".maps");
```
- **บรรทัด 28–33**: กำหนด Per-CPU Array แมป ชื่อ `traffic_metrics` ขนาด 4 ช่อง (0: TCP, 1: UDP, 2: ICMP, 3: Other) แยกอิสระตามแต่ละคอร์

```c
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 50–53**: Verifier Bounds Check บังคับว่าพอยน์เตอร์สิ้นสุดของ Ethernet Header (`eth + 1`) ต้องไม่เกิน `data_end` หากเกินให้ข้ามทันที

```c
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 67–70**: Bounds Check สำหรับ IPv4 Header ป้องกันการอ่านหน่วยความจำนอกขอบเขตของเคอร์เนล

```c
    struct proto_metric *metric = bpf_map_lookup_elem(&traffic_metrics, &proto_idx);
    if (metric) {
        metric->packets += 1;
        metric->bytes += (__u64)(data_end - data);
    }
```
- **บรรทัด 93–97**: ดึง Pointer ไปยังสถิติบน CPU คอร์ปัจจุบัน และอัปเดตสถิติโดยไม่ต้องมี `__sync_fetch_and_add` เพราะเป็นการเขียนบนหน่วยความจำเฉพาะคอร์ (Per-CPU Lock-free)

---

### 2.2 Go Prometheus Exporter (`main.go`)

```go
var (
    packetDesc = prometheus.NewDesc("ebpf_xdp_packets_total", ...)
    byteDesc   = prometheus.NewDesc("ebpf_xdp_bytes_total", ...)
)
```
- **บรรทัด 24–36**: ประกาศตัวแปร Metric Descriptors ตามมาตรฐาน Prometheus พร้อมใส่ Label `protocol` และ `interface`

```go
func (c *xdpCollector) Collect(ch chan<- prometheus.Metric) {
    for idx, proto := range protocolNames {
        perCPUValues := make([]bpfProtoMetric, c.numCPUs)
        c.metricsMap.Lookup(&key, &perCPUValues)
        ...
```
- **บรรทัด 61–95**: ทำงานเมื่อ Prometheus ยิง Scrape เข้ามา โดยฟังก์ชันจะวนลูปอ่านสถิติของทุก Protocol จาก `metricsMap` และกระจายรวมค่าจากทุก CPU Core (`totalPackets += cpuVal.Packets`) จากนั้นส่งออกไปยัง Channel

```go
xdpLink, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.XdpMetricsProg,
    Interface: iface.Index,
})
```
- **บรรทัด 119–126**: แนบโปรแกรม XDP เข้ากับการ์ดเครือข่ายที่ระบุ (`-iface`)

```go
http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
srv.ListenAndServe()
```
- **บรรทัด 134–160**: รัน HTTP Server ให้บริการ Prometheus Scraper ที่พอร์ต `:2112`

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบและคอมไพล์โค้ด
```bash
# คอมไพล์ BPF Bytecode และสร้าง Go ไบนารี
make generate
make build
```

### ขั้นตอนที่ 2: รันโปรแกรม Exporter บน Loopback Interface
```bash
sudo ./bin/metrics_exporter -iface lo -addr :2112
```
ผลลัพธ์บนหน้าจอ:
```text
[INFO] Attached XDP metrics program to interface lo (index 1)
[INFO] Starting Prometheus metrics exporter at http://0.0.0.0:2112/metrics
```

### ขั้นตอนที่ 3: สร้างทราฟฟิกเครือข่ายเพื่อทดสอบ
เปิดหน้าต่าง Terminal ใหม่ แล้วยิงทราฟฟิกโปรโตคอลต่างๆ:

```bash
# 1. ยิง ICMP (Ping)
ping -c 5 127.0.0.1

# 2. ยิง TCP (HTTP curl)
curl -s http://localhost:2112/ > /dev/null

# 3. ยิง UDP
echo "eBPF test" | nc -u -w1 127.0.0.1 9999
```

### ขั้นตอนที่ 4: ตรวจสอบผลลัพธ์ผ่าน Prometheus Scrape Endpoint
เปิด Terminal อีกหน้าต่าง แล้วทดสอบดึง Metrics:
```bash
curl -s http://localhost:2112/metrics | grep ebpf_xdp
```
ผลลัพธ์ที่ปรากฏ:
```text
# HELP ebpf_xdp_bytes_total Total number of bytes observed by eBPF XDP hook aggregated across all CPU cores
# TYPE ebpf_xdp_bytes_total counter
ebpf_xdp_bytes_total{interface="lo",protocol="icmp"} 490
ebpf_xdp_bytes_total{interface="lo",protocol="other"} 0
ebpf_xdp_bytes_total{interface="lo",protocol="tcp"} 1642
ebpf_xdp_bytes_total{interface="lo",protocol="udp"} 94
# HELP ebpf_xdp_packets_total Total number of packets observed by eBPF XDP hook aggregated across all CPU cores
# TYPE ebpf_xdp_packets_total counter
ebpf_xdp_packets_total{interface="lo",protocol="icmp"} 5
ebpf_xdp_packets_total{interface="lo",protocol="other"} 0
ebpf_xdp_packets_total{interface="lo",protocol="tcp"} 18
ebpf_xdp_packets_total{interface="lo",protocol="udp"} 1
```

---

## 4. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **Verifier Bounds Checks** | ตรวจสอบ Ethernet และ IPv4 Header Bounds อย่างรัดกุม 100% | [x] ผ่าน |
| **High-Throughput Map** | เลือกใช้ `BPF_MAP_TYPE_PERCPU_ARRAY` เพื่อความเร็วสูงสุดไร้ Lock | [x] ผ่าน |
| **Multi-Core Aggregation** | รวบรวมสถิติจากทุก CPU Core ใน User space ได้อย่างแม่นยำ | [x] ผ่าน |
| **Prometheus Exporter** | รองรับ Standard Prometheus Collector และ Export ผ่าน `/metrics` | [x] ผ่าน |
| **Protocol Classification** | จำแนกประเภทแพ็กเก็ต TCP, UDP, ICMP, และ Other ได้ถูกต้อง | [x] ผ่าน |
| **Graceful Detach** | ปลด XDP Hook และปิด HTTP Server เมื่อได้รับสัญญาณปิดระบบ | [x] ผ่าน |
