# Week 11: Prometheus Exporter & Performance Tuning

คู่มือการศึกษาเชิงลึกเกี่ยวกับการเลือกใช้ **`BPF_MAP_TYPE_PERCPU_ARRAY`** เพื่อหลีกเลี่ยง Lock Contention ระหว่าง CPU Core (Performance Tuning ของ Map ในเส้นทางที่ร้อนที่สุดของระบบ), การรวมผลข้ามคอร์ใน User space และการสร้างระบบ Network Telemetry ส่งข้อมูลเข้าสู่ **Prometheus & Grafana** พร้อม Unit Test ด้วย `BPF_PROG_TEST_RUN`

> **ย้ายไป Week 06 แล้ว**: เนื้อหาการทำงานของ eBPF Verifier, Error ยอดนิยม, การอ่าน Verifier Log (`ebpf.VerifierError`, `bpftool -d`), แล็บ `verifier_fail/` (`make verifier-demo`) และพื้นฐาน `BPF_PROG_TEST_RUN` ถูกย้ายไปสอนตั้งแต่ **Week 06** (`phase03-modern-ebpf-core/week06-ebpf-maps` หัวข้อ 5–6) สัปดาห์นี้ถือว่าผู้เรียนอ่าน Verifier Log และเขียนเทสต์ด้วย `Program.Run()` เป็นแล้ว (ชื่อโฟลเดอร์ `week11-verifier-prometheus` คงไว้เพื่อไม่ให้ลิงก์เดิมเสีย)

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 ทบทวน: Verifier กับโปรแกรม XDP ของสัปดาห์นี้
`metrics_exporter.c` อ่าน Ethernet และ IPv4 Header จาก Packet จึงต้องมี Bounds Check (`(void *)(eth + 1) > data_end`, `(void *)(iph + 1) > data_end`) และเช็ก NULL หลัง `bpf_map_lookup_elem()` ทุกครั้ง มิฉะนั้น Verifier จะปฏิเสธด้วย `invalid access to packet` หรือ `R0 invalid mem access 'map_value_or_null'` — วิธีอ่าน Log และตัวอย่าง Log จริงบน Linux 7.0 ดู **Week 06 หัวข้อ 5**

### 1.2 ทำไม `BPF_MAP_TYPE_PERCPU_ARRAY` จึงเร็วที่สุดในงาน Telemetry
ในระบบเครือข่ายความเร็วสูงระดับ 10 Gbps ถึง 100 Gbps แพ็กเก็ตจะถูกประมวลผลบนหลาย CPU Core พร้อมๆ กัน:
- หากใช้ `BPF_MAP_TYPE_ARRAY` ทั่วไป: ทุกคอร์จะต้องแย่งกันเขียน Memory ก้อนเดียวกันผ่านคำสั่ง Atomic Lock (`LOCK XADD`) ซึ่งทำให้เกิด **Cache-line Contention / Bouncing** และ Latency สูงขึ้นอย่างมาก
- เมื่อใช้ `BPF_MAP_TYPE_PERCPU_ARRAY`: Linux Kernel จะจัดสรร Array แยกให้ทุก CPU (Possible CPU) แต่ละคอร์เขียนเฉพาะสำเนาของตัวเองโดยไม่ต้องพึ่ง Atomic Instructions ใดๆ (โปรแกรม XDP หนึ่งครั้งรันจนจบบน CPU เดียวโดยไม่ย้ายคอร์ จึงไม่มีใครเขียนช่องเดียวกันพร้อมกัน) จากนั้นฝั่ง User-space Go daemon จะทำหน้าที่รวมผล (Aggregation) ตอนที่มีการ Scrape จาก Prometheus เท่านั้น
- ข้อแลกเปลี่ยน: ใช้หน่วยความจำ `ค่า × จำนวน CPU` และค่าที่ User space อ่านได้ไม่ใช่ Snapshot ณ เวลาเดียวกันของทุกคอร์ (อ่านทีละคอร์) ซึ่งยอมรับได้สำหรับ Counter แต่ **ไม่เหมาะ** กับ State ที่ต้องตัดสินใจร่วมกันข้ามคอร์ (เช่น Rate Limit ต่อ IP ใน Week 12 ที่ต้องใช้ Map ร่วม + Atomic)

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
- **บรรทัด 21–24**: ประกาศโครงสร้างสถิติขนาด 16 ไบต์ สำหรับเก็บจำนวนแพ็กเก็ต (`packets`) และปริมาณข้อมูลรวม (`bytes`)

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct proto_metric);
    __uint(max_entries, 4);
} traffic_metrics SEC(".maps");
```
- **บรรทัด 32–37**: กำหนด Per-CPU Array แมป ชื่อ `traffic_metrics` ขนาด 4 ช่อง (0: TCP, 1: UDP, 2: ICMP, 3: Other) แยกอิสระตามแต่ละคอร์

```c
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 55–58**: Verifier Bounds Check บังคับว่าพอยน์เตอร์สิ้นสุดของ Ethernet Header (`eth + 1`) ต้องไม่เกิน `data_end` หากเกินให้ข้ามทันที

```c
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 75–78**: Bounds Check สำหรับ IPv4 Header ป้องกันการอ่านหน่วยความจำนอกขอบเขตของเคอร์เนล

```c
    struct proto_metric *metric = bpf_map_lookup_elem(&traffic_metrics, &proto_idx);
    if (metric) {
        metric->packets += 1;
        metric->bytes += (__u64)(data_end - data);
    }
```
- **บรรทัด 103–107**: ดึง Pointer ไปยังสถิติบน CPU คอร์ปัจจุบัน และอัปเดตสถิติโดยไม่ต้องมี `__sync_fetch_and_add` เพราะเป็นการเขียนบนหน่วยความจำเฉพาะคอร์ (Per-CPU Lock-free)

---

### 2.2 Go Prometheus Exporter (`main.go`)

```go
var (
    packetDesc = prometheus.NewDesc("ebpf_xdp_packets_total", ...)
    byteDesc   = prometheus.NewDesc("ebpf_xdp_bytes_total", ...)
)
```
- **บรรทัด 25–41**: ประกาศตัวแปร Metric Descriptors ตามมาตรฐาน Prometheus พร้อมใส่ Label `protocol` และ `interface`

```go
func (c *xdpCollector) Collect(ch chan<- prometheus.Metric) {
    for idx, proto := range protocolNames {
        perCPUValues := make([]bpfProtoMetric, c.numCPUs)
        c.metricsMap.Lookup(&key, &perCPUValues)
        ...
```
- **บรรทัด 68–102**: ทำงานเมื่อ Prometheus ยิง Scrape เข้ามา โดยฟังก์ชันจะวนลูปอ่านสถิติของทุก Protocol จาก `metricsMap` และกระจายรวมค่าจากทุก CPU Core (`totalPackets += cpuVal.Packets`) จากนั้นส่งออกไปยัง Channel

```go
xdpLink, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.XdpMetricsProg,
    Interface: iface.Index,
})
```
- **บรรทัด 128–131**: แนบโปรแกรม XDP เข้ากับการ์ดเครือข่ายที่ระบุ (`-iface`)

```go
http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
srv.ListenAndServe()
```
- **บรรทัด 144–175**: รัน HTTP Server ให้บริการ Prometheus Scraper ที่พอร์ต `:2112` (เปลี่ยนได้ด้วย `-addr`) และปิดอย่าง Graceful เมื่อได้รับ `SIGINT`/`SIGTERM` จากนั้น `defer` จะปลด XDP Link และปิด Map

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบและคอมไพล์โค้ด
```bash
# คอมไพล์ BPF Bytecode และสร้าง Go ไบนารี bin/metrics_exporter
make generate
make build
```

### ขั้นตอนที่ 2: รัน Unit Tests ด้วย `BPF_PROG_TEST_RUN`
```bash
make test   # = go generate + go test -exec sudo -v ./...
```
ชุดทดสอบไม่ผูก XDP เข้ากับ Interface ใดเลย แต่ป้อนแพ็กเก็ตที่สร้างขึ้นเอง (TCP/UDP/ICMP/GRE/IPv6/แพ็กเก็ตถูกตัดสั้น) ให้ `xdp_metrics_prog` ผ่าน `Program.Run()` แล้วตรวจค่าที่ออกจาก Prometheus Collector จริง (`metrics_test.go`) — หากไม่ได้รันเป็น root เทสต์จะถูก Skip (พื้นฐานของ `Program.Run()` และชนิดโปรแกรมที่ test_run ได้ ดู Week 06 หัวข้อ 6)

### ขั้นตอนที่ 3: รันโปรแกรม Exporter
วิธีที่ง่ายที่สุดคือ Loopback (`lo`):
```bash
sudo ./bin/metrics_exporter -iface lo -addr :2112
```
> **แนะนำ**: บนเครื่องที่มีผู้อื่นใช้งานร่วม ให้ทดลองบน veth ใน Network Namespace แยก (แบบเดียวกับ Week 1) เพื่อไม่ให้กระทบ `lo` หรือ NIC จริงของเครื่อง:
```bash
sudo ip netns add w11cli; sudo ip netns add w11srv
sudo ip link add w11a type veth peer name w11b
sudo ip link set w11a netns w11cli; sudo ip link set w11b netns w11srv
sudo ip -n w11cli addr add 10.211.0.1/24 dev w11a
sudo ip -n w11srv addr add 10.211.0.2/24 dev w11b
sudo ip -n w11cli link set w11a up; sudo ip -n w11srv link set w11b up
sudo ip -n w11cli link set lo up;   sudo ip -n w11srv link set lo up

sudo ip netns exec w11srv ./bin/metrics_exporter -iface w11b -addr :2112
```

### ขั้นตอนที่ 4: สร้างทราฟฟิกเครือข่ายและดึง Metrics
เปิด Terminal ใหม่ แล้วยิงทราฟฟิกโปรโตคอลต่างๆ (ตัวอย่างสำหรับ Namespace ด้านบน; หากใช้ `lo` ให้เปลี่ยนเป็น `127.0.0.1`/`localhost` และไม่ต้องใส่ `ip netns exec`):
```bash
sudo ip netns exec w11cli ping -c 5 -q 10.211.0.2                       # ICMP
sudo ip netns exec w11cli curl -s -o /dev/null http://10.211.0.2:2112/   # TCP
echo "eBPF test" | sudo ip netns exec w11cli nc -u -w1 10.211.0.2 9999   # UDP

sudo ip netns exec w11cli curl -s http://10.211.0.2:2112/metrics | grep ebpf_xdp
```
> ตัวเลขที่ได้ขึ้นกับทราฟฟิกเบื้องหลังบนเครื่องของคุณ (ARP, IPv6 Neighbor Discovery ฯลฯ จะถูกนับเป็น `other`) จึงไม่จำเป็นต้องตรงกับตัวอย่างในหัวข้อ 4

ปิดด้วย `Ctrl+C` แล้วลบ Namespace: `sudo ip netns del w11cli; sudo ip netns del w11srv`

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04.1 LTS (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), clang 21, Go 1.26, cilium/ebpf v0.16.0 — รันบน veth `w11b` ใน Namespace `w11srv` ตามขั้นตอนที่ 3

### 4.1 ผลลัพธ์ `make test`
```text
go generate ./...
go test -exec sudo -v ./...
=== RUN   TestXDPMetricsCounting
--- PASS: TestXDPMetricsCounting (0.00s)
PASS
ok  	week11-verifier-prometheus	0.007s
```
(ตัดบรรทัด `Compiled/Stripped/Wrote` ของ bpf2go ออก)

### 4.2 ผลลัพธ์การรัน Exporter และดึง Metrics
```text
$ sudo ip netns exec w11cli ping -c 5 -q 10.211.0.2
5 packets transmitted, 5 received, 0% packet loss, time 4108ms
rtt min/avg/max/mdev = 0.060/0.079/0.123/0.022 ms
$ sudo ip netns exec w11cli curl -s -o /dev/null -w "curl http_code=%{http_code}\n" http://10.211.0.2:2112/
curl http_code=200
$ echo "eBPF test" | sudo ip netns exec w11cli nc -u -w1 10.211.0.2 9999
$ sudo ip netns exec w11cli curl -s http://10.211.0.2:2112/metrics | grep ebpf_xdp
# HELP ebpf_xdp_bytes_total Total number of bytes observed by eBPF XDP hook aggregated across all CPU cores
# TYPE ebpf_xdp_bytes_total counter
ebpf_xdp_bytes_total{interface="w11b",protocol="icmp"} 490
ebpf_xdp_bytes_total{interface="w11b",protocol="other"} 362
ebpf_xdp_bytes_total{interface="w11b",protocol="tcp"} 775
ebpf_xdp_bytes_total{interface="w11b",protocol="udp"} 52
# HELP ebpf_xdp_packets_total Total number of packets observed by eBPF XDP hook aggregated across all CPU cores
# TYPE ebpf_xdp_packets_total counter
ebpf_xdp_packets_total{interface="w11b",protocol="icmp"} 5
ebpf_xdp_packets_total{interface="w11b",protocol="other"} 5
ebpf_xdp_packets_total{interface="w11b",protocol="tcp"} 9
ebpf_xdp_packets_total{interface="w11b",protocol="udp"} 1
```
Log ของ Exporter (กด `Ctrl+C` / ส่ง `SIGINT` ตอนท้าย):
```text
2026/10/28 22:06:07 [INFO] Attached XDP metrics program to interface w11b (index 1578)
2026/10/28 22:06:07 [INFO] Starting Prometheus metrics exporter at http://0.0.0.0:2112/metrics
2026/10/28 22:06:13 
[INFO] Termination signal received. Stopping HTTP server and detaching XDP...
2026/10/28 22:06:13 [INFO] Server stopped gracefully. Cleaned up.
```
- ICMP 5 แพ็กเก็ต × 98 ไบต์ = 490 ไบต์ ตรงกับ `ping -c 5` (นับเฉพาะขาเข้า `w11b` เพราะ XDP เป็น Ingress Hook)
- `other` = 5 แพ็กเก็ต คือ ARP และ IPv6 (Neighbor Discovery) ที่เกิดขึ้นเองบนลิงก์

---

## 5. ข้อจำกัดและ Threat Model (Limitations)

- **IPv4-only Classification**: แยกโปรโตคอลเฉพาะ IPv4 เท่านั้น ทราฟฟิก IPv6 ทั้งหมด (รวม TCP/UDP บน IPv6) และ VLAN-tagged Frame (`802.1Q`) จะถูกนับเป็น `other`
- **Ingress เท่านั้น**: XDP เห็นเฉพาะแพ็กเก็ตขาเข้าของ Interface ที่ผูกไว้ ต้องใช้ TC Egress (Week 8) หากต้องการนับขาออก
- **Generic vs Native XDP**: บน `lo` และ veth บางกรณี XDP ทำงานในโหมด Generic (หลังสร้าง `sk_buff` แล้ว) ประสิทธิภาพจึงต่ำกว่า Native XDP บน NIC จริงมาก — อย่านำตัวเลขประสิทธิภาพจากแล็บนี้ไปอ้างอิงกับ Production โดยไม่วัดซ้ำบนฮาร์ดแวร์จริง
- **Counter Reset**: Counter อยู่ใน Map ของโปรเซส เมื่อรีสตาร์ต Exporter ค่าจะเริ่มที่ 0 ใหม่ (Prometheus `rate()`/`increase()` จัดการ Counter Reset ได้ แต่ค่า Raw จะกระโดด)
- **ไม่ใช่ Atomic Snapshot**: การอ่าน Per-CPU Map อ่านทีละคอร์ ค่ารวมที่ได้อาจคลาดเคลื่อนเล็กน้อยระหว่างที่มีทราฟฟิกวิ่งอยู่
- **Endpoint ไม่มีการยืนยันตัวตน**: `/metrics` เปิดที่ `0.0.0.0:2112` โดยไม่มี TLS/Auth ผู้ที่เข้าถึงพอร์ตได้จะเห็นปริมาณทราฟฟิกของเครื่อง ควร Bind เฉพาะ `127.0.0.1` หรือใช้ Firewall ใน Production
- **ตัวเลขประสิทธิภาพ**: เหตุผลเรื่อง Cache-line Contention ในหัวข้อ 1.2 เป็นหลักการทั่วไป สัปดาห์นี้ไม่ได้วัดตัวเลขเปรียบเทียบ `ARRAY` vs `PERCPU_ARRAY` ไว้ (ดูแบบฝึกหัดที่ 3) — ต้องวัดเองบนฮาร์ดแวร์เป้าหมายก่อนอ้างอิง

---

## 6. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **Verifier Bounds Checks** | ตรวจสอบ Ethernet และ IPv4 Header Bounds ก่อนอ่านทุกฟิลด์ | [x] ผ่าน |
| **High-Throughput Map** | เลือกใช้ `BPF_MAP_TYPE_PERCPU_ARRAY` เพื่อหลีกเลี่ยง Atomic/Lock Contention ข้ามคอร์ | [x] ผ่าน |
| **Multi-Core Aggregation** | รวบรวมสถิติจากทุก CPU Core ใน User space ได้อย่างแม่นยำ | [x] ผ่าน |
| **Prometheus Exporter** | รองรับ Standard Prometheus Collector และ Export ผ่าน `/metrics` | [x] ผ่าน |
| **Protocol Classification** | จำแนกประเภทแพ็กเก็ต TCP, UDP, ICMP, และ Other ได้ถูกต้อง | [x] ผ่าน |
| **Graceful Detach** | ปลด XDP Hook และปิด HTTP Server เมื่อได้รับสัญญาณปิดระบบ | [x] ผ่าน |
| **Unit Tests** | `make test` ผ่าน `TestXDPMetricsCounting` (ป้อนแพ็กเก็ตปลอมด้วย `BPF_PROG_TEST_RUN` แล้วตรวจผ่าน Prometheus Collector จริง) | [x] ผ่าน |

---

## 7. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

ข้อความ Error ในตารางจับจากการรันจริงบน Linux 7.0 (การทดสอบ Port ชนกันทำใน Network Namespace แยก `w11ts`)

| อาการ / ข้อความ Error | สาเหตุ | วิธีแก้ |
| :--- | :--- | :--- |
| `Failed to remove memlock: failed to set memlock rlimit: operation not permitted` | รัน `bin/metrics_exporter` โดยไม่ใช้ `sudo` | `sudo ./bin/metrics_exporter ...` หรือ `sudo ip netns exec w11srv ...` |
| `Network interface "w11nosuch" not found: route ip+net: no such network interface` | ชื่อ `-iface` ผิด หรือ Interface อยู่คนละ Network Namespace กับที่รัน Exporter | ตรวจด้วย `ip link` (หรือ `sudo ip -n w11srv link`) แล้วรันใน Namespace เดียวกับ Interface |
| `HTTP server failed: listen tcp :2112: bind: address already in use` (หลังบรรทัด `Attached XDP ...`) | มีโปรแกรมอื่นใช้พอร์ต 2112 อยู่แล้ว (เช่น Exporter ตัวเก่าที่ยังไม่ปิด) — XDP ถูก Attach ไปก่อนแล้ว แต่จะถูกปลดเองเมื่อโปรเซสจบ | `sudo ss -ltnp 'sport = :2112'` หาโปรเซสที่ใช้พอร์ต หรือเปลี่ยนเป็น `-addr :2113` |
| `TestXDPMetricsCounting` ขึ้น `--- SKIP` | รัน `go test` โดยไม่ใช้ `sudo` | `make test` (= `go test -exec sudo -v ./...`) |
| `undefined: loadBpfObjects` ตอน `go test`/`go vet` | ยังไม่ได้ `go generate` (ไฟล์ `bpf_bpf.go` ถูก `.gitignore`) | `make generate` หรือ `make test` |
| ตัวเลขใน `/metrics` ไม่ตรงกับทราฟฟิกที่ยิง | XDP นับเฉพาะขาเข้าของ Interface ที่ผูก + มี ARP/IPv6 ND เบื้องหลัง (นับเป็น `other`) | ปกติ (ดูหัวข้อ 4.2 และข้อจำกัด) |
| โหลดโปรแกรมไม่ผ่าน `load program: permission denied: ...` หลังแก้ `metrics_exporter.c` | Verifier ปฏิเสธ (เช่นลืม Bounds Check หรือ NULL Check) | อ่าน Verifier Log ตามวิธีใน Week 06 หัวข้อ 5 |

---

## 8. แบบฝึกหัดท้ายบท (Exercises)

> แบบฝึกหัดเรื่อง Verifier (แก้ `verifier_fail` เอง, สร้างบั๊กใหม่, ARRAY vs HASH NULL Elision, ชน Instruction Limit) ย้ายไปอยู่ใน Week 06 แล้ว

### ระดับพื้นฐาน
1. **เพิ่มโปรโตคอล**: เพิ่มช่อง `PROTO_INDEX_GRE` (IP Protocol 47) ใน `traffic_metrics` และ `protocolNames`
   - **ส่งงาน**: โค้ดที่แก้ + Output ของ `/metrics` ที่มี `protocol="gre"`
   - **ตรวจสอบ**: แก้ `metrics_test.go` ให้แพ็กเก็ต GRE ถูกนับเป็น `gre` (ไม่ใช่ `other`) และ `make test` ผ่าน
2. **ปิด Endpoint จากภายนอก**: รัน Exporter ด้วย `-addr 127.0.0.1:2112` ใน Namespace `w11srv` แล้วพิสูจน์ว่าเครื่องฝั่ง `w11cli` Scrape ไม่ได้อีก แต่ภายใน `w11srv` ยังได้
   - **ส่งงาน**: Output ของ `sudo ip netns exec w11srv ss -ltn` + ผล `curl` จากทั้งสองฝั่ง
   - **ตรวจสอบ**: `curl` จาก `w11cli` ต้องล้มเหลว (connection refused) และจาก `w11srv` ต้องได้ `ebpf_xdp_packets_total`

### ระดับปานกลาง
3. **วัด ARRAY vs PERCPU_ARRAY ด้วยตัวเอง**: สร้างสำเนาของ `xdp_metrics_prog` ที่ใช้ `BPF_MAP_TYPE_ARRAY` + `__sync_fetch_and_add` แล้วเขียน Go Benchmark ที่เรียก `Program.Benchmark(pkt, repeat, nil)` (ใช้ `BPF_PROG_TEST_RUN` ที่คืนเวลาเฉลี่ยต่อรอบ) จาก Goroutine 1, 2, 4, 8 ตัวพร้อมกัน (แต่ละตัว `runtime.LockOSThread()` และ Pin คนละ CPU)
   - **ส่งงาน**: ตาราง ns/run ของทั้งสองแบบ × จำนวน Goroutine (วัดอย่างน้อย 5 รอบ, รายงานค่ากลางและช่วง) + สเปก CPU + `uname -r`
   - **ตรวจสอบ**: อธิบายผลด้วยหลัก Cache-line Contention ในหัวข้อ 1.2 — ถ้าผลไม่ต่างกันอย่างมีนัยสำคัญ ให้อธิบายว่าทำไม (เช่นทำงานบน CPU เดียว, Overhead ของ test_run กลบผล) แทนการปรับตัวเลข

### ระดับท้าทาย
4. **Packet-Size Histogram**: เพิ่ม Per-CPU Map ที่นับแพ็กเก็ตตามช่วงขนาด (เช่น ≤64, ≤128, ≤256, ≤512, ≤1024, ≤1518, >1518 ไบต์) และ Export เป็น Prometheus Histogram (`prometheus.MustNewConstHistogram`)
   - **ส่งงาน**: โค้ด C/Go + ภาพ Grafana หรือ Output `/metrics` ที่มี `_bucket{le="..."}`
   - **ตรวจสอบ**: เขียน Test ด้วย `BPF_PROG_TEST_RUN` ที่ป้อนแพ็กเก็ตหลายขนาดแล้วตรวจจำนวนในแต่ละ Bucket
5. **ต้นทุนของการ Scrape**: เพิ่ม `max_entries` ของ Map เป็น Per-Flow (เช่น `PERCPU_HASH` คีย์ 5-tuple ขนาด 10,000) แล้ววัดเวลา `Collect()` ต่อการ Scrape เทียบระหว่างการอ่านทีละ Key (`Lookup`/`Iterate`) กับ `BatchLookup`
   - **ส่งงาน**: Go Benchmark (`testing.B`) + ตารางเวลาต่อ Scrape และจำนวน `bpf()` Syscall (`strace -c -e trace=bpf`) ของทั้งสองแบบ
   - **ตรวจสอบ**: อธิบายว่าทำไม Cardinality ของ Label ใน Prometheus กับขนาดของ Map ต้องถูกจำกัดคู่กัน
