# Week 11: Production eBPF Verifier & Prometheus Telemetry Exporter

คู่มือการศึกษาเชิงลึกเกี่ยวกับกลไกการทำงานของ **eBPF Verifier**, การดีบักข้อผิดพลาดของ Verifier ในระดับ Instruction (พร้อมแล็บ **`verifier_fail/`** ที่ตั้งใจเขียนโค้ดผิดให้ Verifier ปฏิเสธ เพื่อฝึกอ่าน Verifier Log ของจริง), การเลือกใช้ **`BPF_MAP_TYPE_PERCPU_ARRAY`** เพื่อหลีกเลี่ยง Lock Contention ระหว่าง CPU Core, และการสร้างระบบ Network Telemetry ส่งข้อมูลเข้าสู่ **Prometheus & Grafana**

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

> ข้อความ Error ด้านล่างเป็นรูปแบบที่พบบ่อย แต่รายละเอียดของ Register State (เช่น `R1=pkt(r=0)`) เปลี่ยนไปตามเวอร์ชันเคอร์เนล ให้ดูตัวอย่าง Log จริงที่จับได้บน Linux 7.0 ในหัวข้อ 3 ขั้นตอนที่ 5

#### 1. `invalid access to packet, off=X size=Y, R1(id=0,off=X,r=0)`
- **สาเหตุ**: โปรแกรมพยายามอ่าน Memory ของ Packet โดยไม่มีการตรวจสอบ Bounds Check หรือตรวจสอบไม่ครอบคลุมขนาดของ Struct ที่อ่าน (`r=0` หมายถึง Verifier พิสูจน์ได้ว่าอ่านได้อย่างปลอดภัย 0 ไบต์)
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

#### 3. `R0 invalid mem access 'map_value_or_null'`
- **สาเหตุ**: นำ Pointer ที่ได้จาก `bpf_map_lookup_elem()` ไปใช้ (Dereference) โดยไม่ตรวจสอบ `NULL` ก่อน — Verifier ถือว่าผลลัพธ์อาจเป็น `NULL` เสมอ (ชนิด `map_value_or_null`)
- **วิธีแก้**: `if (!val) return XDP_PASS;` ก่อนอ่าน/เขียนผ่าน Pointer
- **ข้อสังเกต**: เคอร์เนลรุ่นใหม่ (ทดสอบแล้วบน Linux 7.0) สามารถพิสูจน์ได้ว่าการ Lookup ใน `ARRAY`/`PERCPU_ARRAY` ด้วย Key ที่เป็นค่าคงที่และอยู่ในช่วง `max_entries` จะไม่มีวันเป็น `NULL` จึงยอม **ผ่าน** โค้ดที่ลืมเช็ก NULL ในกรณีนั้น แต่สำหรับ `HASH` Map จะถูกปฏิเสธเสมอ — อย่าพึ่งพฤติกรรมนี้ ให้เช็ก NULL ทุกครั้ง

#### 4. ลูปที่ Verifier พิสูจน์ไม่ได้ว่าจะจบ
- **สาเหตุ**: ตั้งแต่ Linux 5.3 Verifier รองรับ Bounded Loop แล้ว แต่ถ้าพิสูจน์ไม่ได้ว่าลูปจะจบ จะได้ข้อความประเภท `infinite loop detected at insn X` หรือ `BPF program is too large. Processed 1000001 insn` (ข้อความ `back-edge from insn X to Y` จะพบในเคอร์เนลเก่ากว่า 5.3 หรือกรณีโหลดแบบ Unprivileged)
- **วิธีแก้**: ใช้ขอบเขตลูปเป็นค่าคงที่ขนาดเล็ก (เช่น `for (int i = 0; i < 10; i++)`), ใช้ `#pragma unroll` หรือ Helper `bpf_loop()` (Linux 5.17+)

### 1.3 การอ่าน Verifier Log จาก Go (`ebpf.VerifierError`) และ `bpftool`
เมื่อโหลดโปรแกรมไม่ผ่าน cilium/ebpf จะคืน Error ชนิด `*ebpf.VerifierError` ซึ่งเก็บ Log ของ Verifier ไว้ทีละบรรทัด (`ve.Log`) วิธีพิมพ์ออกมาอ่าน:
```go
var ve *ebpf.VerifierError
if errors.As(err, &ve) {
    fmt.Printf("%+v\n", ve)    // พิมพ์ Log ทั้งหมด
    fmt.Printf("%-20v\n", ve)  // พิมพ์เฉพาะ 20 บรรทัดสุดท้าย (จุดที่ Error มักอยู่)
}
```
> หากพิมพ์ด้วย `%v` หรือ `%s` ธรรมดา จะได้แค่บรรทัดสรุปสั้นๆ ไม่มี Trace ของ Register

วิธีอ่าน Log ทีละบรรทัด (ตัวอย่างจริงจากแล็บ `verifier_fail -case bounds`):
```text
0: (61) r1 = *(u32 *)(r1 +0)          ; R1=pkt(r=0)
1: (71) r2 = *(u8 *)(r1 +12)
invalid access to packet, off=12 size=1, R1(id=0,off=12,r=0)
```
- `0:` คือหมายเลข Instruction, `(61)` คือ Opcode, ส่วนหลัง `;` คือ State ของ Register **หลัง** รันคำสั่งนั้น
- `R1=pkt(r=0)` = R1 เป็น Pointer ชี้เข้า Packet แต่ช่วงที่พิสูจน์แล้วว่าอ่านได้ (`r=`) คือ 0 ไบต์ เพราะยังไม่มีการเทียบกับ `data_end`
- บรรทัดสุดท้ายก่อนสถิติคือ **สาเหตุ** ที่ถูกปฏิเสธ — การอ่านไบต์ที่ offset 12 (`h_proto`) ทั้งที่ `r=0`
- บรรทัด `; ... @ verifier_fail.c:48` คือ Source Line ที่ได้จาก BTF (ต้องคอมไพล์ด้วย `-g` ซึ่ง bpf2go ใส่ให้อัตโนมัติ)

ทางเลือกด้วย `bpftool`: เปิด Debug Output ของ libbpf ด้วย `-d` แล้ว libbpf จะพิมพ์ Verifier Log ระหว่าง `-- BEGIN PROG LOAD LOG --` ... `-- END PROG LOAD LOG --` เมื่อโหลดไม่ผ่าน (bpftool โหลดทุกโปรแกรมในไฟล์ `.o` จึงหยุดที่โปรแกรมแรกที่ไม่ผ่าน ในที่นี้คือ `xdp_no_bounds_check`):
```bash
sudo bpftool -d prog load verifier_fail/bpf_bpf.o /sys/fs/bpf/vf_test
sudo rm -f /sys/fs/bpf/vf_test   # ลบ Pin ทิ้ง (กรณีโหลดผ่าน)
```

### 1.4 ทำไม `BPF_MAP_TYPE_PERCPU_ARRAY` จึงเร็วที่สุดในงาน Telemetry
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

### 2.3 แล็บ Verifier ล้มเหลวโดยตั้งใจ (`verifier_fail/`)

ไฟล์ `verifier_fail/verifier_fail.c` มีโปรแกรม XDP 3 ตัว ซึ่ง **clang คอมไพล์ผ่านทั้งหมดโดยไม่มี Warning** — บั๊กจะถูกพบตอนเคอร์เนลรัน Verifier ระหว่าง `BPF_PROG_LOAD` เท่านั้น:

| `-case` | โปรแกรม | บั๊กที่ใส่ไว้ | ผลลัพธ์ที่คาดหวัง |
| :--- | :--- | :--- | :--- |
| `bounds` | `xdp_no_bounds_check` (บรรทัด 41–52) | อ่าน `eth->h_proto` โดยไม่เทียบ `data_end` | `invalid access to packet` |
| `nullcheck` | `xdp_no_null_check` (บรรทัด 58–68) | ใช้ผลของ `bpf_map_lookup_elem()` บน `HASH` Map โดยไม่เช็ก NULL | `R0 invalid mem access 'map_value_or_null'` |
| `fixed` | `xdp_fixed` (บรรทัด 71–95) | แก้ทั้งสองจุดแล้ว | โหลดผ่าน พร้อมสถิติ `processed N insns` |

```go
spec.Programs = map[string]*ebpf.ProgramSpec{progName: spec.Programs[progName]}
return ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: opts})
```
- **`verifier_fail/main.go` บรรทัด 31–42**: โหลด **เฉพาะโปรแกรมที่เลือก** (พร้อม Map ที่มันอ้างถึง) เพราะถ้าโหลดทั้ง Collection จะหยุดที่โปรแกรมแรกที่ไม่ผ่าน

```go
opts := ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats}
...
var ve *ebpf.VerifierError
if errors.As(err, &ve) {
    fmt.Printf("%+v\n", ve)
}
```
- **บรรทัด 59–83**: ขอ Verifier Log ระดับ Instruction ตั้งแต่ครั้งแรก (`LogLevelBranch`) พร้อมสถิติ (`LogLevelStats`) จากนั้นแยก `*ebpf.VerifierError` ด้วย `errors.As` และพิมพ์ด้วย `%+v` (หรือ `%-Nv` เมื่อใช้ `-lines N` เพื่อดูเฉพาะ N บรรทัดสุดท้าย) ส่วนกรณี `fixed` จะพิมพ์ `prog.VerifierLog` ซึ่งมีเฉพาะสถิติ

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบและคอมไพล์โค้ด
```bash
# คอมไพล์ BPF Bytecode และสร้าง Go ไบนารี (bin/metrics_exporter และ bin/verifier_fail)
make generate
make build
```

### ขั้นตอนที่ 2: รัน Unit Tests ด้วย `BPF_PROG_TEST_RUN`
```bash
make test   # = go generate + go test -exec sudo -v ./...
```
ชุดทดสอบไม่ผูก XDP เข้ากับ Interface ใดเลย แต่ป้อนแพ็กเก็ตที่สร้างขึ้นเอง (TCP/UDP/ICMP/GRE/IPv6/แพ็กเก็ตถูกตัดสั้น) ให้ `xdp_metrics_prog` ผ่าน `Program.Run()` แล้วตรวจค่าที่ออกจาก Prometheus Collector จริง (`metrics_test.go`) และตรวจว่าโปรแกรมใน `verifier_fail/` ถูก Verifier ปฏิเสธด้วยข้อความที่คาดไว้ (`verifier_fail/main_test.go`) — หากไม่ได้รันเป็น root เทสต์จะถูก Skip

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

### ขั้นตอนที่ 5: ฝึกอ่าน Verifier Log จริง
```bash
make verifier-demo
# หรือรันทีละกรณี
sudo ./bin/verifier_fail -case bounds
sudo ./bin/verifier_fail -case nullcheck
sudo ./bin/verifier_fail -case nullcheck -lines 3   # ดูเฉพาะ 3 บรรทัดสุดท้าย
sudo ./bin/verifier_fail -case fixed
```
กรณีที่ถูกปฏิเสธจะจบด้วย Exit Code 1 (`make verifier-demo` ตั้งให้ข้าม Error นี้) ผลลัพธ์จริงดูได้ในหัวข้อ 4.3

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
=== RUN   TestVerifierRejectsBrokenPrograms
=== RUN   TestVerifierRejectsBrokenPrograms/bounds
=== RUN   TestVerifierRejectsBrokenPrograms/nullcheck
=== RUN   TestVerifierRejectsBrokenPrograms/fixed
--- PASS: TestVerifierRejectsBrokenPrograms (0.00s)
    --- PASS: TestVerifierRejectsBrokenPrograms/bounds (0.00s)
    --- PASS: TestVerifierRejectsBrokenPrograms/nullcheck (0.00s)
    --- PASS: TestVerifierRejectsBrokenPrograms/fixed (0.00s)
PASS
ok  	week11-verifier-prometheus/verifier_fail	0.006s
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

### 4.3 ผลลัพธ์ `make verifier-demo` (Verifier Log จริง)
```text
sudo ./bin/verifier_fail -case bounds
[VERIFIER] program "xdp_no_bounds_check" REJECTED
load program: permission denied:
	0: R1=ctx() R10=fp0
	; void *data = (void *)(long)ctx->data; @ verifier_fail.c:44
	0: (61) r1 = *(u32 *)(r1 +0)          ; R1=pkt(r=0)
	; if (eth->h_proto != bpf_htons(ETH_P_IP)) @ verifier_fail.c:48
	1: (71) r2 = *(u8 *)(r1 +12)
	invalid access to packet, off=12 size=1, R1(id=0,off=12,r=0)
	R1 offset is outside of the packet
	verification time 27 usec
	stack depth 0
	processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
make: [Makefile:22: verifier-demo] Error 1 (ignored)
sudo ./bin/verifier_fail -case nullcheck
[VERIFIER] program "xdp_no_null_check" REJECTED
load program: permission denied:
	0: R1=ctx() R10=fp0
	; __u32 key = ctx->ingress_ifindex; @ verifier_fail.c:61
	0: (61) r1 = *(u32 *)(r1 +12)         ; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
	1: (63) *(u32 *)(r10 -4) = r1         ; R1=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R10=fp0 fp-8=mmmm????
	2: (bf) r2 = r10                      ; R2=fp0 R10=fp0
	3: (07) r2 += -4                      ; R2=fp-4
	; __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); @ verifier_fail.c:62
	4: (18) r1 = 0xffff8be22e507c00       ; R1=map_ptr(map=pkt_count,ks=4,vs=8)
	6: (85) call bpf_map_lookup_elem#1    ; R0=map_value_or_null(id=1,map=pkt_count,ks=4,vs=8)
	7: (b7) r1 = 1                        ; R1=1
	; __sync_fetch_and_add(count, 1); @ verifier_fail.c:65
	8: (db) lock *(u64 *)(r0 +0) += r1
	R0 invalid mem access 'map_value_or_null'
	verification time 35 usec
	stack depth 8
	processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
make: [Makefile:23: verifier-demo] Error 1 (ignored)
sudo ./bin/verifier_fail -case fixed
[VERIFIER] program "xdp_fixed" ACCEPTED
verification time 40 usec
stack depth 16
processed 37 insns (limit 1000000) max_states_per_insn 0 total_states 3 peak_states 3 mark_read 0
```
ข้อสังเกตจาก Log จริง:
- **กรณี `bounds`**: clang แปลง `eth->h_proto != bpf_htons(ETH_P_IP)` เป็นการอ่านทีละ 1 ไบต์ (`size=1`) ไม่ใช่ 2 ไบต์ตามที่คาดจากซอร์ส — นี่คือเหตุผลที่ต้องอ่าน Log ระดับ Instruction ไม่ใช่เดาจาก C
- **กรณี `nullcheck`**: ไล่ดูชนิดของ `R0` หลัง `call bpf_map_lookup_elem#1` จะเป็น `map_value_or_null` แล้วคำสั่งที่ 8 ใช้ R0 ทันทีโดยไม่มี `if r0 == 0 goto ...` คั่น
- **กรณี `fixed`**: Verifier ตรวจ 37 Instructions (นับรวมทุก Path ที่จำลอง) — `processed` ที่สูงมากเป็นสัญญาณว่าโปรแกรมใกล้ชนเพดาน 1,000,000 Instructions
- ค่า `r1 = 0xffff...` ในคำสั่งที่ 4 คือ Address ของ Map ในเคอร์เนล จะเปลี่ยนทุกครั้งที่โหลด

---

## 5. ข้อจำกัดและ Threat Model (Limitations)

- **IPv4-only Classification**: แยกโปรโตคอลเฉพาะ IPv4 เท่านั้น ทราฟฟิก IPv6 ทั้งหมด (รวม TCP/UDP บน IPv6) และ VLAN-tagged Frame (`802.1Q`) จะถูกนับเป็น `other`
- **Ingress เท่านั้น**: XDP เห็นเฉพาะแพ็กเก็ตขาเข้าของ Interface ที่ผูกไว้ ต้องใช้ TC Egress (Week 8) หากต้องการนับขาออก
- **Generic vs Native XDP**: บน `lo` และ veth บางกรณี XDP ทำงานในโหมด Generic (หลังสร้าง `sk_buff` แล้ว) ประสิทธิภาพจึงต่ำกว่า Native XDP บน NIC จริงมาก — อย่านำตัวเลขประสิทธิภาพจากแล็บนี้ไปอ้างอิงกับ Production โดยไม่วัดซ้ำบนฮาร์ดแวร์จริง
- **Counter Reset**: Counter อยู่ใน Map ของโปรเซส เมื่อรีสตาร์ต Exporter ค่าจะเริ่มที่ 0 ใหม่ (Prometheus `rate()`/`increase()` จัดการ Counter Reset ได้ แต่ค่า Raw จะกระโดด)
- **ไม่ใช่ Atomic Snapshot**: การอ่าน Per-CPU Map อ่านทีละคอร์ ค่ารวมที่ได้อาจคลาดเคลื่อนเล็กน้อยระหว่างที่มีทราฟฟิกวิ่งอยู่
- **Endpoint ไม่มีการยืนยันตัวตน**: `/metrics` เปิดที่ `0.0.0.0:2112` โดยไม่มี TLS/Auth ผู้ที่เข้าถึงพอร์ตได้จะเห็นปริมาณทราฟฟิกของเครื่อง ควร Bind เฉพาะ `127.0.0.1` หรือใช้ Firewall ใน Production
- **Verifier Log ขึ้นกับเวอร์ชันเคอร์เนล**: รูปแบบ Register State, ข้อความ Error และความสามารถของ Verifier (เช่นการยอมรับ ARRAY Lookup โดยไม่เช็ก NULL ในหัวข้อ 1.2) เปลี่ยนไปตามเวอร์ชัน Log ในหัวข้อ 4.3 จับจาก Linux 7.0 เท่านั้น

---

## 6. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **Verifier Bounds Checks** | ตรวจสอบ Ethernet และ IPv4 Header Bounds ก่อนอ่านทุกฟิลด์ | [x] ผ่าน |
| **Verifier Log Reading** | โหลด `verifier_fail` ทั้ง 3 กรณี และอธิบายบรรทัดที่เป็นสาเหตุใน Log ได้ | [x] ผ่าน |
| **High-Throughput Map** | เลือกใช้ `BPF_MAP_TYPE_PERCPU_ARRAY` เพื่อหลีกเลี่ยง Atomic/Lock Contention ข้ามคอร์ | [x] ผ่าน |
| **Multi-Core Aggregation** | รวบรวมสถิติจากทุก CPU Core ใน User space ได้อย่างแม่นยำ | [x] ผ่าน |
| **Prometheus Exporter** | รองรับ Standard Prometheus Collector และ Export ผ่าน `/metrics` | [x] ผ่าน |
| **Protocol Classification** | จำแนกประเภทแพ็กเก็ต TCP, UDP, ICMP, และ Other ได้ถูกต้อง | [x] ผ่าน |
| **Graceful Detach** | ปลด XDP Hook และปิด HTTP Server เมื่อได้รับสัญญาณปิดระบบ | [x] ผ่าน |
| **Unit Tests** | `make test` ผ่านทั้ง `TestXDPMetricsCounting` และ `TestVerifierRejectsBrokenPrograms` | [x] ผ่าน |

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **อ่าน Log แล้วแก้เอง**: แก้ `xdp_no_bounds_check` ใน `verifier_fail/verifier_fail.c` ให้โหลดผ่านโดยเพิ่ม Bounds Check เพียงบรรทัดเดียว
   - **ส่งงาน**: Diff ของไฟล์ + ผลลัพธ์ `sudo ./bin/verifier_fail -case bounds` ที่ขึ้น `ACCEPTED`
   - **ตรวจสอบ**: `make test` จะ **FAIL** ที่ `TestVerifierRejectsBrokenPrograms/bounds` (เพราะเทสต์คาดว่าโปรแกรมต้องถูกปฏิเสธ) — อธิบายว่าทำไมนี่คือพฤติกรรมที่ถูกต้องของเทสต์ แล้ว Revert กลับ
2. **เพิ่มโปรโตคอล**: เพิ่มช่อง `PROTO_INDEX_GRE` (IP Protocol 47) ใน `traffic_metrics` และ `protocolNames`
   - **ส่งงาน**: โค้ดที่แก้ + Output ของ `/metrics` ที่มี `protocol="gre"`
   - **ตรวจสอบ**: แก้ `metrics_test.go` ให้แพ็กเก็ต GRE ถูกนับเป็น `gre` (ไม่ใช่ `other`) และ `make test` ผ่าน

### ระดับปานกลาง
1. **บั๊กใหม่ของคุณเอง**: เพิ่มกรณีที่ 4 ใน `verifier_fail` เช่น อ่าน TCP Header โดยคำนวณ Offset จาก `iph->ihl * 4` แต่ไม่เช็ก `data_end` หลังบวก Offset
   - **ส่งงาน**: โปรแกรม C + Entry ใหม่ใน `cases` + Verifier Log จริงพร้อมคำอธิบายว่าบรรทัดไหนบอกสาเหตุ
   - **ตรวจสอบ**: เพิ่มกรณีใน `TestVerifierRejectsBrokenPrograms` ที่ตรวจข้อความ Error ของคุณ และ `make test` ผ่าน
2. **ARRAY vs HASH NULL Elision**: เปลี่ยน `pkt_count` ใน `verifier_fail.c` เป็น `BPF_MAP_TYPE_ARRAY` และใช้ Key คงที่ `0` แล้วรัน `-case nullcheck`
   - **ส่งงาน**: ผลลัพธ์จริงบนเครื่องของคุณ (ACCEPTED หรือ REJECTED) + ระบุเวอร์ชันเคอร์เนล (`uname -r`) + อธิบายว่าทำไมผลอาจต่างกันบนเคอร์เนลรุ่นเก่า
   - **ตรวจสอบ**: เทียบชนิดของ `R0` หลัง `call bpf_map_lookup_elem` ใน Log ระหว่างสองแบบ (`map_value` vs `map_value_or_null`)

### ระดับท้าทาย
1. **Packet-Size Histogram**: เพิ่ม Per-CPU Map ที่นับแพ็กเก็ตตามช่วงขนาด (เช่น ≤64, ≤128, ≤256, ≤512, ≤1024, ≤1518, >1518 ไบต์) และ Export เป็น Prometheus Histogram (`prometheus.MustNewConstHistogram`)
   - **ส่งงาน**: โค้ด C/Go + ภาพ Grafana หรือ Output `/metrics` ที่มี `_bucket{le="..."}`
   - **ตรวจสอบ**: เขียน Test ด้วย `BPF_PROG_TEST_RUN` ที่ป้อนแพ็กเก็ตหลายขนาดแล้วตรวจจำนวนในแต่ละ Bucket
2. **ชน Instruction Limit**: เขียนโปรแกรมที่วนลูปโดยใช้ขอบเขตเป็นค่า `__u32` ที่อ่านจาก Packet (ไม่มีขอบเขตบนที่ Verifier พิสูจน์ได้) แล้วสังเกตว่า Verifier ตอบอย่างไร จากนั้นเปรียบเทียบกับการใช้ขอบเขตเป็น `__u8` (สูงสุด 255 รอบ), ขอบเขตคงที่ และ `bpf_loop()`
   - **ส่งงาน**: Log ก่อน/หลังแก้ (ใช้ `-lines 20`) + ค่า `processed N insns` ของเวอร์ชันที่ผ่าน
   - **ตรวจสอบ**: อธิบายความสัมพันธ์ระหว่างจำนวน Path ที่ Verifier ต้องจำลองกับค่า `processed` และ `total_states`
