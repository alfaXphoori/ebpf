# Week 12 Capstone: Smart eBPF XDP Intrusion Prevention System (IPS)

โปรเจกต์ Capstone ระดับโปรดักชัน: ระบบป้องกันการบุกรุกและยับยั้งการโจมตี DoS/DDoS อัจฉริยะ (**Smart Intrusion Prevention System**) บนสถาปัตยกรรม **eBPF XDP Data-Plane** ร่วมกับ **Go Daemon Control-Plane**, ระบบ Real-time Alerting ด้วย Ring Buffer, อัตโนมัติ Auto-Ban / Auto-Unban (TTL), REST API สำหรับบริหารจัดการ และ Prometheus Telemetry Exporter

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 สถาปัตยกรรม Smart IPS: การทำงานระหว่าง Data Plane และ Control Plane
ในระบบเครือข่ายความเร็วสูง การหยุดยั้งการโจมตีแบบ DoS/DDoS ต้องทำตั้งแต่จุดที่เร็วที่สุดเท่าที่จะเป็นไปได้ ก่อนที่แพ็กเก็ตจะถูกส่งต่อเข้าสู่ Kernel Network Stack ปกติ

```
+-----------------------------------------------------------------------------------------+
|                สถาปัตยกรรม SMART EBPF IPS (DATA PLANE vs CONTROL PLANE)                 |
|                                                                                         |
|       [ Ingress Packets (NIC Driver) ]                                                  |
|                      |                                                                  |
|                      v                                                                  |
|     +-------------------------------------------------------------+                     |
|     | DATA PLANE: eBPF XDP Driver Hook (ips_kern.c)               |                     |
|     |                                                             |                     |
|     | 1. Bounds Check: eth + iph + tcph/icmph                     |                     |
|     | 2. ตรวจสอบ Blacklist Map (LRU Hash)                         |                     |
|     |    - ถ้าพบ IP: เพิ่มสถิติ Drop -> คืนค่า XDP_DROP ทันที!    |                     |
|     | 3. ตรวจสอบประเภทแพ็กเก็ต: TCP SYN หรือ ICMP Echo             |                     |
|     | 4. ติดตาม Sliding Rate Window (rate_tracker Map)            |                     |
|     |    - ถ้า SYN > 100 pps หรือ ICMP > 50 pps:                  |                     |
|     |      * Auto-Ban: ใส่ IP ลง blacklist_map โดยตรง             |                     |
|     |      * สตรีมแจ้งเตือนลง ips_events (Ring Buffer)           |                     |
|     |      * คืนค่า XDP_DROP                                      |                     |
|     | 5. ทราฟฟิกปกติ: คืนค่า XDP_PASS                             |                     |
|     +-------------------------------------------------------------+                     |
|            |                                              ^                             |
|            | Ring Buffer Events (ips_events)              | BPF Map Operations          |
|            v                                              | (Blacklist / Config)        |
|     +-------------------------------------------------------------+                     |
|     | CONTROL PLANE: Go Daemon Agent (cmd/ips-agent)              |                     |
|     |                                                             |                     |
|     | [Ringbuf Consumer]  <-- อ่าน Event แจ้งเตือนแบบ Real-time   |                     |
|     | [TTL Ban Manager]   --> ตรวจสอบเวลา และปลดแบน IP อัตโนมัติ  |                     |
|     | [Prometheus Server] --> ให้บริการสถิติที่ :2112/metrics     |                     |
|     | [REST API Server]   --> CRUD จัดการ Blacklist IP            |                     |
|     +-------------------------------------------------------------+                     |
+-----------------------------------------------------------------------------------------+
```

### 1.2 การเปรียบเทียบประสิทธิภาพ: XDP vs Iptables / Nftables
เมื่อเซิร์ฟเวอร์ตกอยู่ภายใต้การโจมตีแบบ SYN Flood หรือ Ping Flood ระดับหลายล้านแพ็กเก็ตต่อวินาที:
- **Iptables / Nftables**: แพ็กเก็ตทุกตัวจะต้องผ่านการจัดสรรหน่วยความจำ `sk_buff` (Socket Buffer) ในเคอร์เนล ซึ่งกินเวลาและ CPU สูงมาก แม้กฎ Iptables จะสั่ง `DROP` แต่เคอร์เนลก็เกิดอาการ CPU SoftIRQ เต็ม 100% จนเครื่องดับหรือหยุดตอบสนอง
- **eBPF XDP (eXpress Data Path)**: ทำงานที่ระดับ RX Ring Buffer ของ Network Interface Card (NIC Driver) ก่อนที่เคอร์เนลจะสร้าง `sk_buff` เมื่อคืนค่า `XDP_DROP` แพ็กเก็ตจะถูกทิ้งในระดับฮาร์ดแวร์/ไดรเวอร์ทันที ทำให้เครื่องสามารถทนทานต่อการโจมตีกว่า 10,000,000+ Packets Per Second (PPS)

### 1.3 พฤติกรรมการโจมตีที่ระบบตรวจจับ
1. **TCP SYN Flood**: ผู้โจมตีส่งแพ็กเก็ต TCP ที่มีแฟลก `SYN=1, ACK=0` ถี่ยิบ เพื่อเติมเต็มคิว Connection Backlog ของเซิร์ฟเวอร์จนระบบไม่สามารถรับการเชื่อมต่อจากผู้ใช้ปกติได้
2. **ICMP Echo Flood**: การระดมยิงแพ็กเก็ต Ping ขนาดใหญ่และรวดเร็ว เพื่อเผาผลาญ Bandwidth เครือข่ายและรบกวนการประมวลผล Interrupt ของ CPU

### 1.4 โครงสร้าง Maps ทั้ง 5 ตัวใน eBPF IPS
1. **`blacklist_map` (`BPF_MAP_TYPE_LRU_HASH`)**: เก็บรายชื่อ IP ที่ถูกบล็อก (ขนาด 65,536 entries) พร้อมสถิติจำนวนแพ็กเก็ตและขนาดไบต์ที่ถูกทิ้ง โดยใช้ LRU (Least Recently Used) ป้องกันหน่วยความจำเคอร์เนลเต็ม
2. **`rate_tracker` (`BPF_MAP_TYPE_LRU_HASH`)**: ติดตามอัตราเร็วของแพ็กเก็ตต่อ IP ในแต่ละหน้าต่างเวลา 1 วินาที
3. **`ips_metrics` (`BPF_MAP_TYPE_PERCPU_ARRAY`)**: เก็บข้อมูล Telemetry 4 สล็อต (Passed, Dropped Blacklist, Dropped Rate-Limit, Total Bytes) แบบ Per-CPU คอร์ ไร้ Lock Contention
4. **`ips_events` (`BPF_MAP_TYPE_RINGBUF`)**: สตรีม Alert ไปยัง Go Daemon ด้วยขนาด 4MB
5. **`config_map` (`BPF_MAP_TYPE_ARRAY`)**: อนุญาตให้ Go Daemon ปรับเปลี่ยนค่าขีดจำกัด (Thresholds) ได้แบบ Dynamic ขณะระบบกำลังทำงาน

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 eBPF Kernel Program (`bpf/ips_kern.c`)

```c
struct block_entry {
    __u64 blocked_at_ns;
    __u64 drop_count;
    __u64 drop_bytes;
    __u32 reason;
    __u32 pad;
};
```
- **บรรทัด 31–37**: โครงสร้าง Value ของ `blacklist_map` เก็บเวลาที่ถูกบล็อก, สถิติจำนวนแพ็กเก็ตที่ถูกทิ้ง, ปริมาณไบต์, และรหัสสาเหตุ (SYN Flood, ICMP Flood หรือ Manual Ban)

```c
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
```
- **บรรทัด 106–109**: การตรวจสอบขอบเขต Ethernet Header ก่อนเข้าถึงหน่วยความจำ

```c
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
    if ((void *)iph + ip_hdr_len > data_end) return XDP_PASS;
```
- **บรรทัด 118–127**: ตรวจสอบขอบเขตของ IPv4 Header และคำนวณความยาว Variable Header Length (`ihl * 4`) อย่างเข้มงวดตามมาตรฐาน eBPF Verifier

```c
    struct block_entry *b_entry = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (b_entry) {
        b_entry->drop_count++;
        b_entry->drop_bytes += pkt_len;
        inc_metric(METRIC_DROPPED_BLACKLIST, 1);
        return XDP_DROP;
    }
```
- **บรรทัด 134–141**: ตรวจสอบว่า IP ต้นทางอยู่ใน Blacklist หรือไม่ หากพบ ให้อัปเดตสถิติและสั่ง `XDP_DROP` ทิ้งแพ็กเก็ตทันทีในหลัก Nanoseconds

```c
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;
        if (tcph->syn && !tcph->ack) is_syn = 1;
    }
```
- **บรรทัด 149–157**: สกัด Header ของ TCP และตรวจสอบสถานะแฟลก `SYN=1` และ `ACK=0` ซึ่งเป็นลักษณะของแพ็กเก็ตเริ่มต้นการเชื่อมต่อ

```c
    if (now - r_state->window_start_ns > window_ns) {
        r_state->window_start_ns = now;
        r_state->syn_count = 0;
        r_state->icmp_count = 0;
    }
```
- **บรรทัด 205–209**: รีเซ็ต Sliding Window ทุกๆ 1 วินาที (`1,000,000,000 ns`) เพื่อคำนวณอัตรา Packets Per Second (PPS)

```c
    if (violation_reason != 0) {
        bpf_map_update_elem(&blacklist_map, &src_ip, &new_ban, BPF_ANY);
        struct ips_alert *alert = bpf_ringbuf_reserve(&ips_events, sizeof(*alert), 0);
        if (alert) {
            ...
            bpf_ringbuf_submit(alert, 0);
        }
        return XDP_DROP;
    }
```
- **บรรทัด 229–254**: เมื่อพบการส่งแพ็กเก็ตเกินขีดจำกัด โปรแกรม eBPF จะสั่ง **Auto-Ban** นำ IP เข้า `blacklist_map` ทันที และส่ง Notification ผ่าน Ring Buffer ไปยัง Go Daemon แล้วสั่ง `XDP_DROP`

---

### 2.2 Go Control Plane Agent (`cmd/ips-agent/main.go`)

```go
type BanManager struct {
    mu           sync.RWMutex
    bannedTimes  map[uint32]time.Time
    blacklistMap *ebpf.Map
    ttl          time.Duration
}
```
- **บรรทัด 95–101**: ตัวจัดการ Blacklist ในฝั่ง User-space ทำหน้าที่ติดตามอายุของแต่ละ IP ที่ถูกสั่งแบน

```go
func (bm *BanManager) RunEvictionTicker(ctx context.Context) {
    ticker := time.NewTicker(2 * time.Second)
    for {
        select {
        case <-ticker.C:
            ...
            if now.Sub(banTime) >= bm.ttl {
                bm.blacklistMap.Delete(&ip)
            }
```
- **บรรทัด 150–178**: Background Goroutine ตรวจสอบ IP ที่ถูกบล็อกเกินระยะเวลา TTL (เช่น 30 วินาที) และทำการลบ IP ออกจาก eBPF Blacklist Map โดยอัตโนมัติ

```go
go func() {
    var alert ipsAlert
    for {
        record, err := rd.Read()
        binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &alert)
        ...
```
- **บรรทัด 278–315**: Ring Buffer Consumer ดึงเหตุการณ์การตรวจจับการบุกรุกมาพิมพ์แจ้งเตือนบนหน้าจออย่างละเอียด

```go
mux.HandleFunc("/api/blacklist", func(w http.ResponseWriter, r *http.Request) { ... })
```
- **บรรทัด 337–393**: REST API รองรับคำสั่ง:
  - `GET /api/blacklist`: ดูรายชื่อ IP ที่กำลังถูกบล็อกทั้งหมด
  - `POST /api/blacklist`: สั่งแบน IP แบบ Manual
  - `DELETE /api/blacklist?ip=x.x.x.x`: สั่งปลดแบน IP ทันที

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์โปรเจกต์ Capstone
```bash
# คอมไพล์ eBPF C program และสร้างไบนารี Go Agent
make generate
make build
```
ไฟล์ไบนารีจะถูกสร้างขึ้นที่ `bin/ips-agent`

### ขั้นตอนที่ 2: รัน Smart IPS Daemon
```bash
# รันโดยผูกเข้ากับ Loopback interface พร้อมตั้งเวลาปลดแบนอัตโนมัติ 30 วินาที
sudo ./bin/ips-agent -iface lo -ban-ttl 30s -syn-limit 100 -icmp-limit 50
```
ผลลัพธ์บนคอนโซล:
```text
[CONFIG] SYN Limit=100 pps, ICMP Limit=50 pps, Window=1s, Auto-Ban TTL=30s
[INFO] Smart IPS attached to interface lo (index 1)
[INFO] Smart IPS Daemon active! Web/API running at http://0.0.0.0:2112
```

### ขั้นตอนที่ 3: ทดสอบการจำลอง Ping Flood (ICMP Echo Violation)
เปิด Terminal ใหม่ และจำลองการยิง Ping แบบรวดเร็วเกินขีดจำกัด (50 pps):
```bash
# ยิง Ping 200 ครั้งแบบ Flood (-f)
sudo ping -f -c 200 127.0.0.1
```
ในหน้าต่างของ `ips-agent` จะตรวจพบและทำการ Auto-Ban ทันที:
```text
[IPS ALERT] ICMP_FLOOD  | Proto=ICMP | Src=127.0.0.1:0 -> Dst=127.0.0.1:0 | Rate=51 PPS | Action=AUTO-BANNED
```

### ขั้นตอนที่ 4: ตรวจสอบ Blacklist ผ่าน REST API
เปิด Terminal อื่นและส่งคำสั่งเรียกดูสถานะ:
```bash
curl -s http://localhost:2112/api/blacklist | jq .
```
ผลลัพธ์ JSON:
```json
[
  {
    "ip": "127.0.0.1",
    "drop_count": 149,
    "drop_bytes": 12516,
    "reason": "ICMP_FLOOD"
  }
]
```

### ขั้นตอนที่ 5: ตรวจสอบการปลดแบนอัตโนมัติ (Auto-Unban TTL)
รอประมาณ 30 วินาที จะพบข้อความแจ้งการปลดแบนอัตโนมัติในคอนโซลของ Agent:
```text
[IPS UNBAN] IP 127.0.0.1 unbanned after 30s TTL expiration
```
และเมื่อทดสอบ Ping อีกครั้ง การเชื่อมต่อจะกลับมาใช้งานได้ตามปกติ

### ขั้นตอนที่ 6: ตรวจสอบ Telemetry ผ่าน Prometheus Endpoint
```bash
curl -s http://localhost:2112/metrics | grep ips_
```
ผลลัพธ์:
```text
# HELP ips_active_blacklisted_ips Current number of active blacklisted IP addresses
# TYPE ips_active_blacklisted_ips gauge
ips_active_blacklisted_ips 0
# HELP ips_dropped_blacklist_total Total packets dropped due to active IP blacklisting
# TYPE ips_dropped_blacklist_total counter
ips_dropped_blacklist_total 149
# HELP ips_dropped_ratelimit_total Total packets dropped due to rate limit threshold violations
# TYPE ips_dropped_ratelimit_total counter
ips_dropped_ratelimit_total 1
# HELP ips_passed_packets_total Total packets inspected and passed by Smart IPS
# TYPE ips_passed_packets_total counter
ips_passed_packets_total 50
# HELP ips_total_bytes Total network bytes processed by Smart IPS
# TYPE ips_total_bytes counter
ips_total_bytes 16716
```

---

## 4. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **XDP Bounds Verification** | ผ่านการตรวจสอบ Bounds Check ทั้ง Ethernet, IPv4, TCP, ICMP 100% | [x] ผ่าน |
| **Kernel Blacklist Engine** | ใช้ `BPF_MAP_TYPE_LRU_HASH` จัดการ Blacklist IP ป้องกันหน่วยความจำล้น | [x] ผ่าน |
| **Flood Rate Limiting** | ตรวจจับ TCP SYN Flood และ ICMP Echo Flood ตาม Window 1 วินาที | [x] ผ่าน |
| **In-Kernel Auto-Ban** | สั่งแบน IP ลงใน `blacklist_map` จากใน eBPF XDP โดยตรงทันที | [x] ผ่าน |
| **Zero-Copy Alert Streaming** | ส่งการแจ้งเตือน Real-time Alert สู่ User space ผ่าน 4MB Ring Buffer | [x] ผ่าน |
| **Auto-Unban TTL Engine** | Goroutine ตรวจสอบและปลดแบน IP เมื่อครบเวลา TTL ที่กำหนด | [x] ผ่าน |
| **REST Management API** | ให้บริการ Endpoint `/api/blacklist` (GET/POST/DELETE) ครบถ้วน | [x] ผ่าน |
| **Prometheus Exporter** | ส่งออกตัวชี้วัด Passed, Dropped, Bytes, และ Active Bans ผ่าน `/metrics` | [x] ผ่าน |
