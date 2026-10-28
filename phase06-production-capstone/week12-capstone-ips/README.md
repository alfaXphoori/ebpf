# Week 12 Capstone: Smart eBPF XDP Intrusion Prevention System (IPS)

โปรเจกต์ Capstone: ระบบป้องกันการบุกรุกและยับยั้งการโจมตี DoS อัจฉริยะ (**Smart Intrusion Prevention System**) บนสถาปัตยกรรม **eBPF XDP Data-Plane** ร่วมกับ **Go Daemon Control-Plane**, ระบบ Real-time Alerting ด้วย Ring Buffer, Auto-Ban (เปิด/ปิดได้) / Auto-Unban (TTL), REST API สำหรับบริหารจัดการ, Prometheus Telemetry Exporter และชุด Unit Test ด้วย `BPF_PROG_TEST_RUN`

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
|     |    - ถ้าพบ IP และยังไม่หมด TTL: Atomic เพิ่มสถิติ -> XDP_DROP |                     |
|     | 3. ตรวจสอบประเภทแพ็กเก็ต: TCP SYN หรือ ICMP Echo             |                     |
|     | 4. นับใน Fixed Window ต่อ IP (rate_tracker Map, Atomic)     |                     |
|     |    - ถ้า SYN > 100 หรือ ICMP > 50 ต่อ Window (ค่าเริ่มต้น):  |                     |
|     |      * ถ้า CONF_AUTOBAN_EN=1: ใส่ IP ลง blacklist_map       |                     |
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
|     | [TTL Reaper]        --> สแกน blacklist_map ลบ Ban ที่หมดอายุ |                     |
|     | [Prometheus Server] --> ให้บริการสถิติที่ :2112/metrics     |                     |
|     | [REST API Server]   --> CRUD จัดการ Blacklist IP            |                     |
|     +-------------------------------------------------------------+                     |
+-----------------------------------------------------------------------------------------+
```

### 1.2 การเปรียบเทียบประสิทธิภาพ: XDP vs Iptables / Nftables
เมื่อเซิร์ฟเวอร์ตกอยู่ภายใต้การโจมตีแบบ SYN Flood หรือ Ping Flood ปริมาณสูง:
- **Iptables / Nftables**: แพ็กเก็ตทุกตัวจะต้องผ่านการจัดสรรหน่วยความจำ `sk_buff` (Socket Buffer) และเข้า Netfilter Hook ก่อนจะถูก `DROP` ภายใต้ปริมาณแพ็กเก็ตสูงมาก ต้นทุนต่อแพ็กเก็ตนี้ทำให้ CPU หมดไปกับ SoftIRQ จนบริการอื่นตอบสนองช้าลงได้
- **eBPF XDP (eXpress Data Path)**: ในโหมด Native ทำงานในไดรเวอร์ของ NIC ทันทีที่รับแพ็กเก็ตจาก RX Ring ก่อนที่เคอร์เนลจะสร้าง `sk_buff` เมื่อคืนค่า `XDP_DROP` บัฟเฟอร์จะถูกคืนให้ไดรเวอร์ทันที ต้นทุนต่อแพ็กเก็ตจึงต่ำกว่ามาก งานวิจัยของผู้พัฒนา XDP (Høiland-Jørgensen et al., *The eXpress Data Path*, CoNEXT 2018) รายงานอัตรา Drop ระดับหลายสิบล้าน PPS บนฮาร์ดแวร์ทดสอบของผู้วิจัย (โปรดตรวจสอบตัวเลขและเงื่อนไขการทดลองจากบทความต้นฉบับ) — ตัวเลขจริงขึ้นกับ NIC, ไดรเวอร์และ CPU ควรวัดเองก่อนนำไปอ้างอิง
- **หมายเหตุ**: บน `lo` และ veth ที่ใช้ในแล็บนี้ XDP อาจทำงานในโหมด Generic (หลังสร้าง `sk_buff`) จึงไม่ได้ประโยชน์ด้านความเร็วข้างต้น แล็บนี้มุ่งที่ความถูกต้องของตรรกะ ไม่ใช่การวัดประสิทธิภาพ

### 1.3 พฤติกรรมการโจมตีที่ระบบตรวจจับ
1. **TCP SYN Flood**: ผู้โจมตีส่งแพ็กเก็ต TCP ที่มีแฟลก `SYN=1, ACK=0` ถี่ยิบ เพื่อเติมเต็มคิว Connection Backlog ของเซิร์ฟเวอร์จนระบบไม่สามารถรับการเชื่อมต่อจากผู้ใช้ปกติได้
2. **ICMP Echo Flood**: การระดมยิงแพ็กเก็ต Ping (Echo Request, `type=8`) อย่างรวดเร็ว เพื่อเผาผลาญ Bandwidth และ CPU ในการตอบ Echo Reply

### 1.4 โครงสร้าง Maps ทั้ง 5 ตัวใน eBPF IPS
1. **`blacklist_map` (`BPF_MAP_TYPE_LRU_HASH`)**: เก็บรายชื่อ IP ที่ถูกบล็อก (ขนาด 65,536 entries) พร้อม `blocked_at_ns` (ใช้คำนวณ TTL), สถิติจำนวนแพ็กเก็ตและขนาดไบต์ที่ถูกทิ้ง โดยใช้ LRU ป้องกัน Map เต็ม (เมื่อเต็ม Entry ที่ไม่ได้ใช้นานที่สุดจะถูกไล่ออก)
2. **`rate_tracker` (`BPF_MAP_TYPE_LRU_HASH`)**: ตัวนับ SYN / ICMP Echo ต่อ IP ภายใน Window ปัจจุบัน
3. **`ips_metrics` (`BPF_MAP_TYPE_PERCPU_ARRAY`)**: Telemetry 5 สล็อต (Passed, Dropped Blacklist, Dropped Rate-Limit, Total Bytes, Alerts Lost) แบบ Per-CPU ไร้ Lock Contention
4. **`ips_events` (`BPF_MAP_TYPE_RINGBUF`)**: สตรีม Alert ไปยัง Go Daemon ขนาด 4MB
5. **`config_map` (`BPF_MAP_TYPE_ARRAY`)**: 5 สล็อตที่ Go Daemon เขียนได้ขณะระบบทำงาน — `0`=SYN Limit, `1`=ICMP Limit, `2`=Auto-Ban (`0`/`1`), `3`=Window (ns), `4`=Ban TTL (ns, `0`=ไม่หมดอายุ)
   - **ข้อควรระวัง**: `ARRAY` Map ถูกสร้างมาเป็นศูนย์ทุกช่อง โปรแกรมจึงตีความค่า `0` ของ Limit/Window ว่า "ยังไม่ได้ตั้งค่า" แล้วใช้ค่าเริ่มต้น (100 / 50 / 1 วินาที) แทน — ถ้าไม่ทำเช่นนี้ Limit = 0 จะทำให้ SYN ทุกตัวหลังตัวแรกถูก Drop ส่วน Auto-Ban ค่า `0` หมายถึง **ปิด** (Agent เขียน `1` ให้โดยปริยายผ่าน `-autoban=true`)

### 1.5 Fixed (Tumbling) Window vs Sliding Window
โปรแกรมนี้ใช้ **Fixed Window** (หรือ Tumbling Window): นับแพ็กเก็ตตั้งแต่ `window_start_ns` และเมื่อผ่านไปเกิน `window_ns` ก็รีเซ็ตตัวนับเป็นศูนย์แล้วเริ่ม Window ใหม่
```
เวลา ->  |------ Window 1 (1s) ------|------ Window 2 (1s) ------|
SYN      .......................XXXXX|XXXXX......................
                             100 ตัว  | 100 ตัว
                       (ไม่เกิน Limit)  (ไม่เกิน Limit) แต่ 200 ตัวภายใน ~0.2s!
```
- **ข้อดี**: ใช้หน่วยความจำต่อ IP น้อย (timestamp 1 ตัว + ตัวนับ) และอัปเดตได้ด้วย Atomic ไม่กี่คำสั่ง
- **ข้อเสีย (Boundary Burst)**: ผู้โจมตีที่ยิงคร่อมรอยต่อของสอง Window สามารถส่งได้เกือบ **2 เท่า** ของ Limit ในช่วงเวลาสั้นๆ โดยไม่ถูกจับ
- **Sliding Window** แก้ปัญหานี้ได้ เช่นแบบ **Two-Bucket Weighted**: เก็บตัวนับของ Window ก่อนหน้า (`prev`) และปัจจุบัน (`curr`) แล้วประมาณอัตราเป็น `curr + prev × (1 - elapsed/window)` — ให้ลองทำในแบบฝึกหัดระดับท้าทาย

### 1.6 Concurrency: ทำไมต้อง Atomic ใน Map ที่ใช้ร่วมกัน
NIC สมัยใหม่กระจายแพ็กเก็ตไปหลาย RX Queue / หลาย CPU พร้อมกัน แพ็กเก็ตจาก IP เดียวกันจึงอาจเข้าโปรแกรม XDP บนหลาย CPU ในเวลาเดียวกัน:
- **`ips_metrics` (Per-CPU)**: แต่ละ CPU มีช่องของตัวเอง ใช้ `*val += delta` ธรรมดาได้
- **`blacklist_map` และ `rate_tracker` (Hash ร่วม)**: ทุก CPU ได้ Pointer ไปยัง **ค่าเดียวกัน** ถ้าใช้ `x++` (Load-Add-Store) สอง CPU อาจอ่านค่าเดิมพร้อมกันแล้วเขียนทับกัน ทำให้นับหาย จึงใช้ `__sync_fetch_and_add()` ซึ่งคอมไพล์เป็นคำสั่ง `BPF_ATOMIC` (`lock xadd` บน x86)
- การรีเซ็ต Window ใช้ `__sync_val_compare_and_swap()` บน `window_start_ns` เพื่อให้มีเพียง CPU เดียวที่รีเซ็ตต่อหนึ่ง Window
- การใช้ **ค่าที่คืนกลับ** ของ `__sync_fetch_and_add` (Atomic Fetch) และ `cmpxchg` ต้องใช้ BPF ISA v3 จึงคอมไพล์ด้วย `-cflags "-mcpu=v3"` (bpf2go ตั้ง `-mcpu=v1` เป็นค่าเริ่มต้น) และต้องการเคอร์เนล 5.12 ขึ้นไป
- **ข้อจำกัดที่เหลืออยู่**: ระหว่างที่ CPU หนึ่งกำลังรีเซ็ตตัวนับ CPU อื่นอาจเพิ่มค่าเข้าไปก่อนถูกรีเซ็ต ทำให้นับขาดได้เล็กน้อย (ไม่เกินจำนวน CPU ต่อ Window) ซึ่งยอมรับได้สำหรับ Rate Limiter แบบประมาณ

### 1.7 การออกแบบ TTL ที่ไม่พึ่ง Ring Buffer
Ring Buffer อาจเต็ม (`bpf_ringbuf_reserve()` คืน `NULL`) ถ้า TTL ถูกบันทึกเฉพาะตอนที่ Go ได้รับ Alert, Ban ที่ Alert หายจะ **ค้างถาวร** แล็บนี้จึงออกแบบให้:
1. ทุก Ban เก็บ `blocked_at_ns` (นาฬิกา `CLOCK_MONOTONIC` เดียวกับ `bpf_ktime_get_ns()`) ไว้ใน Value ของ `blacklist_map` เอง — ทั้ง Ban จากเคอร์เนลและ Manual Ban จาก Go
2. **Data Plane** อ่าน `CONF_BAN_TTL_NS` และ **ไม่สนใจ** Ban ที่หมดอายุแล้ว ทันทีที่ครบ TTL (แม้ Go ยังไม่ได้ลบ)
3. **Go Reaper** (`ExpireBans`) สแกน `blacklist_map` ทุก 2 วินาที แล้วลบ Entry ที่หมดอายุออกจริงพร้อม Log `[IPS UNBAN]`
4. เมื่อ Reserve ไม่สำเร็จ โปรแกรมจะเพิ่ม `METRIC_ALERTS_LOST` (Export เป็น `ips_alerts_lost_total`) เพื่อให้มองเห็นปัญหาได้จาก Prometheus

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 eBPF Kernel Program (`bpf/ips_kern.c`)

```c
struct block_entry {
    __u64 blocked_at_ns;   /* CLOCK_MONOTONIC (bpf_ktime_get_ns) - used for TTL expiry */
    __u64 drop_count;
    __u64 drop_bytes;
    __u32 reason;
    __u32 pad;
};
```
- **บรรทัด 47–53**: Value ของ `blacklist_map` เก็บเวลาที่ถูกบล็อก (ใช้คำนวณ TTL ทั้งในเคอร์เนลและใน Go), สถิติแพ็กเก็ต/ไบต์ที่ถูกทิ้ง และรหัสสาเหตุ (SYN Flood, ICMP Flood หรือ Manual Ban)

```c
struct ips_alert {
    ...
    __u8  proto;
    __u8  reason;
    __u8  action;   /* ACTION_BANNED or ACTION_RATE_LIMITED */
    __u8  pad;
    __u32 pps;
};
```
- **บรรทัด 63–74**: Event ที่ส่งผ่าน Ring Buffer ฟิลด์ `action` บอก Go ว่าเคอร์เนล "แบน" หรือ "Rate-limit อย่างเดียว" (ใช้พื้นที่ Padding เดิม ขนาด Struct ไม่เปลี่ยน) — Struct ฝั่ง Go (`ipsAlert`) ต้องเรียงฟิลด์ตรงกันทุกไบต์

```c
static __always_inline __u64 get_conf(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&config_map, &idx);
    return val ? *val : 0;
}
```
- **บรรทัด 114–131**: `inc_metric()` เพิ่มค่า Per-CPU ด้วย `+=` ธรรมดา และ `get_conf()` อ่านค่าคอนฟิก (คืน 0 ถ้าไม่มี)

```c
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    ...
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_PASS;
    if ((void *)iph + ip_hdr_len > data_end) return XDP_PASS;
```
- **บรรทัด 144–170**: ตรวจสอบขอบเขต Ethernet / IPv4 Header และความยาว Variable Header Length (`ihl * 4`) ตามที่ Verifier บังคับ (ทบทวน Week 11)

```c
    struct block_entry *b_entry = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (b_entry) {
        __u64 ban_ttl = get_conf(CONF_BAN_TTL_NS);
        __u64 banned_for = now - b_entry->blocked_at_ns;
        if (ban_ttl == 0 || now < b_entry->blocked_at_ns || banned_for < ban_ttl) {
            __sync_fetch_and_add(&b_entry->drop_count, 1);
            __sync_fetch_and_add(&b_entry->drop_bytes, pkt_len);
            ...
            return XDP_DROP;
        }
    }
```
- **บรรทัด 176–199**: ถ้า IP ต้นทางอยู่ใน Blacklist และ **ยังไม่หมด TTL** ให้เพิ่มสถิติแบบ Atomic (Map นี้ใช้ร่วมทุก CPU) แล้ว `XDP_DROP` ทันที ถ้าหมด TTL แล้วจะไม่ Drop แต่ปล่อยให้ตรวจ Rate ต่อตามปกติ (Go Reaper จะลบ Entry ทิ้งภายหลัง)

```c
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;
        if (tcph->syn && !tcph->ack) is_syn = 1;
    }
```
- **บรรทัด 207–239**: สกัด TCP / ICMP Header พร้อม Bounds Check ตรวจแฟลก `SYN=1, ACK=0` หรือ ICMP `type=ICMP_ECHO` แพ็กเก็ตอื่นทั้งหมด `XDP_PASS`

```c
    __u64 syn_threshold = get_conf(CONF_SYN_LIMIT);
    ...
    __u64 autoban_en = get_conf(CONF_AUTOBAN_EN);
    if (syn_threshold == 0)
        syn_threshold = DEFAULT_SYN_LIMIT;
```
- **บรรทัด 241–252**: อ่านคอนฟิกทั้งหมดจาก `config_map` ค่า 0 = ใช้ค่าเริ่มต้น (ดูหัวข้อ 1.4)

```c
    if (!r_state) {
        struct rate_state initial_state = { .window_start_ns = now };
        bpf_map_update_elem(&rate_tracker, &src_ip, &initial_state, BPF_NOEXIST);
        r_state = bpf_map_lookup_elem(&rate_tracker, &src_ip);
        ...
    }
```
- **บรรทัด 254–268**: สร้างตัวนับให้ IP ใหม่ด้วย `BPF_NOEXIST` ถ้า CPU อื่นสร้างไว้ก่อนแล้วจะไม่เขียนทับ (ไม่ทำให้ตัวนับของอีกฝั่งหาย) จากนั้น Lookup ใหม่เพื่อใช้ Pointer เดียวกัน

```c
    __u64 start = r_state->window_start_ns;
    if (now > start && now - start > window_ns) {
        if (__sync_val_compare_and_swap(&r_state->window_start_ns, start, now) == start) {
            r_state->syn_count = 0;
            r_state->icmp_count = 0;
        }
    }
```
- **บรรทัด 270–283**: รีเซ็ต **Fixed (Tumbling) Window** เมื่อ Window ปัจจุบันเก่ากว่า `window_ns` เฉพาะ CPU ที่ชนะ Compare-and-Swap เท่านั้นที่รีเซ็ต เงื่อนไข `now > start` ป้องกันกรณี CPU อื่นเพิ่งเลื่อน Window ไปด้วย Timestamp ที่ใหม่กว่าเล็กน้อย (ถ้าไม่เช็ก `now - start` จะ Underflow เป็นค่ามหาศาลแล้วรีเซ็ตซ้ำ)

```c
    if (is_syn) {
        count = __sync_fetch_and_add(&r_state->syn_count, 1) + 1;
        ...
```
- **บรรทัด 285–297**: เพิ่มตัวนับแบบ Atomic และใช้ค่าที่คืนกลับ (+1) เป็น "ลำดับของแพ็กเก็ตนี้ใน Window" — แต่ละแพ็กเก็ตได้ลำดับไม่ซ้ำกันแม้มาพร้อมกันหลาย CPU

```c
    if (count > threshold) {
        if (autoban_en) {
            bpf_map_update_elem(&blacklist_map, &src_ip, &new_ban, BPF_ANY);
            action = ACTION_BANNED;
        }
        if (autoban_en || count == threshold + 1) {
            struct ips_alert *alert = bpf_ringbuf_reserve(&ips_events, sizeof(*alert), 0);
            if (alert) { ... bpf_ringbuf_submit(alert, 0); }
            else inc_metric(METRIC_ALERTS_LOST, 1);
        }
        return XDP_DROP;
    }
```
- **บรรทัด 299–345**: เมื่อเกินขีดจำกัด:
  - `CONF_AUTOBAN_EN=1`: ใส่ IP ลง `blacklist_map` (Auto-Ban) แพ็กเก็ตถัดไปทุกชนิดจาก IP นี้จะถูก Drop ที่ขั้นตอน Blacklist
  - `CONF_AUTOBAN_EN=0`: **Rate-limit อย่างเดียว** Drop เฉพาะ SYN/ICMP Echo ที่เกิน Limit ใน Window นั้น ทราฟฟิกอื่นจาก IP เดียวกันยังผ่านได้ และส่ง Alert เพียงครั้งเดียวต่อ Window (`count == threshold + 1`) เพื่อไม่ให้ Ring Buffer ท่วม
  - ถ้า Reserve Ring Buffer ไม่สำเร็จ นับลง `METRIC_ALERTS_LOST` — Ban ยังมี `blocked_at_ns` จึงหมดอายุได้ตามปกติ

---

### 2.2 Go Control Plane Agent (`cmd/ips-agent/main.go`)

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-mcpu=v3" -target bpf bpf ../../bpf/ips_kern.c
```
- **บรรทัด 29**: คอมไพล์ด้วย BPF ISA v3 เพื่อให้ใช้ Atomic Fetch / Compare-and-Swap ได้ (หัวข้อ 1.6)

```go
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}
```
- **บรรทัด 130–138**: อ่านนาฬิกา `CLOCK_MONOTONIC` ซึ่งเป็นฐานเวลาเดียวกับ `bpf_ktime_get_ns()` ห้ามใช้ `time.Now().UnixNano()` (Wall Clock) เพราะเทียบกับเวลาในเคอร์เนลไม่ได้

```go
func applyConfig(m *ebpf.Map, c ipsConfig) error {
	values := map[uint32]uint64{
		ConfSYNLimit:  c.SYNLimit,
		ConfICMPLimit: c.ICMPLimit,
		ConfAutobanEn: autoban,
		ConfWindowNs:  uint64(c.Window.Nanoseconds()),
		ConfBanTTLNs:  uint64(c.BanTTL.Nanoseconds()),
	}
	...
```
- **บรรทัด 140–168**: เขียนคอนฟิกทุกช่องลง `config_map` และคืน Error ถ้าเขียนไม่สำเร็จ (ใช้ร่วมกันทั้งใน `main()` และใน Unit Test)

```go
func (bm *BanManager) ExpireBans(nowNs uint64) ([]uint32, error) {
	iter := bm.blacklistMap.Iterate()
	for iter.Next(&ipKey, &entry) {
		if nowNs >= entry.BlockedAtNs && nowNs-entry.BlockedAtNs >= ttlNs {
			expired = append(expired, ipKey)
		}
	}
	...
	for _, ip := range expired {
		bm.blacklistMap.Delete(&ip)
```
- **บรรทัด 170–288**: `BanManager` ไม่มีสำเนาข้อมูลของตัวเองอีกต่อไป — `blacklist_map` ในเคอร์เนลคือแหล่งข้อมูลเดียว (Single Source of Truth) `ExpireBans()` เก็บ Key ที่หมดอายุก่อน แล้วค่อยลบภายหลัง (การลบระหว่าง Iterate Hash Map อาจทำให้การวนเริ่มใหม่ตั้งแต่ต้น) `RunEvictionTicker()` เรียกฟังก์ชันนี้ทุก 2 วินาที และ `CountActiveBans()` นับจำนวน Entry ใน Map จริง

```go
	cfg := ipsConfig{
		SYNLimit:  *synLimitFlag,
		ICMPLimit: *icmpLimitFlag,
		Autoban:   *autobanFlag,
		Window:    time.Second,
		BanTTL:    *ttlFlag,
	}
	if err := applyConfig(objs.ConfigMap, cfg); err != nil {
```
- **บรรทัด 395–408**: ตั้งค่าคอนฟิกจาก Flag `-syn-limit`, `-icmp-limit`, `-autoban` (ค่าเริ่มต้น `true`) และ `-ban-ttl` (`0` = ไม่ปลดแบนอัตโนมัติ)

```go
go func() {
    var alert ipsAlert
    for {
        record, err := rd.Read()
        binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &alert)
        ...
        log.Printf("[IPS ALERT] ... | Action=%s", ..., actionToString(alert.Action))
```
- **บรรทัด 427–461**: Ring Buffer Consumer พิมพ์ Alert พร้อม Action (`AUTO-BANNED` / `RATE-LIMITED`) — ไม่ต้องบันทึกเวลาแบนเองอีกแล้วเพราะอยู่ใน Map

```go
mux.HandleFunc("/api/blacklist", func(w http.ResponseWriter, r *http.Request) { ... })
```
- **บรรทัด 480–546**: REST API:
  - `GET /api/blacklist`: รายชื่อ IP ใน Blacklist พร้อม `drop_count`, `drop_bytes`, `reason`, `banned_for` (อายุของ Ban)
  - `POST /api/blacklist` (`{"ip":"x.x.x.x"}`): แบน IP แบบ Manual (หมดอายุตาม TTL เช่นเดียวกัน)
  - `DELETE /api/blacklist?ip=x.x.x.x`: ปลดแบนทันที

### 2.3 Unit Tests (`cmd/ips-agent/ips_test.go`)
ชุดทดสอบใช้ `BPF_PROG_TEST_RUN` (`Program.Run()`) ป้อน Ethernet/IPv4 Frame ที่สร้างขึ้นเองให้ `xdp_smart_ips` โดย **ไม่ผูกกับ Interface ใดเลย** แต่ละเทสต์โหลด Map ชุดใหม่:

| Test | สิ่งที่ตรวจ |
| :--- | :--- |
| `TestNonInspectedTrafficPasses` | ARP, TCP ACK, ICMP Echo Reply, UDP และแพ็กเก็ต TCP ที่ถูกตัดสั้น ต้อง `XDP_PASS` ทั้งหมดและไม่ถูกแบน |
| `TestSYNFloodAutoBanEnabled` | SYN ตัวที่ Limit+1 ถูก Drop, IP เข้า Blacklist ด้วย `SYN_FLOOD`, ACK ถัดไปถูก Drop, IP อื่นยังผ่าน, Counter และ Alert ถูกต้อง |
| `TestSYNFloodAutoBanDisabled` | `CONF_AUTOBAN_EN=0`: Drop เฉพาะ SYN ที่เกิน, ไม่มี Blacklist, ACK ยังผ่าน, Alert เพียง 1 ครั้ง (`RATE-LIMITED`) |
| `TestICMPFloodAutoBan` | Echo Request ตัวที่ Limit+1 ถูก Drop และแบนด้วย `ICMP_FLOOD` |
| `TestFixedWindowReset` | หลัง Window (100ms) หมด ตัวนับรีเซ็ตและ SYN ผ่านได้อีก |
| `TestZeroConfigUsesDefaults` | ไม่เขียนคอนฟิกเลย: ใช้ Limit เริ่มต้น 100 และ Auto-Ban ปิด |
| `TestBanTTLExpiry` | Ban จากเคอร์เนล (ไม่มีใครอ่าน Ring Buffer) และ Manual Ban ถูก Data Plane เลิกบังคับใช้เมื่อครบ TTL และ `ExpireBans()` ลบออกจาก Map ได้ทั้งคู่ |

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์โปรเจกต์ Capstone
```bash
# คอมไพล์ eBPF C program และสร้างไบนารี Go Agent
make generate
make build
```
ไฟล์ไบนารีจะถูกสร้างขึ้นที่ `bin/ips-agent`

### ขั้นตอนที่ 2: รัน Unit Tests
```bash
make test   # = go generate + go test -exec sudo -v ./...
```
ต้องใช้สิทธิ์ root (`sudo`) ในการโหลดโปรแกรม หากรัน `go test` เป็นผู้ใช้ธรรมดา เทสต์จะถูก Skip

### ขั้นตอนที่ 3: เตรียมเครือข่ายทดสอบ (แยก Namespace ผู้โจมตี / เซิร์ฟเวอร์)
แนะนำให้ทดสอบบน veth ใน Network Namespace แยก แทน `lo` เพื่อให้ IP ผู้โจมตี (`10.212.0.1`) ต่างจาก IP เซิร์ฟเวอร์ และไม่กระทบเครือข่ายจริงของเครื่อง:
```bash
sudo ip netns add w12atk; sudo ip netns add w12ips
sudo ip link add w12a type veth peer name w12b
sudo ip link set w12a netns w12atk; sudo ip link set w12b netns w12ips
sudo ip -n w12atk addr add 10.212.0.1/24 dev w12a
sudo ip -n w12ips addr add 10.212.0.2/24 dev w12b
sudo ip -n w12atk link set w12a up; sudo ip -n w12ips link set w12b up
sudo ip -n w12atk link set lo up;   sudo ip -n w12ips link set lo up
```
> หากต้องการใช้ `lo` แบบเดิม: `sudo ./bin/ips-agent -iface lo ...` แต่ระวังว่าการแบน `127.0.0.1` จะตัดการเชื่อมต่อ Local ทั้งหมดของเครื่อง (รวมถึง `curl localhost:2112`) จนกว่าจะครบ TTL

### ขั้นตอนที่ 4: รัน Smart IPS Daemon
```bash
# Limit ต่ำเพื่อให้เห็นผลง่าย, ปลดแบนอัตโนมัติหลัง 6 วินาที
sudo ip netns exec w12ips ./bin/ips-agent -iface w12b -ban-ttl 6s -syn-limit 10 -icmp-limit 5 -http-port :2112
```
ตัวเลือก `-autoban=false` เปลี่ยนเป็นโหมด Rate-limit อย่างเดียว (ไม่แบน IP)

### ขั้นตอนที่ 5: จำลอง Ping Flood และ SYN Burst
เปิด Terminal ใหม่:
```bash
# ICMP Echo Flood (ICMP Limit = 5 ต่อวินาที)
sudo ip netns exec w12atk ping -f -c 200 -w 3 10.212.0.2

# SYN Burst: เปิด TCP Connection ไปยังพอร์ตที่ปิดอยู่ 30 ครั้ง (แต่ละครั้งส่ง SYN)
sudo ip netns exec w12atk bash -c 'for i in $(seq 30); do timeout 0.2 bash -c "echo > /dev/tcp/10.212.0.2/8080" 2>/dev/null; done; true'
```

### ขั้นตอนที่ 6: ตรวจสอบ Blacklist, TTL และ Manual Ban ผ่าน REST API
```bash
sudo ip netns exec w12ips curl -s localhost:2112/api/blacklist
# รอเกิน TTL (6s) แล้วดูอีกครั้ง -> ควรว่าง []
sudo ip netns exec w12ips curl -s localhost:2112/api/blacklist
# Manual Ban
sudo ip netns exec w12ips curl -s -X POST -d '{"ip":"203.0.113.99"}' localhost:2112/api/blacklist
```

### ขั้นตอนที่ 7: ตรวจสอบ Telemetry ผ่าน Prometheus Endpoint
```bash
sudo ip netns exec w12ips curl -s localhost:2112/metrics | grep "^ips_"
```
ปิด Agent ด้วย `Ctrl+C` แล้วลบ Namespace: `sudo ip netns del w12atk; sudo ip netns del w12ips`

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04.1 LTS (`Linux 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), clang 21, Go 1.26, cilium/ebpf v0.16.0 — veth `w12b` ใน Namespace `w12ips` ตามขั้นตอนที่ 3 (โค้ดสี ANSI ใน Log ถูกตัดออกเพื่อให้อ่านง่าย)

### 4.1 ผลลัพธ์ `make test`
```text
cd cmd/ips-agent && go generate ./...
go test -exec sudo -v ./...
=== RUN   TestNonInspectedTrafficPasses
--- PASS: TestNonInspectedTrafficPasses (0.00s)
=== RUN   TestSYNFloodAutoBanEnabled
--- PASS: TestSYNFloodAutoBanEnabled (0.05s)
=== RUN   TestSYNFloodAutoBanDisabled
--- PASS: TestSYNFloodAutoBanDisabled (0.05s)
=== RUN   TestICMPFloodAutoBan
--- PASS: TestICMPFloodAutoBan (0.05s)
=== RUN   TestFixedWindowReset
--- PASS: TestFixedWindowReset (0.15s)
=== RUN   TestZeroConfigUsesDefaults
--- PASS: TestZeroConfigUsesDefaults (0.00s)
=== RUN   TestBanTTLExpiry
2026/10/28 22:06:23 [CONTROL] IP 198.51.100.7 manually blacklisted (reason=4)
--- PASS: TestBanTTLExpiry (0.25s)
PASS
ok  	week12-capstone-ips/cmd/ips-agent	0.583s
```
(ตัดบรรทัด `Compiled/Stripped/Wrote` ของ bpf2go ออก)

### 4.2 Auto-Ban Mode (`-autoban=true`, ค่าเริ่มต้น): Flood, Auto-Ban, Auto-Unban TTL และ Manual Ban
ฝั่งผู้โจมตีและ REST API:
```text
--- ping -f -c 200 (ICMP flood from 10.212.0.1) ---
--- 10.212.0.2 ping statistics ---
274 packets transmitted, 5 received, 98.1752% packet loss, time 2995ms
rtt min/avg/max/mdev = 0.003/0.011/0.041/0.014 ms, ipg/ewma 10.969/0.025 ms
--- SYN burst: 30 x connect() to closed port 8080 ---
--- GET /api/blacklist ---
[{"ip":"10.212.0.1","drop_count":5,"drop_bytes":370,"reason":"SYN_FLOOD","banned_for":"1s"}]

--- GET /api/blacklist (after TTL) ---
[]

--- POST /api/blacklist (203.0.113.99) ---
{"status":"banned","ip":"203.0.113.99"}
--- GET /metrics ---
# TYPE ips_active_blacklisted_ips gauge
ips_active_blacklisted_ips 1
# TYPE ips_alerts_lost_total counter
ips_alerts_lost_total 0
# TYPE ips_dropped_blacklist_total counter
ips_dropped_blacklist_total 287
# TYPE ips_dropped_ratelimit_total counter
ips_dropped_ratelimit_total 2
# TYPE ips_passed_packets_total counter
ips_passed_packets_total 22
# TYPE ips_total_bytes counter
ips_total_bytes 29546
```
Log ของ Agent:
```text
2026/10/28 22:03:09 [CONFIG] SYN Limit=10 pps, ICMP Limit=5 pps, Window=1s, Auto-Ban=true, Ban TTL=6s
2026/10/28 22:03:09 [INFO] Smart IPS attached to interface w12b (index 1558)
2026/10/28 22:03:09 [INFO] Smart IPS Daemon active! Web/API running at http://0.0.0.0:2112
2026/10/28 22:03:11 [IPS ALERT] ICMP_FLOOD  | Proto=ICMP | Src=10.212.0.1:0 -> Dst=10.212.0.2:0 | Rate=6 PPS | Action=AUTO-BANNED
2026/10/28 22:03:17 [IPS UNBAN] IP 10.212.0.1 unbanned after 6s TTL expiration
2026/10/28 22:03:18 [IPS ALERT] SYN_FLOOD   | Proto=TCP  | Src=10.212.0.1:43636 -> Dst=10.212.0.2:8080 | Rate=11 PPS | Action=AUTO-BANNED
2026/10/28 22:03:25 [IPS UNBAN] IP 10.212.0.1 unbanned after 6s TTL expiration
2026/10/28 22:03:28 [CONTROL] IP 203.0.113.99 manually blacklisted (reason=4)
2026/10/28 22:03:28 
[INFO] Termination signal received. Stopping Smart IPS Daemon...
2026/10/28 22:03:28 [INFO] Smart IPS cleanly shut down.
```
การอ่านผล:
- `ping -f` ได้รับ Reply เพียง 5 ตัว (= ICMP Limit) จากนั้น Echo ตัวที่ 6 ทำให้ IP ถูกแบน และแพ็กเก็ตที่เหลือถูก Drop ที่ Blacklist (`ips_dropped_blacklist_total`)
- SYN Burst เริ่มขณะ ICMP Ban ยังมีผล SYN ช่วงแรกจึงถูก Drop ด้วย Blacklist เดิม หลัง Ban หมดอายุ (22:03:17) SYN ตัวที่ 11 ใน Window เดียวกันทำให้ถูกแบนใหม่ด้วยเหตุผล `SYN_FLOOD`
- `ips_dropped_ratelimit_total 2` = แพ็กเก็ตที่ "ทำให้เกิด Ban" 2 ครั้ง (ICMP 1 + SYN 1)
- `ips_active_blacklisted_ips 1` = Manual Ban ของ `203.0.113.99` (นับจาก Map จริง)

### 4.3 Rate-limit-only Mode (`-autoban=false`)
```text
--- ping -i 0.01 -c 300 (100 pps for ~3s) ---
300 packets transmitted, 20 received, 93.3333% packet loss, time 3332ms
rtt min/avg/max/mdev = 0.003/0.018/0.044/0.009 ms
--- GET /api/blacklist ---
[]

--- GET /metrics ---
ips_active_blacklisted_ips 0
ips_alerts_lost_total 0
ips_dropped_blacklist_total 0
ips_dropped_ratelimit_total 280
ips_passed_packets_total 25
ips_total_bytes 29762
=== agent log ===
2026/10/28 22:03:51 [CONFIG] SYN Limit=10 pps, ICMP Limit=5 pps, Window=1s, Auto-Ban=false, Ban TTL=6s
2026/10/28 22:03:51 [INFO] Smart IPS attached to interface w12b (index 1564)
2026/10/28 22:03:51 [INFO] Smart IPS Daemon active! Web/API running at http://0.0.0.0:2112
2026/10/28 22:03:53 [IPS ALERT] ICMP_FLOOD  | Proto=ICMP | Src=10.212.0.1:0 -> Dst=10.212.0.2:0 | Rate=6 PPS | Action=RATE-LIMITED
2026/10/28 22:03:54 [IPS ALERT] ICMP_FLOOD  | Proto=ICMP | Src=10.212.0.1:0 -> Dst=10.212.0.2:0 | Rate=6 PPS | Action=RATE-LIMITED
2026/10/28 22:03:55 [IPS ALERT] ICMP_FLOOD  | Proto=ICMP | Src=10.212.0.1:0 -> Dst=10.212.0.2:0 | Rate=6 PPS | Action=RATE-LIMITED
2026/10/28 22:03:56 [IPS ALERT] ICMP_FLOOD  | Proto=ICMP | Src=10.212.0.1:0 -> Dst=10.212.0.2:0 | Rate=6 PPS | Action=RATE-LIMITED
2026/10/28 22:03:56 
[INFO] Termination signal received. Stopping Smart IPS Daemon...
2026/10/28 22:03:56 [INFO] Smart IPS cleanly shut down.
```
- ไม่มี IP ถูกแบน แต่ได้ Reply 20 ตัว = 5 ตัวต่อ Window × 4 Window ที่ ping คร่อมอยู่ (ส่วนที่เกิน 280 ตัวถูก Drop)
- Alert ออกเพียง 1 ครั้งต่อ Window ไม่ใช่ทุกแพ็กเก็ตที่ถูก Drop

---

## 5. ข้อจำกัดและ Threat Model (Limitations)

- **IPv4-only**: ตรวจเฉพาะ IPv4 ทราฟฟิก IPv6 (รวม SYN/ICMPv6 Flood บน IPv6) และ VLAN-tagged Frame จะ `XDP_PASS` โดยไม่ถูกตรวจ ผู้โจมตีที่มี IPv6 จึงเลี่ยงระบบได้ทั้งหมด
- **IP ต้นทางปลอมได้ (Spoofed Source) → Auto-Ban กลายเป็นอาวุธ**: SYN และ ICMP ไม่ต้องจับมือ (Handshake) ก่อน ผู้โจมตีจึงปลอม `saddr` เป็น IP ของผู้ใช้ปกติ, DNS Resolver, Gateway หรือ Monitoring Server แล้วยิงเกิน Limit เพื่อให้ IPS **แบน IP ที่บริสุทธิ์** เอง (Self-inflicted DoS) — ควรมี Allowlist ของ IP สำคัญ, ใช้โหมด `-autoban=false` (Drop เฉพาะส่วนเกิน) สำหรับทราฟฟิกที่ปลอมง่าย หรือใช้ SYN Cookies แทนการแบนสำหรับ SYN Flood
- **Distributed / Spoofed Flood หลบ Per-IP Limit**: การโจมตีที่สุ่ม IP ต้นทางจำนวนมาก (แต่ละ IP ส่งไม่เกิน Limit) จะไม่ถูกตรวจจับเลย ต้องมี Global Rate Limit เสริม
- **LRU Eviction**: `blacklist_map` และ `rate_tracker` เป็น LRU ขนาด 65,536 การยิงจาก IP ปลอมจำนวนมากสามารถ **ไล่ Ban ที่มีอยู่ออก** หรือรีเซ็ตตัวนับของ IP อื่นได้
- **Fixed Window Boundary Burst**: ส่งได้เกือบ 2 เท่าของ Limit คร่อมรอยต่อ Window (หัวข้อ 1.5) และตัวนับอาจขาดได้เล็กน้อยระหว่างรีเซ็ตพร้อมกันหลาย CPU (หัวข้อ 1.6)
- **ตรวจเฉพาะ SYN (ไม่มี ACK) และ ICMP Echo**: ACK Flood, UDP Flood, Fragmented Packet และ IPv4 Fragment ที่ไม่มี L4 Header ใน Fragment แรกจะผ่านไปได้
- **ช่วงเวลาระหว่าง TTL หมดกับ Reaper**: Data Plane เลิกบังคับใช้ Ban ทันทีที่ครบ TTL แต่ Entry ยังอยู่ใน Map (และนับใน `ips_active_blacklisted_ips`) ได้นานสุดประมาณ 2 วินาทีจนกว่า Reaper จะลบ
- **XDP Link ผูกกับโปรเซส**: เมื่อ Agent หยุดทำงาน XDP ถูกถอดออกและ Map ทั้งหมดหายไป (ไม่มีการ Pin ลง bpffs) การป้องกันจึงหยุดทันทีและ Ban ทั้งหมดหายตามไปด้วย
- **REST API ไม่มีการยืนยันตัวตน**: `/api/blacklist` เปิดที่ `0.0.0.0:2112` ใครก็ตามที่เข้าถึงพอร์ตได้สามารถปลดแบนผู้โจมตี หรือแบน IP ใดก็ได้ — ใน Production ต้อง Bind เฉพาะ `127.0.0.1` หรือมี Auth/mTLS
- **Ingress เท่านั้น / ตัวเลขประสิทธิภาพ**: XDP เห็นเฉพาะขาเข้า และผลในแล็บ (veth/lo, Generic XDP) ไม่สะท้อนประสิทธิภาพบน NIC จริง

---

## 6. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **XDP Bounds Verification** | ผ่านการตรวจสอบ Bounds Check ทั้ง Ethernet, IPv4 (รวม IHL), TCP, ICMP | [x] ผ่าน |
| **Kernel Blacklist Engine** | ใช้ `BPF_MAP_TYPE_LRU_HASH` จัดการ Blacklist IP พร้อม Atomic Counter | [x] ผ่าน |
| **Flood Rate Limiting** | ตรวจจับ TCP SYN Flood และ ICMP Echo Flood ด้วย Fixed Window (ค่าเริ่มต้น 1 วินาที) | [x] ผ่าน |
| **Configurable Auto-Ban** | `CONF_AUTOBAN_EN` / `-autoban` เลือกระหว่าง Auto-Ban กับ Rate-limit อย่างเดียว | [x] ผ่าน |
| **Ring Buffer Alert Streaming** | ส่ง Alert สู่ User space ผ่าน 4MB Ring Buffer และนับ Alert ที่หายใน `ips_alerts_lost_total` | [x] ผ่าน |
| **Auto-Unban TTL Engine** | TTL อิง `blocked_at_ns` ใน Map: Data Plane เลิกบังคับใช้ + Go Reaper ลบ Entry แม้ Alert หาย | [x] ผ่าน |
| **REST Management API** | ให้บริการ Endpoint `/api/blacklist` (GET/POST/DELETE) ครบถ้วน | [x] ผ่าน |
| **Prometheus Exporter** | ส่งออกตัวชี้วัด Passed, Dropped, Bytes, Alerts Lost และ Active Bans ผ่าน `/metrics` | [x] ผ่าน |
| **Unit Tests** | `make test` ผ่านทั้ง 7 เทสต์ด้วย `BPF_PROG_TEST_RUN` | [x] ผ่าน |

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **ปรับ Window ได้จาก Flag**: เพิ่ม Flag `-window` (เช่น `500ms`, `2s`) ให้ Agent แทนค่า `time.Second` ที่ฝังไว้ และแสดงใน `[CONFIG]` Log
   - **ส่งงาน**: Diff ของ `main.go` + Log ตอนรันด้วย `-window 2s`
   - **ตรวจสอบ**: เพิ่มเทสต์ที่ตั้ง Window = 300ms แล้วยืนยันว่ายังถูก Rate-limit ที่ 200ms และผ่านได้อีกครั้งหลัง 350ms; `make test` ผ่าน
2. **Allowlist**: เพิ่ม `BPF_MAP_TYPE_HASH` ชื่อ `allowlist_map` ที่ IP ในนี้จะ `XDP_PASS` เสมอ (ตรวจก่อน Blacklist) และเพิ่ม REST Endpoint `/api/allowlist`
   - **ส่งงาน**: โค้ด C/Go + ผลการ `ping -f` จาก IP ที่อยู่ใน Allowlist ซึ่งไม่ถูกแบน
   - **ตรวจสอบ**: เทสต์ `BPF_PROG_TEST_RUN` ที่ยิง SYN จาก IP ใน Allowlist เกิน Limit แล้วยังได้ `XDP_PASS` และไม่มี Entry ใน `blacklist_map`

### ระดับปานกลาง
1. **UDP Flood Detection**: เพิ่มการนับ UDP ต่อ IP พร้อม `CONF_UDP_LIMIT` และ `REASON_UDP_FLOOD`
   - **ส่งงาน**: โค้ด C/Go (อย่าลืมขยาย `config_map` และ Struct ที่ต้องตรงกันทั้งสองฝั่ง) + Alert จริงจากการยิง `nc -u` หรือสคริปต์ส่ง UDP ถี่ๆ ใน Namespace `w12atk`
   - **ตรวจสอบ**: เพิ่ม `TestUDPFlood` แบบเดียวกับ `TestICMPFloodAutoBan` และ `make test` ผ่าน
2. **วัดผลของ Atomic**: แก้ `__sync_fetch_and_add(&b_entry->drop_count, 1)` กลับเป็น `b_entry->drop_count++` แล้วเขียน Test ที่ใส่ IP ลง Blacklist ก่อน จากนั้นรัน `Program.Run()` จากหลาย Goroutine พร้อมกัน โดยแต่ละ Goroutine เรียก `runtime.LockOSThread()` และ `unix.SchedSetaffinity()` ผูก Thread ไว้คนละ CPU (`BPF_PROG_TEST_RUN` รันโปรแกรมบน CPU ของ Thread ที่เรียก; ฟิลด์ `RunOptions.CPU` ใช้กับ XDP ไม่ได้) แล้วเทียบค่า `drop_count` กับจำนวนแพ็กเก็ตที่ส่งจริง
   - **ส่งงาน**: ตารางผลลัพธ์ทั้งสองแบบ (บันทึกจำนวน CPU ของเครื่อง) + คำอธิบายว่าทำไมผลอาจไม่ต่างกันในบางรอบ
   - **ตรวจสอบ**: เวอร์ชัน Atomic ต้องได้ `drop_count` เท่ากับจำนวนแพ็กเก็ตทุกครั้ง

### ระดับท้าทาย
1. **Sliding Window แบบ Two-Bucket Weighted**: เปลี่ยน `rate_state` ให้เก็บ `prev_count` และ `curr_count` แล้วประเมินอัตราด้วย `curr + prev × (window - elapsed) / window` เพื่อปิดช่องโหว่ Boundary Burst (หัวข้อ 1.5)
   - **ส่งงาน**: โค้ด C + คำอธิบายวิธีจัดการ Concurrency ของการเลื่อน Bucket + เทสต์ที่ยิง Limit ตัวท้าย Window แรก และ Limit ตัวต้น Window ถัดไป
   - **ตรวจสอบ**: เทสต์ดังกล่าวต้อง **ถูก Drop** ในเวอร์ชันใหม่ แต่ **ผ่าน** ในเวอร์ชัน Fixed Window เดิม (ควบคุมเวลาโดย `time.Sleep` ใกล้ขอบ Window หรือปรับ `window_start_ns` ใน Map โดยตรงจากเทสต์)
2. **ป้องกัน Spoofed-Source Ban**: ออกแบบและสร้างกลไกลดความเสี่ยงที่ผู้โจมตีปลอม IP เพื่อให้ IP บริสุทธิ์ถูกแบน (หัวข้อ 5) เช่น แบนเฉพาะ IP ที่เคยทำ TCP Handshake สำเร็จ (ติดตามด้วย Map ของ ACK ที่ตอบกลับถูกต้อง), หรือใช้ `bpf_tcp_raw_gen_syncookie_ipv4()` / `bpf_tcp_raw_check_syncookie_ipv4()` (Linux 6.0+) ตอบ SYN Cookie จาก XDP แทนการแบน
   - **ส่งงาน**: เอกสารออกแบบ 1 หน้า (Threat Model ก่อน/หลัง) + โค้ด + ผลการทดลองจริงที่ยิง SYN ด้วย Source IP ปลอมจาก Namespace `w12atk`
   - **ตรวจสอบ**: IP ที่ถูกปลอมต้องไม่ปรากฏใน `GET /api/blacklist` ขณะที่ SYN Flood จริงยังถูกจำกัด และเทสต์เดิมทั้งหมดยังผ่าน (หรืออธิบายเหตุผลที่ต้องปรับเทสต์)
