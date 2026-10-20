# สัปดาห์ที่ 17: วิเคราะห์ความหน่วงฮาร์ดดิสก์และ Block I/O Stalls ด้วย Modern eBPF biolatency

ยินดีต้อนรับสู่ **Week 17** ของหลักสูตร eBPF Noob to Hero!
ในฐานข้อมูล (Database) และระบบจัดเก็บข้อมูล (Storage Systems) ปัญหาความหน่วงสูงของคำสั่ง Disk Read/Write (I/O Tail Latency) มักเป็นสาเหตุหลักของระบบค้าง

ในสัปดาห์นี้ เราจะสร้างเครื่องมือ **`biolatency`** ฉบับ Modern CO-RE ด้วย libbpf และ Cilium Go โดยเชื่อมต่อระหว่าง:
1. `tracepoint/block/block_rq_issue` (จุดที่เคอร์เนลส่ง Request ลงสู่ Block Device Queue)
2. `tracepoint/block/block_rq_complete` (จุดที่ฮาร์ดแวร์ Disk คืนข้อมูลและ Interrupt เคอร์เนล)
3. รวบรวมสถิติเป็นกราฟแท่ง Power-of-two Histogram แสดงการกระจายตัวของเวลา Latency ในหน่วยไมโครวินาที (µs)

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อติดตามการทำงานของ I/O
make run
```

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF Block I/O Latency Analyzer (CO-RE biolatency)
======================================================================
2026/10/20 11:56:31 [INFO] Attached to 'block:block_rq_issue' & 'block:block_rq_complete'!
2026/10/20 11:56:31 [INFO] Tracing disk I/O requests. (Press Ctrl+C to stop and view histogram)

# Generated Direct Disk I/O: sudo dd if=/dev/sda of=/dev/null bs=1M count=30 iflag=direct

[INFO] Detaching probes and generating final I/O latency histogram...

Latency (us)       : Count    Distribution
----------------------------------------------------------------------
0        -> 1       : 0        |                                        |
2        -> 3       : 0        |                                        |
4        -> 7       : 0        |                                        |
8        -> 15      : 0        |                                        |
16       -> 31      : 0        |                                        |
32       -> 63      : 11       |*******                                 |
64       -> 127     : 56       |****************************************|
128      -> 255     : 29       |********************                    |
256      -> 511     : 48       |**********************************      |
512      -> 1023    : 0        |                                        |
1024     -> 2047    : 0        |                                        |
2048     -> 4095    : 1        |                                        |
4096     -> 8191    : 1        |                                        |
----------------------------------------------------------------------
```
