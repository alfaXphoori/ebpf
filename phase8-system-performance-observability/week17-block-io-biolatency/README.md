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
