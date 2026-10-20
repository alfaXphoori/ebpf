# สัปดาห์ที่ 21: การประมวลผลแพ็กเก็ตความเร็วระดับสิบล้านแพ็กเก็ตต่อวินาทีด้วย AF_XDP และ XSKMAP

ยินดีต้อนรับสู่ **Week 21** ของหลักสูตร eBPF Noob to Hero!
เมื่อระบบเครือข่ายต้องการอัตราการส่งข้อมูลสูงระดับ 10 Gbps ถึง 100 Gbps (เช่น Cloudflare, Meta, หรือ High-Frequency Trading) ซอฟต์แวร์แบบดั้งเดิมที่ใช้ Linux Socket จะรับภาระ Overhead ไม่ไหว

ในสัปดาห์นี้ เราจะเจาะลึกเทคโนโลยี **AF_XDP (Address Family XDP)** และ **`BPF_MAP_TYPE_XSKMAP`**:
1. การทำงานของ `bpf_redirect_map()` ที่ส่งต่อแพ็กเก็ตตรงจาก Driver RX Queue เข้าสู่ User-Space Ring Buffer (UMEM)
2. สถาปัตยกรรม Zero-Copy โดยไม่ต้องพึ่งพา Kernel Network Stack และไม่ต้องการ Kernel Module พิเศษแบบ DPDK

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อเปิด Pipeline การส่งต่อแพ็กเก็ต AF_XDP
make run
```

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF AF_XDP Wire-Speed Packet Pipeline (BPF_MAP_TYPE_XSKMAP)
======================================================================
2026/10/20 11:57:20 [INFO] Attached AF_XDP redirect program to lo [Index: 1]!
2026/10/20 11:57:20 [INFO] Monitoring XSK pipeline telemetry... (Press Ctrl+C to stop)

[11:57:22] XSK Redirects: 0        | Fallback Passed Packets: 11      

[INFO] Detaching XDP link and exiting cleanly...
Final Summary -> Redirects: 0, Passed: 13
```
