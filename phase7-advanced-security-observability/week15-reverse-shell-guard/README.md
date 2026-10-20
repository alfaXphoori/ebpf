# สัปดาห์ที่ 15: ตรวจจับ Reverse Shell และภัยคุกคาม Interactive Command Execution ด้วย eBPF CO-RE

ยินดีต้อนรับสู่ **Week 15** ของหลักสูตร eBPF Noob to Hero!
เมื่อเซิร์ฟเวอร์ถูกเจาะผ่านช่องโหว่ประเภท **Remote Code Execution (RCE)** ผู้โจมตีมักจะส่ง Payload เพื่อ Spawn Interactive Shell (`bash`, `sh`, `nc`) ออกมาจาก Process ของ Web Service (`nginx`, `node`, `python`, `php-fpm`)

ในสัปดาห์นี้ เราจะใช้ **eBPF CO-RE** เจาะลึกโครงสร้าง `task_struct->real_parent` ในหน่วยความจำเคอร์เนล เพื่อสืบสาวความสัมพันธ์ระหว่างโพรเซสลูกและพ่อ และส่งสัญญาณเตือนภัยฉุกเฉิน (High-Priority Alert) ผ่าน **BPF Ring Buffer** ทันทีที่มีการลักลอบเปิดเชลล์จาก Daemon Service

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รัน Threat Guard เฝ้าระวังพฤติกรรมในเคอร์เนล
make run
```
