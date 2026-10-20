# สัปดาห์ที่ 14: ระบบความปลอดภัย Zero-Trust Socket Egress Control ด้วย cgroup/connect4

ยินดีต้อนรับสู่ **Week 14** ของหลักสูตร eBPF Noob to Hero!
ในสถาปัตยกรรมคลาวด์เนทีฟ (เช่น Cilium Service Mesh) การดักกรองการเชื่อมต่อออกภายนอก (Egress Filtering) ที่ระดับ Socket Layer ถือเป็นวิธีที่มีประสิทธิภาพสูงสุด:
- **0% Packet Processing Overhead**: สกัดกั้นหรือแปลง IP ปลายทางตั้งแต่จังหวะ System Call `connect()` ใน User Space Application ก่อนที่เคอร์เนลจะเริ่มสร้างแพ็กเก็ต TCP SYN หรือแตะการ์ดเครือข่าย

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อบล็อกพอร์ตอันตราย (ค่าเริ่มต้นบล็อก TCP 2323 และ IP 10.99.99.99)
sudo ./bin/sock-enforce -block-port 2323

# ทดสอบจากอีกหน้าจอ (จะได้รับข้อความ Operation not permitted ทันทีโดยไม่มีแพ็กเก็ตหลุดออกไป)
curl -m 1 http://127.0.0.1:2323
```
