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

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF Zero-Trust Socket Egress Enforcer (cgroup/connect4)
======================================================================
2026/10/20 11:55:54 [POLICY] Blocked destination port: 2323 (TCP)
2026/10/20 11:55:54 [POLICY] Blocked destination IPv4: 10.99.99.99
2026/10/20 11:55:54 [INFO] Successfully attached to cgroup /sys/fs/cgroup!
2026/10/20 11:55:54 [INFO] Zero-overhead socket filter active. (Press Ctrl+C to stop)

# Client Connection Attempt:
$ curl -m 1 http://127.0.0.1:2323
curl: (7) Failed to connect to 127.0.0.1 port 2323 after 0 ms: Could not connect to server

[11:55:56] Blocked Port 2323 attempts: 1     

[INFO] Detaching from cgroup and stopping...
Final drops on Port 2323: 1
```
