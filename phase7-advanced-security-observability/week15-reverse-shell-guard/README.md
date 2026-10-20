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

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF Reverse Shell & Interactive Threat Detector (CO-RE + RingBuffer)
======================================================================
2026/10/20 11:56:01 [INFO] Hooked tracepoint 'sched/sched_process_exec'.
2026/10/20 11:56:01 [INFO] Watching for interactive shell spawns and parent process anomalies...

TIME      SEVERITY               PID    PPID   PROCESS      PARENT        
--------------------------------------------------------------------------------
11:56:02  CRITICAL-RCE          64767  64766  sh           python3       

[INFO] Stopping Threat Guard...
[SUCCESS] Threat Guard cleanly shutdown.
```
