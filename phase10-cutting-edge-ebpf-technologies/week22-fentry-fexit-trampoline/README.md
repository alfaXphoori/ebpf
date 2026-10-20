# สัปดาห์ที่ 22: สถาปัตยกรรม BPF Trampoline (fentry & fexit) ลด Overhead การ Tracing สู่ระดับศูนย์

ยินดีต้อนรับสู่ **Week 22** ของหลักสูตร eBPF Noob to Hero!
ในอดีต `kprobe` และ `kretprobe` ใช้ Interrupt Breakpoint (`int3`) ซึ่งสร้าง Overhead ประมาณ 100ns ต่อการเรียก ทำให้ไม่เหมาะกับการ Trace ฟังก์ชันที่มีการเรียกใช้งานถี่เป็นล้านครั้งต่อวินาที

ในสัปดาห์นี้ เราจะใช้ **BPF Trampoline (`fentry` และ `fexit`)**:
1. แปลงรหัสต้นทางด้วย JIT เป็นคำสั่ง Assembly Patch (Direct Call) มี Overhead ต่ำกว่า 5ns
2. ใน `fexit` สามารถเข้าถึงทั้งอาร์กิวเมนต์ขาเข้าเดิม และค่าที่ฟังก์ชัน Return กลับ (`ret`) ได้โดยตรงในตัวแปรเดียวโดยไม่ต้องบันทึกรีจิสเตอร์แบบยุ่งยาก

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อติดตามการเปิดไฟล์ผ่าน BPF Trampoline
make run
```

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF Trampoline (fentry & fexit) Ultra-Low Latency Tracing
======================================================================
2026/10/20 11:57:36 [INFO] Attached BPF Trampoline fentry to 'do_sys_openat2'
2026/10/20 11:57:36 [INFO] Attached BPF Trampoline fexit to 'do_sys_openat2'
2026/10/20 11:57:36 [INFO] Tracing file open duration with <5ns trampoline overhead...

TIME      PID    COMM             FD / RET   LATENCY    FILENAME
---------------------------------------------------------------------------------------------------
11:57:36  65265  cat              3          9.90us     /etc/ld.so.cache
11:57:36  65265  cat              3          4.43us     /usr/lib/x86_64-linux-gnu/libselinux.so.1
11:57:36  65265  cat              3          3.36us     /usr/lib/x86_64-linux-gnu/libc.so.6
11:57:36  65265  cat              3          3.43us     /etc/hosts
11:57:36  65266  cat              ERR(-2)    19.27us    /nonexistent_file

[INFO] Detaching trampoline links...
[SUCCESS] BPF Trampoline detached safely.
```
