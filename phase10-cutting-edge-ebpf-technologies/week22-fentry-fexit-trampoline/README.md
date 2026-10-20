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
