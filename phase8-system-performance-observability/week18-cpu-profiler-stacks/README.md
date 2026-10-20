# สัปดาห์ที่ 18: การทำ CPU Profiling และรวบรวม Call Stack Traces เพื่อสร้าง Flame Graphs ด้วย eBPF

ยินดีต้อนรับสู่ **Week 18** ของหลักสูตร eBPF Noob to Hero!
เมื่อระบบเกิดอาการ CPU Spike หรือ Thread ติดขัด เครื่องมืออย่าง `top` จะบอกได้เพียงแค่ว่า Process ใดกิน CPU แต่ไม่สามารถบอกได้ว่า **"ฟังก์ชันใดในโค้ดหรือในเคอร์เนลกำลังทำงานอยู่"**

ในสัปดาห์นี้ เราจะใช้ **`BPF_MAP_TYPE_STACK_TRACE`** และตัวถอดรหัส Symbol `/proc/kallsyms` เพื่อ:
1. แกะรอย Stack Trace (Kernel Space & User Space) อัตโนมัติในระดับเคอร์เนล
2. สรุปความถี่ของเส้นทางการเรียกฟังก์ชัน (Call Chains) ซึ่งเป็นรากฐานสำคัญของการทำ **CPU Flame Graphs**
3. มี Overhead ต่ำเป็นพิเศษ ไม่กระทบความเร็วของระบบโปรดักชัน

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อสุ่มจับและบันทึก Call Stack Traces
make run
```
