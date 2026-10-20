# สัปดาห์ที่ 19: ติดตามการจัดสรรหน่วยความจำและวิเคราะห์เหตุการณ์ OOM Killer (Memory Forensics)

ยินดีต้อนรับสู่ **Week 19** ของหลักสูตร eBPF Noob to Hero!
ในระบบ Cloud Native ปัญหา **OOM (Out Of Memory) Kill** เป็นหนึ่งในปัญหาที่พบได้บ่อยที่สุดเมื่อคอนเทนเนอร์ใช้แรมเกินขีดจำกัด แต่เมื่อโปรเซสถูกเคอร์เนลสังหารมักจะไม่มี Log หลงเหลืออยู่ในระดับ Application

ในสัปดาห์นี้ เราจะสร้าง **Memory & OOM Watcher** เพื่อ:
1. ดักจับอัตราการเกิด **Page Faults** (การขอจองหน้าแรมทางกายภาพ) ผ่าน `tracepoint/exceptions/page_fault_user`
2. เกาะติดเหตุการณ์สังหารของเคอร์เนลผ่าน `tracepoint/oom/mark_victim` เพื่อดึง PID, ชื่อโปรแกรม, ขนาด Total Virtual Memory และ Anonymous RSS ที่ถูกกวาดล้างแบบเรียลไทม์

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อเฝ้าระวังหน่วยความจำ
make run
```
