# สัปดาห์ที่ 23: การสำรวจเคอร์เนลด้วย BPF Iterators (bpf_iter_task / Zero-Context-Switch Proc)

ยินดีต้อนรับสู่ **Week 23** ของหลักสูตร eBPF Noob to Hero!
ในอดีต หากเราต้องการดึงรายชื่อโปรเซสและสถานะหน่วยความจำทั้งหมด โปรแกรม User Space (เช่น `ps`, `top`) จะต้องเปิดไฟล์นับพันไฟล์ใต้ `/proc/[pid]/...` ซึ่งสิ้นเปลือง I/O และเกิด Context Switch มหาศาล

ในสัปดาห์นี้ เราจะใช้ **BPF Iterators (`bpf_iter`)**:
1. ให้โค้ด eBPF วิ่งวน Loop ผ่านโครงสร้างข้อมูลของเคอร์เนล (`task_struct`, `tcp_sock`) ภายใน Kernel Space โดยตรง
2. จัดรูปแบบข้อมูลผ่าน `BPF_SEQ_PRINTF()` สตรีมขึ้นมายัง User Space เสมือนอ่านไฟล์เดียวเสร็จในเวลาไม่กี่มิลลิวินาที

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รัน BPF Iterator แสดงตารางโพรเซสจากหน่วยความจำเคอร์เนลโดยตรง
make run
```
