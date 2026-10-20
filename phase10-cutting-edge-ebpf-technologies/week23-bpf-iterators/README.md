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

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
2026/10/20 11:57:42 [INFO] BPF Iterator traversed all kernel task_structs in 309.547µs!

======================================================================
 eBPF Kernel Task Iterator (bpf_iter_task / Zero-Context-Switch Proc)
======================================================================
PID      UID      VM_SIZE_KB COMM            
------------------------------------------------------------
1        0        26828      systemd         
443      0        59460      systemd-journal 
486      986      16940      systemd-oomd    
489      0        41676      systemd-udevd   
492      989      22676      systemd-resolve 
1795     103      6904       avahi-daemon    
1799     995      12012      dbus-daemon     
1840     0        2224504    snapd           
1847     0        9660       cron            
1854     0        18952      systemd-logind  
1858     0        543732     udisksd         
2105     0        54388      tailscaled      
52952    1000     31408      node            
```
