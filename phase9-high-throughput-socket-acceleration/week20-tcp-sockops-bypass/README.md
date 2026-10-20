# สัปดาห์ที่ 20: เพิ่มความเร็ว TCP ข้ามคอนเทนเนอร์ด้วย sockops และ sk_msg (Cilium FastPath Bypass)

ยินดีต้อนรับสู่ **Week 20** ของหลักสูตร eBPF Noob to Hero!
ในการเชื่อมต่อระหว่าง Microservices หรือ Service Mesh Sidecar (เช่น Envoy กับ Application Pod) ทราฟฟิกส่วนใหญ่เกิดขึ้นบนเครื่องเดียวกัน (Localhost / Node-Local) แต่แพ็กเก็ตยังต้องวิ่งผ่าน Linux TCP/IP Stack เต็มรูปแบบ:
- การสร้าง TCP Header, IP Header, Checksum, Routing Table Lookup, และ iptables/nftables traversal

ในสัปดาห์นี้ เราจะสร้างระบบเร่งความเร็วการส่งข้อมูลระดับ Socket ด้วย **`BPF_PROG_TYPE_SOCK_OPS`** และ **`BPF_PROG_TYPE_SK_MSG`** เพื่อยิงข้อมูลข้าม Socket Queue โดยตรง (Direct Memory Push) ลัดข้าม TCP/IP Stack ส่งผลให้ Throughput สูงขึ้นและ Latency ลดลงอย่างมหาศาล

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อเปิดระบบเร่งความเร็วเครือข่าย Local Socket
make run
```
