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

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF TCP Sockops & Direct Socket-to-Socket Bypass (Cilium Mesh FastPath)
======================================================================
2026/10/20 11:57:11 [INFO] Attached BPF_PROG_TYPE_SOCK_OPS to cgroup /sys/fs/cgroup
2026/10/20 11:57:11 [INFO] Attached BPF_PROG_TYPE_SK_MSG verdict to BPF_MAP_TYPE_SOCKHASH
2026/10/20 11:57:11 [INFO] Localhost socket bypass active! Zero-copy socket routing enabled.

# Sent test message: echo "Accelerated TCP Message via BPF SOCKHASH" | nc 127.0.0.1 18080

[11:57:13] Accelerated TCP Messages: 1        | Direct Bypassed Bytes: 41        

[INFO] Detaching sockops and sk_msg hooks...
```
