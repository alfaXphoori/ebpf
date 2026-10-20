# สัปดาห์ที่ 16: ตรวจจับมัลแวร์ eBPF Rootkit และตรวจสอบความสมบูรณ์ของเคอร์เนล (eBPF Integrity Audit)

ยินดีต้อนรับสู่ **Week 16** ของหลักสูตร eBPF Noob to Hero!
ในยุคปัจจุบัน ผู้โจมตีและกลุ่ม APT เริ่มนำเทคโนโลยี eBPF มาสร้าง **eBPF Rootkits** (เช่น TripleCross, Boopkit, BadBPF) เพื่อแอบซ่อนไฟล์ ซ่อนการเชื่อมต่อเครือข่าย หรือดักขโมย Credential โดยไม่ทิ้งร่องรอยใน log แบบเดิม

ในสัปดาห์นี้ เราจะสร้างเครื่องมือ **eBPF Integrity Auditor** เพื่อ:
1. ประเมินการตั้งค่าความปลอดภัยของเคอร์เนล (`kernel.unprivileged_bpf_disabled`, `net.core.bpf_jit_harden`)
2. ตรวจสอบและดักฟัง System Call `bpf()` ทุกครั้งที่มีการโหลดโปรแกรม eBPF หรือสร้าง BPF Map ใหม่ในหน่วยความจำ

---

## 1. วิธีการคอมไพล์และทดสอบ (Build & Test)

```bash
# คอมไพล์โปรแกรม
make generate && make build

# รันเพื่อประเมินสถานะ Hardening และเฝ้าระวัง bpf() syscall
make run
```

---

## 3. ผลการทดสอบจริง (Captured Test Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`)

```text
======================================================================
 eBPF Rootkit Detector & Integrity Scanner (sys_enter_bpf)
======================================================================
----------------------------------------------------------------------
 [1] Host eBPF Security & Hardening Posture Assessment
----------------------------------------------------------------------
  • kernel.unprivileged_bpf_disabled : 2 [SECURE / HARDENED]
  • net.core.bpf_jit_harden          : 0 [DEFAULT / UNHARDENED]
  • net.core.bpf_jit_enable          : 1
----------------------------------------------------------------------

2026/10/20 11:56:24 [INFO] Hooked tracepoint 'syscalls/sys_enter_bpf'.
2026/10/20 11:56:24 [INFO] Auditing all sys_bpf() calls and kernel modifications in real time...

TIME      PID    UID    COMM             BPF COMMAND              RISK
--------------------------------------------------------------------------------
11:56:25  64835  0      bpftool          BPF_MAP_CREATE           INFO
11:56:25  64835  0      bpftool          BPF_MAP_CREATE           INFO
11:56:25  64835  0      bpftool          BPF_MAP_CREATE           INFO

[INFO] Stopping BPF integrity auditor...
[SUCCESS] BPF Integrity Auditor stopped safely.
```
