# 🚀 eBPF Zero to Hero: จากศูนย์สู่เซียน eBPF
### หลักสูตรปฏิบัติการระบบเครือข่าย ความปลอดภัย และความสามารถในการสังเกตการณ์ระดับเคอร์เนล (Hands-on Kernel Engineering with Linux, C & Go)

ยินดีต้อนรับสู่คลังความรู้และโครงการปฏิบัติการ **eBPF (Extended Berkeley Packet Filter)** ฉบับสมบูรณ์ ออกแบบมาเพื่อเปลี่ยนวิศวกรซอฟต์แวร์ ผู้ดูแลระบบ (SysAdmin/SRE) และผู้เชี่ยวชาญด้านความปลอดภัย (Security Engineers) จากผู้เริ่มต้นสู่ระดับชำนาญการที่สามารถพัฒนาและดูแลระบบ eBPF บน Production ได้จริง

---

## 📚 แหล่งเรียนรู้หลักและสคริปต์สภาพแวดล้อม (Core References)

- 📖 **คู่มือตำราฉบับสมบูรณ์ (Master Textbook)**: [`docs/MASTER_STUDY_GUIDE.md`](docs/MASTER_STUDY_GUIDE.md) — เจาะลึก 6 บท ทฤษฎีระดับฮาร์ดแวร์ แผนภาพ ASCII โค้ด C/Go บรรทัดต่อบรรทัด และ Cheat Sheet ฉบับปฏิบัติการ
- ⚙️ **สคริปต์ติดตั้งสภาพแวดล้อมอัตโนมัติ**: [`scripts/setup_env.sh`](scripts/setup_env.sh) — Provisioning Ubuntu 24.04 LTS (Kernel 6.8+), ตรวจสอบ BTF, สร้าง `vmlinux.h` และตั้งค่า BPF LSM

---

## 🗺️ แผนที่การเรียนรู้ 12 สัปดาห์ (12-Week Curriculum Roadmap)

```
+----------------------------------------------------------------------------------------------------+
|                                    12-WEEK eBPF LEARNING ROADMAP                                   |
+----------------------------------------------------------------------------------------------------+
| เฟส 1: รากฐานระบบเครือข่ายและเคอร์เนล Linux (Network Foundation)                                       |
|  - Week 01: ผ่าโครงสร้าง Packet ระดับ Byte และการจำลองระบบเครือข่ายด้วย Network Namespaces         |
|  - Week 02: สำรวจเส้นทางข้อมูล Linux Network Data Path (RX Ring -> SoftIRQ -> sk_buff)             |
+----------------------------------------------------------------------------------------------------+
| เฟส 2: ก้าวแรกสู่ eBPF และด่านตรวจ Verifier (First Step into eBPF)                                  |
|  - Week 03: เครื่องมือวิเคราะห์เคอร์เนลเร่งด่วน: bpftool และ bpftrace One-Liners                    |
|  - Week 04: การสร้างเครื่องมือวิเคราะห์ระดับโปรดักชันด้วย BCC & Python                             |
+----------------------------------------------------------------------------------------------------+
| เฟส 3: หัวใจของ Modern eBPF และสถาปัตยกรรม CO-RE (Modern eBPF Core)                                 |
|  - Week 05: ยุคสมัยใหม่ของ eBPF: libbpf, BTF, vmlinux.h และการเขียน Go Control Plane (Cilium)       |
|  - Week 06: การบริหารจัดการหน่วยความจำ: eBPF Maps (Hash, LRU, Per-CPU) และการแก้ Race Conditions   |
+----------------------------------------------------------------------------------------------------+
| เฟส 4: ระบบเครือข่ายความเร็วสูงระดับ Wire-Speed (High-Speed Networking)                            |
|  - Week 07: ดักจับและคัดกรองแพ็กเก็ตความเร็วสูงด้วย XDP (eXpress Data Path) & Bounds Checking       |
|  - Week 08: การดัดแปลงแพ็กเก็ตและการทำ Load Balancer ด้วย TC (Traffic Control / cls_bpf)          |
+----------------------------------------------------------------------------------------------------+
| เฟส 5: ความปลอดภัยและการสังเกตการณ์เชิงลึก (Security & Observability)                               |
|  - Week 09: สตรีมเหตุการณ์ความเร็วสูงด้วย BPF Ring Buffer และการดักฟัง TLS ด้วย Uprobes           |
|  - Week 10: การรักษาความปลอดภัยเชิงรุกและบล็อกการโจมตีระดับเคอร์เนลด้วย BPF LSM                     |
+----------------------------------------------------------------------------------------------------+
| เฟส 6: โครงการประยุกต์ใช้งานจริงระดับโปรดักชัน (Production Capstone)                                 |
|  - Week 11: การรับมือ Verifier ขั้นสูง, การปรับแต่งประสิทธิภาพ และการส่ง Metrics สู่ Prometheus      |
|  - Week 12: โครงการจบ: ระบบป้องกันการบุกรุก eBPF IPS (Intrusion Prevention System) แบบเรียลไทม์    |
+----------------------------------------------------------------------------------------------------+
| เฟส 7: ความปลอดภัยขั้นสูงและการตรวจจับภัยคุกคามเคอร์เนล (Advanced Kernel Security & Fleet Defense)    |
|  - Week 13: วินิจฉัยแพ็กเก็ตสูญหายในเคอร์เนลด้วย Dropwatch (tracepoint:skb:kfree_skb)               |
|  - Week 14: ระบบความปลอดภัย Zero-Trust Socket Egress Control ด้วย cgroup/connect4                  |
|  - Week 15: ตรวจจับ Reverse Shell และ Web RCE ทันทีในเคอร์เนลด้วย task_struct real_parent          |
|  - Week 16: ตรวจจับมัลแวร์ eBPF Rootkits และประเมินความปลอดภัยเคอร์เนล (sys_enter_bpf Integrity)   |
+----------------------------------------------------------------------------------------------------+
```

---

## 📑 สารบัญห้องทดลองปฏิบัติการทั้ง 16 สัปดาห์ (Weekly Labs & Source Code Index)

| สัปดาห์ | หัวข้อปฏิบัติการ | เอกสารคู่มือ (Lab Guide) | โค้ดต้นฉบับและสคริปต์ (Source Code & Scripts) |
| :---: | :--- | :--- | :--- |
| **01** | Packet Inspection & Network Namespaces | [`week01/README.md`](phase1-network-foundation/week01-packet-netns/README.md) | • [`lab_netns.sh`](phase1-network-foundation/week01-packet-netns/lab_netns.sh)<br>• [`raw_sniffer.py`](phase1-network-foundation/week01-packet-netns/raw_sniffer.py) |
| **02** | Linux Bridge, Router & Network Data Path | [`week02/README.md`](phase1-network-foundation/week02-linux-net-stack/README.md) | • [`bridge_router_lab.sh`](phase1-network-foundation/week02-linux-net-stack/bridge_router_lab.sh) |
| **03** | Kernel Tracing with bpftool & bpftrace | [`week03/README.md`](phase2-first-step-ebpf/week03-bpftool-bpftrace/README.md) | • [`trace_exec_and_tcp.bt`](phase2-first-step-ebpf/week03-bpftool-bpftrace/trace_exec_and_tcp.bt) |
| **04** | Kernel Latency Observability with BCC & Python | [`week04/README.md`](phase2-first-step-ebpf/week04-bcc-python/README.md) | • [`tcp_v4_latency.py`](phase2-first-step-ebpf/week04-bcc-python/tcp_v4_latency.py) |
| **05** | Modern eBPF CO-RE & Pure Go Control Plane | [`week05/README.md`](phase3-modern-ebpf-core/week05-libbpf-cilium-go/README.md) | • [`counter.c`](phase3-modern-ebpf-core/week05-libbpf-cilium-go/counter.c)<br>• [`main.go`](phase3-modern-ebpf-core/week05-libbpf-cilium-go/main.go)<br>• [`Makefile`](phase3-modern-ebpf-core/week05-libbpf-cilium-go/Makefile)<br>• [`go.mod`](phase3-modern-ebpf-core/week05-libbpf-cilium-go/go.mod) |
| **06** | eBPF Maps Architecture & Race Condition Mitigation | [`week06/README.md`](phase3-modern-ebpf-core/week06-ebpf-maps/README.md) | • [`syscall_stats.c`](phase3-modern-ebpf-core/week06-ebpf-maps/syscall_stats.c)<br>• [`main.go`](phase3-modern-ebpf-core/week06-ebpf-maps/main.go)<br>• [`Makefile`](phase3-modern-ebpf-core/week06-ebpf-maps/Makefile)<br>• [`go.mod`](phase3-modern-ebpf-core/week06-ebpf-maps/go.mod) |
| **07** | High-Speed XDP Parsing & Bounds Checking | [`week07/README.md`](phase4-high-speed-networking/week07-xdp-parsing/README.md) | • [`xdp_firewall.c`](phase4-high-speed-networking/week07-xdp-parsing/xdp_firewall.c)<br>• [`main.go`](phase4-high-speed-networking/week07-xdp-parsing/main.go)<br>• [`Makefile`](phase4-high-speed-networking/week07-xdp-parsing/Makefile)<br>• [`go.mod`](phase4-high-speed-networking/week07-xdp-parsing/go.mod) |
| **08** | XDP Load Balancer & TC Egress Checksum Mangling | [`week08/README.md`](phase4-high-speed-networking/week08-tc-loadbalancer/README.md) | • [`xdp_lb.c`](phase4-high-speed-networking/week08-tc-loadbalancer/xdp_lb.c)<br>• [`tc_egress.c`](phase4-high-speed-networking/week08-tc-loadbalancer/tc_egress.c)<br>• [`main.go`](phase4-high-speed-networking/week08-tc-loadbalancer/main.go)<br>• [`Makefile`](phase4-high-speed-networking/week08-tc-loadbalancer/Makefile)<br>• [`go.mod`](phase4-high-speed-networking/week08-tc-loadbalancer/go.mod) |
| **09** | BPF Ring Buffer MPSC Streaming & TLS Uprobes | [`week09/README.md`](phase5-security-observability/week09-ringbuf-uprobes/README.md) | • [`ringbuf_events.c`](phase5-security-observability/week09-ringbuf-uprobes/ringbuf_events.c)<br>• [`main.go`](phase5-security-observability/week09-ringbuf-uprobes/main.go)<br>• [`Makefile`](phase5-security-observability/week09-ringbuf-uprobes/Makefile)<br>• [`go.mod`](phase5-security-observability/week09-ringbuf-uprobes/go.mod) |
| **10** | Proactive Kernel Security with BPF LSM | [`week10/README.md`](phase5-security-observability/week10-bpf-lsm/README.md) | • [`lsm_file_guard.c`](phase5-security-observability/week10-bpf-lsm/lsm_file_guard.c)<br>• [`main.go`](phase5-security-observability/week10-bpf-lsm/main.go)<br>• [`Makefile`](phase5-security-observability/week10-bpf-lsm/Makefile)<br>• [`go.mod`](phase5-security-observability/week10-bpf-lsm/go.mod) |
| **11** | Verifier Invariant Optimization & Prometheus Metrics | [`week11/README.md`](phase6-production-capstone/week11-verifier-prometheus/README.md) | • [`metrics_exporter.c`](phase6-production-capstone/week11-verifier-prometheus/metrics_exporter.c)<br>• [`main.go`](phase6-production-capstone/week11-verifier-prometheus/main.go)<br>• [`Makefile`](phase6-production-capstone/week11-verifier-prometheus/Makefile)<br>• [`go.mod`](phase6-production-capstone/week11-verifier-prometheus/go.mod) |
| **12** | Production Capstone: Autonomous eBPF IPS Engine | [`week12/README.md`](phase6-production-capstone/week12-capstone-ips/README.md) | • [`ips_kern.c`](phase6-production-capstone/week12-capstone-ips/bpf/ips_kern.c)<br>• [`ips-agent/main.go`](phase6-production-capstone/week12-capstone-ips/cmd/ips-agent/main.go)<br>• [`Makefile`](phase6-production-capstone/week12-capstone-ips/Makefile)<br>• [`go.mod`](phase6-production-capstone/week12-capstone-ips/go.mod) |
| **13** | Kernel Dropwatch & Packet Loss Diagnostics | [`week13/README.md`](phase7-advanced-security-observability/week13-kfree-skb-dropwatch/README.md) | • [`dropwatch.c`](phase7-advanced-security-observability/week13-kfree-skb-dropwatch/dropwatch.c)<br>• [`main.go`](phase7-advanced-security-observability/week13-kfree-skb-dropwatch/main.go)<br>• [`Makefile`](phase7-advanced-security-observability/week13-kfree-skb-dropwatch/Makefile)<br>• [`go.mod`](phase7-advanced-security-observability/week13-kfree-skb-dropwatch/go.mod) |
| **14** | Zero-Trust Socket Egress Control | [`week14/README.md`](phase7-advanced-security-observability/week14-cgroup-sock-addr/README.md) | • [`sock_enforce.c`](phase7-advanced-security-observability/week14-cgroup-sock-addr/sock_enforce.c)<br>• [`main.go`](phase7-advanced-security-observability/week14-cgroup-sock-addr/main.go)<br>• [`Makefile`](phase7-advanced-security-observability/week14-cgroup-sock-addr/Makefile)<br>• [`go.mod`](phase7-advanced-security-observability/week14-cgroup-sock-addr/go.mod) |
| **15** | Reverse Shell & Interactive Threat Guard | [`week15/README.md`](phase7-advanced-security-observability/week15-reverse-shell-guard/README.md) | • [`revshell_detect.c`](phase7-advanced-security-observability/week15-reverse-shell-guard/revshell_detect.c)<br>• [`main.go`](phase7-advanced-security-observability/week15-reverse-shell-guard/main.go)<br>• [`Makefile`](phase7-advanced-security-observability/week15-reverse-shell-guard/Makefile)<br>• [`go.mod`](phase7-advanced-security-observability/week15-reverse-shell-guard/go.mod) |
| **16** | eBPF Rootkit Detector & Integrity Scanner | [`week16/README.md`](phase7-advanced-security-observability/week16-ebpf-integrity-audit/README.md) | • [`bpf_audit.c`](phase7-advanced-security-observability/week16-ebpf-integrity-audit/bpf_audit.c)<br>• [`main.go`](phase7-advanced-security-observability/week16-ebpf-integrity-audit/main.go)<br>• [`Makefile`](phase7-advanced-security-observability/week16-ebpf-integrity-audit/Makefile)<br>• [`go.mod`](phase7-advanced-security-observability/week16-ebpf-integrity-audit/go.mod) |

---

## 📂 โครงสร้างไดเรกทอรีของโครงการ (Repository Structure)

```
.
├── docs/
│   └── MASTER_STUDY_GUIDE.md              # หนังสือคู่มือและทฤษฎีฉบับสมบูรณ์ 6 บท (ภาษาไทย)
├── scripts/
│   └── setup_env.sh                       # สคริปต์ติดตั้ง Toolchain และสภาพแวดล้อมอัตโนมัติ
├── phase1-network-foundation/
│   ├── week01-packet-netns/               # ปฏิบัติการระดับ Packet และ Network Namespaces
│   └── week02-linux-net-stack/            # จำลองและตรวจสอบ Linux Network Stack
├── phase2-first-step-ebpf/
│   ├── week03-bpftool-bpftrace/           # แบบฝึกหัด bpftool และสคริปต์ bpftrace
│   └── week04-bcc-python/                 # เครื่องมือติดตามเคอร์เนลด้วย BCC Python
├── phase3-modern-ebpf-core/
│   ├── week05-libbpf-cilium-go/           # โค้ด eBPF สมัยใหม่ด้วย libbpf และ Go
│   └── week06-ebpf-maps/                  # การใช้งาน Maps แบบต่างๆ และ Benchmark
├── phase4-high-speed-networking/
│   ├── week07-xdp-parsing/                # โปรแกรม XDP Packet Filter & Bounds Checking
│   └── week08-tc-loadbalancer/            # ระบบ Load Balancer ด้วย Traffic Control (TC)
├── phase5-security-observability/
│   ├── week09-ringbuf-uprobes/            # Ring Buffer สตรีม และการดักอ่าน Plaintext TLS
│   └── week10-bpf-lsm/                    # ไฟร์วอลล์ความปลอดภัยระดับเคอร์เนลด้วย BPF LSM
├── phase6-production-capstone/
│   ├── week11-verifier-prometheus/        # Prometheus Exporter ผสานรวม eBPF
│   └── week12-capstone-ips/               # โครงการจบ: Full Production-grade eBPF IPS Engine
├── phase7-advanced-security-observability/
│   ├── week13-kfree-skb-dropwatch/        # วินิจฉัยแพ็กเก็ตสูญหายในเคอร์เนลด้วย kfree_skb Dropwatch
│   ├── week14-cgroup-sock-addr/           # นโยบาย Zero-Trust Egress Socket Control ด้วย cgroup/connect4
│   ├── week15-reverse-shell-guard/        # ตรวจจับ Reverse Shell และ Web RCE ผ่าน task_struct real_parent
│   └── week16-ebpf-integrity-audit/       # ตรวจจับมัลแวร์ eBPF Rootkits และประเมินความปลอดภัยเคอร์เนล
├── .gitignore                             # การยกเว้นไฟล์ Binary, Object, และ Cache
└── README.md                              # เอกสารแนะนำโครงการนี้
```

---

## 🛠️ ความต้องการของระบบและการติดตั้ง (Prerequisites & Setup)

### ความต้องการของระบบ (System Requirements):
- **ระบบปฏิบัติการ**: Ubuntu 24.04 LTS (หรือ Linux Kernel 6.8+ เป็นต้นไป)
- **สิทธิ์การใช้งาน**: Root หรือ Sudo Privileges
- **คอมไพเลอร์และเครื่องมือ**: Clang/LLVM 16+, Go 1.21+, Python 3.10+, iproute2, bpftool, bpftrace

### คำสั่งเริ่มต้นติดตั้งสภาพแวดล้อมอัตโนมัติ:
รันสคริปต์ติดตั้งระบบที่เตรียมไว้ในไดเรกทอรี `scripts/`:

```bash
# 1. ให้สิทธิ์รันสคริปต์
chmod +x scripts/setup_env.sh

# 2. รันสคริปต์ด้วย sudo เพื่อติดตั้ง Dependencies และสร้าง vmlinux.h
sudo ./scripts/setup_env.sh
```

สคริปต์จะทำการ:
1. ตรวจสอบเวอร์ชันเคอร์เนลและการเปิดใช้งาน BTF (`/sys/kernel/btf/vmlinux`)
2. ติดตั้งคอมไพเลอร์ `clang`, `llvm`, `libbpf-dev`, `bpftool`, `bpftrace`, `golang-go`, `python3-bpfcc`
3. สกัดโครงสร้างเคอร์เนลออกมาเป็นไฟล์ `vmlinux.h` เพื่อใช้ในการพัฒนาแบบ CO-RE
4. ตรวจสอบสถานะการรองรับ BPF LSM ในเคอร์เนล

---

## ⚡ เริ่มต้นอย่างรวดเร็ว (Quickstart Guide)

1. **ศึกษาบทเรียนทฤษฎี**: อ่าน [docs/MASTER_STUDY_GUIDE.md](docs/MASTER_STUDY_GUIDE.md) เพื่อทำความเข้าใจเรื่อง Byte Ordering, Pointer Bounds Checking และ BPF Verifier
2. **เข้าสู่บทเรียนสัปดาห์ที่ต้องการ**: เข้าไปยังโฟลเดอร์ของแต่ละสัปดาห์ (เช่น `phase4-high-speed-networking/week07-xdp-parsing`)
3. **คอมไพล์และทดสอบ**: ทำตามขั้นตอนในแบบฝึกหัดของแต่ละสัปดาห์ เช่น:
   ```bash
   cd phase4-high-speed-networking/week07-xdp-parsing
   make
   sudo ./bin/xdp_firewall -iface lo -block 192.168.1.100
   ```

---

## 📜 ข้อกำหนดด้านความปลอดภัยและสัญญาอนุญาต (License)
โค้ดโปรแกรมเคอร์เนล eBPF ในคลังข้อมูลนี้เผยแพร่ภายใต้สัญญาอนุญาต **GPL-2.0** เพื่อให้สามารถเรียกใช้งาน Kernel BPF Helper Functions ได้อย่างสมบูรณ์ โค้ดฝั่ง User Space เผยแพร่ภายใต้ **MIT License**