# 🚀 eBPF Zero to Hero: จากศูนย์สู่เซียน eBPF
### หลักสูตรปฏิบัติการระบบเครือข่าย ความปลอดภัย และความสามารถในการสังเกตการณ์ระดับเคอร์เนล (Hands-on Kernel Engineering with Linux, C & Go)

ยินดีต้อนรับสู่คลังความรู้และโครงการปฏิบัติการ **eBPF (Extended Berkeley Packet Filter)** ฉบับสมบูรณ์ ออกแบบมาเพื่อเปลี่ยนวิศวกรซอฟต์แวร์ ผู้ดูแลระบบ (SysAdmin/SRE) และผู้เชี่ยวชาญด้านความปลอดภัย (Security Engineers) จากผู้เริ่มต้นสู่ระดับชำนาญการที่สามารถพัฒนาและดูแลระบบ eBPF บน Production ได้จริง

---

## 📚 แหล่งเรียนรู้หลักและสคริปต์สภาพแวดล้อม (Core References)

- 📖 **คู่มือตำราฉบับสมบูรณ์ (Master Textbook)**: [`docs/MASTER_STUDY_GUIDE.md`](docs/MASTER_STUDY_GUIDE.md) — เจาะลึก 10 บท (ครบทุกเฟส) ทฤษฎีระดับฮาร์ดแวร์ แผนภาพ ASCII โค้ด C/Go บรรทัดต่อบรรทัด และ Cheat Sheet ฉบับปฏิบัติการ
- ⚙️ **สคริปต์ติดตั้งสภาพแวดล้อมอัตโนมัติ**: [`scripts/setup_env.sh`](scripts/setup_env.sh) — Provisioning Ubuntu 26.04 LTS (Kernel 7.0+, แพลตฟอร์มหลัก) / 24.04 LTS (Kernel 6.8, Best-effort), ตรวจสอบ BTF, สร้าง `vmlinux.h` และตั้งค่า BPF LSM

---

## 🗺️ แผนที่การเรียนรู้ 10 เฟส รวม 23 สัปดาห์ (Complete 10-Phase eBPF Curriculum Roadmap)

```
+----------------------------------------------------------------------------------------------------+
|                                    23-WEEK eBPF LEARNING ROADMAP                                   |
+----------------------------------------------------------------------------------------------------+
| เฟส 01: รากฐานระบบเครือข่ายและเคอร์เนล Linux (Network Foundation)                                       |
|  - Week 01: ผ่าโครงสร้าง Packet ระดับ Byte และการจำลองระบบเครือข่ายด้วย Network Namespaces         |
|  - Week 02: สำรวจเส้นทางข้อมูล Linux Network Data Path (RX Ring -> SoftIRQ -> sk_buff)             |
+----------------------------------------------------------------------------------------------------+
| เฟส 02: ก้าวแรกสู่ eBPF และด่านตรวจ Verifier (First Step into eBPF)                                  |
|  - Week 03: เครื่องมือวิเคราะห์เคอร์เนลเร่งด่วน: bpftool และ bpftrace One-Liners                    |
|  - Week 04: การสร้างเครื่องมือวิเคราะห์ระดับโปรดักชันด้วย BCC & Python                             |
+----------------------------------------------------------------------------------------------------+
| เฟส 03: หัวใจของ Modern eBPF และสถาปัตยกรรม CO-RE (Modern eBPF Core)                                 |
|  - Week 05: ยุคสมัยใหม่ของ eBPF: libbpf, BTF, vmlinux.h และการเขียน Go Control Plane (Cilium)       |
|  - Week 06: การบริหารจัดการหน่วยความจำ: eBPF Maps (Hash, LRU, Per-CPU) และการแก้ Race Conditions   |
+----------------------------------------------------------------------------------------------------+
| เฟส 04: ระบบเครือข่ายความเร็วสูงระดับ Wire-Speed (High-Speed Networking)                            |
|  - Week 07: ดักจับและคัดกรองแพ็กเก็ตความเร็วสูงด้วย XDP (eXpress Data Path) & Bounds Checking       |
|  - Week 08: การดัดแปลงแพ็กเก็ตและการทำ Load Balancer ด้วย TC (Traffic Control / cls_bpf)          |
+----------------------------------------------------------------------------------------------------+
| เฟส 05: ความปลอดภัยและการสังเกตการณ์เชิงลึก (Security & Observability)                               |
|  - Week 09: สตรีมเหตุการณ์ความเร็วสูงด้วย BPF Ring Buffer และการดักฟัง TLS ด้วย Uprobes           |
|  - Week 10: การรักษาความปลอดภัยเชิงรุกและบล็อกการโจมตีระดับเคอร์เนลด้วย BPF LSM                     |
+----------------------------------------------------------------------------------------------------+
| เฟส 06: โครงการประยุกต์ใช้งานจริงระดับโปรดักชัน (Production Capstone)                                 |
|  - Week 11: การรับมือ Verifier ขั้นสูง, การปรับแต่งประสิทธิภาพ และการส่ง Metrics สู่ Prometheus      |
|  - Week 12: โครงการจบ: ระบบป้องกันการบุกรุก eBPF IPS (Intrusion Prevention System) แบบเรียลไทม์    |
+----------------------------------------------------------------------------------------------------+
| เฟส 07: ความปลอดภัยขั้นสูงและการตรวจจับภัยคุกคามเคอร์เนล (Advanced Kernel Security & Fleet Defense)    |
|  - Week 13: วินิจฉัยแพ็กเก็ตสูญหายในเคอร์เนลด้วย Dropwatch (tracepoint:skb:kfree_skb)               |
|  - Week 14: ระบบความปลอดภัย Zero-Trust Socket Egress Control ด้วย cgroup/connect4                  |
|  - Week 15: ตรวจจับ Reverse Shell และ Web RCE ทันทีในเคอร์เนลด้วย task_struct real_parent          |
|  - Week 16: ตรวจจับมัลแวร์ eBPF Rootkits และประเมินความปลอดภัยเคอร์เนล (fentry/__sys_bpf Integrity)|
+----------------------------------------------------------------------------------------------------+
| เฟส 08: การวัดประสิทธิภาพระบบ การแกะรอย Stack และการวิเคราะห์ฮาร์ดแวร์ (System Performance)          |
|  - Week 17: สร้าง Storage I/O Latency Log2 Histogram (biolatency: block_rq_issue/complete)         |
|  - Week 18: On-CPU Profiler & Kernel Call Stack Unwinding (Flamegraph Profiling ด้วย perf_event)   |
|  - Week 19: เฝ้าระวัง Memory Page Faults และดักจับ OOM Killer ทันทีในเคอร์เนล (oom:mark_victim)     |
+----------------------------------------------------------------------------------------------------+
| เฟส 09: การเร่งความเร็ว Socket และสถาปัตยกรรม Kernel Bypass (Socket Acceleration & AF_XDP)          |
|  - Week 20: เร่งความเร็ว Local TCP ด้วย Sockops และ sk_msg Socket Bypass (ข้าม TCP/IP Stack)        |
|  - Week 21: AF_XDP (XSK) Kernel-Bypass Packet Redirect ด้วย UMEM + BPF_MAP_TYPE_XSKMAP               |
+----------------------------------------------------------------------------------------------------+
| เฟส 10: เทคโนโลยี eBPF ยุคใหม่ระดับแนวหน้า (Cutting-Edge Modern eBPF Technologies)                 |
|  - Week 22: BPF Trampoline (fentry / fexit) ดักฟังฟังก์ชันเคอร์เนลแบบ Low-Overhead (เทียบกับ kprobe)  |
|  - Week 23: BPF Task Iterators (bpf_iter_task) ท่องโครงสร้างเคอร์เนลโดยตรง ไม่ง้อ /proc             |
+----------------------------------------------------------------------------------------------------+
```

---

## 📑 สารบัญห้องทดลองปฏิบัติการครบทั้ง 23 สัปดาห์ (Weekly Labs & Source Code Index)

| สัปดาห์ | หัวข้อปฏิบัติการ | เอกสารคู่มือ (Lab Guide) | โค้ดต้นฉบับและสคริปต์ (Source Code & Scripts) |
| :---: | :--- | :--- | :--- |
| **01** | Packet Inspection & Network Namespaces | [`week01/README.md`](phase01-network-foundation/week01-packet-netns/README.md) | • [`lab_netns.sh`](phase01-network-foundation/week01-packet-netns/lab_netns.sh)<br>• [`raw_sniffer.py`](phase01-network-foundation/week01-packet-netns/raw_sniffer.py) |
| **02** | Linux Bridge, Router & Network Data Path | [`week02/README.md`](phase01-network-foundation/week02-linux-net-stack/README.md) | • [`bridge_router_lab.sh`](phase01-network-foundation/week02-linux-net-stack/bridge_router_lab.sh) |
| **03** | Kernel Tracing with bpftool & bpftrace | [`week03/README.md`](phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) | • [`trace_exec_and_tcp.bt`](phase02-first-step-ebpf/week03-bpftool-bpftrace/trace_exec_and_tcp.bt) |
| **04** | Kernel Latency Observability with BCC & Python | [`week04/README.md`](phase02-first-step-ebpf/week04-bcc-python/README.md) | • [`tcp_v4_latency.py`](phase02-first-step-ebpf/week04-bcc-python/tcp_v4_latency.py) |
| **05** | Modern eBPF CO-RE & Pure Go Control Plane | [`week05/README.md`](phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) | • [`counter.c`](phase03-modern-ebpf-core/week05-libbpf-cilium-go/counter.c)<br>• [`main.go`](phase03-modern-ebpf-core/week05-libbpf-cilium-go/main.go)<br>• [`Makefile`](phase03-modern-ebpf-core/week05-libbpf-cilium-go/Makefile)<br>• [`go.mod`](phase03-modern-ebpf-core/week05-libbpf-cilium-go/go.mod) |
| **06** | eBPF Maps Architecture & Race Condition Mitigation | [`week06/README.md`](phase03-modern-ebpf-core/week06-ebpf-maps/README.md) | • [`syscall_stats.c`](phase03-modern-ebpf-core/week06-ebpf-maps/syscall_stats.c)<br>• [`main.go`](phase03-modern-ebpf-core/week06-ebpf-maps/main.go)<br>• [`Makefile`](phase03-modern-ebpf-core/week06-ebpf-maps/Makefile)<br>• [`go.mod`](phase03-modern-ebpf-core/week06-ebpf-maps/go.mod) |
| **07** | High-Speed XDP Parsing & Bounds Checking | [`week07/README.md`](phase04-high-speed-networking/week07-xdp-parsing/README.md) | • [`xdp_firewall.c`](phase04-high-speed-networking/week07-xdp-parsing/xdp_firewall.c)<br>• [`main.go`](phase04-high-speed-networking/week07-xdp-parsing/main.go)<br>• [`main_test.go`](phase04-high-speed-networking/week07-xdp-parsing/main_test.go)<br>• [`Makefile`](phase04-high-speed-networking/week07-xdp-parsing/Makefile)<br>• [`go.mod`](phase04-high-speed-networking/week07-xdp-parsing/go.mod) |
| **08** | XDP Load Balancer & TC Egress Checksum Mangling | [`week08/README.md`](phase04-high-speed-networking/week08-tc-loadbalancer/README.md) | • [`xdp_lb.c`](phase04-high-speed-networking/week08-tc-loadbalancer/xdp_lb.c)<br>• [`tc_egress.c`](phase04-high-speed-networking/week08-tc-loadbalancer/tc_egress.c)<br>• [`main.go`](phase04-high-speed-networking/week08-tc-loadbalancer/main.go)<br>• [`main_test.go`](phase04-high-speed-networking/week08-tc-loadbalancer/main_test.go)<br>• [`Makefile`](phase04-high-speed-networking/week08-tc-loadbalancer/Makefile)<br>• [`go.mod`](phase04-high-speed-networking/week08-tc-loadbalancer/go.mod) |
| **09** | BPF Ring Buffer MPSC Streaming & TLS Uprobes | [`week09/README.md`](phase05-security-observability/week09-ringbuf-uprobes/README.md) | • [`ringbuf_events.c`](phase05-security-observability/week09-ringbuf-uprobes/ringbuf_events.c)<br>• [`main.go`](phase05-security-observability/week09-ringbuf-uprobes/main.go)<br>• [`Makefile`](phase05-security-observability/week09-ringbuf-uprobes/Makefile)<br>• [`go.mod`](phase05-security-observability/week09-ringbuf-uprobes/go.mod) |
| **10** | Proactive Kernel Security with BPF LSM | [`week10/README.md`](phase05-security-observability/week10-bpf-lsm/README.md) | • [`lsm_file_guard.c`](phase05-security-observability/week10-bpf-lsm/lsm_file_guard.c)<br>• [`main.go`](phase05-security-observability/week10-bpf-lsm/main.go)<br>• [`Makefile`](phase05-security-observability/week10-bpf-lsm/Makefile)<br>• [`go.mod`](phase05-security-observability/week10-bpf-lsm/go.mod) |
| **11** | Verifier Invariant Optimization & Prometheus Metrics | [`week11/README.md`](phase06-production-capstone/week11-verifier-prometheus/README.md) | • [`metrics_exporter.c`](phase06-production-capstone/week11-verifier-prometheus/metrics_exporter.c)<br>• [`main.go`](phase06-production-capstone/week11-verifier-prometheus/main.go)<br>• [`metrics_test.go`](phase06-production-capstone/week11-verifier-prometheus/metrics_test.go)<br>• [`verifier_fail/verifier_fail.c`](phase06-production-capstone/week11-verifier-prometheus/verifier_fail/verifier_fail.c)<br>• [`verifier_fail/main.go`](phase06-production-capstone/week11-verifier-prometheus/verifier_fail/main.go)<br>• [`Makefile`](phase06-production-capstone/week11-verifier-prometheus/Makefile)<br>• [`go.mod`](phase06-production-capstone/week11-verifier-prometheus/go.mod) |
| **12** | Production Capstone: Autonomous eBPF IPS Engine | [`week12/README.md`](phase06-production-capstone/week12-capstone-ips/README.md) | • [`ips_kern.c`](phase06-production-capstone/week12-capstone-ips/bpf/ips_kern.c)<br>• [`ips-agent/main.go`](phase06-production-capstone/week12-capstone-ips/cmd/ips-agent/main.go)<br>• [`cmd/ips-agent/ips_test.go`](phase06-production-capstone/week12-capstone-ips/cmd/ips-agent/ips_test.go)<br>• [`Makefile`](phase06-production-capstone/week12-capstone-ips/Makefile)<br>• [`go.mod`](phase06-production-capstone/week12-capstone-ips/go.mod) |
| **13** | Kernel Dropwatch & Packet Loss Diagnostics | [`week13/README.md`](phase07-advanced-security-observability/week13-kfree-skb-dropwatch/README.md) | • [`dropwatch.c`](phase07-advanced-security-observability/week13-kfree-skb-dropwatch/dropwatch.c)<br>• [`main.go`](phase07-advanced-security-observability/week13-kfree-skb-dropwatch/main.go)<br>• [`Makefile`](phase07-advanced-security-observability/week13-kfree-skb-dropwatch/Makefile)<br>• [`go.mod`](phase07-advanced-security-observability/week13-kfree-skb-dropwatch/go.mod) |
| **14** | Zero-Trust Socket Egress Control | [`week14/README.md`](phase07-advanced-security-observability/week14-cgroup-sock-addr/README.md) | • [`sock_enforce.c`](phase07-advanced-security-observability/week14-cgroup-sock-addr/sock_enforce.c)<br>• [`main.go`](phase07-advanced-security-observability/week14-cgroup-sock-addr/main.go)<br>• [`Makefile`](phase07-advanced-security-observability/week14-cgroup-sock-addr/Makefile)<br>• [`go.mod`](phase07-advanced-security-observability/week14-cgroup-sock-addr/go.mod) |
| **15** | Reverse Shell & Interactive Threat Guard | [`week15/README.md`](phase07-advanced-security-observability/week15-reverse-shell-guard/README.md) | • [`revshell_detect.c`](phase07-advanced-security-observability/week15-reverse-shell-guard/revshell_detect.c)<br>• [`main.go`](phase07-advanced-security-observability/week15-reverse-shell-guard/main.go)<br>• [`Makefile`](phase07-advanced-security-observability/week15-reverse-shell-guard/Makefile)<br>• [`go.mod`](phase07-advanced-security-observability/week15-reverse-shell-guard/go.mod) |
| **16** | eBPF Rootkit Detector & Integrity Scanner | [`week16/README.md`](phase07-advanced-security-observability/week16-ebpf-integrity-audit/README.md) | • [`bpf_audit.c`](phase07-advanced-security-observability/week16-ebpf-integrity-audit/bpf_audit.c)<br>• [`main.go`](phase07-advanced-security-observability/week16-ebpf-integrity-audit/main.go)<br>• [`Makefile`](phase07-advanced-security-observability/week16-ebpf-integrity-audit/Makefile)<br>• [`go.mod`](phase07-advanced-security-observability/week16-ebpf-integrity-audit/go.mod) |
| **17** | Block I/O Latency Histogram (biolatency) | [`week17/README.md`](phase08-system-performance-observability/week17-block-io-biolatency/README.md) | • [`biolatency.c`](phase08-system-performance-observability/week17-block-io-biolatency/biolatency.c)<br>• [`main.go`](phase08-system-performance-observability/week17-block-io-biolatency/main.go)<br>• [`Makefile`](phase08-system-performance-observability/week17-block-io-biolatency/Makefile)<br>• [`go.mod`](phase08-system-performance-observability/week17-block-io-biolatency/go.mod) |
| **18** | On-CPU Profiler & Call Stack Unwinding | [`week18/README.md`](phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md) | • [`cpu_stacks.c`](phase08-system-performance-observability/week18-cpu-profiler-stacks/cpu_stacks.c)<br>• [`main.go`](phase08-system-performance-observability/week18-cpu-profiler-stacks/main.go)<br>• [`usersyms.go`](phase08-system-performance-observability/week18-cpu-profiler-stacks/usersyms.go)<br>• [`workload/busy.c`](phase08-system-performance-observability/week18-cpu-profiler-stacks/workload/busy.c)<br>• [`flamegraph.py`](phase08-system-performance-observability/week18-cpu-profiler-stacks/flamegraph.py)<br>• [`Makefile`](phase08-system-performance-observability/week18-cpu-profiler-stacks/Makefile)<br>• [`go.mod`](phase08-system-performance-observability/week18-cpu-profiler-stacks/go.mod) |
| **19** | Memory Page Faults & OOM Victim Watcher | [`week19/README.md`](phase08-system-performance-observability/week19-memory-oom-watcher/README.md) | • [`oom_watcher.c`](phase08-system-performance-observability/week19-memory-oom-watcher/oom_watcher.c)<br>• [`main.go`](phase08-system-performance-observability/week19-memory-oom-watcher/main.go)<br>• [`Makefile`](phase08-system-performance-observability/week19-memory-oom-watcher/Makefile)<br>• [`go.mod`](phase08-system-performance-observability/week19-memory-oom-watcher/go.mod) |
| **20** | TCP Sockops & sk_msg Fastpath Bypass | [`week20/README.md`](phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/README.md) | • [`sockops.c`](phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/sockops.c)<br>• [`main.go`](phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/main.go)<br>• [`main_test.go`](phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/main_test.go)<br>• [`cmd/tcpbench/main.go`](phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/cmd/tcpbench/main.go)<br>• [`Makefile`](phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/Makefile)<br>• [`go.mod`](phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/go.mod) |
| **21** | AF_XDP Kernel-Bypass Redirect (UMEM & XSKMAP) | [`week21/README.md`](phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) | • [`xsk_kern.c`](phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/xsk_kern.c)<br>• [`main.go`](phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/main.go)<br>• [`xsk.go`](phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/xsk.go)<br>• [`main_test.go`](phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/main_test.go)<br>• [`Makefile`](phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/Makefile)<br>• [`go.mod`](phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/go.mod) |
| **22** | Modern BPF Trampoline (fentry / fexit) | [`week22/README.md`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/README.md) | • [`trampoline.c`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/trampoline.c)<br>• [`main.go`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/main.go)<br>• [`main_test.go`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/main_test.go)<br>• [`bench/openbench.c`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/bench/openbench.c)<br>• [`bench/run_bench.sh`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/bench/run_bench.sh)<br>• [`Makefile`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/Makefile)<br>• [`go.mod`](phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/go.mod) |
| **23** | Kernel Traversal with BPF Iterators | [`week23/README.md`](phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/README.md) | • [`task_iter.c`](phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/task_iter.c)<br>• [`main.go`](phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/main.go)<br>• [`main_test.go`](phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/main_test.go)<br>• [`Makefile`](phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/Makefile)<br>• [`go.mod`](phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/go.mod) |

---

## 📂 โครงสร้างไดเรกทอรีของโครงการ (Repository Structure)

```
.
├── docs/
│   └── MASTER_STUDY_GUIDE.md              # หนังสือคู่มือและทฤษฎีฉบับสมบูรณ์ 10 บท (ภาษาไทย)
├── scripts/
│   └── setup_env.sh                       # สคริปต์ติดตั้ง Toolchain และสภาพแวดล้อมอัตโนมัติ
├── phase01-network-foundation/
│   ├── week01-packet-netns/               # ปฏิบัติการระดับ Packet และ Network Namespaces
│   └── week02-linux-net-stack/            # จำลองและตรวจสอบ Linux Network Stack
├── phase02-first-step-ebpf/
│   ├── week03-bpftool-bpftrace/           # แบบฝึกหัด bpftool และสคริปต์ bpftrace
│   └── week04-bcc-python/                 # เครื่องมือติดตามเคอร์เนลด้วย BCC Python
├── phase03-modern-ebpf-core/
│   ├── week05-libbpf-cilium-go/           # โค้ด eBPF สมัยใหม่ด้วย libbpf และ Go
│   └── week06-ebpf-maps/                  # การใช้งาน Maps แบบต่างๆ และ Benchmark
├── phase04-high-speed-networking/
│   ├── week07-xdp-parsing/                # โปรแกรม XDP Packet Filter & Bounds Checking
│   └── week08-tc-loadbalancer/            # ระบบ Load Balancer ด้วย Traffic Control (TC)
├── phase05-security-observability/
│   ├── week09-ringbuf-uprobes/            # Ring Buffer สตรีม และการดักอ่าน Plaintext TLS
│   └── week10-bpf-lsm/                    # ไฟร์วอลล์ความปลอดภัยระดับเคอร์เนลด้วย BPF LSM
├── phase06-production-capstone/
│   ├── week11-verifier-prometheus/        # Prometheus Exporter ผสานรวม eBPF
│   └── week12-capstone-ips/               # โครงการจบ: Full Production-grade eBPF IPS Engine
├── phase07-advanced-security-observability/
│   ├── week13-kfree-skb-dropwatch/        # วินิจฉัยแพ็กเก็ตสูญหายในเคอร์เนลด้วย kfree_skb Dropwatch
│   ├── week14-cgroup-sock-addr/           # นโยบาย Zero-Trust Egress Socket Control ด้วย cgroup/connect4
│   ├── week15-reverse-shell-guard/        # ตรวจจับ Reverse Shell และ Web RCE ผ่าน task_struct real_parent
│   └── week16-ebpf-integrity-audit/       # ตรวจจับมัลแวร์ eBPF Rootkits และประเมินความปลอดภัยเคอร์เนล
├── phase08-system-performance-observability/
│   ├── week17-block-io-biolatency/        # วิเคราะห์ Storage I/O Latency Histogram (biolatency)
│   ├── week18-cpu-profiler-stacks/        # CPU Profiler ถอดรหัส Kernel Call Stack (Flamegraph-ready)
│   └── week19-memory-oom-watcher/         # ตรวจจับ Page Faults และเฝ้าระวัง OOM Killer แบบเรียลไทม์
├── phase09-high-throughput-socket-acceleration/
│   ├── week20-tcp-sockops-bypass/         # เร่งความเร็ว Local TCP ด้วย Sockops และ sk_msg Fastpath
│   └── week21-af-xdp-redirect/            # Kernel-Bypass แพ็กเก็ตด้วย AF_XDP Socket (UMEM + XSKMAP)
├── phase10-cutting-edge-ebpf-technologies/
│   ├── week22-fentry-fexit-trampoline/    # เทคโนโลยี BPF Trampoline (fentry/fexit) Zero-Overhead Tracing
│   └── week23-bpf-iterators/              # BPF Iterators (bpf_iter_task) ท่องเคอร์เนลโดยไม่พึ่ง /proc
├── .github/workflows/ci.yml               # CI: build ทุกแล็บ + รัน BPF_PROG_TEST_RUN tests บน GitHub Actions
├── LICENSES/                              # ตัวบทสัญญาอนุญาต GPL-2.0 และ MIT
├── .gitignore                             # การยกเว้นไฟล์ Binary, Object, และ Cache
├── LICENSE                                # สรุปสัญญาอนุญาตแยกตามส่วนประกอบ (GPL-2.0 / MIT)
├── Makefile                               # Build / Test ทุกแล็บในคำสั่งเดียว (make, make test, make week07)
└── README.md                              # เอกสารแนะนำโครงการนี้
```

---

## 🛠️ ความต้องการของระบบและการติดตั้ง (Prerequisites & Setup)

### ความต้องการของระบบ (System Requirements):
- **ระบบปฏิบัติการ (Operating System)**: **Ubuntu 26.04 LTS (Linux Kernel 7.0+) เป็นแพลตฟอร์มหลัก** ทุกแล็บ ผลการทดลอง และ Unit Tests ทดสอบบน `Linux 7.0.0-38-generic x86_64` แล้ว ส่วน Ubuntu 24.04 LTS (Kernel 6.8) รองรับแบบ Best-effort ผ่าน CO-RE แต่ยังไม่ได้ทดสอบจริงทุกแล็บ
- **สิทธิ์การใช้งาน (Privileges)**: Root หรือ Sudo Privileges (หรือ Fine-grained Linux Capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_ADMIN`)
- **คอมไพเลอร์และเครื่องมือพัฒนา (Compilers & Toolchains)**:
  - **Clang / LLVM**: 16+ ขึ้นไป (แนะนำเวอร์ชัน 18+ หรือ 21+) พร้อมติดตั้ง `gcc-multilib` และ Multiarch Headers (`/usr/include/asm`)
  - **Go**: Go 1.22+ หรือ Go 1.26+ (รองรับ pure Go eBPF control planes ผ่าน `github.com/cilium/ebpf`)
  - **Python**: Python 3.10+ / 3.12+ / 3.14+ พร้อมโมดูล `python3-bpfcc` สำหรับแล็บ BCC
  - **เครื่องมือจัดการเครือข่ายและการดีบักเคอร์เนล**: `iproute2` (`ip`, `tc`), `bpftool` (v7.0+), `bpftrace`, `libbpf-dev`, `tcpdump`, `netcat`
- **ฟีเจอร์ระดับเคอร์เนล (Required Kernel Subsystems)**:
  - **BTF (BPF Type Format)**: เปิดใช้งานที่ `/sys/kernel/btf/vmlinux` สำหรับการสกัดโครงสร้าง `vmlinux.h` แบบ CO-RE
  - **cgroup v2**: เมานต์อยู่ที่ `/sys/fs/cgroup` สำหรับแล็บ Socket Enforcement (`cgroup/connect4`) และ TCP Sockops Acceleration
  - **BPF Trampoline & Iterators**: รองรับ Kernel Trampoline (`fentry`/`fexit`) และ BPF Task Iterators (`CONFIG_BPF_TRAMPOLINE=y`)

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
2. **เข้าสู่บทเรียนสัปดาห์ที่ต้องการ**: เข้าไปยังโฟลเดอร์ของแต่ละสัปดาห์ (เช่น `phase04-high-speed-networking/week07-xdp-parsing`)
3. **คอมไพล์และทดสอบ**: ทำตามขั้นตอนในแบบฝึกหัดของแต่ละสัปดาห์ เช่น:
   ```bash
   cd phase04-high-speed-networking/week07-xdp-parsing
   make
   sudo ./bin/xdp-firewall -iface lo -block-ip 192.168.1.100
   ```
4. **ทำแบบฝึกหัดท้ายบท**: ทุกสัปดาห์มีหัวข้อ "แบบฝึกหัดท้ายบท (Exercises)" แบ่ง 3 ระดับ (พื้นฐาน / ปานกลาง / ท้าทาย) อยู่ท้าย README ของสัปดาห์นั้น

### Build และ Test ทุกแล็บจาก Root ของ Repository

```bash
make              # สร้าง vmlinux.h (ถ้ายังไม่มี) แล้ว go generate + go build ทุกแล็บ
make test         # รัน Unit Tests ด้วย BPF_PROG_TEST_RUN (ต้องใช้ sudo) ในแล็บที่มีชุดทดสอบ
make week07       # build เฉพาะสัปดาห์ที่ 7
make week07-test  # test เฉพาะสัปดาห์ที่ 7
make clean        # ลบไฟล์ที่ generate และไบนารีทั้งหมด
```

> Unit Tests ใช้ `BPF_PROG_TEST_RUN` ป้อนแพ็กเก็ตที่สร้างขึ้นเองเข้าโปรแกรม eBPF โดยตรงแล้วตรวจผลลัพธ์ (เช่น `XDP_DROP` / `XDP_PASS`) โดยไม่ต้องผูกโปรแกรมเข้ากับการ์ดเครือข่ายจริง จึงรันใน CI ได้ และใช้เป็นเครื่องมือตรวจงานนักศึกษาอัตโนมัติได้ด้วย ทุกครั้งที่ push ขึ้น `main` GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) จะ build ทุกแล็บและรันชุดทดสอบบน GitHub-hosted Runner (Ubuntu 24.04) เป็นการตรวจความเข้ากันได้ข้ามเวอร์ชันเคอร์เนลของ CO-RE เพิ่มเติม ส่วนการทดสอบหลักให้รัน `make test` บนเครื่อง Linux 7.0

---

## 📜 ข้อกำหนดด้านความปลอดภัยและสัญญาอนุญาต (License)
โค้ดโปรแกรมเคอร์เนล eBPF ในคลังข้อมูลนี้เผยแพร่ภายใต้สัญญาอนุญาต **GPL-2.0** เพื่อให้สามารถเรียกใช้งาน Kernel BPF Helper Functions ได้อย่างสมบูรณ์ โค้ดฝั่ง User Space สคริปต์ และเอกสารเผยแพร่ภายใต้ **MIT License** รายละเอียดดูที่ [`LICENSE`](LICENSE) และตัวบทเต็มใน [`LICENSES/`](LICENSES/)

> ⚠️ **ข้อกำหนดด้านจริยธรรม**: แล็บด้านความปลอดภัย (เช่น การดักอ่าน TLS plaintext ใน Week 09, การจำลอง Reverse Shell ใน Week 15) ให้ทดลองบนเครื่องหรือ VM ของตนเอง หรือระบบที่ได้รับอนุญาตเป็นลายลักษณ์อักษรเท่านั้น