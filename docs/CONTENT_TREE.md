# 🌳 แผนผังเนื้อหาทั้งหมด (Course Content Tree)

แผนผังต้นไม้ของหลักสูตร **eBPF Zero to Hero** ทั้งหมด เริ่มจากภาพรวม 11 เฟส / 26 สัปดาห์ แล้วแตกรายละเอียดของแต่ละเฟสว่าแต่ละสัปดาห์ใช้ Hook อะไร, Map ชนิดไหน, มีไฟล์อะไร และทดสอบอย่างไร ข้อมูลทั้งหมดดึงจากโค้ดจริงในแต่ละแล็บ

**สีในแผนผัง:** 🟪 เฟส · 🟦 สัปดาห์ · 🟥 Hook · 🟨 Maps · ⬜ ไฟล์ · 🟩 การทดสอบ · 🟧 เอกสาร/เครื่องมือ

> แผนผังนี้ตอบคำถามว่า "เรียนอะไร อยู่ที่ไหน" ส่วนลำดับการทำงานภายในของแต่ละแล็บ ดูได้จากแผนภาพ **Workflow Overview** ในต้น `README.md` ของแต่ละสัปดาห์ และแผนภาพ **Chapter Overview** ใน [`MASTER_STUDY_GUIDE.md`](MASTER_STUDY_GUIDE.md)

## สารบัญ

- [ภาพรวมทั้งหลักสูตร](#overall-tree)
- [เฟส 01: Network Foundation](#phase-01)
- [เฟส 02: First Step into eBPF](#phase-02)
- [เฟส 03: Modern eBPF Core (CO-RE)](#phase-03)
- [เฟส 04: High-Speed Networking](#phase-04)
- [เฟส 05: Security + Observability](#phase-05)
- [เฟส 06: Production Capstone](#phase-06)
- [เฟส 07: Advanced Kernel Security](#phase-07)
- [เฟส 08: System Performance](#phase-08)
- [เฟส 09: Socket Acceleration](#phase-09)
- [เฟส 10: Cutting-Edge eBPF](#phase-10)
- [เฟส 11: Modern Extensibility](#phase-11)

---

<a id="overall-tree"></a>

## ภาพรวมทั้งหลักสูตร

```mermaid
flowchart LR
    ROOT["eBPF Zero to Hero<br/>11 เฟส · 26 สัปดาห์"]
    ROOT --> DOCS["docs/"]
    DOCS --> GUIDE["MASTER_STUDY_GUIDE.md<br/>คู่มือ 11 บท"]
    DOCS --> TREE["CONTENT_TREE.md<br/>แผนผังนี้"]
    ROOT --> TOOLS["เครื่องมือ"]
    TOOLS --> SETUP["scripts/setup_env.sh"]
    TOOLS --> MK["Makefile<br/>make · make test · make check"]
    TOOLS --> VM["vmlinux.h<br/>จาก BTF ของเคอร์เนล"]
    ROOT --> P01["เฟส 01: Network Foundation"]
    P01 --> W01["W01 Packet bytes + Network Namespaces"]
    P01 --> W02["W02 Bridge, Router + Data Path"]
    ROOT --> P02["เฟส 02: First Step into eBPF"]
    P02 --> W03["W03 bpftool + bpftrace"]
    P02 --> W04["W04 BCC + Python"]
    ROOT --> P03["เฟส 03: Modern eBPF Core (CO-RE)"]
    P03 --> W05["W05 libbpf, CO-RE + bpf2go"]
    P03 --> W06["W06 Maps + Verifier + test_run"]
    ROOT --> P04["เฟส 04: High-Speed Networking"]
    P04 --> W07["W07 XDP Parsing + Bounds Checking"]
    P04 --> W08["W08 XDP LB + TC Egress"]
    ROOT --> P05["เฟส 05: Security + Observability"]
    P05 --> W09["W09 Ring Buffer + TLS Uprobes"]
    P05 --> W10["W10 BPF LSM"]
    ROOT --> P06["เฟส 06: Production Capstone"]
    P06 --> W11["W11 Prometheus Exporter"]
    P06 --> W12["W12 Capstone: eBPF IPS"]
    ROOT --> P07["เฟส 07: Advanced Kernel Security"]
    P07 --> W13["W13 Dropwatch"]
    P07 --> W14["W14 Zero-Trust Egress"]
    P07 --> W15["W15 Reverse Shell Guard"]
    P07 --> W16["W16 eBPF Integrity Audit"]
    ROOT --> P08["เฟส 08: System Performance"]
    P08 --> W17["W17 biolatency"]
    P08 --> W18["W18 CPU Profiler + Flame Graph"]
    P08 --> W19["W19 Page Faults + OOM"]
    ROOT --> P09["เฟส 09: Socket Acceleration"]
    P09 --> W20["W20 sockops + sk_msg Bypass"]
    P09 --> W21["W21 AF_XDP Redirect"]
    ROOT --> P10["เฟส 10: Cutting-Edge eBPF"]
    P10 --> W22["W22 fentry / fexit Trampoline"]
    P10 --> W23["W23 BPF Task Iterators"]
    ROOT --> P11["เฟส 11: Modern Extensibility"]
    P11 --> W24["W24 kfuncs + BPF Arena"]
    P11 --> W25["W25 struct_ops + sched_ext"]
    P11 --> W26["W26 Tetragon + Cilium"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class ROOT root
    class DOCS,GUIDE,TREE,TOOLS,SETUP,MK,VM doc
    class P01,P02,P03,P04,P05,P06,P07,P08,P09,P10,P11 phase
    class W01,W02,W03,W04,W05,W06,W07,W08,W09,W10,W11,W12,W13,W14,W15,W16,W17,W18,W19,W20,W21,W22,W23,W24,W25,W26 week
```

---

<a id="phase-01"></a>

## เฟส 01: Network Foundation

```mermaid
flowchart LR
    P01["เฟส 01: Network Foundation<br/>คู่มือบทที่ 1"]
    P01 --> W01["Week 01<br/>Packet bytes + Network Namespaces"]
    W01 --> W01H["Hook: ไม่ใช้ BPF<br/>AF_PACKET raw socket"]
    W01 --> W01M["Maps: —"]
    W01 --> W01F["ไฟล์: lab_netns.sh<br/>raw_sniffer.py"]
    W01 --> W01T["ทดสอบ: ping / UDP ข้าม veth<br/>sniffer แกะ Eth/IP/TCP"]
    P01 --> W02["Week 02<br/>Bridge, Router + Data Path"]
    W02 --> W02H["Hook: ไม่ใช้ BPF<br/>br0 + ip_forward"]
    W02 --> W02M["Maps: —"]
    W02 --> W02F["ไฟล์: bridge_router_lab.sh"]
    W02 --> W02T["ทดสอบ: ping ข้าม bridge<br/>softnet_stat, perf net"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P01 phase
    class W01,W02 week
    class W01H,W02H hook
    class W01M,W02M map
    class W01F,W02F file
    class W01T,W02T test
```

**คู่มือแล็บ:** [Week 01](../phase01-network-foundation/week01-packet-netns/README.md) · [Week 02](../phase01-network-foundation/week02-linux-net-stack/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 1](MASTER_STUDY_GUIDE.md#overview-1)

---

<a id="phase-02"></a>

## เฟส 02: First Step into eBPF

```mermaid
flowchart LR
    P02["เฟส 02: First Step into eBPF<br/>คู่มือบทที่ 2"]
    P02 --> W03["Week 03<br/>bpftool + bpftrace"]
    W03 --> W03H["Hook: tracepoint sched_process_exec<br/>kprobe tcp_sendmsg<br/>tracepoint tcp:tcp_retransmit_skb"]
    W03 --> W03M["Maps: bpftrace @maps<br/>hist / count / sum"]
    W03 --> W03F["ไฟล์: trace_exec_and_tcp.bt"]
    W03 --> W03T["ทดสอบ: bpftool prog / map dump<br/>xlated + jited"]
    P02 --> W04["Week 04<br/>BCC + Python"]
    W04 --> W04H["Hook: kprobe + kretprobe<br/>tcp_v4_connect"]
    W04 --> W04M["Maps: HASH start_ts<br/>PERF_OUTPUT + log2 hist"]
    W04 --> W04F["ไฟล์: tcp_v4_latency.py"]
    W04 --> W04T["ทดสอบ: curl → latency histogram"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P02 phase
    class W03,W04 week
    class W03H,W04H hook
    class W03M,W04M map
    class W03F,W04F file
    class W03T,W04T test
```

**คู่มือแล็บ:** [Week 03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) · [Week 04](../phase02-first-step-ebpf/week04-bcc-python/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 2](MASTER_STUDY_GUIDE.md#overview-2)

---

<a id="phase-03"></a>

## เฟส 03: Modern eBPF Core (CO-RE)

```mermaid
flowchart LR
    P03["เฟส 03: Modern eBPF Core (CO-RE)<br/>คู่มือบทที่ 3"]
    P03 --> W05["Week 05<br/>libbpf, CO-RE + bpf2go"]
    W05 --> W05H["Hook: tracepoint<br/>sched/sched_process_exec"]
    W05 --> W05M["Maps: ARRAY exec_count"]
    W05 --> W05F["ไฟล์: counter.c · main.go<br/>Makefile"]
    W05 --> W05T["ทดสอบ: exec ใด ๆ → rate/sec"]
    P03 --> W06["Week 06<br/>Maps + Verifier + test_run"]
    W06 --> W06H["Hook: tracepoint raw_syscalls/sys_enter<br/>xdp (maps_testrun, verifier_fail)"]
    W06 --> W06M["Maps: HASH · LRU_HASH<br/>PERCPU_HASH · ARRAY"]
    W06 --> W06F["ไฟล์: syscall_stats.c · main.go<br/>maps_testrun/ · verifier_fail/"]
    W06 --> W06T["ทดสอบ: make test: test_run<br/>make verifier-demo"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P03 phase
    class W05,W06 week
    class W05H,W06H hook
    class W05M,W06M map
    class W05F,W06F file
    class W05T,W06T test
```

**คู่มือแล็บ:** [Week 05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) · [Week 06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 3](MASTER_STUDY_GUIDE.md#overview-3)

---

<a id="phase-04"></a>

## เฟส 04: High-Speed Networking

```mermaid
flowchart LR
    P04["เฟส 04: High-Speed Networking<br/>คู่มือบทที่ 4"]
    P04 --> W07["Week 07<br/>XDP Parsing + Bounds Checking"]
    W07 --> W07H["Hook: xdp"]
    W07 --> W07M["Maps: HASH blocked_ips<br/>PERCPU_ARRAY proto_counters"]
    W07 --> W07F["ไฟล์: xdp_firewall.c · main.go<br/>main_test.go"]
    W07 --> W07T["ทดสอบ: make test: test_run<br/>netns traffic"]
    P04 --> W08["Week 08<br/>XDP LB + TC Egress"]
    W08 --> W08H["Hook: xdp + tc (TCX)"]
    W08 --> W08M["Maps: LRU_HASH flows<br/>HASH · ARRAY"]
    W08 --> W08F["ไฟล์: xdp_lb.c · tc_egress.c<br/>main.go · main_test.go"]
    W08 --> W08T["ทดสอบ: make test: test_run<br/>curl VIP 10.10.1.100"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P04 phase
    class W07,W08 week
    class W07H,W08H hook
    class W07M,W08M map
    class W07F,W08F file
    class W07T,W08T test
```

**คู่มือแล็บ:** [Week 07](../phase04-high-speed-networking/week07-xdp-parsing/README.md) · [Week 08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 4](MASTER_STUDY_GUIDE.md#overview-4)

---

<a id="phase-05"></a>

## เฟส 05: Security + Observability

```mermaid
flowchart LR
    P05["เฟส 05: Security + Observability<br/>คู่มือบทที่ 5"]
    P05 --> W09["Week 09<br/>Ring Buffer + TLS Uprobes"]
    W09 --> W09H["Hook: tracepoint/sched/sched_process_exec<br/>uprobe SSL_write / SSL_write_ex"]
    W09 --> W09M["Maps: RINGBUF events"]
    W09 --> W09F["ไฟล์: ringbuf_events.c<br/>main.go"]
    W09 --> W09T["ทดสอบ: exec + HTTPS ผ่าน libssl"]
    P05 --> W10["Week 10<br/>BPF LSM"]
    W10 --> W10H["Hook: lsm/file_open<br/>fentry/security_file_open (audit)"]
    W10 --> W10M["Maps: HASH · ARRAY<br/>RINGBUF lsm_events"]
    W10 --> W10F["ไฟล์: lsm_file_guard.c<br/>main.go"]
    W10 --> W10T["ทดสอบ: เปิดไฟล์ secret<br/>→ EPERM หรือ audit"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P05 phase
    class W09,W10 week
    class W09H,W10H hook
    class W09M,W10M map
    class W09F,W10F file
    class W09T,W10T test
```

**คู่มือแล็บ:** [Week 09](../phase05-security-observability/week09-ringbuf-uprobes/README.md) · [Week 10](../phase05-security-observability/week10-bpf-lsm/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 5](MASTER_STUDY_GUIDE.md#overview-5)

---

<a id="phase-06"></a>

## เฟส 06: Production Capstone

```mermaid
flowchart LR
    P06["เฟส 06: Production Capstone<br/>คู่มือบทที่ 6"]
    P06 --> W11["Week 11<br/>Prometheus Exporter"]
    W11 --> W11H["Hook: xdp"]
    W11 --> W11M["Maps: PERCPU_ARRAY<br/>traffic_metrics"]
    W11 --> W11F["ไฟล์: metrics_exporter.c · main.go<br/>metrics_test.go"]
    W11 --> W11T["ทดสอบ: make test: test_run<br/>curl :2112/metrics"]
    P06 --> W12["Week 12<br/>Capstone: eBPF IPS"]
    W12 --> W12H["Hook: xdp xdp_smart_ips"]
    W12 --> W12M["Maps: LRU_HASH ×2 · ARRAY<br/>PERCPU_ARRAY · RINGBUF"]
    W12 --> W12F["ไฟล์: bpf/ips_kern.c<br/>cmd/ips-agent/"]
    W12 --> W12T["ทดสอบ: make test: test_run<br/>ping -f / SYN burst"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P06 phase
    class W11,W12 week
    class W11H,W12H hook
    class W11M,W12M map
    class W11F,W12F file
    class W11T,W12T test
```

**คู่มือแล็บ:** [Week 11](../phase06-production-capstone/week11-verifier-prometheus/README.md) · [Week 12](../phase06-production-capstone/week12-capstone-ips/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 6](MASTER_STUDY_GUIDE.md#overview-6)

---

<a id="phase-07"></a>

## เฟส 07: Advanced Kernel Security

```mermaid
flowchart LR
    P07["เฟส 07: Advanced Kernel Security<br/>คู่มือบทที่ 7"]
    P07 --> W13["Week 13<br/>Dropwatch"]
    W13 --> W13H["Hook: tracepoint skb/kfree_skb"]
    W13 --> W13M["Maps: HASH drop_reason_stats<br/>RINGBUF"]
    W13 --> W13F["ไฟล์: dropwatch.c<br/>main.go"]
    W13 --> W13T["ทดสอบ: nc / python<br/>สร้าง packet drop"]
    P07 --> W14["Week 14<br/>Zero-Trust Egress"]
    W14 --> W14H["Hook: cgroup/connect4"]
    W14 --> W14M["Maps: HASH ×2 blocklist<br/>RINGBUF"]
    W14 --> W14F["ไฟล์: sock_enforce.c<br/>main.go"]
    W14 --> W14T["ทดสอบ: connect ไป port 2323<br/>ใน cgroup ของแล็บ"]
    P07 --> W15["Week 15<br/>Reverse Shell Guard"]
    W15 --> W15H["Hook: tracepoint<br/>sched/sched_process_exec"]
    W15 --> W15M["Maps: HASH ×2 names<br/>RINGBUF"]
    W15 --> W15F["ไฟล์: revshell_detect.c<br/>main.go"]
    W15 --> W15T["ทดสอบ: listener.py<br/>127.0.0.1:4444"]
    P07 --> W16["Week 16<br/>eBPF Integrity Audit"]
    W16 --> W16H["Hook: fentry/__sys_bpf<br/>fallback raw_syscalls/sys_enter"]
    W16 --> W16M["Maps: RINGBUF"]
    W16 --> W16F["ไฟล์: bpf_audit.c<br/>main.go"]
    W16 --> W16T["ทดสอบ: bpftool prog load<br/>ทุก CPU"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P07 phase
    class W13,W14,W15,W16 week
    class W13H,W14H,W15H,W16H hook
    class W13M,W14M,W15M,W16M map
    class W13F,W14F,W15F,W16F file
    class W13T,W14T,W15T,W16T test
```

**คู่มือแล็บ:** [Week 13](../phase07-advanced-security-observability/week13-kfree-skb-dropwatch/README.md) · [Week 14](../phase07-advanced-security-observability/week14-cgroup-sock-addr/README.md) · [Week 15](../phase07-advanced-security-observability/week15-reverse-shell-guard/README.md) · [Week 16](../phase07-advanced-security-observability/week16-ebpf-integrity-audit/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 7](MASTER_STUDY_GUIDE.md#overview-7)

---

<a id="phase-08"></a>

## เฟส 08: System Performance

```mermaid
flowchart LR
    P08["เฟส 08: System Performance<br/>คู่มือบทที่ 8"]
    P08 --> W17["Week 17<br/>biolatency"]
    W17 --> W17H["Hook: tp_btf/block_rq_issue<br/>tp_btf/block_rq_complete"]
    W17 --> W17M["Maps: HASH start_times<br/>HASH hist · ARRAY"]
    W17 --> W17F["ไฟล์: biolatency.c<br/>main.go"]
    W17 --> W17T["ทดสอบ: gnudd (GNU dd) O_DIRECT"]
    P08 --> W18["Week 18<br/>CPU Profiler + Flame Graph"]
    W18 --> W18H["Hook: perf_event 99 Hz"]
    W18 --> W18M["Maps: STACK_TRACE · HASH<br/>PERCPU_ARRAY"]
    W18 --> W18F["ไฟล์: cpu_stacks.c · main.go<br/>usersyms.go · flamegraph.py"]
    W18 --> W18T["ทดสอบ: workload/busy.c<br/>→ flame graph SVG"]
    P08 --> W19["Week 19<br/>Page Faults + OOM"]
    W19 --> W19H["Hook: tracepoint/exceptions/page_fault_user<br/>tracepoint/oom/mark_victim"]
    W19 --> W19M["Maps: HASH page_fault_counts<br/>RINGBUF oom_events"]
    W19 --> W19F["ไฟล์: oom_watcher.c<br/>main.go"]
    W19 --> W19T["ทดสอบ: systemd-run<br/>MemoryMax=50M"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P08 phase
    class W17,W18,W19 week
    class W17H,W18H,W19H hook
    class W17M,W18M,W19M map
    class W17F,W18F,W19F file
    class W17T,W18T,W19T test
```

**คู่มือแล็บ:** [Week 17](../phase08-system-performance-observability/week17-block-io-biolatency/README.md) · [Week 18](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md) · [Week 19](../phase08-system-performance-observability/week19-memory-oom-watcher/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 8](MASTER_STUDY_GUIDE.md#overview-8)

---

<a id="phase-09"></a>

## เฟส 09: Socket Acceleration

```mermaid
flowchart LR
    P09["เฟส 09: Socket Acceleration<br/>คู่มือบทที่ 9"]
    P09 --> W20["Week 20<br/>sockops + sk_msg Bypass"]
    W20 --> W20H["Hook: sockops + sk_msg"]
    W20 --> W20M["Maps: SOCKHASH<br/>ARRAY bypass_stats"]
    W20 --> W20F["ไฟล์: sockops.c · main.go<br/>cmd/tcpbench/"]
    W20 --> W20T["ทดสอบ: make test: end-to-end<br/>tcpbench / iperf3"]
    P09 --> W21["Week 21<br/>AF_XDP Redirect"]
    W21 --> W21H["Hook: xdp → XSKMAP"]
    W21 --> W21M["Maps: XSKMAP · ARRAY"]
    W21 --> W21F["ไฟล์: xsk_kern.c · xsk.go<br/>main.go · main_test.go"]
    W21 --> W21T["ทดสอบ: make test<br/>UDP ใน netns w21"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P09 phase
    class W20,W21 week
    class W20H,W21H hook
    class W20M,W21M map
    class W20F,W21F file
    class W20T,W21T test
```

**คู่มือแล็บ:** [Week 20](../phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/README.md) · [Week 21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 9](MASTER_STUDY_GUIDE.md#overview-9)

---

<a id="phase-10"></a>

## เฟส 10: Cutting-Edge eBPF

```mermaid
flowchart LR
    P10["เฟส 10: Cutting-Edge eBPF<br/>คู่มือบทที่ 10"]
    P10 --> W22["Week 22<br/>fentry / fexit Trampoline"]
    W22 --> W22H["Hook: fentry + fexit<br/>do_sys_openat2"]
    W22 --> W22M["Maps: HASH start_map<br/>RINGBUF"]
    W22 --> W22F["ไฟล์: trampoline.c · main.go<br/>bench/"]
    W22 --> W22T["ทดสอบ: make test<br/>make bench vs kprobe"]
    P10 --> W23["Week 23<br/>BPF Task Iterators"]
    W23 --> W23H["Hook: iter/task"]
    W23 --> W23M["Maps: ไม่ใช้ map<br/>BPF_SEQ_PRINTF → seq_file"]
    W23 --> W23F["ไฟล์: task_iter.c · main.go<br/>main_test.go"]
    W23 --> W23T["ทดสอบ: make test<br/>เทียบเวลากับ /proc"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P10 phase
    class W22,W23 week
    class W22H,W23H hook
    class W22M,W23M map
    class W22F,W23F file
    class W22T,W23T test
```

**คู่มือแล็บ:** [Week 22](../phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/README.md) · [Week 23](../phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 10](MASTER_STUDY_GUIDE.md#overview-10)

---

<a id="phase-11"></a>

## เฟส 11: Modern Extensibility

```mermaid
flowchart LR
    P11["เฟส 11: Modern Extensibility<br/>คู่มือบทที่ 11"]
    P11 --> W24["Week 24<br/>kfuncs + BPF Arena"]
    W24 --> W24H["Hook: SEC syscall<br/>kfuncs acquire / release"]
    W24 --> W24M["Maps: ARENA"]
    W24 --> W24F["ไฟล์: task_kfunc.c · arena_list.c<br/>task_kfunc_broken.c · patches/"]
    W24 --> W24T["ทดสอบ: make test<br/>syscall prog ผ่าน test_run"]
    P11 --> W25["Week 25<br/>struct_ops + sched_ext"]
    W25 --> W25H["Hook: struct_ops w25_ops<br/>sched_ext callbacks"]
    W25 --> W25M["Maps: PERCPU_ARRAY stats<br/>DSQ เป็นคิวของ sched_ext ไม่ใช่ map"]
    W25 --> W25F["ไฟล์: scx_w25.c · scx_mini.h<br/>main.go · sched.go"]
    W25 --> W25T["ทดสอบ: make test: attach จริง<br/>nice_demo.sh"]
    P11 --> W26["Week 26<br/>Tetragon + Cilium"]
    W26 --> W26H["Hook: Tetragon TracingPolicy<br/>kprobe / LSM"]
    W26 --> W26M["Maps: จัดการโดย Tetragon"]
    W26 --> W26F["ไฟล์: policies/ 6 ไฟล์<br/>cilium/ · run-tetragon.sh"]
    W26 --> W26T["ทดสอบ: validate-policies.py<br/>make up / down"]

    classDef root fill:#2c3e50,stroke:#1b2631,color:#fff
    classDef phase fill:#e8daef,stroke:#7d3c98,color:#000
    classDef week fill:#e2f0fd,stroke:#2471a3,color:#000
    classDef hook fill:#fde2e2,stroke:#c0392b,color:#000
    classDef map fill:#fff4d6,stroke:#b9770e,color:#000
    classDef file fill:#f2f3f4,stroke:#717d7e,color:#000
    classDef test fill:#e3f7e3,stroke:#1e8449,color:#000
    classDef doc fill:#fdebd0,stroke:#ca6f1e,color:#000
    class P11 phase
    class W24,W25,W26 week
    class W24H,W25H,W26H hook
    class W24M,W25M,W26M map
    class W24F,W25F,W26F file
    class W24T,W25T,W26T test
```

**คู่มือแล็บ:** [Week 24](../phase11-modern-ebpf-extensibility/week24-kfuncs-arena/README.md) · [Week 25](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md) · [Week 26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) · **ทฤษฎี:** [MASTER_STUDY_GUIDE บทที่ 11](MASTER_STUDY_GUIDE.md#overview-11)

---

*กลับไปที่ [README หลัก](../README.md)*
