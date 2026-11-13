"""Animated SVG builders for the remaining 21 weekly diagrams (Weeks 01-06, 09-19, 23-26)."""

from anim_svg_ui import (
    kf_move,
    kf_pop,
    make_header,
    make_stage,
    make_step_table,
    node_card,
    pkt_chip,
    pop_pill,
)


def build_week01_veth_pair():
    dur = 12.0
    steps = [
        ("สร้าง veth & แยกห้อง", "สร้าง w01-ns1 กับ w01-ns2 แล้วต่อสายเสมือน veth1 ↔ veth2 ข้ามหากัน", 0.3, 2.8),
        ("ns1 ส่ง ICMP Echo", "แอปใน w01-ns1 ยิง ping 10.10.1.2 ออกทาง veth1 (10.10.1.1/24)", 2.9, 5.6),
        ("วิ่งข้ามสายเสมือน", "แพ็กเก็ตเข้าปลายสายฝั่งหนึ่งแล้วโผล่ออกอีกฝั่งทันทีเหมือนสาย LAN จริง", 5.7, 8.6),
        ("Sniffer ดักดู & ตอบกลับ", "raw_sniffer.py (AF_PACKET) แอบเห็นเฟรม L2 ขณะ ns2 ส่ง Echo Reply กลับ", 8.7, 11.7),
    ]
    header = make_header(
        "Week 01 · NetNS", "สาย LAN เสมือน veth pair + Sniffer",
        "แยกห้องเครือข่ายด้วย Network Namespace แล้วเชื่อมหากันด้วยสายเสมือนที่จับแพ็กเก็ตดูได้ตรงกลาง"
    )
    stage = make_stage(120, 326, "w01-ns1 (10.10.1.1)  ◀════ Virtual Wire (veth pair) ════▶  w01-ns2 (10.10.1.2)")

    ns1_box = (
        '<rect x="44" y="182" width="268" height="242" rx="14" fill="#eff6ff" stroke="#2563eb" stroke-width="2" stroke-dasharray="6 4"/>'
        '<text x="178" y="204" font-size="13.5" font-weight="700" fill="#1d4ed8" text-anchor="middle">Namespace: w01-ns1</text>'
    )
    ns2_box = (
        '<rect x="648" y="182" width="268" height="242" rx="14" fill="#ecfdf5" stroke="#16a34a" stroke-width="2" stroke-dasharray="6 4"/>'
        '<text x="782" y="204" font-size="13.5" font-weight="700" fill="#15803d" text-anchor="middle">Namespace: w01-ns2</text>'
    )

    c_app1 = node_card(62, 214, 232, 84, "ping / Client App", "ส่งออกหา 10.10.1.2", "#ffffff", badge="User Space", badge_fill="#dbeafe")
    c_veth1 = node_card(62, 316, 232, 92, "w01-veth1", "IP: 10.10.1.1/24", "#dbeafe", badge="Virtual NIC ฝั่ง 1", badge_fill="#93c5fd")

    c_app2 = node_card(666, 214, 232, 84, "Server / ICMP Stack", "รับและตอบ Echo Reply", "#ffffff", badge="Kernel Stack", badge_fill="#dcfce7")
    c_veth2 = node_card(666, 316, 232, 92, "w01-veth2", "IP: 10.10.1.2/24", "#dcfce7", badge="Virtual NIC ฝั่ง 2", badge_fill="#86efac")

    c_sniff = node_card(356, 186, 248, 128, "raw_sniffer.py", "AF_PACKET / SOCK_RAW", "#fef3c7", "bb-shield", "ดักฟัง L2 Frame (ETH_P_ALL)", "#fde68a")

    arrows = (
        '<path class="ant-blue" d="M178 298V312" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant" d="M298 354H660" marker-end="url(#bb-ah)"/>'
        '<path class="ant-green" d="M660 374H298" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-green" d="M782 316V302" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M480 354V318" marker-end="url(#bb-ah-amber)"/>'
        '<rect x="386" y="344" width="188" height="22" rx="11" fill="#ffffff" stroke="#111111" stroke-width="1.5"/>'
        '<text x="480" y="359" font-size="11.5" font-weight="700" fill="#111111" text-anchor="middle">Virtual Wire (L1 Link)</text>'
    )

    anim_css = (
        kf_move("pk-req", dur, 2.8, 8.6, [(178, 256), (178, 354), (480, 354), (782, 354), (782, 256)])
        + kf_move("pk-sniff", dur, 5.8, 9.5, [(480, 354), (480, 250)])
        + kf_move("pk-rep", dur, 8.6, 11.7, [(782, 256), (782, 374), (480, 374), (178, 374), (178, 256)])
        + kf_pop("bd-cap", dur, 7.6, 11.4)
    )
    anim_els = (
        pkt_chip("pk-req", "ICMP Echo Req", "#93c5fd", 112)
        + pkt_chip("pk-sniff", "L2 Copy", "#fde047", 86)
        + pkt_chip("pk-rep", "Echo Reply", "#7de3b4", 104)
        + pop_pill("bd-cap", 480, 174, "จับได้แล้ว: Src→Dst IP + MAC!", "#f59e0b", "#111111")
    )

    tbl, tbl_css, tbl_h = make_step_table(464, steps, dur, split_x=256)
    return "Week 01: Virtual Ethernet Pair & Raw Sniffer", 464 + tbl_h + 24, header + stage + ns1_box + ns2_box + c_app1 + c_veth1 + c_app2 + c_veth2 + c_sniff + arrows + anim_els + tbl, anim_css + tbl_css


def build_week02_rx_path():
    dur = 14.0
    steps = [
        ("NIC รับ & ยิง DMA", "การ์ดแลนวางข้อมูลลง RX Ring Buffer ใน RAM แล้วส่ง Hard IRQ ปลุก CPU", 0.3, 3.0),
        ("NAPI Poll + XDP Hook", "เคอร์เนลวนเก็บแพ็กเก็ตทีละชุด (งบ 64 ใบ) และผ่านด่าน XDP ก่อนสร้าง sk_buff", 3.1, 6.0),
        ("L2/L3 แกะหัวส่งต่อ", "Bridge/FDB ตรวจ MAC แล้วส่งต่อ ip_rcv() และ Netfilter (PREROUTING/LOCAL_IN)", 6.1, 9.2),
        ("L4 + Socket ส่งถึงแอป", "tcp_v4_rcv() ใส่คิว Socket แล้วปลุก epoll_wait() ให้แอปมา recvmsg()", 9.3, 13.7),
    ]
    header = make_header(
        "Week 02 · Linux RX", "เส้นทางรับแพ็กเก็ตตั้งแต่สายถึงแอป",
        "กว่า 1 แพ็กเก็ตจะถึงมือโปรแกรมของเรา ต้องผ่าน DMA, NAPI, XDP, L2/L3/L4 และ Socket ตามลำดับ"
    )
    stage = make_stage(120, 344, "Hardware / Driver  ──▶  NAPI + XDP  ──▶  L2 / L3 / L4 Stack  ──▶  Socket / App")

    n1 = node_card(44, 184, 198, 128, "1. NIC + RX Ring", "DMA ลง RAM + Hard IRQ", "#ffffff", "bb-nic", "Ring Buffer", "#dcfce7")
    n2 = node_card(268, 184, 212, 128, "2. NAPI Poll + XDP", "SoftIRQ Budget 64 pkts", "#fff1f2", "bb-shield", "ก่อนสร้าง sk_buff", "#fecdd3")
    n3 = node_card(506, 184, 198, 128, "3. L2 Bridge / FDB", "br_handle_frame()", "#fef3c7", badge="L2 Forwarding / Local", badge_fill="#fde68a")
    n4 = node_card(730, 184, 186, 128, "4. L3 ip_rcv()", "Netfilter + Routing", "#e0f2fe", badge="สร้าง sk_buff แล้ว", badge_fill="#bae6fd")

    n5 = node_card(668, 342, 248, 102, "5. L4 tcp_v4_rcv() / udp", "เช็กพอร์ต & ใส่ Socket Queue", "#e7dff8", badge="Transport Layer", badge_fill="#ddd6fe")
    n6 = node_card(360, 342, 268, 102, "6. Socket + epoll_wait()", "sk_receive_queue ปลุกโปรเซส", "#dbeafe", badge="Kernel → User Boundary", badge_fill="#bfdbfe")
    n7 = node_card(44, 342, 276, 102, "7. User App recvmsg()", "ดึง Payload ไปใช้งานในแอป", "#dcfce7", badge="ถึงมือแอปสำเร็จ ✓", badge_fill="#86efac")

    arrows = (
        '<path class="ant" d="M242 248H264" marker-end="url(#bb-ah)"/>'
        '<path class="ant-red" d="M480 248H502" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-amber" d="M704 248H726" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M823 312V338" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-blue" d="M668 393H632" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-green" d="M360 393H324" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-rx", dur, 0.3, 13.4, [(143, 248), (374, 248), (605, 248), (823, 248), (823, 393), (494, 393), (182, 393)])
        + kf_pop("bd-skb", dur, 5.2, 8.8)
        + kf_pop("bd-ep", dur, 10.6, 13.7)
    )
    anim_els = (
        pkt_chip("pk-rx", "Frame / sk_buff", "#7de3b4", 120)
        + pop_pill("bd-skb", 605, 174, "Allocated struct sk_buff!", "#3b82f6", "#ffffff")
        + pop_pill("bd-ep", 182, 330, "recvmsg() รับข้อมูล ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(482, steps, dur, split_x=256)
    return "Week 02: Linux Packet RX Path", 482 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n5 + n6 + n7 + arrows + anim_els + tbl, anim_css + tbl_css


def build_week03_ebpf_architecture():
    dur = 13.0
    steps = [
        ("คอมไพล์เป็น Bytecode", "โค้ด C ถูก LLVM Clang แปลงเป็นคำสั่ง eBPF (.o ELF) เตรียมส่งเข้า Kernel", 0.3, 3.2),
        ("Verifier ตรวจความปลอดภัย", "เรียก sys_bpf(BPF_PROG_LOAD) เพื่อสแกนว่าไม่มีลูปค้างหรืออ่านเมมมั่ว", 3.3, 6.6),
        ("JIT แปลงเป็นภาษาเครื่อง", "ถ้าผ่าน Verifier จะถูก JIT แปลงเป็น Native x86/ARM64 วิ่งเร็วระดับเคอร์เนล", 6.7, 9.6),
        ("เกาะ Hook & คุยผ่าน Maps", "ติดเข้า kprobe/tracepoint แล้วเก็บข้อมูลใน BPF Maps ให้ User Space อ่าน", 9.7, 12.7),
    ]
    header = make_header(
        "Week 03 · สถาปัตยกรรม", "eBPF โหลดและทำงานอย่างไร",
        "ภาพรวมตั้งแต่เขียนโค้ด C → ผ่านด่านตรวจ Verifier → แปลงเป็น Machine Code → ติด Hook ใน Kernel"
    )
    stage = make_stage(120, 356, "User Space (Clang + Loader)  ──▶  Kernel Gate (Verifier + JIT)  ──▶  Hooks & Maps")

    n_src = node_card(44, 186, 210, 142, "1. โค้ด C → Clang", "คอมไพล์เป็น .o Bytecode", "#ffffff", "bb-doc", "ELF eBPF Instructions", "#dbeafe")
    n_usr = node_card(44, 346, 210, 96, "bpftool / bpftrace", "CLI ดูสถานะ & อ่าน Map", "#eff6ff", badge="User Space Tools", badge_fill="#bfdbfe")

    n_ver = node_card(306, 186, 240, 144, "2. Verifier + JIT", "sys_bpf(BPF_PROG_LOAD)", "#fff1f2", "bb-shield", "Safe? → Native x86/ARM64", "#fecdd3")
    n_rej = node_card(306, 346, 240, 88, "ถ้าไม่ปลอดภัย → Reject!", "คืนค่า -EACCES + Verifier Log", "#ffe4e6", badge="ป้องกัน Kernel Panic", badge_fill="#fb7185")

    n_hook = node_card(604, 186, 312, 134, "3. Kernel Hooks", "kprobe / tracepoint / XDP", "#dcfce7", "bb-cpu", "ทำงานทุกครั้งที่เกิดเหตุการณ์", "#86efac")
    n_map = node_card(604, 336, 312, 102, "4. BPF MAPS (แชร์ข้อมูล)", "Hash / Array / RingBuffer", "#fef3c7", badge="Kernel ↔ User Exchange", badge_fill="#fde68a")

    arrows = (
        '<path class="ant" d="M254 257H302" marker-end="url(#bb-ah)"/>'
        '<path class="ant-red" d="M426 330V343" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M546 253H600" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M760 320V333" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M760 438V458H149V446" marker-end="url(#bb-ah-blue)"/>'
    )

    anim_css = (
        kf_move("pk-bc", dur, 0.3, 6.4, [(149, 257), (426, 257)])
        + kf_pop("bd-safe", dur, 5.6, 8.8)
        + kf_move("pk-nat", dur, 6.5, 10.6, [(426, 257), (760, 253), (760, 387)])
        + kf_move("pk-rd", dur, 10.0, 12.7, [(760, 438), (760, 458), (149, 458), (149, 394)])
    )
    anim_els = (
        pkt_chip("pk-bc", "eBPF .o", "#93c5fd", 84)
        + pop_pill("bd-safe", 426, 174, "Verifier PASS → JIT OK ✓", "#16a34a", "#ffffff")
        + pkt_chip("pk-nat", "Native Code", "#7de3b4", 104)
        + pkt_chip("pk-rd", "Map Stats", "#fde047", 92)
    )

    tbl, tbl_css, tbl_h = make_step_table(494, steps, dur, split_x=256)
    return "Week 03: eBPF Build, Verifier, JIT & Maps Architecture", 494 + tbl_h + 24, header + stage + n_src + n_usr + n_ver + n_rej + n_hook + n_map + arrows + anim_els + tbl, anim_css + tbl_css


def build_week04_kprobe_timing():
    dur = 12.0
    steps = [
        ("แอปเรียกฟังก์ชันเคอร์เนล", "Thread A เข้าฟังก์ชันเป้าหมายใน Kernel (เช่น tcp_v4_connect หรือ do_sys_openat2)", 0.3, 2.8),
        ("kprobe จดเวลาเข้า (t1)", "จังหวะขาเข้าบันทึก start_ts[TID_A] = bpf_ktime_get_ns() ลงใน Hash Map", 2.9, 5.8),
        ("ฟังก์ชันเคอร์เนลทำงาน", "Kernel ทำงานจริงจนเสร็จสิ้น (ใช้เวลาช่วงหนึ่ง ระหว่างนั้น Map จำ t1 ไว้)", 5.9, 8.5),
        ("kretprobe หักลบเวลา (Δt)", "จังหวะขาออกอ่าน t1 ออกมาคำนวณ delta = t2 - t1 แล้วลบทิ้งไม่ให้ Map บวม", 8.6, 11.7),
    ]
    header = make_header(
        "Week 04 · kprobe", "วัดเวลาเข้า-ออกฟังก์ชัน Kernel",
        "จับคู่ kprobe (ขาเข้า) กับ kretprobe (ขาออก) ด้วย Thread ID เพื่อจับเวลา Latency ของฟังก์ชันระดับ ns"
    )
    stage = make_stage(120, 344, "Thread A Timeline: Entry (จด t1)  ──▶  Kernel Function  ──▶  Exit (t2 - t1)")

    n1 = node_card(44, 186, 178, 134, "1. Thread A", "เรียก Syscall / Kernel", "#eff6ff", "bb-app", "TID = 1042", "#bfdbfe")
    n2 = node_card(256, 186, 200, 134, "2. kprobe (Entry)", "จดเวลาเริ่ม t1", "#fff1f2", "bb-shield", "จับขาเข้าฟังก์ชัน", "#fecdd3")
    n3 = node_card(490, 186, 190, 134, "3. Kernel Func", "ทำงานจริงในเคอร์เนล", "#dcfce7", "bb-cpu", "ใช้เวลาทำงาน Δt", "#86efac")
    n4 = node_card(714, 186, 202, 134, "4. kretprobe (Exit)", "อ่านเวลาจบ t2 คำนวณผล", "#fef3c7", "bb-shield", "delta = t2 - t1", "#fde68a")

    n_map = node_card(296, 350, 396, 94, "Hash Map: start_ts[TID]", "เก็บ t1 ชั่วคราวระหว่างที่ฟังก์ชันยังไม่จบ", "#fef3c7", badge="อัปเดตเมื่อ Entry / ลบเมื่อ Exit", badge_fill="#fde68a")

    arrows = (
        '<path class="ant" d="M222 253H252" marker-end="url(#bb-ah)"/>'
        '<path class="ant" d="M456 253H486" marker-end="url(#bb-ah)"/>'
        '<path class="ant" d="M680 253H710" marker-end="url(#bb-ah)"/>'
        '<path class="ant-amber" d="M356 320V346" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M632 346V324" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-th", dur, 0.3, 10.6, [(133, 253), (356, 253), (585, 253), (815, 253)])
        + kf_move("pk-w1", dur, 2.9, 5.8, [(356, 286), (356, 392)])
        + kf_move("pk-r1", dur, 8.6, 11.2, [(632, 392), (815, 286)])
        + kf_pop("bd-dt", dur, 9.2, 11.7)
    )
    anim_els = (
        pkt_chip("pk-th", "Thread #1042", "#93c5fd", 104)
        + pkt_chip("pk-w1", "Save t1", "#fda4af", 76)
        + pkt_chip("pk-r1", "Read t1", "#fde047", 76)
        + pop_pill("bd-dt", 815, 174, "Latency = t2 - t1 (ลบ Key ทิ้ง) ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(482, steps, dur, split_x=256)
    return "Week 04: kprobe & kretprobe Latency Correlation", 482 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_map + arrows + anim_els + tbl, anim_css + tbl_css


def build_week05_core_architecture():
    dur = 13.0
    steps = [
        ("bpf2go แปลงโค้ด C", "go generate รัน clang -target bpf แปลง counter.c เป็นไฟล์ Go ที่ฝังไบต์โค้ดไว้เลย", 0.3, 3.4),
        ("Go โหลดเข้า Kernel", "main.go เรียก loadBpfObjects() + link.Tracepoint() พร้อมปรับข้อมูล CO-RE BTF", 3.5, 6.8),
        ("เหตุการณ์ execve เกิด", "ทุกครั้งที่เปิดโปรแกรมใหม่ tracepoint/sched/sched_process_exec จะยิงเข้า eBPF", 6.9, 9.8),
        ("บวกตัวนับ & ดู log", "__sync_fetch_and_add อัปเดต exec_count และ bpf_printk() ส่งข้อความออก trace_pipe", 9.9, 12.7),
    ]
    header = make_header(
        "Week 05 · Go + CO-RE", "สร้างโปรแกรม eBPF ด้วย bpf2go",
        "เขียน C ครั้งเดียว แล้วให้ bpf2go ผนึกเข้ากับ Go เพื่อรันข้ามเวอร์ชัน Linux ได้ด้วย BTF (CO-RE)"
    )
    stage = make_stage(120, 344, "Build Time (bpf2go)  ──▶  Go Loader (CO-RE BTF)  ──▶  Tracepoint + Map + trace_pipe")

    n1 = node_card(44, 186, 198, 140, "1. counter.c", "go generate → bpf2go", "#ffffff", "bb-doc", "clang -target bpf + BTF", "#dbeafe")
    n2 = node_card(272, 186, 212, 140, "2. Go (main.go)", "loadBpfObjects() + link", "#eff6ff", "bb-app", "Embed ไบต์โค้ดใน Binary", "#bfdbfe")
    n3 = node_card(514, 186, 200, 140, "3. sched_process_exec", "ทำงานเมื่อเกิด execve()", "#dcfce7", "bb-cpu", "Verifier + JIT OK", "#86efac")
    n4 = node_card(744, 186, 172, 140, "4. exec_count", "ARRAY Map + trace_pipe", "#fef3c7", "bb-map", "นับยอดรันโปรแกรม", "#fde68a")

    n_ev = node_card(272, 352, 442, 92, "ทริกเกอร์: ผู้ใช้รันคำสั่ง ls / whoami / bash", "เกิด execve() → Kernel เรียก Tracepoint → +1 แบบ Atomic", "#fff1f2", badge="ไม่ต้องแก้โค้ดเมื่อย้าย Kernel (CO-RE)", badge_fill="#fecdd3")

    arrows = (
        '<path class="ant" d="M242 256H268" marker-end="url(#bb-ah)"/>'
        '<path class="ant-blue" d="M484 256H510" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-amber" d="M714 256H740" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M614 352V330" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-gen", dur, 0.3, 3.6, [(143, 256), (378, 256)])
        + kf_move("pk-ld", dur, 3.7, 6.8, [(378, 256), (614, 256)])
        + kf_move("pk-ex", dur, 6.9, 10.6, [(614, 398), (614, 256), (830, 256)])
        + kf_pop("bd-cnt", dur, 9.9, 12.7)
    )
    anim_els = (
        pkt_chip("pk-gen", "BPF + BTF", "#93c5fd", 88)
        + pkt_chip("pk-ld", "Attach Hook", "#7de3b4", 100)
        + pkt_chip("pk-ex", "execve +1", "#fde047", 88)
        + pop_pill("bd-cnt", 830, 174, "exec_count++ & trace_pipe ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(482, steps, dur, split_x=256)
    return "Week 05: cilium/ebpf, bpf2go & CO-RE Architecture", 482 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_ev + arrows + anim_els + tbl, anim_css + tbl_css


def build_week06_verifier():
    dur = 13.0
    steps = [
        ("รับ .o Bytecode", "Loader ส่งคำสั่ง eBPF จากไฟล์ C เข้า Kernel เพื่อขออนุญาตทำงาน", 0.3, 2.8),
        ("ตรวจด่าน 1: กราฟเส้นทาง", "CFG Check ยืนยันว่าโปรแกรมจบแน่ ไม่มีลูปวนไม่รู้จบและไม่มีโค้ดค้าง", 2.9, 5.5),
        ("ตรวจ Register & Bounds", "ไล่เช็ก Register R0-R10 ทุกแขนง และบังคับเทียบ data + offset <= data_end", 5.6, 9.2),
        ("ตัดสินใจ Reject vs JIT Pass", "ถ้าจุดไหนเสี่ยงจะถูกปฏิเสธทันที (Fail) ถ้าชัวร์ 100% จึงผ่านไป JIT (Pass)", 9.3, 12.7),
    ]
    header = make_header(
        "Week 06 · Verifier", "ผู้คุมกฎ 3 ด่านก่อนรันใน Kernel",
        "ทำไม eBPF ไม่ทำให้เครื่องค้าง? เพราะ Verifier จำลองรันทุกเส้นทางให้มั่นใจก่อนแปลงเป็น Machine Code"
    )
    stage = make_stage(120, 352, "Bytecode  ──▶  3-Stage Kernel Verifier  ──▶  Reject (Log Error) หรือ Pass (JIT)")

    n_in = node_card(44, 218, 174, 152, "1. .o Bytecode", "จาก Clang / bpf2go", "#ffffff", "bb-doc", "R0-R10 Instructions", "#dbeafe")

    ver_box = (
        '<rect x="252" y="178" width="356" height="278" rx="14" fill="#fff1f2" stroke="#e11d48" stroke-width="2"/>'
        '<text x="430" y="200" font-size="14" font-weight="700" fill="#be123c" text-anchor="middle">ด่านตรวจความปลอดภัย (Kernel Verifier)</text>'
    )
    c1 = node_card(270, 210, 320, 72, "ด่าน 1: CFG (Control Flow Graph)", "ห้ามลูปไม่รู้จบ / ต้องออกจบทุกทาง", "#ffffff")
    c2 = node_card(270, 290, 320, 72, "ด่าน 2: Register R0-R10 State", "ต้องตั้งค่าก่อนใช้ (No Uninit / Bad Ptr)", "#ffffff")
    c3 = node_card(270, 370, 320, 72, "ด่าน 3: Bounds Check", "บังคับ if (data + len > data_end) return", "#ffffff")

    n_fail = node_card(656, 184, 258, 122, "FAIL: ปฏิเสธการโหลด", "คืน Error + Verifier Log ชี้บรรทัด", "#ffe4e6", badge="R1 invalid mem access", badge_fill="#fb7185")
    n_pass = node_card(656, 324, 258, 126, "PASS: JIT Compiler ✓", "แปลงเป็นคำสั่ง CPU Native พร้อมวิ่ง!", "#dcfce7", badge="ปลอดภัยระดับ Kernel 100%", badge_fill="#4ade80")

    arrows = (
        '<path class="ant" d="M218 294H248" marker-end="url(#bb-ah)"/>'
        '<path class="ant-red" d="M608 245H652" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M608 386H652" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-bad", dur, 0.3, 10.6, [(131, 294), (430, 246), (430, 326), (785, 245)])
        + kf_pop("bd-rej", dur, 7.6, 10.8)
        + kf_move("pk-good", dur, 5.4, 12.7, [(131, 294), (430, 246), (430, 326), (430, 406), (785, 387)])
        + kf_pop("bd-jit", dur, 10.0, 12.7)
    )
    anim_els = (
        pkt_chip("pk-bad", "No Bounds!", "#fb7185", 94)
        + pkt_chip("pk-good", "Safe Bounds", "#7de3b4", 102)
        + pop_pill("bd-rej", 785, 174, "REJECTED: เสี่ยงอ่านเกินขอบ! ⛔", "#e11d48", "#ffffff")
        + pop_pill("bd-jit", 785, 314, "PASSED → JIT Native Code ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 06: eBPF Verifier Safety Checks", 492 + tbl_h + 24, header + stage + n_in + ver_box + c1 + c2 + c3 + n_fail + n_pass + arrows + anim_els + tbl, anim_css + tbl_css


def build_week09_uprobe_flow():
    dur = 13.0
    steps = [
        ("เคอร์เนลฝัง 0xCC (int3)", "ตอน attach uprobe เคอร์เนลเขียน Breakpoint (0xCC) ทับคำสั่งแรกของ SSL_write()", 0.3, 3.0),
        ("แอปเรียก SSL_write()", "curl หรือ python3 ส่งข้อความธรรมดาก่อนเข้ารหัส มาชน 0xCC แล้วเด้ง #BP Trap", 3.1, 6.2),
        ("uprobe แอบอ่าน Plaintext", "eBPF ดึง arg2 (buf=%rsi) และ arg3 (num=%rdx) ด้วย bpf_probe_read_user()", 6.3, 9.6),
        ("ส่งเข้า Ringbuf & รันต่อ", "ส่งข้อความให้ Go เก็บ Log แล้วให้ CPU ทำคำสั่งเดิมที่พักไว้ OpenSSL ไม่สะดุด", 9.7, 12.7),
    ]
    header = make_header(
        "Week 09 · Uprobe", "ดักอ่านข้อมูลแอปก่อนเข้ารหัส TLS",
        "วาง Breakpoint (0xCC) ที่ฟังก์ชัน SSL_write ใน libssl.so เพื่ออ่านข้อความดิบโดยไม่ต้องมี Private Key"
    )
    stage = make_stage(120, 344, "User App (curl/OpenSSL)  ──▶  0xCC Breakpoint Trap  ──▶  uprobe_ssl_write  ──▶  Go Log")

    n1 = node_card(44, 186, 186, 140, "1. curl / python3", "เรียก SSL_write(buf, len)", "#eff6ff", "bb-app", "ยังไม่เข้ารหัส (Plaintext)", "#bfdbfe")
    n2 = node_card(266, 186, 198, 140, "2. 0xCC (int3) Trap", "ทับจุดเริ่มใน libssl.so", "#ffe4e6", "bb-shield", "#BP เข้า Kernel (ไร้ SIGTRAP)", "#fecdd3")
    n3 = node_card(500, 186, 206, 140, "3. uprobe_ssl_write", "อ่าน %rsi (buf), %rdx (len)", "#fff1f2", "bb-cpu", "bpf_probe_read_user()", "#fda4af")
    n4 = node_card(742, 186, 174, 140, "4. Go Collector", "รับผ่าน Ringbuf แสดงผล", "#dcfce7", "bb-ring", "ได้ข้อความดิบครบ ✓", "#86efac")

    n_ret = node_card(266, 352, 440, 92, "5. Single-Step คำสั่งเดิมของ SSL_write() แล้วคืนกลับ User Space", "OpenSSL เข้ารหัสเป็น TLS และส่งออกเน็ตตามปกติโดยแอปไม่รู้ตัว", "#fef3c7", badge="Zero App Code Changes", badge_fill="#fde68a")

    arrows = (
        '<path class="ant-blue" d="M230 256H262" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-red" d="M464 256H496" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M706 256H738" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M603 326V348" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-amber" d="M266 398H137V330" marker-end="url(#bb-ah-amber)"/>'
    )

    anim_css = (
        kf_move("pk-pl", dur, 0.3, 6.2, [(137, 256), (365, 256), (603, 256)])
        + kf_move("pk-rb", dur, 6.3, 10.6, [(603, 256), (829, 256)])
        + kf_move("pk-ret", dur, 8.6, 12.7, [(603, 286), (603, 398), (137, 398), (137, 286)])
        + kf_pop("bd-dec", dur, 9.6, 12.7)
    )
    anim_els = (
        pkt_chip("pk-pl", "GET /secret", "#93c5fd", 94)
        + pkt_chip("pk-rb", "Plaintext Log", "#7de3b4", 104)
        + pkt_chip("pk-ret", "Resume TLS", "#fde047", 96)
        + pop_pill("bd-dec", 829, 174, "เห็น Plaintext ก่อนเข้ารหัส ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(482, steps, dur, split_x=256)
    return "Week 09: User-Space Uprobe SSL/TLS Interception", 482 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_ret + arrows + anim_els + tbl, anim_css + tbl_css


def build_week10_lsm_hook_path():
    dur = 13.0
    steps = [
        ("แอปสั่งเปิดไฟล์", "โปรเซสเรียก open(\"secret_keys.pem\") ผ่าน sys_openat() เพื่อขออ่านไฟล์สำคัญ", 0.3, 3.0),
        ("ผ่าน DAC + VFS", "สิทธิ์ User/chmod (may_open) และ VFS ผ่านฉลุย เตรียมส่งเข้า Security Check", 3.1, 6.0),
        ("เข้าด่าน BPF LSM Hook", "เคอร์เนลเรียก security_file_open() เข้าฟังก์ชัน restrict_secret_files()", 6.1, 9.4),
        ("คืน 0 ผ่าน / -EPERM บล็อก", "ถ้าโปรเซสไม่ได้รับอนุญาต คืน -EPERM บล็อกทันทีแม้เป็น root หรือไม่มี log หลอก", 9.5, 12.7),
    ]
    header = make_header(
        "Week 10 · BPF LSM", "เฝ้ายามเปิดไฟล์ระดับเคอร์เนล",
        "เสริมเกราะป้องกันต่อจาก chmod/AppArmor ด้วย LSM Hook ที่สั่งบล็อกการเปิดไฟล์ได้แบบ Real-time"
    )
    stage = make_stage(120, 352, "open()  ──▶  DAC (chmod) + VFS  ──▶  security_file_open (BPF LSM)  ──▶  Allow / -EPERM")

    n1 = node_card(44, 214, 180, 146, "1. โปรเซส open()", "open(\"secret_keys.pem\")", "#eff6ff", "bb-app", "sys_openat()", "#bfdbfe")
    n2 = node_card(256, 214, 172, 146, "2. DAC & VFS", "may_open() → vfs_open()", "#ffffff", "bb-doc", "สิทธิ์ Linux ปกติผ่าน", "#dbeafe")
    n3 = node_card(460, 214, 198, 146, "3. BPF LSM Hook", "restrict_secret_files(file)", "#fff1f2", "bb-shield", "security_file_open()", "#fecdd3")

    n_ok = node_card(696, 184, 218, 120, "return 0 → อนุญาต ✓", "ได้ File Descriptor เปิดไฟล์ได้", "#dcfce7", badge="Authorized App / Path", badge_fill="#86efac")
    n_blk = node_card(696, 326, 218, 126, "return -EPERM → บล็อก!", "Permission Denied ทันที ⛔", "#ffe4e6", badge="ส่ง Alert เข้า Ringbuf", badge_fill="#fb7185")

    arrows = (
        '<path class="ant" d="M224 287H252" marker-end="url(#bb-ah)"/>'
        '<path class="ant" d="M428 287H456" marker-end="url(#bb-ah)"/>'
        '<path class="ant-green" d="M658 260L692 244" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-red" d="M658 314L692 382" marker-end="url(#bb-ah-red)"/>'
    )

    anim_css = (
        kf_move("pk-blk", dur, 0.3, 10.6, [(134, 287), (342, 287), (559, 287), (805, 389)])
        + kf_pop("bd-deny", dur, 7.6, 11.2)
        + kf_move("pk-ok", dur, 6.2, 12.7, [(134, 287), (342, 287), (559, 287), (805, 244)])
        + kf_pop("bd-allow", dur, 10.2, 12.7)
    )
    anim_els = (
        pkt_chip("pk-blk", "cat secret.pem", "#fb7185", 112)
        + pkt_chip("pk-ok", "trusted-svc", "#7de3b4", 98)
        + pop_pill("bd-deny", 805, 314, "Blocked by BPF LSM (-EPERM) ⛔", "#e11d48", "#ffffff")
        + pop_pill("bd-allow", 805, 174, "Allowed (return 0) ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 10: BPF LSM File-Open Enforcement Path", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n_ok + n_blk + arrows + anim_els + tbl, anim_css + tbl_css


def build_week11_telemetry_arch():
    dur = 13.0
    steps = [
        ("XDP นับทราฟฟิกเข้า", "xdp_metrics_prog อ่าน Protocol (TCP/UDP/ICMP) ของทุกแพ็กเก็ตที่เข้า NIC", 0.3, 3.0),
        ("แยกเขียนลงแต่ละ CPU", "อัปเดตตัวนับใน PERCPU_ARRAY ตามคอร์ใครคอร์มัน ไม่ต้องแย่ง Lock กัน", 3.1, 6.4),
        ("Go รวมยอดเปิด Endpoint", "xdpCollector รวมค่าจากทุก CPU เป็น ebpf_xdp_packets_total บนพอร์ต :2112", 6.5, 9.8),
        ("Grafana ดึงกราฟ Real-time", "Prometheus มาดึง /metrics ทุกระยะ แล้วขึ้นแดชบอร์ด Grafana แบบ Real-time", 9.9, 12.7),
    ]
    header = make_header(
        "Week 11 · Telemetry", "นับสถิติความเร็วสูง → Grafana",
        "ใช้ PERCPU_ARRAY ลดปัญหา CPU แย่ง Lock กัน แล้วส่งยอดรวมให้ Prometheus/Grafana ทำกราฟ"
    )
    stage = make_stage(120, 344, "XDP Metrics  ──▶  PERCPU_ARRAY (Lockless)  ──▶  Go :2112/metrics  ──▶  Grafana")

    n1 = node_card(44, 212, 180, 146, "1. xdp_metrics", "แยกนับ TCP/UDP/ICMP", "#fff1f2", "bb-nic", "XDP_PASS ส่งต่อ", "#fecdd3")

    p_box = (
        '<rect x="256" y="182" width="218" height="256" rx="14" fill="#fef3c7" stroke="#d97706" stroke-width="2"/>'
        '<text x="365" y="204" font-size="13.5" font-weight="700" fill="#92400e" text-anchor="middle">2. PERCPU_ARRAY (Lock-Free)</text>'
    )
    c0 = node_card(272, 214, 186, 64, "CPU 0 Slot", "pkts += 1, bytes += len", "#ffffff")
    c1 = node_card(272, 286, 186, 64, "CPU 1 Slot", "pkts += 1, bytes += len", "#ffffff")
    c2 = node_card(272, 358, 186, 64, "CPU 2 Slot", "pkts += 1, bytes += len", "#ffffff")

    n3 = node_card(508, 212, 196, 146, "3. Go Exporter", "Sum CPU0+1+2 → :2112", "#eff6ff", "bb-app", "GET /metrics", "#bfdbfe")
    n4 = node_card(738, 212, 178, 146, "4. Prometheus", "+ Grafana Dashboard", "#dcfce7", "bb-server", "Scrape & Visualize ✓", "#86efac")

    arrows = (
        '<path class="ant-amber" d="M224 260L268 246" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-amber" d="M224 285H268" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-amber" d="M224 310L268 390" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M474 285H504" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-green" d="M704 285H734" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-m0", dur, 0.3, 5.2, [(134, 285), (365, 246)])
        + kf_move("pk-m1", dur, 1.4, 6.2, [(134, 285), (365, 318)])
        + kf_move("pk-sum", dur, 6.3, 10.2, [(365, 318), (606, 285)])
        + kf_move("pk-sc", dur, 9.8, 12.7, [(606, 285), (827, 285)])
        + kf_pop("bd-gr", dur, 10.4, 12.7)
    )
    anim_els = (
        pkt_chip("pk-m0", "TCP +1", "#fde047", 72)
        + pkt_chip("pk-m1", "UDP +1", "#fdba74", 72)
        + pkt_chip("pk-sum", "Sum All CPU", "#93c5fd", 104)
        + pkt_chip("pk-sc", ":2112/metrics", "#7de3b4", 108)
        + pop_pill("bd-gr", 827, 174, "Grafana ขึ้นกราฟ Real-time ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(482, steps, dur, split_x=256)
    return "Week 11: Per-CPU eBPF Telemetry → Prometheus → Grafana", 482 + tbl_h + 24, header + stage + n1 + p_box + c0 + c1 + c2 + n3 + n4 + arrows + anim_els + tbl, anim_css + tbl_css


def build_week12_ips_arch():
    dur = 13.0
    steps = [
        ("ตรวจบัญชีดำ blacklist_map", "XDP อ่านหัว IP แล้วเช็กว่าเคยโดนแบนและยังไม่หมดอายุ (TTL) หรือไม่", 0.3, 3.2),
        ("นับความถี่ rate_tracker", "นับ TCP SYN / ICMP ต่อวินาที: ถ้าเกินโควตา (SYN>100 / ICMP>50) ถือว่าโจมตี!", 3.3, 6.8),
        ("แบนอัตโนมัติ + XDP_DROP", "ใส่ IP ลง blacklist_map ยิงแจ้งเตือนเข้า ips_events แล้วทิ้งแพ็กเก็ตทันที", 6.9, 10.0),
        ("Control Plane ดูแลอายุแบน", "ips-agent อ่าน Ringbuf ส่ง Prometheus และตั้ง TTL Reaper ปลดแบนเมื่อครบเวลา", 10.1, 12.7),
    ]
    header = make_header(
        "Week 12 · Mini IPS", "ระบบกันยิง + แบน IP อัตโนมัติ",
        "รวม XDP Data Plane ที่ตรวจจับ Flood & แบนทันที เข้ากับ Go Control Plane ที่คอยปลดแบนเมื่อหมดเวลา"
    )
    stage = make_stage(120, 352, "XDP Data Plane (ตรวจสอบ & แบนทันที)  ◀═══ Maps / Ringbuf ═══▶  Go Control Plane (Reaper + API)")

    n1 = node_card(44, 212, 162, 146, "1. Ingress Traffic", "SYN Flood / ICMP", "#ffffff", "bb-nic", "Bounds Check", "#dcfce7")
    n2 = node_card(236, 212, 198, 146, "2. XDP ips_kern.c", "เช็ก blacklist + rate", "#fff1f2", "bb-shield", "Data Plane ระดับ ns", "#fecdd3")

    n_map = node_card(466, 184, 214, 114, "3. blacklist & rate", "SYN > 100 → Auto-Ban", "#fef3c7", badge="LRU Hash + TTL", badge_fill="#fde68a")
    n_evt = node_card(466, 326, 214, 118, "ips_events Ringbuf", "ส่ง Alert เหตุการณ์แบน", "#dbeafe", badge="แจ้งเตือน Real-time", badge_fill="#93c5fd")

    n_drop = node_card(714, 184, 200, 114, "XDP_DROP ทันที!", "IP ในบัญชีดำไม่หลุดเข้า", "#ffe4e6", badge="หรือปกติ → XDP_PASS", badge_fill="#fb7185")
    n_ctl = node_card(714, 326, 200, 118, "4. ips-agent (Go)", "TTL Reaper + REST API", "#dcfce7", badge="Prometheus :2112", badge_fill="#86efac")

    arrows = (
        '<path class="ant" d="M206 285H232" marker-end="url(#bb-ah)"/>'
        '<path class="ant-amber" d="M434 256L462 241" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M434 314L462 385" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-red" d="M680 241H710" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M680 385H710" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-green" d="M814 326V302" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-syn", dur, 0.3, 6.8, [(125, 285), (335, 285), (573, 241)])
        + kf_pop("bd-ban", dur, 6.2, 9.8)
        + kf_move("pk-drp", dur, 6.9, 10.2, [(573, 241), (814, 241)])
        + kf_move("pk-reap", dur, 8.6, 12.7, [(335, 285), (573, 385), (814, 385), (814, 241)])
    )
    anim_els = (
        pkt_chip("pk-syn", "SYN Flood!", "#fb7185", 94)
        + pop_pill("bd-ban", 573, 174, "Auto-Ban → blacklist_map!", "#e11d48", "#ffffff")
        + pkt_chip("pk-drp", "XDP_DROP", "#fda4af", 88)
        + pkt_chip("pk-reap", "Alert + TTL", "#7de3b4", 94)
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 12: XDP Inline Mini-IPS Architecture", 492 + tbl_h + 24, header + stage + n1 + n2 + n_map + n_evt + n_drop + n_ctl + arrows + anim_els + tbl, anim_css + tbl_css


def build_week13_drop_path():
    dur = 13.0
    steps = [
        ("แพ็กเก็ตตกหล่นระหว่างทาง", "เกิดปัญหาใน Linux Stack เช่น RX เต็ม, Header พัง, Firewall DROP หรือไม่มีพอร์ตรับ", 0.3, 3.0),
        ("เรียก kfree_skb_reason()", "เคอร์เนลทิ้งแพ็กเก็ตพร้อมแนบรหัสเหตุผล SKB_DROP_REASON_* เข้าไปด้วย", 3.1, 6.2),
        ("Tracepoint ดักจับทันที", "skb:kfree_skb อ่านเหตุผล + Location Pointer (ที่อยู่ฟังก์ชันต้นตอ) ส่งให้ Go", 6.3, 9.6),
        ("แปลรหัสเป็นภาษาคน", "Go เทียบรหัสจาก Kernel BTF และแปล Address ผ่าน /proc/kallsyms ให้เห็นจุดพัง", 9.7, 12.7),
    ]
    header = make_header(
        "Week 13 · DropWatch", "สืบหาจุดที่แพ็กเก็ตโดนทิ้งใน Kernel",
        "เวลาเน็ตหายอย่าเพิ่งเดา: เกาะ skb:kfree_skb เพื่อดูทั้ง 'สาเหตุ (Reason)' และ 'ฟังก์ชันที่สั่งทิ้ง'"
    )
    stage = make_stage(120, 352, "จุดทิ้งใน Kernel Stack  ──▶  kfree_skb_reason()  ──▶  Tracepoint + Go (BTF + kallsyms)")

    n1 = node_card(44, 184, 240, 114, "1. จุดพังใน Stack", "Bad Header / No Socket / DROP", "#fff1f2", badge="กำลังทำลาย sk_buff", badge_fill="#fecdd3")
    n2 = node_card(336, 184, 260, 114, "2. kfree_skb_reason()", "แนบ reason + caller address", "#ffe4e6", badge="SKB_DROP_REASON_*", badge_fill="#fda4af")
    n3 = node_card(648, 184, 266, 114, "3. tracepoint kfree_skb", "dropwatch.c เก็บ event", "#fef3c7", badge="ส่งเข้า Ringbuf + Hash", badge_fill="#fde68a")

    n4 = node_card(648, 332, 266, 114, "4. Drop Counter & Events", "รวมยอดแยกตามสาเหตุ", "#dbeafe", badge="Kernel → User Ringbuf", badge_fill="#bfdbfe")
    n5 = node_card(336, 332, 260, 114, "5. Go + BTF & kallsyms", "แปลง enum + ชื่อฟังก์ชัน", "#eff6ff", badge="ip_rcv / tcp_v4_rcv / ...", badge_fill="#93c5fd")
    n6 = node_card(44, 332, 240, 114, "6. รายงานผลชัดเป๊ะ!", "รู้ทันทีทิ้งที่ไหน เพราะอะไร", "#dcfce7", badge="เช่น NO_SOCKET @ tcp_v4_rcv", badge_fill="#86efac")

    arrows = (
        '<path class="ant-red" d="M284 241H332" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-amber" d="M596 241H644" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M781 298V328" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-blue" d="M648 389H600" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-green" d="M336 389H288" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-dr", dur, 0.3, 12.4, [(164, 241), (466, 241), (781, 241), (781, 389), (466, 389), (164, 389)])
        + kf_pop("bd-rs", dur, 3.4, 6.8)
        + kf_pop("bd-ks", dur, 9.8, 12.7)
    )
    anim_els = (
        pkt_chip("pk-dr", "sk_buff Drop", "#fb7185", 104)
        + pop_pill("bd-rs", 466, 174, "Reason + Addr Captured!", "#e11d48", "#ffffff")
        + pop_pill("bd-ks", 164, 320, "ชี้เป้าฟังก์ชันต้นตอ ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 13: Kernel Packet Drop Tracing with DropWatch", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n5 + n6 + arrows + anim_els + tbl, anim_css + tbl_css


def build_week14_connect_hook():
    dur = 13.0
    steps = [
        ("แอปใน cgroup สั่ง connect()", "โปรแกรมใน cgroup w14-sock-enforce เรียก connect() ไปยัง 127.0.0.1:2323", 0.3, 3.0),
        ("เรียก sock4_connect", "ก่อนสร้าง SYN Packet เคอร์เนลแวะรัน BPF_CGROUP_RUN_PROG_INET4_CONNECT", 3.1, 6.2),
        ("ค้นบัญชีดำ IP / Port", "เช็ก blocked_ips กับ blocked_ports ว่าปลายทางอยู่ในรายการห้ามหรือไม่", 6.3, 9.4),
        ("return 0 บล็อก / 1 ปล่อย SYN", "ถ้าเจอคืน 0 → -EPERM ทันที (SYN ไม่หลุดออกสาย) ถ้าไม่เจอคืน 1 ต่อได้ปกติ", 9.5, 12.7),
    ]
    header = make_header(
        "Week 14 · cgroup/connect4", "บล็อกการเชื่อมต่อก่อนส่ง SYN",
        "ดักตั้งแต่แอปเพิ่งเริ่ม connect() ในระดับ Socket: บล็อกได้แม้ยังไม่ทันส่ง TCP SYN ออกจากเครื่อง"
    )
    stage = make_stage(120, 352, "App in cgroup  ──▶  __sys_connect()  ──▶  sock4_connect (BPF)  ──▶  -EPERM vs TCP SYN")

    n1 = node_card(44, 212, 184, 146, "1. App ใน cgroup", "connect(127.0.0.1:2323)", "#eff6ff", "bb-app", "w14-sock-enforce", "#bfdbfe")
    n2 = node_card(260, 212, 206, 146, "2. sock4_connect", "INET4_CONNECT Hook", "#fff1f2", "bb-shield", "ทำงานก่อนสร้าง TCP SYN!", "#fecdd3")
    n3 = node_card(498, 212, 174, 146, "3. Policy Maps", "blocked_ips / ports", "#fef3c7", "bb-map", ":2323 อยู่ในบัญชีดำ", "#fde68a")

    n_blk = node_card(706, 184, 208, 120, "return 0 → -EPERM!", "ปฏิเสธทันที (Zero Packet)", "#ffe4e6", badge="SYN ไม่หลุดออกสาย ⛔", badge_fill="#fb7185")
    n_ok = node_card(706, 326, 208, 124, "return 1 → ต่อได้ ✓", "ไป tcp_v4_connect() ส่ง SYN", "#dcfce7", badge="เชื่อมต่อปลายทางปกติ", badge_fill="#86efac")

    arrows = (
        '<path class="ant-blue" d="M228 285H256" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-amber" d="M466 285H494" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-red" d="M672 258L702 244" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M672 312L702 384" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-c1", dur, 0.3, 10.6, [(136, 285), (363, 285), (585, 285), (810, 244)])
        + kf_pop("bd-c0", dur, 7.6, 11.2)
        + kf_move("pk-c2", dur, 6.2, 12.7, [(136, 285), (363, 285), (585, 285), (810, 388)])
        + kf_pop("bd-c1", dur, 10.2, 12.7)
    )
    anim_els = (
        pkt_chip("pk-c1", ":2323 (Blocked)", "#fb7185", 108)
        + pkt_chip("pk-c2", ":443 (Allow)", "#7de3b4", 100)
        + pop_pill("bd-c0", 810, 174, "Stopped Before SYN (-EPERM) ⛔", "#e11d48", "#ffffff")
        + pop_pill("bd-c1", 810, 316, "SYN Sent Normally ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 14: Cgroup Socket connect4 Enforcement", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n_blk + n_ok + arrows + anim_els + tbl, anim_css + tbl_css


def build_week15_reverse_shell():
    dur = 13.0
    steps = [
        ("เว็บแอปโดนเจาะรัน Shell", "Victim Web App เกิด Command Injection แล้วแตกโปรเซสลูก bash / sh ขึ้นมา", 0.3, 3.0),
        ("ชี้ fd 0/1/2 เข้า TCP Socket", "ผู้บุกรุกใช้ /dev/tcp/ATK/4444 โยง stdin/stdout/stderr ของ sh ไปหาเครื่อง nc -l", 3.1, 6.4),
        ("eBPF ไล่สายตระกูล & fd", "revshell_detect.c เดินย้อน task_struct parent + เช็กว่า fd0/1/2 เป็น TCP Socket", 6.5, 9.8),
        ("ยิง Alert เข้า Ringbuf!", "ตรวจครบทั้ง Lineage น่าสงสัย + Socket stdin/stdout → แจ้งเตือน Go ทันที!", 9.9, 12.7),
    ]
    header = make_header(
        "Week 15 · Reverse Shell", "จับแฮกเกอร์แอบเปิด Shell ออกนอก",
        "รู้ทัน Reverse Shell จาก 2 หลักฐาน: โปรเซสลูกผิดธรรมชาติ + fd 0/1/2 (คีย์บอร์ด/จอ) กลายเป็น TCP Socket"
    )
    stage = make_stage(120, 352, "Victim App  ──▶  bash/sh (fd 0/1/2 = Socket)  ◀══▶  eBPF Detector (task_struct + fd check)")

    n1 = node_card(44, 186, 196, 134, "1. Victim Web App", "โดน Command Injection", "#eff6ff", "bb-app", "Parent Process (web)", "#bfdbfe")
    n2 = node_card(272, 186, 212, 134, "2. Child: bash / sh", "exec /dev/tcp/ATK/4444", "#ffe4e6", "bb-app", "fd 0,1,2 → TCP Socket!", "#fb7185")
    n3 = node_card(518, 186, 194, 134, "3. Attacker nc -l", "รับ Shell ทางพอร์ต :4444", "#fff1f2", "bb-server", "Remote Control Session", "#fda4af")
    n4 = node_card(742, 186, 174, 134, "4. Go Alert", "รับสัญญาณเตือนฉุกเฉิน!", "#dcfce7", "bb-ring", "Ringbuf Alert 🚨", "#86efac")

    n_det = node_card(160, 348, 520, 96, "revshell_detect.c (eBPF Tracepoint / Kprobe)", "เช็ก 2 เงื่อนไข: (1) task_struct lineage web→sh  +  (2) fd0/fd1 ชี้ไป struct socket", "#fef3c7", badge="จับได้แม้ตั้งชื่อสคริปต์ปลอม!", badge_fill="#fde68a")

    arrows = (
        '<path class="ant-red" d="M240 253H268" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-red" d="M484 253H514" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-amber" d="M378 320V344" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M680 396H829V324" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-cmd", dur, 0.3, 6.2, [(142, 253), (378, 253), (615, 253)])
        + kf_move("pk-fd", dur, 5.2, 9.6, [(378, 286), (378, 396), (560, 396)])
        + kf_move("pk-al", dur, 9.4, 12.7, [(560, 396), (829, 396), (829, 253)])
        + kf_pop("bd-sh", dur, 9.8, 12.7)
    )
    anim_els = (
        pkt_chip("pk-cmd", "sh <&3 >&3", "#fb7185", 96)
        + pkt_chip("pk-fd", "fd0=TCP!", "#fde047", 84)
        + pkt_chip("pk-al", "ALERT! 🚨", "#fda4af", 92)
        + pop_pill("bd-sh", 829, 174, "Reverse Shell Detected! 🚨", "#e11d48", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 15: eBPF Reverse Shell Lineage & Socket FD Detection", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_det + arrows + anim_els + tbl, anim_css + tbl_css


def build_week16_inventory_loop():
    dur = 12.5
    steps = [
        ("เริ่มเดินสำรวจ id = 0", "Go เริ่มเรียก sys_bpf(BPF_PROG_GET_NEXT_ID) จาก id=0 เพื่อขอโปรแกรมถัดไป", 0.3, 3.0),
        ("เปิด FD ของโปรแกรมนั้น", "ถ้ายังไม่หมด (ไม่เจอ ENOENT) เอา id ไปเรียก BPF_PROG_GET_FD_BY_ID", 3.1, 6.0),
        ("ดึงข้อมูล Metadata ครบชุด", "เรียก BPF_OBJ_GET_INFO_BY_FD ได้ type, name, tag, uid และ map_ids", 6.1, 9.2),
        ("วนรอบ & เฝ้าโหลดใหม่", "อัปเดต id แล้ววนลูปจนครบทั้งเครื่อง พร้อมติด trace_bpf จับการแอบโหลดเพิ่ม", 9.3, 12.2),
    ]
    header = make_header(
        "Week 16 · eBPF Audit", "ตรวจเช็ก eBPF ที่แอบรันทั้งเครื่อง",
        "ไล่สำรวจทุกโปรแกรม eBPF ด้วย syscall 3 จังหวะ (GET_NEXT_ID → GET_FD → GET_INFO) กัน Rootkit แฝงตัว"
    )
    stage = make_stage(120, 352, "Start id=0  ──▶  GET_NEXT_ID  ──▶  GET_FD_BY_ID  ──▶  GET_INFO_BY_FD  ──▶  Next id")

    n1 = node_card(44, 198, 178, 146, "1. GET_NEXT_ID", "เริ่มจาก id = 0 → cur_id", "#eff6ff", "bb-app", "ENOENT = จบครบทุกตัว", "#bfdbfe")
    n2 = node_card(260, 198, 198, 146, "2. GET_FD_BY_ID", "NewProgramFromID(id)", "#fef3c7", "bb-shield", "ได้ Handle (fd) ชั่วคราว", "#fde68a")
    n3 = node_card(496, 198, 214, 146, "3. GET_INFO_BY_FD", "prog.Info() อ่านรายละเอียด", "#dcfce7", "bb-doc", "type, name, tag, map_ids", "#86efac")
    n4 = node_card(748, 198, 168, 146, "4. Inventory List", "บันทึกลง Audit Report", "#e7dff8", "bb-map", "เช็กซ้ำ trace_bpf", "#ddd6fe")

    n_loop = node_card(180, 366, 560, 82, "วนลูป id = cur_id หาโปรแกรมตัวถัดไปจนกว่า Kernel จะตอบ ENOENT", "เสริมด้วย trace_bpf จับ sys_bpf(BPF_PROG_LOAD) แบบ Real-time ถ้ามีใครโหลดตัวใหม่เข้ามา", "#fff1f2")

    arrows = (
        '<path class="ant-blue" d="M222 271H256" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-amber" d="M458 271H492" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M710 271H744" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant" d="M832 344V407H744" marker-end="url(#bb-ah)"/>'
        '<path class="ant" d="M180 407H133V348" marker-end="url(#bb-ah)"/>'
    )

    anim_css = (
        kf_move("pk-id", dur, 0.3, 9.4, [(133, 271), (359, 271), (603, 271), (832, 271)])
        + kf_move("pk-nxt", dur, 9.5, 12.2, [(832, 344), (832, 407), (133, 407), (133, 271)])
        + kf_pop("bd-inv", dur, 6.4, 10.0)
    )
    anim_els = (
        pkt_chip("pk-id", "prog id=42", "#93c5fd", 92)
        + pkt_chip("pk-nxt", "next(42)->43", "#fde047", 104)
        + pop_pill("bd-inv", 603, 184, "Info: XDP / uid=0 / tag ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 16: eBPF Program Inventory Loop & Runtime Audit", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_loop + arrows + anim_els + tbl, anim_css + tbl_css


def build_week17_block_io_path():
    dur = 13.0
    steps = [
        ("แอปสั่งอ่าน/เขียนไฟล์", "App เรียก read/write/fsync แล้วไม่เจอใน Page Cache จึงต้องลงไปหา Disk จริง", 0.3, 2.8),
        ("เข้าคิว blk-mq (insert)", "Multi-Queue Block Layer รวมคำขอเป็น struct request แล้วเกิด tracepoint block_rq_insert", 2.9, 5.6),
        ("ส่งเข้าฮาร์ดดิสก์ (issue = t0)", "ไดรเวอร์ NVMe/AHCI หยิบงานไปสั่ง Hardware (block_rq_issue) → eBPF จดเวลา t0", 5.7, 9.0),
        ("ทำงานเสร็จ (complete = t1)", "ดิสก์ตอบกลับ (block_rq_complete) → คำนวณ t1 - t0 ใส่ Log2 Histogram ดูความช้า", 9.1, 12.7),
    ]
    header = make_header(
        "Week 17 · Disk I/O", "จับความช้าของดิสก์ด้วย blk-mq",
        "วัดเฉพาะเวลาที่ Hardware/Driver ทำงานจริง (D2C Latency) ด้วยการจับคู่ block_rq_issue กับ complete"
    )
    stage = make_stage(120, 352, "App / VFS  ──▶  blk-mq (insert)  ──▶  Driver issue (t0)  ──▶  NVMe Disk  ──▶  complete (t1)")

    n1 = node_card(44, 186, 184, 134, "1. VFS / Page Cache", "Cache Miss → ลง Block", "#eff6ff", "bb-app", "read / write / fsync", "#bfdbfe")
    n2 = node_card(260, 186, 198, 134, "2. blk-mq Queue", "รวม bio → struct request", "#fef3c7", "bb-ring", "block_rq_insert", "#fde68a")
    n3 = node_card(490, 186, 198, 134, "3. block_rq_issue", "ส่งเข้า NVMe / AHCI (จด t0)", "#fff1f2", "bb-shield", "D2C Timer Start!", "#fecdd3")
    n4 = node_card(720, 186, 194, 134, "4. Hardware Disk", "อ่าน-เขียน Sector จริง", "#e2e8f0", "bb-disk", "I/O In-Flight...", "#cbd5e1")

    n_hist = node_card(220, 348, 520, 96, "5. block_rq_complete (เวลา t1) → latency = t1 - t0 ลง Log2 Histogram", "แยกได้ทันทีว่าดิสก์ช้าเองหรือแค่รอคิว (Queue vs Device Latency)", "#dcfce7", badge="แสดงกราฟ Bucket (us / ms) ✓", badge_fill="#86efac")

    arrows = (
        '<path class="ant-blue" d="M228 253H256" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-amber" d="M458 253H486" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-red" d="M688 253H716" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M817 320V396H744" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-io", dur, 0.3, 9.0, [(136, 253), (359, 253), (589, 253), (817, 253)])
        + kf_pop("bd-t0", dur, 5.8, 8.8)
        + kf_move("pk-cmp", dur, 8.8, 12.4, [(817, 253), (817, 396), (480, 396)])
        + kf_pop("bd-t1", dur, 9.6, 12.7)
    )
    anim_els = (
        pkt_chip("pk-io", "4K Write req", "#93c5fd", 104)
        + pop_pill("bd-t0", 589, 174, "issue() จด t0[req]!", "#e11d48", "#ffffff")
        + pkt_chip("pk-cmp", "IRQ Done (t1)", "#7de3b4", 108)
        + pop_pill("bd-t1", 480, 336, "Histogram += (t1 - t0) ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 17: Linux Block I/O Path & D2C Latency Histogram", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_hist + arrows + anim_els + tbl, anim_css + tbl_css


def build_week18_sampling_profiler():
    dur = 13.0
    steps = [
        ("ตั้งนาฬิกาสุ่มตรวจ 99 Hz", "เปิด perf_event (PERF_COUNT_SW_CPU_CLOCK) ยิง Interrupt ทุก 10 ms โดยไม่ตรงรอบ 100 Hz", 0.3, 3.0),
        ("eBPF แคป Call Stack สด", "ทุก Interrupt เรียก bpf_get_stackid() เก็บทั้งฝั่ง Kernel และฝั่ง User (BPF_F_USER_STACK)", 3.1, 6.4),
        ("เก็บ Stack ID & นับความถี่", "บันทึกเลข ID ลง stack_traces และนับยอดซ้ำของ {pid, kstack, ustack} ใน stack_counts", 6.5, 9.6),
        ("แปลชื่อ → Flame Graph", "Go เทียบ /proc/kallsyms และ /proc/<pid>/maps แปลง Address เป็นชื่อฟังก์ชันวาด Flame Graph", 9.7, 12.7),
    ]
    header = make_header(
        "Week 18 · Profiler", "สร้าง Flame Graph หาคอขวด CPU",
        "สุ่มถ่ายรูป Call Stack ด้วยความถี่ 99 Hz เพื่อดูว่าฟังก์ชันไหนกิน CPU หนักสุดโดยแทบไม่หน่วงเครื่อง"
    )
    stage = make_stage(120, 352, "99 Hz Timer  ──▶  eBPF bpf_get_stackid()  ──▶  Maps  ──▶  Go Symbolizer  ──▶  Flame Graph")

    n1 = node_card(44, 188, 184, 140, "1. CPU 99 Hz Timer", "PERF_COUNT_SW_CPU_CLOCK", "#fff1f2", "bb-cpu", "สุ่ม Snapshot ทุก ~10ms", "#fecdd3")
    n2 = node_card(260, 188, 212, 140, "2. perf_event eBPF", "bpf_get_stackid(ctx)", "#fef3c7", "bb-shield", "อ่าน Kernel + User Stack", "#fde68a")
    n3 = node_card(504, 188, 198, 140, "3. Stack Maps", "stack_traces + counts", "#dbeafe", "bb-map", "{pid, kstack, ustack}++", "#93c5fd")
    n4 = node_card(734, 188, 182, 140, "4. Go Symbolizer", "kallsyms + /proc/pid/maps", "#dcfce7", "bb-app", "ส่งเข้า flamegraph.py", "#86efac")

    n_fg = node_card(180, 350, 560, 94, "ผลลัพธ์: Flame Graph SVG — แถบยิ่งกว้าง = กินเวลา CPU เยอะสุด!", "เช่น main() → handleReq() → jsonEncode() (90% CPU) เห็นจุดแก้คอขวดได้ทันที", "#ffe4e6")

    arrows = (
        '<path class="ant-red" d="M228 258H256" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-amber" d="M472 258H500" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M702 258H730" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-green" d="M825 328V397H744" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-hz", dur, 0.3, 6.4, [(136, 258), (366, 258), (603, 258)])
        + kf_move("pk-sym", dur, 6.5, 10.6, [(603, 258), (825, 258), (825, 397), (460, 397)])
        + kf_pop("bd-fg", dur, 9.8, 12.7)
    )
    anim_els = (
        pkt_chip("pk-hz", "Stack Snapshot", "#fde047", 112)
        + pkt_chip("pk-sym", "0xffff → func()", "#93c5fd", 112)
        + pop_pill("bd-fg", 460, 338, "Flame Graph SVG Ready! 🔥", "#e11d48", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 18: 99Hz CPU Sampling Profiler & Flame Graph", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_fg + arrows + anim_els + tbl, anim_css + tbl_css


def build_week19_page_fault():
    dur = 13.0
    steps = [
        ("malloc() แค่จองสิทธิ์ (VMA)", "ตอนแอปขอ malloc(50 MB) เคอร์เนลยังไม่ให้ RAM จริง แค่จดสัญญา VMA ไว้ก่อน", 0.3, 3.0),
        ("เขียนจริงชน #PF (Vector 14)", "พอแอปเริ่มเขียน *p = 1 CPU ไม่เจอหน้าเพจจริงจึงโยน Page Fault เข้า exc_page_fault()", 3.1, 6.4),
        ("จัดสรร 4 KiB + หักงบ cgroup", "trace_page_fault_user เก็บสถิติ ขณะ handle_mm_fault() จ่าย RAM จริงและชาร์จ cgroup", 6.5, 9.6),
        ("เกินงบ → OOM Killer!", "เมื่อ cgroup เต็มและคืนพื้นที่ไม่ไหว เคอร์เนลเรียก OOM Killer สั่งฆ่าโปรเซสทันที", 9.7, 12.7),
    ]
    header = make_header(
        "Week 19 · Page Fault", "เบื้องหลัง RAM จริง & OOM Killer",
        "ทำไม malloc() แล้วยังไม่เสีย RAM จนกว่าจะเขียนจริง? มาดูจังหวะ #PF จัดสรร 4 KiB จนถึงจุดโดน OOM Kill"
    )
    stage = make_stage(120, 352, "malloc (VMA)  ──▶  *p = 1 (#PF)  ──▶  handle_mm_fault (4KiB)  ──▶  cgroup OK vs OOM Kill")

    n1 = node_card(44, 212, 184, 146, "1. malloc(50 MB)", "จองแค่ Address (VMA)", "#eff6ff", "bb-app", "ยังไม่ใช้ RAM จริง", "#bfdbfe")
    n2 = node_card(260, 212, 198, 146, "2. *p = 1 → #PF", "exc_page_fault() + eBPF", "#fef3c7", "bb-shield", "trace_page_fault_user", "#fde68a")
    n3 = node_card(490, 212, 184, 146, "3. mm + cgroup", "handle_mm_fault() 4 KiB", "#e0f2fe", "bb-cpu", "เช็กงบ memory.max", "#bae6fd")

    n_ok = node_card(706, 184, 208, 118, "ยังไม่เกินงบ → ผ่าน ✓", "ผูก Physical Page ใช้งานต่อ", "#dcfce7", badge="Demand Paging ปกติ", badge_fill="#86efac")
    n_oom = node_card(706, 324, 208, 126, "เกิน memory.max → OOM!", "mark_victim → SIGKILL 9 💀", "#ffe4e6", badge="OOM Killer ทำงาน!", badge_fill="#fb7185")

    arrows = (
        '<path class="ant-blue" d="M228 285H256" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-amber" d="M458 285H486" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M674 256L702 243" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-red" d="M674 314L702 387" marker-end="url(#bb-ah-red)"/>'
    )

    anim_css = (
        kf_move("pk-pf1", dur, 0.3, 9.8, [(136, 285), (359, 285), (582, 285), (810, 243)])
        + kf_move("pk-oom", dur, 5.4, 12.7, [(136, 285), (359, 285), (582, 285), (810, 387)])
        + kf_pop("bd-4k", dur, 6.6, 9.6)
        + kf_pop("bd-kill", dur, 9.8, 12.7)
    )
    anim_els = (
        pkt_chip("pk-pf1", "4 KiB Page", "#7de3b4", 88)
        + pkt_chip("pk-oom", "Over Limit!", "#fb7185", 94)
        + pop_pill("bd-4k", 810, 174, "Allocated 4 KiB ✓", "#16a34a", "#ffffff")
        + pop_pill("bd-kill", 810, 314, "OOM Kill (SIGKILL) 💀", "#e11d48", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 19: Page Fault Demand Allocation & cgroup OOM Killer", 492 + tbl_h + 24, header + stage + n1 + n2 + n3 + n_ok + n_oom + arrows + anim_els + tbl, anim_css + tbl_css


def build_week23_iter_flow():
    dur = 13.0
    steps = [
        ("โหลด BPF Iterator", "Go โหลด iter/task (BPF_PROG_LOAD) แล้วสร้าง seq_file 1 ตัวด้วย BPF_ITER_CREATE", 0.3, 3.2),
        ("อ่านทีเดียวด้วย read(fd)", "Go เรียก read(fd) เพียงครั้งเดียวแทนที่จะวนเปิด /proc/<pid>/stat เป็นพันไฟล์", 3.3, 6.4),
        ("เคอร์เนลวนทุก Process", "Kernel เดินดู task_struct ทุกตัว แล้วเรียก dump_task + BPF_SEQ_PRINTF() ลงบัฟเฟอร์", 6.5, 9.8),
        ("ส่งผลรวมก้อนเดียวถึง EOF", "Go ได้รายชื่อโปรเซสครบทั้งเครื่องใน Syscall ไม่กี่ครั้ง ประหยัด Context Switch สุดๆ", 9.9, 12.7),
    ]
    header = make_header(
        "Week 23 · BPF Iterator", "สแกนทั้งเครื่องใน Syscall เดียว",
        "ไม่ต้องเปิด /proc/<pid> ทีละพันไฟล์! ให้ Kernel เดินวน struct task_struct เองแล้วเทผลรวมกลับมาทีเดียว"
    )
    stage = make_stage(120, 348, "Go Loader (BPF_ITER_CREATE)  ──▶  1x read(fd)  ──▶  Kernel Loops Every Task  ──▶  Batch EOF")

    n1 = node_card(44, 198, 194, 146, "1. Go + iter/task", "BPF_LINK_CREATE +", "#eff6ff", "bb-app", "BPF_ITER_CREATE (1 fd)", "#bfdbfe")
    n2 = node_card(272, 198, 206, 146, "2. Single read(fd)", "ขอข้อมูลทีเดียวทั้งชุด", "#fef3c7", "bb-doc", "ไม่ต้องวน open(/proc/*)", "#fde68a")
    n3 = node_card(512, 198, 212, 146, "3. dump_task Loop", "Kernel วนทุก task_struct", "#fff1f2", "bb-cpu", "BPF_SEQ_PRINTF(seq, ...)", "#fecdd3")
    n4 = node_card(758, 198, 158, 146, "4. Batch → EOF", "ส่งก้อนผลลัพธ์ให้ Go", "#dcfce7", "bb-ring", "เร็ว & เบาสุดๆ ✓", "#86efac")

    n_cmp = node_card(80, 364, 790, 82, "เทียบ /proc เดิม: 2,000 โปรเซสต้องเรียก open+read+close กว่า 6,000 Syscalls!", "แต่ BPF Iterator เรียก read(seq_fd) แค่ไม่กี่รอบก็ได้ข้อมูลครบทั้ง Kernel + Private Data", "#e0f2fe")

    arrows = (
        '<path class="ant-blue" d="M238 271H268" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-amber" d="M478 271H508" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M724 271H754" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-fd1", dur, 0.3, 6.2, [(141, 271), (375, 271), (618, 271)])
        + kf_move("pk-bat", dur, 6.5, 12.2, [(618, 271), (837, 271), (837, 405), (141, 405)])
        + kf_pop("bd-it", dur, 9.6, 12.7)
    )
    anim_els = (
        pkt_chip("pk-fd1", "1x read(fd)", "#93c5fd", 92)
        + pkt_chip("pk-bat", "Batch Tasks", "#7de3b4", 100)
        + pop_pill("bd-it", 837, 184, "Done (EOF) ประหยัด Syscall ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(488, steps, dur, split_x=256)
    return "Week 23: BPF Iterator Single-Read Kernel Walk", 488 + tbl_h + 24, header + stage + n1 + n2 + n3 + n4 + n_cmp + arrows + anim_els + tbl, anim_css + tbl_css


def build_week24_arena_mapping():
    dur = 13.0
    steps = [
        ("จอง Physical RAM ร่วมกัน", "สร้าง BPF_MAP_TYPE_ARENA จองหน้า RAM จริง (page 0, page 1, ...) เป็นฐานเดียว", 0.3, 3.0),
        ("ชี้ Address ทั้งสองฝั่ง", "Kernel มองที่ kern_vm_start (32-bit offset) ส่วน User mmap(fd) ได้ Pointer 64-bit", 3.1, 6.4),
        ("eBPF เขียนโครงสร้างสด", "โปรแกรม eBPF สร้าง Linked List / Tree ด้วย Pointer __arena ลง RAM ทันที", 6.5, 9.8),
        ("User อ่านตรง Zero-Copy", "Go/C อ่านค่าผ่าน Pointer ใน mmap ได้เลย ไม่ต้องเสีย Syscall เรียก map lookup!", 9.9, 12.7),
    ]
    header = make_header(
        "Week 24 · BPF Arena", "แชร์ RAM ร่วมกันแบบ Zero-Copy",
        "ไม่ต้องคัดลอกข้อมูลไปมาระหว่าง Kernel กับแอป: แมพ Physical Page เดียวกันให้ทั้งสองฝั่งชี้ตรงเลย"
    )
    stage = make_stage(120, 352, "Kernel BPF (32-bit Arena Ptr)  ◀════ Physical RAM Pages ════▶  User Space (mmap 64-bit Ptr)")

    n_k = node_card(44, 198, 250, 146, "Kernel BPF Space", "kern_vm_start (4 GiB + Guard)", "#fff1f2", "bb-cpu", "เขียนผ่าน __arena pointer", "#fecdd3")
    n_ram = node_card(336, 186, 288, 170, "Shared Physical RAM", "[ Page 0 | Page 1 | Page 2 ... ]", "#fef3c7", "bb-map", "BPF_MAP_TYPE_ARENA (Zero-Copy)", "#fde68a")
    n_u = node_card(666, 198, 250, 146, "User Space (mmap)", "user_vm_start (64-bit addr)", "#eff6ff", "bb-app", "อ่าน List / Tree ตรงใน RAM ✓", "#bfdbfe")

    n_note = node_card(160, 372, 640, 78, "จุดเด่น: ใช้ Pointer ชี้ข้ามโหนด Linked List / Hash / Queue ได้เอง — ไม่ต้อง sys_bpf() ทุกครั้ง!", "User และ Kernel เห็นไบต์เดียวกันใน RAM ทันทีที่เขียนเสร็จ", "#dcfce7")

    arrows = (
        '<path class="ant-red" d="M294 271H332" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-blue" d="M666 271H628" marker-end="url(#bb-ah-blue)"/>'
    )

    anim_css = (
        kf_move("pk-wr", dur, 0.3, 8.8, [(169, 271), (480, 271)])
        + kf_pop("bd-sh", dur, 5.2, 8.8)
        + kf_move("pk-rd2", dur, 6.8, 12.5, [(480, 271), (791, 271)])
        + kf_pop("bd-zc", dur, 9.6, 12.7)
    )
    anim_els = (
        pkt_chip("pk-wr", "Write Node", "#fda4af", 92)
        + pop_pill("bd-sh", 480, 174, "Same Physical Page!", "#f59e0b", "#111111")
        + pkt_chip("pk-rd2", "Direct Ptr Read", "#7de3b4", 116)
        + pop_pill("bd-zc", 791, 184, "Zero Syscall Overhead ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 24: BPF Arena Shared Memory Mapping", 492 + tbl_h + 24, header + stage + n_k + n_ram + n_u + n_note + arrows + anim_els + tbl, anim_css + tbl_css


def build_week25_scx_lifecycle():
    dur = 14.0
    steps = [
        ("งานตื่นขึ้น: select_cpu()", "เมื่อ Task พร้อมรัน sched_ext เรียก ops.select_cpu(p, prev_cpu) เช็กว่ามี CPU ว่างไหม", 0.3, 3.2),
        ("CPU ว่าง → ทางลัด LOCAL", "ถ้าเจอ Idle CPU โยนเข้า SCX_DSQ_LOCAL ของ CPU นั้นเลย ข้ามคิวกลางไปรันทันที!", 3.3, 6.2),
        ("ไม่ว่าง → คิว SHARED_DSQ", "ถ้าไม่ว่างส่ง ops.enqueue(p) เข้าคิวกลาง แล้ว ops.dispatch() หยิบไปให้ CPU ที่ว่าง", 6.3, 10.2),
        ("running → stopping วนรอบ", "ช่วงรันเรียก ops.running(p) พอหมด slice/ถูกแย่งเรียก ops.stopping() วนกลับถ้ายัง runnable", 10.3, 13.7),
    ]
    header = make_header(
        "Week 25 · sched_ext", "เขียนตัวจัดคิว CPU เองด้วย eBPF",
        "วงจรชีวิต Task บน sched_ext: select_cpu หาทางลัดตอน CPU ว่าง หรือต่อคิว DSQ กลางแล้วผลัดกันรัน"
    )
    stage = make_stage(120, 352, "Task Wakeup  ──▶  select_cpu()  ──▶  LOCAL Fastpath / SHARED_DSQ  ──▶  running / stopping")

    n1 = node_card(44, 198, 178, 136, "1. select_cpu()", "มี Idle CPU ว่างไหม?", "#eff6ff", "bb-cpu", "Task Wakeup", "#bfdbfe")
    n_fast = node_card(256, 182, 240, 88, "Idle → SCX_DSQ_LOCAL", "ทางลัด! ข้าม enqueue รันเลย", "#dcfce7", badge="Fast Path (Latency ต่ำมาก)", badge_fill="#86efac")
    n_enq = node_card(256, 286, 240, 88, "Busy → enqueue + SHARED", "ต่อคิวกลางรอ dispatch()", "#fef3c7", badge="Wait Queue (DSQ)", badge_fill="#fde68a")

    n_run = node_card(530, 198, 192, 136, "3. running(p)", "CPU หยิบจาก Local DSQ", "#e0f2fe", "bb-app", "เริ่มนับเวลา Slice", "#bae6fd")
    n_stop = node_card(754, 198, 162, 136, "4. stopping(p)", "หมดรอบ / โดนแย่ง CPU", "#fff1f2", "bb-ring", "ถ้ารอต่อ → วนกลับ", "#fecdd3")

    n_loop = node_card(180, 390, 620, 62, "ถ้า task.runnable == true จะวนกลับเข้า ops.enqueue() เพื่อรอคิวรอบถัดไปเรื่อยๆ", "", "#e7dff8")

    arrows = (
        '<path class="ant-green" d="M222 246L252 226" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M222 288L252 326" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M496 226L526 248" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M496 326L526 286" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant" d="M722 266H750" marker-end="url(#bb-ah)"/>'
        '<path class="ant-red" d="M835 334V421H804" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-red" d="M180 421H133V338" marker-end="url(#bb-ah-red)"/>'
    )

    anim_css = (
        kf_move("pk-fst", dur, 0.3, 6.2, [(133, 266), (376, 226), (626, 266)])
        + kf_pop("bd-lcl", dur, 3.3, 6.2)
        + kf_move("pk-slw", dur, 5.8, 13.7, [(133, 266), (376, 330), (626, 266), (835, 266), (835, 421), (376, 421)])
        + kf_pop("bd-cy", dur, 10.6, 13.7)
    )
    anim_els = (
        pkt_chip("pk-fst", "Task Fast", "#7de3b4", 84)
        + pop_pill("bd-lcl", 376, 174, "Direct Local DSQ ⚡", "#16a34a", "#ffffff")
        + pkt_chip("pk-slw", "Task Q", "#fde047", 74)
        + pop_pill("bd-cy", 835, 184, "Slice End → Re-queue!", "#e11d48", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 25: sched_ext (scx) BPF Scheduler Task Lifecycle", 492 + tbl_h + 24, header + stage + n1 + n_fast + n_enq + n_run + n_stop + n_loop + arrows + anim_els + tbl, anim_css + tbl_css


def build_week26_tetragon_arch():
    dur = 14.0
    steps = [
        ("เขียน TracingPolicy YAML", "ประกาศกฎ YAML (เช่นห้าม cat ไฟล์ลับ) แล้วสั่ง tetra tracingpolicy add", 0.3, 3.2),
        ("คอมไพล์ Sensor & Selector", "Tetragon Daemon แปลง YAML เป็น kprobe_multi/LSM พร้อม Map เงื่อนไข", 3.3, 6.4),
        ("กรอง & ลงโทษใน Kernel!", "Tail Call ไล่ *_event → *_filter_arg (matchArgs/Binaries) → *_actions (Post/Sigkill)", 6.5, 10.6),
        ("ส่งก้อน Log ให้ gRPC CLI", "ส่ง Event ออก Ringbuf เข้า Process Cache แล้วแสดงผลสวยๆ ผ่าน gRPC :54321", 10.7, 13.7),
    ]
    header = make_header(
        "Week 26 · Tetragon", "Security Runtime ระดับ Production",
        "เปลี่ยนกฎ YAML เป็น eBPF Pipeline ใน Kernel ที่ทั้งกรอง Argument และสั่ง Sigkill ได้ก่อน Syscall จบ"
    )
    stage = make_stage(120, 352, "YAML Policy  ──▶  Tetragon Daemon  ──▶  Kernel Tail-Call Pipeline  ──▶  gRPC :54321")

    n1 = node_card(44, 198, 174, 146, "1. YAML Policy", "matchArgs + matchActions", "#eff6ff", "bb-doc", "tetra tracingpolicy add", "#bfdbfe")
    n2 = node_card(248, 198, 192, 146, "2. Tetragon Agent", "โหลด kprobe_multi / LSM", "#fef3c7", "bb-server", "+ ใส่ Selector Maps", "#fde68a")

    k_box = (
        '<rect x="470" y="180" width="256" height="190" rx="14" fill="#fff1f2" stroke="#e11d48" stroke-width="2"/>'
        '<text x="598" y="202" font-size="13" font-weight="700" fill="#be123c" text-anchor="middle">3. Kernel Tail-Call Pipeline</text>'
    )
    k1 = node_card(486, 212, 224, 44, "hook → *_event → *_setup", "", "#ffffff")
    k2 = node_card(486, 264, 224, 44, "*_filter_arg (เช็กใน Kernel!)", "", "#ffe4e6")
    k3 = node_card(486, 316, 224, 44, "*_actions: Post หรือ SIGKILL!", "", "#fecdd3")

    n4 = node_card(754, 198, 162, 146, "4. Process Cache", "gRPC :54321", "#dcfce7", "bb-ring", "tetra getevents ✓", "#86efac")

    n_why = node_card(74, 384, 800, 66, "ข้อดี Production: กรองคำสั่งใน Kernel และฆ่าโปรเซสอันตรายก่อนเปิดไฟล์!", "", "#e0f2fe")

    arrows = (
        '<path class="ant-blue" d="M218 271H244" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-amber" d="M440 271H482" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M710 338H732V271H750" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-ym", dur, 0.3, 6.2, [(131, 271), (344, 271), (598, 234)])
        + kf_move("pk-tc", dur, 6.3, 10.6, [(598, 234), (598, 286), (598, 338)])
        + kf_pop("bd-sk", dur, 8.2, 11.4)
        + kf_move("pk-ev", dur, 10.5, 13.7, [(598, 338), (835, 271)])
        + kf_pop("bd-gt", dur, 11.2, 13.7)
    )
    anim_els = (
        pkt_chip("pk-ym", "Policy YAML", "#93c5fd", 96)
        + pkt_chip("pk-tc", "Tail Call", "#fda4af", 82)
        + pop_pill("bd-sk", 598, 174, "Match! → Post + SIGKILL ⚡", "#e11d48", "#ffffff")
        + pkt_chip("pk-ev", "gRPC Event", "#7de3b4", 94)
        + pop_pill("bd-gt", 835, 184, "tetra getevents ✓", "#16a34a", "#ffffff")
    )

    tbl, tbl_css, tbl_h = make_step_table(492, steps, dur, split_x=256)
    return "Week 26: Cilium Tetragon Policy Enforcement Architecture", 492 + tbl_h + 24, header + stage + n1 + n2 + k_box + k1 + k2 + k3 + n4 + n_why + arrows + anim_els + tbl, anim_css + tbl_css


EXTRA_BUILDERS = {
    "week01-veth-pair": build_week01_veth_pair,
    "week02-rx-path": build_week02_rx_path,
    "week03-ebpf-architecture": build_week03_ebpf_architecture,
    "week04-kprobe-timing": build_week04_kprobe_timing,
    "week05-core-architecture": build_week05_core_architecture,
    "week06-verifier": build_week06_verifier,
    "week09-uprobe-flow": build_week09_uprobe_flow,
    "week10-lsm-hook-path": build_week10_lsm_hook_path,
    "week11-telemetry-arch": build_week11_telemetry_arch,
    "week12-ips-arch": build_week12_ips_arch,
    "week13-drop-path": build_week13_drop_path,
    "week14-connect-hook": build_week14_connect_hook,
    "week15-reverse-shell": build_week15_reverse_shell,
    "week16-inventory-loop": build_week16_inventory_loop,
    "week17-block-io-path": build_week17_block_io_path,
    "week18-sampling-profiler": build_week18_sampling_profiler,
    "week19-page-fault": build_week19_page_fault,
    "week23-iter-flow": build_week23_iter_flow,
    "week24-arena-mapping": build_week24_arena_mapping,
    "week25-scx-lifecycle": build_week25_scx_lifecycle,
    "week26-tetragon-arch": build_week26_tetragon_arch,
}
