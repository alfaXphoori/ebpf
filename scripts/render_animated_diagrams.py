#!/usr/bin/env python3
"""Generate standalone animated ByteByteGo-style SVGs with synchronized step tables.

Uses pure SVG + CSS @keyframes (no JavaScript, respects prefers-reduced-motion)
and embeds subsetted Noto Sans / Noto Sans Thai / DejaVu Sans WOFF fonts via
scripts/diagram_postprocess.py so Thai typography renders consistently everywhere.

Usage:
    scripts/render_animated_diagrams.py                 # render all animated diagrams
    scripts/render_animated_diagrams.py week07-xdp-path # render specific diagram(s)
"""

import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIAG_DIR = ROOT / "docs" / "diagrams"
sys.path.insert(0, str(Path(__file__).resolve().parent))

import diagram_postprocess  # noqa: E402
from anim_svg_ui import (  # noqa: E402
    BASE_CSS,
    SHARED_SYMBOLS,
    esc,
    kf_move,
    kf_pop,
    make_header,
    make_stage,
    make_step_table,
    node_card,
    pkt_chip,
)
from anim_weeks_extra import EXTRA_BUILDERS  # noqa: E402

FONT_SOURCES = [
    Path("/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"),
    Path("/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf"),
    Path("/usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf"),
    Path("/usr/share/fonts/truetype/noto/NotoSansThai-Bold.ttf"),
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
]

# ------------------------------------------------------------------------------
# Diagram Builders (9 Core Animated Conceptual Diagrams + 21 Weekly Diagrams)
# ------------------------------------------------------------------------------

def build_guide_ch01_ingress_path():
    dur = 14.0
    steps = [
        ("NIC + DMA", "แพ็กเก็ตเข้าสายแลนแล้ว DMA ยิงลง RX Ring ใน RAM โดยตรง", 0.3, 2.5),
        ("XDP Hook (Driver)", "รันก่อนจอง sk_buff! แพ็กเก็ตอันตรายโดน XDP_DROP ทิ้งทันที", 2.6, 5.4),
        ("จอง sk_buff", "แพ็กเก็ตที่ XDP_PASS ผ่าน จะถูกสร้าง sk_buff (GRO) เข้า Stack", 5.5, 8.0),
        ("TC Ingress & Routing", "ผ่าน TC cls_bpf → Netfilter → Routing หา Socket ปลายทาง", 8.1, 10.9),
        ("User Space read()", "เข้าคิว sk_receive_queue แล้วแอปเรียก read() รับข้อมูลไปใช้", 11.0, 13.7),
    ]
    header = make_header(
        "เส้นทางแพ็กเก็ต", "Linux Kernel Ingress & eBPF Hooks",
        "เทียบความเร็ว: XDP ตัดแพ็กเก็ตทิ้งก่อนสร้าง sk_buff vs แพ็กเก็ตปกติที่ไหลจนถึงแอป User Space"
    )
    stage = make_stage(120, 386, "Packet Ingress Flow: NIC → XDP (Drop/Pass) → sk_buff → TC → App")

    n_nic = node_card(42, 184, 152, 146, "1. NIC + DMA", "RX Ring Buffer", "#ffffff", "bb-nic", "Raw Memory", "#dcfce7")
    n_xdp = node_card(232, 184, 166, 146, "2. XDP Hook", "ระดับ Driver", "#fff1f2", "bb-shield", "40M+ pps", "#fecdd3")
    n_skb = node_card(436, 184, 152, 146, "3. sk_buff", "จอง RAM ~240B", "#fefce8", "bb-map", "GRO + Metadata", "#fde68a")
    n_tc = node_card(622, 184, 142, 146, "4. TC & Stack", "Routing / Netfilter", "#fff1f2", "bb-server", "cls_bpf", "#fecdd3")
    n_app = node_card(796, 184, 122, 146, "5. App", "read() / recv", "#eff6ff", "bb-app", "User Space", "#bfdbfe")

    drop_box = (
        '<rect class="card" x="232" y="384" width="166" height="98" rx="14" fill="#ffe4e6" stroke="#e11d48" stroke-width="2.2"/>'
        '<text x="315" y="414" font-size="15" font-weight="700" fill="#9f1239" text-anchor="middle">XDP_DROP ทันที!</text>'
        '<text x="315" y="436" font-size="12.5" font-weight="600" fill="#111111" text-anchor="middle">ไม่เสียแรงจอง sk_buff</text>'
        '<text x="315" y="458" font-size="12" font-weight="500" fill="#475569" text-anchor="middle">ไม่รบกวน Network Stack</text>'
    )

    paths = (
        '<path class="ant" d="M194 257H228" marker-end="url(#bb-ah)"/>'
        '<path class="ant-red" d="M315 330V378" marker-end="url(#bb-ah-red)"/>'
        '<text x="368" y="358" font-size="12" font-weight="700" fill="#e11d48" text-anchor="middle">XDP_DROP</text>'
        '<path class="ant-green" d="M398 257H432" marker-end="url(#bb-ah-green)"/>'
        '<text x="415" y="244" font-size="11.5" font-weight="700" fill="#16a34a" text-anchor="middle">PASS</text>'
        '<path class="ant" d="M588 257H618" marker-end="url(#bb-ah)"/>'
        '<path class="ant" d="M764 257H792" marker-end="url(#bb-ah)"/>'
        '<rect x="436" y="386" width="482" height="94" rx="12" fill="#ffffff" stroke="#111111" stroke-width="2"/>'
        '<text x="677" y="415" font-size="14.5" font-weight="700" fill="#1e293b" text-anchor="middle">สรุปความต่างของจุดเกาะ (Hook Point)</text>'
        '<text x="454" y="440" font-size="12.5" font-weight="500" fill="#334155" text-anchor="start">• XDP: เร็วสุด จับ Raw Packet ก่อนสร้าง sk_buff (บล็อก DDoS / Drop / Redirect)</text>'
        '<text x="454" y="462" font-size="12.5" font-weight="500" fill="#334155" text-anchor="start">• TC: เห็น sk_buff ครบ ทั้ง VLAN, Mark, cgroup คุมทราฟฟิกทั้งขาเข้าและขาออก</text>'
    )

    anim_css = (
        kf_move("pk-bad", dur, 0.4, 5.2, [(95, 257), (315, 257), (315, 412)])
        + kf_pop("bd-drop", dur, 3.3, 5.4)
        + kf_move("pk-ok", dur, 3.0, 13.5, [(315, 257), (512, 257), (693, 257), (857, 257)])
        + kf_pop("bd-app", dur, 11.4, 13.7)
    )
    anim_els = (
        pkt_chip("pk-bad", "DDoS SYN", "#fb7185", 92)
        + pkt_chip("pk-ok", "HTTP OK", "#7de3b4", 88)
        + '<g class="bd-drop"><rect x="251" y="356" width="128" height="24" rx="12" fill="#e11d48" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="315" y="372.5" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">DROPPED ⚡</text></g>'
        + '<g class="bd-app"><rect x="803" y="152" width="108" height="24" rx="12" fill="#4ade80" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="857" y="168.5" font-size="12" font-weight="700" fill="#111111" text-anchor="middle">อ่านสำเร็จ ✓</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(526, steps, dur, split_x=256)
    return "เส้นทางแพ็กเก็ตขาเข้าใน Linux Kernel: NIC → XDP → sk_buff → TC → User Space App", 526 + tbl_h + 24, header + stage + n_nic + n_xdp + n_skb + n_tc + n_app + drop_box + paths + anim_els + tbl, anim_css + tbl_css


def build_guide_ch02_build_load_pipeline():
    dur = 14.0
    steps = [
        ("เขียน C + Clang", "คอมไพล์ my_prog.bpf.c ด้วย -target bpf เป็น .o (.text, .maps, .BTF)", 0.3, 3.0),
        ("Loader + BTF Reloc", "bpf2go / Go อ่าน ELF แล้วปรับตำแหน่ง struct ให้ตรงกับเคอร์เนลนี้", 3.1, 6.0),
        ("Verifier ตรวจโค้ด", "เช็ก Pointer Bounds, Loop, Stack ถ้าไม่ปลอดภัยจะปัดตกทันที", 6.1, 9.4),
        ("JIT Compiler", "แปลง eBPF Bytecode เป็น Machine Code ของ CPU (x86_64 / ARM64)", 9.5, 11.7),
        ("Attach Hook", "ผูกเข้ากับ XDP / TC / Tracepoint / Kprobe / LSM พร้อมทำงานทันที", 11.8, 13.7),
    ]
    header = make_header(
        "Build & Load", "วงจรชีวิตโปรแกรม eBPF",
        "กว่าโค้ด C 1 ไฟล์จะเข้าไปวิ่งใน Linux Kernel ได้อย่างปลอดภัย ต้องผ่าน 5 ด่านนี้"
    )
    stage = make_stage(120, 356, "Compile (User Space)  ──▶  Verify & JIT (Kernel Space)  ──▶  Hook")

    zones = (
        '<rect x="44" y="182" width="420" height="272" rx="14" fill="#eff6ff" stroke="#2563eb" stroke-width="2" stroke-dasharray="7 5"/>'
        '<rect x="154" y="170" width="200" height="24" rx="12" fill="#2563eb"/><text x="254" y="186" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">User Space (Build &amp; Load)</text>'
        '<rect x="488" y="182" width="428" height="272" rx="14" fill="#fff1f2" stroke="#e11d48" stroke-width="2" stroke-dasharray="7 5"/>'
        '<rect x="602" y="170" width="200" height="24" rx="12" fill="#e11d48"/><text x="702" y="186" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">Linux Kernel Space</text>'
    )
    n1 = node_card(62, 206, 174, 136, "1. Source + Clang", "clang -target bpf", "#ffffff", "bb-doc", ".bpf.o (ELF)", "#dbeafe")
    n2 = node_card(268, 206, 178, 136, "2. Go / bpf2go", "BTF Relocation", "#ffffff", "bb-app", "BPF_PROG_LOAD", "#dbeafe")
    n3 = node_card(508, 206, 184, 136, "3. Verifier", "Bounds & Loop Check", "#ffffff", "bb-shield", "Safety Gate", "#fecdd3")
    n4 = node_card(722, 206, 174, 136, "4. JIT Compiler", "Bytecode → Native", "#ffffff", "bb-cpu", "x86_64 / ARM64", "#fde68a")

    hook_bar = (
        '<rect class="card" x="508" y="366" width="388" height="72" rx="14" fill="#dcfce7" stroke="#16a34a" stroke-width="2"/>'
        '<text x="702" y="396" font-size="15" font-weight="700" fill="#14532d" text-anchor="middle">5. เกาะ Hook พร้อมทำงาน: XDP · TC · Kprobe · LSM</text>'
        '<text x="702" y="418" font-size="12.5" font-weight="500" fill="#1e293b" text-anchor="middle">ทำงานเร็วระดับ Native CPU และไม่สามารถทำเคอร์เนลแครชได้</text>'
        '<rect class="card" x="62" y="366" width="384" height="72" rx="14" fill="#ffffff" stroke="#111111" stroke-width="2"/>'
        '<text x="254" y="396" font-size="14.5" font-weight="700" fill="#1e293b" text-anchor="middle">โครงสร้างในไฟล์ ELF (.o)</text>'
        '<text x="254" y="418" font-size="12.5" font-weight="500" fill="#475569" text-anchor="middle">.text (Bytecode 8B/คำสั่ง) · .maps · .BTF (CO-RE)</text>'
    )
    arrows = (
        '<path class="ant-blue" d="M236 274H264" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant" d="M446 274H504" marker-end="url(#bb-ah)"/>'
        '<path class="ant-red" d="M692 274H718" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M809 342V362" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-c", dur, 0.3, 3.0, [(149, 274), (255, 274), (357, 274)])
        + kf_move("pk-elf", dur, 3.1, 6.2, [(357, 274), (470, 274), (600, 274)])
        + kf_pop("bd-vf", dur, 6.5, 9.4)
        + kf_move("pk-jit", dur, 9.2, 13.6, [(600, 274), (809, 274), (809, 376)])
        + kf_pop("bd-hk", dur, 11.8, 13.7)
    )
    anim_els = (
        pkt_chip("pk-c", "my_prog.o", "#93c5fd", 92)
        + pkt_chip("pk-elf", "PROG_LOAD", "#fde68a", 96)
        + '<g class="bd-vf"><rect x="536" y="192" width="128" height="24" rx="12" fill="#4ade80" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="600" y="208" font-size="12" font-weight="700" fill="#111111" text-anchor="middle">Verifier ผ่าน ✓</text></g>'
        + pkt_chip("pk-jit", "Native Code", "#7de3b4", 98)
        + '<g class="bd-hk"><rect x="612" y="348" width="180" height="24" rx="12" fill="#22c55e" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="702" y="364" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">ติด Hook สำเร็จ (Active)</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(496, steps, dur, split_x=256)
    return "วงจร Build และ Load ของโปรแกรม eBPF", 496 + tbl_h + 24, header + stage + zones + n1 + n2 + n3 + n4 + hook_bar + arrows + anim_els + tbl, anim_css + tbl_css


def build_guide_ch03_race_condition():
    dur = 12.5
    steps = [
        ("2 CPU อ่านพร้อมกัน", "CPU 0 และ CPU 1 อ่าน Counter จาก BPF Map ได้ค่า 100 เท่ากันทั้งคู่", 0.3, 3.4),
        ("ต่างคนต่างบวก +1", "CPU 0 คำนวณ 100+1 = 101 ส่วน CPU 1 ก็คำนวณ 100+1 = 101", 3.5, 6.2),
        ("เขียนทับกัน (Lost!)", "ทั้ง 2 CPU เขียนเลข 101 ทับลงช่องเดิม → แพ็กเก็ตมา 2 แต่นับได้แค่ 1!", 6.3, 9.3),
        ("วิธีแก้ที่ถูกต้อง", "ใช้ __sync_fetch_and_add() หรือเปลี่ยนเป็น PERCPU_ARRAY แยกนับตาม Core", 9.4, 12.2),
    ]
    header = make_header(
        "Race Condition", "ปัญหาข้อมูลหายเมื่อหลาย CPU นับพร้อมกัน",
        "สาเหตุที่ต้องใช้ Atomic Add (__sync_fetch_and_add) หรือ Per-CPU Map ใน eBPF"
    )
    stage = make_stage(120, 356, "แพ็กเก็ตเข้า CPU 0 และ CPU 1 พร้อมกัน → ทำไม Counter ได้ 101 แทนที่จะเป็น 102?")

    c0 = node_card(54, 194, 196, 144, "CPU 0", "แพ็กเก็ต #1 เข้า", "#eff6ff", "bb-cpu", "อ่านได้ 100 → +1", "#bfdbfe")
    cm = node_card(366, 194, 228, 144, "Shared Hash Map", "Counter ปกติ (ไม่ Atomic)", "#fef3c7", "bb-map", "ค่าปัจจุบัน: 100", "#fde68a")
    c1 = node_card(710, 194, 196, 144, "CPU 1", "แพ็กเก็ต #2 เข้า", "#eff6ff", "bb-cpu", "อ่านได้ 100 → +1", "#bfdbfe")

    arrows = (
        '<path class="ant-blue" d="M250 242H362" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-red" d="M366 290H254" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-blue" d="M710 242H598" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-red" d="M594 290H706" marker-end="url(#bb-ah-red)"/>'
        '<rect class="card" x="54" y="370" width="852" height="84" rx="14" fill="#dcfce7" stroke="#16a34a" stroke-width="2"/>'
        '<text x="480" y="400" font-size="15" font-weight="700" fill="#14532d" text-anchor="middle">ทางแก้ 2 แบบใน eBPF (ไม่มีตัวเลขหล่นแน่นอน)</text>'
        '<text x="480" y="426" font-size="12" font-weight="600" fill="#111111" text-anchor="middle">1) __sync_fetch_and_add(val, 1) — ล็อกระดับฮาร์ดแวร์   |   2) BPF_MAP_TYPE_PERCPU_ARRAY — แยกช่องของใครของมัน แล้วให้ Go รวมยอด</text>'
    )

    anim_css = (
        kf_move("pk-r0", dur, 0.3, 3.3, [(410, 242), (200, 242)])
        + kf_move("pk-r1", dur, 0.5, 3.3, [(550, 242), (760, 242)])
        + kf_pop("bd-calc", dur, 3.5, 6.2)
        + kf_move("pk-w0", dur, 6.3, 9.1, [(200, 290), (435, 290)])
        + kf_move("pk-w1", dur, 6.6, 9.1, [(760, 290), (525, 290)])
        + kf_pop("bd-lost", dur, 7.2, 9.5)
        + kf_pop("bd-fix", dur, 9.5, 12.2)
    )
    anim_els = (
        pkt_chip("pk-r0", "Read: 100", "#93c5fd", 92)
        + pkt_chip("pk-r1", "Read: 100", "#93c5fd", 92)
        + '<g class="bd-calc"><rect x="76" y="168" width="152" height="24" rx="12" fill="#ffe27a" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="152" y="184" font-size="12" font-weight="700" fill="#111111" text-anchor="middle">คำนวณได้ 101</text>'
        + '<rect x="732" y="168" width="152" height="24" rx="12" fill="#ffe27a" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="808" y="184" font-size="12" font-weight="700" fill="#111111" text-anchor="middle">คำนวณได้ 101</text></g>'
        + pkt_chip("pk-w0", "Write: 101", "#fda4af", 96)
        + pkt_chip("pk-w1", "Write: 101", "#fda4af", 96)
        + '<g class="bd-lost"><rect x="372" y="166" width="216" height="26" rx="13" fill="#e11d48" stroke="#111111" stroke-width="2"/>'
        + '<text x="480" y="183.5" font-size="12.5" font-weight="700" fill="#ffffff" text-anchor="middle">เขียนทับ! ได้แค่ 101 (หายไป 1)</text></g>'
        + '<g class="bd-fix"><rect x="300" y="348" width="360" height="26" rx="13" fill="#22c55e" stroke="#111111" stroke-width="2"/>'
        + '<text x="480" y="365.5" font-size="12.5" font-weight="700" fill="#ffffff" text-anchor="middle">ใช้ Atomic หรือ PERCPU_ARRAY → ได้ 102 ครบ! ✓</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(496, steps, dur, split_x=256)
    return "Race Condition เมื่อหลาย CPU นับพร้อมกัน", 496 + tbl_h + 24, header + stage + c0 + cm + c1 + arrows + anim_els + tbl, anim_css + tbl_css


def build_guide_ch05_ringbuf_mpsc():
    dur = 13.0
    steps = [
        ("หลาย CPU จองพื้นที่", "CPU 0, CPU 1, CPU 2 เรียก bpf_ringbuf_reserve() จองช่องแบบเรียงลำดับ", 0.3, 3.6),
        ("เขียนและ Commit", "กรอกข้อมูล Event ลงหน่วยความจำร่วมแล้วเรียก bpf_ringbuf_submit()", 3.7, 6.8),
        ("Zero-Copy ข้ามเขต", "Go เปิด mmap ชี้ตรงไปยัง RAM ของ Ring Buffer (ไม่ต้องก๊อปปี้ซ้ำ)", 6.9, 9.8),
        ("User Space อ่านเรียง", "ringbuf.NewReader() ดึง Event ออกมาตามลำดับเวลาที่จองจริง", 9.9, 12.7),
    ]
    header = make_header(
        "BPF Ring Buffer", "ส่งข้อมูลเร็วแบบ MPSC + Zero-Copy",
        "หลาย CPU ส่งข้อมูลเข้าบัฟเฟอร์เดียวพร้อมกัน แล้วฝั่ง Go อ่านได้เรียงตามลำดับโดยไม่เสียแรงก๊อปปี้"
    )
    stage = make_stage(120, 340, "Multi-Producer (หลาย CPU)  ──▶  Shared Ring Buffer (mmap)  ──▶  Single Consumer (Go)")

    c0 = node_card(44, 184, 176, 76, "CPU 0", "bpf_ringbuf_reserve()", "#fff1f2")
    c1 = node_card(44, 274, 176, 76, "CPU 1", "bpf_ringbuf_reserve()", "#fff1f2")
    c2 = node_card(44, 364, 176, 76, "CPU 2", "bpf_ringbuf_reserve()", "#fff1f2")

    rb = node_card(330, 212, 268, 200, "Shared Ring Buffer", "Circular RAM (MPSC)", "#fef3c7", "bb-ring", "mmap Shared Memory", "#fde68a")
    go_rd = node_card(704, 232, 212, 160, "Go Reader", "ringbuf.NewReader()", "#eff6ff", "bb-app", "อ่าน Event เรียงคิว", "#bfdbfe")

    arrows = (
        '<path class="ant-red" d="M220 222L326 270" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-red" d="M220 312H326" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-red" d="M220 402L326 354" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-blue" d="M598 312H700" marker-end="url(#bb-ah-blue)"/>'
        '<rect x="606" y="276" width="88" height="24" rx="12" fill="#ffffff" stroke="#111111" stroke-width="1.6"/>'
        '<text x="650" y="292" font-size="11.5" font-weight="700" fill="#2563eb" text-anchor="middle">Zero-Copy</text>'
    )

    anim_css = (
        kf_move("pk-e0", dur, 0.3, 4.4, [(132, 222), (380, 286)])
        + kf_move("pk-e1", dur, 1.0, 5.2, [(132, 312), (430, 312)])
        + kf_move("pk-e2", dur, 1.8, 6.0, [(132, 402), (380, 338)])
        + kf_pop("bd-sub", dur, 4.0, 6.8)
        + kf_move("pk-go1", dur, 6.9, 10.6, [(480, 312), (760, 312)])
        + kf_move("pk-go2", dur, 8.2, 12.0, [(480, 312), (760, 312)])
        + kf_pop("bd-ok", dur, 9.9, 12.7)
    )
    anim_els = (
        pkt_chip("pk-e0", "Evt #1 (C0)", "#fda4af", 96)
        + pkt_chip("pk-e1", "Evt #2 (C1)", "#fdba74", 96)
        + pkt_chip("pk-e2", "Evt #3 (C2)", "#fde047", 96)
        + '<g class="bd-sub"><rect x="374" y="186" width="180" height="24" rx="12" fill="#fbbf24" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="464" y="202" font-size="12" font-weight="700" fill="#111111" text-anchor="middle">Submit เรียง #1 → #2 → #3</text></g>'
        + pkt_chip("pk-go1", "Evt #1", "#93c5fd", 72)
        + pkt_chip("pk-go2", "Evt #2", "#7de3b4", 72)
        + '<g class="bd-ok"><rect x="720" y="204" width="180" height="24" rx="12" fill="#22c55e" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="810" y="220" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">Go อ่านครบ ไม่ตกหล่น ✓</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(480, steps, dur, split_x=256)
    return "สถาปัตยกรรม BPF Ring Buffer แบบ MPSC", 480 + tbl_h + 24, header + stage + c0 + c1 + c2 + rb + go_rd + arrows + anim_els + tbl, anim_css + tbl_css


def build_week07_xdp_path():
    dur = 13.0
    steps = [
        ("แพ็กเก็ตเข้า NIC", "DMA ยิงแพ็กเก็ตลง RX Ring ของไดรเวอร์การ์ดเครือข่าย", 0.3, 2.4),
        ("เช็ก Bounds + อ่าน IP", "Verifier บังคับตรวจ data_end ก่อนอ่าน Ethernet / IPv4 Header", 2.5, 5.2),
        ("เปิดดู blocked_ips", "เอา Source IP ไปค้นใน BPF_MAP_TYPE_HASH และอัปเดตตัวนับ", 5.3, 7.8),
        ("เจอในบัญชีดำ → DROP", "ถ้า IP ตรง Blocklist สั่ง XDP_DROP ทิ้งทันทีโดยไม่สร้าง sk_buff!", 7.9, 10.4),
        ("ไม่เจอ → XDP_PASS", "แพ็กเก็ตปกติผ่านเข้า Linux Network Stack ต่อไปยังแอป", 10.5, 12.7),
    ]
    header = make_header(
        "Week 07 · XDP", "Stateless Firewall ระดับ Driver",
        "แกะ Header ตั้งแต่หน้าประตูไดรเวอร์: บล็อกแพ็กเก็ตอันตรายก่อนสร้าง sk_buff"
    )
    stage = make_stage(120, 366, "XDP Hook: แพ็กเก็ตสีแดง (IP 10.10.1.10) โดน XDP_DROP vs แพ็กเก็ตสีเขียว XDP_PASS")

    n_in = node_card(44, 198, 150, 146, "1. NIC RX", "w07-s (eth)", "#ffffff", "bb-nic", "ctx->data", "#dcfce7")
    n_xdp = node_card(240, 196, 224, 150, "2. xdp_firewall.c", "Bounds → Hash Lookup", "#fff1f2", "bb-shield", "XDP Driver Hook", "#fecdd3")
    n_map = node_card(256, 376, 192, 92, "blocked_ips", "HASH key = saddr", "#fef3c7", badge="10.10.1.10 (BLOCK)", badge_fill="#fda4af")
    n_drop = node_card(548, 178, 356, 104, "4. XDP_DROP (ทราฟฟิกต้องห้าม)", "นับ dropped_packets แล้วทิ้งทันที!", "#ffe4e6", "", "Zero sk_buff Overhead ⚡", "#fb7185")
    n_pass = node_card(548, 306, 356, 104, "5. XDP_PASS (ทราฟฟิกปกติ)", "ส่งต่อสร้าง sk_buff เข้า Linux Stack", "#dcfce7", "", "เข้า Socket / แอปปกติ ✓", "#4ade80")

    arrows = (
        '<path class="ant" d="M194 271H236" marker-end="url(#bb-ah)"/>'
        '<path class="ant-amber" d="M352 346V372" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-red" d="M464 242H544" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M464 316L544 352" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-blk", dur, 0.3, 10.2, [(119, 271), (352, 271), (352, 345), (352, 271), (710, 226)])
        + kf_pop("bd-hit", dur, 5.4, 8.2)
        + kf_pop("bd-xdp-drop", dur, 7.9, 10.4)
        + kf_move("pk-cln", dur, 7.8, 12.7, [(119, 271), (352, 271), (710, 358)])
        + kf_pop("bd-xdp-pass", dur, 10.5, 12.7)
    )
    anim_els = (
        pkt_chip("pk-blk", "10.10.1.10", "#fb7185", 96)
        + pkt_chip("pk-cln", "10.10.1.11", "#7de3b4", 96)
        + '<g class="bd-hit"><rect x="272" y="349" width="160" height="22" rx="11" fill="#ffe27a" stroke="#111111" stroke-width="1.6"/>'
        + '<text x="352" y="364" font-size="11.5" font-weight="700" fill="#111111" text-anchor="middle">เจอใน blocked_ips!</text></g>'
        + '<g class="bd-xdp-drop"><rect x="646" y="164" width="160" height="24" rx="12" fill="#e11d48" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="726" y="180" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">ทิ้งทันที XDP_DROP</text></g>'
        + '<g class="bd-xdp-pass"><rect x="646" y="292" width="160" height="24" rx="12" fill="#16a34a" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="726" y="308" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">ส่งต่อ XDP_PASS ✓</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(506, steps, dur, split_x=256)
    return "Week 07: XDP Packet Parsing & Stateless Firewall", 506 + tbl_h + 24, header + stage + n_in + n_xdp + n_map + n_drop + n_pass + arrows + anim_els + tbl, anim_css + tbl_css


def build_week08_sequence():
    dur = 14.5
    steps = [
        ("Client ส่งเข้า VIP", "w08-client ส่ง SYN ไปที่ VIP 10.10.1.100:80", 0.3, 2.7),
        ("XDP LB ทำ Hash + DNAT", "flow_hash() % 2 เลือก Backend, บันทึกลง flows, แก้ MAC/IP/Checksum", 2.8, 5.8),
        ("XDP_TX ออกการ์ดเดิม", "ส่งกลับออกไปหา Backend (w08-b0/b1) แบบ Hairpin โดยไม่เข้า Stack", 5.9, 8.2),
        ("TC Ingress แก้ SNAT", "ขากลับ Backend ตอบ → TC ค้น flows แล้วแก้ saddr กลับเป็น VIP", 8.3, 11.4),
        ("TC Egress ส่งกลับ Client", "ส่งออกทาง eth0 พร้อมนับ egress_stats — Client เห็นตอบจาก VIP", 11.5, 14.2),
    ]
    header = make_header(
        "Week 08 · LB", "XDP Load Balancer + TC Reverse NAT",
        "ขาเข้าใช้ XDP_TX สลับปลายทางให้ไว ขากลับใช้ TC แก้ต้นทางกลับเป็น VIP ให้เนียน"
    )
    stage = make_stage(120, 364, "ทางเดิน 2 ขา:  ขาเข้า (Client → XDP → Backend)  &  ขากลับ (Backend → TC Ingress/Egress → Client)")

    n_cli = node_card(44, 212, 160, 148, "w08-client", "10.10.2.10", "#dcfce7", "bb-app", "เรียก VIP :80", "#86efac")
    n_xdp = node_card(276, 178, 206, 136, "XDP Load Balancer", "DNAT → Backend IP", "#fff1f2", "bb-shield", "XDP_TX (Hairpin)", "#fecdd3")
    n_map = node_card(516, 212, 162, 144, "flows Map", "LRU_HASH", "#fef3c7", "bb-map", "จำคู่ VIP ↔ Backend", "#fde68a")
    n_tc = node_card(276, 330, 206, 134, "TC Ingress + Egress", "Reverse SNAT → VIP", "#eff6ff", "bb-server", "TC_ACT_OK", "#bfdbfe")
    n_be = node_card(728, 212, 184, 148, "Backend b0 / b1", "HTTP Server :80", "#ffffff", "bb-server", "รับ-ตอบตรงๆ", "#e2e8f0")

    arrows = (
        '<path class="ant-green" d="M204 252L272 238" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-red" d="M482 222L724 250" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-amber" d="M482 268L512 276" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-amber" d="M516 320L486 356" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M728 334L486 392" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-blue" d="M276 388L204 334" marker-end="url(#bb-ah-blue)"/>'
    )

    anim_css = (
        kf_move("pk-syn", dur, 0.3, 8.1, [(124, 250), (379, 232), (597, 224), (820, 260)])
        + kf_pop("bd-flow", dur, 3.2, 6.0)
        + kf_move("pk-ack", dur, 8.3, 14.2, [(820, 322), (597, 344), (379, 388), (124, 322)])
        + kf_pop("bd-rev", dur, 8.8, 11.4)
    )
    anim_els = (
        pkt_chip("pk-syn", "SYN → VIP", "#7de3b4", 94)
        + '<g class="bd-flow"><rect x="298" y="162" width="162" height="22" rx="11" fill="#ffe27a" stroke="#111111" stroke-width="1.6"/>'
        + '<text x="379" y="177" font-size="11.5" font-weight="700" fill="#111111" text-anchor="middle">จำ flow ลง LRU_HASH</text></g>'
        + pkt_chip("pk-ack", "SYN-ACK ← VIP", "#93c5fd", 112)
        + '<g class="bd-rev"><rect x="294" y="454" width="170" height="22" rx="11" fill="#3b82f6" stroke="#111111" stroke-width="1.6"/>'
        + '<text x="379" y="469" font-size="11.5" font-weight="700" fill="#ffffff" text-anchor="middle">แก้ src กลับเป็น VIP ✓</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(504, steps, dur, split_x=256)
    return "Week 08: XDP Load Balancer + TC Reverse NAT", 504 + tbl_h + 24, header + stage + n_cli + n_xdp + n_map + n_tc + n_be + arrows + anim_els + tbl, anim_css + tbl_css


def build_week20_sequence():
    dur = 13.5
    steps = [
        ("Handshake ครั้งแรก", "Client connect() → ผ่าน TCP/IP stack บน lo ตามปกติจน ESTABLISHED", 0.3, 3.2),
        ("sockops จดลง Map", "เคอร์เนลเรียก sockops ใส่ key ของทั้ง Client และ Server ลง SOCKHASH", 3.3, 6.2),
        ("sendmsg() → sk_msg", "พอแอปส่งข้อมูล sk_msg เอา key กลับด้านมาเปิดหา Peer ใน SOCKHASH", 6.3, 9.2),
        ("ลัดคิวตรงเข้า Server!", "bpf_msg_redirect_hash ส่งเข้าคิว recv() ตรงๆ ข้าม TCP/IP stack!", 9.3, 13.2),
    ]
    header = make_header(
        "Week 20 · Sockops", "TCP Socket Bypass (ข้าม TCP/IP Stack)",
        "เชื่อมครั้งแรกให้ sockops จำ socket ไว้ จากนั้นส่งข้อมูลข้าม TCP/IP stack ได้เลย!"
    )
    stage = make_stage(120, 364, "เส้นทางปกติ (TCP/IP Stack ช้ากว่า)  vs  ทางลัด eBPF (sk_msg → SOCKHASH ตรงเข้าคิว Server)")

    n_cli = node_card(44, 214, 168, 152, "Client Socket", "tcpbench / nc", "#eff6ff", "bb-app", "sendmsg(data)", "#bfdbfe")
    n_msg = node_card(276, 178, 186, 138, "sk_msg Hook", "bpf_msg_redirect_hash", "#dcfce7", "bb-shield", "ทางลัด SK_PASS!", "#86efac")
    n_hash = node_card(508, 178, 166, 138, "SOCKHASH Map", "เก็บ Peer Sockets", "#fef3c7", "bb-map", "ผูกโดย sockops", "#fde68a")
    n_tcp = node_card(276, 350, 398, 108, "ทางปกติ: TCP/IP Stack บน lo (เมื่อไม่เจอใน Map)", "สร้าง Header → Netfilter → SoftIRQ → ACK (ใช้แค่ตอน Handshake)", "#fff1f2", badge="ถูกข้ามเมื่อ Bypass สำเร็จ", badge_fill="#fecdd3")
    n_srv = node_card(734, 214, 178, 152, "Server Socket", "127.0.0.1:18080", "#eff6ff", "bb-server", "recv() รับข้อมูลตรง", "#bfdbfe")

    arrows = (
        '<path class="ant-red" d="M212 336L272 384" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-red" d="M674 384L730 336" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-amber" d="M476 350V320" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M212 248H272" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M462 248H504" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-green" d="M674 248H730" marker-end="url(#bb-ah-green)"/>'
    )

    anim_css = (
        kf_move("pk-hs", dur, 0.3, 3.2, [(128, 330), (272, 392), (674, 392), (823, 330)])
        + kf_move("pk-so", dur, 3.3, 6.1, [(476, 352), (591, 258)])
        + kf_pop("bd-sh", dur, 3.8, 6.2)
        + kf_move("pk-fast", dur, 6.3, 13.0, [(128, 248), (369, 248), (591, 248), (823, 258)])
        + kf_pop("bd-byp", dur, 9.5, 13.2)
    )
    anim_els = (
        pkt_chip("pk-hs", "SYN / ACK", "#fda4af", 92)
        + pkt_chip("pk-so", "Save Socket", "#fde68a", 96)
        + '<g class="bd-sh"><rect x="510" y="162" width="162" height="22" rx="11" fill="#fbbf24" stroke="#111111" stroke-width="1.6"/>'
        + '<text x="591" y="177" font-size="11.5" font-weight="700" fill="#111111" text-anchor="middle">จำ Client+Server ครบ ✓</text></g>'
        + pkt_chip("pk-fast", "Data ทางลัด!", "#4ade80", 104)
        + '<g class="bd-byp"><rect x="734" y="180" width="178" height="24" rx="12" fill="#16a34a" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="823" y="196" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">ลัด TCP Stack สำเร็จ ⚡</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(504, steps, dur, split_x=256)
    return "Week 20: TCP SOCKOPS & sk_msg Socket Bypass", 504 + tbl_h + 24, header + stage + n_cli + n_msg + n_hash + n_tcp + n_srv + arrows + anim_els + tbl, anim_css + tbl_css


def build_week21_sequence():
    dur = 14.0
    steps = [
        ("Go เติม FILL Ring", "xsk.go ส่งที่อยู่ช่องว่างของ UMEM ลง FILL Ring ให้เคอร์เนลเตรียมรับ", 0.3, 3.1),
        ("UDP เข้า XDP Redirect", "แพ็กเก็ตเข้า w21-xsk0 → XDP เปิด xsks_map แล้วสั่ง XDP_REDIRECT", 3.2, 6.3),
        ("ย้ายลง UMEM + RX Ring", "เคอร์เนลขอช่องจาก FILL Ring, วางข้อมูลลง UMEM แล้วชี้ใน RX Ring", 6.4, 9.6),
        ("Go อ่านและคืน Frame", "Go Poll/Receive จาก RX Ring อ่านจาก UMEM แล้วคืนเข้า FILL Ring", 9.7, 13.7),
    ]
    header = make_header(
        "Week 21 · AF_XDP", "XDP Redirect ตรงเข้า User Space",
        "ใช้หน่วยความจำร่วม (UMEM + Ring Queues) รับแพ็กเก็ตจากไดรเวอร์ตรงเข้า Go โดยข้าม Network Stack"
    )
    stage = make_stage(120, 366, "วงจร UMEM + 2 Rings: FILL Ring (ส่งช่องว่างให้ Kernel) ⇄ RX Ring (ส่งแพ็กเก็ตขึ้น Go)")

    n_tx = node_card(44, 218, 150, 146, "w21-tx", "ส่ง UDP :9999", "#dcfce7", "bb-nic", "แพ็กเก็ตเข้า", "#86efac")
    n_xdp = node_card(242, 218, 184, 146, "XDP Hook", "xsks_map[qid]", "#fff1f2", "bb-shield", "XDP_REDIRECT", "#fecdd3")
    n_fill = node_card(472, 176, 202, 94, "FILL Ring", "Kernel Consumer", "#fef3c7", badge="ชี้เฟรมว่างใน UMEM", badge_fill="#fde68a")
    n_umem = node_card(472, 286, 202, 74, "UMEM Frames (mmap)", "แชร์ RAM ร่วม Kernel ↔ Go", "#ffffff")
    n_rx = node_card(472, 376, 202, 92, "RX Ring", "Go Consumer", "#dbeafe", badge="Descriptor (addr, len)", badge_fill="#93c5fd")
    n_go = node_card(728, 218, 184, 146, "Go User Space", "main.go / xsk.go", "#eff6ff", "bb-app", "Poll & Recycle", "#bfdbfe")

    arrows = (
        '<path class="ant-green" d="M194 291H238" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M728 244L678 224" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-red" d="M426 270L468 232" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-red" d="M426 308L468 323" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-blue" d="M573 360V372" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-blue" d="M674 420L724 318" marker-end="url(#bb-ah-blue)"/>'
    )

    anim_css = (
        kf_move("pk-fill", dur, 0.3, 3.1, [(790, 240), (573, 224)])
        + kf_move("pk-udp", dur, 3.2, 6.2, [(119, 291), (334, 291)])
        + kf_move("pk-umem", dur, 6.4, 9.6, [(334, 298), (573, 323), (573, 418)])
        + kf_move("pk-rec", dur, 9.7, 13.6, [(573, 418), (820, 292), (573, 224)])
        + kf_pop("bd-rc", dur, 11.2, 13.7)
    )
    anim_els = (
        pkt_chip("pk-fill", "Empty Frame", "#fde68a", 96)
        + pkt_chip("pk-udp", "UDP :9999", "#7de3b4", 88)
        + pkt_chip("pk-umem", "Data → RX", "#fda4af", 92)
        + pkt_chip("pk-rec", "Read & Recycle", "#93c5fd", 112)
        + '<g class="bd-rc"><rect x="740" y="184" width="160" height="24" rx="12" fill="#22c55e" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="820" y="200" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">รับครบ &amp; คืน Frame วนใช้ ✓</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(506, steps, dur, split_x=256)
    return "Week 21: XDP Redirect & AF_XDP Rings", 506 + tbl_h + 24, header + stage + n_tx + n_xdp + n_fill + n_umem + n_rx + n_go + arrows + anim_els + tbl, anim_css + tbl_css


def build_week22_sequence():
    dur = 13.0
    steps = [
        ("โปรเซสเรียก openat()", "แอปเช่น cat เปิดไฟล์ → เข้าเคอร์เนลฟังก์ชัน do_sys_openat2()", 0.3, 2.8),
        ("โดดเข้า Trampoline", "ไม่มี INT3 Interrupt! เคอร์เนลเปลี่ยนหัวฟังก์ชันเป็น Direct Call ตรงๆ", 2.9, 5.6),
        ("fentry จดเวลาเริ่ม", "trace_openat2_entry เก็บ timestamp ลง start_map ก่อนฟังก์ชันรัน", 5.7, 8.2),
        ("ฟังก์ชันจริงรัน → fexit", "do_sys_openat2() คืนค่า fd แล้ว fexit คิด latency ส่งเข้า Ringbuf", 8.3, 10.9),
        ("Go อ่านค่า Latency", "main.go ดึงข้อมูลจาก Ring Buffer พิมพ์ PID, COMM, FD และ Latency", 11.0, 12.7),
    ]
    header = make_header(
        "Week 22 · fentry/fexit", "BPF Trampoline (เร็วกว่า kprobe)",
        "ไม่ต้องพึ่ง breakpoint INT3 อีกต่อไป — เรียกฟังก์ชันจับเวลาเข้า-ออกด้วย Direct Jump ระดับเครื่อง"
    )
    stage = make_stage(120, 366, "ลำดับทำงาน:  openat()  ──▶  BPF Trampoline  ──▶  fentry  ──▶  do_sys_openat2  ──▶  fexit → Ringbuf")

    n_app = node_card(44, 214, 148, 146, "User Process", "cat /etc/hosts", "#eff6ff", "bb-app", "syscall openat()", "#bfdbfe")
    n_tr = node_card(242, 208, 206, 148, "BPF Trampoline", "JIT Call (nop→call)", "#dcfce7", "bb-cpu", "ไม่ใช้ INT3 (เร็วมาก)", "#86efac")
    n_fe = node_card(492, 178, 184, 96, "fentry Hook", "ก่อนเข้าฟังก์ชัน", "#fff1f2", badge="จด start_ns ลง Map", badge_fill="#fecdd3")
    n_fn = node_card(718, 214, 194, 146, "do_sys_openat2", "ฟังก์ชันจริงใน Kernel", "#ffffff", "bb-server", "คืนค่า fd / -errno", "#e2e8f0")
    n_fx = node_card(492, 304, 184, 96, "fexit Hook", "รับ ret หลังจบฟังก์ชัน", "#fef3c7", badge="ส่ง Ringbuf → Go", badge_fill="#fde68a")
    n_go = node_card(242, 386, 206, 72, "Go Ringbuf Reader", "พิมพ์ PID, COMM, FD, Latency", "#eff6ff")

    arrows = (
        '<path class="ant-blue" d="M192 282H238" marker-end="url(#bb-ah-blue)"/>'
        '<path class="ant-red" d="M448 242L488 226" marker-end="url(#bb-ah-red)"/>'
        '<path class="ant-green" d="M676 226L714 252" marker-end="url(#bb-ah-green)"/>'
        '<path class="ant-amber" d="M714 312L680 342" marker-end="url(#bb-ah-amber)"/>'
        '<path class="ant-blue" d="M492 368L452 404" marker-end="url(#bb-ah-blue)"/>'
    )

    anim_css = (
        kf_move("pk-op", dur, 0.3, 5.5, [(118, 282), (345, 282)])
        + kf_move("pk-fe", dur, 5.6, 8.2, [(345, 270), (584, 226), (760, 260)])
        + kf_move("pk-fx", dur, 8.3, 11.2, [(815, 290), (584, 352), (345, 418)])
        + kf_pop("bd-tr", dur, 2.9, 5.6)
        + kf_pop("bd-go", dur, 11.0, 12.7)
    )
    anim_els = (
        pkt_chip("pk-op", "openat()", "#93c5fd", 86)
        + '<g class="bd-tr"><rect x="261" y="180" width="168" height="22" rx="11" fill="#22c55e" stroke="#111111" stroke-width="1.6"/>'
        + '<text x="345" y="195" font-size="11.5" font-weight="700" fill="#ffffff" text-anchor="middle">Direct Call (ไม่มี INT3!)</text></g>'
        + pkt_chip("pk-fe", "จด start_ns", "#fda4af", 92)
        + pkt_chip("pk-fx", "ret + delta_ns", "#fde68a", 104)
        + '<g class="bd-go"><rect x="255" y="454" width="180" height="24" rx="12" fill="#2563eb" stroke="#111111" stroke-width="1.8"/>'
        + '<text x="345" y="470" font-size="12" font-weight="700" fill="#ffffff" text-anchor="middle">พิมพ์ Latency สำเร็จ ✓</text></g>'
    )

    tbl, tbl_css, tbl_h = make_step_table(506, steps, dur, split_x=256)
    return "Week 22: fentry/fexit Trampolines vs kprobe", 506 + tbl_h + 24, header + stage + n_app + n_tr + n_fe + n_fn + n_fx + n_go + arrows + anim_els + tbl, anim_css + tbl_css


BUILDERS = {
    "guide-ch01-ingress-path": build_guide_ch01_ingress_path,
    "guide-ch02-build-load-pipeline": build_guide_ch02_build_load_pipeline,
    "guide-ch03-race-condition": build_guide_ch03_race_condition,
    "guide-ch05-ringbuf-mpsc": build_guide_ch05_ringbuf_mpsc,
    "week07-xdp-path": build_week07_xdp_path,
    "week08-sequence": build_week08_sequence,
    "week20-sequence": build_week20_sequence,
    "week21-sequence": build_week21_sequence,
    "week22-sequence": build_week22_sequence,
    **EXTRA_BUILDERS,
}


def prepare_font_dir(tmp: Path) -> Path:
    for src in FONT_SOURCES:
        if not src.exists():
            raise FileNotFoundError(f"missing required font: {src}")
        (tmp / src.name).symlink_to(src)
    return tmp


def render_one(name: str, font_dir: Path) -> Path:
    title, height, body, extra_css = BUILDERS[name]()
    raw_for_fonts = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 {height}" '
        f'width="960" height="{height}" role="img">'
        f'<title>{esc(title)}</title>'
        f'{SHARED_SYMBOLS}'
        f'<rect width="960" height="{height}" rx="18" fill="#eceef9" stroke="#cbd5e1" stroke-width="2"/>'
        f'{body}</svg>'
    )
    faces = diagram_postprocess.font_faces(raw_for_fonts, font_dir)
    full_svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 {height}" '
        f'width="960" height="{height}" role="img" style="background-color: transparent;">'
        f'<title>{esc(title)}</title>'
        f'<style>{faces}{BASE_CSS}{extra_css}</style>'
        f'{SHARED_SYMBOLS}'
        f'<rect width="960" height="{height}" rx="18" fill="#eceef9" stroke="#cbd5e1" stroke-width="2"/>'
        f'{body}</svg>'
    )
    ET.fromstring(full_svg)
    out = DIAG_DIR / f"{name}.svg"
    out.write_text(full_svg, encoding="utf-8")
    return out


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--list":
        for name in sorted(BUILDERS):
            print(name)
        return 0
    targets = sys.argv[1:] if len(sys.argv) > 1 else sorted(BUILDERS)
    unknown = [t for t in targets if t not in BUILDERS]
    if unknown:
        print(f"ERROR: unknown animated diagram(s): {unknown}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        font_dir = prepare_font_dir(Path(tmp))
        for name in targets:
            out = render_one(name, font_dir)
            print(f"  {out.name:<34s} {out.stat().st_size // 1024:5d} KB (animated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
