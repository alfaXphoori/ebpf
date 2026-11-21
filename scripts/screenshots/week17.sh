#!/usr/bin/env bash
# Week 17: biolatency (tp_btf block_rq_issue/complete) — real disk I/O:
# read-only O_DIRECT reads of /dev/sdb (idle disk; sda holds the repo and
# is busy with the other labs' builds, so its READ count would not be exact) + a 64 MiB direct write to a temp file in
# the lab dir (on /mnt/sda; /tmp is tmpfs here so it would make no block I/O)
source "$(dirname "$0")/lib.sh"
lab_init phase08-system-performance-observability/week17-block-io-biolatency
make -s all >/dev/null 2>&1

LOG=$(mktemp)
cleanup() { sudo pkill -INT -f '^./bin/biolatency' 2>/dev/null; rm -f "$LOG" "$LAB_DIR"/biolat.*; }
trap cleanup EXIT

# append_hist <log>: the histogram covers every disk; keep the sections our
# workload produced (sdb READ, sda WRITE) and list the others by header only
append_hist() {
    python3 - "$1" >> "$SHOT_FILE" <<'PY'
import sys
L = open(sys.argv[1], errors="replace").read().replace("\r", "").replace("^@", "").split("\n")
out, keep, skipped = [], True, []
for l in L:
    if l.startswith("disk = "):
        keep = l.startswith("disk = sdb") or (l.startswith("disk = sda") and "op = WRITE" in l)
        if not keep: skipped.append(l); continue
    if keep: out.append(l)
while out and not out[-1].strip(): out.pop()
if skipped:
    out.append("")
    out.append("\x1b[2m# ตัด histogram ของดิสก์/การทำงานพื้นหลังอื่นออก (แสดงเฉพาะหัวข้อ):\x1b[0m")
    out += ["\x1b[2m#   %s\x1b[0m" % s for s in skipped]
print("\n".join(out))
PY
}

shot_begin 1-precheck "Terminal — ตรวจ BTF และดิสก์ก่อนรัน"
run ls /sys/kernel/btf/vmlinux
run 'grep -c "btf_trace_block_rq_issue" ../../vmlinux.h'
run lsblk -e7 -o NAME,ROTA,MODEL
run "grep . /sys/block/{sda,sdb}/queue/{max_sectors_kb,scheduler}"
shot_end

bg "$LOG" sudo ./bin/biolatency -duration 10s
sleep 2

shot_begin 2-workload "Terminal 2 — สร้าง Disk I/O ระหว่าง biolatency ทำงาน"
note "อ่านดิบแบบอ่านอย่างเดียวจาก sdb (ดิสก์ว่าง; sda เป็นดิสก์ของ repo ที่แล็บอื่นกำลังใช้อยู่)"
run sudo gnudd if=/dev/sdb of=/dev/null bs=4k count=5000 iflag=direct
note "เขียนไฟล์ชั่วคราวในไดเรกทอรีแล็บ (/mnt/sda = ดิสก์ sda; /tmp บนเครื่องนี้เป็น tmpfs)"
run 'TMPF=$(mktemp -p . biolat.XXXXXX); dd if=/dev/zero of=$TMPF bs=1M count=64 oflag=direct conv=fsync; rm -f $TMPF'
run sudo bpftool prog show name trace_rq_issue
run sudo bpftool map dump name io_totals
shot_end

# wait for -duration 10s to finish by itself
for _ in $(seq 1 150); do kill -0 "$BG_PID" 2>/dev/null || break; sleep 0.1; done
wait "$BG_PID" 2>/dev/null

shot_begin 3-histogram "Terminal 1 — sudo ./bin/biolatency -duration 10s"
prompt_only sudo ./bin/biolatency -duration 10s
append_hist "$LOG"
shot_end
