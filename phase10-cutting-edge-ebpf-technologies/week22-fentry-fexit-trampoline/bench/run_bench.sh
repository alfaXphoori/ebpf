#!/usr/bin/env bash
# run_bench.sh - เปรียบเทียบ overhead ของ kprobe / kretprobe / fentry / fexit บน do_sys_openat2
#
# วิธีวัด 2 แบบ:
#   (1) End-to-end: เวลาเฉลี่ยต่อรอบ openat()+close() ของ openbench เมื่อมี/ไม่มี probe
#       ส่วนต่างจาก baseline = ต้นทุนรวมของกลไก attach (ftrace/int3/trampoline) + ตัวโปรแกรม BPF
#   (2) bpf_stats: run_time_ns / run_cnt ของแต่ละโปรแกรม (kernel.bpf_stats_enabled=1)
#       วัดเฉพาะเวลาที่ "ตัวโปรแกรม BPF" รัน ไม่รวมต้นทุนของกลไก attach
#
# ทุก probe ใช้ body เดียวกัน: { @c = count(); }  (bpftrace, per-CPU map)
# ต้องการ: bpftrace, bpftool, jq, gcc, taskset, sudo
set -euo pipefail

FUNC=do_sys_openat2
ITER=${ITER:-1000000}
REPS=${REPS:-5}
CPU=${CPU:-2}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)          # คอมไพล์ load generator ไว้นอก repo
BIN="$WORK/openbench"
LOG="$WORK/bpftrace.log"
BT_PID=""

gcc -O2 -o "$BIN" "$HERE/openbench.c"

OLD_STATS=$(sysctl -n kernel.bpf_stats_enabled)
cleanup() {
    [ -n "$BT_PID" ] && sudo kill -INT "$BT_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    sudo sysctl -q kernel.bpf_stats_enabled="$OLD_STATS"
    rm -rf "$WORK"
}
trap cleanup EXIT

# best-of-N (ค่าน้อยสุด): ทนต่อ noise จากโปรเซสอื่น/CPU frequency scaling ได้ดีกว่า mean
best() { sort -n | head -1; }

bench() {  # รัน openbench REPS ครั้ง บน CPU เดียว แล้วคืนค่า best-of-REPS ns/op
    for _ in $(seq "$REPS"); do taskset -c "$CPU" "$BIN" "$ITER"; done | best
}

start_bt() {  # $1 = probe spec
    sudo bpftrace -e "$1 { @c = count(); }" >"$LOG" 2>&1 &
    BT_PID=$!
    for _ in $(seq 100); do grep -q "Attached\|Attaching" "$LOG" && break; sleep 0.1; done
    sleep 1
}

stop_bt() {
    sudo kill -INT "$BT_PID" 2>/dev/null || true
    wait "$BT_PID" 2>/dev/null || true
    BT_PID=""
}

echo "== (1) End-to-end: openat()+close() on /dev/null, $ITER iters, best of $REPS, pinned CPU $CPU =="
printf "%-10s %12s %12s %10s\n" "probe" "baseline" "with-probe" "delta"
for P in kprobe kretprobe fentry fexit; do
    BASE=$(bench)              # วัด baseline ใหม่ก่อนทุก probe เพื่อลดผลของ drift
    start_bt "$P:$FUNC"
    V=$(bench)
    stop_bt
    printf "%-10s %9s ns %9s ns %+7.1f ns\n" "$P" "$BASE" "$V" "$(awk -v a="$V" -v b="$BASE" 'BEGIN{print a-b}')"
done

echo
echo "== (2) bpf_stats: average BPF program run time (run_time_ns / run_cnt) =="
sudo sysctl -q kernel.bpf_stats_enabled=1
for P in kprobe kretprobe fentry fexit; do
    start_bt "$P:$FUNC"
    taskset -c "$CPU" "$BIN" "$ITER" >/dev/null
    # bpftrace ตั้งชื่อโปรแกรมเป็น <probe>_..._do_sys_openat2_N  เช่น fexit_vmlinux_do_sys_openat2_1
    sudo bpftool prog show -j | jq -r --arg p "${P}_" '.[]
        | select((.name // "") | startswith($p) and contains("openat2"))
        | select((.run_cnt // 0) > 0)
        | "\($p)\t\(.type)\trun_cnt=\(.run_cnt)\trun_time_ns=\(.run_time_ns)\tavg=\((.run_time_ns / .run_cnt * 10 | floor) / 10) ns"' 
    stop_bt
done
sudo sysctl -q kernel.bpf_stats_enabled="$OLD_STATS"
echo
echo "kernel.bpf_stats_enabled restored to $(sysctl -n kernel.bpf_stats_enabled)"
