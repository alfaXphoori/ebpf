#!/usr/bin/env bash
# Week 22: fentry/fexit trampoline tracer + overhead bench (real run)
source "$(dirname "$0")/lib.sh"
lab_init phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline
make -s generate >/dev/null 2>&1; make -s build >/dev/null 2>&1

cleanup() { sudo pkill -INT -f '^./bin/trampoline-tracer' 2>/dev/null; true; }
trap cleanup EXIT
cleanup

shot_begin 1-make-test "Terminal — make test (fexit อ่านค่า return)"
run "make test 2>&1 | grep -v -e 'vmlinux.h' -e '^ *[0-9]* |' -e '^ *|' -e 'warnings generated' -e 'In file included'"
shot_end

LOG=$(mktemp)
bg "$LOG" sudo ./bin/trampoline-tracer -comm cat
sleep 2.5

shot_begin 3-trampoline-inspect "Terminal 2 — ตรวจ trampoline ขณะ tracer รัน (ขั้นตอนที่ 4)"
run cat /etc/hosts '>' /dev/null
run cat /nonexistent_file
run sudo bpftool prog show name trace_openat2_entry
show "sudo bpftool link show | grep -A1 tracing" \
     "sudo bpftool link show | grep -B1 -A2 -E 'attach_type trace_(fentry|fexit)' | grep -v '^--' | head -n 12"
run "sudo cat /sys/kernel/tracing/enabled_functions | grep -A1 openat2"
shot_end
sleep 2.5

bg_stop '^./bin/trampoline-tracer'
shot_begin 2-tracer-cat "Terminal 1 — sudo ./bin/trampoline-tracer -comm cat (cat /etc/hosts + /nonexistent_file)"
prompt_only sudo ./bin/trampoline-tracer -comm cat
append "$LOG"
shot_end
rm -f "$LOG"

shot_begin 4-bench "Terminal — วัด overhead: REPS=9 ./bench/run_bench.sh (เครื่องว่าง)"
run REPS=9 ./bench/run_bench.sh
run sysctl kernel.bpf_stats_enabled
shot_end

# `script` under a background/no-tty stdin sometimes echoes a stray NUL as the
# two characters "^@" (tty echoctl) — a capture artifact, not program output.
sed -i 's/\^@//g' "$SHOT_RAW"/week22-*.ansi
