#!/usr/bin/env bash
# Week 18: on-CPU profiler (perf_event + stack maps) — real run against bin/busy
# NOTE: this regenerates images/cpu-busy.{folded,svg}; after a re-run update the
# sample numbers quoted in README section 4.5 (ก) to match the new graph.
source "$(dirname "$0")/lib.sh"
lab_init phase08-system-performance-observability/week18-cpu-profiler-stacks
make -s all >/dev/null 2>&1

cleanup() {
    sudo pkill -INT -f '^./bin/cpu-profiler' 2>/dev/null
    pkill -f '^./bin/busy' 2>/dev/null
    rm -f "$LAB_DIR/out.txt" "$LAB_DIR/all.txt"
}
trap cleanup EXIT

shot_begin 1-objdump "Terminal — ตรวจ frame pointer ของ workload"
run 'objdump -d bin/busy --no-show-raw-insn | grep -A6 "<hot_path_a>:"'
shot_end

shot_begin 2-pid-profile "Terminal — profile เฉพาะ PID ของ busy"
run './bin/busy 10 & sleep 0.2; sudo ./bin/cpu-profiler -p $! -d 6s -folded out.txt'
shot_end
sleep 4.5   # let the first busy finish

shot_begin 3-system-wide "Terminal — profile ทั้งระบบขณะ busy ทำงาน"
run './bin/busy 8 & sleep 0.2; sudo ./bin/cpu-profiler -d 5s -top 3 -folded all.txt'
shot_end
sleep 3.5

# 4.5: render the flame graph from this run (same paths as the README uses)
shot_begin 4-flamegraph "Terminal — สร้าง Flame Graph ด้วย flamegraph.py"
run cat out.txt
run 'cp out.txt images/cpu-busy.folded'
run "python3 flamegraph.py out.txt --title \"busy (PID) on-CPU profile — Linux $(uname -r | cut -d- -f1-2), 99 Hz, 6 s\" > images/cpu-busy.svg"
run 'ls -l images/'
run "grep -o '<title>[^<]*hot_path_[ab][^<]*</title>' images/cpu-busy.svg"
shot_end
