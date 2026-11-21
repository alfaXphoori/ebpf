#!/usr/bin/env bash
# Week 05: bpf2go + cilium/ebpf exec counter on tracepoint sched/sched_process_exec
source "$(dirname "$0")/lib.sh"
# stdin at EOF makes `script` inject a NUL that sudo's pty echoes as "^@";
# give every `run` a stdin that never ends (local workaround, not in lib.sh)
exec 0< <(exec sleep 3600); STDIN_PID=$!
lab_init phase03-modern-ebpf-core/week05-libbpf-cilium-go

PAT='^./bin/exec-counter'
LOG=$(mktemp)
PIDS=/tmp/w05-pids
cleanup() { kill $STDIN_PID 2>/dev/null; sudo pkill -INT -f "$PAT" 2>/dev/null; sleep 1; sudo pkill -KILL -f "$PAT" 2>/dev/null; rm -f "$LOG" "$PIDS"; }
trap cleanup EXIT

shot_begin 1-build "Terminal — make generate build"
run make generate build
shot_end

shot_begin 2-test "Terminal — make test (go test -exec sudo)"
run make test
shot_end

shot_begin 3-run "Terminal — sudo ./bin/exec-counter"
run sudo timeout -s INT 6 ./bin/exec-counter
shot_end

# 4.2 + step 6: keep the counter running, check bpftool and per-CPU coverage
bg "$LOG" sudo ./bin/exec-counter
for _ in $(seq 1 40); do grep -q 'Monitoring active' "$LOG" && break; sleep 0.25; done
sleep 0.5

shot_begin 4-bpftool "Terminal 2 — bpftool ขณะ exec-counter ทำงาน"
run sudo bpftool prog list name handle_exec
run sudo bpftool map dump name exec_count
shot_end

shot_begin 5-all-cpus "Terminal 2 — ตรวจว่าจับ exec ได้ครบทุก CPU"
run "for c in 0 1 2 3 4 5 6 7; do taskset -c \$c /bin/true & echo \$!; wait; done > $PIDS; xargs < $PIDS"
run "sudo grep -wE \"exec by PID (\$(paste -sd'|' $PIDS))\" /sys/kernel/tracing/trace"
note "แต่ละ PID มี 2 บรรทัด: exec ของ taskset ก่อน แล้วจึง exec ของ /bin/true บน CPU ที่ระบุ [000]..[007]"
run "sudo grep -wcE \"exec by PID (\$(paste -sd'|' $PIDS))\" /sys/kernel/tracing/trace"
shot_end

bg_stop "$PAT"
