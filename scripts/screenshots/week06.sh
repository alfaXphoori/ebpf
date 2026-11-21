#!/usr/bin/env bash
# Week 06: syscall-top (BPF_MAP_TYPE_HASH), bpftool map dump, verifier logs, test_run tests
source "$(dirname "$0")/lib.sh"
# stdin at EOF makes `script` inject a NUL that sudo's pty echoes as "^@";
# give every `run` a stdin that never ends (local workaround, not in lib.sh)
exec 0< <(exec sleep 3600); STDIN_PID=$!
lab_init phase03-modern-ebpf-core/week06-ebpf-maps

PAT='^./bin/syscall-top'
LOG=$(mktemp)
cleanup() { kill $STDIN_PID 2>/dev/null; sudo pkill -INT -f "$PAT" 2>/dev/null; sleep 1; sudo pkill -KILL -f "$PAT" 2>/dev/null; rm -f "$LOG"; }
trap cleanup EXIT

shot_begin 1-build "Terminal — make clean && make all"
run "make clean && make all"
shot_end

# --- 4.2: dashboard in Terminal 1, load generator + bpftool in Terminal 2
bg "$LOG" sudo ./bin/syscall-top
for _ in $(seq 1 40); do grep -q 'Collecting syscall' "$LOG" && break; sleep 0.25; done
sleep 0.5

shot_begin 2-load "Terminal 2 — สร้างโหลด getpid() 50,000 ครั้ง + bpftool"
run "python3 -c 'import os
print(\"python3 PID\", os.getpid())
for _ in range(50000): os.getpid()'"
sleep 2.2
run sudo bpftool map list name syscall_map
run "sudo bpftool map dump name syscall_map | head -n 16"
shot_end
sleep 0.5

bg_stop "$PAT"
shot_begin 3-syscall-top "Terminal 1 — sudo ./bin/syscall-top (กด Ctrl+C)"
prompt_only sudo ./bin/syscall-top
append_head "$LOG" 5
note "... (หน้าจอ dashboard ถูกล้างและวาดใหม่ทุก 2 วินาที) ..."
append_last_frame "$LOG"
OURPID=$(grep -ao 'python3 PID [0-9]*' "$SHOT_RAW/week06-2-load.ansi" | awk '{print $3}')
note "PID $OURPID = python3 getpid() จาก Terminal 2; python3 อื่นเป็นงานอื่นบนเครื่อง (raw_syscalls เห็นทั้งระบบ)"
shot_end

shot_begin 4-verifier "Terminal — Verifier Log จริง (verifier_fail)"
run sudo ./bin/verifier_fail -case bounds
run sudo ./bin/verifier_fail -case nullcheck
run sudo ./bin/verifier_fail -case fixed
shot_end

shot_begin 5-test "Terminal — make test (BPF_PROG_TEST_RUN)"
run "make test 2>&1 | grep -vE '^(Compiled|Stripped|Wrote) '"
shot_end
