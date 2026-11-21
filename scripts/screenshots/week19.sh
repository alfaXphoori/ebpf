#!/usr/bin/env bash
# Week 19: OOM watcher — OOM is triggered ONLY inside a transient systemd scope
# with MemoryMax=50M / MemorySwapMax=0 (as the README describes), never host-wide.
source "$(dirname "$0")/lib.sh"
lab_init phase08-system-performance-observability/week19-memory-oom-watcher
make -s all >/dev/null 2>&1

LOG=$(mktemp)
cleanup() { sudo pkill -INT -f '^./bin/oom-watcher' 2>/dev/null; rm -f "$LOG"; }
trap cleanup EXIT

bg "$LOG" sudo ./bin/oom-watcher -duration 10s
sleep 2

shot_begin 1-trigger-oom "Terminal 2 — กระตุ้น OOM ใน scope ที่จำกัดแรม 50M"
run "systemd-run --user --scope -p MemoryMax=50M -p MemorySwapMax=0 python3 -c '
blocks = []
for i in range(200):              # safety cap: never more than ~200 MB
    blocks.append(b\"\\x01\" * (1 << 20))
print(\"allocated\", len(blocks), \"MB without OOM?!\")
'
echo \"exit status: \$?\"            # 137 = 128 + 9 (SIGKILL)"
shot_end
sleep 1

shot_begin 3-kernel-log "Terminal 2 — เทียบกับ kernel log และ bpftool"
run 'journalctl -k --since "-1min" | grep -i "Killed process"'
run sudo bpftool prog show name on_oom_mark_victim
run 'sudo bpftool map dump name page_fault_coun | head'
shot_end

for _ in $(seq 1 150); do kill -0 "$BG_PID" 2>/dev/null || break; sleep 0.1; done
wait "$BG_PID" 2>/dev/null

shot_begin 2-watcher "Terminal 1 — sudo ./bin/oom-watcher -duration 10s"
prompt_only sudo ./bin/oom-watcher -duration 10s
tr -d '\r' < "$LOG" | sed 's/^\^@//' >> "$SHOT_FILE"
shot_end
