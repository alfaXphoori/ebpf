#!/usr/bin/env bash
# Week 03: bpftrace exec/tcp tracing (system-wide by design) + bpftool inspection
source "$(dirname "$0")/lib.sh"
# stdin at EOF makes `script` inject a NUL that sudo's pty echoes as "^@";
# give every `run` a stdin that never ends (local workaround, not in lib.sh)
exec 0< <(exec sleep 3600); STDIN_PID=$!
lab_init phase02-first-step-ebpf/week03-bpftool-bpftrace

PAT='^bpftrace trace_exec_and_tcp.bt'
LOG=$(mktemp)
cleanup() { kill $STDIN_PID 2>/dev/null; sudo pkill -INT -f "$PAT" 2>/dev/null; sleep 1; sudo pkill -KILL -f "$PAT" 2>/dev/null; rm -f "$LOG"; }
trap cleanup EXIT

# The machine runs many other jobs, so the raw bpftrace log has thousands of
# exec lines. Local helper (not in lib.sh): keep the banner, our own commands,
# retransmits and map/histogram output; collapse everything else into a dim
# "(ตัด N บรรทัด)" marker, and keep only the K largest entries of each map.
append_trimmed() {  # <log> <section: live|summary>
    python3 - "$1" "$2" >> "$SHOT_FILE" <<'PY'
import re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().replace("\r", "").split("\n")
mode = sys.argv[2]
KEEP_EXEC = ("/usr/bin/ls", "/usr/bin/whoami", "/usr/bin/curl")
K = 6
import os
W0, W1 = os.environ.get("W0", "00:00:00"), os.environ.get("W1", "99:99:99")  # time window of Terminal 2
dim = lambda s: "\033[2m# %s\033[0m" % s
end_i = next((i for i, l in enumerate(lines) if "FINAL OBSERVABILITY SUMMARY" in l), len(lines))
if mode == "live":
    body = lines[:max(end_i - 2, 0)]
else:
    body = lines[end_i - 2:]
out, skipped, mapbuf = [], 0, []
def flush_skip():
    global skipped
    if skipped: out.append(dim("... (ตัด %d บรรทัด: exec อื่นบนเครื่อง)" % skipped)); skipped = 0
def flush_map():
    global mapbuf
    if len(mapbuf) > K:
        # keep the K largest entries, plus our own curl (the lab's workload)
        kept = [l for i, l in enumerate(mapbuf) if i >= len(mapbuf) - K or "[curl]" in l]
        out.append(dim("... (ตัด %d รายการที่ค่าน้อยกว่า)" % (len(mapbuf) - len(kept))))
        out.extend(kept)
    else:
        out.extend(mapbuf)
    mapbuf = []
exec_re = re.compile(r"^\d\d:\d\d:\d\d  ")
in_events = False
for l in body:
    if l.startswith("@") and "[" in l:
        flush_skip(); mapbuf.append(l); continue
    flush_map()
    if exec_re.match(l) and "[TCP RETRANSMIT]" not in l:
        if l.rstrip().endswith(KEEP_EXEC) and W0 <= l[:8] <= W1:
            flush_skip(); out.append(l)
        else:
            skipped += 1
        continue
    flush_skip(); out.append(l)
flush_map(); flush_skip()
# drop the second and later periodic reports in the live view (they repeat)
if mode == "live":
    res, n = [], 0
    for l in out:
        if "--- [Periodic Report" in l:
            n += 1
        if n >= 2 and "--- [Periodic Report" in l:
            res.append(dim("... (Periodic Report รอบถัดไปตัดออก)")); skip = True
        res.append(l) if n < 2 else None
    out = res
print("\n".join(out).rstrip("\n"))
PY
}

shot_begin 1-versions "Terminal — ตรวจเครื่องมือ bpftrace / bpftool / BTF"
run bpftrace --version
run sudo bpftool version
run ls -la /sys/kernel/btf/vmlinux
run sudo bpftrace -l 'tracepoint:sched:sched_process_exec'
shot_end

bg "$LOG" sudo bpftrace trace_exec_and_tcp.bt
for _ in $(seq 1 60); do grep -q 'Tracing started' "$LOG" && break; sleep 0.5; done
T0=$(date +%s)
sleep 1

export W0=$(date +%H:%M:%S)
shot_begin 2-workload "Terminal 2 — สร้าง exec และทราฟฟิก TCP"
run ls -la
run whoami
run "curl -s https://example.com > /dev/null"
run "curl -s https://www.google.com > /dev/null"
shot_end
export W1=$(date +%H:%M:%S)

shot_begin 3-bpftool "Terminal 3 — bpftool ขณะ bpftrace ทำงาน"
run "sudo bpftool prog show | grep -A2 -E 'name (tracepoint|kprobe)_(sched|tcp)'"
run "sudo bpftool map show | grep -A2 ' name AT_'"
shot_end

# wait for the first interval:s:10 report, then Ctrl-C
while [ $(( $(date +%s) - T0 )) -lt 12 ]; do sleep 0.5; done
bg_stop "$PAT"

shot_begin 4-bpftrace-live "Terminal 1 — sudo bpftrace trace_exec_and_tcp.bt"
prompt_only sudo bpftrace trace_exec_and_tcp.bt
append_trimmed "$LOG" live
shot_end

shot_begin 5-bpftrace-summary "Terminal 1 — กด Ctrl+C: FINAL OBSERVABILITY SUMMARY"
append_trimmed "$LOG" summary
shot_end
cp "$LOG" /tmp/claude-1000/-mnt-sda-ebpf/b6d0fbfd-2869-4420-a3c8-d1859df2134d/scratchpad/week03-raw.log 2>/dev/null
