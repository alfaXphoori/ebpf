#!/usr/bin/env bash
# Week 13: kfree_skb dropwatch — real drops on loopback (NO_SOCKET) as in README
source "$(dirname "$0")/lib.sh"
lab_init phase07-advanced-security-observability/week13-kfree-skb-dropwatch

LOG=$(mktemp)
cleanup() { sudo pkill -INT -f '^./bin/dropwatch' 2>/dev/null; rm -f "$LOG"; }
trap cleanup EXIT

# append_ours <log> <max-background>: the host is busy (other labs run
# concurrently), so keep every event from OUR test commands (nc/python3), the
# first few background events, and replace the rest with a visible dim note
append_ours() {
    python3 - "$1" "$2" >> "$SHOT_FILE" <<'PY'
import sys
lines = open(sys.argv[1], errors="replace").read().replace("\r", "").split("\n")
keep_bg, out, bg, cut, state = int(sys.argv[2]), [], 0, 0, "head"
for l in lines:
    if state == "head":
        out.append(l)
        if l.startswith("-----"): state = "ev"
    elif state == "ev" and l.strip() and l[:2].isdigit():
        comm = l.split()[2]
        if comm in ("nc", "python3") or bg < keep_bg:
            if comm not in ("nc", "python3"): bg += 1
            out.append(l)
        else:
            cut += 1
    else:
        if state == "ev" and cut:
            out.append("\x1b[2m# (... ตัด event พื้นหลังจากแล็บอื่น/ระบบออก %d บรรทัด ...)\x1b[0m" % cut)
        state = "tail"; out.append(l)
print("\n".join(out).rstrip("\n"))
PY
}

shot_begin 1-build "Terminal — make all (bpf2go + go build)"
make -s clean >/dev/null 2>&1
show "make all 2>&1 | grep -v -e '^\s' -e 'warning:' -e '^\^' -e '~~'" "make all 2>&1 | grep -v -e '^\s' -e 'warning:' -e '^\^' -e '~~'"
run "sudo cat /sys/kernel/tracing/events/skb/kfree_skb/format | head -12"
shot_end

bg "$LOG" sudo ./bin/dropwatch -ip-only
sleep 4

shot_begin 2-trigger-drops "Terminal 2 — สร้าง drop ที่รู้สาเหตุบน loopback"
run 'nc -z -w1 127.0.0.1 9999; echo exit=$?'
run 'echo hi | nc -u -w1 127.0.0.1 9998'
run "python3 -c \"import socket; s=socket.socket(socket.AF_INET6); s.connect(('::1', 9997))\" 2>&1 | tail -1"
run sudo bpftool prog show name trace_kfree_skb
shot_end
sleep 3

bg_stop '^./bin/dropwatch'
shot_begin 3-dropwatch "Terminal 1 — sudo ./bin/dropwatch -ip-only"
prompt_only sudo ./bin/dropwatch -ip-only
append_ours "$LOG" 8
shot_end
