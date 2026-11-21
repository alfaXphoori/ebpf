#!/usr/bin/env bash
# Week 04: BCC kprobe/kretprobe tcp_v4_connect latency tracker (system-wide by design)
source "$(dirname "$0")/lib.sh"
# stdin at EOF makes `script` inject a NUL that sudo's pty echoes as "^@";
# give every `run` a stdin that never ends (local workaround, not in lib.sh)
exec 0< <(exec sleep 3600); STDIN_PID=$!
lab_init phase02-first-step-ebpf/week04-bcc-python

PAT='^python3 tcp_v4_latency.py'
LOG=$(mktemp)
cleanup() { kill $STDIN_PID 2>/dev/null; sudo pkill -INT -f "$PAT" 2>/dev/null; sleep 1; sudo pkill -KILL -f "$PAT" 2>/dev/null; rm -f "$LOG"; }
trap cleanup EXIT

shot_begin 1-prereq "Terminal — ตรวจความพร้อมของ BCC"
run "python3 -c \"import bcc; print(bcc.__file__)\""
run 'ls -d /lib/modules/$(uname -r)/build'
run "sudo bpftrace -l 'kprobe:tcp_v4_connect'"
shot_end

bg "$LOG" sudo python3 tcp_v4_latency.py
for _ in $(seq 1 120); do grep -q -- '-----------' "$LOG" && break; sleep 0.5; done
sleep 1

shot_begin 2-traffic "Terminal 2 — สร้าง Outbound TCP connections"
run "curl -s http://1.1.1.1 > /dev/null"
run "curl -s https://example.com > /dev/null"
run "curl -s https://www.google.com > /dev/null"
run "curl -s https://github.com > /dev/null"
run "python3 -c \"import socket; s=socket.create_connection(('127.0.0.1', 22)); print('ACTUAL local', s.getsockname())\""
shot_end
sleep 2

bg_stop "$PAT"
shot_begin 3-tracker "Terminal 1 — sudo python3 tcp_v4_latency.py"
prompt_only sudo python3 tcp_v4_latency.py
append "$LOG"
shot_end
