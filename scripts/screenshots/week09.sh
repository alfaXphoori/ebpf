#!/usr/bin/env bash
# Week 09: ring buffer + execve tracepoint + SSL_write uprobes — real run.
# TLS traffic goes to a local HTTPS server on 127.0.0.1:18409 (self-signed),
# plus one curl to https://example.com to show the HTTP/2 (ALPN) case.
source "$(dirname "$0")/lib.sh"
lab_init phase05-security-observability/week09-ringbuf-uprobes
make -s all >/dev/null 2>&1 || { echo "build failed"; exit 1; }

W=$(mktemp -d /tmp/w09-tls.XXXX)
SRV_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    sudo pkill -INT -f '^./bin/ringbuf_events' 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

# local HTTPS server (python ssl, OpenSSL libssl.so.3)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$W/key.pem" -out "$W/cert.pem" >/dev/null 2>&1
mkdir -p "$W/www"; echo "hello from w09 local https" > "$W/www/index.html"
python3 - "$W" >/dev/null 2>&1 <<'PY' &
import http.server, ssl, sys, functools
d = sys.argv[1]
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=d + "/www")
s = http.server.HTTPServer(("127.0.0.1", 18409), h)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(d + "/cert.pem", d + "/key.pem")
s.socket = c.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
SRV_PID=$!
sleep 1

# keep only the tracer's own header/info lines and our test commands (the box
# runs other processes at the same time, like the README notes)
filt() {
    python3 - "$1" >> "$SHOT_FILE" <<'PY'
import re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().replace("\r", "").replace("\x00", "").replace("^@", "").splitlines()
ev = re.compile(r"\[(EXECVE|TLS_PLAINTEXT)\]\S*\s+(\d+)\s+\d+\s+\d+\s+(\S+)\s")
tls_pids = {m.group(2) for l in lines if (m := ev.search(re.sub(r"\x1b\[[0-9;]*m", "", l))) and m.group(1) == "TLS_PLAINTEXT"}
started = False   # our first test command is /bin/echo hello
for l in lines:
    m = ev.search(re.sub(r"\x1b\[[0-9;]*m", "", l))
    if m and m.group(3) == "echo": started = True
    if m and not started: continue
    if not m:
        if re.search(r"\[INFO\]|\[WARN\]|EVENT_TYPE|^-{20}", l): print(l)
        continue
    kind, pid, comm = m.groups()
    if kind == "TLS_PLAINTEXT" or comm in ("echo", "id", "curl", "wget") or (comm == "python3" and pid in tls_pids):
        print(l)
PY
}

# ---------------- 4.1: sched_process_exec + uprobes ----------------
LOG=$(mktemp)
bg "$LOG" sudo ./bin/ringbuf_events
sleep 3

shot_begin 1-traffic "Terminal 2 — สร้าง exec และ TLS traffic (ขั้นตอนที่ 3–4)"
note "เซิร์ฟเวอร์ HTTPS ทดสอบ (python3 + OpenSSL, self-signed) รันอยู่ที่ https://127.0.0.1:18409"
run ldd /usr/bin/curl \| grep libssl
run /bin/echo hello
run id
run curl -sk --http1.1 https://127.0.0.1:18409/
run curl -s -o /dev/null -w "'%{http_version}\n'" https://example.com
run python3 -c "\"import ssl,urllib.request; print(urllib.request.urlopen('https://127.0.0.1:18409/', context=ssl._create_unverified_context()).read())\""
run wget -q --no-check-certificate -O - https://127.0.0.1:18409/
shot_end
sleep 2

bg_stop '^./bin/ringbuf_events'
shot_begin 2-ringbuf-events "Terminal 1 — sudo ./bin/ringbuf_events (sched_process_exec + SSL_write uprobes)"
prompt_only sudo ./bin/ringbuf_events
note "กรองเฉพาะบรรทัดของ tracer และคำสั่งทดสอบ (ตัด [EXECVE] ของ process อื่นบนเครื่องออก)"
note "python3 PID $SRV_PID คือเซิร์ฟเวอร์ HTTPS ทดสอบ: uprobe เห็น response ฝั่ง server ด้วยเพราะใช้ libssl เดียวกัน"
filt "$LOG"
shot_end
rm -f "$LOG"

# ---------------- 4.2: sys_enter_execve CPU0 quirk ----------------
LOG=$(mktemp)
bg "$LOG" sudo ./bin/ringbuf_events -exec-hook=syscall
sleep 3
shot_begin 3-syscall-hook "sys_enter_execve + taskset ทุก CPU (ข้อสังเกต Linux 7.0)"
run 'for c in 0 1 2 3 4 5 6 7; do taskset -c $c /bin/echo cpu$c; done'
sleep 2
bg_stop '^./bin/ringbuf_events'
prompt_only "sudo ./bin/ringbuf_events -exec-hook=syscall    # (Terminal 1, filtered: /bin/echo only)"
sed 's/\^@//' "$LOG" | grep -E '\[INFO\] Tracepoint|EVENT_TYPE|^-{20}|binary=/bin/echo|Ringbuf reader closed' | tr -d '\r' >> "$SHOT_FILE"
shot_end
rm -f "$LOG"
