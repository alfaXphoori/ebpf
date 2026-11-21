#!/usr/bin/env bash
# Week 14: cgroup/connect4 egress enforcer — real run in cgroup w14-sock-enforce,
# all destinations are loopback (or 10.99.99.99, which is denied before any SYN)
source "$(dirname "$0")/lib.sh"
lab_init phase07-advanced-security-observability/week14-cgroup-sock-addr
make -s all >/dev/null 2>&1

LOG=$(mktemp); LST=""
cleanup() {
    sudo pkill -INT -f '^./bin/sock-enforce' 2>/dev/null
    [ -n "$LST" ] && kill "$LST" 2>/dev/null
    rm -f "$LOG" "$LAB_DIR/client.py" "$LAB_DIR/precreate.py"
    sleep 1; sudo rmdir /sys/fs/cgroup/w14-sock-enforce 2>/dev/null
}
trap cleanup EXIT

# client.py exactly as in README section 3, step 4 (temporary, removed on exit)
cat > client.py <<'PY'
import socket, errno, sys
def tryit(label, fn):
    try: fn(); print(f"  {label:<48} -> OK (not blocked)")
    except OSError as e: print(f"  {label:<48} -> {errno.errorcode.get(e.errno)} ({e.strerror})")
def tcp4(h, p):
    def f():
        s = socket.socket(); s.settimeout(1)
        try: s.connect((h, p))
        finally: s.close()
    return f
def udp4_connect(h, p):
    def f():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect((h, p))
        finally: s.close()
    return f
def udp4_sendto(h, p):
    def f():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.sendto(b"x", (h, p))
        finally: s.close()
    return f
def tcp6_mapped(h, p):
    def f():
        s = socket.socket(socket.AF_INET6); s.settimeout(1)
        try: s.connect(("::ffff:" + h, p))
        finally: s.close()
    return f
print("cgroup of client:", open("/proc/self/cgroup").read().strip())
tryit("TCP  connect 127.0.0.1:2323 (blocked port)", tcp4("127.0.0.1", 2323))
tryit("TCP  connect 127.0.0.1:8080 (allowed port)", tcp4("127.0.0.1", 8080))
if "--in-cgroup" in sys.argv:   # ไม่ทดสอบ IP ภายนอกจากนอก cgroup เพื่อไม่ให้มี SYN ออกไปจริง
    tryit("TCP  connect 10.99.99.99:80 (blocked IP)", tcp4("10.99.99.99", 80))
tryit("UDP  connect 127.0.0.1:2323 (blocked port)", udp4_connect("127.0.0.1", 2323))
if "--bypass" in sys.argv:
    tryit("UDP  sendto 127.0.0.1:2323 without connect()", udp4_sendto("127.0.0.1", 2323))
    tryit("TCP6 connect [::ffff:127.0.0.1]:2323 (v4-mapped)", tcp6_mapped("127.0.0.1", 2323))
PY

# precreate.py: README 4.3 experiment (socket created before vs after joining)
cat > precreate.py <<'PY'
import os, socket
CG = "/sys/fs/cgroup/w14-sock-enforce/cgroup.procs"
before = socket.socket()                       # created while still outside
open(CG, "w").write(str(os.getpid()))          # join the test cgroup
after = socket.socket()                        # created inside the cgroup
print("now in:", open("/proc/self/cgroup").read().strip())
for label, s in (("socket created BEFORE joining cgroup", before),
                 ("socket created AFTER joining cgroup", after)):
    try: s.connect(("127.0.0.1", 2323)); print(f"  {label:<40} -> connected")
    except OSError as e: print(f"  {label:<40} -> {e}")
PY

# Terminal 1: loopback listeners on 2323 and 8080 (README step 2)
python3 -c "
import socket,time
ls=[]
for p in (2323,8080):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('127.0.0.1',p)); s.listen(16); ls.append(s)
time.sleep(600)" &
LST=$!
sleep 1

bg "$LOG" sudo ./bin/sock-enforce
sleep 3

shot_begin 1-client "Terminal 3 — client.py นอก/ใน cgroup w14-sock-enforce"
note "baseline: client OUTSIDE the test cgroup"
run python3 client.py
note "client INSIDE /sys/fs/cgroup/w14-sock-enforce"
run "sudo sh -c 'echo \$\$ > /sys/fs/cgroup/w14-sock-enforce/cgroup.procs && exec sudo -u $USER python3 client.py --in-cgroup --bypass'"
run sudo bpftool cgroup show /sys/fs/cgroup/w14-sock-enforce
run "sudo bpftool cgroup show /sys/fs/cgroup | wc -l"
shot_end

# 4.3 needs port 2323 WITHOUT a listener (to tell ECONNREFUSED from EPERM)
kill "$LST" 2>/dev/null; wait "$LST" 2>/dev/null; LST=""
sleep 0.5
shot_begin 3-precreate "Terminal 3 — socket ที่สร้างก่อนเข้า cgroup (ไม่มี listener ที่ 2323)"
run "ss -ltn 'sport = :2323'"
run sudo python3 precreate.py
shot_end
sleep 1

bg_stop '^./bin/sock-enforce'
shot_begin 2-enforcer "Terminal 2 — sudo ./bin/sock-enforce"
prompt_only sudo ./bin/sock-enforce
tr -d '\r\000' < "$LOG" | sed 's/^\^@//' >> "$SHOT_FILE"
note "DENY บรรทัดสุดท้าย (pid ต่างออกไป) มาจากการทดลองเสริม 4.3 precreate.py"
run 'ls -d /sys/fs/cgroup/w14-* 2>/dev/null || echo "clean"'
shot_end

shot_begin 4-root-guard "Terminal 2 — ด่านป้องกัน root cgroup"
run 'sudo ./bin/sock-enforce -cgroup /sys/fs/cgroup; echo "exit=$?"'
shot_end
