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
    rm -f "$LOG"
    sleep 1; sudo rmdir /sys/fs/cgroup/w14-sock-enforce 2>/dev/null
}
trap cleanup EXIT



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
