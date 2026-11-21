#!/usr/bin/env bash
# Week 01: netns + veth + raw socket sniffer — real run in w01-ns1 / w01-ns2
source "$(dirname "$0")/lib.sh"
# stdin at EOF makes `script` inject a NUL that sudo's pty echoes as "^@";
# give every `run` a stdin that never ends (local workaround, not in lib.sh)
exec 0< <(exec sleep 3600); STDIN_PID=$!
lab_init phase01-network-foundation/week01-packet-netns

cleanup_lab() {
    sudo pkill -INT -f '^python3 raw_sniffer.py --interface w01-veth2' 2>/dev/null
    sudo pkill -f '^nc -l 8080$' 2>/dev/null
    sudo ./lab_netns.sh clean >/dev/null 2>&1
}
cleanup() { kill $STDIN_PID 2>/dev/null; cleanup_lab; }
trap cleanup EXIT
cleanup_lab

shot_begin 1-setup "Terminal — sudo ./lab_netns.sh setup"
run sudo ./lab_netns.sh setup
shot_end

shot_begin 2-connectivity "Terminal — sudo ./lab_netns.sh test"
run sudo ./lab_netns.sh test
shot_end

# --- 4.2: sniffer in w01-ns2 (Terminal 1), traffic from w01-ns1 (Terminal 2)
LOG=$(mktemp)
SRVLOG=$(mktemp)
bg "$LOG" sudo ip netns exec w01-ns2 python3 raw_sniffer.py --interface w01-veth2 --verbose
SNIFF_PID=$BG_PID
sleep 1.5
setsid sudo ip netns exec w01-ns2 nc -l 8080 > "$SRVLOG" 2>&1 < /dev/null &
sleep 0.5

shot_begin 3-traffic "Terminal 2 — ส่งทราฟฟิกจาก w01-ns1"
note "Terminal 3 รัน: sudo ip netns exec w01-ns2 nc -l 8080  (รอรับ TCP)"
run sudo ip netns exec w01-ns1 ip neigh flush dev w01-veth1
run sudo ip netns exec w01-ns2 ip neigh flush dev w01-veth2
run sudo ip netns exec w01-ns1 ping -c 1 10.10.1.2
run "sudo ip netns exec w01-ns1 bash -c \"echo 'Hello eBPF Network!' | nc -u -w1 10.10.1.2 9999\""
run "sudo ip netns exec w01-ns1 bash -c \"echo hi | nc -N -w1 10.10.1.2 8080\""
shot_end
sleep 1.5

BG_PID=$SNIFF_PID
bg_stop '^python3 raw_sniffer.py --interface w01-veth2'
shot_begin 4-sniffer "Terminal 1 — raw_sniffer.py ใน w01-ns2"
prompt_only sudo ip netns exec w01-ns2 python3 raw_sniffer.py --interface w01-veth2 --verbose
append "$LOG"
shot_end
rm -f "$LOG" "$SRVLOG"
