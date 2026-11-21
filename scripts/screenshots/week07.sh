#!/usr/bin/env bash
# Week 07: XDP firewall — real run in isolated netns w07-client / w07-server
source "$(dirname "$0")/lib.sh"
lab_init phase04-high-speed-networking/week07-xdp-parsing
make -s all >/dev/null 2>&1

cleanup() { sudo ip netns del w07-client 2>/dev/null; sudo ip netns del w07-server 2>/dev/null; }
cleanup

shot_begin 1-unit-tests "Terminal — make test (BPF_PROG_TEST_RUN)"
run make test
shot_end

sudo ip netns add w07-client; sudo ip netns add w07-server
sudo ip link add w07-c type veth peer name w07-s
sudo ip link set w07-c netns w07-client; sudo ip link set w07-s netns w07-server
sudo ip netns exec w07-client ip addr add 10.10.1.10/24 dev w07-c
sudo ip netns exec w07-client ip addr add 10.10.1.11/24 dev w07-c
sudo ip netns exec w07-server ip addr add 10.10.1.20/24 dev w07-s
for ns in w07-client w07-server; do sudo ip netns exec $ns ip link set lo up; done
sudo ip netns exec w07-client ip link set w07-c up
sudo ip netns exec w07-server ip link set w07-s up

LOG=$(mktemp)
bg "$LOG" sudo ip netns exec w07-server ./bin/xdp-firewall -iface w07-s -block-ip 10.10.1.10
sleep 2

shot_begin 2-client-ping "Terminal 2 — ping จาก client (w07-client)"
run sudo ip netns exec w07-client ping -c 5 -W 1 -I 10.10.1.10 10.10.1.20
run sudo ip netns exec w07-client ping -c 3 -W 1 -I 10.10.1.11 10.10.1.20
run sudo ip netns exec w07-server ip link show w07-s
run sudo bpftool map dump name blocked_ips
shot_end
sleep 2.5

bg_stop '^./bin/xdp-firewall'
shot_begin 3-firewall-dashboard "Terminal 1 — sudo ip netns exec w07-server ./bin/xdp-firewall"
prompt_only sudo ip netns exec w07-server ./bin/xdp-firewall -iface w07-s -block-ip 10.10.1.10
append_last_frame "$LOG"
shot_end
rm -f "$LOG"
cleanup
