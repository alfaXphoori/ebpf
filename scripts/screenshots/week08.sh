#!/usr/bin/env bash
# Week 08: XDP L4 load balancer + TC reverse NAT — real run in w08-* netns
source "$(dirname "$0")/lib.sh"
lab_init phase04-high-speed-networking/week08-tc-loadbalancer
make -s all >/dev/null 2>&1 || { echo "build failed"; exit 1; }

NSES="w08-client w08-lb w08-b0 w08-b1 w08-sw"
cleanup() {
    for ns in $NSES; do
        sudo ip netns pids $ns 2>/dev/null | xargs -r sudo kill 2>/dev/null
        sudo ip netns del $ns 2>/dev/null
    done
    rm -rf /tmp/w08-www-b0 /tmp/w08-www-b1
}
trap cleanup EXIT
cleanup

shot_begin 1-unit-tests "Terminal — make test (BPF_PROG_TEST_RUN)"
run 'make test | grep -vE "^(Compiled|Stripped|Wrote) "'
shot_end

# --- README step 3: client / lb / b0 / b1 behind a bridge in w08-sw ---
sudo ip netns add w08-sw
sudo ip netns exec w08-sw ip link add br0 type bridge
sudo ip netns exec w08-sw ip link set br0 up
add_node() {
    local ns=$1 mac=$2
    sudo ip netns add "$ns"
    sudo ip link add eth0 netns "$ns" type veth peer name "p-${ns#w08-}" netns w08-sw
    sudo ip netns exec w08-sw ip link set "p-${ns#w08-}" master br0 up
    sudo ip netns exec "$ns" ip link set lo up
    sudo ip netns exec "$ns" ip link set eth0 address "$mac"
    sudo ip netns exec "$ns" ip link set eth0 up
    sudo ip netns exec "$ns" ethtool -K eth0 tx off >/dev/null
}
add_node w08-client 02:00:00:00:10:00
add_node w08-lb     02:00:00:00:01:00
add_node w08-b0     02:00:00:00:02:00
add_node w08-b1     02:00:00:00:03:00
sudo ip netns exec w08-client ip addr add 10.10.2.10/24 dev eth0
sudo ip netns exec w08-client ip route add 10.10.1.0/24 via 10.10.2.1
sudo ip netns exec w08-lb ip addr add 10.10.1.1/24 dev eth0
sudo ip netns exec w08-lb ip addr add 10.10.2.1/24 dev eth0
sudo ip netns exec w08-lb sysctl -qw net.ipv4.ip_forward=1
sudo ip netns exec w08-lb sysctl -qw net.ipv4.conf.all.send_redirects=0
sudo ip netns exec w08-lb sysctl -qw net.ipv4.conf.eth0.send_redirects=0
for i in 0 1; do
    sudo ip netns exec w08-b$i ip addr add 10.10.1.$((i+2))/24 dev eth0
    sudo ip netns exec w08-b$i ip route add 10.10.2.0/24 via 10.10.1.1
done
# --- step 4: HTTP backends ---
for i in 0 1; do
    mkdir -p /tmp/w08-www-b$i && echo "Hello from Backend $i" > /tmp/w08-www-b$i/index.html
    sudo ip netns exec w08-b$i python3 -m http.server 80 --bind 10.10.1.$((i+2)) \
        --directory /tmp/w08-www-b$i >/dev/null 2>&1 &
done
sleep 1.5

# --- step 5: LB ---
LBCMD="./bin/xdp-tc-lb -iface eth0 -xdp-mode generic -vip 10.10.1.100 -backend0-ip 10.10.1.2 -backend0-mac 02:00:00:00:02:00 -backend1-ip 10.10.1.3 -backend1-mac 02:00:00:00:03:00"
LOG=$(mktemp)
bg "$LOG" sudo ip netns exec w08-lb $LBCMD
sleep 2

shot_begin 2-client-curl "Terminal 2 — curl ไปยัง VIP จาก client (w08-client) และตรวจจุดแนบ"
run 'for i in {1..10}; do sudo ip netns exec w08-client curl -s --connect-timeout 2 -m 3 http://10.10.1.100/ || echo "request $i FAILED"; done'
run sudo ip netns exec w08-lb ip link show eth0
run sudo ip netns exec w08-lb bpftool net show dev eth0
run sudo bpftool map dump name lb_stats
shot_end
sleep 2.5

bg_stop '^./bin/xdp-tc-lb'
shot_begin 3-lb-dashboard "Terminal 1 — sudo ip netns exec w08-lb ./bin/xdp-tc-lb (หลัง Ctrl+C)"
prompt_only sudo ip netns exec w08-lb $LBCMD
append_head "$LOG" 10
note "... (dashboard redraws every 2s; last frame shown) ..."
append_last_frame "$LOG"
shot_end
rm -f "$LOG"
