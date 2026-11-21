#!/usr/bin/env bash
# Week 12: Smart IPS capstone — real run on veth in netns w12atk / w12ips.
# REST API + Prometheus listen on :2112 inside w12ips only (README step 4).
source "$(dirname "$0")/lib.sh"
lab_init phase06-production-capstone/week12-capstone-ips
make -s all >/dev/null 2>&1 || { echo "build failed"; exit 1; }

PAT='^./bin/ips-agent -iface w12b'
cleanup() {
    sudo pkill -INT -f "$PAT" 2>/dev/null
    sudo ip netns del w12atk 2>/dev/null; sudo ip netns del w12ips 2>/dev/null
}
trap cleanup EXIT
cleanup

shot_begin 1-unit-tests "Terminal — make test (BPF_PROG_TEST_RUN)"
run 'make test | grep -vE "^(Compiled|Stripped|Wrote) "'
shot_end

sudo ip netns add w12atk; sudo ip netns add w12ips
sudo ip link add w12a type veth peer name w12b
sudo ip link set w12a netns w12atk; sudo ip link set w12b netns w12ips
sudo ip -n w12atk addr add 10.212.0.1/24 dev w12a
sudo ip -n w12ips addr add 10.212.0.2/24 dev w12b
sudo ip -n w12atk link set w12a up; sudo ip -n w12ips link set w12b up
sudo ip -n w12atk link set lo up;   sudo ip -n w12ips link set lo up

AGENT="./bin/ips-agent -iface w12b -ban-ttl 6s -syn-limit 10 -icmp-limit 5 -http-port :2112"
agent_log() { sed 's/\^@//' "$1" | tr -d '\r' >> "$SHOT_FILE"; }

# ---------------- 4.2 auto-ban mode ----------------
LOG=$(mktemp)
bg "$LOG" sudo ip netns exec w12ips $AGENT
sleep 2
shot_begin 2-autoban-attack "Terminal 2 — Ping Flood / SYN Burst จาก w12atk และตรวจผ่าน REST API + /metrics"
run sudo ip netns exec w12atk ping -f -c 200 -w 3 10.212.0.2
run sudo ip netns exec w12atk bash -c "'for i in \$(seq 30); do timeout 0.2 bash -c \"echo > /dev/tcp/10.212.0.2/8080\" 2>/dev/null; done; true'"
run 'sudo ip netns exec w12ips curl -s localhost:2112/api/blacklist; echo'
run sleep 7
run 'sudo ip netns exec w12ips curl -s localhost:2112/api/blacklist; echo'
run "sudo ip netns exec w12ips curl -s -X POST -d '{\"ip\":\"203.0.113.99\"}' localhost:2112/api/blacklist; echo"
run 'sudo ip netns exec w12ips curl -s localhost:2112/metrics | grep "^ips_"'
shot_end
bg_stop "$PAT"
shot_begin 3-autoban-agent "Terminal 1 — sudo ip netns exec w12ips ./bin/ips-agent (Auto-Ban mode, หลัง Ctrl+C)"
prompt_only sudo ip netns exec w12ips $AGENT
agent_log "$LOG"
shot_end
rm -f "$LOG"

# ---------------- 4.3 rate-limit-only mode ----------------
LOG=$(mktemp)
bg "$LOG" sudo ip netns exec w12ips $AGENT -autoban=false
sleep 2
shot_begin 4-ratelimit-only "Rate-limit-only mode (-autoban=false): ping 100 pps จาก w12atk + log ของ agent"
run sudo ip netns exec w12atk ping -q -i 0.01 -c 300 10.212.0.2
run 'sudo ip netns exec w12ips curl -s localhost:2112/api/blacklist; echo'
run 'sudo ip netns exec w12ips curl -s localhost:2112/metrics | grep "^ips_"'
bg_stop "$PAT"
note "Terminal 1 (agent) หลังกด Ctrl+C:"
prompt_only sudo ip netns exec w12ips $AGENT -autoban=false
agent_log "$LOG"
shot_end
rm -f "$LOG"
