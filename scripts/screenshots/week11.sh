#!/usr/bin/env bash
# Week 11: XDP per-CPU metrics + Prometheus exporter — real run on veth in
# isolated netns w11cli / w11srv (README step 3, recommended variant)
source "$(dirname "$0")/lib.sh"
lab_init phase06-production-capstone/week11-verifier-prometheus
make -s all >/dev/null 2>&1 || { echo "build failed"; exit 1; }

cleanup() {
    sudo pkill -INT -f '^./bin/metrics_exporter -iface w11b' 2>/dev/null
    sudo ip netns del w11cli 2>/dev/null; sudo ip netns del w11srv 2>/dev/null
}
trap cleanup EXIT
cleanup

shot_begin 1-unit-tests "Terminal — make test (BPF_PROG_TEST_RUN)"
run 'make test | grep -vE "^(Compiled|Stripped|Wrote) "'
shot_end

sudo ip netns add w11cli; sudo ip netns add w11srv
sudo ip link add w11a type veth peer name w11b
sudo ip link set w11a netns w11cli; sudo ip link set w11b netns w11srv
sudo ip -n w11cli addr add 10.211.0.1/24 dev w11a
sudo ip -n w11srv addr add 10.211.0.2/24 dev w11b
sudo ip -n w11cli link set w11a up; sudo ip -n w11srv link set w11b up
sudo ip -n w11cli link set lo up;   sudo ip -n w11srv link set lo up

LOG=$(mktemp)
bg "$LOG" sudo ip netns exec w11srv ./bin/metrics_exporter -iface w11b -addr :2112
sleep 2

shot_begin 2-metrics "Terminal 2 — สร้างทราฟฟิกจาก w11cli และดึง /metrics"
run sudo ip netns exec w11cli ping -c 5 -q 10.211.0.2
run sudo ip netns exec w11cli curl -s -o /dev/null -w "'curl http_code=%{http_code}\n'" http://10.211.0.2:2112/
run 'echo "eBPF test" | sudo ip netns exec w11cli nc -u -w1 10.211.0.2 9999'
run 'sudo ip netns exec w11cli curl -s http://10.211.0.2:2112/metrics | grep ebpf_xdp'
shot_end
sleep 1

bg_stop '^./bin/metrics_exporter -iface w11b'
shot_begin 3-exporter-log "Terminal 1 — sudo ip netns exec w11srv ./bin/metrics_exporter (หลัง Ctrl+C)"
prompt_only sudo ip netns exec w11srv ./bin/metrics_exporter -iface w11b -addr :2112
sed 's/\^@//' "$LOG" | tr -d '\r' >> "$SHOT_FILE"
shot_end
rm -f "$LOG"
