#!/usr/bin/env bash
# Week 02: Linux bridge in w02-sw + 3 namespaces, FDB, softirq/strace/perf trace
source "$(dirname "$0")/lib.sh"
# stdin at EOF makes `script` inject a NUL that sudo's pty echoes as "^@";
# give every `run` a stdin that never ends (local workaround, not in lib.sh)
exec 0< <(exec sleep 3600); STDIN_PID=$!
lab_init phase01-network-foundation/week02-linux-net-stack

cleanup_lab() { sudo ./bridge_router_lab.sh clean >/dev/null 2>&1; }
cleanup() { kill $STDIN_PID 2>/dev/null; cleanup_lab; }
trap cleanup EXIT
cleanup_lab

shot_begin 1-setup "Terminal — sudo ./bridge_router_lab.sh setup"
run sudo ./bridge_router_lab.sh setup
shot_end

shot_begin 2-test "Terminal — sudo ./bridge_router_lab.sh test"
run sudo ./bridge_router_lab.sh test
shot_end

shot_begin 3-fdb "Terminal — ตรวจตาราง FDB ของ br0"
run "sudo ip netns exec w02-sw bridge fdb show br br0 | grep -v permanent"
for i in 1 2 3; do
    run sudo ip netns exec w02-ns$i ip -br link show veth-ns$i
done
shot_end

shot_begin 4-trace "Terminal — sudo ./bridge_router_lab.sh trace"
run sudo ./bridge_router_lab.sh trace
shot_end
