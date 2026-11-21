#!/usr/bin/env bash
# Week 20: TCP sockops + SOCKHASH redirect — real run inside the lab cgroup
# /sys/fs/cgroup/w20-sockops-lab (localhost traffic by design of the lab)
source "$(dirname "$0")/lib.sh"
lab_init phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass
make -s all >/dev/null 2>&1

CG=/sys/fs/cgroup/w20-sockops-lab
TMPD=$(mktemp -d)
chmod 755 "$TMPD"
cleanup() {
    sudo pkill -INT -f '^./bin/sockops-accelerator' 2>/dev/null
    sleep 1
    # kill anything we left in the lab cgroup, then remove it
    if [ -d "$CG" ]; then
        for p in $(cat "$CG/cgroup.procs" 2>/dev/null); do sudo kill "$p" 2>/dev/null; done
        sleep 0.5; sudo rmdir "$CG" 2>/dev/null
    fi
    rm -rf "$TMPD"
}
trap cleanup EXIT
cleanup; TMPD=$(mktemp -d); chmod 755 "$TMPD"

# resume an existing transcript without truncating it
shot_resume() { SHOT_FILE="$SHOT_RAW/$LAB_WEEK-$1.ansi"; }
# incg "<cmd>": run a command as root inside the lab cgroup (like the README's
# `sudo bash; echo $$ > $CG/cgroup.procs`)
incg() { echo "sudo bash -c 'echo \$\$ > $CG/cgroup.procs; $1'"; }

# --- 1. make test --------------------------------------------------------------
shot_begin 1-make-test "Terminal — make test (load/attach + end-to-end redirect)"
run make test
shot_end

sudo mkdir -p "$CG"

# tcpdump demo: capture on lo while nc (inside the cgroup) sends 14 bytes
tcpdump_demo() {
    cat > "$TMPD/td.sh" <<SH
tcpdump -i lo -nn -q -l "tcp port 18081" 2>/dev/null &
TD=\$!; sleep 1
echo \$\$ > $CG/cgroup.procs
nc -l 127.0.0.1 18081 > /dev/null &
sleep 0.3
echo hello-sockmap | nc -q 1 127.0.0.1 18081
sleep 1.5; kill \$TD; wait \$TD 2>/dev/null
SH
    show 'sudo tcpdump -i lo -nn -q "tcp port 18081" &  echo hello-sockmap | nc -q 1 127.0.0.1 18081   # nc อยู่ใน cgroup' \
        "sudo bash $TMPD/td.sh"
}

bench() {
    show "./bin/tcpbench -mode throughput -bytes 268435456 -verify=true" \
        "$(incg './bin/tcpbench -mode throughput -bytes 268435456 -verify=true')"
    for i in 1 2 3; do
        show "./bin/tcpbench -bytes 2147483648 -verify=false -iters 20000   # รอบที่ $i" \
            "$(incg './bin/tcpbench -bytes 2147483648 -verify=false -iters 20000')"
    done
    show "iperf3 -s -1 -4 -B 127.0.0.1 -p 15201 & sleep 0.5; iperf3 -4 -c 127.0.0.1 -p 15201 -t 3 | grep -E 'sender|receiver'" \
        "$(incg 'iperf3 -s -1 -4 -B 127.0.0.1 -p 15201 >/dev/null & sleep 0.5; iperf3 -4 -c 127.0.0.1 -p 15201 -t 3 | grep -E "sender|receiver"')"
}

# --- baseline (no eBPF attached, same cgroup) ----------------------------------
shot_begin 4-tcpdump-lo "Terminal 2 — tcpdump -i lo: baseline vs accelerated"
note "== baseline: ยังไม่ได้เปิด Agent =="
tcpdump_demo
shot_end

shot_begin 5-benchmark "Terminal 2 — tcpbench/iperf3 ใน cgroup w20-sockops-lab: baseline vs accelerated"
note "== baseline: cgroup เดียวกัน ไม่มี eBPF =="
bench
shot_end

# --- start the agent ---------------------------------------------------------------
LOG="$TMPD/agent.log"
bg "$LOG" sudo ./bin/sockops-accelerator -cgroup "$CG"
sleep 2

shot_begin 2-nc-bpftool "Terminal 2 — nc ใน cgroup + bpftool ขณะ connection เปิดอยู่"
prompt_only "sudo bash"
prompt_only "echo \$\$ > $CG/cgroup.procs"
sudo bash -c "echo \$\$ > $CG/cgroup.procs; exec nc -l 127.0.0.1 18080 > $TMPD/recv.txt" &
prompt_only "nc -l 127.0.0.1 18080 > /tmp/recv.txt &"
sleep 0.5
sudo bash -c "echo \$\$ > $CG/cgroup.procs; (echo 'Accelerated TCP Message via BPF SOCKHASH'; sleep 4) | nc -q 1 127.0.0.1 18080" &
CLI=$!
prompt_only '(echo "Accelerated TCP Message via BPF SOCKHASH"; sleep 4) | nc -q 1 127.0.0.1 18080 &'
sleep 1
run sudo bpftool map dump name sock_hash
run sudo bpftool map dump name bypass_stats
wait $CLI 2>/dev/null; sleep 0.5
show "cat /tmp/recv.txt" "cat $TMPD/recv.txt"
shot_end

shot_resume 4-tcpdump-lo
note "== accelerated: Agent ทำงานอยู่ =="
tcpdump_demo
shot_end

shot_resume 5-benchmark
printf "\n" >> "$SHOT_FILE"
note "== accelerated: Agent ทำงานอยู่ (SOCKHASH redirect) =="
bench
shot_end
sleep 2.5

bg_stop '^./bin/sockops-accelerator'
shot_begin 3-agent-dashboard "Terminal 1 — sudo ./bin/sockops-accelerator (ระหว่างขั้นตอนที่ 3-5)"
prompt_only sudo ./bin/sockops-accelerator -cgroup $CG
append "$LOG"
shot_end
