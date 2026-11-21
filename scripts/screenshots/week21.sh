#!/usr/bin/env bash
# Week 21: AF_XDP pipeline — real run in isolated netns w21-rx / w21-tx (veth)
source "$(dirname "$0")/lib.sh"
lab_init phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect
make -s all >/dev/null 2>&1

cleanup() {
    sudo pkill -INT -f '^./bin/af-xdp-pipeline -iface w21-xsk0' 2>/dev/null
    sudo ip netns del w21-rx 2>/dev/null; sudo ip netns del w21-tx 2>/dev/null
}
trap cleanup EXIT
cleanup

shot_begin 1-make-test "Terminal — make test (BPF_PROG_TEST_RUN)"
run make test
shot_end

sudo ip netns add w21-rx; sudo ip netns add w21-tx
sudo ip link add w21-xsk0 type veth peer name w21-peer0
sudo ip link set w21-xsk0 netns w21-rx
sudo ip link set w21-peer0 netns w21-tx
sudo ip -n w21-rx addr add 10.21.0.1/24 dev w21-xsk0
sudo ip -n w21-tx addr add 10.21.0.2/24 dev w21-peer0
sudo ip -n w21-rx link set lo up; sudo ip -n w21-rx link set w21-xsk0 up
sudo ip -n w21-tx link set lo up; sudo ip -n w21-tx link set w21-peer0 up
sleep 1

shot_begin 4-zerocopy "Terminal 1 — ขอ Zero-Copy บน veth (ขั้นตอนที่ 3)"
run sudo ip netns exec w21-rx ./bin/af-xdp-pipeline -iface w21-xsk0 -zerocopy
shot_end

LOG=$(mktemp)
bg "$LOG" sudo ip netns exec w21-rx ./bin/af-xdp-pipeline -iface w21-xsk0
sleep 2

shot_begin 2-status-traffic "Terminal 2 — ตรวจสถานะ + ส่งทราฟฟิกจาก w21-tx"
run sudo ip -n w21-rx link show w21-xsk0
run sudo ip netns exec w21-rx bpftool net show dev w21-xsk0
run sudo ip netns exec w21-rx ss --xdp -e
run sudo ip netns exec w21-tx ping -c 3 -i 0.2 10.21.0.1
show "for i in 1 2 3 4 5; do sudo ip netns exec w21-tx bash -c \"echo -n 'hello-af-xdp-\$i' > /dev/udp/10.21.0.1/9999\"; done" \
     "for i in 1 2 3 4 5; do sudo ip netns exec w21-tx bash -c \"echo -n 'hello-af-xdp-\$i' > /dev/udp/10.21.0.1/9999\"; done"
PY='import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
t=time.time()
for i in range(20000): s.sendto(b"bulk-%d"%i,("10.21.0.1",9999))
print("sent 20000 in %.3fs"%(time.time()-t))'
show "sudo ip netns exec w21-tx python3 -c '...ส่ง UDP 20000 แพ็กเก็ตไป 10.21.0.1:9999...'" \
     "sudo ip netns exec w21-tx python3 -c '$PY'"
run sudo ip netns exec w21-rx nstat -az UdpInDatagrams UdpNoPorts
shot_end
sleep 2.5

bg_stop '^./bin/af-xdp-pipeline -iface w21-xsk0'
shot_begin 3-pipeline-output "Terminal 1 — sudo ip netns exec w21-rx ./bin/af-xdp-pipeline -iface w21-xsk0"
prompt_only sudo ip netns exec w21-rx ./bin/af-xdp-pipeline -iface w21-xsk0
append "$LOG"
shot_end
rm -f "$LOG"
