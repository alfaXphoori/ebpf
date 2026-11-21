#!/usr/bin/env bash
# Week 23: BPF iterator (iter/task) vs procfs walk — real run
source "$(dirname "$0")/lib.sh"
lab_init phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators
make -s generate >/dev/null 2>&1; make -s build >/dev/null 2>&1

OUT=/tmp/w23-task-iter.txt
cleanup() { sudo rm -f /sys/fs/bpf/w23_tasks; rm -f "$OUT"; }
trap cleanup EXIT
cleanup

shot_begin 1-make-test "Terminal — make test (1 แถวต่อ 1 โปรเซส)"
run "make test 2>&1 | grep -v -e 'vmlinux.h' -e '^ *[0-9]* |' -e '^ *|' -e 'warnings generated' -e 'In file included'"
shot_end

shot_begin 2-task-iter "Terminal — sudo ./bin/task-iter (ตัดแถวกลางออก)"
run "sudo ./bin/task-iter > $OUT; head -n 15 $OUT; echo ...; tail -n 6 $OUT"
shot_end

shot_begin 3-quiet-strace "Terminal — รันซ้ำ 3 ครั้ง (-quiet) และนับ syscall ด้วย strace -c"
run "for i in 1 2 3; do sudo ./bin/task-iter -quiet; done"
run "sudo strace -f -c -e trace=bpf,openat,read ./bin/task-iter -quiet -runs 1"
shot_end

shot_begin 4-ps-pin "Terminal — เทียบกับ ps และ pin iterator แล้วอ่านด้วย cat (ขั้นตอนที่ 4-5)"
run "sudo ./bin/task-iter | grep -w systemd | head -3"
run ps -o pid,uid,nlwp,vsz,comm -p 1
run sudo bpftool iter pin bpf_bpfel.o /sys/fs/bpf/w23_tasks
run sudo head -4 /sys/fs/bpf/w23_tasks
run sudo head -4 /sys/fs/bpf/w23_tasks
run sudo rm /sys/fs/bpf/w23_tasks
shot_end
