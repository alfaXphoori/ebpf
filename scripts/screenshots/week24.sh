#!/usr/bin/env bash
# Week 24: kfuncs + BPF arena — real run (Makefile vendors + patches cilium/ebpf)
source "$(dirname "$0")/lib.sh"
lab_init phase11-modern-ebpf-extensibility/week24-kfuncs-arena
make -s all >/dev/null 2>&1

cleanup() { sudo rm -f /sys/fs/bpf/w24_leak; }
trap cleanup EXIT
cleanup
# hide the (harmless) clang warnings about anonymous members in the shared vmlinux.h
NOWARN="grep -v -e 'vmlinux.h' -e '^ *[0-9]* |' -e '^ *|' -e 'warnings generated' -e 'In file included'"

shot_begin 1-make-test "Terminal — make test (kfunc + verifier + arena, BPF_PROG_TEST_RUN)"
run "make test 2>&1 | $NOWARN | grep -v -e '^Compiled' -e '^Stripped' -e '^Wrote'"
shot_end

shot_begin 2-kfunc-arena "Terminal — sudo ./bin/kfunc-arena"
run sudo ./bin/kfunc-arena
shot_end

shot_begin 3-verifier-log "Terminal — verifier log เต็มของ leak_task"
run "go test -exec sudo -run 'TestBrokenProgramsRejected/leak_task' -v ."
note "go test แสดงแค่ PASS (= ถูกปฏิเสธจริง) ถ้าอยากเห็น log เต็มโดยไม่ต้องแก้โค้ด ให้ bpftool โหลด object ตรง ๆ (libbpf พิมพ์ log ของโปรแกรมแรกที่ล้ม = leak_task)"
run sudo bpftool prog load broken_bpfel.o /sys/fs/bpf/w24_leak
shot_end

shot_begin 4-kfunc-discovery "Terminal — ค้นหา kfunc บนเครื่อง (หัวข้อ 1.5)"
run "bpftool btf dump file /sys/kernel/btf/vmlinux | grep -c \"DECL_TAG 'bpf_kfunc'\""
ID=$(bpftool btf dump file /sys/kernel/btf/vmlinux | awk '$2=="FUNC" && $3=="'"'"'bpf_task_from_pid'"'"'"{print substr($1,2,length($1)-2)}')
run "bpftool btf dump file /sys/kernel/btf/vmlinux | grep -E \"FUNC 'bpf_task_from_pid'|type_id=$ID \""
run "bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -E '^extern .*\\bbpf_(task_from_pid|task_release|task_acquire|cpumask_create|cpumask_copy|arena_alloc_pages)\\('"
show 'for m in /sys/kernel/btf/*; do n=$(bpftool btf dump file $m 2>/dev/null | grep -c "DECL_TAG '"'"'bpf_kfunc'"'"'"); [ "$n" -gt 0 ] && echo "$(basename $m) $n"; done' \
     'for m in /sys/kernel/btf/*; do n=$(bpftool btf dump file $m 2>/dev/null | grep -c "DECL_TAG '"'"'bpf_kfunc'"'"'"); [ "$n" -gt 0 ] && echo "$(basename $m) $n"; done; true'
shot_end

shot_begin 5-addr-space-cast "Terminal — addr_space_cast ใน arena_bpfel.o"
run "llvm-objdump -S --no-show-raw-insn arena_bpfel.o | grep -B2 -A2 addr_space_cast | head -30"
run "llvm-objdump -d --no-show-raw-insn arena_bpfel.o | grep -c addr_space_cast"
shot_end
