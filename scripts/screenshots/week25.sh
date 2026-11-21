#!/usr/bin/env bash
# Week 25: struct_ops + sched_ext — real runs, SCX_OPS_SWITCH_PARTIAL only
# (only our own SCHED_EXT workload is affected), short durations, and
# /sys/kernel/sched_ext/state is verified to be "disabled" before/after.
source "$(dirname "$0")/lib.sh"
lab_init phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext
make -s all >/dev/null 2>&1

STATE=/sys/kernel/sched_ext/state
grep -q 'SCX_OPS_SWITCH_PARTIAL' scx_w25.c || { echo "scx_w25.c is not SWITCH_PARTIAL — refusing"; exit 1; }
cleanup() {
    sudo pkill -INT -f '^./bin/scx-w25' 2>/dev/null
    sleep 1
    sudo pkill -KILL -f '^./bin/scx-w25' 2>/dev/null
    echo "sched_ext state at exit: $(cat $STATE)" >&2
}
trap cleanup EXIT
need_disabled() {
    local s; s=$(cat $STATE)
    if [ "$s" != disabled ]; then echo "sched_ext state is '$s' (expected disabled) — stopping" >&2; exit 1; fi
}
need_disabled
NOWARN="grep -v -e 'vmlinux.h' -e '^ *[0-9]* |' -e '^ *|' -e 'warnings generated' -e 'In file included' -e '^Compiled' -e '^Stripped' -e '^Wrote'"

shot_begin 1-make-test "Terminal — make test (attach จริงในโหมด SWITCH_PARTIAL แล้ว detach)"
run "make test 2>&1 | $NOWARN"
shot_end
need_disabled

shot_begin 2-fifo-run "Terminal — sudo ./bin/scx-w25 -duration 5s (FIFO)"
run sudo ./bin/scx-w25 -duration 5s
run "sudo dmesg | grep 'sched_ext:' | tail -n 2"
shot_end
need_disabled

LOG=$(mktemp)
bg "$LOG" sudo ./bin/scx-w25 -duration 6s
sleep 2
shot_begin 3-bpftool-view "Terminal 2 — มุมมองจาก bpftool ระหว่าง scheduler ทำงาน"
run make state
run sudo bpftool struct_ops show
run "sudo bpftool link show | grep struct_ops"
run "sudo bpftool prog show | grep -A1 struct_ops | head -n 8"
run "./bin/scx-w25 ext-run sh -c 'grep -E \"^(policy|ext)\" /proc/\$\$/sched'"
shot_end
wait "$BG_PID" 2>/dev/null
rm -f "$LOG"
need_disabled

shot_begin 4-demo-nice "Terminal — make demo-nice (FIFO vs vtime, spinner 4 ตัวบน CPU 3)"
run make demo-nice
shot_end
need_disabled

shot_begin 5-demo-stall "Terminal — make demo-stall (watchdog eject)"
run make demo-stall
shot_end
need_disabled

shot_begin 6-demo-error "Terminal — make demo-error (scx_bpf_error eject) + ยืนยันว่าเครื่องกลับสู่สภาพเดิม"
run make demo-error
run cat /sys/kernel/sched_ext/state
run sudo bpftool struct_ops show
# under `script -c` the wrapper shell's own cmdline contains "ext-run", so the
# real pattern uses [e] to avoid matching itself (same meaning for a student)
show "pgrep -af 'ext-run' || echo 'no workload left'" "pgrep -af '[e]xt-run' || echo 'no workload left'"
shot_end
need_disabled
