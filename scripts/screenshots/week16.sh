#!/usr/bin/env bash
# Week 16: eBPF integrity auditor — preloaded pinned prog (inventory) + per-CPU loads
# Test programs are the Week 13/14 .o files (built, not modified). Pins: /sys/fs/bpf/w16_*
source "$(dirname "$0")/lib.sh"
lab_init phase07-advanced-security-observability/week16-ebpf-integrity-audit
PHASE="$SHOT_ROOT/phase07-advanced-security-observability"
make -s -C "$PHASE/week13-kfree-skb-dropwatch" all >/dev/null 2>&1
make -s -C "$PHASE/week14-cgroup-sock-addr" all >/dev/null 2>&1
make -s all >/dev/null 2>&1

LOG=/tmp/w16-audit.log; LF=/tmp/w16-audit-fentry.log; LR=/tmp/w16-audit-raw.log
cleanup() {
    sudo pkill -INT -f '^./bin/bpf-audit' 2>/dev/null
    sudo sh -c 'rm -f /sys/fs/bpf/w16_*'
    rm -f "$LOG" "$LF" "$LR"
}
trap cleanup EXIT
cleanup

# append_audit <log>: the auditor is host-wide (other labs load BPF concurrently)
# and prints 22 lines per bpftool process. Keep: posture, the inventory (first
# rows + our pinned prog + the auditor + Total), the first bpftool process in
# full, and only the real PROG_LOAD line of the other bpftool processes.
append_audit() {
    python3 - "$1" >> "$SHOT_FILE" <<'PY'
import sys
D = lambda s: "\x1b[2m# " + s + "\x1b[0m"
L = open(sys.argv[1], errors="replace").read().replace("\r", "").replace("^@", "").split("\n")
out, state, inv_rows, inv_cut, first_pid, ev_cut, other, noted = [], "pre", 0, 0, None, 0, 0, False
for l in L:
    f = l.split()
    if state == "pre":
        out.append(l)
        if "Startup Inventory" in l: state = "inv"
    elif state == "inv":
        if f and f[0].isdigit():
            if inv_rows < 6 or "trace_kfree_skb" in l or "this auditor" in l:
                if inv_cut and inv_rows >= 6:
                    out.append(D("(... ตัด %d แถว (systemd/แล็บอื่น) ...)" % inv_cut)); inv_cut = 0
                out.append(l); inv_rows += 1
            else:
                inv_cut += 1
        else:
            out.append(l)
            if l.startswith("  Total"): state = "mid"
    elif state == "mid":
        out.append(l)
        if l.startswith("-----") and "TIME" in out[-2]: state = "ev"
    elif state == "ev" and len(f) >= 5 and f[0][:2].isdigit():
        if f[3] != "bpftool":
            other += 1; continue
        if first_pid is None: first_pid = f[1]
        if f[1] == first_pid:
            out.append(l)
        elif 'name="sock4_connect"' in l:
            if ev_cut and not noted:
                noted = True
                out.append(D("(... bpftool อีก 7 โปรเซส (CPU 1-7) แต่ละตัวมีบรรทัดรูปแบบเดียวกัน ตัดเหลือเฉพาะบรรทัด PROG_LOAD ของโปรแกรมจริง ...)"))
            out.append(l)
        else:
            ev_cut += 1
    else:
        if state == "ev" and other:
            out.append(D("(ตัด event ของโปรเซสอื่นบนเครื่อง %d บรรทัด)" % other)); other = 0
        if state == "ev": state = "tail"
        out.append(l)
print("\n".join(out).rstrip("\n"))
PY
}

cd "$PHASE"
shot_begin 1-terminal2 "Terminal 2 — โหลดโปรแกรมทดสอบ (ก่อน/ระหว่าง auditor ทำงาน)"
note "ก่อนเริ่ม auditor:"
run 'sudo bpftool prog load week13-kfree-skb-dropwatch/bpf_bpfel.o /sys/fs/bpf/w16_preloaded && echo loaded'
cd "$LAB_DIR"
bg "$LOG" sudo ./bin/bpf-audit
sleep 4
cd "$PHASE"
note "auditor ทำงานแล้ว (Terminal 1): โหลดทีละ CPU"
run 'for c in $(seq 0 $(($(nproc)-1))); do sudo taskset -c $c bpftool prog load week14-cgroup-sock-addr/bpf_bpfel.o /sys/fs/bpf/w16_cpu$c; done'
run sudo bpftool prog show pinned /sys/fs/bpf/w16_cpu7
run 'sudo bpftool prog list | grep -c "^[0-9]*:"'
sleep 2
run "sudo sh -c 'rm -f /sys/fs/bpf/w16_*'"
run "sudo ls /sys/fs/bpf/"
shot_end
sleep 1
cd "$LAB_DIR"
bg_stop '^./bin/bpf-audit'

shot_begin 2-auditor "Terminal 1 — sudo ./bin/bpf-audit"
prompt_only sudo ./bin/bpf-audit
append_audit "$LOG"
shot_end

# 4.3: each hook separately, count what it saw from the 8 pinned-CPU loads
shot_begin 3-per-cpu "ยืนยันการจับครบทุก CPU ของแต่ละ hook (fentry / raw)"
for h in fentry raw; do
    l=/tmp/w16-audit-$h.log
    bg "$l" sudo ./bin/bpf-audit -hook $h
    sleep 4
    cd "$PHASE"
    for c in $(seq 0 $(($(nproc)-1))); do
        sudo taskset -c $c bpftool prog load week14-cgroup-sock-addr/bpf_bpfel.o /sys/fs/bpf/w16_cpu$c
    done
    sleep 2
    sudo sh -c 'rm -f /sys/fs/bpf/w16_*'
    cd "$LAB_DIR"
    bg_stop '^./bin/bpf-audit'
    note "Terminal 1: sudo ./bin/bpf-audit -hook $h > $l  (Terminal 2: for c in 0..7; taskset -c \$c bpftool prog load ... ; Ctrl+C)"
    run "grep -h 'Hooked' $l"
    run "grep 'name=\"sock4_connect\"' $l | awk '{print \$2}' | sort -u | wc -l"
    run "grep -c 'BPF_OBJ_PIN' $l"
done
shot_end
