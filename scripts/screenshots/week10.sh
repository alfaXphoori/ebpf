#!/usr/bin/env bash
# Week 10: BPF LSM file guard — audit mode and enforce mode, tested as the
# normal (non-root) user against the lab's own lab-files/.
# Section 4.2 (kernel WITHOUT bpf LSM) cannot be reproduced on this box
# (bpf is in /sys/kernel/security/lsm), so it has no screenshot.
source "$(dirname "$0")/lib.sh"
lab_init phase05-security-observability/week10-bpf-lsm
make -s all >/dev/null 2>&1 || { echo "build failed"; exit 1; }

cleanup() {
    sudo pkill -INT -f '^./bin/lsm_file_guard' 2>/dev/null
    rm -rf "$LAB_DIR/lab-files"
}
trap cleanup EXIT

# README step 2
rm -rf lab-files; mkdir -p lab-files
( cd lab-files
  echo "top secret" > secret.txt
  echo "api-key"    > app.key
  ln secret.txt notes.txt
  ln app.key backup.txt
  ln -s secret.txt shortcut )

user_cmds() {
    run 'cat lab-files/secret.txt; echo exit=$?'
    run 'cat lab-files/notes.txt; echo exit=$?'
    run 'cat lab-files/shortcut; echo exit=$?'
    run 'cat lab-files/app.key; echo exit=$?'
    run 'cat lab-files/backup.txt; echo exit=$?'
    run 'python3 -c "import secrets" 2>&1 | tail -n 1; echo exit=${PIPESTATUS[0]}'
    run 'sudo cat lab-files/secret.txt; echo exit=$?'
}
# guard output: drop alerts from unrelated processes on this busy box
# (e.g. go builds opening runtime/secret.go, an editor indexing lab-files/) —
# keep the header, INFO/POLICY lines and alerts from our test commands (cat, python3).
guard_out() {
    sed 's/\^@//' "$1" | tr -d '\r' | grep -E '\[(INFO|POLICY|WARNING)\]|SECURITY_ACTION|^-{20}|(cat|python3) +(name|inode) ' >> "$SHOT_FILE"
}

# ---------------- 4.1 audit mode ----------------
LOG=$(mktemp)
bg "$LOG" sudo ./bin/lsm_file_guard -mode=audit -protect lab-files/app.key
sleep 3
shot_begin 1-audit-user "Terminal 2 — user ทั่วไป (UID 1000) ขณะ guard อยู่ใน AUDIT mode"
run 'cat /sys/kernel/security/lsm; echo'
run id -u
user_cmds
shot_end
sleep 1
bg_stop '^./bin/lsm_file_guard'
shot_begin 2-audit-guard "Terminal 1 — sudo ./bin/lsm_file_guard -mode=audit -protect lab-files/app.key"
prompt_only sudo ./bin/lsm_file_guard -mode=audit -protect lab-files/app.key
note "ตัด alert ของ process อื่นในเครื่องที่ไม่เกี่ยวกับแล็บออก"
guard_out "$LOG"
shot_end
rm -f "$LOG"

# ---------------- 4.3 enforce mode (auto -> bpf LSM active) ----------------
# Kept as short as possible: while enforcing, every non-root open of secret*
# on the whole machine is denied.
LOG=$(mktemp)
bg "$LOG" sudo ./bin/lsm_file_guard -protect lab-files/app.key
sleep 3
shot_begin 3-enforce-user "Terminal 2 — user ทั่วไป (UID 1000) ขณะ guard อยู่ใน ENFORCE mode (BPF LSM)"
run 'sudo bpftool link show | grep -B1 -A1 lsm_mac'
user_cmds
bg_stop '^./bin/lsm_file_guard'
note "กด Ctrl+C ที่หน้าต่าง guard แล้ว (link ถูก detach)"
run 'cat lab-files/secret.txt; echo exit=$?'
shot_end
shot_begin 4-enforce-guard "Terminal 1 — sudo ./bin/lsm_file_guard -protect lab-files/app.key (auto -> ENFORCE)"
prompt_only sudo ./bin/lsm_file_guard -protect lab-files/app.key
note "ตัด alert ของ process อื่นในเครื่องที่ไม่เกี่ยวกับแล็บออก"
guard_out "$LOG"
shot_end
rm -f "$LOG"
