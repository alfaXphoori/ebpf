#!/usr/bin/env bash
# Week 26: Tetragon hands-on (privileged container w26-tetragon, policies scoped
# to lab-files/ and port 18026). Cilium-on-kind (README 4.9) is NOT run here:
# it needs kind/cilium-cli downloads and ~1.3 GB of cluster images.
source "$(dirname "$0")/lib.sh"
lab_init phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium

TMPD=$(mktemp -d)
cleanup() {
    pkill -f '^python3 -m http.server 18026' 2>/dev/null
    ./run-tetragon.sh down >/dev/null 2>&1
    rm -rf lab-files "$TMPD"
}
trap cleanup EXIT
cleanup; TMPD=$(mktemp -d)

shot_begin 1-make-test "Terminal — make test + unit test ของ validator (ไม่ต้อง root)"
run make test
run python3 -B -m unittest -v test_validate_policies
shot_end

shot_begin 2-up-apply "Terminal — make up และโหลด policy 01–03"
run make up
run make apply-exec apply-file apply-connect
shot_end

# --- events: two captures running while terminal 2 generates activity --------
CAPA="./run-tetragon.sh capture 14 --process 'w26-hello|cat|curl' | grep -E 'lab-files|18026|18027'"
CAPB="./run-tetragon.sh capture 14 --policy-names w26-process-exec-lsm,w26-file-monitor,w26-tcp-connect"
bash -c "$CAPA" > "$TMPD/a.log" 2>&1 &
PA=$!
bash -c "$CAPB" > "$TMPD/b.log" 2>&1 &
PB=$!
sleep 4

shot_begin 3-terminal2-activity "Terminal 2 — สร้างเหตุการณ์ (exec / เปิดไฟล์ / TCP connect)"
python3 -m http.server 18026 --bind 127.0.0.1 --directory lab-files >/dev/null 2>&1 &
HTTP=$!
prompt_only "python3 -m http.server 18026 --bind 127.0.0.1 --directory lab-files &"
sleep 1
run ./lab-files/bin/w26-hello
run cat lab-files/notes.txt
run cat lab-files/secret.txt
run 'curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18026/notes.txt'
run 'curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18027/; echo exit=$?'
prompt_only "kill %1"
kill $HTTP 2>/dev/null
shot_end
wait $PA $PB 2>/dev/null

shot_begin 4-events "Terminal 1 — event ของ policy 01–03 (tetra getevents -o compact)"
note "(ก) exec/exit + connect กรองด้วย --process และ grep เฉพาะบรรทัดของแล็บ"
prompt_only "$CAPA"
append "$TMPD/a.log"
note "(ข) เฉพาะ event ของ policy ทั้ง 3 (ไม่ได้ตัดบรรทัดใด)"
prompt_only "$CAPB"
append "$TMPD/b.log"
shot_end

shot_begin 5-progs "Terminal — make progs + make list (policy 01–03 ทำงานอยู่)"
run make progs
run make list
shot_end

shot_begin 6-sigkill "Terminal — Policy 04: Sigkill (monitor ก่อน แล้วค่อย enforce)"
run "./run-tetragon.sh remove w26-process-exec-lsm >/dev/null; ./run-tetragon.sh remove w26-file-monitor >/dev/null; ./run-tetragon.sh remove w26-tcp-connect"
run make apply-sigkill-monitor
run 'cat lab-files/secret.txt; echo "exit=$?"'
run ./run-tetragon.sh list
run ./run-tetragon.sh mode w26-enforce-secret-sigkill enforce
run 'cat lab-files/secret.txt; echo "exit=$?"'
run 'cat lab-files/notes.txt; echo "exit=$?"'
run ./run-tetragon.sh list
shot_end

shot_begin 7-override-lsm "Terminal — Policy 05: Override ผ่าน BPF LSM (EPERM แทน SIGKILL)"
run ./run-tetragon.sh remove w26-enforce-secret-sigkill
run make apply-override
run 'cat lab-files/secret.txt; echo "exit=$?"'
run 'head -c 14 lab-files/notes.txt; echo; echo "exit=$?"'
run ./run-tetragon.sh list
shot_end

shot_begin 8-fmodret "Terminal — Override บน kprobe: ทำไมต้อง --disable-kprobe-multi"
run ./run-tetragon.sh remove w26-enforce-secret-override
note "ลองโหลด policy 06 ขณะที่ daemon ยังใช้ kprobe_multi (ค่าเริ่มต้น)"
run make apply-fmodret
run make down
run make up-nomulti
run make apply-fmodret
run 'cat lab-files/secret.txt; echo "exit=$?"'
run 'cat lab-files/notes.txt; echo "exit=$?"'
run "docker exec w26-tetragon bpftool link show | grep -B1 -A2 -E 'security_file_open|modify_return'"
shot_end

shot_begin 9-down "Terminal — make down และตรวจว่าไม่มีอะไรค้าง"
run make down
run 'sudo bpftool prog show | grep -i tetragon ; echo "matches=$?"'
run 'docker ps -a --filter name=w26-tetragon --format "{{.Names}}" | wc -l'
run make clean
shot_end
