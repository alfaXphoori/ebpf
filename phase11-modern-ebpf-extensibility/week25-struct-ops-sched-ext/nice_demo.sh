#!/usr/bin/env bash
# nice_demo.sh <fifo|vtime>
# โหลด scheduler (ไม่มี workload ในตัว) แล้วรัน spinner SCHED_EXT 4 ตัวที่ pin ไว้บน CPU เดียวกัน:
# nice 0 สองตัว + nice 10 สองตัว จากนั้นวัด CPU time จริงจาก /proc/<pid>/sched
set -euo pipefail
cd "$(dirname "$0")"

MODE=${1:-vtime}
CPU=${CPU:-3}
SECS=${SECS:-6}
BIN=./bin/scx-w25

sudo "$BIN" -mode "$MODE" -workload 0 -duration $((SECS + 3))s -interval $((SECS + 3))s >/dev/null &
LOADER=$!
sleep 1

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait "$LOADER" 2>/dev/null || true; }
trap cleanup EXIT

for n in 0 0 10 10; do
	taskset -c "$CPU" nice -n "$n" "$BIN" ext-run sh -c 'while :; do :; done' &
	pids+=($!)
done
sleep "$SECS"

echo "== mode=$MODE: 4 SCHED_EXT spinners pinned to CPU $CPU for ${SECS}s"
for p in "${pids[@]}"; do
	printf "pid=%-7s nice=%-3s policy=%s cpu_ms=%s\n" "$p" \
		"$(awk '{print $19}' /proc/"$p"/stat)" \
		"$(awk '/^policy/{print $3}' /proc/"$p"/sched)" \
		"$(awk '/se.sum_exec_runtime/{printf "%.0f", $3}' /proc/"$p"/sched)"
done
