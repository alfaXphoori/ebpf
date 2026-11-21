#!/usr/bin/env bash
# ==============================================================================
# lib.sh: helpers for recording REAL lab runs as terminal transcripts
# ==============================================================================
# Each scripts/screenshots/weekNN.sh sources this file, then:
#
#   lab_init phase04-high-speed-networking/week07-xdp-parsing
#   shot_begin unit-tests "Terminal — make test"   # new transcript
#   run make test                                  # prints a prompt + runs for real
#   note "ข้อความอธิบาย"                            # dim comment line (optional)
#   shot_end
#
# Transcripts (.ansi) land in $SHOT_RAW/<week>-<name>.ansi together with a
# .title file. render.py turns them into PNG screenshots under
# <lab>/screenshots/. Nothing is faked: every line comes from the real command.
# ==============================================================================

set -uo pipefail

SHOT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHOT_RAW="${SHOT_RAW:-$SHOT_ROOT/scripts/screenshots/raw}"
SHOT_USER="${SHOT_USER:-student}"
SHOT_HOST="${SHOT_HOST:-ebpf-lab}"
mkdir -p "$SHOT_RAW"

lab_init() {
    LAB_REL="$1"
    LAB_DIR="$SHOT_ROOT/$LAB_REL"
    LAB_WEEK="$(basename "$LAB_REL" | cut -d- -f1)"
    cd "$LAB_DIR" || exit 1
}

# shot_begin <name> <window title>
shot_begin() {
    SHOT_FILE="$SHOT_RAW/$LAB_WEEK-$1.ansi"
    printf '%s\n' "$2" > "$SHOT_RAW/$LAB_WEEK-$1.title"
    : > "$SHOT_FILE"
}

_prompt() {
    local cwd="~/ebpf/$LAB_REL"
    [ "$(pwd)" != "$LAB_DIR" ] && cwd="$(pwd | sed "s#^$SHOT_ROOT#~/ebpf#")"
    cwd="~/${cwd##*/}"
    printf '\033[1;32m%s@%s\033[0m:\033[1;34m%s\033[0m$ %s\n' \
        "$SHOT_USER" "$SHOT_HOST" "$cwd" "$*" >> "$SHOT_FILE"
}

# run <command...>: show prompt, run under a pty (keeps colors), append output
run() {
    _prompt "$*"
    script -qefc "$*" /dev/null 2>&1 | tr -d '\r' | tee -a "$SHOT_FILE"
    return "${PIPESTATUS[0]}"
}

# show <display-cmd> <real-cmd>: show a shortened command but run another one
show() {
    local disp="$1"; shift
    _prompt "$disp"
    script -qefc "$*" /dev/null 2>&1 | tr -d '\r' | tee -a "$SHOT_FILE"
}

# bg <logfile> <command...>: start a long-running tool in the background
bg() {
    local log="$1"; shift
    setsid script -qefc "$*" /dev/null > "$log" 2>&1 < /dev/null &
    BG_PID=$!
}

# bg_stop <pkill -f pattern> [signal]: stop a background tool like Ctrl-C would
bg_stop() {
    local pat="$1" sig="${2:-INT}"
    sudo pkill -"$sig" -f "$pat" 2>/dev/null
    for _ in $(seq 1 100); do kill -0 "$BG_PID" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$BG_PID" 2>/dev/null; then sudo pkill -KILL -f "$pat"; sleep 0.5; fi
    wait "$BG_PID" 2>/dev/null || true
}

# append <file>: append captured background output (shows a ^C like a human)
append() {
    tr -d '\r' < "$1" >> "$SHOT_FILE"
}

# prompt_only <text>: print a prompt line without running (e.g. the command
# whose output came from a background log)
prompt_only() { _prompt "$*"; }

note() { printf '\033[2m# %s\033[0m\n' "$*" >> "$SHOT_FILE"; }

shot_end() { SHOT_FILE=/dev/null; }

# append_last_frame <file>: for full-screen dashboards that redraw with a
# clear-screen escape, keep only the final frame (what the terminal shows when
# you press Ctrl-C), plus whatever was printed after it.
append_last_frame() {
    python3 - "$1" >> "$SHOT_FILE" <<'PY'
import re, sys
s = open(sys.argv[1], encoding="utf-8", errors="replace").read().replace("\r", "")
parts = re.split(r"\x1b\[(?:H\x1b\[2J|2J\x1b\[H|2J|3J|H\x1b\[J)|\x1bc", s)
print(parts[-1].strip("\n") if parts[-1].strip() else parts[-2].strip("\n"))
PY
}

# append_first_lines <file> <n>: startup banner of a background tool
append_head() { head -n "$2" "$1" | tr -d '\r' >> "$SHOT_FILE"; }
