#!/usr/bin/env bash
# ==============================================================================
# Week 26: run Tetragon as a privileged Docker container (no Kubernetes needed)
# ==============================================================================
#
#   ./run-tetragon.sh up                 # start the container (pinned image tag)
#   ./run-tetragon.sh status             # container state + daemon version + policies
#   ./run-tetragon.sh apply <policy.yaml> [monitor|enforce] # load a TracingPolicy from ./policies
#   ./run-tetragon.sh mode <name> <monitor|enforce>          # switch a loaded policy's mode
#   ./run-tetragon.sh remove <name>      # unload a TracingPolicy by metadata.name
#   ./run-tetragon.sh list               # list loaded TracingPolicies
#   ./run-tetragon.sh events [args...]   # stream events (tetra getevents -o compact), Ctrl+C to stop
#   ./run-tetragon.sh capture <sec> [args...] # same, but stop after <sec> seconds (for scripts)
#   ./run-tetragon.sh progs              # BPF programs that Tetragon loaded (bpftool)
#   ./run-tetragon.sh capture-json <sec> [args...] # JSON events (pipe to: jq -c -f event-summary.jq)
#   ./run-tetragon.sh down               # stop + remove the container, verify cleanup
#   ./run-tetragon.sh prepare            # create lab-files/ (secret.txt, notes.txt)
#
# Safety: every policy in ./policies matches ONLY paths inside this lab folder
# (suffix ".../week26-ecosystem-tetragon-cilium/lab-files/...") or a lab-only TCP
# port (18026). The container is removed by `down`; `down` then checks that no
# Tetragon BPF program is still loaded.
# ==============================================================================
set -euo pipefail

TETRAGON_IMAGE="${TETRAGON_IMAGE:-quay.io/cilium/tetragon:v1.7.1}"
NAME="${TETRAGON_NAME:-w26-tetragon}"
# Extra daemon flags, e.g. TETRAGON_ARGS="--disable-kprobe-multi" (see README, policy 06)
TETRAGON_ARGS="${TETRAGON_ARGS:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$HERE/policies"
LAB_DIR="$HERE/lab-files"

# Use sudo for docker/bpftool only when the current user cannot talk to docker.
SUDO=""
if [ "$(id -u)" -ne 0 ] && ! docker info >/dev/null 2>&1; then SUDO="sudo"; fi
BPFTOOL_SUDO=""
[ "$(id -u)" -ne 0 ] && BPFTOOL_SUDO="sudo"

die() { echo "error: $*" >&2; exit 1; }

running() { [ "$($SUDO docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = "true" ]; }

tetra() { $SUDO docker exec "$NAME" tetra "$@"; }

wait_ready() {
    # The gRPC server needs a few seconds to load the base sensor (exec/exit).
    for _ in $(seq 1 60); do
        if tetra version --server >/dev/null 2>&1; then return 0; fi
        running || { $SUDO docker logs "$NAME" 2>&1 | tail -20; die "container exited"; }
        sleep 1
    done
    die "Tetragon did not become ready within 60s (see: docker logs $NAME)"
}

cmd_prepare() {
    mkdir -p "$LAB_DIR"
    echo "w26 lab secret: tetragon-should-block-this" > "$LAB_DIR/secret.txt"
    echo "w26 lab notes: reading this is only logged" > "$LAB_DIR/notes.txt"
    mkdir -p "$LAB_DIR/bin"
    printf '#!/bin/sh\necho "hello from w26-hello (pid $$)"\n' > "$LAB_DIR/bin/w26-hello"
    chmod +x "$LAB_DIR/bin/w26-hello"
    echo "prepared $LAB_DIR (secret.txt, notes.txt, bin/w26-hello)"
}

cmd_up() {
    command -v docker >/dev/null || die "docker not found"
    if running; then echo "$NAME already running"; return 0; fi
    $SUDO docker rm -f "$NAME" >/dev/null 2>&1 || true
    cmd_prepare
    echo "starting $NAME from $TETRAGON_IMAGE ${TETRAGON_ARGS:+(args: $TETRAGON_ARGS)}"
    # Flags follow the upstream "Deploy as a container" guide:
    #   --pid=host --cgroupns=host : see every host process/cgroup, not just the container's
    #   --privileged               : CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON to load BPF programs
    #   --hostname                 : events carry the node name (default would be the container ID)
    #   -v /sys/kernel:/sys/kernel : kernel BTF (/sys/kernel/btf/vmlinux) + tracefs/debugfs
    # We deliberately do NOT bind-mount the host /sys/fs/bpf: Tetragon mounts its own
    # bpffs inside the container, so pins vanish together with the container.
    $SUDO docker run --name "$NAME" -d \
        --pid=host --cgroupns=host --privileged \
        --hostname "$(hostname)" \
        -v /sys/kernel:/sys/kernel \
        -v "$POLICY_DIR":/w26/policies:ro \
        "$TETRAGON_IMAGE" ${TETRAGON_ARGS:+/usr/bin/tetragon $TETRAGON_ARGS} >/dev/null
    wait_ready
    cmd_status
}

cmd_status() {
    if ! running; then echo "$NAME is not running"; return 0; fi
    echo "container: $NAME ($TETRAGON_IMAGE)"
    echo -n "daemon version: "; tetra version --server 2>/dev/null | tail -1
    tetra tracingpolicy list
}

cmd_apply() {
    local f="${1:-}"
    [ -n "$f" ] || die "usage: $0 apply <policy.yaml>"
    f="$(basename "$f")"
    [ -f "$POLICY_DIR/$f" ] || die "no such policy: $POLICY_DIR/$f"
    running || die "$NAME is not running (run: $0 up)"
    local mode="${2:-}"   # optional: monitor | enforce (default: enforce if the policy has actions)
    if [ -n "$mode" ]; then
        tetra tracingpolicy add --mode "$mode" "/w26/policies/$f"
    else
        tetra tracingpolicy add "/w26/policies/$f"
    fi
    tetra tracingpolicy list
}

cmd_mode() {
    [ $# -eq 2 ] || die "usage: $0 mode <policy-name> <monitor|enforce>"
    tetra tracingpolicy set-mode "$1" "$2"
    tetra tracingpolicy list
}

cmd_remove() {
    local n="${1:-}"
    [ -n "$n" ] || die "usage: $0 remove <policy-name>"
    tetra tracingpolicy delete "$n"
}

cmd_events() {
    running || die "$NAME is not running (run: $0 up)"
    # -t only when stdout is a terminal (colours); plain text when piped to a file
    local tty=""
    [ -t 1 ] && tty="-t"
    $SUDO docker exec -i $tty "$NAME" tetra getevents -o compact "$@"
}

cmd_capture() {
    local secs="${1:-}"
    [[ "$secs" =~ ^[0-9]+$ ]] || die "usage: $0 capture <seconds> [tetra getevents args...]"
    shift
    running || die "$NAME is not running (run: $0 up)"
    # timeout runs INSIDE the container so tetra exits cleanly and flushes its output
    $SUDO docker exec "$NAME" timeout "$secs" tetra getevents -o compact "$@" || true
}

# Program names Tetragon v1.7 gives its BPF programs (base sensor + generic sensors).
# Used to verify cleanup from the HOST, whose bpftool may be built without the
# "pids" feature and therefore cannot show which process owns a program.
TETRAGON_PROG_RE='name (event_execve|event_exit_acct|event_wake_up_n|execve_rate|execve_send|execve_map_upda|tg_kp_|generic_)'

cmd_capture_json() {
    local secs="${1:-}"
    [[ "$secs" =~ ^[0-9]+$ ]] || die "usage: $0 capture-json <seconds> [tetra getevents args...]"
    shift
    running || die "$NAME is not running (run: $0 up)"
    $SUDO docker exec "$NAME" timeout "$secs" tetra getevents -o json "$@" || true
}

cmd_progs() {
    running || die "$NAME is not running (run: $0 up)"
    # The bpftool inside the image is built with skeletons, so it prints
    # "pids tetragon(<pid>)" for programs whose fd/link the daemon holds directly.
    # Tail-call targets (generic_*_filter_arg, *_actions, ...) live in prog-array
    # maps and therefore show no pids line; we list them by load time instead.
    echo "== programs held directly by the tetragon process (bpftool inside the container)"
    $SUDO docker exec "$NAME" bpftool prog show | grep -B4 'pids tetragon' | grep -E '^[0-9]+:' || true
    echo "== all Tetragon programs (id type name), matched by name on the host"
    $BPFTOOL_SUDO bpftool prog show | grep -E "$TETRAGON_PROG_RE" | awk '{for(i=1;i<=NF;i++) if($i=="name") print $1, $2, $(i+1)}'
    echo "== total: $($BPFTOOL_SUDO bpftool prog show | grep -cE "$TETRAGON_PROG_RE") programs"
}

cmd_down() {
    if $SUDO docker inspect "$NAME" >/dev/null 2>&1; then
        echo "stopping $NAME"
        $SUDO docker stop -t 10 "$NAME" >/dev/null || true
        $SUDO docker rm -f "$NAME" >/dev/null 2>&1 || true
    else
        echo "$NAME is not present"
    fi
    command -v bpftool >/dev/null || { echo "bpftool not found: cannot verify cleanup" >&2; return 0; }
    # Programs are freed asynchronously after the last fd/link/pin goes away
    for _ in $(seq 1 15); do
        if ! $BPFTOOL_SUDO bpftool prog show | grep -qE "$TETRAGON_PROG_RE|tetragon"; then
            echo "cleanup OK: no Tetragon BPF program is loaded"
            return 0
        fi
        sleep 1
    done
    echo "WARNING: Tetragon BPF programs are still loaded:" >&2
    $BPFTOOL_SUDO bpftool prog show | grep -E "$TETRAGON_PROG_RE|tetragon" >&2
    return 1
}

case "${1:-}" in
    up)       cmd_up ;;
    down)     cmd_down ;;
    status)   cmd_status ;;
    prepare)  cmd_prepare ;;
    apply)    shift; cmd_apply "$@" ;;
    remove)   shift; cmd_remove "$@" ;;
    mode)     shift; cmd_mode "$@" ;;
    list)     tetra tracingpolicy list ;;
    events)   shift; cmd_events "$@" ;;
    capture)  shift; cmd_capture "$@" ;;
    capture-json) shift; cmd_capture_json "$@" ;;
    progs)    cmd_progs ;;
    *) sed -n '2,24p' "$0"; exit 1 ;;
esac
