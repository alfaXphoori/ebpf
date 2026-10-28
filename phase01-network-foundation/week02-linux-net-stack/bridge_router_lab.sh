#!/usr/bin/env bash
# ==============================================================================
# eBPF Zero to Hero - Week 02: Linux Network Stack & Virtual Bridge Lab
# Script: bridge_router_lab.sh
# Description: Provisions a multi-namespace topology connected via a Linux Bridge (br0)
#              and provides diagnostic tracing for sk_buff, SoftIRQ, and syscalls.
#
#              Safety: the bridge lives inside its own "switch" namespace (w02-sw)
#              instead of the host (root) namespace, so this lab never touches host
#              interfaces, host routes, host iptables, or host sysctls. All names are
#              prefixed with 'w02-' to avoid collisions with other labs.
# Topology:
#              +-----------------------------------------+
#              | netns w02-sw                            |
#              |   Linux Bridge: br0 (10.20.0.1/24)      |
#              +---------+-----------+-----------+-------+
#                        |           |           |
#                    veth-br1    veth-br2    veth-br3
#                        |           |           |
#                    veth-ns1    veth-ns2    veth-ns3
#                  +---------+ +---------+ +---------+
#                  | w02-ns1 | | w02-ns2 | | w02-ns3 |
#                  |   .11   | |   .12   | |   .13   |
#                  +---------+ +---------+ +---------+
# Author: eBPF Mastery Team
# ==============================================================================

set -euo pipefail

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Topology Configuration ---
HUB_NS="w02-sw"                     # namespace that owns the bridge ("the switch/gateway")
BRIDGE="br0"                        # lives inside ${HUB_NS}, not on the host
BRIDGE_IP="10.20.0.1/24"
GATEWAY_IP="10.20.0.1"
NAMESPACES=("w02-ns1" "w02-ns2" "w02-ns3")
NS_IPS=("10.20.0.11/24" "10.20.0.12/24" "10.20.0.13/24")
RAW_IPS=("10.20.0.11" "10.20.0.12" "10.20.0.13")

# --- Helper Functions ---
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_step() {
    echo -e "\n${CYAN}${BOLD}===> $1${NC}"
}

# Run a command inside the switch namespace
hub() {
    ip netns exec "${HUB_NS}" "$@"
}

ns_exists() {
    [[ -e "/run/netns/$1" ]]
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This script requires root privileges to manage Linux bridges and network namespaces."
        echo -e "Please run with sudo: ${BOLD}sudo $0 $*${NC}"
        exit 1
    fi
}

require_lab() {
    if ! ns_exists "${HUB_NS}"; then
        log_error "Lab topology not found. Run: sudo $0 setup"
        exit 1
    fi
}

# --- Teardown / Cleanup ---
clean_lab() {
    log_step "Tearing down Bridge and Namespaces..."

    # Deleting a namespace destroys every interface inside it; deleting one end of a
    # veth pair destroys its peer as well. Nothing is left behind in the host namespace.
    for ns in "${NAMESPACES[@]}" "${HUB_NS}"; do
        if ns_exists "${ns}"; then
            ip netns del "${ns}"
            log_info "Deleted namespace: ${ns}"
        fi
    done

    log_success "Cleanup finished cleanly."
}

# --- Setup Topology ---
setup_lab() {
    log_step "Building Multi-Namespace Bridge Topology (${NAMESPACES[*]} <-> ${HUB_NS}/${BRIDGE})..."

    clean_lab

    log_info "Step 1: Creating switch namespace '${HUB_NS}' and Linux Bridge '${BRIDGE}' inside it"
    ip netns add "${HUB_NS}"
    hub ip link set lo up
    hub ip link add name "${BRIDGE}" type bridge
    hub ip addr add "${BRIDGE_IP}" dev "${BRIDGE}"
    hub ip link set "${BRIDGE}" up

    # Optional: adjust FDB ageing time (centiseconds) for lab determinism
    hub ip link set dev "${BRIDGE}" type bridge ageing_time 30000 2>/dev/null || true

    log_info "Step 2: Creating namespaces and interconnecting with veth pairs"
    for idx in "${!NAMESPACES[@]}"; do
        local ns="${NAMESPACES[$idx]}"
        local ip="${NS_IPS[$idx]}"
        local num=$((idx + 1))
        local veth_ns="veth-ns${num}"
        local veth_br="veth-br${num}"

        log_info "  - Provisioning ${ns} (${ip}) connected via ${veth_ns} <---> ${veth_br}"
        ip netns add "${ns}"

        # Create the veth pair with each end born directly inside its target namespace
        ip link add "${veth_ns}" netns "${ns}" type veth peer name "${veth_br}" netns "${HUB_NS}"

        # Attach bridge-side end to br0 (= plug the cable into the switch)
        hub ip link set "${veth_br}" master "${BRIDGE}"
        hub ip link set "${veth_br}" up

        # Configure namespace interface
        ip netns exec "${ns}" ip addr add "${ip}" dev "${veth_ns}"
        ip netns exec "${ns}" ip link set lo up
        ip netns exec "${ns}" ip link set "${veth_ns}" up

        # Add default gateway pointing to bridge IP
        ip netns exec "${ns}" ip route add default via "${GATEWAY_IP}" dev "${veth_ns}" 2>/dev/null || true

        # Disable offloading for educational packet analysis
        ip netns exec "${ns}" ethtool -K "${veth_ns}" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true
        hub ethtool -K "${veth_br}" rx off tx off tso off gso off gro off >/dev/null 2>&1 || true
    done

    # IP forwarding is per network namespace: enabling it in ${HUB_NS} does NOT change
    # the host's net.ipv4.ip_forward. (Pure L2 bridging does not need it; it is only
    # used if you later route between subnets through the switch namespace.)
    hub sysctl -qw net.ipv4.ip_forward=1

    log_success "Bridge topology provisioned successfully!"
    print_status
}

# --- Status Display ---
print_status() {
    require_lab
    log_step "Current Topology and Bridge Forwarding Database (FDB)"

    echo -e "${BOLD}Linux Bridge [${BRIDGE}] in netns ${HUB_NS}:${NC}"
    hub ip -brief addr show "${BRIDGE}"

    echo -e "\n${BOLD}Interfaces attached to ${BRIDGE}:${NC}"
    hub ip -brief link show master "${BRIDGE}"

    echo -e "\n${BOLD}Bridge Forwarding Database (FDB) Entries (learned, non-permanent):${NC}"
    hub bridge fdb show br "${BRIDGE}" 2>/dev/null | grep -v "permanent" || true

    echo -e "\n${BOLD}Namespace Status:${NC}"
    for idx in "${!NAMESPACES[@]}"; do
        local ns="${NAMESPACES[$idx]}"
        local veth_ns="veth-ns$((idx + 1))"
        echo -e "  [${BOLD}${ns}${NC}]: $(ip netns exec "${ns}" ip -brief addr show dev "${veth_ns}")"
    done
}

# --- Connectivity Tests ---
ping_test() {
    local src_ns="$1" dst_ip="$2" label="$3"
    log_info "Testing ${label}..."
    if ip netns exec "${src_ns}" ping -c 2 -W 1 "${dst_ip}" >/dev/null; then
        log_success "${label} reached!"
    else
        log_error "${label} ping failed!"
        exit 1
    fi
}

test_connectivity() {
    require_lab
    log_step "Testing Cross-Namespace and Bridge Gateway Connectivity..."

    ping_test "${NAMESPACES[0]}" "${GATEWAY_IP}" "${NAMESPACES[0]} -> Bridge Gateway (${GATEWAY_IP})"
    ping_test "${NAMESPACES[0]}" "${RAW_IPS[1]}" "${NAMESPACES[0]} (${RAW_IPS[0]}) -> ${NAMESPACES[1]} (${RAW_IPS[1]})"
    ping_test "${NAMESPACES[1]}" "${RAW_IPS[2]}" "${NAMESPACES[1]} (${RAW_IPS[1]}) -> ${NAMESPACES[2]} (${RAW_IPS[2]})"
    ping_test "${NAMESPACES[2]}" "${RAW_IPS[0]}" "${NAMESPACES[2]} (${RAW_IPS[2]}) -> ${NAMESPACES[0]} (${RAW_IPS[0]})"

    log_success "All bridge L2 switching tests succeeded!"
    print_status
}

# --- Diagnostic Tracing (Kernel Network Stack & SoftIRQ) ---
trace_stack() {
    require_lab
    log_step "Diagnostic Tracing: Kernel Network Stack & SoftIRQ Traversal"

    echo -e "${MAGENTA}${BOLD}[1. /proc/net/softnet_stat Inspection]${NC}"
    echo "Values are hex, per CPU (system-wide: /proc/net/softnet_stat is not per-namespace)."
    echo "Shown: col1=Processed col2=Dropped col3=TimeSqueeze (col13 = CPU id on newer kernels)"
    echo "------------------------------------------------------------------------------------------------"
    local row=0
    while read -r line; do
        local processed dropped time_squeeze cpu nf
        nf=$(echo "${line}" | awk '{print NF}')
        processed=$(echo "${line}" | awk '{print $1}')
        dropped=$(echo "${line}" | awk '{print $2}')
        time_squeeze=$(echo "${line}" | awk '{print $3}')
        # Column 13 holds the real CPU number (offline CPUs are skipped, so row != CPU id)
        if [[ "${nf}" -ge 13 ]]; then
            cpu=$((16#$(echo "${line}" | awk '{print $13}')))
        else
            cpu=${row}
        fi
        printf "  CPU %2d : Processed=0x%-8s Dropped=0x%-8s TimeSqueeze=0x%-8s\n" "${cpu}" "${processed}" "${dropped}" "${time_squeeze}"
        row=$((row + 1))
    done < /proc/net/softnet_stat
    echo -e "${YELLOW}Note: 'TimeSqueeze' increments when net_rx_action() runs out of budget (netdev_budget packets or netdev_budget_usecs) with work still pending.${NC}\n"

    echo -e "${MAGENTA}${BOLD}[2. /proc/softirqs (NET_RX / NET_TX Activity)]${NC}"
    grep -E "NET_RX|NET_TX" /proc/softirqs || true
    echo ""

    echo -e "${MAGENTA}${BOLD}[3. Bridge Device Interface Counters (ip -s link, netns ${HUB_NS})]${NC}"
    hub ip -s link show dev "${BRIDGE}"
    echo ""

    echo -e "${MAGENTA}${BOLD}[4. System Call Tracing with strace (Socket Send & Recv)]${NC}"
    if command -v strace &>/dev/null; then
        log_info "Executing strace on a 1-packet ICMP ping from ${NAMESPACES[0]} to ${NAMESPACES[1]}..."
        ip netns exec "${NAMESPACES[0]}" strace -f -e trace=socket,sendto,recvmsg,close -T -- ping -c 1 -W 1 "${RAW_IPS[1]}" 2>&1 | \
            grep -E "socket|sendto|recvmsg" | sed 's/^/  [syscall] /' || true
    else
        log_warn "'strace' command not found. Install via 'apt install strace' or 'yum install strace'."
    fi
    echo ""

    echo -e "${MAGENTA}${BOLD}[5. Kernel Tracepoint Inspection (perf stat / trace)]${NC}"
    if command -v perf &>/dev/null; then
        log_info "Running perf stat tracking net:* events during cross-bridge traffic..."
        perf stat -e 'net:net_dev_queue,net:net_dev_xmit,net:netif_rx,net:netif_receive_skb' \
            ip netns exec "${NAMESPACES[0]}" ping -c 3 "${RAW_IPS[1]}" 2>&1 | grep -E "net:|seconds" | sed 's/^/  [perf] /' || true
    else
        log_info "Tip: Install 'linux-tools-common' to inspect kernel net:* tracepoints with perf."
    fi

    log_success "Diagnostic trace complete."
}

# --- CLI Dispatcher ---
print_usage() {
    echo -e "${BOLD}Usage:${NC} sudo $0 [command]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}setup${NC}    Deploy 3-namespace bridge topology (${NAMESPACES[*]} <-> ${HUB_NS}/${BRIDGE})"
    echo -e "  ${GREEN}test${NC}     Verify cross-namespace ICMP packet forwarding"
    echo -e "  ${GREEN}trace${NC}    Inspect softnet_stat, softirqs, bridge counters, and syscalls"
    echo -e "  ${GREEN}status${NC}   Display active bridge ports and learned FDB MAC table"
    echo -e "  ${GREEN}clean${NC}    Tear down bridge, namespaces, and all associated veth links"
    echo -e "  ${GREEN}help${NC}     Display this help documentation"
    echo ""
    echo -e "${BOLD}Default:${NC} If no command is passed, '${BOLD}setup${NC}' followed by '${BOLD}test${NC}' will execute."
}

main() {
    check_root "$@"

    local cmd="${1:-default}"

    case "${cmd}" in
        setup)
            setup_lab
            ;;
        test)
            test_connectivity
            ;;
        trace)
            trace_stack
            ;;
        status)
            print_status
            ;;
        clean)
            clean_lab
            ;;
        help|--help|-h)
            print_usage
            ;;
        default)
            setup_lab
            test_connectivity
            log_info "Tip: Run 'sudo $0 trace' to observe softnet_stat, SoftIRQ, and syscall behavior."
            ;;
        *)
            log_error "Unknown command: ${cmd}"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"
