#!/usr/bin/env bash
# ==============================================================================
# eBPF Noob to Hero - Week 02: Linux Network Stack & Virtual Bridge Lab
# Script: bridge_router_lab.sh
# Description: Provisions a multi-namespace topology connected via a Linux Bridge (br0)
#              and provides diagnostic tracing for sk_buff, SoftIRQ, and syscalls.
# Topology:
#              +-------------------+
#              | Linux Bridge: br0 | (10.20.0.1/24)
#              +---------+---------+
#             /          |          \
#   veth-br1 /  veth-br2 |  veth-br3 \
#           /            |            \
#  veth-ns1/     veth-ns2|     veth-ns3\
#  +------+       +------+       +------+
#  | ns1  |       | ns2  |       | ns3  |
#  | .11  |       | .12  |       | .13  |
#  +------+       +------+       +------+
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
BRIDGE="br0"
BRIDGE_IP="10.20.0.1/24"
NAMESPACES=("ns1" "ns2" "ns3")
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

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This script requires root privileges to manage Linux bridges and network namespaces."
        echo -e "Please run with sudo: ${BOLD}sudo $0 $@${NC}"
        exit 1
    fi
}

# --- Teardown / Cleanup ---
clean_lab() {
    log_step "Tearing down Bridge and Namespaces..."

    for ns in "${NAMESPACES[@]}"; do
        if ip netns list | grep -q "^${ns}\b"; then
            ip netns del "${ns}"
            log_info "Deleted namespace: ${ns}"
        fi
    done

    # Remove Linux Bridge if it exists
    if ip link show "${BRIDGE}" &>/dev/null; then
        ip link set "${BRIDGE}" down 2>/dev/null || true
        ip link del "${BRIDGE}" type bridge 2>/dev/null || true
        log_info "Deleted Linux Bridge: ${BRIDGE}"
    fi

    # Clean any dangling bridge-side veth interfaces in host namespace
    for i in 1 2 3; do
        if ip link show "veth-br${i}" &>/dev/null; then
            ip link del "veth-br${i}" 2>/dev/null || true
            log_info "Cleaned dangling interface: veth-br${i}"
        fi
    done

    log_success "Cleanup finished cleanly."
}

# --- Setup Topology ---
setup_lab() {
    log_step "Building Multi-Namespace Bridge Topology (ns1, ns2, ns3 <-> br0)..."

    clean_lab

    log_info "Step 1: Creating Linux Bridge '${BRIDGE}'"
    ip link add name "${BRIDGE}" type bridge
    ip addr add "${BRIDGE_IP}" dev "${BRIDGE}"
    ip link set "${BRIDGE}" up

    # Optional: Enable STP or adjust ageing time for lab determinism
    ip link set dev "${BRIDGE}" type bridge ageing_time 30000 2>/dev/null || true

    log_info "Step 2: Creating namespaces and interconnecting with veth pairs"
    for idx in "${!NAMESPACES[@]}"; do
        local ns="${NAMESPACES[$idx]}"
        local ip="${NS_IPS[$idx]}"
        local num=$((idx + 1))
        local veth_ns="veth-ns${num}"
        local veth_br="veth-br${num}"

        log_info "  - Provisioning ${ns} (${ip}) connected via ${veth_ns} <---> ${veth_br}"
        ip netns add "${ns}"
        ip link add "${veth_ns}" type veth peer name "${veth_br}"

        # Attach bridge-side end to br0
        ip link set "${veth_br}" master "${BRIDGE}"
        ip link set "${veth_br}" up

        # Move namespace-side end to target namespace
        ip link set "${veth_ns}" netns "${ns}"

        # Configure namespace interface
        ip netns exec "${ns}" ip addr add "${ip}" dev "${veth_ns}"
        ip netns exec "${ns}" ip link set lo up
        ip netns exec "${ns}" ip link set "${veth_ns}" up

        # Add default gateway pointing to bridge IP
        ip netns exec "${ns}" ip route add default via 10.20.0.1 dev "${veth_ns}" 2>/dev/null || true

        # Disable offloading for educational packet analysis
        ip netns exec "${ns}" ethtool -K "${veth_ns}" rx off tx off tso off gso off gro off 2>/dev/null || true
        ethtool -K "${veth_br}" rx off tx off tso off gso off gro off 2>/dev/null || true
    done

    # Enable IP forwarding on host so bridge forwards properly if routing is used
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    log_success "Bridge topology provisioned successfully!"
    print_status
}

# --- Status Display ---
print_status() {
    log_step "Current Topology and Bridge Forwarding Database (FDB)"

    echo -e "${BOLD}Linux Bridge [${BRIDGE}]:${NC}"
    ip -brief addr show "${BRIDGE}"

    echo -e "\n${BOLD}Interfaces attached to ${BRIDGE}:${NC}"
    bridge link show dev "${BRIDGE}" 2>/dev/null || ip link show master "${BRIDGE}"

    echo -e "\n${BOLD}Bridge Forwarding Database (FDB) Entries:${NC}"
    bridge fdb show dev "${BRIDGE}" 2>/dev/null | grep -v "permanent" || true

    echo -e "\n${BOLD}Namespace Status:${NC}"
    for ns in "${NAMESPACES[@]}"; do
        echo -e "  [${BOLD}${ns}${NC}]: $(ip netns exec "${ns}" ip -brief addr show dev "veth-${ns}")"
    done
}

# --- Connectivity Tests ---
test_connectivity() {
    log_step "Testing Cross-Namespace and Host Bridge Connectivity..."

    # Test ns1 -> Host Bridge
    log_info "Testing ns1 -> Bridge Gateway (10.20.0.1)..."
    if ip netns exec ns1 ping -c 2 -W 1 10.20.0.1 >/dev/null; then
        log_success "ns1 -> Bridge Gateway reached!"
    else
        log_error "ns1 -> Bridge Gateway ping failed!"
        exit 1
    fi

    # Test ns1 -> ns2
    log_info "Testing ns1 (10.20.0.11) -> ns2 (10.20.0.12)..."
    if ip netns exec ns1 ping -c 2 -W 1 10.20.0.12 >/dev/null; then
        log_success "ns1 -> ns2 reached!"
    else
        log_error "ns1 -> ns2 ping failed!"
        exit 1
    fi

    # Test ns2 -> ns3
    log_info "Testing ns2 (10.20.0.12) -> ns3 (10.20.0.13)..."
    if ip netns exec ns2 ping -c 2 -W 1 10.20.0.13 >/dev/null; then
        log_success "ns2 -> ns3 reached!"
    else
        log_error "ns2 -> ns3 ping failed!"
        exit 1
    fi

    # Test ns3 -> ns1
    log_info "Testing ns3 (10.20.0.13) -> ns1 (10.20.0.11)..."
    if ip netns exec ns3 ping -c 2 -W 1 10.20.0.11 >/dev/null; then
        log_success "ns3 -> ns1 reached!"
    else
        log_error "ns3 -> ns1 ping failed!"
        exit 1
    fi

    log_success "All bridge L2 switching tests succeeded!"
    print_status
}

# --- Diagnostic Tracing (Kernel Network Stack & SoftIRQ) ---
trace_stack() {
    log_step "Diagnostic Tracing: Kernel Network Stack & SoftIRQ Traversal"

    echo -e "${MAGENTA}${BOLD}[1. /proc/net/softnet_stat Inspection]${NC}"
    echo "Columns: [CPU] [Processed] [Dropped] [TimeSqueeze] [CPUCollision] [ReceivedRps] [FlowLimitCount]"
    echo "------------------------------------------------------------------------------------------------"
    local cpu=0
    while read -r line; do
        local processed dropped time_squeeze
        processed=$(echo "${line}" | awk '{print $1}')
        dropped=$(echo "${line}" | awk '{print $2}')
        time_squeeze=$(echo "${line}" | awk '{print $3}')
        printf "  CPU %2d : Processed=0x%-8s Dropped=0x%-8s TimeSqueeze=0x%-8s\n" "${cpu}" "${processed}" "${dropped}" "${time_squeeze}"
        cpu=$((cpu + 1))
    done < /proc/net/softnet_stat
    echo -e "${YELLOW}Note: 'TimeSqueeze' increments when SoftIRQ runs out of budget before draining RX Ring.${NC}\n"

    echo -e "${MAGENTA}${BOLD}[2. /proc/softirqs (NET_RX / NET_TX Activity)]${NC}"
    grep -E "NET_RX|NET_TX" /proc/softirqs || true
    echo ""

    echo -e "${MAGENTA}${BOLD}[3. Bridge Device Interface Counters (ip -s link)]${NC}"
    ip -s link show dev "${BRIDGE}"
    echo ""

    echo -e "${MAGENTA}${BOLD}[4. System Call Tracing with strace (Socket Send & Recv)]${NC}"
    if command -v strace &>/dev/null; then
        log_info "Executing strace on a 1-packet ICMP ping from ns1 to ns2..."
        ip netns exec ns1 strace -f -e trace=socket,sendto,recvmsg,close -T -- ping -c 1 -W 1 10.20.0.12 2>&1 | \
            grep -E "socket|sendto|recvmsg" | sed 's/^/  [syscall] /' || true
    else
        log_warn "'strace' command not found. Install via 'apt install strace' or 'yum install strace'."
    fi
    echo ""

    echo -e "${MAGENTA}${BOLD}[5. Kernel Tracepoint Inspection (perf stat / trace)]${NC}"
    if command -v perf &>/dev/null; then
        log_info "Running perf stat tracking net:* events during cross-bridge traffic..."
        perf stat -e 'net:net_dev_queue,net:net_dev_xmit,net:netif_rx,net:netif_receive_skb' \
            ip netns exec ns1 ping -c 3 10.20.0.12 2>&1 | grep -E "net:|seconds" | sed 's/^/  [perf] /' || true
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
    echo -e "  ${GREEN}setup${NC}    Deploy 3-namespace bridge topology (ns1, ns2, ns3 <-> br0)"
    echo -e "  ${GREEN}test${NC}     Verify cross-namespace ICMP packet forwarding"
    echo -e "  ${GREEN}trace${NC}    Inspect softnet_stat, softirqs, bridge counters, and syscalls"
    echo -e "  ${GREEN}status${NC}   Display active bridge ports and learned FDB MAC table"
    echo -e "  ${GREEN}clean${NC}    Tear down bridge, namespaces, and all associated veth links"
    echo -e "  ${GREEN}help${NC}     Display this help documentation"
    echo ""
    echo -e "${BOLD}Default:${NC} If no command is passed, '${BOLD}setup${NC}' followed by '${BOLD}test${NC}' will execute."
}

main() {
    check_root

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
