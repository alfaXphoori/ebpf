#!/usr/bin/env bash
# ==============================================================================
# eBPF Noob to Hero - Week 01: Network Namespaces & veth Pair Lab
# Script: lab_netns.sh
# Description: Automates creation, testing, packet capture, and cleanup of
#              isolated Linux Network Namespaces (ns1 <-> ns2) with a veth pair.
# Author: eBPF Mastery Team
# ==============================================================================

set -euo pipefail

# --- Color Definitions for Terminal Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Network Configuration Constants ---
NS1="ns1"
NS2="ns2"
VETH1="veth1"
VETH2="veth2"
IP_NS1="10.10.1.1/24"
IP_NS2="10.10.1.2/24"
RAW_IP_NS1="10.10.1.1"
RAW_IP_NS2="10.10.1.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# Ensure script is executed with root privileges
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This script requires root privileges to manage network namespaces and veth pairs."
        echo -e "Please run with sudo: ${BOLD}sudo $0 $@${NC}"
        exit 1
    fi
}

# --- Core Lab Operations ---

# 1. Clean existing namespaces and interfaces
clean_lab() {
    log_step "Cleaning up existing Network Namespaces and veth interfaces..."

    # Kill any lingering background sniffer processes if running
    if [[ -f "/tmp/raw_sniffer_week01.pid" ]]; then
        local pid
        pid=$(cat /tmp/raw_sniffer_week01.pid 2>/dev/null || true)
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            log_info "Stopping background sniffer process (PID: ${pid})..."
            kill "${pid}" 2>/dev/null || true
        fi
        rm -f /tmp/raw_sniffer_week01.pid
    fi

    # Delete namespaces (this automatically tears down associated veth interfaces inside)
    if ip netns list | grep -q "^${NS1}\b"; then
        ip netns del "${NS1}"
        log_info "Deleted namespace: ${NS1}"
    fi

    if ip netns list | grep -q "^${NS2}\b"; then
        ip netns del "${NS2}"
        log_info "Deleted namespace: ${NS2}"
    fi

    # Explicitly check and delete dangling veth interfaces in host namespace if any
    if ip link show "${VETH1}" &>/dev/null; then
        ip link del "${VETH1}"
        log_info "Removed dangling host interface: ${VETH1}"
    fi

    if ip link show "${VETH2}" &>/dev/null; then
        ip link del "${VETH2}"
        log_info "Removed dangling host interface: ${VETH2}"
    fi

    log_success "Cleanup completed successfully."
}

# 2. Setup namespaces, veth pair, IP addresses, and routing
setup_lab() {
    log_step "Setting up isolated Network Namespaces (${NS1} <-> ${NS2})..."

    # Ensure clean slate before setup
    clean_lab

    log_info "Step 1: Creating network namespaces '${NS1}' and '${NS2}'"
    ip netns add "${NS1}"
    ip netns add "${NS2}"

    log_info "Step 2: Creating virtual Ethernet pair '${VETH1}' <---> '${VETH2}'"
    ip link add "${VETH1}" type veth peer name "${VETH2}"

    log_info "Step 3: Moving '${VETH1}' to namespace '${NS1}' and '${VETH2}' to '${NS2}'"
    ip link set "${VETH1}" netns "${NS1}"
    ip link set "${VETH2}" netns "${NS2}"

    log_info "Step 4: Assigning IP addresses"
    log_info "        ${NS1}:${VETH1} -> ${IP_NS1}"
    log_info "        ${NS2}:${VETH2} -> ${IP_NS2}"
    ip netns exec "${NS1}" ip addr add "${IP_NS1}" dev "${VETH1}"
    ip netns exec "${NS2}" ip addr add "${IP_NS2}" dev "${VETH2}"

    log_info "Step 5: Bringing up loopback and veth interfaces in both namespaces"
    ip netns exec "${NS1}" ip link set lo up
    ip netns exec "${NS2}" ip link set lo up
    ip netns exec "${NS1}" ip link set "${VETH1}" up
    ip netns exec "${NS2}" ip link set "${VETH2}" up

    log_info "Step 6: Disabling TX/RX checksum and segment offloading (TSO/GSO/GRO)"
    # Disabling hardware offloading ensures raw sockets observe realistic, fully calculated checksums
    ip netns exec "${NS1}" ethtool -K "${VETH1}" rx off tx off tso off gso off gro off 2>/dev/null || {
        log_warn "ethtool could not disable some offload features on ${VETH1} (may be non-critical in virtualized environments)"
    }
    ip netns exec "${NS2}" ethtool -K "${VETH2}" rx off tx off tso off gso off gro off 2>/dev/null || {
        log_warn "ethtool could not disable some offload features on ${VETH2} (may be non-critical in virtualized environments)"
    }

    log_success "Lab topology successfully established!"
    print_status
}

# 3. Print current topology status
print_status() {
    log_step "Current Network Namespaces & Interface Topology"

    echo -e "${BOLD}Active Namespaces:${NC}"
    ip netns list | sed 's/^/  - /'

    echo -e "\n${BOLD}[Namespace ${NS1}] Interfaces:${NC}"
    ip netns exec "${NS1}" ip -brief addr show

    echo -e "\n${BOLD}[Namespace ${NS2}] Interfaces:${NC}"
    ip netns exec "${NS2}" ip -brief addr show
}

# 4. Run connectivity tests
test_connectivity() {
    log_step "Testing bidirectional ICMP connectivity..."

    log_info "Pinging from ${NS1} (${RAW_IP_NS1}) -> ${NS2} (${RAW_IP_NS2})..."
    if ip netns exec "${NS1}" ping -c 3 -W 2 "${RAW_IP_NS2}"; then
        log_success "Ping ${NS1} -> ${NS2} succeeded!"
    else
        log_error "Ping ${NS1} -> ${NS2} failed!"
        exit 1
    fi

    log_info "Pinging from ${NS2} (${RAW_IP_NS2}) -> ${NS1} (${RAW_IP_NS1})..."
    if ip netns exec "${NS2}" ping -c 3 -W 2 "${RAW_IP_NS1}"; then
        log_success "Ping ${NS2} -> ${NS1} succeeded!"
    else
        log_error "Ping ${NS2} -> ${NS1} failed!"
        exit 1
    fi

    log_success "All connectivity tests passed!"
}

# 5. Automated capture demonstration
capture_demo() {
    log_step "Starting automated raw packet capture demo..."

    local sniffer_script="${SCRIPT_DIR}/raw_sniffer.py"
    if [[ ! -f "${sniffer_script}" ]]; then
        log_error "Sniffer script '${sniffer_script}' not found!"
        exit 1
    fi

    if ! ip netns list | grep -q "^${NS2}\b"; then
        log_info "Namespaces not found. Running setup first..."
        setup_lab
    fi

    log_info "Spawning raw_sniffer.py inside namespace '${NS2}' capturing on '${VETH2}' (count: 4)..."
    ip netns exec "${NS2}" python3 "${sniffer_script}" --interface "${VETH2}" --count 4 &
    local sniffer_pid=$!
    echo "${sniffer_pid}" > /tmp/raw_sniffer_week01.pid

    # Give sniffer half a second to initialize raw socket
    sleep 0.8

    log_info "Sending ICMP Echo Requests from namespace '${NS1}' to '${RAW_IP_NS2}'..."
    ip netns exec "${NS1}" ping -c 2 -W 1 "${RAW_IP_NS2}" >/dev/null 2>&1 || true

    log_info "Waiting for sniffer to finish capturing packets..."
    wait "${sniffer_pid}" || true
    rm -f /tmp/raw_sniffer_week01.pid

    log_success "Capture demonstration complete."
}

# --- Command-line Interface Dispatcher ---
print_usage() {
    echo -e "${BOLD}Usage:${NC} sudo $0 [command]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}setup${NC}    Create isolated namespaces (ns1, ns2) and veth pair with IPs"
    echo -e "  ${GREEN}test${NC}     Run bidirectional ICMP ping tests between namespaces"
    echo -e "  ${GREEN}capture${NC}  Run raw_sniffer.py in ns2 while generating traffic from ns1"
    echo -e "  ${GREEN}status${NC}   Show current namespaces, interfaces, and IP configurations"
    echo -e "  ${GREEN}clean${NC}    Tear down and remove all created namespaces and virtual links"
    echo -e "  ${GREEN}help${NC}     Show this help message"
    echo ""
    echo -e "${BOLD}Default:${NC} If no command is provided, '${BOLD}setup${NC}' followed by '${BOLD}test${NC}' will run."
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
        capture)
            capture_demo
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
            log_info "Tip: Run 'sudo $0 capture' to test packet sniffing inside the namespace."
            ;;
        *)
            log_error "Unknown command: ${cmd}"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"
