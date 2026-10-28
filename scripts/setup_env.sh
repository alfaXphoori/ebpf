#!/usr/bin/env bash
# ==============================================================================
# eBPF Development Environment Setup Script
# Target: Ubuntu 24.04 LTS (Linux 6.8+) / Ubuntu 26.04 LTS (Linux 7.0+)
# ==============================================================================

set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Resolve repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${CYAN}======================================================================"
echo -e "   eBPF Zero-to-Hero Environment Provisioning (Ubuntu 24.04 / 26.04 LTS)"
echo -e "======================================================================${NC}"
echo "Repository Root: ${REPO_ROOT}"
echo "Kernel Release : $(uname -r)"
echo "Kernel Version : $(uname -v)"
echo "Architecture   : $(uname -m)"
echo ""

# 1. Check Root/Sudo Privileges
log_info "1. Checking privileges..."
if [[ "${EUID}" -ne 0 ]]; then
    log_error "This script requires superuser privileges to install packages and access BTF/LSM."
    echo "Please run with sudo: sudo $0"
    exit 1
fi
log_success "Running as root."

# 2. Kernel Version Verification
log_info "2. Verifying kernel version requirements..."
KERNEL_MAJOR=$(uname -r | cut -d'.' -f1)
KERNEL_MINOR=$(uname -r | cut -d'.' -f2)

if (( KERNEL_MAJOR < 5 || (KERNEL_MAJOR == 5 && KERNEL_MINOR < 15) )); then
    log_warn "Current kernel is $(uname -r). eBPF modern features (CO-RE, Ring Buffer, BPF LSM) require 5.15+ (6.8+ recommended)."
else
    log_success "Kernel version $(uname -r) meets minimum requirements (>= 5.15)."
fi

# 3. Verify BTF Support in Running Kernel
log_info "3. Verifying kernel BTF (BPF Type Format) support..."
if [[ -f "/sys/kernel/btf/vmlinux" ]]; then
    log_success "Kernel BTF found at /sys/kernel/btf/vmlinux."
else
    log_error "Kernel BTF NOT found at /sys/kernel/btf/vmlinux!"
    log_error "CONFIG_DEBUG_INFO_BTF=y is required for modern eBPF (CO-RE, vmlinux.h)."
    log_error "Please ensure your kernel is compiled with BTF support or update to an Ubuntu official kernel."
    exit 1
fi

# 4. Package Installation
log_info "4. Updating package lists and installing core eBPF dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y

BASE_PACKAGES=(
    clang
    llvm
    libbpf-dev
    libelf-dev
    zlib1g-dev
    linux-tools-common
    ethtool
    bpftrace
    golang-go
    python3-bpfcc
    bpfcc-tools
    iproute2
    tcpdump
    netcat-openbsd
    curl
    jq
    strace
    make
    git
    pkg-config
)

log_info "Installing standard toolchain packages..."
apt-get install -y --no-install-recommends "${BASE_PACKAGES[@]}"

# Handle kernel-specific packages (linux-headers and linux-tools)
CURRENT_KERNEL="$(uname -r)"
log_info "Attempting to install kernel-specific headers: linux-headers-${CURRENT_KERNEL}..."
if ! apt-get install -y "linux-headers-${CURRENT_KERNEL}"; then
    log_warn "Could not install exact linux-headers-${CURRENT_KERNEL}. Installing linux-headers-generic..."
    apt-get install -y linux-headers-generic
fi

log_info "Attempting to install kernel-specific tools: linux-tools-${CURRENT_KERNEL}..."
if ! apt-get install -y "linux-tools-${CURRENT_KERNEL}"; then
    log_warn "Could not install exact linux-tools-${CURRENT_KERNEL}. Installing linux-tools-generic..."
    apt-get install -y linux-tools-generic
fi

log_success "All prerequisite packages successfully installed."

# Ensure /usr/include/{asm,sys,bits,gnu} symlinks exist for clang -target bpf
ARCH_TRIPLET="$(gcc -dumpmachine 2>/dev/null || echo "$(uname -m)-linux-gnu")"
for dir in asm sys bits gnu; do
    if [[ ! -e "/usr/include/${dir}" && -d "/usr/include/${ARCH_TRIPLET}/${dir}" ]]; then
        ln -sf "/usr/include/${ARCH_TRIPLET}/${dir}" "/usr/include/${dir}"
        log_success "Linked /usr/include/${dir} -> /usr/include/${ARCH_TRIPLET}/${dir} for clang -target bpf."
    fi
done

# 5. Generate vmlinux.h
log_info "5. Generating vmlinux.h for CO-RE development..."
VMLINUX_TARGET="${REPO_ROOT}/vmlinux.h"

if command -v bpftool &> /dev/null; then
    log_info "Extracting BTF types to ${VMLINUX_TARGET}..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_TARGET}"
    if [[ -s "${VMLINUX_TARGET}" ]]; then
        LINE_COUNT=$(wc -l < "${VMLINUX_TARGET}")
        log_success "Generated ${VMLINUX_TARGET} successfully (${LINE_COUNT} lines)."
    else
        log_error "Generated ${VMLINUX_TARGET} is empty!"
        exit 1
    fi
else
    log_error "bpftool command not found in PATH! Make sure linux-tools or bpftool is installed."
    exit 1
fi

# 6. Verify BPF LSM Support
log_info "6. Checking Linux Security Module (LSM) configuration for BPF..."
LSM_PATH="/sys/kernel/security/lsm"
if [[ -f "${LSM_PATH}" ]]; then
    ACTIVE_LSMS=$(cat "${LSM_PATH}")
    log_info "Active LSMs: ${ACTIVE_LSMS}"
    if [[ "${ACTIVE_LSMS}" =~ "bpf" ]]; then
        log_success "BPF LSM is ENABLED in the running kernel."
    else
        log_warn "BPF LSM is NOT active in /sys/kernel/security/lsm."
        echo -e "${YELLOW}----------------------------------------------------------------------"
        echo "To enable BPF LSM for Chapter 5 / Week 10 exercises, execute:"
        echo "1. Edit /etc/default/grub:"
        echo '   GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"'
        echo "2. Update GRUB and reboot:"
        echo "   sudo update-grub"
        echo "   sudo reboot"
        echo -e "----------------------------------------------------------------------${NC}"
    fi
else
    log_warn "/sys/kernel/security/lsm not found. SecurityFS may not be mounted."
fi

# 7. Environment Verification Summary
echo ""
echo -e "${CYAN}======================================================================"
echo -e "   eBPF Toolchain Verification Summary"
echo -e "======================================================================${NC}"
echo -n "Clang Version     : "; clang --version | head -n 1
echo -n "LLVM Version      : "; llc --version | head -n 2 | tr '\n' ' ' && echo ""
echo -n "bpftool Version   : "; bpftool version | head -n 1
echo -n "bpftrace Version  : "; bpftrace --version | head -n 1
echo -n "Go Version        : "; go version
echo -n "Python BCC        : "; python3 -c "import bcc; print('bcc available:', bcc.__file__)" 2>/dev/null || echo "BCC Python module check skipped/warning"
echo -n "vmlinux.h Status  : "; ls -lh "${VMLINUX_TARGET}"
echo -e "${GREEN}======================================================================"
echo -e " Environment setup completed successfully! You are ready to build eBPF."
echo -e "======================================================================${NC}"
