#!/usr/bin/env python3
"""
================================================================================
eBPF Noob to Hero - Week 04: Kernel Tracing with BCC (BPF Compiler Collection)
Script: tcp_v4_latency.py
Description: Measures TCP IPv4 connection establishment latency (SYN -> SYN-ACK -> ACK)
             by hooking kprobe/kretprobe on tcp_v4_connect, correlating timestamps
             using a BPF Hash Map, streaming events via BPF Perf Ring Buffer, and
             computing a logarithmic microsecond latency histogram.
Author: eBPF Mastery Team
================================================================================
"""

import ctypes
import os
import signal
import socket
import struct
import sys
import time

# Try importing BCC module with informative fallback guidance
try:
    from bcc import BPF
except ImportError:
    print(
        "\033[0;31m[ERROR] The 'bcc' Python module is not installed or not found.\033[0m\n"
        "BCC requires a Linux system with kernel headers and BCC packages installed.\n\n"
        "Installation on Ubuntu / Debian:\n"
        "  sudo apt-get update\n"
        "  sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)\n\n"
        "Installation on Fedora / RHEL 9:\n"
        "  sudo dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r)\n",
        file=sys.stderr,
    )
    sys.exit(1)

# --- eBPF C Source Code (Compiled at runtime by embedded Clang/LLVM inside BCC) ---
EBPF_C_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/in.h>

// Struct storing active connection initiation metadata in kernel memory
struct conn_info_t {
    u64 ts;                     // Timestamp in nanoseconds (bpf_ktime_get_ns)
    struct sock *sk;            // Socket pointer for L4 state tracking
    u32 pid;                    // Process ID (TGID)
    u32 daddr;                  // Destination IPv4 address
    u16 dport;                  // Destination TCP port
    char comm[TASK_COMM_LEN];   // Executable process name
};

// Struct streamed to user space via BPF_PERF_OUTPUT
struct event_t {
    u64 delta_us;               // Connection latency in microseconds
    u32 pid;                    // Process ID
    u32 saddr;                  // Source IPv4 address
    u32 daddr;                  // Destination IPv4 address
    u16 sport;                  // Source TCP port
    u16 dport;                  // Destination TCP port
    char comm[TASK_COMM_LEN];   // Process name
};

// BPF Maps:
// 1. Hash map correlating kprobe entry with kretprobe exit keyed by (pid_tgid)
BPF_HASH(start_ts, u64, struct conn_info_t);

// 2. Perf Event Output channel to transfer structured events to user space
BPF_PERF_OUTPUT(events);

// 3. Logarithmic histogram tracking connection latency in microseconds
BPF_HISTOGRAM(dist);

/**
 * Hook 1: Entry probe for tcp_v4_connect()
 * Signature: int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 */
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct conn_info_t info = {};

    info.ts = bpf_ktime_get_ns();
    info.sk = sk;
    info.pid = pid_tgid >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // Cast sockaddr to sockaddr_in to extract IPv4 destination and port
    struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&info.daddr, sizeof(info.daddr), &usin->sin_addr.s_addr);
    bpf_probe_read_kernel(&info.dport, sizeof(info.dport), &usin->sin_port);

    // Save timestamp and socket context into hash map
    start_ts.update(&pid_tgid, &info);
    return 0;
}

/**
 * Hook 2: Return probe for tcp_v4_connect()
 * Evaluates connection return code and calculates latency delta
 */
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct conn_info_t *infop = start_ts.lookup(&pid_tgid);
    if (!infop) {
        return 0; // Missed entry probe or interrupted
    }

    // Return code 0 indicates immediate success; -EINPROGRESS (-115) indicates non-blocking connect in progress
    if (ret != 0 && ret != -115) {
        // Connection attempt failed directly
        start_ts.delete(&pid_tgid);
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 delta_us = (now - infop->ts) / 1000;

    struct event_t event = {};
    event.delta_us = delta_us;
    event.pid = infop->pid;
    event.daddr = infop->daddr;
    event.dport = infop->dport;
    __builtin_memcpy(event.comm, infop->comm, sizeof(event.comm));

    // Read bound source IP and ephemeral source port from struct sock
    struct sock *sk = infop->sk;
    if (sk) {
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    }

    // Submit structured event to User Space via Perf Event Ring Buffer
    events.perf_submit(ctx, &event, sizeof(event));

    // Record latency value into power-of-two histogram
    dist.increment(bpf_log2l(delta_us));

    // Cleanup hash entry to prevent memory exhaustion
    start_ts.delete(&pid_tgid);
    return 0;
}
"""

# --- Python User-Space Data Structures (Matching C struct event_t) ---
TASK_COMM_LEN = 16


class Event(ctypes.Structure):
    _fields_ = [
        ("delta_us", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("saddr", ctypes.c_uint),
        ("daddr", ctypes.c_uint),
        ("sport", ctypes.c_ushort),
        ("dport", ctypes.c_ushort),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


# Format IP from 32-bit unsigned integer (Host/Network format)
def ip_to_str(addr_int: int) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr_int))
    except Exception:
        return "0.0.0.0"


def main():
    if os.geteuid() != 0:
        print("\033[0;31m[ERROR] Root privileges required to load eBPF programs.\033[0m", file=sys.stderr)
        print(f"Please run: sudo python3 {sys.argv[0]}", file=sys.stderr)
        sys.exit(1)

    print("\033[1;36m========================================================================\033[0m")
    print("\033[1;32m  eBPF Noob to Hero - Week 04: TCP IPv4 Connect Latency Tracker (BCC)   \033[0m")
    print("\033[1;36m========================================================================\033[0m")
    print(" Compiling embedded C eBPF code via LLVM/Clang and attaching kprobes...")

    start_compile = time.time()
    b = BPF(text=EBPF_C_PROGRAM)
    compile_duration = (time.time() - start_compile) * 1000
    print(f" JIT compilation & Kernel attach completed in \033[1;33m{compile_duration:.1f} ms\033[0m.\n")

    print(" Tracing active IPv4 TCP outbound connection latency (SYN initiation).")
    print(" Hit \033[1;33mCtrl+C\033[0m to terminate and view microsecond latency histogram.\n")
    print(
        f"{'TIME':<9} {'PID':<7} {'COMM':<16} "
        f"{'SRC ADDR:PORT':<22} {'DST ADDR:PORT':<22} {'LATENCY (us)':<12}"
    )
    print("-" * 92)

    # Callback invoked by BCC when a new event arrives in the Perf Buffer
    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        timestamp = time.strftime("%H:%M:%S")

        src_ip = ip_to_str(event.saddr)
        dst_ip = ip_to_str(event.daddr)
        src_port = event.sport
        # dport was stored in Network Byte Order inside sockaddr_in
        dst_port = socket.ntohs(event.dport)
        comm_name = event.comm.decode("utf-8", "replace")

        src_endpoint = f"{src_ip}:{src_port}" if src_port > 0 else f"{src_ip}:*"
        dst_endpoint = f"{dst_ip}:{dst_port}"

        print(
            f"{timestamp:<9} {event.pid:<7} {comm_name:<16} "
            f"{src_endpoint:<22} {dst_endpoint:<22} {event.delta_us:<12}"
        )

    # Open Perf Event Ring Buffer
    b["events"].open_perf_buffer(handle_event, page_cnt=64)

    stop_flag = False
    def sig_handler(signum, frame):
        nonlocal stop_flag
        stop_flag = True

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # Main event polling loop
    try:
        while not stop_flag:
            b.perf_buffer_poll(timeout=200)
    except KeyboardInterrupt:
        pass
    print("\n\n\033[1;33m[!] Detaching eBPF probes and generating latency distribution...\033[0m\n")

    # Output log2 histogram
    print("\033[1;36m========================================================================\033[0m")
    print("\033[1;32m           TCP Outbound Connection Latency Histogram (usecs)           \033[0m")
    print("\033[1;36m========================================================================\033[0m")
    b["dist"].print_log2_hist("Latency (us)")
    print("\033[1;36m========================================================================\033[0m")
    print("eBPF session concluded safely. All kernel maps freed.\n")


if __name__ == "__main__":
    main()
