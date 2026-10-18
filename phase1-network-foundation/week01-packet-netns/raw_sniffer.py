#!/usr/bin/env python3
"""
================================================================================
eBPF Noob to Hero - Week 01: Low-Level Packet Sniffer
Script: raw_sniffer.py
Description: Captures raw Layer 2 Ethernet frames using Linux AF_PACKET raw sockets
             and performs manual byte-level header parsing and bitwise flag extraction
             (Ethernet, IPv4, ARP, TCP, UDP, ICMP) without external dependencies.
Author: eBPF Mastery Team
================================================================================
"""

import argparse
import os
import signal
import socket
import struct
import sys
import time
from typing import Optional, Tuple

# ANSI Color Codes for terminal formatting
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[0;31m"
CLR_GREEN = "\033[0;32m"
CLR_YELLOW = "\033[0;33m"
CLR_BLUE = "\033[0;34m"
CLR_MAGENTA = "\033[0;35m"
CLR_CYAN = "\033[0;36m"
CLR_DIM = "\033[2m"

# Packet statistics counter
STATS = {
    "total": 0,
    "ipv4": 0,
    "arp": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
}


def format_mac(raw_mac: bytes) -> str:
    """Format 6-byte raw hardware address into human-readable MAC format (XX:XX:XX:XX:XX:XX)."""
    return ":".join(f"{b:02x}" for b in raw_mac)


def format_hexdump(data: bytes, length_per_line: int = 16, max_bytes: int = 64) -> str:
    """
    Generate canonical hex + ASCII dump formatted string for packet payload.
    """
    if not data:
        return f"{CLR_DIM}    <empty payload>{CLR_RESET}"

    lines = []
    display_data = data[:max_bytes]

    for i in range(0, len(display_data), length_per_line):
        chunk = display_data[i : i + length_per_line]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex representation to align ASCII output
        padding = "   " * (length_per_line - len(chunk))

        # Printable ASCII or dot
        ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"    {i:04x}:  {hex_bytes}{padding}  |{ascii_text}|")

    if len(data) > max_bytes:
        lines.append(f"    {CLR_DIM}... ({len(data) - max_bytes} more bytes omitted) ...{CLR_RESET}")

    return "\n".join(lines)


def parse_ethernet(packet: bytes) -> Tuple[str, str, int, bytes]:
    """
    Parse 14-byte Ethernet II header:
    - Destination MAC (6 bytes) [0..5]
    - Source MAC (6 bytes)      [6..11]
    - EtherType (2 bytes)       [12..13]
    """
    eth_header = packet[:14]
    dst_mac_raw, src_mac_raw, ether_type = struct.unpack("!6s6sH", eth_header)
    payload = packet[14:]
    return format_mac(dst_mac_raw), format_mac(src_mac_raw), ether_type, payload


def parse_arp(data: bytes) -> dict:
    """
    Parse 28-byte ARP header (RFC 826):
    - Hardware Type (2B), Protocol Type (2B)
    - Hardware Size (1B), Protocol Size (1B)
    - Opcode (2B: 1=Request, 2=Reply)
    - Sender MAC (6B), Sender IP (4B)
    - Target MAC (6B), Target IP (4B)
    """
    arp_fields = struct.unpack("!HHBBH6s4s6s4s", data[:28])
    hw_type, proto_type, hw_len, proto_len, opcode = arp_fields[0:5]
    sender_mac = format_mac(arp_fields[5])
    sender_ip = socket.inet_ntoa(arp_fields[6])
    target_mac = format_mac(arp_fields[7])
    target_ip = socket.inet_ntoa(arp_fields[8])

    opcode_name = {1: "ARP Request", 2: "ARP Reply"}.get(opcode, f"Unknown ({opcode})")
    return {
        "hw_type": hw_type,
        "proto_type": hex(proto_type),
        "opcode": opcode_name,
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip,
    }


def parse_ipv4(data: bytes) -> Tuple[dict, bytes]:
    """
    Parse IPv4 Header (RFC 791, 20 bytes minimum):
    - Version & IHL (1B): Version (4b), Internet Header Length (4b)
    - Type of Service / DSCP+ECN (1B)
    - Total Length (2B)
    - Identification (2B)
    - Flags & Fragment Offset (2B)
    - Time To Live (1B)
    - Protocol (1B: 1=ICMP, 6=TCP, 17=UDP)
    - Header Checksum (2B)
    - Source IP (4B)
    - Destination IP (4B)
    """
    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    tos = iph[1]
    total_length = iph[2]
    identification = iph[3]
    flags_frag = iph[4]
    ttl = iph[5]
    protocol = iph[6]
    checksum = iph[7]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    # Extract IP payload after IHL bytes
    l4_payload = data[ihl:]

    ip_info = {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "total_length": total_length,
        "id": identification,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": hex(checksum),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }
    return ip_info, l4_payload


def parse_tcp(data: bytes) -> Tuple[dict, bytes]:
    """
    Parse TCP Header (RFC 793, 20 bytes minimum):
    - Source Port (2B), Destination Port (2B)
    - Sequence Number (4B)
    - Acknowledgment Number (4B)
    - Data Offset & Reserved (1B): Data Offset (4b) * 4 bytes
    - TCP Flags (1B): URG, ACK, PSH, RST, SYN, FIN
    - Window Size (2B)
    - Checksum (2B), Urgent Pointer (2B)
    """
    tcph = struct.unpack("!HHLLBBHHH", data[:20])
    src_port = tcph[0]
    dst_port = tcph[1]
    seq = tcph[2]
    ack = tcph[3]
    offset_reserved = tcph[4]
    tcp_header_len = (offset_reserved >> 4) * 4
    flags = tcph[5]
    window = tcph[6]
    checksum = tcph[7]
    urg_ptr = tcph[8]

    flag_names = []
    if flags & 0x20:
        flag_names.append("URG")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x01:
        flag_names.append("FIN")

    flags_str = "|".join(flag_names) if flag_names else "NONE"
    payload = data[tcp_header_len:]

    tcp_info = {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "header_len": tcp_header_len,
        "flags": flags_str,
        "window": window,
        "checksum": hex(checksum),
    }
    return tcp_info, payload


def parse_udp(data: bytes) -> Tuple[dict, bytes]:
    """
    Parse UDP Header (RFC 768, 8 bytes):
    - Source Port (2B), Destination Port (2B)
    - Length (2B)
    - Checksum (2B)
    """
    udph = struct.unpack("!HHHH", data[:8])
    src_port = udph[0]
    dst_port = udph[1]
    length = udph[2]
    checksum = udph[3]
    payload = data[8:length]

    udp_info = {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": hex(checksum),
    }
    return udp_info, payload


def parse_icmp(data: bytes) -> Tuple[dict, bytes]:
    """
    Parse ICMP Header (RFC 792, 4 bytes minimum):
    - Type (1B): 0=Echo Reply, 8=Echo Request, 3=Dest Unreachable
    - Code (1B)
    - Checksum (2B)
    """
    icmph = struct.unpack("!BBH", data[:4])
    icmp_type = icmph[0]
    icmp_code = icmph[1]
    checksum = icmph[2]

    type_desc = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request",
        11: "Time Exceeded",
    }.get(icmp_type, f"Type {icmp_type}")

    payload = data[4:]

    icmp_info = {
        "type": icmp_type,
        "code": icmp_code,
        "type_desc": type_desc,
        "checksum": hex(checksum),
    }
    return icmp_info, payload


def print_stats_summary():
    """Display final captured packet statistics."""
    print(f"\n{CLR_BOLD}========== Packet Capture Statistics =========={CLR_RESET}")
    print(f"  Total Packets Captured : {STATS['total']}")
    print(f"  IPv4 Packets           : {STATS['ipv4']}")
    print(f"    - TCP Packets        : {STATS['tcp']}")
    print(f"    - UDP Packets        : {STATS['udp']}")
    print(f"    - ICMP Packets       : {STATS['icmp']}")
    print(f"    - Other L4 Protocols : {STATS['other']}")
    print(f"  ARP Packets            : {STATS['arp']}")
    print(f"{CLR_BOLD}==============================================={CLR_RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Week 01: Low-level Packet Sniffer using Linux AF_PACKET raw socket."
    )
    parser.add_argument(
        "-i", "--interface",
        default="",
        help="Interface to bind and capture on (e.g. veth2, eth0). Default: all interfaces."
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture before stopping (0 = continuous). Default: 0."
    )
    parser.add_argument(
        "-p", "--protocol",
        choices=["all", "tcp", "udp", "icmp", "arp"],
        default="all",
        help="Filter capture by Layer 4 / ARP protocol. Default: all."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed hexdump of packet payload."
    )
    args = parser.parse_args()

    # Graceful exit handler
    def sigint_handler(sig, frame):
        print(f"\n{CLR_YELLOW}[!] Interrupted by user. Exiting...{CLR_RESET}")
        print_stats_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    # Check for AF_PACKET availability (Linux-specific raw socket)
    if not hasattr(socket, "AF_PACKET"):
        print(f"{CLR_RED}[ERROR] socket.AF_PACKET is only supported on Linux!{CLR_RESET}", file=sys.stderr)
        print("Note: Run this script inside a Linux virtual machine, WSL2, or container namespace.", file=sys.stderr)
        sys.exit(1)

    # Check root privileges required for RAW socket creation
    if os.geteuid() != 0:
        print(f"{CLR_RED}[ERROR] Raw sockets require root privileges!{CLR_RESET}", file=sys.stderr)
        print(f"Please run: sudo python3 {sys.argv[0]} [options]", file=sys.stderr)
        sys.exit(1)

    # Create raw socket to capture all Layer 2 Ethernet frames (ETH_P_ALL = 0x0003)
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if args.interface:
            raw_sock.bind((args.interface, 0))
            bind_target = f"interface '{args.interface}'"
        else:
            bind_target = "all interfaces"
    except PermissionError:
        print(f"{CLR_RED}[ERROR] Operation not permitted. Superuser (root) required.{CLR_RESET}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"{CLR_RED}[ERROR] Failed to bind raw socket: {e}{CLR_RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"{CLR_CYAN}{CLR_BOLD}======================================================{CLR_RESET}")
    print(f"{CLR_GREEN}{CLR_BOLD} eBPF Noob to Hero - Week 01: Low-Level Raw Sniffer   {CLR_RESET}")
    print(f"{CLR_CYAN}{CLR_BOLD}======================================================{CLR_RESET}")
    print(f" Capturing on : {CLR_BOLD}{bind_target}{CLR_RESET}")
    print(f" Filter       : {CLR_BOLD}{args.protocol.upper()}{CLR_RESET}")
    print(f" Count limit  : {CLR_BOLD}{args.count if args.count > 0 else 'Unlimited'}{CLR_RESET}")
    print(f" Verbose dump : {CLR_BOLD}{'Enabled' if args.verbose else 'Disabled'}{CLR_RESET}")
    print(f" Press {CLR_YELLOW}Ctrl+C{CLR_RESET} at any time to stop and view statistics.")
    print(f"{CLR_CYAN}------------------------------------------------------{CLR_RESET}\n")

    captured = 0
    try:
        while True:
            if args.count > 0 and captured >= args.count:
                break

            packet, _ = raw_sock.recvfrom(65535)
            if len(packet) < 14:
                continue

            STATS["total"] += 1
            dst_mac, src_mac, eth_type, l3_payload = parse_ethernet(packet)
            timestamp = time.strftime("%H:%M:%S")

            # --- ARP Frame (EtherType = 0x0806) ---
            if eth_type == 0x0806:
                STATS["arp"] += 1
                if args.protocol not in ["all", "arp"]:
                    continue

                captured += 1
                arp_data = parse_arp(l3_payload)
                print(f"[{timestamp}] {CLR_YELLOW}[ARP]{CLR_RESET} {src_mac} -> {dst_mac} | {arp_data['opcode']}: Who has {arp_data['target_ip']}? Tell {arp_data['sender_ip']}")
                if args.verbose:
                    print(format_hexdump(l3_payload))
                continue

            # --- IPv4 Frame (EtherType = 0x0800) ---
            if eth_type == 0x0800:
                STATS["ipv4"] += 1
                if len(l3_payload) < 20:
                    continue

                ip_info, l4_payload = parse_ipv4(l3_payload)
                proto = ip_info["protocol"]

                # 1 = ICMP
                if proto == 1:
                    STATS["icmp"] += 1
                    if args.protocol not in ["all", "icmp"]:
                        continue

                    captured += 1
                    icmp_info, payload = parse_icmp(l4_payload)
                    print(
                        f"[{timestamp}] {CLR_MAGENTA}[ICMP]{CLR_RESET} "
                        f"{ip_info['src_ip']} -> {ip_info['dst_ip']} | "
                        f"{icmp_info['type_desc']} (Code {icmp_info['code']}) TTL={ip_info['ttl']} Len={ip_info['total_length']}"
                    )
                    if args.verbose and payload:
                        print(format_hexdump(payload))

                # 6 = TCP
                elif proto == 6:
                    STATS["tcp"] += 1
                    if args.protocol not in ["all", "tcp"]:
                        continue

                    captured += 1
                    tcp_info, payload = parse_tcp(l4_payload)
                    print(
                        f"[{timestamp}] {CLR_GREEN}[TCP]{CLR_RESET}  "
                        f"{ip_info['src_ip']}:{tcp_info['src_port']} -> {ip_info['dst_ip']}:{tcp_info['dst_port']} "
                        f"[{tcp_info['flags']}] Seq={tcp_info['seq']} Ack={tcp_info['ack']} Win={tcp_info['window']}"
                    )
                    if args.verbose and payload:
                        print(format_hexdump(payload))

                # 17 = UDP
                elif proto == 17:
                    STATS["udp"] += 1
                    if args.protocol not in ["all", "udp"]:
                        continue

                    captured += 1
                    udp_info, payload = parse_udp(l4_payload)
                    print(
                        f"[{timestamp}] {CLR_BLUE}[UDP]{CLR_RESET}  "
                        f"{ip_info['src_ip']}:{udp_info['src_port']} -> {ip_info['dst_ip']}:{udp_info['dst_port']} "
                        f"Len={udp_info['length']} Checksum={udp_info['checksum']}"
                    )
                    if args.verbose and payload:
                        print(format_hexdump(payload))

                else:
                    STATS["other"] += 1
                    if args.protocol == "all":
                        captured += 1
                        print(f"[{timestamp}] [IPv4-Other] Proto={proto} {ip_info['src_ip']} -> {ip_info['dst_ip']}")

            else:
                # Other Layer 2 protocols (e.g. IPv6 0x86DD)
                if args.protocol == "all":
                    print(f"[{timestamp}] [L2-Other] EtherType={hex(eth_type)} {src_mac} -> {dst_mac}")

    except KeyboardInterrupt:
        pass
    finally:
        print_stats_summary()
        raw_sock.close()


if __name__ == "__main__":
    main()
