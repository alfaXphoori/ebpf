#!/usr/bin/env python3
"""Unit tests for Week 01 raw_sniffer.py packet parsers (no root required)."""

import socket
import struct
import unittest

import raw_sniffer


class TestRawSnifferParsers(unittest.TestCase):
    def test_parse_ethernet_ipv4(self):
        dst = b"\xaa\xbb\xcc\xdd\xee\xff"
        src = b"\x11\x22\x33\x44\x55\x66"
        frame = dst + src + struct.pack("!H", 0x0800) + b"payload"
        dst_mac, src_mac, eth_type, payload = raw_sniffer.parse_ethernet(frame)
        self.assertEqual(dst_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(src_mac, "11:22:33:44:55:66")
        self.assertEqual(eth_type, 0x0800)
        self.assertEqual(payload, b"payload")

    def test_parse_arp_request(self):
        pkt = struct.pack(
            "!HHBBH6s4s6s4s",
            1,
            0x0800,
            6,
            4,
            1,
            b"\x01\x02\x03\x04\x05\x06",
            socket.inet_aton("10.10.1.1"),
            b"\x00" * 6,
            socket.inet_aton("10.10.1.2"),
        )
        info = raw_sniffer.parse_arp(pkt)
        self.assertEqual(info["opcode"], "ARP Request")
        self.assertEqual(info["sender_ip"], "10.10.1.1")
        self.assertEqual(info["target_ip"], "10.10.1.2")

    def test_parse_ipv4_with_options(self):
        ver_ihl = (4 << 4) | 6  # 24 bytes (4 bytes of IP options)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            0,
            28,
            0x1234,
            0,
            64,
            6,
            0xBEEF,
            socket.inet_aton("10.10.1.1"),
            socket.inet_aton("10.10.1.2"),
        ) + b"\x01\x01\x01\x01"
        info, l4 = raw_sniffer.parse_ipv4(ip_hdr + b"ABCD")
        self.assertEqual(info["version"], 4)
        self.assertEqual(info["ihl"], 24)
        self.assertEqual(info["protocol"], 6)
        self.assertEqual(info["src_ip"], "10.10.1.1")
        self.assertEqual(info["dst_ip"], "10.10.1.2")
        self.assertEqual(l4, b"ABCD")

    def test_parse_tcp_flags_and_payload(self):
        tcp_hdr = struct.pack(
            "!HHLLBBHHH",
            12345,
            80,
            100,
            200,
            5 << 4,  # 20 bytes header
            0x12,    # SYN|ACK
            65535,
            0xCAFE,
            0,
        )
        info, payload = raw_sniffer.parse_tcp(tcp_hdr + b"GET /")
        self.assertEqual(info["src_port"], 12345)
        self.assertEqual(info["dst_port"], 80)
        self.assertEqual(info["flags"], "ACK|SYN")
        self.assertEqual(payload, b"GET /")

    def test_parse_udp_respects_length(self):
        udp_hdr = struct.pack("!HHHH", 5000, 9999, 13, 0x1111)
        info, payload = raw_sniffer.parse_udp(udp_hdr + b"helloTRAILING")
        self.assertEqual(info["src_port"], 5000)
        self.assertEqual(info["dst_port"], 9999)
        self.assertEqual(info["length"], 13)
        self.assertEqual(payload, b"hello")

    def test_parse_icmp_echo_request(self):
        icmp = struct.pack("!BBHHH", 8, 0, 0x1234, 42, 7) + b"ping"
        info, payload = raw_sniffer.parse_icmp(icmp)
        self.assertEqual(info["type"], 8)
        self.assertEqual(info["type_desc"], "Echo Request")
        self.assertEqual(payload, struct.pack("!HH", 42, 7) + b"ping")


if __name__ == "__main__":
    unittest.main()
