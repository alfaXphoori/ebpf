#!/usr/bin/env python3
# Week 14 test client (same code as README step 4). Usage: python3 client.py [--in-cgroup] [--bypass]
import socket, errno, sys
def tryit(label, fn):
    try: fn(); print(f"  {label:<48} -> OK (not blocked)")
    except OSError as e: print(f"  {label:<48} -> {errno.errorcode.get(e.errno)} ({e.strerror})")
def tcp4(h, p):
    def f():
        s = socket.socket(); s.settimeout(1)
        try: s.connect((h, p))
        finally: s.close()
    return f
def udp4_connect(h, p):
    def f():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect((h, p))
        finally: s.close()
    return f
def udp4_sendto(h, p):
    def f():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.sendto(b"x", (h, p))
        finally: s.close()
    return f
def tcp6_mapped(h, p):
    def f():
        s = socket.socket(socket.AF_INET6); s.settimeout(1)
        try: s.connect(("::ffff:" + h, p))
        finally: s.close()
    return f
print("cgroup of client:", open("/proc/self/cgroup").read().strip())
tryit("TCP  connect 127.0.0.1:2323 (blocked port)", tcp4("127.0.0.1", 2323))
tryit("TCP  connect 127.0.0.1:8080 (allowed port)", tcp4("127.0.0.1", 8080))
if "--in-cgroup" in sys.argv:   # ไม่ทดสอบ IP ภายนอกจากนอก cgroup เพื่อไม่ให้มี SYN ออกไปจริง
    tryit("TCP  connect 10.99.99.99:80 (blocked IP)", tcp4("10.99.99.99", 80))
tryit("UDP  connect 127.0.0.1:2323 (blocked port)", udp4_connect("127.0.0.1", 2323))
if "--bypass" in sys.argv:
    tryit("UDP  sendto 127.0.0.1:2323 without connect()", udp4_sendto("127.0.0.1", 2323))
    tryit("TCP6 connect [::ffff:127.0.0.1]:2323 (v4-mapped)", tcp6_mapped("127.0.0.1", 2323))
