#!/usr/bin/env python3
# Week 14 section 4.3: a socket created BEFORE joining the cgroup keeps its old cgroup.
# Run as root while sock-enforce is attached: sudo python3 precreate.py
import os, socket
CG = "/sys/fs/cgroup/w14-sock-enforce/cgroup.procs"
before = socket.socket()                       # created while still outside
open(CG, "w").write(str(os.getpid()))          # join the test cgroup
after = socket.socket()                        # created inside the cgroup
print("now in:", open("/proc/self/cgroup").read().strip())
for label, s in (("socket created BEFORE joining cgroup", before),
                 ("socket created AFTER joining cgroup", after)):
    try: s.connect(("127.0.0.1", 2323)); print(f"  {label:<40} -> connected")
    except OSError as e: print(f"  {label:<40} -> {e}")
