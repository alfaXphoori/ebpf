# แนวทางเฉลยและวิธีเช็กผลแบบฝึกหัด (Exercise Solutions)

> [!TIP]
> รวม **ไอเดียหลัก จุดที่ต้องแก้ในโค้ด จุดที่ verifier ชอบฟ้อง และคำสั่งไว้เช็กผล** ครบทั้ง **26 สัปดาห์** (3 ระดับ: พื้นฐาน / ปานกลาง / ท้าทาย) อ้างอิงจากโค้ดจริงใน repo นี้

## สารบัญตามเฟส

| เฟส | หัวข้อหลัก | สัปดาห์ & README |
|---|---|---|
| เฟส 01 | ปูพื้นฐานเครือข่าย | [W01](../phase01-network-foundation/week01-packet-netns/README.md), [W02](../phase01-network-foundation/week02-linux-net-stack/README.md) |
| เฟส 02 | ก้าวแรกสู่ eBPF | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md), [W04](../phase02-first-step-ebpf/week04-bcc-python/README.md) |
| เฟส 03 | แกนหลัก eBPF ยุคใหม่ | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md), [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) |
| เฟส 04 | เน็ตเวิร์กความเร็วสูง | [W07](../phase04-high-speed-networking/week07-xdp-parsing/README.md), [W08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) |
| เฟส 05 | จับตาความปลอดภัย | [W09](../phase05-security-observability/week09-ringbuf-uprobes/README.md), [W10](../phase05-security-observability/week10-bpf-lsm/README.md) |
| เฟส 06 | โปรเจกต์รวมระบบ Production | [W11](../phase06-production-capstone/week11-verifier-prometheus/README.md), [W12](../phase06-production-capstone/week12-capstone-ips/README.md) |
| เฟส 07 | ความปลอดภัยขั้นสูง | [W13](../phase07-advanced-security-observability/week13-kfree-skb-dropwatch/README.md), [W14](../phase07-advanced-security-observability/week14-cgroup-sock-addr/README.md), [W15](../phase07-advanced-security-observability/week15-reverse-shell-guard/README.md), [W16](../phase07-advanced-security-observability/week16-ebpf-integrity-audit/README.md) |
| เฟส 08 | ดูประสิทธิภาพระบบ | [W17](../phase08-system-performance-observability/week17-block-io-biolatency/README.md), [W18](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md), [W19](../phase08-system-performance-observability/week19-memory-oom-watcher/README.md) |
| เฟส 09 | เร่งความเร็ว Socket & AF_XDP | [W20](../phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/README.md), [W21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) |
| เฟส 10 | Tracing ยุคใหม่ (`fentry`, Iterator) | [W22](../phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/README.md), [W23](../phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/README.md) |
| เฟส 11 | ต่อยอดเคอร์เนล & ระบบนิเวศ | [W24](../phase11-modern-ebpf-extensibility/week24-kfuncs-arena/README.md), [W25](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md), [W26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) |

---

## เฟส 01: ปูพื้นฐานเครือข่าย

### Week 01 — Packet & Network Namespaces ([README](../phase01-network-foundation/week01-packet-netns/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (ตัวกรองโปรโตคอล) | ใน `raw_sniffer.py` ย้ายหรือดูตำแหน่งที่อัปเดต `STATS` | ตอนนี้ `STATS` บวกค่าหลัง `parse_ipv4()` **ก่อน** บรรทัด `if args.protocol ...: continue` เลยยังเห็นยอด ICMP ในสรุปท้ายโปรแกรมแม้ไม่ได้พิมพ์แพ็กเก็ต |
| พื้นฐาน 2 (คำนวณ Offset) | อ่าน ICMP Header ต่อจาก IPv4 Header (`14 + ihl*4`) | Byte `0` Type, `1` Code, `2–3` Checksum, `4–5` ID (`struct.unpack("!H", ...)`), `6–7` Seq — เช็กเทียบกับ `tcpdump -ni w01-veth2 -c 2 -vv icmp` |
| ปานกลาง 3 (TCP Options MSS / WScale) | ถ้า `data_offset * 4 > 20` ให้วนอ่าน `raw[tcph_end : tcph_start + header_len]` แบบ TLV | `kind == 0` หยุด, `kind == 1` ข้าม 1 ไบต์, `kind == 2, len == 4` คือ `MSS`, `kind == 3, len == 3` คือ `WScale`, อื่นๆ ข้ามตาม `length` (เช็ก `length < 2` กัน loop ค้าง) |
| ปานกลาง 4 (IPv4 Checksum) | รวม 16-bit big-endian words ของ IPv4 header ทั้ง `header_len` ไบต์ | พับ carry 32-bit เป็น 16-bit (`(s & 0xffff) + (s >> 16)` ทำ 2 รอบ) แล้ว `~s & 0xffff` ต้องได้ `0` (แล็บปิด `tx off` ไว้แล้ว) |
| ท้าทาย 5 (Router 3 โหนด) | เพิ่ม `w01-r` พร้อม veth 2 คู่ (`10.10.1.254/24`, `10.10.2.254/24`) และ default route ใน `w01-ns1`/`w01-ns2` | เปิด `sudo ip netns exec w01-r sysctl -w net.ipv4.ip_forward=1` — ห้ามแก้ `sysctl` ของเครื่องหลัก |
| ท้าทาย 6 (Classic BPF Filter) | เอา bytecode จาก `tcpdump -dd icmp` ใส่ `ctypes` `sock_filter` + `sock_fprog` | ส่งเข้า `sock.setsockopt(socket.SOL_SOCKET, 26 /* SO_ATTACH_FILTER */, ...)` ให้เคอร์เนลกรองก่อนถึง `recvfrom()` |

### Week 02 — Linux Network Stack & Bridge ([README](../phase01-network-foundation/week02-linux-net-stack/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (FDB Ageing) | รัน `sudo ip netns exec w02-sw ip link set br0 type bridge ageing_time 1000` (10 วินาที) | รอ 15 วิแล้วดู `bridge fdb show br br0 \| grep -v permanent` MAC จะหายไป และ ping รอบแรกถัดไปจะเกิด BUM flooding |
| พื้นฐาน 2 (`softnet_stat`) | อ่านคอลัมน์แรกของ `/proc/net/softnet_stat` (เลขฐาน 16 = `processed`) | แปลง delta ด้วย `printf "%d\n" 0x...`; ตัวเลขเกิน 20,000 request+reply เพราะ 1 ping วิ่งผ่าน veth pair + bridge หลายรอบ |
| ปานกลาง 3 (Trace `br_handle_frame`) | เช็ก symbol ก่อนด้วย `sudo bpftrace -l 'kprobe:br_handle_frame*'` | ใช้ `kprobe:br_handle_frame` จะเห็น `comm` เป็นทั้งโปรเซสที่ส่งและ `ksoftirqd/*` / `swapper/*` ตอนทำงานใน softirq |
| ปานกลาง 4 (เพิ่ม `w02-ns4`) | แก้ 4 จุดใน `bridge_router_lab.sh`: `NAMESPACES`, `NS_IPS`, `RAW_IPS`, และคู่ ping ใน `test_connectivity()` | ลองรันครบวงจร `setup` -> `test` -> `clean` |
| ท้าทาย 5 (VLAN Isolation) | เปิด `ip link set br0 type bridge vlan_filtering 1` | ใช้ `bridge vlan del vid 1 dev ...` และ `bridge vlan add vid 10 pvid untagged dev ...` แยก L2 domain |
| ท้าทาย 6 (Offload Benchmark) | รัน `iperf3` ข้าม netns สลับเปิด/ปิด `tso gso gro` อย่างน้อย 3 รอบ | สังเกตว่า GRO/TSO ช่วยลดจำนวน `sk_buff` ที่วิ่งผ่าน stack อย่างมาก |

---

## เฟส 02: ก้าวแรกสู่ eBPF

### Week 03 — bpftool & bpftrace ([README](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (กรอง UID) | เติม `/uid == <id>/` ใน `tracepoint:sched:sched_process_exec` | เห็นเฉพาะคำสั่งที่รันด้วย UID นั้น |
| พื้นฐาน 2 (สำรวจ `tcp:` tracepoints) | รัน `sudo bpftrace -l 'tracepoint:tcp:*' \| wc -l` | ดูฟิลด์ด้วย `-lv tracepoint:tcp:tcp_retransmit_skb` |
| ปานกลาง 3 (Windowed vs Total Map) | แยก `@win_calls` กับ `@total_calls` | เรียก `clear(@win_calls)` หลัง `print` ใน `interval:s:10` ส่วน `@total_calls` พิมพ์ตอน `END` |
| ปานกลาง 4 (`tcp_sendmsg` Latency) | `fentry:vmlinux:tcp_sendmsg { @start[tid] = nsecs; }` คู่ `fexit` + ลบด้วย `delete(@start[tid])` | ต้องใช้ `tid` ไม่ใช่ `pid` เพราะโปรเซสที่มีหลาย thread อาจเรียกพร้อมกัน |
| ท้าทาย 5 (พฤติกรรม `sys_enter_*`) | ใช้ `taskset -c $c` วนทุก core เทียบ `bpftrace` กับ `perf stat` | ลองกับ `getpid`, `openat`, `execve`, `read`, `write` |
| ท้าทาย 6 (ดึง `argv` ผ่าน `raw_syscalls`) | จับ `tracepoint:raw_syscalls:sys_enter /args->id == 59/` (execve) | อ่าน `args->args[1]` ด้วย `uptr((uint64)args->args[1] + i*8)` แบบ loop 4–8 รอบแล้วครอบ `str()` |

### Week 04 — BCC & Python ([README](../phase02-first-step-ebpf/week04-bcc-python/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (เช็กว่าไม่ใช่ RTT จริง) | probe วัดแค่ตั้งแต่เข้าจนออกจาก `tcp_v4_connect` (setup syscall) | เลยใช้เวลาแค่ไม่กี่ µs ก่อน SYN-ACK กลับมา ถึงแม้ปลายทางอยู่ต่างประเทศหรือพอร์ตปิด |
| พื้นฐาน 2 (Filter `--comm`) | ส่ง `-DFILTER_COMM="..."` ผ่าน `cflags` หรือเทียบด้วย `bpf_get_current_comm` | กรองชื่อโปรเซสจาก CLI flag ได้เลย |
| ปานกลาง 3 (IPv6 `tcp_v6_connect`) | ดูโครง `struct sock_common` (`skc_v6_daddr`) จาก `bpftool btf dump ... format c` | อ่าน 16 ไบต์ด้วย `bpf_probe_read_kernel` แล้วแปลงใน Python ด้วย `socket.inet_ntop(socket.AF_INET6, ...)` |
| ปานกลาง 4 (Ring Buffer ใน BCC) | เปลี่ยน `BPF_PERF_OUTPUT` เป็น `BPF_RINGBUF_OUTPUT(events, 8)` + `events.ringbuf_output(...)` | ฝั่ง Python ใช้ `b["events"].open_ring_buffer(cb)` + `b.ring_buffer_poll()` |
| ท้าทาย 5 (Handshake RTT จริง) | ใช้ pointer `struct sock *` เป็น key ตอนเข้า `tcp_v4_connect` เพื่อเก็บ `ts` | อ่านกลับตอนเข้า `tcp_rcv_state_process` เมื่อ `skc_state == TCP_SYN_SENT` (จุดนี้เป็น softirq ใช้ `pid_tgid` ไม่ได้) |
| ท้าทาย 6 (เขียนใหม่ด้วย bpftrace) | ดึง field ด้วย BTF (`((struct sock *)arg0)->__sk_common.skc_state`) | วัด Max RSS (`time -v`) และเวลาตอนเปิดเทียบระหว่าง BCC กับ bpftrace |

---

## เฟส 03: แกนหลัก eBPF ยุคใหม่

### Week 05 — libbpf & cilium/ebpf Go ([README](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`PERCPU_ARRAY`) | เปลี่ยนชนิด map ใน `counter.c` และใช้ `*val += 1;` แทน atomic add | ใน Go ส่ง `var perCPU []uint64` เข้า `Lookup(uint32(0), &perCPU)` แล้ววนบวกทุก CPU |
| พื้นฐาน 2 (เทียบ Hook) | สลับเป็น `SEC("tracepoint/syscalls/sys_enter_execve")` ชั่วคราว | ทดสอบเทียบด้วย `taskset -c 0..N /bin/true` |
| ปานกลาง 3 (อ่าน `filename` ผ่าน `__data_loc`) | ประกาศ header 8 ไบต์ + `__u32 filename_loc` ตาม `/sys/kernel/tracing/events/sched/sched_process_exec/format` | อ่านสตริงด้วย `bpf_probe_read_kernel_str(..., (void *)ctx + (ctx->filename_loc & 0xFFFF))` |
| ปานกลาง 4 (HTTP `/metrics`) | เพิ่ม goroutine `http.HandleFunc("/metrics", ...)` | คืนข้อความ `exec_events_total <count>\n` |
| ท้าทาย 5 (CO-RE PPID) | `#include "../../vmlinux.h"` ใช้ `bpf_get_current_task_btf()` และ `BPF_CORE_READ(task, real_parent, tgid)` | เช็ก `.BTF.ext` core relo ด้วย `bpftool btf dump` หรือ `llvm-objdump -r bpf_bpfel.o` |
| ท้าทาย 6 (Pin Map) | ใส่ `PinByName: ebpf.PinByName` หรือ `CollectionOptions{Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/w05"}}` | จบแล็บอย่าลืมลบ `/sys/fs/bpf/w05` |

### Week 06 — eBPF Maps & Verifier Lab ([README](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`LRU_HASH`) | เปลี่ยน `syscall_map` ใน `syscall_stats.c` เป็น `BPF_MAP_TYPE_LRU_HASH`, `max_entries = 256` | อัปเดตค่าที่คาดหวังใน `TestSyscallStatsLoads` ให้ `make test` ผ่าน |
| พื้นฐาน 2 (TID vs TGID) | ใช้ `(__u32)pid_tgid` แทน `pid_tgid >> 32` | เพื่อแยกนับราย thread |
| พื้นฐาน 3–4 (แก้ Verifier / ลองทำ Test พัง) | ไล่อ่าน register state ของ verifier (`R0=pkt`, `R1=pkt_end`) | ลองแก้ให้พัง/ผ่านตามโจทย์แล้ว revert กลับให้ `make test` เขียว |
| ปานกลาง 5 (Atomic Insert-or-Increment) | ถ้า `!val` ให้ `bpf_map_update_elem(..., BPF_NOEXIST)`; ถ้าชน `-EEXIST` ให้ lookup อีกรอบแล้ว `__sync_fetch_and_add` | ป้องกัน race ตอนสร้าง key ใหม่พร้อมกัน |
| ปานกลาง 6 (Cleanup on Exit) | เพิ่ม `SEC("tracepoint/sched/sched_process_exit")` ลบ key เมื่อ `(pid_tgid >> 32) == (__u32)pid_tgid` | อย่าลืม attach ทั้ง 2 tracepoint ใน `main.go` |
| ปานกลาง 7–8 (`verifier_fail` & NULL Elision) | เพิ่มเทสต์ IPv4 header + offset bounds | บนเคอร์เนลใหม่ `BPF_MAP_TYPE_ARRAY` key คงที่ verifier อาจตัด NULL check ออกได้ (`R0=map_value` แทน `map_value_or_null`) |
| ท้าทาย 9 (`{pid, syscall_id}`) | เปลี่ยน hook เป็น `raw_syscalls/sys_enter` | อ่าน `ctx->id` เพื่อแยกนับตามเลข syscall |
| ท้าทาย 10–12 (`LRU`, `BatchLookup`, Loop) | `LockOSThread` + `SchedSetaffinity` ดูพฤติกรรม per-CPU free list เทียบ `BPF_F_NO_COMMON_LRU` | ใช้ `maps.BatchLookup` ลด `bpf()` syscall และเทียบ bounded loop กับ `bpf_loop()` |

---

## เฟส 04: เน็ตเวิร์กความเร็วสูง

### Week 07 — XDP Packet Parsing & Stateless Firewall ([README](../phase04-high-speed-networking/week07-xdp-parsing/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`blocked_ports`) | อ่าน `tcph->dest`/`udph->dest` (network byte order) | ต้องเช็ก `if (dest + 1 > data_end) return XDP_PASS;` ก่อน แล้วใช้ byte order เดียวกันทั้ง C/Go (`htons`) |
| พื้นฐาน 2 (นับ EtherType) | เพิ่ม `PERCPU_ARRAY` 4 ช่อง (IPv4, IPv6, ARP, Other) | อัปเดตตัวนับก่อน early return |
| ปานกลาง 3 (IPv6 Blocklist) | เมื่อ `h_proto == bpf_htons(ETH_P_IPV6)` เช็ก `ip6h + 1 <= data_end` | lookup `struct in6_addr` (16 ไบต์) ใน `blocked_ips6` |
| ปานกลาง 4 (802.1Q VLAN) | เช็ก `h_proto == bpf_htons(ETH_P_8021Q)` และ `struct vlan_hdr *vh` (`+ 1 <= data_end`) | ขยับ `nh_off += sizeof(*vh)` แล้วอ่านต่อจาก `vh->h_vlan_encapsulated_proto` |
| ท้าทาย 5 (LPM Trie CIDR) | ใช้ `BPF_MAP_TYPE_LPM_TRIE` + `map_flags = BPF_F_NO_PREALLOC` | key คือ `{__u32 prefixlen; __u8 data[4];}` (ต้องเป็น network byte order) |
| ท้าทาย 6 (SYN Token Bucket) | เก็บ `{__u64 tokens, last_ns}` ใน `LRU_HASH` | เมื่อ `tcph->syn && !tcph->ack` เติม token ด้วย `(bpf_ktime_get_ns() - last_ns) * rate / 1e9` (cap ที่ burst) |

### Week 08 — TC Load Balancer & DSR ([README](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (Dynamic Backends) | ขยาย `backends` `max_entries = 16` + เพิ่ม array 1 ช่อง `backend_count` | ใช้ `hash % cnt` หลังเช็ก `if (cnt == 0) return XDP_PASS;` เพื่อกัน divide-by-zero ที่ verifier บังคับ |
| พื้นฐาน 2 (Service Port Filter) | เพิ่ม `service_port` (`__be16`) ใน `lb_config_t` | ถ้าวิ่งเข้า `VIP` แต่ `tcph->dest != cfg->service_port` ให้คืน `XDP_DROP` |
| ปานกลาง 3 (Dual-stack VIPv6) | แยก `flow_key6` แล้วคำนวณ L4 checksum delta | ใช้ `bpf_csum_diff((__be32 *)&old_ip6, 16, (__be32 *)&new_ip6, 16, 0)` (XDP) และ `BPF_F_PSEUDO_HDR` (TC) |
| ปานกลาง 4 (Flow Teardown & Expiry) | เพิ่ม `flags` (`FIN_CLIENT=1`, `FIN_SERVER=2`) + `last_seen_ns` ใน `flow_value` | ลบจาก `flows` เมื่อเจอ `RST` หรือ `FIN` ครบสองฝั่ง + ให้ Go ticker กวาด entry ที่อายุ > 60s |
| ท้าทาย 5 (Maglev Hashing) | สร้าง lookup table ขนาดจำนวนเฉพาะ `M = 65537` ใน Go ใส่ `BPF_MAP_TYPE_ARRAY` | XDP อ่าน `table[hash % 65537]` ตรงๆ ไม่ต้องคำนวณหนักในเคอร์เนล |
| ท้าทาย 6 (DSR ด้วย IPIP) | ใช้ `bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr))` ใส่ outer IPv4 (`IPPROTO_IPIP`) | คำนวณ outer IP checksum ใหม่ + ตั้ง `lo`, `arp_ignore=1`, `ipip` บนเครื่อง Backend |

---

## เฟส 05: จับตาความปลอดภัย

### Week 09 — Ring Buffer & OpenSSL Uprobes ([README](../phase05-security-observability/week09-ringbuf-uprobes/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 7.1 (Drop Counter) | เพิ่ม `PERCPU_ARRAY` 1 ช่อง `drops`; ถ้า `bpf_ringbuf_reserve()` ได้ `NULL` ให้ `*cnt += 1;` | อ่านสรุปยอดตกหล่นใน Go ตอน `<-ctx.Done()` |
| พื้นฐาน 7.2 (`-uid` Filter) | ประกาศ `const volatile __u32 filter_uid = 0xffffffff;` + `spec.RewriteConstants` ใน Go | ฝั่ง C เทียบ `(__u32)bpf_get_current_uid_gid() != filter_uid` |
| ปานกลาง 7.3 (Per-CPU Check) | รัน `bpftrace` คู่ `taskset -c $c /usr/bin/true` | ดูจำนวน event กระจายตาม core |
| ปานกลาง 7.4 (`SSL_read` Uprobe + Uretprobe) | เก็บ `buf` ptr ลง hash map key=`pid_tgid` ใน `BPF_UPROBE(SSL_read, void *ssl, void *buf, int num)` | ใน `BPF_URETPROBE` อ่าน `ret = PT_REGS_RC(ctx)` ถ้า `ret > 0` ให้ lookup `buf`, `bpf_probe_read_user` เข้า ringbuf แล้ว `bpf_map_delete_elem` |
| ท้าทาย 7.5 (หา `libssl` อัตโนมัติ) | พอเจอ event `EXEC` ให้สแกน `/proc/<pid>/maps` หา path `libssl*.so*` | cache ด้วย `(dev, ino)` เพื่อ attach uprobe บน `/proc/<pid>/root/...` โดยไม่เกาะซ้ำ |
| ท้าทาย 7.6 (Go `crypto/tls`) | x86_64 Go Internal ABI: receiver อยู่ใน `AX`, slice ptr ใน `BX`, slice len ใน `CX` | **ห้ามใช้ uretprobe** กับ Go เพราะ goroutine stack โตแล้วจะย้าย return frame ทำให้ trampoline พัง |

### Week 10 — BPF LSM ([README](../phase05-security-observability/week10-bpf-lsm/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 7.1 (`-EACCES`) | ใน `lsm_file_guard.c` (ใช้ `vmlinux.h` เลยไม่มี `<errno.h>`) | ประกาศ `#define EACCES 13` แล้วคืน `-EACCES` |
| พื้นฐาน 7.2 (Case-insensitive + Suffix) | แปลง `A-Z` -> `a-z` (`c \| 0x20`) ใน loop แบบ fixed bound (เช่น `< 64`) | วัดความยาวจริงแบบ bounded ก่อนเทียบ 4 ไบต์ท้าย `.pem` / `.key` |
| ปานกลาง 7.3 (Enforce Test ใน VM) | ทดสอบบน VM ที่ `/sys/kernel/security/lsm` มี `bpf` | เช็ก boot flags ด้วย `cat /proc/cmdline` |
| ปานกลาง 7.4 (`path_rename` / `inode_rename`) | ใช้ `SEC("lsm/inode_rename")` (`BPF_PROG(restrict_rename, struct mnt_idmap *idmap, struct inode *old_dir, ...)`) | เช็ก signature ให้ตรงกับเคอร์เนลที่ใช้ผ่าน `bpftool btf dump` |
| ท้าทาย 7.5 (`bpf_d_path` Policy) | ใช้ `BPF_MAP_TYPE_LPM_TRIE` เทียบ path prefix | ระวังเรื่อง bind mount กับ mount namespace ของ container เพราะ path อาจต่างจากมุมมอง host |
| ท้าทาย 7.6 (Self-Protection) | pin link/maps ใน `/sys/fs/bpf/week10/` แล้วติด `SEC("lsm/bpf")` | บล็อก `BPF_MAP_UPDATE_ELEM`/`BPF_MAP_DELETE_ELEM` บน map ID ที่หวงไว้ (`attr->map_fd` / `lsm/bpf_map`) |

---

## เฟส 06: โปรเจกต์รวมระบบ Production

### Week 11 — Verifier Limits & Prometheus ([README](../phase06-production-capstone/week11-verifier-prometheus/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (GRE Protocol 47) | เพิ่ม `PROTO_INDEX_GRE` ใน enum C และ `protocolNames` ใน Go | เพิ่ม test case แพ็กเก็ต IP proto `47` ใน `metrics_test.go` |
| พื้นฐาน 2 (Bind Localhost Only) | สตาร์ต `w11srv` ด้วย `-addr 127.0.0.1:2112` | จำกัดไม่ให้รับ request จากภายนอก |
| ปานกลาง 3 (`ARRAY` vs `PERCPU_ARRAY`) | เรียก `prog.Benchmark()` จากหลาย goroutine | ผูกแต่ละ goroutine ด้วย `runtime.LockOSThread()` + `unix.SchedSetaffinity` |
| ท้าทาย 4 (Packet-Size Histogram) | เพิ่ม Per-CPU Array 7 ช่อง `size_buckets` นับขนาด `ctx->data_end - ctx->data` | ส่งออกผ่าน `prometheus.MustNewConstHistogram` |
| ท้าทาย 5 (Batch Scrape Cost) | เปลี่ยนเป็น `PERCPU_HASH` 10,000 flow | เทียบ `Iterate()` กับ `BatchLookup()` ด้วย `strace -c -e trace=bpf` |

### Week 12 — Capstone Stateful XDP IPS ([README](../phase06-production-capstone/week12-capstone-ips/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`-window` Flag) | แปลง `-window` เป็น nanosecond แล้วเขียนลง `config_map` | แทนที่ค่า `1000000000ULL` เดิมที่ hard-code ไว้ |
| พื้นฐาน 2 (`allowlist_map`) | เพิ่ม hash map เช็ก IP ก่อนเข้าตรวจ blacklist/rate-limit ใน C (`XDP_PASS`) | เพิ่ม REST endpoint `/api/allowlist` ใน Go |
| ปานกลาง 1 (UDP Flood) | เพิ่ม `udp_count` ใน `rate_state`, ค่าตั้งต้น `CONF_UDP_LIMIT`, และ `REASON_UDP_FLOOD` | เขียน unit test เพิ่มใน `main_test.go` |
| ปานกลาง 2 (Race Without Atomic) | ลองถอด `__sync_fetch_and_add` ชั่วคราว | ยิงเทสต์หลาย goroutine/CPU แล้วดูยอดตกหล่น (lost updates) |
| ท้าทาย 1 (Sliding Window 2-Bucket) | เก็บ `prev_count`, `curr_count`, `window_start_ns` | คำนวณ `curr + prev * (window - elapsed) / window` ด้วย integer ล้วน (ห้ามใช้ float ใน eBPF) |
| ท้าทาย 2 (กัน Spoofed-Source Ban) | ทำ XDP SYN Cookie (`bpf_tcp_raw_gen_syncookie_ipv4` / `check_syncookie`) หรือรอให้ครบ 3-way handshake ก่อนแบน | กันผู้โจมตีปลอม IP คนอื่นมาให้โดนระบบเราแบน |

---

## เฟส 07: ความปลอดภัยขั้นสูง

### Week 13 — `kfree_skb` Dropwatch ([README](../phase07-advanced-security-observability/week13-kfree-skb-dropwatch/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (Netfilter Drop) | ใน `w13` netns รัน `iptables -A INPUT -p tcp --dport 8080 -j DROP` แล้วลองต่อด้วย `nc` | Reason ที่จับได้ต้องเป็น `NETFILTER_DROP` |
| พื้นฐาน 2 (BTF vs Tracepoint Format) | เทียบ `bpftool btf dump file /sys/kernel/btf/vmlinux` ของ `trace_event_raw_kfree_skb` กับ `/sys/kernel/tracing/events/skb/kfree_skb/format` | ดูความตรงกันของ offset และชื่อฟิลด์ |
| ปานกลาง 1 (Kernel Filter) | เพิ่ม `const volatile __u32 filter_reason` | นับยอดรวมลง map ทุก reason เหมือนเดิม แต่เรียก `bpf_ringbuf_reserve()` เฉพาะ reason ที่ตรง filter |
| ปานกลาง 2 (5-Tuple จาก `skb`) | อ่าน `head`, `network_header`, `transport_header` ด้วย `BPF_CORE_READ` | ใช้ `bpf_probe_read_kernel` อ่าน `iphdr` + `tcphdr`/`udphdr` (เช็ก `skb->protocol == bpf_htons(ETH_P_IP)` และ offset bounds) |
| ท้าทาย 1–2 (Custom BTF / `tp_btf`) | จำลอง `btf.Spec` ส่งเข้า `ProgramOptions{KernelTypes: ...}` หรือเขียน `SEC("tp_btf/kfree_skb")` | `BPF_PROG(..., struct sk_buff *skb, void *location, enum skb_drop_reason reason)` จะรับ `skb` โดยตรง |

### Week 14 — Cgroup Socket Enforcement ([README](../phase07-advanced-security-observability/week14-cgroup-sock-addr/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (Multiple Ports) | รับ `-block-ports` แบบ `flag.String` แยกด้วย `,` แล้ว `Put` ลง `blocked_ports` | ใส่หลายพอร์ตได้ในครั้งเดียว |
| พื้นฐาน 2 (วัด Overhead) | เปิด `kernel.bpf_stats_enabled=1` แล้วดู `run_time_ns / run_cnt` จาก `bpftool prog show` | วัดเสร็จอย่าลืมปิดกลับเป็น `0` |
| ปานกลาง 1 (อุด UDP `sendto`) | เพิ่ม `SEC("cgroup/sendmsg4")` ใช้ logic lookup เดียวกับ `connect4` | `return 0;` จะกลายเป็นการปฏิเสธ `-EPERM` |
| ปานกลาง 2 (อุด IPv4-mapped IPv6) | เพิ่ม `SEC("cgroup/connect6")` เช็ก `user_ip6[0..2]` ว่าเป็น `::ffff:` (`0, 0, bpf_htonl(0x0000ffff)`) | ดึง `ctx->user_ip6[3]` มาเช็กเทียบกับ `blocked_ips`/`blocked_ports` |
| ท้าทาย 1 (Transparent Socket LB) | เขียนทับ `ctx->user_ip4` และ `ctx->user_port` แล้ว `return 1;` | ถ้าอยากให้แอปเรียก `getpeername()` แล้วเห็น VIP เดิม ให้เพิ่ม `cgroup/getpeername4` แปลงกลับ |
| ท้าทาย 2 (Default-Deny Allowlist) | เปลี่ยนไป lookup `allowed_dests` ถ้าไม่เจอคืน `0` | อย่าลืมเพิ่ม DNS พอร์ต `53` ของ resolver ไว้ด้วยไม่งั้น resolve ชื่อไม่ออก |

### Week 15 — Reverse Shell Guard ([README](../phase07-advanced-security-observability/week15-reverse-shell-guard/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1–2 (`bpftool` & Noise Audit) | Key ของ `daemon_names` ยาว 16 ไบต์ ต้อง pad `0x00` ให้ครบทุกช่อง | เช่น `"python3"` -> `70 79 74 68 6f 6e 33 00 00 00 00 00 00 00 00 00` |
| ปานกลาง 1 (จับตาม Inode) | อ่าน `BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino)` และ `i_sb->s_dev` ส่งเข้า ringbuf | ฝั่ง Go เทียบกับ `syscall.Stat_t` ของ `/bin/bash`, `/bin/dash` (กันคนก๊อปปี้ binary เปลี่ยนชื่อ) |
| ปานกลาง 2 (`dup2`/`dup3` Monitor) | ใช้ `SEC("tracepoint/raw_syscalls/sys_enter")` กรอง `args->id == 33 \|\| args->id == 292` | เช็ก `args->args[1] <= 2` (`newfd`) และดูว่า `oldfd` ใน `task->files->fdt->fd[oldfd]` เป็น network socket |
| ท้าทาย 1 (บล็อกด้วย BPF LSM) | เพิ่ม `SEC("lsm/bprm_check_security")` | คืน `-EPERM` เมื่อ shell ที่กำลัง exec มี fd 0/1/2 ผูกอยู่กับ network socket |
| ท้าทาย 2 (4-Level Lineage) | วน `for (int i = 0; i < 4; i++)` เดิน `p = BPF_CORE_READ(p, real_parent)` | อ่าน `comm` เทียบ `daemon_names` (loop ตายตัว 4 รอบ ผ่าน verifier แน่นอน) |

### Week 16 — eBPF Integrity Auditor ([README](../phase07-advanced-security-observability/week16-ebpf-integrity-audit/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (Baseline JSON) | เพิ่ม flag `-save-baseline` และ `-baseline` | เทียบ slice/map ของ `(Name, Type, Tag)` ที่ได้จาก `inventoryPrograms()` |
| พื้นฐาน 2 (`auditd`) | รัน `sudo ausearch -m BPF -ts recent` | เอา `prog-id` มาเทียบ cross-check กับข้อมูลในเครื่องมือเรา |
| ปานกลาง 1 (Kernel `cmd` Filter) | เพิ่ม `ARRAY` map bitmap 64 ช่องเก็บ `enum bpf_cmd` ที่อยากจับ | ทิ้งคำสั่ง read-only (`MAP_LOOKUP_ELEM`, `PROG_GET_NEXT_ID`, ...) ก่อนเรียก `bpf_ringbuf_reserve()` |
| ปานกลาง 2 (Link Inventory) | วน `link.GetNextID()` หรือ `link.NewFromID(id)` แบบเดียวกับ `inventoryPrograms()` | เก็บรายการ link ทั้งหมดที่มีอยู่ในระบบ |
| ท้าทาย 1 (Enforce `lsm/bpf`) | ใช้ `SEC("lsm/bpf")` ตรวจ `cmd == BPF_PROG_LOAD` เทียบ whitelist `comm`/cgroup | ลองใน VM และติดแบบ process-scoped link เผื่อสั่ง Ctrl+C ปิดได้ |
| ท้าทาย 2 (Red vs Blue) | ทดสอบวิธีเลี่ยงตรวจจับ: ฆ่า agent, ยิง lookup ถล่ม ringbuf หรือ preload ก่อนเปิด | วางแผนป้องกันด้วย pinning + ส่ง log ออกภายนอก + `lsm/bpf` |

---

## เฟส 08: ดูประสิทธิภาพระบบ

### Week 17 — Block I/O Biolatency ([README](../phase08-system-performance-observability/week17-block-io-biolatency/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (Page Cache) | อ่านไฟล์เดิม 2 รอบโดยไม่ใส่ `iflag=direct` | รอบสองจะอ่านจาก RAM (Page Cache); ถ้าจะเคลียร์ให้ใช้ `drop_caches=1` |
| พื้นฐาน 2 (`-disk` Flag) | กรองใน `main.go` ให้พิมพ์เฉพาะเมื่อ `devName(key.Dev) == *disk` | ลด noise จากดิสก์ลูกอื่น |
| ปานกลาง 1 (Queue Latency `-queued`) | เพิ่ม `SEC("tp_btf/block_rq_insert")` + `const volatile __u8 mode_queued = 0;` | เมื่อ `mode_queued == 1` ให้เริ่มจับเวลาตั้งแต่ `insert`, ถ้า `0` จับที่ `issue` |
| ปานกลาง 2 (Drop / Unmatched Stats) | เพิ่ม `PERCPU_ARRAY` 2 ช่อง | นับกรณี `bpf_map_update_elem` fail กับ `block_rq_complete` ที่หา `rq` ไม่เจอ |
| ท้าทาย 1 (Per-Process Attribution) | เก็บ `comm[16]` คู่กับ `ts` ใน value ของ `start_times` | async writeback จะขึ้นเป็น `kworker/*`/`jbd2/*` แต่ `oflag=direct` จะเห็นชื่อโปรเซสจริง |
| ท้าทาย 2 (Raw Tracepoint Fallback) | เขียน `tracepoint/block/block_rq_issue` จับคู่ด้วย `(dev, sector)` | เทียบ request ที่โดน merge/split จนตกหล่นกับแบบที่ใช้ `struct request *` |

### Week 18 — CPU Profiler & Flame Graphs ([README](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1–2 (`-fomit-frame-pointer` & `-F`) | คอมไพล์ `workload/busy.c` ด้วย `-fomit-frame-pointer` เพื่อดู stack ขาด | เช็กจำนวน sample ที่ได้เทียบกับ `F * seconds * busy_cores` |
| ปานกลาง 1 (`-per-thread`) | เพิ่ม `Tid uint32` ใน `struct stack_key` ทั้ง C และ Go (เช็กขนาด alignment ด้วย) | แสดงเฟรมแรกใน Go เป็น `fmt.Sprintf("%s-%d", comm, key.Tid)` |
| ปานกลาง 2 (Stack Collision) | ทดลองปรับ `max_entries` ของ `stack_traces` เป็น `1024`, `16384`, `65536` | ดู `statKernEexist` / `statUserEexist` คู่กับ `memlock` ใน `bpftool map show` |
| ท้าทาย 1 (`-offcpu`) | Hook `tp_btf/sched_switch` เก็บ `{start_ns, stack_id}` ของ `prev` ที่โดนสลับออก (`prev_pid > 0`) | พอกลับเข้า CPU ใน `next` ค่อยคิด `delta_us` บวกใส่ `stack_counts` |
| ท้าทาย 2 (Build ID / DWARF Line) | ใช้ `bpf_get_stack()` กับ flag `BPF_F_USER_BUILD_ID` | หรือเอา `<rel_addr>` ไปแปลงชื่อบรรทัดใน userspace ด้วย `addr2line -e <bin> -f` |

### Week 19 — Memory & OOM Watcher ([README](../phase08-system-performance-observability/week19-memory-oom-watcher/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`oom_score_adj`) | รัน 2 worker ใน `systemd-run --scope -p MemoryMax=50M -p MemorySwapMax=0` | ตัวแรกเขียน `1000` ลง `/proc/self/oom_score_adj` ก่อนจองหน่วยความจำ |
| พื้นฐาน 2 (`-comm` Flag) | กรองชื่อโปรเซสตอนพิมพ์ตาราง page fault ใน `main.go` | ดูเฉพาะโปรเซสที่อยากติดตาม |
| ปานกลาง 1 (`{tgid, comm}` + Fault Kind) | ดู `ctx->error_code`: bit 0 (`0x1`) = `X86_PF_PROT` (CoW write), bit 4 (`0x10`) = `X86_PF_INSTR` | เช็กชื่อฟิลด์ที่ `/sys/kernel/tracing/events/exceptions/page_fault_user/format` |
| ปานกลาง 2 (Memcg Reclaim) | เช็ก `/sys/kernel/tracing/events/vmscan/` แล้ว hook `mm_vmscan_memcg_reclaim_begin` | นับตาม `cgroup_id` ตอนตั้ง `MemoryHigh=40M MemoryMax=50M` |
| ท้าทาย 1 (OOM Stack Trace) | เรียก `bpf_get_stack(ctx, event.stack, sizeof(event.stack), 0)` ใน `mark_victim` | แปลง address เป็นชื่อฟังก์ชันด้วย `/proc/kallsyms` |
| ท้าทาย 2 (Prometheus `/metrics`) | เพิ่ม HTTP endpoint ส่งออก `oom_kills_total` และ `page_faults_total` | ใช้รูปแบบ metrics มาตรฐานของ Prometheus |

---

## เฟส 09: เร่งความเร็ว Socket & AF_XDP

### Week 20 — TCP SOCKOPS & `sk_msg` Bypass ([README](../phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (Byte Order Bug) | ลองเปลี่ยน `.sport` กลับเป็น `bpf_ntohl(skops->local_port)` ชั่วคราว | จะเห็นชัดว่า `sockops` กับ `sk_msg` ใช้ byte order ของ `local_port`/`remote_port` ต่างกัน |
| พื้นฐาน 2 (Cross-cgroup) | เปิด server ใน cgroup แล็บ แต่เปิด client นอก cgroup | `SOCKHASH` จะมีแค่ 1 entry และ `sk_msg` bypass จะไม่ทำงาน (fallback หมด) |
| ปานกลาง 1 (`PERCPU_ARRAY` Stats) | เปลี่ยน `bypass_stats` เป็น `PERCPU_ARRAY` | ลดอาการ cache-line bouncing ข้าม CPU แล้วค่อยรวมยอดใน Go |
| ปานกลาง 2 (`-chunk` Sweep) | รัน `tcpbench -chunk` ที่ `64, 1024, 16384, 65536` อย่างน้อย 3 รอบ | สรุปค่า min / median / max เพื่อดูจุดที่ bypass คุ้มที่สุด |
| ท้าทาย 1 (IPv6 Support) | เพิ่ม `local_ip6[4]`/`remote_ip6[4]` ด้วย `bpf_memcpy`/`__builtin_memcpy` | คัดลอกจาก `skops->local_ip6` และ `msg->local_ip6` เพื่อลองกับ `[::1]` |
| ท้าทาย 2 (Port Allowlist) | เพิ่ม `allowed_ports` hash map | ใน `sk_msg` ให้เรียก `bpf_msg_redirect_hash` เฉพาะพอร์ตใน map นอกนั้น `return SK_PASS;` |

### Week 21 — XDP Redirect & AF_XDP Socket ([README](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1–2 (Ring Starvation & `no_xsk`) | ลองไม่เติม FILL ring หรือไม่ใส่ socket ลง `xsks_map` | เห็นอาการ fallback ไป `XDP_PASS` และดูตัวนับ `nstat -az UdpNoPorts` |
| ปานกลาง 1 (Port Filter) | เพิ่ม `udp_ports` hash map ใน `af_xdp_kern.c` เช็ก `udph->dest` (network byte order) ก่อน `bpf_redirect_map` | เพิ่ม unit test `TestXDPPortFilter` |
| ปานกลาง 2 (PPS Benchmark) | เขียน Go UDP sender (`net.DialUDP`) ยิงจาก `w21-tx` | เทียบ throughput กับ `net.ListenUDP` บน veth ในโหมด Copy Mode |
| ท้าทาย 1 (TX Echo) | map `XDP_PGOFF_TX_RING`, สลับ MAC + IP + UDP port, อัปเดต checksum (หรือตั้ง `0` สำหรับ IPv4 ทดสอบ) | ใส่ desc ลง TX ring, เรียก `unix.Sendto(fd, nil, unix.MSG_DONTWAIT, ...)` เพื่อปลุกเคอร์เนล แล้ว reclaim จาก COMPLETION ring |
| ท้าทาย 2 (Multi-Queue) | สร้าง veth ด้วย `numrxqueues 4 numtxqueues 4` เปิด AF_XDP 1 socket ต่อ `qid` | แชร์ UMEM ด้วย `XDP_SHARED_UMEM` หรือแยก UMEM แล้วใส่ครบทุก `qid` ลง `xsks_map` |

---

## เฟส 10: Tracing ยุคใหม่ (`fentry`, Iterator)

### Week 22 — `fentry`/`fexit` Trampolines ([README](../phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (Trace `vfs_read`) | ดู signature ด้วย `sudo bpftrace -lv 'fexit:vfs_read'` | พารามิเตอร์คือ `(file, buf, count, pos, ret)` — ต้องประกาศให้ครบจำนวนตาม BTF |
| พื้นฐาน 2 (เช็ก Trampoline) | ดูด้วย `bpftool prog show`, `bpftool link show` และ `/sys/kernel/tracing/enabled_functions` | ยืนยันว่าติดแบบ fentry trampoline ไม่ใช่ kprobe |
| ปานกลาง 1 (Filter `comm` ใน C) | ประกาศ `const volatile char target_comm[16]` | เทียบทีละตัวแบบ loop คงที่ 16 รอบก่อน reserve ringbuf |
| ปานกลาง 2 (Log2 Histogram) | เก็บเวลาลง `ARRAY` ด้วย `bpf_log2l(delta_ns / 1000)` | ประหยัด overhead กว่าการส่งทุก event ขึ้น ringbuf |
| ท้าทาย 1 (Minimal Overhead Bench) | เขียน probe 4 แบบ (kprobe, kretprobe, fentry, fexit) ที่ไส้ในเหมือนกัน + probe เปล่า | แยกต้นทุนของกลไก attach ออกจากโค้ดภายใน |
| ท้าทาย 2 (`fexit` บนโปรแกรม XDP) | ตั้ง `ProgramSpec.AttachTarget` ชี้ `*ebpf.Program` ของ Week 07 และ `AttachTo` ชื่อ C function ของ XDP นั้น | อ่าน `int ret` ใน `BPF_PROG(trace_xdp, struct xdp_md *ctx, int ret)` นับ `ret == XDP_DROP` |

### Week 23 — BPF Iterators ([README](../phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (คอลัมน์ PPID) | อ่าน `BPF_CORE_READ(task, real_parent, tgid)` | พิมพ์ออกทาง `BPF_SEQ_PRINTF` |
| พื้นฐาน 2 (กรอง UID) | ใช้ `const volatile __u32 target_uid` | เทียบกับ `BPF_CORE_READ(task, real_cred, uid.val)` |
| ปานกลาง 1 (`iter/task_file`) | ประกาศ `SEC("iter/task_file")` รับ `(struct bpf_iter_meta *meta, struct task_struct *task, __u32 fd, struct file *file)` | นับรวมจำนวนไฟล์เปิดต่อ TGID |
| ปานกลาง 2 (เทียบ `/proc/*/stat`) | วัดเวลาอ่าน `/proc/*/stat` (บรรทัดเดียว) กับ `/proc/*/status` (หลายบรรทัด) | ใช้เป็น baseline เทียบความเร็วกับ BPF Iterator |
| ท้าทาย 1 (`iter/tcp`) | `SEC("iter/tcp")` รับ `struct sock_common *skc` | แปลงเป็น `struct tcp_sock *` ด้วย `bpf_skc_to_tcp_sock(skc)` แล้วเช็ก `skc != NULL` ก่อนพิมพ์ IP/port/state |
| ท้าทาย 2 (`iter/bpf_prog`) | `SEC("iter/bpf_prog")` รับ `struct bpf_prog *prog` | อ่าน `prog->aux->id`, `prog->type`, `prog->aux->name` เทียบผลกับ `bpftool prog show` |

---

## เฟส 11: ต่อยอดเคอร์เนล & ระบบนิเวศ

### Week 24 — Kernel Functions (kfuncs) & BPF Arena ([README](../phase11-modern-ebpf-extensibility/week24-kfuncs-arena/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`bpf_task_from_vpid`) | ครอบด้วย `if (bpf_ksym_exists(bpf_task_from_vpid))` เพื่อให้ fallback ได้ | รันใน `sudo unshare -fp --mount-proc` จะเห็น `vpid 1` ต่างจาก init pid namespace |
| พื้นฐาน 2 (`double_release`) | เรียก `bpf_task_release(t)` สองรอบใน `task_kfunc_broken.c` | ดู error เรื่อง reference tracking ของ verifier แล้วคัดลอกข้อความจริงใส่เทสต์ |
| ปานกลาง 1 (`bpf_cpumask_and`) | สร้างด้วย `bpf_cpumask_create()`, เคลียร์และ AND กับ `p->cpus_ptr`, นับด้วย `bpf_cpumask_weight()` | จบแล้ว**ต้องเรียก `bpf_cpumask_release()`** ไม่งั้น verifier ไม่ให้ผ่าน |
| ปานกลาง 2 (Arena Hash Table) | เปลี่ยนหัว list ใน arena header เป็น `node_off head[64]` (64 buckets) | เพิ่ม `ARENA_PAGES` ให้พอรับ >= 2,000 nodes × 32B (>16 pages = 64 KiB) |
| ท้าทาย 1 (Concurrent Arena) | ใช้ `__sync_fetch_and_add` กับตัวนับใน node | ใช้ CAS loop `__sync_val_compare_and_swap` ทำ lock-free push-front บน bucket |
| ท้าทาย 2 (Free-List & Free Pages) | เก็บ `free_head` และ `live_per_page[]` ใน header | พอทุก slot บนหน้านั้นถูก free หมดค่อยเรียก `bpf_arena_free_pages()` |

### Week 25 — `struct_ops` & `sched_ext` ([README](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`ops.stopping`) | เพิ่ม `STAT_STOPPING` และนับแยกตาม `runnable ? ... : ...` | ใช้ดูว่า task หยุดวิ่งเพราะ slice หมดหรือโดน block |
| พื้นฐาน 2 (`SCX_OPS_ENQ_LAST`) | ถ้ามีงานเดียวบน CPU ตัว scheduler อาจให้รันต่อโดยไม่ผ่าน `enqueue` | ใส่ `SCX_OPS_ENQ_LAST` ใน `.flags` ของ `struct sched_ext_ops` เพื่อให้เข้า `enqueue` ทุกครั้ง |
| ปานกลาง 1 (Per-CPU DSQ + Steal) | ใน `ops.init` สร้างคิวด้วย `bpf_for(cpu, 0, nr_cpu_ids) scx_bpf_create_dsq(cpu, -1);` | `dispatch` เรียก `scx_bpf_dsq_move_to_local(cpu)` ก่อน แล้วค่อยวนขโมยจาก CPU อื่นพร้อมนับ `STAT_STEAL` |
| ปานกลาง 2 (`scx_bpf_kick_cpu`) | ใน `enqueue` เช็กว่า task ที่รันอยู่บน target CPU มี `vtime` สูงกว่างานใหม่มากไหม | ถ้าใช่ เรียก `scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT)` |
| ท้าทาย 1 (`prev` vtime check) | เช็ก `scx_bpf_dsq_peek(DSQ_ID)` เทียบ `prev->scx.dsq_vtime` | ถ้า `prev` น้อยกว่าให้ปล่อยหรือ re-dispatch อย่างระวัง อย่าคิด slice ใน `stopping` ซ้ำ |
| ท้าทาย 2 (`tcp_congestion_ops`) | ประกาศ `SEC(".struct_ops.link") struct tcp_congestion_ops` (`.init`, `.ssthresh`, `.cong_avoid`, `.undo_cwnd`, `.name`) | attach ผ่าน `link.AttachStructOps` แล้วทดสอบใน `w25-` netns |

### Week 26 — Tetragon & Cilium Ecosystem ([README](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md))

| ข้อ | แก้ตรงไหน / ทำยังไง | จุดสำคัญที่ต้องระวัง & วิธีเช็ก |
|---|---|---|
| พื้นฐาน 1 (`07-write-monitor.yaml`) | Hook `security_file_permission` ตรวจ `args[0]` (`file`) ใน `lab-files/notes.txt` | เช็ก `args[1]` (`int`) `Mask: 2` (`MAY_WRITE`) |
| พื้นฐาน 2 (`matchBinaries`) | เพิ่ม `matchBinaries: [{ operator: "In", values: ["/usr/bin/cat"] }]` | สังเกตดูว่าโปรแกรมอื่น (`head`, `python3`) หลุดการตรวจจับได้ยังไง |
| ปานกลาง 3 (`syscall: true` + `Override`) | เช็ก `/sys/kernel/debug/error_injection/list` ว่ามี `__x64_sys_connect` | ชี้ `matchBinaries` ไปที่ copy ของ curl ใน `lab-files/bin/` เท่านั้น **ห้ามใส่ `/usr/bin/curl` เด็ดขาด** |
| ปานกลาง 4 (วัด Overhead) | วัด baseline vs base sensor vs policy 02 อย่างน้อย 5 รอบ | ใช้ `time` หรือโปรแกรม C วน `open/close` |
| ท้าทาย 5 (Hardlink Bypass) | ทดสอบ `ln lab-files/secret.txt lab-files/alias.txt` แล้วเขียน policy hook `security_path_link` | หรือดักเทียบจาก inode/directory แทนชื่อไฟล์อย่างเดียว |
| ท้าทาย 6 (Self-Audit BPF Loads) | Hook `security_bpf_prog_load` หรือ `bpf_check` | รัน `make week06-test` แล้วเอาผลมาเทียบกับเครื่องมือใน Week 16 |
