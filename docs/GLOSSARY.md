# 📖 อภิธานศัพท์ eBPF (Glossary)

รวม **86 คำศัพท์** ที่ใช้ในหลักสูตร **eBPF Zero to Hero** พร้อมความหมายภาษาไทย คอลัมน์ "เรียนใน" ลิงก์ไปยังแล็บที่สอนหรือใช้คำนั้นเป็นหลัก ส่วนทฤษฎีเชิงลึกดูได้ใน [`MASTER_STUDY_GUIDE.md`](MASTER_STUDY_GUIDE.md)

> ค้นหาคำที่ต้องการได้เร็วด้วย Ctrl+F ชื่อคำศัพท์ใช้ภาษาอังกฤษตามที่พบในโค้ดและเอกสารของเคอร์เนล

<a id="toc"></a>

## สารบัญ

- [🌐 เครือข่ายลินุกซ์ (Linux Networking)](#net)
- [🧠 แกนหลัก eBPF (Core Concepts)](#core)
- [🧰 เครื่องมือและไลบรารี (Toolchain)](#tools)
- [🪝 จุด Hook และชนิดโปรแกรม (Hooks & Program Types)](#hooks)
- [🗃️ ชนิดของ Map (Map Types)](#maps)
- [🛡️ ความปลอดภัย (Security)](#sec)
- [📈 ประสิทธิภาพและ Observability](#perf)
- [⚡ เร่งความเร็ว Socket (Socket Acceleration)](#accel)
- [🚀 eBPF ยุคใหม่ (Modern Extensibility)](#modern)
- [🌍 ระบบนิเวศ (Ecosystem)](#eco)

---

<a id="net"></a>

## 🌐 เครือข่ายลินุกซ์ (Linux Networking)

พื้นฐานที่ต้องรู้ก่อนเขียนโปรแกรม XDP/TC

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **Network Namespace (netns)** | สำเนาแยกของ network stack ทั้งชุด (interface, route, ARP, iptables, socket) ใช้จำลองหลายเครื่องในเครื่องเดียว ทุกแล็บเครือข่ายรันใน netns เพื่อไม่กระทบเครื่องจริง | [W01](../phase01-network-foundation/week01-packet-netns/README.md) |
| **veth pair** | interface เสมือนที่มาเป็นคู่ แพ็กเก็ตที่ส่งเข้าปลายหนึ่งจะออกอีกปลายหนึ่ง ใช้เชื่อม netns เข้าด้วยกันหรือเข้ากับ bridge | [W01](../phase01-network-foundation/week01-packet-netns/README.md) |
| **Linux Bridge** | switch ระดับ L2 ในเคอร์เนล เรียนรู้ MAC address แล้วส่งเฟรมไปยังพอร์ตที่ถูกต้อง | [W02](../phase01-network-foundation/week02-linux-net-stack/README.md) |
| **sk_buff (skb)** | โครงสร้างที่เคอร์เนลใช้แทนแพ็กเก็ตหนึ่งตัวตลอดเส้นทางใน stack เก็บทั้งข้อมูลและ metadata โปรแกรม TC เห็นผ่าน `struct __sk_buff` | [W02](../phase01-network-foundation/week02-linux-net-stack/README.md) |
| **NAPI** | กลไกของ driver ที่สลับจาก interrupt ทีละแพ็กเก็ตไปเป็น polling เป็นชุดเมื่อทราฟฟิกสูง XDP แบบ native ทำงานในขั้นนี้ ก่อนเคอร์เนลสร้าง skb | [W02](../phase01-network-foundation/week02-linux-net-stack/README.md) |
| **GRO (Generic Receive Offload)** | รวมแพ็กเก็ต TCP ที่ต่อเนื่องกันเป็นก้อนใหญ่ก่อนส่งขึ้น stack เพื่อลดต้นทุนต่อแพ็กเก็ต | [W02](../phase01-network-foundation/week02-linux-net-stack/README.md) |
| **DNAT / Reverse NAT** | DNAT เปลี่ยน IP ปลายทาง (เช่น VIP → backend) ในขาไป ส่วน Reverse NAT เปลี่ยน IP ต้นทางกลับ (backend → VIP) ในขากลับ เพื่อให้ client เห็นคู่สนทนาเดิม | [W08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) |
| **DSR (Direct Server Return)** | รูปแบบ load balancing ที่ backend ตอบ client โดยตรงไม่ผ่าน LB ทางเลือกของ Reverse NAT | [W08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) |
| **Incremental Checksum (RFC 1624)** | แก้ checksum จากส่วนต่างของฟิลด์ที่เปลี่ยน แทนการคำนวณใหม่ทั้ง header ใน BPF ใช้ `bpf_csum_diff()` หรือ `bpf_l3_csum_replace()` / `bpf_l4_csum_replace()` | [W08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="core"></a>

## 🧠 แกนหลัก eBPF (Core Concepts)

แนวคิดที่ใช้ในทุกแล็บ

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **eBPF** | virtual machine ในเคอร์เนลที่รันโปรแกรมขนาดเล็กซึ่งผ่านการตรวจแล้ว ณ จุด hook ต่าง ๆ ขยายความสามารถเคอร์เนลได้โดยไม่ต้องแก้ซอร์สหรือโหลด kernel module | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) |
| **bpf() syscall** | ช่องทางที่ user space ใช้คุยกับระบบย่อย BPF ทั้งหมด: โหลดโปรแกรม สร้าง/อ่าน map และ attach | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) |
| **Verifier** | ตัวตรวจโปรแกรมก่อนโหลด ไล่ทุกเส้นทางที่เป็นไปได้ บังคับให้ตรวจขอบเขตก่อนอ่านหน่วยความจำ เช็ก NULL ก่อนใช้ pointer และลูปต้องจบเสมอ ถ้าไม่ผ่านจะได้ verifier log บอกคำสั่งที่ผิด | [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) [W11](../phase06-production-capstone/week11-verifier-prometheus/README.md) |
| **JIT (Just-In-Time) Compiler** | แปลง bytecode ของ BPF เป็นคำสั่งเครื่องจริงหลังผ่าน verifier ทำให้เร็วใกล้เคียงโค้ดเคอร์เนลปกติ | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) |
| **Helper Function** | ฟังก์ชันที่เคอร์เนลเปิดให้โปรแกรม BPF เรียก มี ABI คงที่ เช่น `bpf_map_lookup_elem()`, `bpf_ktime_get_ns()`, `bpf_get_current_pid_tgid()` | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **kfunc** | ฟังก์ชันภายในเคอร์เนลที่เปิดให้ BPF เรียกผ่าน BTF ต่างจาก helper ตรงที่ไม่รับประกัน ABI ข้ามเวอร์ชัน และใช้ flag อย่าง `KF_ACQUIRE` / `KF_RELEASE` ให้ verifier ตรวจการคืน reference | [W24](../phase11-modern-ebpf-extensibility/week24-kfuncs-arena/README.md) |
| **Map** | โครงสร้างข้อมูลแบบ key/value ที่อยู่ในหน่วยความจำเคอร์เนล ใช้เก็บสถานะข้ามการทำงานของโปรแกรม และแชร์ข้อมูลระหว่าง BPF กับ user space | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) |
| **BTF (BPF Type Format)** | ข้อมูลชนิดแบบกะทัดรัด (struct, field, function signature) เคอร์เนลเผยแพร่ของตัวเองที่ `/sys/kernel/btf/vmlinux` เป็นฐานของ CO-RE, fentry, kfunc และ struct_ops | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **CO-RE (Compile Once – Run Everywhere)** | คอมไพล์ครั้งเดียวรันได้หลายเคอร์เนล คอมไพเลอร์บันทึกว่าโค้ดอ่านฟิลด์ใด แล้ว loader ปรับ offset ให้ตรงกับ BTF ของเครื่องที่รันตอนโหลด | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **vmlinux.h** | header ที่สร้างจาก BTF ของเคอร์เนล (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`) รวมนิยาม struct ทั้งหมด ใช้แทนการ include kernel headers | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **BPF_CORE_READ()** | macro อ่านฟิลด์ผ่าน pointer หลายชั้นพร้อม CO-RE relocation เช่น `BPF_CORE_READ(task, real_parent, tgid)` | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **SEC()** | macro ระบุ ELF section ของโปรแกรมหรือ map ซึ่ง loader ใช้รู้ชนิดโปรแกรมและ hook เช่น `SEC("xdp")`, `SEC("tracepoint/sched/sched_process_exec")`, `SEC(".maps")` | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **bpf_link** | อ็อบเจกต์ที่แทนการ attach หนึ่งครั้ง เมื่อปิด fd สุดท้าย (และไม่ได้ pin) โปรแกรมจะถูก detach อัตโนมัติ จึงไม่ค้างหลังโปรเซสจบ | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **bpffs และ Pinning** | ระบบไฟล์ `/sys/fs/bpf` ใช้ pin โปรแกรม, map หรือ link ไว้เป็นไฟล์ เพื่อให้อยู่ต่อหลังโปรเซสที่โหลดจบ หรือให้โปรเซสอื่นเปิดใช้ | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **RLIMIT_MEMLOCK** | เคอร์เนลก่อน 5.11 คิดหน่วยความจำของ map จาก memlock rlimit โค้ดจึงเรียก `rlimit.RemoveMemlock()` ไว้เพื่อความเข้ากันได้ เคอร์เนลใหม่คิดผ่าน memory cgroup แทน | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **BPF_PROG_TEST_RUN** | รันโปรแกรมกับ input จำลองโดยไม่ต้อง attach จริง (Go: `prog.Run()`) ใช้เขียน unit test ของ XDP/TC ได้ แต่ไม่รองรับ tracepoint/kprobe | [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="tools"></a>

## 🧰 เครื่องมือและไลบรารี (Toolchain)

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **bpftool** | เครื่องมือมาตรฐานสำหรับดูและจัดการ BPF: `prog show`, `map dump`, `btf dump`, `prog load` และดูโค้ดที่ JIT แล้ว | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) |
| **bpftrace** | ภาษาสคริปต์ระดับสูงสำหรับ tracing แบบ one-liner คอมไพล์เป็น BPF ให้อัตโนมัติ มี map ในตัว (`@name`) และฟังก์ชันสรุปผลอย่าง `count()`, `hist()` | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) |
| **BCC (BPF Compiler Collection)** | framework Python/C ที่คอมไพล์โค้ด C ตอนรันบนเครื่องเป้าหมาย ต้องมี clang และ kernel headers เป็นรุ่นก่อนยุค CO-RE | [W04](../phase02-first-step-ebpf/week04-bcc-python/README.md) |
| **libbpf** | ไลบรารี C อ้างอิงของเคอร์เนลสำหรับโหลด BPF object จัดการ CO-RE relocation และ attach | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **cilium/ebpf** | ไลบรารี Go แท้ (ไม่ใช้ cgo) สำหรับโหลด attach และอ่าน map ใช้เป็นฝั่ง user space ของแล็บตั้งแต่ W05 | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **bpf2go** | เครื่องมือที่เรียกผ่าน `go generate` คอมไพล์ไฟล์ `.c` ด้วย clang แล้วฝัง `.o` ลงในไบนารี Go พร้อมสร้าง struct ของโปรแกรมและ map ให้ | [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **PT_REGS_PARMn()** | macro อ่านอาร์กิวเมนต์ตัวที่ n จาก `struct pt_regs` ใน kprobe ตาม calling convention ของสถาปัตยกรรม fentry ไม่ต้องใช้เพราะได้อาร์กิวเมนต์ตามชนิดจาก BTF | [W04](../phase02-first-step-ebpf/week04-bcc-python/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="hooks"></a>

## 🪝 จุด Hook และชนิดโปรแกรม (Hooks & Program Types)

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **kprobe / kretprobe** | แทรก probe ที่ต้นหรือตอนคืนค่าของฟังก์ชันเคอร์เนลเกือบทุกตัวแบบ dynamic ยืดหยุ่นแต่ไม่มี ABI คงที่ ชื่อหรืออาร์กิวเมนต์ของฟังก์ชันอาจเปลี่ยนข้ามเวอร์ชัน | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) [W04](../phase02-first-step-ebpf/week04-bcc-python/README.md) |
| **Tracepoint** | จุดที่นักพัฒนาเคอร์เนลวางไว้ล่วงหน้า รูปแบบข้อมูลค่อนข้างคงที่ เช่น `sched:sched_process_exec`, `skb:kfree_skb` | [W03](../phase02-first-step-ebpf/week03-bpftool-bpftrace/README.md) [W05](../phase03-modern-ebpf-core/week05-libbpf-cilium-go/README.md) |
| **Raw Tracepoint** | tracepoint ที่ได้อาร์กิวเมนต์ดิบโดยไม่ผ่านการจัดรูปแบบ ต้นทุนต่ำกว่า เช่น `raw_syscalls:sys_enter` ที่ใช้นับ syscall ทุกตัว | [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) |
| **tp_btf** | raw tracepoint ที่มี BTF กำกับ อ่านอาร์กิวเมนต์ชนิด pointer (เช่น `struct request *`) ได้ตรงโดยไม่ต้องใช้ probe_read | [W17](../phase08-system-performance-observability/week17-block-io-biolatency/README.md) |
| **uprobe / uretprobe** | probe ที่ฟังก์ชันในโปรแกรมหรือไลบรารีฝั่ง user space เช่น `SSL_write` ของ libssl เพื่อดูข้อมูลก่อนเข้ารหัส | [W09](../phase05-security-observability/week09-ringbuf-uprobes/README.md) |
| **fentry / fexit** | hook ต้นและท้ายฟังก์ชันเคอร์เนลผ่าน BPF trampoline เร็วกว่า kprobe ได้อาร์กิวเมนต์ตามชนิดจาก BTF และ fexit เห็นทั้งอาร์กิวเมนต์และค่าที่คืน | [W10](../phase05-security-observability/week10-bpf-lsm/README.md) [W22](../phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/README.md) |
| **BPF Trampoline** | โค้ดเครื่องที่ JIT สร้างให้แต่ละฟังก์ชันเป้าหมาย เคอร์เนล patch คำสั่ง nop ต้นฟังก์ชันให้ call เข้า trampoline ซึ่งเรียกโปรแกรม fentry ตัวฟังก์ชันจริง และ fexit ตามลำดับ | [W22](../phase10-cutting-edge-ebpf-technologies/week22-fentry-fexit-trampoline/README.md) |
| **fmod_ret** | โปรแกรมแบบ trampoline ที่เปลี่ยนค่าที่คืนของฟังก์ชันได้ (เฉพาะฟังก์ชันที่อนุญาต) Tetragon ใช้ทำ action `Override` | [W26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) |
| **XDP (eXpress Data Path)** | hook เร็วที่สุดของขาเข้า ทำงานใน driver ก่อนสร้าง skb คืนค่า `XDP_PASS`, `XDP_DROP`, `XDP_TX`, `XDP_REDIRECT` หรือ `XDP_ABORTED` มีโหมด native, generic และ offload | [W07](../phase04-high-speed-networking/week07-xdp-parsing/README.md) |
| **XDP_TX / XDP_REDIRECT** | `XDP_TX` ส่งแพ็กเก็ตกลับออกการ์ดใบเดิม (hairpin) ส่วน `XDP_REDIRECT` ส่งต่อไปการ์ดอื่น CPU อื่น หรือ AF_XDP socket ผ่าน map | [W08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) [W21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) |
| **TC (Traffic Control) / clsact** | hook ทั้งขาเข้าและขาออกที่ทำงานกับ skb แล้ว มี metadata ครบและแก้แพ็กเก็ตได้ด้วย helper ของ skb คืนค่าเช่น `TC_ACT_OK`, `TC_ACT_SHOT` | [W08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) |
| **TCX** | วิธี attach โปรแกรม TC แบบใหม่ (Linux 6.6+) ผ่าน bpf_link ไม่ต้องสร้าง qdisc clsact และจัดลำดับหลายโปรแกรมได้ Cilium ใช้กลไกนี้ | [W08](../phase04-high-speed-networking/week08-tc-loadbalancer/README.md) |
| **BPF LSM** | แนบโปรแกรมกับ LSM hook (เช่น `file_open`, `bprm_check_security`) เพื่อตัดสินอนุญาตหรือปฏิเสธ (`-EPERM`) ต้องเปิด `bpf` ในรายการ LSM ของเคอร์เนล | [W10](../phase05-security-observability/week10-bpf-lsm/README.md) |
| **cgroup sock_addr (connect4)** | hook ที่ทำงานตอนโปรเซสใน cgroup เรียก `connect()` ใน process context ของผู้เรียก ใช้อนุญาตหรือปฏิเสธการเชื่อมต่อก่อนสร้าง SYN | [W14](../phase07-advanced-security-observability/week14-cgroup-sock-addr/README.md) |
| **sockops** | โปรแกรมที่เคอร์เนลเรียกเมื่อเกิดเหตุการณ์ของ TCP socket ใน cgroup เช่น handshake สำเร็จ (`ACTIVE/PASSIVE_ESTABLISHED_CB`) | [W20](../phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/README.md) |
| **sk_msg** | โปรแกรมที่ทำงานตอน `sendmsg()` บน socket ที่อยู่ใน SOCKHASH/SOCKMAP ส่งข้อมูลตรงเข้าคิวรับของ socket ปลายทางได้ด้วย `bpf_msg_redirect_hash()` | [W20](../phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/README.md) |
| **perf_event** | โปรแกรมที่ทำงานทุกครั้งที่ perf event เกิด เช่น CPU clock sampling ที่ความถี่คงที่ ใช้ทำ CPU profiler | [W18](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md) |
| **BPF Iterator (bpf_iter)** | โปรแกรมที่เคอร์เนลเรียกทีละรายการขณะเดินโครงสร้างข้อมูล (เช่น task ทุกตัว) แล้วเขียนผลลง seq_file ให้ user space อ่านผ่าน `read()` | [W23](../phase10-cutting-edge-ebpf-technologies/week23-bpf-iterators/README.md) |
| **struct_ops** | ให้โปรแกรม BPF ทำหน้าที่แทนตารางฟังก์ชัน (ops) ของระบบย่อยในเคอร์เนล เช่น TCP congestion control หรือ CPU scheduler | [W25](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="maps"></a>

## 🗃️ ชนิดของ Map (Map Types)

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **HASH / ARRAY** | map พื้นฐาน HASH ใช้ key อะไรก็ได้ ARRAY ใช้ index 0..N-1 จองไว้ครบตั้งแต่สร้าง | [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) |
| **PERCPU_HASH / PERCPU_ARRAY** | แต่ละ CPU มีสำเนาค่าของตัวเอง เขียนได้โดยไม่ต้อง atomic ฝั่ง user space ต้องรวมค่าจากทุก CPU เอง | [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) |
| **LRU_HASH** | HASH ที่ไล่ entry ที่ใช้น้อยที่สุดออกอัตโนมัติเมื่อเต็ม เหมาะกับตาราง flow หรือ rate limit ที่ key ไม่จำกัด | [W06](../phase03-modern-ebpf-core/week06-ebpf-maps/README.md) |
| **PERF_EVENT_ARRAY** | ส่ง event ไป user space ผ่านบัฟเฟอร์แยกต่อ CPU (BCC เรียก `BPF_PERF_OUTPUT`) ลำดับ event ข้าม CPU ไม่รับประกัน | [W04](../phase02-first-step-ebpf/week04-bcc-python/README.md) |
| **RINGBUF** | บัฟเฟอร์วงแหวนเดียวที่ทุก CPU ใช้ร่วมกัน (Linux 5.8+) รักษาลำดับ event และใช้ `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()` เพื่อเขียนโดยไม่ต้อง copy ซ้ำ | [W09](../phase05-security-observability/week09-ringbuf-uprobes/README.md) |
| **STACK_TRACE** | เก็บ call stack ที่ได้จาก `bpf_get_stackid()` แล้วคืน id ไปใช้เป็น key ใน map อื่น | [W18](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md) |
| **SOCKHASH / SOCKMAP** | map ที่เก็บ socket ใช้คู่กับ sk_msg เพื่อ redirect ข้อมูลระหว่าง socket | [W20](../phase09-high-throughput-socket-acceleration/week20-tcp-sockops-bypass/README.md) |
| **XSKMAP** | map ที่เก็บ AF_XDP socket ตาม queue id ให้โปรแกรม XDP ใช้ `bpf_redirect_map()` ส่งแพ็กเก็ตขึ้น user space | [W21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) |
| **ARENA** | พื้นที่หน่วยความจำ (สูงสุด 4 GiB) ที่ BPF และ user space `mmap` ร่วมกัน ใช้สร้างโครงสร้างข้อมูลที่มี pointer จริงอย่าง linked list | [W24](../phase11-modern-ebpf-extensibility/week24-kfuncs-arena/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="sec"></a>

## 🛡️ ความปลอดภัย (Security)

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **LSM (Linux Security Module)** | กรอบของเคอร์เนลที่วาง hook ไว้ก่อนการกระทำสำคัญ (เปิดไฟล์, exec, socket) ให้โมดูลความปลอดภัยตัดสิน เช่น SELinux, AppArmor และ BPF LSM | [W10](../phase05-security-observability/week10-bpf-lsm/README.md) |
| **unprivileged_bpf_disabled** | sysctl ที่กำหนดว่าผู้ใช้ทั่วไปใช้ `bpf()` ได้หรือไม่ หนึ่งในค่าที่ W16 ตรวจเพื่อประเมินความแข็งแรงของระบบ | [W16](../phase07-advanced-security-observability/week16-ebpf-integrity-audit/README.md) |
| **bpf_jit_harden** | sysctl ที่ให้ JIT สุ่ม (blind) ค่าคงที่ในโค้ดเครื่องเพื่อลดความเสี่ยงจากการโจมตีแบบ JIT spraying | [W16](../phase07-advanced-security-observability/week16-ebpf-integrity-audit/README.md) |
| **BPF Token** | กลไก (ราว Linux 6.9+) มอบสิทธิ์ใช้ BPF แบบจำกัดคำสั่งและชนิดโปรแกรมให้ container แทนการให้ `CAP_SYS_ADMIN` หรือ `CAP_BPF` เต็มรูปแบบ | [W16](../phase07-advanced-security-observability/week16-ebpf-integrity-audit/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="perf"></a>

## 📈 ประสิทธิภาพและ Observability

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **kfree_skb และ Drop Reason** | tracepoint `skb:kfree_skb` เกิดทุกครั้งที่เคอร์เนลทิ้งแพ็กเก็ต พร้อมรหัสเหตุผล (`enum skb_drop_reason`) เช่น `NO_SOCKET` ซึ่งแปลงเป็นชื่อได้จาก BTF | [W13](../phase07-advanced-security-observability/week13-kfree-skb-dropwatch/README.md) |
| **Log2 Histogram** | เก็บค่าเป็นช่วงกำลังสอง (1, 2–3, 4–7, ...) ด้วยการนับ slot = log2(ค่า) ประหยัดที่และเห็นการกระจายของ latency ได้ทันที | [W17](../phase08-system-performance-observability/week17-block-io-biolatency/README.md) |
| **Flame Graph** | ภาพสรุป stack ที่สุ่มเก็บ แกนนอนคือสัดส่วนเวลา CPU กล่องกว้างคือโค้ดที่กิน CPU มาก | [W18](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md) |
| **kallsyms** | `/proc/kallsyms` ตารางที่อยู่ของ symbol ในเคอร์เนล ใช้แปลงที่อยู่ใน stack หรือ `location` ให้เป็นชื่อฟังก์ชัน | [W13](../phase07-advanced-security-observability/week13-kfree-skb-dropwatch/README.md) [W18](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md) |
| **Frame Pointer** | รีจิสเตอร์ที่ชี้ frame ปัจจุบันบน stack ทำให้ไล่ call stack ได้ถูกต้อง โปรแกรมที่คอมไพล์โดยตัด frame pointer ทิ้งจะได้ stack ฝั่ง user ไม่ครบ | [W18](../phase08-system-performance-observability/week18-cpu-profiler-stacks/README.md) |
| **Page Fault / OOM Killer** | page fault เกิดเมื่อโปรเซสแตะหน้าหน่วยความจำที่ยังไม่ map ส่วน OOM killer เลือกโปรเซสทิ้งเมื่อหน่วยความจำ (หรือ `memory.max` ของ cgroup) เต็ม | [W19](../phase08-system-performance-observability/week19-memory-oom-watcher/README.md) |
| **Prometheus Exporter** | โปรแกรมที่เปิด endpoint `/metrics` ให้ Prometheus มาดึงตัวเลข ใช้ส่งค่าจาก BPF map ไปทำ dashboard | [W11](../phase06-production-capstone/week11-verifier-prometheus/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="accel"></a>

## ⚡ เร่งความเร็ว Socket (Socket Acceleration)

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **AF_XDP** | socket family ที่รับส่งแพ็กเก็ตระหว่าง XDP กับ user space ผ่าน ring ในหน่วยความจำร่วม ข้าม TCP/IP stack ของเคอร์เนล | [W21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) |
| **UMEM** | พื้นที่หน่วยความจำที่ user space จองแล้วลงทะเบียนกับ AF_XDP socket แบ่งเป็น frame ขนาดเท่ากันไว้เก็บแพ็กเก็ต | [W21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) |
| **FILL / RX / TX / COMPLETION Ring** | ring 4 วงของ AF_XDP: FILL (user ส่ง frame ว่างให้ kernel), RX (kernel ส่ง frame ที่มีแพ็กเก็ตให้ user), TX และ COMPLETION (ขาส่ง) แต่ละวงมีผู้ผลิตและผู้บริโภคฝ่ายละหนึ่ง | [W21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) |
| **Copy Mode / Zero-copy** | copy mode (`XDP_COPY`) ให้เคอร์เนล copy แพ็กเก็ตลง UMEM ใช้ได้ทุก driver ส่วน zero-copy (`XDP_ZEROCOPY`) ให้การ์ดเขียนลง UMEM ตรง ต้องใช้ driver ที่รองรับ | [W21](../phase09-high-throughput-socket-acceleration/week21-af-xdp-redirect/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="modern"></a>

## 🚀 eBPF ยุคใหม่ (Modern Extensibility)

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **KF_ACQUIRE / KF_RELEASE** | flag ของ kfunc: ตัวที่เป็น `KF_ACQUIRE` คืน reference ที่โปรแกรมต้องส่งให้ kfunc แบบ `KF_RELEASE` ก่อนจบทุกเส้นทาง ไม่อย่างนั้น verifier ปฏิเสธด้วย `Unreleased reference` | [W24](../phase11-modern-ebpf-extensibility/week24-kfuncs-arena/README.md) |
| **RCU (Read-Copy-Update)** | กลไก synchronization ที่ให้อ่านข้อมูลร่วมได้โดยไม่ล็อก ใน BPF ใช้ `bpf_rcu_read_lock()` / `bpf_rcu_read_unlock()` ครอบการอ่าน pointer ที่ RCU ปกป้อง | [W24](../phase11-modern-ebpf-extensibility/week24-kfuncs-arena/README.md) |
| **sched_ext** | scheduling class (Linux 6.12+) ที่ให้เขียน CPU scheduler ทั้งตัวด้วย BPF ผ่าน struct_ops ถ้า scheduler ผิดพลาดเคอร์เนลจะ eject แล้วคืน task ให้ fair class | [W25](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md) |
| **DSQ (Dispatch Queue)** | คิวงานของ sched_ext ที่ callback ใส่และดึง task (`scx_bpf_dsq_insert()`, `scx_bpf_dsq_move_to_local()`) มีทั้ง local DSQ ต่อ CPU และ DSQ ที่สร้างเอง ไม่ใช่ BPF map | [W25](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md) |
| **vtime** | virtual time ที่ใช้เรียงคิวแบบยุติธรรม task ที่ใช้ CPU ไปมากหรือ weight ต่ำจะมี vtime สูงและได้คิวหลัง | [W25](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md) |
| **Watchdog (sched_ext)** | ตัวเฝ้าที่ eject scheduler ถ้า task ที่ runnable ไม่ได้รันภายในเวลา `timeout_ms` กันระบบค้างจาก scheduler ที่มีบั๊ก | [W25](../phase11-modern-ebpf-extensibility/week25-struct-ops-sched-ext/README.md) |

[↑ กลับสารบัญ](#toc)

<a id="eco"></a>

## 🌍 ระบบนิเวศ (Ecosystem)

| คำศัพท์ | ความหมาย | เรียนใน |
|---|---|---|
| **Tetragon** | เครื่องมือ security observability และ runtime enforcement ของ Cilium กำหนดสิ่งที่จะเฝ้าด้วย TracingPolicy แล้วสร้างโปรแกรม BPF ให้อัตโนมัติ | [W26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) |
| **TracingPolicy** | ไฟล์ YAML ของ Tetragon ระบุ hook (kprobe, tracepoint, LSM), เงื่อนไขอย่าง `matchArgs` / `matchBinaries` และ action เช่น `Sigkill`, `Override` | [W26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) |
| **Cilium** | CNI สำหรับ Kubernetes ที่ใช้ eBPF ทำ networking, network policy และ load balancing แทน iptables | [W26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) |
| **kube-proxy Replacement** | โหมดของ Cilium ที่ทำ Service load balancing ด้วย BPF แทน kube-proxy (iptables/IPVS) | [W26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) |
| **Hubble** | ระบบ observability ของ Cilium แสดง flow ของเครือข่ายและ verdict ของ policy เช่น `hubble observe --verdict DROPPED` | [W26](../phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/README.md) |

[↑ กลับสารบัญ](#toc)
