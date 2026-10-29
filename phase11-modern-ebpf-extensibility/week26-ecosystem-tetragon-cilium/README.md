# สัปดาห์ที่ 26: ระบบนิเวศ eBPF ในงาน Production — Tetragon และ Cilium (The eBPF Ecosystem: Tetragon & Cilium)

ยินดีต้อนรับสู่ **Week 26** ของหลักสูตร eBPF Zero to Hero!

ตลอด 25 สัปดาห์ที่ผ่านมา เราเขียนโปรแกรม eBPF ด้วยมือทุกชิ้น ตั้งแต่ tracepoint ดู `execve` (Week 09), BPF LSM บล็อกไฟล์ (Week 10), cgroup/connect4 คุมการเชื่อมต่อ (Week 14), ไปจนถึง fentry/fexit (Week 22) สัปดาห์สุดท้ายนี้เราจะดูว่า **เครื่องมือ production** ของจริงเอากลไกเดียวกันนี้ไป "แพ็ก" อย่างไร:

- **Tetragon** (ลงมือจริง): security observability + runtime enforcement ที่เขียน "นโยบาย" เป็น YAML (`TracingPolicy`) แทนการเขียน C/Go เอง
- **Cilium** (แนวคิด + hands-on แบบทางเลือก): CNI ของ Kubernetes ที่ใช้ eBPF ทำ datapath (TCX/XDP), socket load balancing, kube-proxy replacement และ observability ผ่าน Hubble

เป้าหมายของบทนี้ไม่ใช่การท่องคำสั่งของเครื่องมือ แต่คือ **อ่าน output ของเครื่องมือเหล่านี้แล้วบอกได้ว่าข้างใต้คือ BPF program ชนิดไหน แนบที่ hook ใด** ซึ่งเป็นสิ่งที่เราสร้างเองมาแล้วทั้งหมด

> [!WARNING]
> **ความปลอดภัยของแล็บ:** Tetragon รันเป็น **privileged container** (`--privileged --pid=host`) ซึ่งเท่ากับให้สิทธิ์ root เต็มบนโฮสต์ ทุก policy ในโฟลเดอร์นี้จึงจับเฉพาะไฟล์ใน `lab-files/` ของโฟลเดอร์นี้ (หรือพอร์ต 18026 บน loopback) เท่านั้น `make test` ตรวจกฎนี้ให้อัตโนมัติ (path ใน `matchArgs` หรือ binary ใน `matchBinaries` ต้องอยู่ใน `lab-files/`) และ **ต้อง `make down` ทุกครั้งหลังทดลอง** (สคริปต์จะตรวจให้ว่าไม่มี BPF program ของ Tetragon ค้างอยู่)

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 จาก "โค้ดที่เราเขียนเอง" สู่ "นโยบายที่เครื่องมือโหลดให้"

ทุกเครื่องมือ eBPF ระดับ production มีส่วนประกอบเดียวกับแล็บของเรา คือ BPF program + map + loader ใน user space + ช่องทางส่ง event (ring buffer/perf buffer) ความต่างอยู่ที่ **ใครเป็นคนเขียน BPF program**:

| สิ่งที่ทำในแล็บนี้ | กลไกใน Tetragon / Cilium | สัปดาห์ที่เราเขียนเองด้วยมือ |
| :--- | :--- | :--- |
| เห็น `process_exec` / `process_exit` ทุกโปรเซส | base sensor: tracepoint `sched_process_exec` (`event_execve`), kprobe `acct_process`, `wake_up_new_task` + ring/perf buffer | **Week 09** (`tracepoint/sched/sched_process_exec` + ring buffer), Week 15, Week 23 |
| Policy 01: LSM `bprm_check_security` | `lsmhooks:` → BPF LSM program (`generic_lsm_*`) | **Week 10** (`SEC("lsm/file_open")`) |
| Policy 02: ดูการเปิดไฟล์ใน `lab-files/` | `kprobes: security_file_open` + `matchArgs` (กรองใน kernel) | **Week 10** (`fentry/security_file_open`), **Week 22** (fentry/fexit) |
| Policy 03: ดู `tcp_connect` / `tcp_close` | kprobe + อ่าน `struct sock` ด้วย BTF | **Week 14** (`cgroup/connect4`), **Week 15** (reverse shell = shell + socket) |
| Policy 04: `Sigkill` คนที่เปิด `secret.txt` | `bpf_send_signal(SIGKILL)` จากใน BPF | (ใหม่) — ต่อยอด Week 10/15 จาก "ตรวจจับ" เป็น "ตอบโต้" |
| Policy 05: `Override` → `-EPERM` | BPF LSM return value | **Week 10** (enforce mode) |
| Policy 06: `Override` บน kprobe | BPF trampoline **`fmod_ret`** (`BPF_MODIFY_RETURN`) | **Week 22** (BPF trampoline) |
| `make progs` ดูว่า Tetragon โหลดอะไร | `bpftool prog show` / `link show` | **Week 03** (bpftool), **Week 16** (audit BPF บนโฮสต์) |
| Cilium: socket LB / kube-proxy replacement | `cgroup_inet4_connect`, `cgroup_inet4_getpeername`, ... | **Week 14** (`cgroup/connect4`), **Week 20** (socket-level shortcut ด้วย sockops/sk_msg) |
| Cilium: datapath บน interface | `tcx/ingress`, `tcx/egress` (และ XDP บน NIC ที่รองรับ) | **Week 07** (XDP), **Week 08** (TC), Week 12 |
| Hubble: เห็น flow และ `DROPPED` พร้อมเหตุผล | event จาก datapath ส่งขึ้น agent | **Week 13** (drop reason จาก `kfree_skb`) |

### 1.2 สถาปัตยกรรมของ Tetragon

```
 ┌──────────────────────────── user space ─────────────────────────────────────┐
 │                                                                              │
 │   policies/*.yaml ──(tetra tracingpolicy add)──┐                             │
 │                                                ▼                             │
 │   ┌──────────────── tetragon daemon (privileged container) ──────────────┐   │
 │   │ policy handler → แปลง YAML เป็น BPF program + ค่าใน map (selectors)  │   │
 │   │ process cache (execve_map) → เติม parent / exec_id / arguments      │   │
 │   │ gRPC server :54321 ──→ tetra getevents -o compact / json            │   │
 │   └──────────────▲────────────────────────────────────────────────────────┘   │
 └──────────────────┼───────────────────────────────────────────────────────────┘
                    │ event (ring buffer / perf buffer)
 ┌──────────────────┼────────────────── kernel ─────────────────────────────────┐
 │  base sensor:    │                                                           │
 │   tracepoint sched_process_exec ─┐   kprobe acct_process / wake_up_new_task  │
 │                                  │                                           │
 │  generic sensors (ตาม policy):    ▼                                           │
 │   hook ─→ *_event ─tail call→ *_setup_event ─→ *_process_event               │
 │        ─→ *_filter_arg (matchArgs/matchBinaries ประเมิน "ใน kernel")          │
 │        ─→ *_actions  (Post | Sigkill | Override | ...)  ─→ *_output ─→ event   │
 │                                                                              │
 │   hook = kprobe_multi (kprobes:) | BPF LSM (lsmhooks:) | fmod_ret (Override)  │
 └──────────────────────────────────────────────────────────────────────────────┘
```

ประเด็นสำคัญ:

1. **กรองใน kernel ก่อนส่งขึ้น user space** — `matchArgs` ถูกประเมินใน `generic_*_filter_arg` เหตุการณ์ที่ไม่ตรงจะไม่ข้าม ring buffer เลย ต่างจากเครื่องมือที่ดัก syscall ทั้งหมดแล้วไปกรองใน user space
2. **Tail call pipeline** — โปรแกรมเดียวทำทุกอย่างไม่ได้เพราะติดขีดจำกัดของ verifier Tetragon จึงแตกเป็นหลายโปรแกรม (`_event`, `_setup_event`, `_process_event`, `_filter_arg`, `_actions`, `_output`) แล้วกระโดดหากันด้วย `bpf_tail_call` ผลคือ policy 1 ตัวที่มี hook 2 ตัวสร้าง BPF program ได้หลายสิบตัว (ดู 4.4)
3. **Enforcement เกิดแบบ synchronous ใน kernel** — `Sigkill`/`Override` ทำงานในบริบทของโปรเซสที่กำลังเรียก syscall อยู่ ไม่ต้องรอ user space ตัดสินใจ (จึงไม่มี race แบบ "ตรวจเจอแล้วค่อยไป kill ทีหลัง")
4. **Policy mode** — `enforce` หรือ `monitor` (`tetra tracingpolicy set-mode`) ในโหมด monitor action ที่เป็น enforcement จะถูกนับใน `NMONITOR` แทนที่จะทำจริง เหมาะกับการ "ซ้อมใช้" policy ก่อนบังคับจริง

### 1.3 โครงสร้างของ `TracingPolicy`

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "..."                 # ชื่อที่เห็นใน tetra tracingpolicy list / --policy-names
spec:
  kprobes:  | lsmhooks: | tracepoints: | uprobes:     # จะ hook ที่ไหน
  - call: "security_file_open"  # (lsmhooks ใช้ hook: "file_open")
    args:                       # อ่านอาร์กิวเมนต์ตัวไหน และตีความเป็นชนิดอะไร
    - index: 0
      type: "file"              # file / path / linux_binprm / sock / int / string ...
    selectors:                  # หลาย selector = OR, เงื่อนไขภายใน selector = AND
    - matchArgs:  [...]         # Equal / Prefix / Postfix / DAddr / DPort / Mask ...
      matchBinaries: [...]      # จำกัดเฉพาะ binary
      matchActions: [...]       # Post (ค่าเริ่มต้น) / Sigkill / Override / Signal / ...
```

`type: "file"` สำคัญมาก: Tetragon อ่าน `struct file *` แล้วสร้าง path เต็มด้วย d_path ภายใน BPF เอง (สิ่งที่ Week 10 ต้องเลือกระหว่าง "ชื่อไฟล์" กับ "inode") ส่วน `type: "sock"` จะถอด `saddr/daddr/sport/dport` จาก `struct sock` ผ่าน BTF ให้ — นี่คือเหตุผลที่ policy เขียนสั้นได้ขนาดนี้

### 1.4 Enforcement 3 แบบ และข้อจำกัดของแต่ละแบบ

| Action / hook | กลไก kernel | ผลต่อโปรเซส | เงื่อนไข (ตรวจบน Linux 7.0.0-38) |
| :--- | :--- | :--- | :--- |
| `Sigkill` (kprobe ใดก็ได้) | `bpf_send_signal(SIGKILL)` | ตายทันทีตอนกลับสู่ user space (exit 137) | ต้องการแค่ helper `bpf_send_signal` (Tetragon log: `signal: true`) |
| `Override` บน `lsmhooks:` | BPF LSM คืนค่า error | syscall คืน `-EPERM`, โปรเซสยังอยู่ | ต้องมี `bpf` ใน `/sys/kernel/security/lsm` (เครื่องนี้: `lockdown,capability,landlock,yama,apparmor,bpf,ima,evm`) |
| `Override` บน `kprobes:` ฟังก์ชัน `security_*` | BPF trampoline `fmod_ret` | syscall คืน `-EPERM` | verifier ยอมให้ `fmod_ret` เฉพาะฟังก์ชัน `security_*` หรือที่อยู่ใน error-injection list และ Tetragon ต้องรันด้วย `--disable-kprobe-multi` (ดู 4.7) |
| `Override` บน syscall (`syscall: true`) | `bpf_override_return()` | syscall คืน error | ต้อง `CONFIG_BPF_KPROBE_OVERRIDE=y` (เครื่องนี้ `=y`) และฟังก์ชันต้องอยู่ใน `/sys/kernel/debug/error_injection/list` (เครื่องนี้มี 1066 รายการ เช่น `__x64_sys_openat` แต่ **ไม่มี** `security_*` เลย) |

> [!NOTE]
> ตรรกะการเลือกกลไก Override ข้างบนอ่านจาก `pkg/sensors/tracing/generickprobe.go` (`validateOverride`) ของ Tetragon tag `v1.7.1` ถ้าใช้เวอร์ชันอื่นให้ตรวจซ้ำ

### 1.5 Cilium: eBPF เป็น datapath ของทั้งคลัสเตอร์

```
                         Kubernetes API (Service, Pod, CiliumNetworkPolicy)
                                          │ watch
 ┌────────────────────────── Node ────────┼──────────────────────────────────────────┐
 │                                        ▼                                          │
 │   cilium-agent ── compile/load BPF ── เขียน map: services, backends, identity,    │
 │      │                                 policy (ต่อ endpoint), conntrack, NAT      │
 │      └── Hubble server ◄── trace/drop events ── datapath                          │
 │                                                                                   │
 │   Pod A (client)                        Pod B (web)                               │
 │   connect(10.96.x.x:80)                    ▲                                      │
 │      │                                     │                                      │
 │      ▼  cgroup_inet4_connect (socket LB):  │  tcx/ingress บน lxcXXXX               │
 │      เลือก backend แล้วเขียน dst ใหม่       │  (cil_from_container / to-endpoint):  │
 │      เป็น PodIP:80 ตั้งแต่ connect()        │  ตรวจ policy ด้วย security identity    │
 │      (getpeername ยังเห็น ClusterIP)       │                                      │
 │      ▼                                     │                                      │
 │   lxcXXXX ──► cilium_host / cilium_vxlan (tcx) ──► eth0 (tcx; XDP บน NIC จริง*)  │
 └───────────────────────────────────────────────────────────────────────────────────┘
   * XDP LB acceleration ใช้ได้เฉพาะ NIC/driver ที่รองรับ native XDP (ใน kind ไม่มี XDP)
```

- **TCX datapath** (Week 08): ทุก interface ที่ Cilium ดูแลมีโปรแกรม `tcx/ingress`/`tcx/egress` (เช่น `cil_from_container`, `cil_to_overlay`) แทน iptables
- **Socket LB / kube-proxy replacement** (Week 14, 20): แปลง ClusterIP → backend ตั้งแต่ `connect()` ด้วยโปรแกรม `cgroup_inet4_connect` จึงไม่ต้อง DNAT ทุกแพ็กเก็ต และไม่มีกฎ `KUBE-SVC` ใน iptables เลย (4.9 นับได้ 0)
- **Identity-based policy**: Cilium แปลง label ของ pod เป็นเลข **security identity** แล้วเก็บกฎใน policy map ของแต่ละ endpoint (Week 06) เมื่อ label เปลี่ยน identity ก็เปลี่ยน (เห็นจริงใน 4.9: `ID:14409` → `ID:34803`)
- **Hubble**: เก็บ trace/drop event จาก datapath แล้วแสดงเป็น flow พร้อมชื่อ pod และ verdict (`FORWARDED`, `Policy denied DROPPED`) — แนวคิดเดียวกับ drop reason ของ Week 13 แต่ผูกกับ identity ของ Kubernetes

### 1.6 เทียบกับ Falco แบบย่อ (ข้อมูลจากเอกสาร ไม่ได้ทดลองในแล็บนี้)

| | Tetragon | Falco |
| :--- | :--- | :--- |
| จุดดักข้อมูล | kprobe/LSM/tracepoint/uprobe ใดก็ได้ตาม policy | เน้น syscall (driver แบบ kernel module หรือ "modern eBPF probe" แบบ CO-RE) และ plugin เช่น audit log ของ k8s |
| การกรอง | ประเมิน selector **ใน kernel** | ส่ง syscall event ขึ้น user space แล้วประเมิน rule (ภาษา condition ของ Falco) ใน user space |
| Enforcement | มีใน kernel (`Sigkill`, `Override`) | โดยหลักเป็น detection; การตอบโต้ทำผ่านระบบภายนอก (เช่น Falcosidekick / Falco Talon) |

> [!NOTE]
> รายละเอียดของ Falco (ชนิด driver, ค่า default, ชื่อโปรเจกต์ response) เปลี่ยนตามเวอร์ชัน ตารางนี้สรุปจากเอกสารสาธารณะ ณ เวลาที่เขียน ยังไม่ได้รันบนเครื่องแล็บ ควรตรวจกับ <https://falco.org/docs/> ก่อนนำไปอ้างอิง

---

## 2. อธิบาย Policy และสคริปต์ทีละบรรทัด (Line-by-Line Breakdown)

ทุก policy อยู่ใน `policies/` และใช้ `operator: "Postfix"` กับ path ที่ลงท้ายด้วย `week26-ecosystem-tetragon-cilium/lab-files/...` เหตุผลคือ path เต็มขึ้นกับว่านักศึกษา clone repo ไว้ที่ไหน (เครื่องนี้คือ `/mnt/sda/ebpf/...`) การจับ "ส่วนท้าย" ทำให้ YAML ใช้ได้ทุกเครื่องโดยไม่ต้องแก้ และยังแคบพอที่จะไม่ไปโดนไฟล์ระบบ

### 2.1 `01-process-exec-lsm.yaml` — exec/exit + มุมมองจาก LSM

```yaml
spec:
  lsmhooks:
  - hook: "bprm_check_security"
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "week26-ecosystem-tetragon-cilium/lab-files/bin/w26-hello"
```
- **`process_exec` / `process_exit` ไม่ต้องมี policy**: base sensor ของ Tetragon (`__base__`) สร้างให้ทุกโปรเซสตั้งแต่เริ่มรัน (ดู 4.3) ตรงกับที่ Week 09 ทำด้วย `tracepoint/sched/sched_process_exec`
- **`lsmhooks:` + `bprm_check_security`**: เป็น BPF LSM hook ตัวเดียวกับที่ kernel ใช้ถาม LSM ว่า "รันไฟล์นี้ได้ไหม" (ชนิดโปรแกรมเดียวกับ Week 10)
- **`type: "linux_binprm"`**: Tetragon อ่าน `bprm->file` แล้วคืน path ของไฟล์ที่กำลังจะถูก exec
- **ไม่มี `matchActions`** → action เริ่มต้นคือ `Post` (ส่ง event อย่างเดียว)
- **ข้อสังเกต**: event นี้เกิด *ก่อน* exec สำเร็จ โปรเซสใน event จึงยังเป็น image เดิม (`/usr/bin/bash` ที่กำลังจะ exec) ไม่ใช่ `w26-hello` — กรองด้วย `--policy-names` แทน `--process`

### 2.2 `02-file-monitor.yaml` — ดูการเปิดไฟล์ใน `lab-files/`

```yaml
  kprobes:
  - call: "security_file_open"
    syscall: false
    return: true
    args:
    - index: 0
      type: "file"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "week26-ecosystem-tetragon-cilium/lab-files/notes.txt"
        - "week26-ecosystem-tetragon-cilium/lab-files/secret.txt"
```
- **`call: "security_file_open"`**: ฟังก์ชันที่ `do_dentry_open()` เรียกหลัง path lookup สำเร็จ ครอบคลุม `open`/`openat`/`openat2` ทั้งหมด (ต่างจากการ hook syscall ที่ต้องตามทุกเวอร์ชันของ syscall และอ่าน string จาก user memory)
- **`syscall: false`**: บอกว่าเป็นฟังก์ชันใน kernel ไม่ใช่ syscall entry (ไม่ต้องเติม prefix `__x64_sys_`)
- **`return: true` + `returnArg`**: แนบ kretprobe ด้วย ทำให้ event มีค่า return (`0` = LSM อนุญาต) — นี่คือที่มาของโปรแกรม `generic_retkprobe_*` ใน 4.4
- **`values` 2 ค่า**: ภายใน `matchArgs` ค่าหลายค่าเป็น OR

### 2.3 `03-tcp-connect.yaml` — ดูการเชื่อมต่อ TCP ขาออก

```yaml
  - call: "tcp_connect"
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DAddr"
        values: ["127.0.0.0/8"]
      - index: 0
        operator: "DPort"
        values: ["18026"]
  - call: "tcp_close"   # ... selector เดียวกัน
```
- **`tcp_connect(struct sock *sk)`**: ถูกเรียกตอนส่ง SYN ของ active open (หลัง `connect()` เลือก source port แล้ว) จึงเห็นทั้ง 4-tuple ต่างจาก `cgroup/connect4` ใน Week 14 ที่ทำงาน *ก่อน* เลือก source port และสามารถปฏิเสธได้
- **`DAddr` + `DPort` ใน selector เดียวกัน = AND**: เอาเฉพาะ `127.0.0.0/8:18026` (พอร์ตของแล็บ) ทำให้ event stream อ่านง่าย — curl ไปพอร์ต 18027 จะไม่มี event (ดู 4.3)
- **`tcp_close`**: คู่กับ connect ทำให้เห็นวงจรชีวิตของ connection (`🔌 connect` → `🧹 close`)

### 2.4 `04-enforce-secret-sigkill.yaml` — Sigkill

```yaml
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "week26-ecosystem-tetragon-cilium/lab-files/secret.txt"
      matchActions:
      - action: Sigkill
      - action: Post
```
- **`action: Sigkill`**: BPF program เรียก `bpf_send_signal(SIGKILL)` กับโปรเซสปัจจุบัน สัญญาณถูกส่งระหว่างที่ยังอยู่ใน `open()` โปรเซสจึงตายตอนกลับสู่ user space และ **ไม่ได้ `read()` ข้อมูลเลย** (ใน 4.5 `cat` ไม่พิมพ์อะไรออกมา exit 137 = 128 + 9)
- **`action: Post`**: ยังส่ง event เข้า audit trail ด้วย
- **`notes.txt` ไม่โดน**: เพราะ `Postfix` ตรงเฉพาะ `secret.txt`

### 2.5 `05-enforce-secret-override.yaml` — Override ผ่าน BPF LSM

```yaml
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs: [ Postfix ".../lab-files/secret.txt" ]
      matchActions:
      - action: Override
        argError: -1
      - action: Post
```
- นี่คือ Week 10 ทั้งบทในรูป YAML 15 บรรทัด: `SEC("lsm/file_open")` + คืนค่า `-EPERM`
- **`argError: -1`**: ค่าที่ LSM hook คืน (`-1` = `-EPERM`) → `open()` ล้มเหลวด้วย `Operation not permitted` แต่โปรเซส **ไม่ตาย** (exit 1 ตามปกติของ `cat`)

### 2.6 `06-enforce-secret-fmodret.yaml` — Override บน kprobe (`fmod_ret`)

เหมือน 2.5 แต่เขียนเป็น `kprobes: call: "security_file_open"` + `Override` เพื่อแสดงข้อจำกัดในหัวข้อ 1.4:
- Tetragon แปลง Override บนฟังก์ชัน `security_*` เป็นโปรแกรม **`fmod_ret`** (`BPF_MODIFY_RETURN` — BPF trampoline ชนิดเดียวกับ fentry/fexit ใน Week 22) ซึ่งใช้ร่วมกับ `kprobe_multi` link ไม่ได้
- ถ้า daemon รันด้วยค่าเริ่มต้นจะได้ error `can't override 'security_file_open' function with kprobe_multi, use --disable-kprobe-multi option` (4.7) จึงต้อง `make up-nomulti`

### 2.7 `run-tetragon.sh`

```bash
    $SUDO docker run --name "$NAME" -d \
        --pid=host --cgroupns=host --privileged \
        --hostname "$(hostname)" \
        -v /sys/kernel:/sys/kernel \
        -v "$POLICY_DIR":/w26/policies:ro \
        "$TETRAGON_IMAGE" ${TETRAGON_ARGS:+/usr/bin/tetragon $TETRAGON_ARGS} >/dev/null
```
- **`TETRAGON_IMAGE=quay.io/cilium/tetragon:v1.7.1`**: pin เวอร์ชันแน่นอน (release ล่าสุด ณ วันที่เขียน ออกเมื่อ 2026-08-25) ไม่ใช้ `:latest` เพื่อให้ผลลัพธ์ทำซ้ำได้ เปลี่ยนได้ด้วย env `TETRAGON_IMAGE`
- **`--pid=host --cgroupns=host`**: ให้ Tetragon เห็น PID/cgroup จริงของโฮสต์ (ไม่อย่างนั้นจะเห็นแค่โปรเซสในคอนเทนเนอร์)
- **`--privileged`**: ต้องใช้ CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN เพื่อโหลด BPF program และ mount bpffs
- **`-v /sys/kernel:/sys/kernel`**: ให้เห็น BTF (`/sys/kernel/btf/vmlinux`) สำหรับ CO-RE และ tracefs/debugfs (ตามคู่มือ "Deploy as a container" ของ Tetragon)
- **ไม่ mount `/sys/fs/bpf` ของโฮสต์ (ตั้งใจ)**: Tetragon จะ mount bpffs ของตัวเองในคอนเทนเนอร์ (`/sys/fs/bpf/tetragon`) pin ต่าง ๆ จึงหายไปพร้อมคอนเทนเนอร์ ไม่มีโอกาสค้างบนโฮสต์ (production มัก mount ของโฮสต์เพื่อให้ policy อยู่รอดตอน restart daemon — แลกกับความเสี่ยงที่ pin จะค้าง)
- **`--hostname`**: ไม่อย่างนั้นทุก event จะแสดงชื่อโหนดเป็น container ID (เช่น `04cc908bc793`) — เราเจอจริงตอนรันครั้งแรก
- **`-v policies:/w26/policies:ro`**: ให้ `tetra tracingpolicy add /w26/policies/<file>` อ่าน YAML ในคอนเทนเนอร์ได้ (read-only)

คำสั่งย่อยอื่น ๆ:
- **`capture <sec>`**: รัน `timeout` *ภายในคอนเทนเนอร์* เพราะถ้า kill `docker exec` จากฝั่งโฮสต์ ข้อความที่ค้างใน buffer ของ `tetra` จะหาย (เราลองแล้วได้ไฟล์ว่าง)
- **`progs`**: ใช้ `bpftool` *ในคอนเทนเนอร์* (build แบบมี skeleton → แสดง `pids tetragon(<pid>)`) เพราะ `bpftool v7.7.0` ของโฮสต์ build มาโดยไม่มีฟีเจอร์นี้ จึงต้องจับชื่อโปรแกรมแทน (`TETRAGON_PROG_RE`)
- **`down`**: `docker stop` + `docker rm` แล้ววนตรวจ 15 วินาทีว่าไม่มีโปรแกรมชื่อตรง `TETRAGON_PROG_RE` หรือคำว่า `tetragon` เหลือใน `bpftool prog show`

### 2.8 `validate-policies.py` และ `event-summary.jq`

- `validate-policies.py` (เรียกจาก `make all` และ `make test`, ไม่ต้องใช้ root/Docker): ตรวจว่าเป็น `TracingPolicy` ที่ parse ได้, ชื่อขึ้นต้นด้วย `w26-`, ทุก hook มี `matchArgs`, **ทุก path filter ต้องอยู่ใน `.../lab-files/`** และ **ทุก action แบบ `Sigkill`/`Override`/`Signal` ต้องอยู่ใน selector ที่ถูกจำกัดด้วย path ของแล็บ** (ใน `matchArgs` หรือ `matchBinaries` ที่ทุกค่าอยู่ใน `lab-files/`) — ถ้าแก้ policy 04 ให้ชี้ `/etc/shadow` สคริปต์จะ FAIL ทันที
- `event-summary.jq`: ย่อ JSON event ของ Tetragon (ยาวหลายร้อยบรรทัด) ให้เหลือ `type`, `policy`, `hook`, `binary`, `pid`, `args`, `return`, `exit_status`, `signal` (หมายเหตุ: JSON ของ Tetragon มาจาก protobuf จึงละฟิลด์ที่เป็นค่า 0 เช่น `status: 0`)

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจความพร้อมของเครื่อง
```bash
cd phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium
docker --version                         # ต้องมี Docker และอยู่ในกลุ่ม docker (หรือมี sudo)
ls /sys/kernel/btf/vmlinux               # ต้องมี BTF
cat /sys/kernel/security/lsm             # ต้องมี "bpf" สำหรับ policy 01 และ 05
grep -E 'CONFIG_BPF_LSM|CONFIG_BPF_KPROBE_OVERRIDE' /boot/config-$(uname -r)
make test                                # ตรวจ YAML + กฎความปลอดภัย (ไม่ต้อง root)
```

### ขั้นตอนที่ 2: เริ่ม Tetragon และโหลด policy แบบ observe
```bash
make up                                  # ครั้งแรกจะ pull image (~88 MB ดาวน์โหลด, 376 MB บนดิสก์)
make apply-exec apply-file apply-connect
make list
```

### ขั้นตอนที่ 3: ดู event (เปิด 2 terminal)
Terminal 1 (ค้างไว้ Ctrl+C เพื่อหยุด):
```bash
./run-tetragon.sh events --process 'w26-hello|cat|curl'           # exec/exit + connect
# หรือ
./run-tetragon.sh events --policy-names w26-process-exec-lsm,w26-file-monitor,w26-tcp-connect
```
Terminal 2:
```bash
python3 -m http.server 18026 --bind 127.0.0.1 --directory lab-files &   # เซิร์ฟเวอร์ของแล็บ
./lab-files/bin/w26-hello
cat lab-files/notes.txt
cat lab-files/secret.txt
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18026/notes.txt
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18027/   # ไม่ควรมี event (ผิดพอร์ต)
kill %1
```
ดูอาร์กิวเมนต์เต็ม (path ไฟล์ / 4-tuple) แบบ JSON:
```bash
./run-tetragon.sh capture-json 15 --policy-names w26-file-monitor,w26-tcp-connect | jq -c -f event-summary.jq
```

### ขั้นตอนที่ 4: ดู BPF program ที่ Tetragon โหลด
```bash
make progs
sudo bpftool prog show name event_execve       # เปรียบเทียบกับ Week 09
```

### ขั้นตอนที่ 5: Enforcement แบบ Sigkill (ซ้อมด้วย monitor ก่อน)
```bash
./run-tetragon.sh remove w26-process-exec-lsm
./run-tetragon.sh remove w26-file-monitor
./run-tetragon.sh remove w26-tcp-connect
make apply-sigkill-monitor
cat lab-files/secret.txt; echo "exit=$?"      # ยังอ่านได้ แต่ NMONITOR +1
./run-tetragon.sh list
./run-tetragon.sh mode w26-enforce-secret-sigkill enforce
cat lab-files/secret.txt; echo "exit=$?"      # Killed, exit=137
cat lab-files/notes.txt; echo "exit=$?"       # ไฟล์อื่นไม่โดน
```

### ขั้นตอนที่ 6: Enforcement แบบ Override (BPF LSM)
```bash
./run-tetragon.sh remove w26-enforce-secret-sigkill
make apply-override
cat lab-files/secret.txt; echo "exit=$?"      # Operation not permitted, exit=1
./run-tetragon.sh list                        # NENFORCE เพิ่มขึ้น
```

### ขั้นตอนที่ 7 (ทางเลือก): Override บน kprobe ด้วย fmod_ret
```bash
make down
make up-nomulti                               # = TETRAGON_ARGS="--disable-kprobe-multi"
make apply-fmodret
cat lab-files/secret.txt; echo "exit=$?"
docker exec w26-tetragon bpftool link show | grep -A3 modify_return
```

### ขั้นตอนที่ 8: เก็บกวาด (ห้ามข้าม)
```bash
make down                                     # ต้องเห็น "cleanup OK"
sudo bpftool prog show | grep -i tetragon     # ต้องว่าง
docker ps -a --filter name=w26-tetragon       # ต้องไม่มีคอนเทนเนอร์
make clean                                    # ลบ lab-files/ (ไม่แตะ Docker)
```

### ขั้นตอนที่ 9 (ทางเลือก): Cilium บน kind
ใช้เวลาประมาณ 5 นาทีบนเครื่องแล็บ (ส่วนใหญ่คือ pull image) และใช้พื้นที่ดิสก์ราว 1.3 GB สำหรับ `kindest/node` อย่างเดียว ไบนารีวางไว้ในไดเรกทอรีชั่วคราวได้ ไม่ต้องติดตั้งลงระบบ
```bash
# 1) เครื่องมือ (ตรวจ checksum ทุกครั้ง)
curl -fsSLo kind https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64
curl -fsSL https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64.sha256sum   # เทียบกับ sha256sum kind
curl -fsSLO https://github.com/cilium/cilium-cli/releases/download/v0.20.1/cilium-linux-amd64.tar.gz{,.sha256sum}
sha256sum -c cilium-linux-amd64.tar.gz.sha256sum && tar xzf cilium-linux-amd64.tar.gz && chmod +x kind

# 2) คลัสเตอร์ที่ไม่มี CNI และไม่มี kube-proxy แล้วติดตั้ง Cilium
export KUBECONFIG=$PWD/w26-kubeconfig
./kind create cluster --config cilium/kind-w26.yaml
./cilium install --version 1.20.4 --set kubeProxyReplacement=true --set hubble.relay.enabled=true
./cilium status --wait

# 3) แอปทดสอบ (ใช้ kubectl ที่อยู่ใน node container จึงไม่ต้องติดตั้ง kubectl)
K="docker exec -i w26-cilium-control-plane kubectl"
$K create namespace w26
$K -n w26 create deployment web --image=nginx:1.27-alpine --replicas=2
$K -n w26 expose deployment web --port=80
$K -n w26 run client --image=curlimages/curl:8.10.1 --restart=Never --command -- sleep 600
$K -n w26 wait --for=condition=Ready pod --all --timeout=180s
$K -n w26 exec client -- curl -s -o /dev/null -w "%{http_code} from %{remote_ip}\n" http://web.w26.svc.cluster.local/

# 4) ส่องของข้างใน (เลือก cilium pod บน worker)
CP=$($K -n kube-system get pod -l k8s-app=cilium --field-selector spec.nodeName=w26-cilium-worker -o name)
$K -n kube-system exec $CP -c cilium-agent -- cilium-dbg status | grep -E 'KubeProxyReplacement|Attach Mode|Routing'
$K -n kube-system exec $CP -c cilium-agent -- cilium-dbg service list
$K -n kube-system exec $CP -c cilium-agent -- bpftool cgroup tree /run/cilium/cgroupv2 | head -15
$K -n kube-system exec $CP -c cilium-agent -- bpftool net show
$K -n kube-system exec $CP -c cilium-agent -- hubble observe --namespace w26 --protocol tcp --last 8

# 5) Network policy ตาม identity
$K apply -f - < cilium/web-allow-only-frontend.yaml
$K -n w26 exec client -- curl -s -m 3 -o /dev/null -w "%{http_code}\n" http://web.w26.svc.cluster.local/   # timeout
$K -n kube-system exec $CP -c cilium-agent -- hubble observe --namespace w26 --verdict DROPPED --last 3
$K -n w26 label pod client role=frontend    # รอ ~5-10 วินาทีให้ identity ใหม่ถูกคำนวณ แล้ว curl ใหม่

# 6) เก็บกวาด
./kind delete cluster --name w26-cilium
docker network rm kind                       # kind ไม่ลบ network นี้ให้
sudo bpftool prog show | grep -c 'name cil_' # ต้องเป็น 0
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), Docker 29.1.3, **Tetragon v1.7.1** (`quay.io/cilium/tetragon:v1.7.1`, digest `sha256:afc9458b…4a02`), host bpftool v7.7.0, BPF LSM เปิดอยู่, `CONFIG_BPF_KPROBE_OVERRIDE=y`
>
> ส่วน Cilium: kind v0.33.0 (node image เริ่มต้น `kindest/node:v1.37.0`), cilium-cli v0.20.1, Cilium v1.20.4
>
> เครื่องแล็บมีงานอื่นรันพร้อมกัน event ที่ไม่เกี่ยวข้องจึงถูกกรองออกด้วย `--process` / `--policy-names` / `grep lab-files` ตามที่ระบุในแต่ละหัวข้อ

### 4.1 `make test` (ไม่ต้อง root, ไม่เริ่มคอนเทนเนอร์)
```text
===> Validating TracingPolicy YAML (policies/*.yaml)...
  ok    policies/01-process-exec-lsm.yaml
  ok    policies/02-file-monitor.yaml
  ok    policies/03-tcp-connect.yaml
  ok    policies/04-enforce-secret-sigkill.yaml
  ok    policies/05-enforce-secret-override.yaml
  ok    policies/06-enforce-secret-fmodret.yaml
  ok    cilium/kind-w26.yaml
  ok    cilium/web-allow-only-frontend.yaml
  ok    run-tetragon.sh (bash -n)
```
ทดสอบด้านลบ: สำเนาของ policy 04 ที่เปลี่ยน path เป็น `/etc/shadow`
```text
ERROR: 04-bad.yaml: kprobes/security_file_open selector 0: non-lab path(s) ['/etc/shadow']
ERROR: 04-bad.yaml: kprobes/security_file_open selector 0: ['Sigkill'] is not restricted to a lab-files/ path
  FAIL  policies/04-bad.yaml
neg exit=1
```

### 4.2 `make up` และโหลด policy 01–03
```text
$ make up
./run-tetragon.sh up
prepared /mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files (secret.txt, notes.txt, bin/w26-hello)
starting w26-tetragon from quay.io/cilium/tetragon:v1.7.1
container: w26-tetragon (quay.io/cilium/tetragon:v1.7.1)
daemon version: Server version: v1.7.1
ID   NAME   STATE   FILTERID   NAMESPACE   SENSORS   KERNELMEMORY   MODE   NPOST   NENFORCE   NMONITOR
$ make apply-exec apply-file apply-connect
tracing policy "/w26/policies/01-process-exec-lsm.yaml" added
ID   NAME                   STATE     FILTERID   NAMESPACE   SENSORS       KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
2    w26-process-exec-lsm   enabled   0          (global)    generic_lsm   1.16 MB        monitor_only   0       0          0
tracing policy "/w26/policies/02-file-monitor.yaml" added
ID   NAME                   STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
2    w26-process-exec-lsm   enabled   0          (global)    generic_lsm      1.16 MB        monitor_only   0       0          0
3    w26-file-monitor       enabled   0          (global)    generic_kprobe   1.13 MB        monitor_only   0       0          0
tracing policy "/w26/policies/03-tcp-connect.yaml" added
ID   NAME                   STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
2    w26-process-exec-lsm   enabled   0          (global)    generic_lsm      1.16 MB        monitor_only   0       0          0
3    w26-file-monitor       enabled   0          (global)    generic_kprobe   1.13 MB        monitor_only   0       0          0
4    w26-tcp-connect        enabled   0          (global)    generic_kprobe   865.74 kB      monitor_only   0       0          0
```
`MODE monitor_only` = policy ที่ไม่มี enforcement action เลย ส่วน `KERNELMEMORY` คือหน่วยความจำของ map ที่ policy นั้นใช้ — policy LSM ตัวเดียวใช้ ~1.16 MB

Log ตอนเริ่มของ daemon (`docker logs w26-tetragon`) แสดงความสามารถของ kernel ที่ Tetragon ตรวจพบ (ตัดมาบางบรรทัด):
```text
level=info msg="Starting tetragon" version=v1.7.1
level=info msg="BTF discovery: default kernel btf file found" btf-file=/sys/kernel/btf/vmlinux
level=info msg="BPF detected features: override_return: true, buildid: true, kprobe_multi: true, uprobe_multi: true, fmodret: true, fmodret_syscall: true, signal: true, large: true, link_pin: true, lsm: true, missed_stats_kprobe_multi: true, missed_stats_kprobe: true, batch_update: true, uprobe_refctroff: true, audit_loginuid: true, probe_write_user: false, uprobe_regs_change: true, mix_bpf_and_tail_calls: true, fentry: true, get_func_ret: true"
level=info msg="Deployment mode detection succeeded" cgroup.fs=/sys/fs/cgroup deployment.mode=Container
level=info msg="Loading sensor" name=__base__
level=info msg="Loading kernel version 7.0.14"
level=info msg="Loaded sensor successfully" sensor=__base__
level=info msg="Registered probe types" types="generic_uprobe, loader, execve, enforcer, generic_fentry, generic_tracepoint, generic_usdt, generic_kprobe, generic_lsm"
```
(`Loading kernel version 7.0.14` คือเลข `LINUX_VERSION_CODE` ที่ Tetragon อ่านได้ ซึ่งต่างจากสตริง `uname -r` ของ Ubuntu `7.0.0-38-generic`)

### 4.3 Event จริงของ policy 01–03

คำสั่งที่รันใน terminal 2:
```text
$ ./lab-files/bin/w26-hello
hello from w26-hello (pid 80131)
$ cat lab-files/notes.txt
w26 lab notes: reading this is only logged
$ cat lab-files/secret.txt
w26 lab secret: tetragon-should-block-this
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18026/notes.txt
200
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18027/   # ไม่มีใครฟังพอร์ตนี้
000
exit=7
```

**(ก) `./run-tetragon.sh capture 12 --process 'w26-hello|cat|curl'`** (แสดงเฉพาะบรรทัดที่มี `lab-files|18026|18027`):
```text
🚀 process ce-desk /mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/bin/w26-hello ./lab-files/bin/w26-hello
💥 exit    ce-desk /mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/bin/w26-hello ./lab-files/bin/w26-hello 0
🚀 process ce-desk /usr/bin/cat lab-files/notes.txt
💥 exit    ce-desk /usr/bin/cat lab-files/notes.txt 0
🚀 process ce-desk /usr/bin/cat lab-files/secret.txt
💥 exit    ce-desk /usr/bin/cat lab-files/secret.txt 0
🚀 process ce-desk /usr/bin/curl "-s -o /dev/null -w %{http_code}\\n http://127.0.0.1:18026/notes.txt"
🔌 connect ce-desk /usr/bin/curl tcp 127.0.0.1:55338 -> 127.0.0.1:18026
🧹 close   ce-desk /usr/bin/curl tcp 127.0.0.1:55338 -> 127.0.0.1:18026
💥 exit    ce-desk /usr/bin/curl "-s -o /dev/null -w %{http_code}\\n http://127.0.0.1:18026/notes.txt" 0
🚀 process ce-desk /usr/bin/curl "-s -o /dev/null -w %{http_code}\\n http://127.0.0.1:18027/"
💥 exit    ce-desk /usr/bin/curl "-s -o /dev/null -w %{http_code}\\n http://127.0.0.1:18027/" 7
```
- `🚀 process` / `💥 exit` มาจาก base sensor โดยไม่ต้องมี policy (Week 09) — `exit ... 7` คือ exit code ของ curl (connection refused)
- curl ไปพอร์ต 18027 **ไม่มี** `🔌 connect` เพราะ selector `DPort 18026` กรองทิ้งใน kernel

**(ข) `./run-tetragon.sh capture 12 --policy-names w26-process-exec-lsm,w26-file-monitor,w26-tcp-connect`** (ไม่ได้ตัดบรรทัดใด):
```text
🔒 LSM     ce-desk /usr/bin/bash bprm_check_security
❓ syscall ce-desk /usr/bin/cat security_file_open
❓ syscall ce-desk /usr/bin/cat security_file_open
🔌 connect ce-desk /usr/bin/curl tcp 127.0.0.1:55338 -> 127.0.0.1:18026
❓ syscall ce-desk /usr/bin/python3 security_file_open
🧹 close   ce-desk /usr/bin/curl tcp 127.0.0.1:55338 -> 127.0.0.1:18026
```
รูปแบบ compact ไม่แสดง path ของ `security_file_open` (Tetragon รู้จักเฉพาะฟังก์ชันยอดนิยม เช่น `tcp_connect` จึงใส่ไอคอน `❓ syscall`) และ `python3` ที่เห็นคือ `http.server` ที่เปิด `notes.txt` เพื่อตอบ curl

**(ค) JSON เดียวกัน: `capture-json 12 --policy-names ... | jq -c -f event-summary.jq | jq -c 'del(.argv)'`** (`del(.argv)` ใช้ลบ command line ยาวของ bash ที่ใช้รันสคริปต์ทดลอง):
```text
{"type":"process_lsm","policy":"w26-process-exec-lsm","hook":"bprm_check_security","binary":"/usr/bin/bash","pid":80131,"args":["/mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/bin/w26-hello"],"action":"KPROBE_ACTION_POST"}
{"type":"process_kprobe","policy":"w26-file-monitor","hook":"security_file_open","binary":"/usr/bin/cat","pid":80132,"args":["/mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/notes.txt"],"return":0,"action":"KPROBE_ACTION_POST"}
{"type":"process_kprobe","policy":"w26-file-monitor","hook":"security_file_open","binary":"/usr/bin/cat","pid":80133,"args":["/mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/secret.txt"],"return":0,"action":"KPROBE_ACTION_POST"}
{"type":"process_kprobe","policy":"w26-tcp-connect","hook":"tcp_connect","binary":"/usr/bin/curl","pid":80134,"args":["127.0.0.1:55338 -> 127.0.0.1:18026"],"action":"KPROBE_ACTION_POST"}
{"type":"process_kprobe","policy":"w26-file-monitor","hook":"security_file_open","binary":"/usr/bin/python3","pid":79852,"args":["/mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/notes.txt"],"return":0,"action":"KPROBE_ACTION_POST"}
{"type":"process_kprobe","policy":"w26-tcp-connect","hook":"tcp_close","binary":"/usr/bin/curl","pid":80134,"args":["127.0.0.1:55338 -> 127.0.0.1:18026"],"action":"KPROBE_ACTION_POST"}
```
- event LSM มี `pid 80131` เท่ากับ PID ที่ `w26-hello` พิมพ์ออกมา แต่ `binary` ยังเป็น `/usr/bin/bash` เพราะ `bprm_check_security` เกิดก่อน exec จะเปลี่ยน image (ข้อ 2.1)
- `"return":0` มาจาก `return: true` ใน policy 02 (LSM อนุญาต)

### 4.4 `make progs` — BPF program ที่ Tetragon โหลด (policy 01–03 ทำงานอยู่)
```text
$ make progs
./run-tetragon.sh progs
== programs held directly by the tetragon process (bpftool inside the container)
3427: kprobe  name event_exit_acct_process  tag 4dfbb31db5fbfce9  gpl
3429: kprobe  name event_wake_up_new_task  tag 76339515e02ae53c  gpl
3431: tracepoint  name event_execve  tag cd7b659f13f2958e  gpl
3433: kprobe  name tg_kp_bprm_committing_creds  tag baccda55c3fe363a  gpl
3434: socket_filter  name execve_map_update  tag 4c99e2a331f84f3f  gpl
3437: lsm  name generic_lsm_output  tag 3b150978387431f5  gpl
3442: lsm  name generic_lsm_event  tag 4e8d0279dd900ba1  gpl
3450: kprobe  name generic_kprobe_event  tag 933294ece4aef2b4  gpl
3452: kprobe  name generic_retkprobe_event  tag 2147666b19be2e50  gpl
3460: kprobe  name generic_kprobe_event  tag 933294ece4aef2b4  gpl
== all Tetragon programs (id type name), matched by name on the host
3427: kprobe event_exit_acct_process
3429: kprobe event_wake_up_new_task
3430: tracepoint execve_rate
3431: tracepoint event_execve
3432: tracepoint execve_send
3433: kprobe tg_kp_bprm_committing_creds
3434: socket_filter execve_map_update
3437: lsm generic_lsm_output
3438: lsm generic_lsm_process_event
3439: lsm generic_lsm_setup_event
3440: lsm generic_lsm_process_filter
3441: lsm generic_lsm_filter_arg
3442: lsm generic_lsm_event
3443: lsm generic_lsm_actions
3444: kprobe generic_kprobe_output
3445: kprobe generic_kprobe_process_event
3446: kprobe generic_kprobe_setup_event
3447: kprobe generic_kprobe_process_filter
3448: kprobe generic_kprobe_actions
3449: kprobe generic_kprobe_filter_arg
3450: kprobe generic_kprobe_event
3451: kprobe generic_retkprobe_filter_arg
3452: kprobe generic_retkprobe_event
3453: kprobe generic_retkprobe_actions
3454: kprobe generic_retkprobe_output
3455: kprobe generic_kprobe_filter_arg
3456: kprobe generic_kprobe_output
3457: kprobe generic_kprobe_process_event
3458: kprobe generic_kprobe_process_filter
3459: kprobe generic_kprobe_actions
3460: kprobe generic_kprobe_event
3461: kprobe generic_kprobe_setup_event
$ make list
./run-tetragon.sh list
ID   NAME                   STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
2    w26-process-exec-lsm   enabled   0          (global)    generic_lsm      1.16 MB        monitor_only   0       0          0
3    w26-file-monitor       enabled   0          (global)    generic_kprobe   1.13 MB        monitor_only   3       0          0
4    w26-tcp-connect        enabled   0          (global)    generic_kprobe   865.74 kB      monitor_only   2       0          0
```
(บรรทัดสรุปท้ายของ `progs` คือ `== total: 32 programs`)

อ่านผล:
- **base sensor 7 โปรแกรม** (3427–3434): `event_execve` คือ tracepoint `sched_process_exec` แบบเดียวกับ Week 09; `execve_map_update` เป็นชนิด `socket_filter` แต่ไม่มี link ใน `bpftool link show` จึงไม่ได้แนบกับ hook ใด เป็นโปรแกรมใช้ภายในของ Tetragon (อ่านซอร์สของ Tetragon หากต้องการรายละเอียด)
- **มีแค่ 10 โปรแกรมที่มี `pids tetragon`** ส่วนที่เหลือคือปลายทางของ tail call (อยู่ใน prog-array map ไม่ได้ถือ fd โดยตรง)
- Policy 02 มี kretprobe จึงมีชุด `generic_retkprobe_*` เพิ่ม; policy 03 (2 ฟังก์ชัน) ใช้ **kprobe_multi link เดียว**

ส่วนของ `docker exec w26-tetragon bpftool link show` (ตัดมาเฉพาะ link ของ Tetragon):
```text
132: perf_event  prog 3427
	kprobe ffffffff9ada52b0 acct_process
133: perf_event  prog 3429
	kprobe ffffffff9aca96f0 wake_up_new_task
134: perf_event  prog 3431
	tracepoint sched_process_exec
135: perf_event  prog 3433
	kprobe ffffffff9b323cb0 security_bprm_committing_creds
136: tracing  prog 3437
	prog_type lsm  attach_type lsm_mac
137: tracing  prog 3442
	prog_type lsm  attach_type lsm_mac
138: kprobe_multi  prog 3450
	kprobe.multi  func_cnt 1
139: kprobe_multi  prog 3452
	kretprobe.multi  func_cnt 1
140: kprobe_multi  prog 3460
	kprobe.multi  func_cnt 2
```

### 4.5 Policy 04: Sigkill — monitor ก่อน แล้วค่อย enforce
```text
$ make apply-sigkill-monitor
tracing policy "/w26/policies/04-enforce-secret-sigkill.yaml" added
ID   NAME                         STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
5    w26-enforce-secret-sigkill   enabled   0          (global)    generic_kprobe   860.91 kB      monitor   0       0          0
$ cat lab-files/secret.txt
w26 lab secret: tetragon-should-block-this
exit=0
$ ./run-tetragon.sh list
ID   NAME                         STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
5    w26-enforce-secret-sigkill   enabled   0          (global)    generic_kprobe   860.91 kB      monitor   1       0          1
$ ./run-tetragon.sh mode w26-enforce-secret-sigkill enforce
tracing policy "w26-enforce-secret-sigkill" set to mode "enforce"
$ cat lab-files/secret.txt
/bin/bash: line 11: 81953 Killed                     cat lab-files/secret.txt
exit=137
$ cat lab-files/notes.txt
w26 lab notes: reading this is only logged
exit=0
$ ./run-tetragon.sh list
ID   NAME                         STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
5    w26-enforce-secret-sigkill   enabled   0          (global)    generic_kprobe   860.91 kB      enforce   2       1          1
```
Event ระหว่าง enforce (บรรทัด `🚀`/`💥` จาก `capture 7 --process cat | grep lab-files` และบรรทัด `❓` จาก `capture 7 --policy-names w26-enforce-secret-sigkill` ที่รันพร้อมกัน):
```text
🚀 process ce-desk /usr/bin/cat lab-files/secret.txt
💥 exit    ce-desk /usr/bin/cat lab-files/secret.txt SIGKILL
🚀 process ce-desk /usr/bin/cat lab-files/notes.txt
💥 exit    ce-desk /usr/bin/cat lab-files/notes.txt 0
❓ syscall ce-desk /usr/bin/cat security_file_open
```
JSON (`capture-json 7 --process cat | jq -c -f event-summary.jq | grep lab-files`):
```text
{"type":"process_exec","binary":"/usr/bin/cat","pid":81953,"argv":"lab-files/secret.txt"}
{"type":"process_kprobe","policy":"w26-enforce-secret-sigkill","hook":"security_file_open","binary":"/usr/bin/cat","pid":81953,"argv":"lab-files/secret.txt","args":["/mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/secret.txt"],"action":"KPROBE_ACTION_POST"}
{"type":"process_exit","binary":"/usr/bin/cat","pid":81953,"argv":"lab-files/secret.txt","exit_status":0,"signal":"SIGKILL"}
{"type":"process_exec","binary":"/usr/bin/cat","pid":81954,"argv":"lab-files/notes.txt"}
{"type":"process_exit","binary":"/usr/bin/cat","pid":81954,"argv":"lab-files/notes.txt","exit_status":0}
```
- โหมด monitor: `cat` อ่านได้ปกติ แต่ `NMONITOR` = 1 (บอกว่า "ถ้า enforce จะ kill แล้ว")
- โหมด enforce: `cat` ไม่ได้พิมพ์เนื้อหาเลยและตายด้วย SIGKILL (`NENFORCE` = 1) ส่วน `notes.txt` อ่านได้ปกติ
- ฟิลด์ `action` ของ event เป็น `KPROBE_ACTION_POST` เพราะ event ถูกส่งโดย action `Post` หลักฐานของการบังคับคือ `signal: SIGKILL` ใน `process_exit` และตัวนับ `NENFORCE`

### 4.6 Policy 05: Override ผ่าน BPF LSM
```text
$ ./run-tetragon.sh remove w26-enforce-secret-sigkill
tracing policy "w26-enforce-secret-sigkill" deleted
$ make apply-override
tracing policy "/w26/policies/05-enforce-secret-override.yaml" added
ID   NAME                          STATE     FILTERID   NAMESPACE   SENSORS       KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
6    w26-enforce-secret-override   enabled   0          (global)    generic_lsm   1.16 MB        enforce   0       0          0
$ cat lab-files/secret.txt
cat: lab-files/secret.txt: Operation not permitted
exit=1
$ head -c 14 lab-files/notes.txt; echo
w26 lab notes:
exit=0
$ ./run-tetragon.sh list
ID   NAME                          STATE     FILTERID   NAMESPACE   SENSORS       KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
6    w26-enforce-secret-override   enabled   0          (global)    generic_lsm   1.16 MB        enforce   0       1          0
```
Event (บรรทัด `🚀`/`💥` จาก `capture 7 --process 'cat|head' | grep lab-files`, บรรทัด `🔒` จาก `capture 7 --policy-names w26-enforce-secret-override` และ JSON จาก `capture-json 7 --process 'cat|head' | jq -c -f event-summary.jq | grep lab-files`):
```text
🚀 process ce-desk /usr/bin/cat lab-files/secret.txt
💥 exit    ce-desk /usr/bin/cat lab-files/secret.txt 1
🚀 process ce-desk /usr/bin/head "-c 14 lab-files/notes.txt"
💥 exit    ce-desk /usr/bin/head "-c 14 lab-files/notes.txt" 0
🔒 LSM     ce-desk /usr/bin/cat file_open
```
```text
{"type":"process_exec","binary":"/usr/bin/cat","pid":82606,"argv":"lab-files/secret.txt"}
{"type":"process_lsm","policy":"w26-enforce-secret-override","hook":"file_open","binary":"/usr/bin/cat","pid":82606,"argv":"lab-files/secret.txt","args":["/mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files/secret.txt"],"action":"KPROBE_ACTION_POST"}
{"type":"process_exit","binary":"/usr/bin/cat","pid":82606,"argv":"lab-files/secret.txt","exit_status":1}
{"type":"process_exec","binary":"/usr/bin/head","pid":82607,"argv":"-c 14 lab-files/notes.txt"}
{"type":"process_exit","binary":"/usr/bin/head","pid":82607,"argv":"-c 14 lab-files/notes.txt","exit_status":0}
```
เปรียบเทียบกับ 4.5: คราวนี้ `cat` **ไม่ตาย** แต่ได้ `EPERM` แล้วจบด้วย exit 1 ตามปกติ — ผลลัพธ์เดียวกับ enforce mode ของ Week 10

### 4.7 Override บน kprobe: ทำไมต้อง `--disable-kprobe-multi`

ลองโหลด policy ที่เหมือน 06 ขณะที่ daemon รันด้วยค่าเริ่มต้น:
```text
Error: failed to add tracing policy: rpc error: code = Unknown desc = policy handler 'tracing' failed loading policy 'w26-kprobe-override-test': override validation failed: can't override 'security_file_open' function with kprobe_multi, use --disable-kprobe-multi option
```
และ error-injection list ของ kernel นี้:
```text
$ sudo grep -c "" /sys/kernel/debug/error_injection/list
1066
$ sudo grep -E "^security_" /sys/kernel/debug/error_injection/list | wc -l
0
$ sudo grep -E '^__x64_sys_openat\b' /sys/kernel/debug/error_injection/list
__x64_sys_openat	ERRNO
```
เริ่มใหม่ด้วย `make up-nomulti` แล้วโหลด policy 06:
```text
$ TETRAGON_ARGS="--disable-kprobe-multi" ./run-tetragon.sh up
prepared /mnt/sda/ebpf/phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium/lab-files (secret.txt, notes.txt, bin/w26-hello)
starting w26-tetragon from quay.io/cilium/tetragon:v1.7.1 (args: --disable-kprobe-multi)
container: w26-tetragon (quay.io/cilium/tetragon:v1.7.1)
daemon version: Server version: v1.7.1
ID   NAME   STATE   FILTERID   NAMESPACE   SENSORS   KERNELMEMORY   MODE   NPOST   NENFORCE   NMONITOR
$ ./run-tetragon.sh apply 06-enforce-secret-fmodret.yaml
tracing policy "/w26/policies/06-enforce-secret-fmodret.yaml" added
ID   NAME                         STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
2    w26-enforce-secret-fmodret   enabled   0          (global)    generic_kprobe   3.48 MB        enforce   0       0          0
$ cat lab-files/secret.txt
cat: lab-files/secret.txt: Operation not permitted
exit=1
$ cat lab-files/notes.txt
w26 lab notes: reading this is only logged
exit=0
$ ./run-tetragon.sh list
ID   NAME                         STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
2    w26-enforce-secret-fmodret   enabled   0          (global)    generic_kprobe   3.48 MB        enforce   1       1          0
$ docker exec w26-tetragon bpftool link show | grep -B2 -A2 security_file_open
	pids tetragon(83184)
157: perf_event  prog 3548
	kprobe ffffffff9b32b410 security_file_open
	bpf_cookie 0
	pids tetragon(83184)
```
และ link ของโปรแกรม override (`bpftool prog show` ในคอนเทนเนอร์พบ `3549: tracing  name generic_fmodret_override`):
```text
156: tracing  prog 3549
	prog_type tracing  attach_type modify_return
	target_obj_id 1  target_btf_id 149750
	pids tetragon(83184)
```
- ไม่มี kprobe_multi: kprobe ถูกแนบเป็น `perf_event` link ทีละฟังก์ชัน
- Override จริงทำโดยโปรแกรม `tracing` / `attach_type modify_return` (BPF trampoline — Week 22) ไม่ใช่ `bpf_override_return()` ซึ่งเป็นเหตุผลที่ `security_file_open` ไม่ต้องอยู่ใน error-injection list
- policy นี้ใช้ map ถึง 3.48 MB (เทียบกับ 0.86 MB ของ policy 04)

### 4.8 `make down` และตรวจว่าไม่มีอะไรค้าง
```text
$ make down
./run-tetragon.sh down
stopping w26-tetragon
cleanup OK: no Tetragon BPF program is loaded
$ sudo bpftool prog show | grep -i tetragon ; echo "matches=$?"
matches=1
$ docker ps -a --filter name=w26-tetragon --format "{{.Names}}" | wc -l
0
```
(`grep` คืนค่า 1 = ไม่พบบรรทัดใดเลย) หลังรอบ `up-nomulti` ก็ได้ `cleanup OK: no Tetragon BPF program is loaded` เช่นกัน

### 4.9 Cilium บน kind (รันจริงบนเครื่องแล็บ)

`kind create cluster` ใช้เวลา 60 วินาที (23:09:35 → 23:10:35) และ `cilium install` + `cilium status --wait` อีกราว 2 นาที (23:10:45 → 23:12:45)

```text
$ ./cilium install --version 1.20.4 --set kubeProxyReplacement=true --set hubble.relay.enabled=true
🔮 Auto-detected Kubernetes kind: kind
ℹ️  Using Cilium version 1.20.4
🔮 Auto-detected cluster name: kind-w26-cilium
ℹ️  Detecting real Kubernetes API server addr and port on Kind
🔮 Auto-detected kube-proxy has not been installed
ℹ️  Cilium will fully replace all functionalities of kube-proxy
```
`cilium status --wait` (ลบรหัสสี ANSI และโลโก้ออก):
```text
    Cilium:             OK
    Operator:           OK
    Envoy DaemonSet:    OK
    Hubble Relay:       OK
    ClusterMesh:        disabled

DaemonSet              cilium                   Desired: 2, Ready: 2/2, Available: 2/2
DaemonSet              cilium-envoy             Desired: 2, Ready: 2/2, Available: 2/2
Deployment             cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
Deployment             hubble-relay             Desired: 1, Ready: 1/1, Available: 1/1
Containers:            cilium                   Running: 2
                       cilium-envoy             Running: 2
                       cilium-operator          Running: 1
                       clustermesh-apiserver
                       hubble-relay             Running: 1
Cluster Pods:          4/4 managed by Cilium
Helm chart version:    1.20.4
```
แอปทดสอบ:
```text
NAME                      READY   STATUS    RESTARTS   AGE   IP             NODE                NOMINATED NODE   READINESS GATES
pod/client                1/1     Running   0          14s   10.244.1.209   w26-cilium-worker   <none>           <none>
pod/web-7c6cdd646-2gwgs   1/1     Running   0          14s   10.244.1.109   w26-cilium-worker   <none>           <none>
pod/web-7c6cdd646-hr4f8   1/1     Running   0          14s   10.244.1.214   w26-cilium-worker   <none>           <none>

NAME          TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE   SELECTOR
service/web   ClusterIP   10.96.212.94   <none>        80/TCP    14s   app=web
```
**Kube-proxy replacement + socket LB:**
```text
curl http://web.w26 -> 200 from 10.96.212.94
curl http://web.w26 -> 200 from 10.96.212.94
curl http://web.w26 -> 200 from 10.96.212.94
curl http://web.w26 -> 200 from 10.96.212.94
== kube-proxy pods:
No resources found in kube-system namespace.
== iptables KUBE-SVC rules on worker:
0
KubeProxyReplacement:    True   [eth0    172.20.0.2 fc00:f853:ccd:e793::2 fe80::8449:f3ff:feaa:1cd6 (Direct Routing)]
Cilium:                  Ok   1.20.4 (v1.20.4-beb276d2)
Routing:                 Network: Tunnel [vxlan]   Host: Legacy
Attach Mode:             TCX
Device Mode:             veth
Masquerading:            IPTables [IPv4: Enabled, IPv6: Disabled]
Hubble:                  Ok              Current/Max Flows: 321/4095 (7.84%), Flows/s: 5.22   Metrics: Disabled
== service list
7    10.96.212.94:80/TCP    ClusterIP      1 => 10.244.1.109:80/TCP (active)
                                           2 => 10.244.1.214:80/TCP (active)
```
`bpftool cgroup tree /run/cilium/cgroupv2` ใน cilium-agent (15 บรรทัดแรก):
```text
CgroupPath
ID       AttachType      AttachFlags       Name
/run/cilium/cgroupv2
2945     cgroup_inet_sock_release multi             cil_sock_release
2938     cgroup_inet4_post_bind multi             cil_sock4_post_bind
2943     cgroup_inet6_post_bind multi             cil_sock6_post_bind
2939     cgroup_inet4_connect multi             cil_sock4_connect
2946     cgroup_inet6_connect multi             cil_sock6_connect
2940     cgroup_inet4_getpeername multi             cil_sock4_getpeername
2942     cgroup_inet6_getpeername multi             cil_sock6_getpeername
2944     cgroup_udp4_sendmsg multi             cil_sock4_sendmsg
2941     cgroup_udp6_sendmsg multi             cil_sock6_sendmsg
2947     cgroup_udp4_recvmsg multi             cil_sock4_recvmsg
2948     cgroup_udp6_recvmsg multi             cil_sock6_recvmsg
2211     cgroup_device   multi
```
`bpftool net show` ใน cilium-agent (worker):
```text
xdp:

tc:
eth0(2) tcx/ingress cil_from_netdev prog_id 3035 link_id 94
eth0(2) tcx/egress cil_to_netdev prog_id 3033 link_id 95
cilium_net(3) tcx/ingress cil_to_host prog_id 3028 link_id 91
cilium_host(4) tcx/ingress cil_to_host prog_id 3012 link_id 89
cilium_host(4) tcx/egress cil_from_host prog_id 3015 link_id 90
cilium_vxlan(5) tcx/ingress cil_from_overlay prog_id 2993 link_id 86
cilium_vxlan(5) tcx/egress cil_to_overlay prog_id 2997 link_id 87
lxc_health(7) tcx/ingress cil_from_container prog_id 3090 link_id 100
lxcb5e734adf683(9) tcx/ingress cil_from_container prog_id 3078 link_id 99
lxc57de6430fa66(11) tcx/ingress cil_from_container prog_id 3185 link_id 115
lxca815b05ff489(13) tcx/ingress cil_from_container prog_id 3194 link_id 116
lxc8e33ed387c09(15) tcx/ingress cil_from_container prog_id 3217 link_id 117

flow_dissector:

netfilter:
```
`hubble observe --namespace w26 --protocol tcp --last 8`:
```text
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) -> w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: SYN)
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) <- w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: SYN, ACK)
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) -> w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK)
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) -> w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK, PSH)
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) <- w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK, PSH)
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) -> w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK, FIN)
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) <- w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK, FIN)
Oct 28 16:13:30.853: w26/client:55772 (ID:14409) -> w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK)
```
**CiliumNetworkPolicy ตาม identity:**
```text
ciliumnetworkpolicy.cilium.io/web-allow-only-frontend created
client (no role label) -> 000
command terminated with exit code 28
curl exit=28
client (role=frontend) -> 000
command terminated with exit code 28
Oct 28 16:13:50.812: w26/client:41030 (ID:14409) <> w26/web-7c6cdd646-2gwgs:80 (ID:8106) policy-verdict:none INGRESS DENIED (TCP Flags: SYN)
Oct 28 16:13:50.812: w26/client:41030 (ID:14409) <> w26/web-7c6cdd646-2gwgs:80 (ID:8106) Policy denied DROPPED (TCP Flags: SYN)
Oct 28 16:13:51.836: w26/client:41030 (ID:14409) <> w26/web-7c6cdd646-2gwgs:80 (ID:8106) policy-verdict:none INGRESS DENIED (TCP Flags: SYN)
```
บรรทัด `client (role=frontend) -> 000` คือ curl หลัง `kubectl label pod client role=frontend` เพียง 3 วินาที (identity ยังเป็น 14409 ดังที่ Hubble แสดง) เมื่อรออีก ~5 วินาทีแล้วลองใหม่:
```text
NAME     READY   STATUS    RESTARTS   AGE   LABELS
client   1/1     Running   0          68s   role=frontend,run=client
client (role=frontend) -> 200
Oct 28 16:14:02.650: w26/client:42814 (ID:34803) <- w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK, PSH)
Oct 28 16:14:02.650: w26/client:42814 (ID:34803) -> w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK, FIN)
Oct 28 16:14:02.650: w26/client:42814 (ID:34803) <- w26/web-7c6cdd646-hr4f8:80 (ID:8106) to-endpoint FORWARDED (TCP Flags: ACK, FIN)
```
เก็บกวาด:
```text
cil_ progs before delete: 69
Deleting cluster "w26-cilium" ...
Deleted nodes: ["w26-cilium-control-plane" "w26-cilium-worker"]
cil_ progs after delete: 0
```
แล้วลบ docker network `kind` ที่ถูกสร้างตอน 23:10:14 (ไม่มีคอนเทนเนอร์ใช้อยู่)

อ่านผล:
1. **ไม่มี kube-proxy และไม่มีกฎ `KUBE-SVC` ใน iptables** แต่ ClusterIP ใช้ได้ — Cilium ทำ service LB ด้วย eBPF
2. **Hubble เห็น client คุยกับ pod `web-...:80` โดยตรง ไม่ใช่ `10.96.212.94`** แปลว่า dst ถูกแปลตั้งแต่ `connect()` (`cil_sock4_connect` = `cgroup_inet4_connect` แบบเดียวกับ Week 14) ส่วน curl ยังรายงาน `remote_ip` เป็น ClusterIP เพราะ `cil_sock4_getpeername` แปลกลับให้แอปเห็นที่อยู่เดิม
3. **`Attach Mode: TCX`** และทุก interface มี `tcx/ingress`/`tcx/egress` (Week 08) ส่วน `xdp:` ว่าง เพราะ veth ใน kind ไม่ได้เปิด XDP acceleration
4. **Identity**: เปลี่ยน label แล้ว identity เปลี่ยนจาก 14409 เป็น 34803 policy map ใน datapath จึงเริ่มอนุญาต — มีช่วงหน่วงสั้น ๆ ระหว่างที่ agent คำนวณ identity ใหม่
5. **โปรแกรมของ Cilium อยู่ใน kernel เดียวกับโฮสต์** (kind node เป็นแค่ container) จึงนับ `name cil_` จาก `bpftool` ของโฮสต์ได้ 69 โปรแกรม และกลับเป็น 0 หลังลบคลัสเตอร์

---

## 5. ข้อจำกัด (Limitations)

- **Policy แบบ kprobe ขึ้นกับ symbol ของ kernel:** `security_file_open`, `tcp_connect`, `tcp_close` ไม่ใช่ ABI ที่เสถียร อาจถูก inline/เปลี่ยนชื่อ/เปลี่ยน signature ในเวอร์ชันอื่น เมื่อหาไม่เจอ policy จะขึ้น `load_error` (ตรวจได้ด้วย `grep -w security_file_open /proc/kallsyms`) — LSM hook (`lsmhooks:`) และ tracepoint เสถียรกว่า
- **Override มีเงื่อนไข:** `bpf_override_return()` ต้องการ `CONFIG_BPF_KPROBE_OVERRIDE=y` (เครื่องนี้ `=y`) และฟังก์ชันใน `/sys/kernel/debug/error_injection/list` (ไม่มี `security_*` เลยบน 7.0.0-38); Override บน `security_*` ผ่าน kprobe ต้องใช้ `fmod_ret` + `--disable-kprobe-multi`; Override ผ่าน `lsmhooks:` ต้องมี `bpf` ใน `lsm=`
- **`Sigkill` เป็นการตอบโต้ที่รุนแรง:** โปรเซสตายโดยไม่มีโอกาส cleanup (ไฟล์ temp, lock, transaction) ใน production ควรซ้อมด้วย `monitor` ก่อนและจำกัดด้วย `matchBinaries`/namespace
- **Path matching มีช่องโหว่แบบเดียวกับ Week 10:** `Postfix` ดูที่ path ตอนเปิด hard link หรือ bind mount ไปยัง inode เดียวกันจะมี path อื่น (ดูแบบฝึกหัดข้อ 5) และ policy ไม่ได้ป้องกันการอ่านผ่าน fd ที่เปิดไว้ก่อน policy จะถูกโหลด
- **Privileged container = เชื่อใจเต็มที่:** Tetragon มีสิทธิ์ root บนโฮสต์ทั้งหมด ต้อง pin image ด้วย tag (หรือ digest) จากแหล่งที่เชื่อถือได้ ใครที่คุย gRPC (`localhost:54321` ในคอนเทนเนอร์) ได้ก็โหลด policy ที่ kill โปรเซสใดก็ได้
- **Event อาจหายเมื่อโหลดสูง:** ring/perf buffer มีขนาดจำกัด (log: `BPF ring buffer size (bytes) total=512K`) ถ้า user space อ่านไม่ทัน event จะถูกทิ้ง (production ควรเปิด `--metrics-server` เพื่อเฝ้าดู) — แต่ **enforcement ไม่หาย** เพราะเกิดใน kernel
- **kind ≠ production:** Cilium ใน kind ใช้ veth + VXLAN, ไม่มี XDP, `Host: Legacy` routing ตัวเลขประสิทธิภาพจาก kind จึงใช้อ้างอิงไม่ได้
- **ตาราง Falco ไม่ได้ทดลองจริง** (หัวข้อ 1.6)

---

## 6. การแก้ปัญหาที่พบบ่อย (Troubleshooting)

| อาการ | สาเหตุ / วิธีแก้ |
| :--- | :--- |
| `make up` ค้าง/ขึ้น `container exited` | ดู `docker logs w26-tetragon`; ตรวจว่ามี `/sys/kernel/btf/vmlinux` และ Docker รัน `--privileged` ได้ (rootless Docker ใช้ไม่ได้) |
| `permission denied ... docker.sock` | เพิ่มตัวเองในกลุ่ม `docker` หรือให้สคริปต์ใช้ `sudo` (สคริปต์ตรวจ `docker info` ให้อัตโนมัติ) |
| ทุก event แสดงชื่อโหนดเป็นเลขฐาน 16 | ลืม `--hostname` (สคริปต์ใส่ให้แล้ว) |
| `capture` ได้ไฟล์ว่าง | อย่า kill `docker exec` จากฝั่งโฮสต์ ใช้ `./run-tetragon.sh capture <sec>` ซึ่งรัน `timeout` ในคอนเทนเนอร์ |
| ไม่เห็น event LSM เมื่อกรอง `--process w26-hello` | event `bprm_check_security` เป็นของโปรเซสก่อน exec (bash) ให้กรองด้วย `--policy-names` |
| compact output ไม่มี path ไฟล์ | ใช้ `capture-json ... \| jq -c -f event-summary.jq` |
| policy ขึ้น `load_error` | `docker logs w26-tetragon \| grep -i error`; มักเป็น symbol ไม่มีใน kernel, BPF LSM ปิดอยู่ หรือ Override ผิดเงื่อนไข (หัวข้อ 1.4/4.7) |
| `can't override '...' function with kprobe_multi` | ใช้ `lsmhooks:` (policy 05) หรือ `make down && make up-nomulti` |
| Sigkill/Override ไม่ทำงาน แต่ `NMONITOR` เพิ่ม | policy อยู่ในโหมด `monitor` → `./run-tetragon.sh mode <name> enforce` |
| `cat secret.txt` ยังอ่านได้ทั้งที่ enforce | ตรวจว่าเปิดไฟล์ผ่าน path ที่ลงท้ายตรงกับ `Postfix` (symlink จะถูก resolve ให้ แต่ bind mount/hard link ไม่ใช่) |
| `make down` เตือนว่ายังมีโปรแกรมค้าง | รอสักครู่แล้วรันซ้ำ (kernel free แบบ asynchronous); ถ้ายังค้างให้ดู `sudo bpftool prog show` ว่าชื่อตรงกับโปรแกรมของเครื่องมืออื่นหรือไม่ |
| Cilium: curl ยัง timeout หลังติด label | รอ 5–10 วินาทีให้ identity ใหม่ถูกคำนวณ (`cilium-dbg endpoint list` ดูเลข IDENTITY) |
| `kind create cluster` ชนกับ cluster อื่น | ใช้ชื่อ `w26-cilium` ตาม `cilium/kind-w26.yaml` และลบด้วย `kind delete cluster --name w26-cilium` |

---

## 7. Milestone Checklist

- [x] รัน Tetragon (pin `v1.7.1`) เป็น privileged container และอธิบายเหตุผลของทุก flag ได้
- [x] เขียน `TracingPolicy` ด้วย `kprobes:` และ `lsmhooks:` พร้อม `args`/`selectors`/`matchArgs`
- [x] เห็น `process_exec`/`process_exit` จาก base sensor และอธิบายว่าเทียบเท่ากับ Week 09
- [x] Monitor การเปิดไฟล์ใน `lab-files/` และการเชื่อมต่อ TCP ไปพอร์ต 18026 ด้วย event จริง
- [x] บังคับใช้นโยบาย 3 แบบ: `Sigkill`, `Override` (BPF LSM), `Override` (fmod_ret) และอธิบายความต่าง
- [x] ใช้ `monitor` → `enforce` และอ่านตัวนับ `NPOST`/`NENFORCE`/`NMONITOR`
- [x] ใช้ `bpftool prog show`/`link show` ระบุว่า Tetragon โหลดโปรแกรมชนิดใด แนบที่ไหน (tail call, kprobe_multi, lsm_mac, modify_return)
- [x] อธิบาย datapath ของ Cilium (TCX, socket LB, kube-proxy replacement, identity, Hubble) และโยงกับ Week 07/08/13/14/20
- [x] (ทางเลือก) ติดตั้ง Cilium บน kind, เห็น socket LB และ `Policy denied DROPPED` ใน Hubble
- [x] เก็บกวาดจนไม่มี BPF program ของ Tetragon/Cilium ค้างในเครื่อง

---

## 8. แบบฝึกหัดท้ายบท (Exercises)

ทุกข้อต้องผ่าน `make test` (กฎความปลอดภัย: path ต้องอยู่ใน `lab-files/`) และแนบ output จริงจาก `./run-tetragon.sh capture ...` เป็นหลักฐาน

### ระดับพื้นฐาน
1. **Monitor การเขียนไฟล์**
   - *Deliverable:* `policies/07-write-monitor.yaml` ใช้ `security_file_permission` (arg 0 `file`, arg 1 `int`) กรอง path `.../lab-files/notes.txt` และ `Mask` ของ `MAY_WRITE` (`2`)
   - *Verify:* `echo x >> lab-files/notes.txt` ต้องมี event ส่วน `cat lab-files/notes.txt` ต้องไม่มี
2. **จำกัดด้วย binary**
   - *Deliverable:* แก้สำเนาของ policy 04 ให้มี `matchBinaries: In ["/usr/bin/cat"]` เพิ่มใน selector เดียวกัน
   - *Verify:* `cat lab-files/secret.txt` ถูก kill แต่ `head lab-files/secret.txt` อ่านได้ อธิบายว่าทำไมนี่จึงเป็น policy ที่ "อ่อนกว่า" ในเชิงความปลอดภัย

### ระดับปานกลาง
3. **บล็อก connect ด้วย Override บน syscall**
   - *Deliverable:* policy ที่ hook `connect` แบบ `syscall: true` (ใช้ `bpf_override_return`) แล้วคืน `-ECONNREFUSED` (`-111`) เฉพาะเมื่อ binary คือ `lab-files/bin/` ที่คุณสร้างเอง (เช่นสำเนาของ curl) — ห้ามบล็อก curl ของระบบ
   - *Verify:* แสดงว่า `__x64_sys_connect` อยู่ใน `error_injection/list`, สำเนา curl ได้ `Connection refused` ส่วน `/usr/bin/curl` ยังใช้ได้ เปรียบเทียบกับ `cgroup/connect4` ของ Week 14 ว่าต่างกันอย่างไร (ระดับ hook, ขอบเขต cgroup, ค่า errno)
4. **วัด overhead ของ policy**
   - *Deliverable:* วัดเวลา `for i in $(seq 1 20000); do cat lab-files/notes.txt; done > /dev/null` (หรือโปรแกรม C ที่ `open`/`close` วนซ้ำ) 3 กรณี: ไม่มี Tetragon / มี base sensor / มี policy 02
   - *Verify:* รายงานค่าเฉลี่ยและส่วนเบี่ยงเบนจากอย่างน้อย 5 รอบ ระบุวิธีวัดและข้อจำกัด (หลักการเดียวกับ Week 22)

### ระดับท้าทาย
5. **หาทางเลี่ยง Postfix แล้วปิดช่องโหว่**
   - *Deliverable:* พิสูจน์ว่า hard link `ln lab-files/secret.txt lab-files/alias.txt` เลี่ยง policy 05 ได้ แล้วเขียน policy ใหม่ที่ป้องกันได้ (เช่น hook `path_link`/`security_path_link` เพื่อห้ามสร้าง link ไปยังไฟล์ลับ หรือจับตาม inode/ไดเรกทอรีของแล็บ)
   - *Verify:* แสดง output ก่อน/หลัง และวิเคราะห์ว่ายังเหลือช่องทางใดอีก (เทียบกับหัวข้อ 1.5 ของ Week 10)
6. **Tetragon เฝ้าดู eBPF เอง (ต่อยอด Week 16)**
   - *Deliverable:* policy ที่ hook `security_bpf_prog_load` (หรือ `bpf_check`) เพื่อบันทึกทุกครั้งที่มีการโหลด BPF program พร้อม binary ที่โหลด
   - *Verify:* รัน `make test` ของ Week 06/07 ขณะ Tetragon ทำงาน แล้วแสดง event ที่ระบุว่า `go test` binary โหลดโปรแกรม เปรียบเทียบกับ `fentry/__sys_bpf` ใน Week 16 และอภิปรายว่า "ใครเฝ้า Tetragon" (Tetragon โหลด BPF ของตัวเองก่อนที่ policy นี้จะทำงาน)
