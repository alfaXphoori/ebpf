# Week 10: BPF LSM Inline Security & Policy Enforcement

คู่มือการศึกษาเชิงลึกเกี่ยวกับการบังคับใช้นโยบายความปลอดภัยของระบบปฏิบัติการ Linux ในระดับ Kernel ด้วย **BPF LSM (Linux Security Modules)** เพื่อปฏิเสธการเปิดไฟล์สำคัญแบบ Synchronous Inline Blocking (`-EPERM`) โดยเขียนแบบ **CO-RE** (`vmlinux.h` + `BPF_CORE_READ`) และมีโหมด **Audit** (fentry) สำหรับเคอร์เนลที่ยังไม่ได้เปิด BPF LSM (เช่น Ubuntu ค่าเริ่มต้น)

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 สถาปัตยกรรม Linux Security Modules (LSM)
Linux Security Modules (LSM) คือเฟรมเวิร์กของ Linux Kernel ที่ถูกออกแบบขึ้นตั้งแต่ Linux 2.6 เพื่อให้ระบบสามารถบังคับใช้นโยบายสิทธิ์แบบ **Mandatory Access Control (MAC)** ควบคู่ไปกับ Discretionary Access Control (DAC: สิทธิ์ `rwxrwxrwx` ปกติ)

โมดูลความปลอดภัยดั้งเดิมเช่น SELinux, AppArmor, Smack, และ Tomoyo ล้วนถูกเขียนเป็นโมดูล C ภายในเคอร์เนล ซึ่งการจะเพิ่มกฎหรือเปลี่ยนแปลงพฤติกรรมจำเป็นต้องคอมไพล์เคอร์เนลใหม่หรือใช้ไวยากรณ์เฉพาะของโมดูลนั้นๆ BPF LSM (Linux 5.7+) เปิดให้เราเขียน logic ของ hook เหล่านี้เป็นโปรแกรม eBPF แล้วโหลดได้ขณะระบบทำงาน

```
+-------------------------------------------------------------------------+
|                  สถาปัตยกรรม VFS และ LSM HOOK EXECUTION                 |
|                                                                         |
|  User Process: open("secret_keys.pem", O_RDONLY)                        |
|        |                                                                |
|        v                                                                |
|  [ System Call: sys_openat() ]                                          |
|        |                                                                |
|        v                                                                |
|  [ Path lookup + DAC Check (may_open): สิทธิ์ rwx ของ user/group ]       |
|        | ผ่าน DAC                                                       |
|        v                                                                |
|  [ VFS: vfs_open() -> do_dentry_open() ]                                |
|        |                                                                |
|        v                                                                |
|  [ security_file_open(file) ]  <-- fentry (audit mode) ดักตรงนี้ได้      |
|        |                                                                |
|        +---> AppArmor / IMA ... (ตามลำดับใน lsm=)                       |
|        +---> BPF LSM Hook: restrict_secret_files(file)                  |
|                 |                                                       |
|                 |-- คืนค่า 0      --> อนุญาต ให้เปิดไฟล์ต่อไป               |
|                 \-- คืนค่า -EPERM --> open() ล้มเหลว errno=EPERM         |
+-------------------------------------------------------------------------+
```

### 1.2 ทำไม BPF LSM ถึงเหมาะกับงาน Prevention มากกว่า Kprobes / Tracepoints
ก่อนหน้าที่มี BPF LSM นักพัฒนาความปลอดภัยมักใช้ Kprobes หรือ Tracepoints เช่น `sys_enter_openat` ในการตรวจสอบพฤติกรรม แต่พบข้อจำกัดในเชิงการป้องกัน (Prevention):

1. **Observe ได้ แต่เปลี่ยนผลลัพธ์ไม่ได้**:
   - Kprobe / Tracepoint / fentry ทำงานแบบ synchronous ในบริบทของ process ก็จริง แต่ค่าที่โปรแกรม eBPF คืนกลับ **ไม่มีผลต่อการทำงานของเคอร์เนล** (ยกเว้นกรณีพิเศษอย่าง `bpf_override_return` ที่ใช้ได้เฉพาะฟังก์ชันที่เปิด error injection) ทำได้แค่ส่ง alert แล้วให้ user space ไป kill process ทีหลัง ซึ่งช้าเกินไป -- ไฟล์ถูกอ่านไปแล้ว
2. **ปัญหา TOCTOU (Time-of-Check to Time-of-Use)**:
   - Hook ที่ `sys_enter_openat` เห็นแค่ **string path ใน user memory** ผู้โจมตีสามารถเปลี่ยน string หรือสลับ symlink ระหว่างจังหวะที่โพรบอ่านกับจังหวะที่เคอร์เนล resolve path จริงได้
   - LSM `file_open` ได้รับ `struct file *` ที่เคอร์เนล resolve และจะใช้งานจริงแล้ว การตัดสินใจจึงผูกกับ object เดียวกับที่ถูกเปิด (ไม่มี race ระหว่าง "สิ่งที่ตรวจ" กับ "สิ่งที่เปิด" ในจุดนี้) -- แต่กฎที่อิง **ชื่อไฟล์** ยังหลบได้ด้วยวิธีอื่น (ดูหัวข้อ 6)
3. **Synchronous Inline Decision**:
   - เมื่อ BPF LSM คืนค่าติดลบ `-errno` เช่น `-EPERM` เคอร์เนลจะยกเลิกการเปิดไฟล์นั้น และ `open()` คืน `-1` พร้อม `errno = EPERM` ("Operation not permitted") โดยไม่มี File Descriptor ถูกส่งคืนให้ User space

### 1.3 การเปิดใช้งาน BPF LSM ในเคอร์เนล
ต้องมี **2 เงื่อนไข** พร้อมกัน:
1. **Compile-time**: เคอร์เนลถูก build ด้วย `CONFIG_BPF_LSM=y` (Ubuntu มีอยู่แล้ว)
   ```bash
   grep CONFIG_BPF_LSM /boot/config-$(uname -r)   # ต้องได้ CONFIG_BPF_LSM=y
   ```
2. **Boot-time**: ต้องมี `bpf` อยู่ในรายการ LSM ที่ active (กำหนดด้วย `CONFIG_LSM` ตอน build หรือพารามิเตอร์ `lsm=` ตอนบูต)
   ```bash
   cat /sys/kernel/security/lsm
   # เครื่อง lab (Ubuntu 26.04, Linux 7.0.0-38-generic) ได้:
   # lockdown,capability,landlock,yama,apparmor,ima,evm     <-- ไม่มี bpf
   ```

**ขั้นตอนเปิดผ่าน GRUB (Ubuntu/Debian)** -- แนะนำให้ทำใน **VM สำหรับแล็บ** และ *ยังไม่ได้ทดสอบบนเครื่อง lab ที่ใช้เขียนบทนี้* (เพราะไม่ได้รับอนุญาตให้แก้ kernel cmdline):
```bash
# 1) อ่านรายการปัจจุบัน แล้ว "ต่อท้าย" bpf -- ห้ามตัดตัวเดิมออก
CUR=$(cat /sys/kernel/security/lsm)        # เช่น lockdown,capability,landlock,yama,apparmor,ima,evm
echo "lsm=${CUR},bpf"                       # ตรวจด้วยตาก่อน

# 2) เขียน drop-in config (Ubuntu อ่าน /etc/default/grub.d/*.cfg ต่อจาก /etc/default/grub)
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT lsm=${CUR},bpf\"" \
  | sudo tee /etc/default/grub.d/99-bpf-lsm.cfg

# 3) สร้าง grub.cfg ใหม่ แล้วตรวจว่ามี lsm=...,bpf
sudo update-grub
grep -o 'lsm=[^ ]*' /boot/grub/grub.cfg | sort -u

# 4) รีบูต แล้วตรวจผล
sudo reboot
grep -o 'lsm=[^ ]*' /proc/cmdline
cat /sys/kernel/security/lsm               # ต้องมี ,bpf
```
ข้อควรระวัง:
- `lsm=` **แทนที่** รายการทั้งหมด ถ้าลืมใส่ `apparmor` AppArmor จะถูกปิด (snap และ profile ต่างๆ จะไม่ถูกบังคับใช้) จึงต้องเริ่มจากรายการปัจจุบันเสมอ
- ทดลองแบบไม่ถาวรได้โดยกด `e` ที่เมนู GRUB แล้วเติม `lsm=...,bpf` ท้ายบรรทัด `linux` (หายไปเมื่อรีบูตครั้งถัดไป)
- ยกเลิก: `sudo rm /etc/default/grub.d/99-bpf-lsm.cfg && sudo update-grub && sudo reboot`

### 1.4 เกิดอะไรขึ้นถ้าไม่มี `bpf` ใน `/sys/kernel/security/lsm`? (ตรวจสอบจริงบนเครื่อง lab)
บน Linux 7.0.0-38-generic ที่ `CONFIG_BPF_LSM=y` แต่ไม่มี `bpf` ใน LSM list:
- **โหลด** program ชนิด `BPF_PROG_TYPE_LSM` ได้ (verifier ผ่าน รวมถึงการเรียก `bpf_d_path()` ใน `lsm/file_open`)
- **Attach** ได้สำเร็จ (`bpftool link show` แสดง `prog_type lsm  attach_type lsm_mac`)
- แต่ **เคอร์เนลไม่เคยเรียก program นั้นเลย**: user ปกติ `cat lab-files/secret.txt` อ่านได้ตามปกติ และไม่มี alert (ดูหัวข้อ 4.2)

นี่คือกับดักสำคัญ: "attach สำเร็จ" **ไม่ได้แปลว่า "บังคับใช้อยู่"** เวอร์ชันก่อนหน้าของแล็บนี้พิมพ์ `Successfully attached BPF LSM hook` แม้บนเครื่องที่ไม่มีผลใดๆ เวอร์ชันนี้จึง:
- ตรวจ `/sys/kernel/security/lsm` ก่อน และใน `-mode=auto` (ค่าเริ่มต้น) ถ้าไม่มี `bpf` จะสลับไป **AUDIT mode** อัตโนมัติ: attach `fentry/security_file_open` ซึ่งเห็นทุกการเปิดไฟล์แบบเดียวกัน แต่ **block ไม่ได้** (fentry เปลี่ยนค่าคืนของฟังก์ชันไม่ได้) ใช้เพื่อทดสอบ logic การ match / ring buffer / `bpf_d_path` บนเครื่องที่ยังไม่เปิด BPF LSM
- `-mode=enforce` บังคับใช้ LSM เสมอ พร้อมคำเตือนถ้า `bpf` ไม่ active

### 1.5 การจับคู่ไฟล์: ชื่อ (basename) vs ตัวไฟล์ (inode)
แล็บนี้มีกฎ 2 แบบทำงานพร้อมกัน:

| กฎ | วิธี | จุดแข็ง | จุดอ่อน |
| :--- | :--- | :--- | :--- |
| **Name** (`secret*`) | อ่าน `file->f_path.dentry->d_name.name` (basename ของ dentry ที่ใช้เปิด) | ไม่ต้องตั้งค่าล่วงหน้า, ครอบคลุมไฟล์ที่สร้างใหม่ | หลบได้ด้วย hardlink ชื่ออื่น/rename, **false positive** กับไฟล์ระบบที่ชื่อขึ้นต้นด้วย secret (ดูหัวข้อ 4.1) |
| **Inode** (`-protect <path>`) | key = (`inode->i_sb->s_dev`, `inode->i_ino`) ใน hash map `protected_inodes` | ผูกกับตัวไฟล์จริง: hardlink, symlink, rename ไม่หลุด | ต้องระบุไฟล์ล่วงหน้า; ถ้าไฟล์ถูกลบแล้วสร้างใหม่ (เช่น editor ที่ save แบบเขียนไฟล์ใหม่แล้ว rename ทับ) จะได้ inode ใหม่ที่ไม่ถูกป้องกัน; inode number อาจถูก reuse |

`bpf_d_path()` ใช้สร้าง **full path** สำหรับ log (ตาม mount namespace ของ process ที่เปิด) helper นี้เรียกได้เฉพาะ hook ที่เคอร์เนลอนุญาต (allowlist) -- `fentry/security_file_open` และ `lsm/file_open` ผ่านเงื่อนไขนี้บน Linux 7.0 (ตรวจโดยโหลดจริงทั้งสองโหมด) เราใช้ path เพื่อ **แสดงผลเท่านั้น** ไม่ใช้ตัดสินใจ เพราะ path ของไฟล์เดียวกันมีได้หลายแบบ (bind mount, namespace, hardlink)

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 eBPF C LSM Program (`lsm_file_guard.c`)

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
...
#define EPERM 1 /* include/uapi/asm-generic/errno-base.h: Operation not permitted */
```
- **บรรทัด 9–19**: เวอร์ชันก่อนประกาศ `struct file`/`dentry`/`inode` เองและ `#define __VMLINUX_H__` หลอก ซึ่งขัดกับหลัก CO-RE ที่สอนในคอร์ส ตอนนี้ใช้ `vmlinux.h` จริง (สร้างด้วย `bpftool btf dump file /sys/kernel/btf/vmlinux format c` ผ่าน `scripts/setup_env.sh` วางที่ root ของ repo) ห้าม include `<linux/*.h>` ร่วมด้วยเพราะ type จะชนกัน ค่าคงที่อย่าง `EPERM` จึงต้อง `#define` เอง (vmlinux.h มีแต่ type ไม่มี macro)

```c
struct lsm_alert {
    __u64 ino;
    __u32 dev;
    __u32 pid;
    __u32 uid;
    __s32 ret;    /* -EPERM (-1) = block, 0 = audit only */
    __u32 reason; /* MATCH_NAME / MATCH_INODE */
    __u32 pad;
    char  comm[TASK_COMM_LEN];
    char  path[PATH_LEN];
};
```
- **บรรทัด 32–42**: Alert ขนาด 304 ไบต์ เรียง field ให้ไม่มี padding แอบแฝง เพื่อให้ตรงกับ Go struct `lsmAlert` `ret` คือค่าที่โปรแกรมคืนให้เคอร์เนลจริง (แทน `action = -1` แบบ hard-code เดิม) และ `path` ขยายเป็น 256 ไบต์สำหรับ full path

```c
struct inode_key {
    __u64 ino;
    __u32 dev;
    __u32 pad;
};
... protected_inodes SEC(".maps");  /* BPF_MAP_TYPE_HASH, max 1024 */
```
- **บรรทัด 67–78**: Map สำหรับกฎแบบ inode ฝั่ง Go เติมค่าจาก `stat()` ของไฟล์ที่ระบุด้วย `-protect` (ต้องเติม `pad = 0` ทุกครั้ง เพราะ hash map เทียบ key ทุกไบต์)

```c
static __always_inline __u32 match_file(struct file *file, struct inode_key *key)
{
    key->ino = BPF_CORE_READ(file, f_inode, i_ino);
    key->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    ...
    const unsigned char *name_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    char fname[8] = {};
    long str_len = bpf_probe_read_kernel_str(fname, sizeof(fname), name_ptr);
```
- **บรรทัด 85–114**: ทุกการอ่าน kernel struct ใช้ `BPF_CORE_READ()` ซึ่งอ่าน pointer chain (`file->f_inode->i_sb->s_dev`) ทีละขั้นด้วย `bpf_probe_read_kernel()` พร้อมบันทึก CO-RE relocation ให้ loader ปรับ offset ตาม BTF ของเคอร์เนลที่รันจริง ตรวจ inode ก่อน (O(1) hash lookup) แล้วจึงตรวจ prefix ชื่อ `"secret"` (ต้องการแค่ 6 ตัวอักษรแรก buffer 8 ไบต์จึงพอ ไม่ต้องใช้ 64 ไบต์บน stack แบบเดิม)

```c
static __always_inline int check_file_open(struct file *file, int enforce)
{
    ...
    if (block_all == 0 && uid == 0) {
        return 0;
    }
    int ret = enforce ? -EPERM : 0;
    ...
        if (bpf_d_path((struct path *)&file->f_path, alert->path, sizeof(alert->path)) < 0) {
```
- **บรรทัด 120–167**: logic ร่วมของทั้งสองโหมด: อ่าน `policy_map` (0 = ยกเว้น root, 1 = `-block-all`), คำนวณค่าคืน (`-EPERM` ใน enforce, `0` ใน audit), จอง alert ใน ring buffer แล้วเรียก `bpf_d_path()` เขียน full path ลงพื้นที่ ring buffer โดยตรง (ไม่ใช้ stack 256 ไบต์) ต้อง cast `const struct path *` เพราะ `f_path` เป็น `const` ใน `struct file` ของเคอร์เนลรุ่นใหม่ UID ที่ใช้คือ **real UID** จาก `bpf_get_current_uid_gid()` (ดู Limitations)

```c
SEC("lsm/file_open")
int BPF_PROG(restrict_secret_files, struct file *file)
{
    return check_file_open(file, 1);
}
```
- **บรรทัด 177–186**: Hook LSM `file_open` (ENFORCE) Macro `BPF_PROG` แปลง context (array ของ `u64`) เป็น argument ที่มี type ให้อัตโนมัติ **การแก้บั๊ก**: เดิม `return -1; /* -EPERM */` ซึ่งตัวเลขเท่ากัน (EPERM = 1) แต่สื่อเจตนาไม่ชัด และถ้าเปลี่ยนเป็น errno อื่น (เช่น `-EACCES` = -13) จะลืมแก้ได้ง่าย ตอนนี้คืน `-EPERM` ตรงๆ ฝั่ง Go ก็เทียบกับ `-int32(syscall.EPERM)` แทนเลข `-1`

```c
SEC("fentry/security_file_open")
int BPF_PROG(audit_secret_files, struct file *file)
{
    check_file_open(file, 0);
    return 0;
}
```
- **บรรทัด 193–198**: AUDIT fallback ผ่าน BPF trampoline (fentry) บนฟังก์ชันเคอร์เนล `security_file_open()` ที่ถูกเรียกเสมอไม่ว่า BPF LSM จะ active หรือไม่ ค่าที่ fentry คืนถูกเคอร์เนลเพิกเฉย จึงใช้ได้แค่ log

---

### 2.2 Go Control Plane (`main.go`)

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" -target bpf bpf lsm_file_guard.c
```
- **บรรทัด 22**: `-cflags "-I../../"` ให้ clang หา `vmlinux.h` ที่ root ของ repo (แบบเดียวกับ Week 22–23) ตอน generate จะเห็น warning `declaration does not declare anything` 5 บรรทัดจาก `vmlinux.h` ซึ่งไม่มีผลต่อการทำงาน

```go
type enforceObjects struct {
	bpfMaps
	Prog *ebpf.Program `ebpf:"restrict_secret_files"`
}
```
- **บรรทัด 49–58**: แทนที่จะใช้ `loadBpfObjects()` (โหลด **ทุก** program) เราโหลด spec แล้ว `LoadAndAssign` เฉพาะ maps + program ของโหมดที่เลือก ถ้าเคอร์เนลไม่มี `CONFIG_BPF_LSM` โหมด audit ก็ยังโหลดได้

```go
func bpfLSMActive() bool { ... strings.Split(activeLSMs, ",") ... m == "bpf" ... }
```
- **บรรทัด 61–79**: อ่าน `/sys/kernel/security/lsm` แล้วเทียบเป็นรายการ (ไม่ใช้ `strings.Contains` แบบเดิมที่จะเข้าใจผิดถ้ามีชื่อ LSM อื่นที่มีคำว่า bpf อยู่ข้างใน)

```go
func kernelDev(statDev uint64) uint32 {
	return unix.Major(statDev)<<20 | unix.Minor(statDev)
}
```
- **บรรทัด 81–85**: `st_dev` จาก `stat()` ใช้ encoding ของ user space (`new_encode_dev`) แต่ `sb->s_dev` ในเคอร์เนลเป็น `MKDEV(major, minor) = major<<20 | minor` จึงต้องแปลงก่อนใส่ key มิฉะนั้น lookup จะไม่เจอ

```go
case "auto":
	if lsmActive { mode = "enforce" } else { mode = "audit" ... }
```
- **บรรทัด 112–129**: เลือกโหมด `auto` / `enforce` / `audit`

```go
if err := maps.PolicyMap.Put(&policyKey, &policyVal); ...
...
key := inodeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
if err := maps.ProtectedInodes.Put(&key, &one); ...
```
- **บรรทัด 155–183**: ตั้งค่า policy (`-block-all`) และเติม inode ของทุก `-protect <path>` (ใช้ `unix.Stat` ซึ่ง follow symlink: ป้องกันไฟล์ปลายทาง)

```go
hook, err = link.AttachLSM(link.LSMOptions{Program: prog})        // enforce
hook, err = link.AttachTracing(link.TracingOptions{Program: prog}) // audit (fentry)
```
- **บรรทัด 185–199**: Attach ตามโหมด

```go
rd, err := ringbuf.NewReader(maps.LsmEvents)
...
if alert.Ret == -int32(syscall.EPERM) { ... "[BLOCKED -EPERM]" ... }
```
- **บรรทัด 203–254**: อ่าน alert จาก ring buffer แสดง `[BLOCKED -EPERM]` (สีแดง) หรือ `[AUDIT would-block]` (สีเหลือง) พร้อมเหตุผล `name`/`inode` และ full path

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบเคอร์เนลและคอมไพล์โปรแกรม
```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
cat /sys/kernel/security/lsm            # มี bpf ไหม? ถ้าไม่มี จะได้ AUDIT mode
ls ../../vmlinux.h                      # สร้างโดย scripts/setup_env.sh
make all                                # = go generate + go build -> bin/lsm_file_guard
```

### ขั้นตอนที่ 2: สร้างไฟล์ทดสอบ (ใน `lab-files/` ซึ่ง `make clean` จะลบให้)
```bash
mkdir -p lab-files && cd lab-files
echo "top secret" > secret.txt
echo "api-key"    > app.key
ln secret.txt notes.txt        # hardlink ชื่ออื่นของ secret.txt
ln app.key backup.txt          # hardlink ชื่ออื่นของ app.key
ln -s secret.txt shortcut      # symlink
cd ..
```

### ขั้นตอนที่ 3: รันโปรแกรม
```bash
sudo ./bin/lsm_file_guard -protect lab-files/app.key              # auto: enforce ถ้ามี bpf LSM, ไม่งั้น audit
sudo ./bin/lsm_file_guard -mode=audit -protect lab-files/app.key  # บังคับ audit
sudo ./bin/lsm_file_guard -mode=enforce                           # บังคับ LSM (มีผลเฉพาะเมื่อ bpf active)
```
> **คำเตือน**: อย่าใช้ `-block-all` บนเครื่องที่ใช้งานจริง กฎ `secret*` จะบล็อกแม้แต่ root จากไฟล์ระบบอย่าง `/usr/lib/python3.*/secrets.py` หรือ `/usr/share/go-*/src/runtime/secret.go` (ดูหัวข้อ 4.1) ซึ่งอาจทำให้โปรแกรมของระบบทำงานผิดพลาด

### ขั้นตอนที่ 4: ทดสอบด้วย User ทั่วไป (UID != 0) ในอีกหน้าต่าง
```bash
cat lab-files/secret.txt     # name match
cat lab-files/notes.txt      # hardlink: name rule หลุด!
cat lab-files/shortcut       # symlink: dentry ปลายทางชื่อ secret.txt -> match
cat lab-files/app.key        # inode match
cat lab-files/backup.txt     # hardlink ของ app.key: inode rule ยังจับได้
python3 -c "import secrets"  # false positive ของกฎ secret*
sudo cat lab-files/secret.txt   # root: ได้รับการยกเว้น (ถ้าไม่ใช้ -block-all)
```
- **Enforce mode (มี bpf LSM)**: คำสั่งที่ match ควรได้ `cat: ...: Operation not permitted` และหน้าต่าง guard แสดง `[BLOCKED -EPERM]`
- **Audit mode**: ทุกคำสั่งอ่านไฟล์ได้ตามปกติ แต่หน้าต่าง guard แสดง `[AUDIT would-block]` สำหรับคำสั่งที่ *จะ* ถูกบล็อก

---

## 4. ผลลัพธ์จากการทดลองจริง (Actual Lab Execution Output)

> **Environment**: Ubuntu 26.04.1 LTS (`Linux ce-desk 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC x86_64`), `CONFIG_BPF_LSM=y`, LSM=`lockdown,capability,landlock,yama,apparmor,ima,evm` (**ไม่มี bpf**), clang 21, Go 1.26, cilium/ebpf v0.16.0
> เพราะเครื่องนี้ไม่ได้เปิด BPF LSM จึง **ยังไม่ได้ทดสอบการ block จริง (enforce) ของโค้ดเวอร์ชันนี้** -- ทดสอบแล้วเฉพาะ: build, การโหลด/attach ทั้งสองโหมด และ logic การ match ผ่าน audit mode

### 4.1 Audit mode: `sudo ./bin/lsm_file_guard -protect lab-files/app.key` แล้วรันคำสั่งในขั้นตอนที่ 4
(ตัดบรรทัดของ process อื่นในเครื่องออก: `go` build ของงานอื่นเปิด `/usr/share/go-1.26/src/runtime/secret.go`, `secret_asm.go`, `secret_amd64.s` และถูกรายงานเป็น `name` match ด้วย -- อีกหนึ่ง false positive จริง)
```text
2026/10/28 22:08:37 [INFO] Active Linux Security Modules: lockdown,capability,landlock,yama,apparmor,ima,evm
2026/10/28 22:08:37 [WARNING] 'bpf' is NOT in /sys/kernel/security/lsm!
2026/10/28 22:08:37 [WARNING] BPF LSM programs can still be loaded/attached, but the kernel will never call them.
2026/10/28 22:08:37 [WARNING] To enable BPF LSM, append 'bpf' to the lsm= boot parameter (see README section 'การเปิดใช้งาน BPF LSM').
2026/10/28 22:08:37 [INFO] -mode=auto: BPF LSM inactive -> falling back to AUDIT mode (fentry/security_file_open, cannot block)
2026/10/28 22:08:37 [POLICY] Enforce Mode: BLOCK NON-ROOT (root UID 0 allowed)
2026/10/28 22:08:37 [POLICY] Protecting inode dev=8:0 ino=7340734 (lab-files/app.key)
2026/10/28 22:08:37 [INFO] Attached 'fentry/security_file_open' (AUDIT: matching opens are logged, NOT blocked)
2026/10/28 22:08:37 [INFO] Watching for access to 'secret*' files and protected inodes...
SECURITY_ACTION      PID     UID    COMM       MATCH  PATH -> RESULT
----------------------------------------------------------------------------------------------------
[AUDIT would-block]  4132668 1000   cat        name   /mnt/sda/ebpf/phase05-security-observability/week10-bpf-lsm/lab-files/secret.txt -> ALLOWED (audit only)
[AUDIT would-block]  4132674 1000   cat        name   /mnt/sda/ebpf/phase05-security-observability/week10-bpf-lsm/lab-files/secret.txt -> ALLOWED (audit only)
[AUDIT would-block]  4132675 1000   cat        inode  /mnt/sda/ebpf/phase05-security-observability/week10-bpf-lsm/lab-files/app.key -> ALLOWED (audit only)
[AUDIT would-block]  4132676 1000   cat        inode  /mnt/sda/ebpf/phase05-security-observability/week10-bpf-lsm/lab-files/backup.txt -> ALLOWED (audit only)
[AUDIT would-block]  4132677 1000   python3    name   /usr/lib/python3.14/__pycache__/secrets.cpython-314.pyc -> ALLOWED (audit only)
```
วิเคราะห์ผล (เทียบกับคำสั่งในขั้นตอนที่ 4 ตามลำดับ):
| คำสั่ง | ผล | ความหมาย |
| :--- | :--- | :--- |
| `cat secret.txt` | `name` | กฎชื่อทำงาน |
| `cat notes.txt` (hardlink) | **ไม่มี alert** | **bypass กฎชื่อ** สำเร็จ: dentry ที่ใช้เปิดชื่อ `notes.txt` |
| `cat shortcut` (symlink) | `name` (path = `secret.txt`) | symlink ถูก resolve ก่อนถึง `file_open` จึงไม่หลุด |
| `cat app.key` / `cat backup.txt` | `inode` | กฎ inode จับได้ทั้งสองชื่อ และ `bpf_d_path` แสดงชื่อที่ใช้เปิดจริง |
| `python3 -c "import secrets"` | `name` | **false positive**: ถ้า enforce, user ทั่วไปจะ import โมดูล `secrets` ของ Python ไม่ได้ |
| `sudo cat secret.txt` | ไม่มี alert | root ได้รับการยกเว้น (policy 0) |

### 4.2 Enforce mode บนเคอร์เนลที่ **ไม่มี** bpf LSM: `sudo ./bin/lsm_file_guard -mode=enforce`
```text
2026/10/28 22:13:58 [INFO] Active Linux Security Modules: lockdown,capability,landlock,yama,apparmor,ima,evm
2026/10/28 22:13:58 [WARNING] 'bpf' is NOT in /sys/kernel/security/lsm!
2026/10/28 22:13:58 [WARNING] BPF LSM programs can still be loaded/attached, but the kernel will never call them.
2026/10/28 22:13:58 [WARNING] To enable BPF LSM, append 'bpf' to the lsm= boot parameter (see README section 'การเปิดใช้งาน BPF LSM').
2026/10/28 22:13:58 [WARNING] -mode=enforce on a kernel without active BPF LSM: attach may succeed but NOTHING will be blocked.
2026/10/28 22:13:58 [POLICY] Enforce Mode: BLOCK NON-ROOT (root UID 0 allowed)
2026/10/28 22:13:58 [INFO] Attached BPF LSM hook 'lsm/file_open' (ENFORCE: matching opens return -EPERM)
2026/10/28 22:13:58 [INFO] Watching for access to 'secret*' files and protected inodes...
SECURITY_ACTION      PID     UID    COMM       MATCH  PATH -> RESULT
----------------------------------------------------------------------------------------------------
2026/10/28 22:14:04 [INFO] Termination signal received. Detaching hook and exiting...
2026/10/28 22:14:04 [INFO] Ringbuf reader closed. Goodbye.
```
ระหว่างที่โปรแกรมทำงาน (อีกหน้าต่าง):
```text
$ sudo bpftool link show
3975: tracing  prog 10485
	prog_type lsm  attach_type lsm_mac
	target_obj_id 1  target_btf_id 98575
$ cat lab-files/secret.txt
top secret
exit=0
```
ยืนยันหัวข้อ 1.4: verifier ยอมรับ program (รวม `bpf_d_path`), attach สำเร็จ แต่ไม่มีการ block และไม่มี alert

### 4.3 ผลจากโค้ด **เวอร์ชันก่อนหน้า** บนเครื่องที่เปิด BPF LSM แล้ว (อ้างอิงเท่านั้น)
> ผลนี้มาจากเวอร์ชันเดิมของแล็บ (ก่อนแปลงเป็น CO-RE และก่อนเพิ่ม inode/audit) บน Ubuntu 24.04 LTS `6.8.0-142-generic aarch64`, LSM=`lockdown,capability,landlock,yama,apparmor,bpf` จึงมีรูปแบบคอลัมน์ต่างจากปัจจุบัน และ **ไม่ได้ capture ใหม่** เก็บไว้เพื่อแสดงพฤติกรรม enforce ของ `lsm/file_open` เท่านั้น
```text
2026/10/18 13:50:40 [INFO] Active Linux Security Modules: lockdown,capability,landlock,yama,apparmor,bpf
2026/10/18 13:50:40 [POLICY] Enforce Mode: BLOCK NON-ROOT (root UID 0 allowed)
2026/10/18 13:50:40 [INFO] Successfully attached BPF LSM hook to 'file_open'!
2026/10/18 13:50:40 [INFO] Watching for unauthorized attempts to access 'secret*' files...
SECURITY_ACTION    PID     UID    COMM             FILENAME             RESULT
-------------------------------------------------------------------------------------
[BLOCKED -EPERM]   9982    501    cat              secret.txt           EPERM (Blocked)

--- ผลลัพธ์ฝั่งผู้ใช้งาน (User Terminal Output) ---
$ sudo -u phoori cat /tmp/secret.txt (Non-Root User)
cat: /tmp/secret.txt: Operation not permitted

$ sudo cat /tmp/secret.txt (Root UID 0)
TOP_SECRET_CREDENTIAL=admin123

$ sudo -u phoori cat /tmp/secret.txt (After detaching BPF LSM)
TOP_SECRET_CREDENTIAL=admin123
```

---

## 5. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **BPF LSM Support** | ตรวจ `CONFIG_BPF_LSM=y` และ `bpf` ใน `/sys/kernel/security/lsm` แยกเป็นรายการ | [x] ผ่าน |
| **BTF / CO-RE Header** | ใช้ `vmlinux.h` จริง + `BPF_CORE_READ` ทุกการอ่าน kernel struct (ไม่มี struct ประกาศเอง) | [x] ผ่าน |
| **Inline Blocking Logic** | คืนค่า `-EPERM` ชัดเจน (EPERM = 1) | [x] build/load ผ่าน, enforce ต้องทดสอบบนเครื่องที่เปิด bpf LSM |
| **Name + Inode Matching** | prefix `secret*` และ hash map `(s_dev, i_ino)` จาก `-protect` | [x] ผ่าน (ทดสอบผ่าน audit mode) |
| **Full Path Logging** | `bpf_d_path()` ใน `lsm/file_open` และ `fentry/security_file_open` | [x] ผ่าน |
| **Audit Fallback** | `-mode=auto` สลับเป็น fentry เมื่อไม่มี bpf LSM | [x] ผ่าน |
| **Policy Configuration** | มี `policy_map` ให้สลับโหมด Enforce All กับ Block Non-Root ได้ | [x] ผ่าน |
| **Real-time Ringbuf Alert** | สตรีม Alert: PID, UID, COMM, MATCH, PATH สู่ User-space | [x] ผ่าน |

---

## 6. ข้อจำกัดและ Threat Model (Limitations)

แล็บนี้เป็นตัวอย่างการสอน ไม่ใช่ระบบป้องกันที่สมบูรณ์ ผู้โจมตีที่รู้กฎสามารถหลบได้ดังนี้:

**หลบกฎชื่อ (`secret*`)**
1. **Hardlink ชื่ออื่น**: `ln secret.txt notes.txt` แล้วเปิด `notes.txt` (ยืนยันแล้วในหัวข้อ 4.1) ทำได้ถ้าผู้โจมตีเป็นเจ้าของไฟล์หรือมีสิทธิ์อ่าน/เขียนไฟล์นั้นตาม `fs.protected_hardlinks=1` -- กฎ inode ปิดช่องนี้
2. **Rename / copy**: ถ้ามีสิทธิ์เขียนใน directory ก็ `mv secret.txt x` ได้ (การ rename ไม่ผ่าน `file_open`) ควร hook `path_rename` / `inode_rename` เพิ่ม
3. **กรณีชื่อ**: กฎเทียบตัวพิมพ์เล็กเท่านั้น `SECRET.txt` / `Secret.txt` ไม่ match

**หลบ hook `file_open` ทั้งหมด**
4. **FD ที่เปิดไว้ก่อน**: process ที่เปิดไฟล์ไว้ก่อน program ถูก attach (หรือรับ fd ผ่าน `SCM_RIGHTS` / สืบทอดจาก parent ที่เป็น root) อ่านต่อได้ เพราะ `read()`/`mmap()` ไม่ผ่าน `file_open` (ต้อง hook `file_permission` / `mmap_file` เพิ่ม)
5. **ไม่ต้องเปิดไฟล์เลย**: อ่านข้อมูลผ่านช่องทางอื่น เช่น backup, block device (`/dev/sda` ถ้ามีสิทธิ์), `/proc/<pid>/mem` ของ process ที่โหลด secret ไว้แล้ว, หรือ swap

**จุดอ่อนของนโยบาย**
6. **Root bypass โดยออกแบบ**: policy 0 ยกเว้น `uid == 0` ซึ่งเป็น **real UID** -- ไบนารี setuid-root ที่ user รันจะยังถูกบล็อก (real UID = user) แต่ process root ใดๆ ผ่านได้ และ root ที่ถูก map ใน user namespace (container rootless) จะไม่ได้ UID 0 ในมุมของ init namespace
7. **Root ปิดระบบป้องกันได้**: ผู้มี `CAP_SYS_ADMIN`/`CAP_BPF` สามารถ kill agent (link ถูก detach เมื่อ process จบเพราะไม่ได้ pin) หรือแก้ `policy_map` / `protected_inodes` ผ่าน `bpftool map update` ได้ ป้องกันเพิ่มได้ด้วยการ pin link ใน bpffs, hook `lsm/bpf` เพื่อปฏิเสธการแก้ map/program ของเรา, และ kernel lockdown
8. **Fail-open**: ถ้า `bpf_ringbuf_reserve()` คืน `NULL` (buffer เต็ม) การ block ยังเกิดขึ้น แต่ **ไม่มี alert** -- ผู้โจมตีอาจสร้าง event จำนวนมากเพื่อกลบร่องรอย
9. **Inode เปลี่ยน**: กฎ inode ผูกกับไฟล์ ณ ตอนเริ่มโปรแกรม ถ้าไฟล์ถูกแทนที่ด้วยไฟล์ใหม่ (inode ใหม่) จะไม่ถูกป้องกัน และบนบาง filesystem (btrfs subvolume, overlayfs) `st_dev` จาก `stat()` อาจไม่ตรงกับ `i_sb->s_dev` ทำให้ lookup ไม่เจอ (ยังไม่ได้ทดสอบ -- ทดสอบแล้วบน ext4 และ tmpfs)
10. **False positive = DoS ตัวเอง**: กฎชื่อกว้างเกินไป (Python `secrets`, Go `runtime/secret.go`) ใน production ควรใช้ allowlist path/inode ที่ชัดเจน และเริ่มจาก audit mode ก่อน enforce เสมอ
11. **ไม่มี BPF LSM = ไม่มีการป้องกัน**: บนเคอร์เนลส่วนใหญ่ที่ไม่ได้ใส่ `bpf` ใน `lsm=` program จะไม่ถูกเรียกเลย (หัวข้อ 1.4)

---

## 7. แบบฝึกหัดท้ายบท (Exercises)

### ระดับพื้นฐาน
**7.1 เปลี่ยน errno**: แก้ให้ enforce mode คืน `-EACCES` (13, "Permission denied") แทน `-EPERM` โดย `#define EACCES 13` ใน C และแก้การแสดงผลใน `main.go` ให้รองรับ
- *ส่งงาน*: diff + อธิบายว่าทำไมต้อง define เองเมื่อใช้ `vmlinux.h`
- *ตรวจสอบ*: บนเครื่องที่เปิด bpf LSM, `cat lab-files/secret.txt` ต้องได้ `Permission denied`; บนเครื่องที่ไม่เปิด ให้ตรวจด้วย `llvm-objdump -d bpf_bpf.o` ว่า program `restrict_secret_files` คืนค่า `-13`

**7.2 Case-insensitive + suffix**: ปรับกฎชื่อให้ match `secret` แบบไม่สนตัวพิมพ์ และ match นามสกุล `.pem` / `.key` เพิ่ม (ระวัง verifier: loop ต้องมีขอบเขตชัดเจน หรือใช้ `bpf_loop`)
- *ตรวจสอบ*: สร้างไฟล์ทดสอบใน `lab-files/` แล้วรัน audit mode ต้องรายงาน `SECRET.txt`, `Secret.md`, `server.pem` และไม่รายงาน `public.txt` ส่วน `secretary.txt` ให้ตัดสินใจเองว่าควร match หรือไม่ พร้อมอธิบายเหตุผล (trade-off ระหว่าง false positive กับ false negative)

### ระดับปานกลาง
**7.3 เปิด BPF LSM ใน VM แล้วทดสอบ enforce**: ทำตามหัวข้อ 1.3 ใน VM (เช่น Multipass/QEMU) แล้วรันขั้นตอนที่ 4 ใน enforce mode
- *ส่งงาน*: `cat /proc/cmdline`, `cat /sys/kernel/security/lsm` และ output จริงของ guard + terminal ผู้ใช้
- *ตรวจสอบ*: `cat lab-files/secret.txt` และ `cat lab-files/backup.txt` ได้ `Operation not permitted`, `cat lab-files/notes.txt` **อ่านได้** (พิสูจน์ bypass ในหัวข้อ 6 ข้อ 1) และ `python3 -c "import secrets"` ล้มเหลว (พิสูจน์ false positive)

**7.4 ปิดช่อง rename**: เพิ่ม `SEC("lsm/path_rename")` (ต้องใช้ `CONFIG_SECURITY_PATH`; ตรวจด้วย `grep CONFIG_SECURITY_PATH /boot/config-$(uname -r)`) หรือ `lsm/inode_rename` ที่ปฏิเสธการ rename ไฟล์ที่อยู่ใน `protected_inodes` หรือชื่อขึ้นต้นด้วย `secret` สำหรับ non-root พร้อม fentry fallback สำหรับ audit
- *ตรวจสอบ*: audit mode ต้องเห็น alert เมื่อ `mv lab-files/secret.txt lab-files/x`; enforce mode (ใน VM) ต้องได้ `Operation not permitted`

### ระดับท้าทาย
**7.5 Policy ตาม full path ด้วย `bpf_d_path`**: เพิ่ม map แบบ `BPF_MAP_TYPE_LPM_TRIE` หรือ hash ของ path prefix (เช่น `/etc/ssl/private/`) แล้วตัดสินใจจาก path ที่ได้จาก `bpf_d_path()` วิเคราะห์ว่าวิธีนี้หลบได้อย่างไร (bind mount, mount namespace ของ container, `chroot`, path ยาวเกิน buffer) เทียบกับกฎ inode
- *ส่งงาน*: โค้ด + ตารางเปรียบเทียบ name / inode / path ด้าน correctness, performance, ความสามารถในการหลบ
- *ตรวจสอบ*: `sudo mount --bind lab-files /mnt/x` (ใน VM) แล้วเปิดผ่าน `/mnt/x/...` -- อธิบายผลที่เห็น

**7.6 ป้องกันตัวเอง (Self-protection)**: pin link และ maps ไว้ใน `/sys/fs/bpf/week10/` เพื่อให้ policy อยู่ต่อแม้ agent ถูก kill และเพิ่ม `SEC("lsm/bpf")` ที่ปฏิเสธ `BPF_MAP_UPDATE_ELEM`/`BPF_MAP_DELETE_ELEM` ต่อ map ของเรา จาก process ที่ไม่ใช่ agent (เปรียบเทียบ map id หรือใช้ `bpf_map` hook)
- *ตรวจสอบ*: ใน VM ที่เปิด bpf LSM, `sudo kill <agent>` แล้ว policy ยังทำงาน และ `sudo bpftool map update id <id> ...` ต้องล้มเหลว อธิบายว่าทำไม root ยังมีทางหลบ (เช่น reboot ด้วย cmdline อื่น, โหลด kernel module) และ kernel lockdown ช่วยได้แค่ไหน
