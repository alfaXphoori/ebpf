# Week 10: BPF LSM Inline Security & Policy Enforcement

คู่มือการศึกษาเชิงลึกเกี่ยวกับการบังคับใช้นโยบายความปลอดภัยของระบบปฏิบัติการ Linux ในระดับ Kernel ด้วย **BPF LSM (Linux Security Modules)** เพื่อการป้องกันการเข้าถึงไฟล์สำคัญแบบ Synchronous Inline Blocking (`-EPERM`) โดยไม่มีปัญหา TOCTOU Race Condition

---

## 1. ทฤษฎีเชิงลึก (Deep-Dive Theory)

### 1.1 สถาปัตยกรรม Linux Security Modules (LSM)
Linux Security Modules (LSM) คือเฟรมเวิร์กของ Linux Kernel ที่ถูกออกแบบขึ้นตั้งแต่ Linux 2.6 เพื่อให้ระบบสามารถบังคับใช้นโยบายสิทธิ์แบบ **Mandatory Access Control (MAC)** ควบคู่ไปกับ Discretionary Access Control (DAC: สิทธิ์ `rwxrwxrwx` ปกติ)

โมดูลความปลอดภัยดั้งเดิมเช่น SELinux, AppArmor, Smack, และ Tomoyo ล้วนถูกเขียนเป็นโมดูล C ภายในเคอร์เนล ซึ่งการจะเพิ่มกฎหรือเปลี่ยนแปลงพฤติกรรมจำเป็นต้องคอมไพล์เคอร์เนลใหม่หรือใช้ไวยากรณ์เฉพาะของโมดูลนั้นๆ

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
|  [ Linux DAC Check: สิทธิ์ rwx ของ user/group ]                           |
|        | ผ่าน DAC                                                       |
|        v                                                                |
|  [ VFS: Virtual File System Layer ]                                     |
|        |                                                                |
|        v                                                                |
|  [ security_file_open() Hook ]                                          |
|        |                                                                |
|        +---> SELinux / AppArmor Hook                                    |
|        +---> BPF LSM Hook: restrict_secret_files(file)                  |
|                 |                                                       |
|                 |-- คืนค่า 0      --> อนุญาต ให้เปิดไฟล์ต่อไป               |
|                 \-- คืนค่า -EPERM --> หยุดทันที คืนค่า Operation not permitted |
+-------------------------------------------------------------------------+
```

### 1.2 ทำไม BPF LSM ถึงเหนือกว่า Kprobes / Tracepoints ในงาน Security
ก่อนหน้าที่มี BPF LSM นักพัฒนาความปลอดภัยมักใช้ Kprobes หรือ Tracepoints เช่น `sys_enter_openat` ในการตรวจสอบพฤติกรรม แต่พบข้อจำกัดร้ายแรงในเชิงการป้องกัน (Prevention):

1. **ปัญหา TOCTOU (Time-of-Check to Time-of-Use)**:
   - Kprobe หรือ Tracepoint เป็นเพียงการ **Observe (เฝ้าสังเกต)** แบบ Asynchronous
   - ถึงแม้ eBPF จะตรวจพบว่าโปรเซสกำลังเปิดไฟล์อันตราย แต่โปรแกรม eBPF ภายใต้ Kprobe ทั่วไป **ไม่สามารถสั่งปฏิเสธหรือคืนค่ารหัสผิดพลาดให้กับเคอร์เนลได้**
   - ผู้โจมตีสามารถสลับไฟล์ (Symlink race / Path switching) ระหว่างจังหวะที่โพรบทำงานกับจังหวะที่เคอร์เนลอ่านไฟล์จริงได้สำเร็จ
2. **Synchronous Inline Decision**:
   - BPF LSM (`CONFIG_BPF_LSM=y`) ทำงานอยู่บนจุดตรวจสอบความปลอดภัยของเคอร์เนลโดยตรง
   - เมื่อ BPF LSM คืนค่าติดลบ เช่น `-1` (`-EPERM` หรือ Operation not permitted) เคอร์เนลจะ **ยกเลิกคำสั่ง System call นั้นทันที** โดยที่กระบวนการเปิดไฟล์ยังไม่เสร็จสมบูรณ์ และไม่มี File Descriptor ใดๆ ถูกส่งคืนให้แก่ User space

### 1.3 การเปิดใช้งาน BPF LSM ในเคอร์เนล
BPF LSM บรรจุเข้ามาตั้งแต่ Linux Kernel 5.7 ขึ้นไป โดยเคอร์เนลต้องเปิดใช้งานออปชัน `CONFIG_BPF_LSM=y` และต้องเปิดใช้งานใน Linux Boot Parameters

สามารถตรวจสอบได้ด้วยคำสั่ง:
```bash
cat /sys/kernel/security/lsm
```
หากผลลัพธ์มีคำว่า `bpf` (เช่น `lockdown,capability,landlock,yama,apparmor,bpf`) แสดงว่าพร้อมใช้งาน

หากยังไม่มี `bpf` ให้ทำการแก้ไข GRUB:
```bash
sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf /' /etc/default/grub
sudo update-grub
sudo reboot
```

---

## 2. อธิบายโค้ดทีละบรรทัด (Line-by-Line Code Breakdown)

### 2.1 eBPF C LSM Program (`lsm_file_guard.c`)

```c
struct lsm_alert {
    __u32 pid;
    __u32 uid;
    char  comm[16];
    char  filename[64];
    __s32 action; /* -1 for -EPERM (Blocked) */
};
```
- **บรรทัด 11–17**: โครงสร้างบันทึกเหตุการณ์แจ้งเตือนความปลอดภัย เพื่อส่งต่อไปยัง Ring Buffer ให้ฝั่ง User-space รับทราบว่าโปรเซสใดถูกสกัดกั้น

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MB */
} lsm_events SEC(".maps");
```
- **บรรทัด 20–23**: Ring Buffer ขนาด 1MB สำหรับสตรีมข้อมูล Alert ไปยัง User Space แบบ Real-time

```c
SEC("lsm/file_open")
int BPF_PROG(restrict_secret_files, struct file *file)
```
- **บรรทัด 42–43**: ประกาศฟังก์ชัน eBPF Hook เข้ากับ LSM Hook ที่ชื่อ `file_open` โดยใช้ Macro `BPF_PROG` ซึ่งช่วยแปลง Argument จากเคอร์เนลให้อัตโนมัติ

```c
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
```
- **บรรทัด 50–56**: ดึงข้อมูล Directory Entry (`dentry`) และพอยน์เตอร์ชื่อไฟล์ (`d_name.name`) จากโครงสร้าง `struct file` ของเคอร์เนลผ่าน Macro `BPF_CORE_READ` ซึ่งรองรับ CO-RE (Compile Once – Run Everywhere) ย้าย Offset ตามเวอร์ชันเคอร์เนลโดยอัตโนมัติ

```c
    char fname[64] = {0};
    long str_len = bpf_probe_read_kernel_str(fname, sizeof(fname), name_ptr);
```
- **บรรทัด 58–59**: คัดลอก String ชื่อไฟล์จาก Kernel Space เข้าสู่ Local Buffer `fname` ขนาด 64 ไบต์อย่างปลอดภัย

```c
    if (fname[0] == 's' &&
        fname[1] == 'e' &&
        fname[2] == 'c' &&
        fname[3] == 'r' &&
        fname[4] == 'e' &&
        fname[5] == 't') {
```
- **บรรทัด 66–71**: ตรวจสอบ Prefix ของชื่อไฟล์ว่าขึ้นต้นด้วยคำว่า `"secret"` หรือไม่ โดยหลีกเลี่ยงการใช้ `strcmp` ขนาดยาวที่อาจทำให้ eBPF Verifier ปฏิเสธ

```c
        if (block_all == 0 && uid == 0) {
            return 0; /* root bypass */
        }
```
- **บรรทัด 87–89**: อ่านค่านโยบายจาก `policy_map` หากตั้งไว้ให้ป้องกันเฉพาะผู้ใช้ทั่วไป แต่ผู้ที่เรียกใช้คือ root (`uid == 0`) จะอนุญาตให้ผ่านได้

```c
        struct lsm_alert *alert = bpf_ringbuf_reserve(&lsm_events, sizeof(*alert), 0);
        if (alert) {
            ...
            bpf_ringbuf_submit(alert, 0);
        }
        return -1; /* -EPERM */
```
- **บรรทัด 92–108**: จองหน่วยความจำใน Ring Buffer เพื่อบันทึกแจ้งเตือน และ **คืนค่า `-1` (`-EPERM`)** ให้กับ VFS Layer ของเคอร์เนลเพื่อปฏิเสธการเปิดไฟล์ทันที!

---

### 2.2 Go Control Plane (`main.go`)

```go
func checkLSMStatus() {
    content, err := os.ReadFile("/sys/kernel/security/lsm")
    ...
}
```
- **บรรทัด 27–40**: ฟังก์ชันตรวจสอบสถานะของเคอร์เนลว่าเปิดใช้งาน BPF LSM ไว้หรือไม่ หากไม่พบ จะพิมพ์คำแนะนำการตั้งค่า GRUB ให้แก่ผู้ใช้อย่างชัดเจน

```go
objs.PolicyMap.Put(&policyKey, &policyVal)
```
- **บรรทัด 69–73**: อัปเดต Map ค่านโยบายแบบ Dynamic โดยสามารถเลือกบล็อกเฉพาะ Non-Root หรือบล็อกทุกคนรวมถึง Root ผ่าน Flag `-block-all`

```go
lsmLink, err := link.AttachLSM(link.LSMOptions{
    Program: objs.RestrictSecretFiles,
})
```
- **บรรทัด 76–81**: สั่ง Attach BPF LSM Program เข้ากับเคอร์เนล ซึ่งจะเริ่มมีผลการบังคับใช้นโยบายทันทีทั่วทั้งเครื่อง

```go
rd, err := ringbuf.NewReader(objs.LsmEvents)
for {
    record, err := rd.Read()
    ...
}
```
- **บรรทัด 87–125**: อ่าน Security Alert จาก Ring Buffer และแสดงผลบนหน้าจอเมื่อมีความพยายามเข้าถึงไฟล์ที่ถูกบล็อก

---

## 3. ขั้นตอนการรันและทดสอบ (Step-by-Step Execution & Verification)

### ขั้นตอนที่ 1: ตรวจสอบและคอมไพล์โปรแกรม
```bash
# คอมไพล์ BPF Bytecode และสร้าง Go Executable
make generate
make build
```

### ขั้นตอนที่ 2: สร้างไฟล์ทดสอบ
```bash
echo "This is public data" > normal.txt
echo "SUPER_SECRET_KEY=ABC123XYZ" > secret_passwords.txt
echo "INTERNAL_TOKEN=99999" > secret_token.json
```

### ขั้นตอนที่ 3: รันโปรแกรม LSM Guard
```bash
# รันโปรแกรมด้วยสิทธิ์ root
sudo ./bin/lsm_file_guard
```
ผลลัพธ์บนหน้าจอ:
```text
[INFO] Active Linux Security Modules: lockdown,capability,landlock,yama,apparmor,bpf
[POLICY] Enforce Mode: BLOCK NON-ROOT (root UID 0 allowed)
[INFO] Successfully attached BPF LSM hook to 'file_open'!
[INFO] Watching for unauthorized attempts to access 'secret*' files...
SECURITY_ACTION    PID     UID    COMM             FILENAME             RESULT
-------------------------------------------------------------------------------------
```

### ขั้นตอนที่ 4: ทดสอบการอ่านไฟล์ด้วย User ทั่วไป (UID != 0)
เปิดหน้าต่าง Terminal ใหม่ในฐานะ User ธรรมดา:
```bash
# 1. ทดสอบอ่านไฟล์ปกติ -> อ่านได้ตามปกติ
cat normal.txt
# ผลลัพธ์: This is public data

# 2. ทดสอบอ่านไฟล์ secret -> ถูกสกัดกั้นทันที!
cat secret_passwords.txt
# ผลลัพธ์ในเทอร์มินัล: cat: secret_passwords.txt: Operation not permitted
```

### ขั้นตอนที่ 5: ตรวจสอบการแจ้งเตือน Real-time Alert
ในหน้าต่างของ `lsm_file_guard` จะแสดงการตรวจจับพร้อมชื่อไฟล์และ Process ทันที:
```text
[BLOCKED -EPERM]   15402   1000   cat              secret_passwords.txt EPERM (Blocked)
```

### ขั้นตอนที่ 6: ทดสอบบล็อกทุกผู้ใช้รวมถึง Root
หากต้องการบังคับใช้นโยบายสูงสุดไม่ให้แม้แต่ Root เข้าถึงไฟล์ลับ:
```bash
sudo ./bin/lsm_file_guard -block-all
```
เมื่อผู้ใช้รัน `sudo cat secret_passwords.txt` ก็จะถูกปฏิเสธด้วย `Operation not permitted` เช่นเดียวกัน

---

## 4. Milestone Checklist

| หัวข้อที่ตรวจสอบ | รายละเอียดความถูกต้อง | สถานะ |
| :--- | :--- | :---: |
| **BPF LSM Support** | ตรวจสอบ `CONFIG_BPF_LSM=y` และการตั้งค่าใน `/sys/kernel/security/lsm` | [x] ผ่าน |
| **BTF / CO-RE Header** | ใช้งาน `vmlinux.h` และ Macro `BPF_CORE_READ` ถูกต้อง | [x] ผ่าน |
| **Inline Blocking Logic** | คืนค่า `-1` (`-EPERM`) เพื่อหยุด System Call โดยไม่มี TOCTOU Race | [x] ผ่าน |
| **Prefix Matching** | ตรวจสอบไฟล์ที่ขึ้นต้นด้วย `"secret"` อย่างรัดกุมผ่าน Verifier | [x] ผ่าน |
| **Policy Configuration** | มี `policy_map` ให้สลับโหมด Enforce All กับ Block Non-Root ได้ | [x] ผ่าน |
| **Real-time Ringbuf Alert** | สตรีมบันทึก Alert ข้อมูล PID, UID, COMM, FILENAME สู่ User-space | [x] ผ่าน |
