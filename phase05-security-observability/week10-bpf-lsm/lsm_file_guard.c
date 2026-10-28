//go:build ignore
// +build ignore

/*
 * CO-RE: ใช้ vmlinux.h (สร้างจาก BTF ของเคอร์เนลด้วย bpftool, อยู่ที่ repo root)
 * แทนการประกาศ struct file / dentry / inode เอง และห้าม include UAPI header
 * (linux/...h) ปนกับ vmlinux.h เพราะ type จะชนกัน ค่าคงที่ที่ต้องใช้จึง #define เอง
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* BPF LSM ต้องใช้ GPL-compatible license (Dual BSD/GPL ผ่าน) */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef EPERM
#define EPERM 1 /* include/uapi/asm-generic/errno-base.h: Operation not permitted */
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define PATH_LEN 256

/* เหตุผลที่ตรงกฎ (match reason) */
#define MATCH_NAME  1 /* basename ขึ้นต้นด้วย "secret" */
#define MATCH_INODE 2 /* (dev, ino) อยู่ใน protected_inodes map */

/* Alert structure sent to User Space upon blocked file access */
struct lsm_alert {
    __u64 ino;
    __u32 dev;
    __u32 pid;
    __u32 uid;
    __s32 ret;    /* ค่าที่คืนให้เคอร์เนล: -EPERM (-1) = block, 0 = audit only */
    __u32 reason; /* MATCH_NAME / MATCH_INODE */
    __u32 pad;
    char  comm[TASK_COMM_LEN];
    char  path[PATH_LEN]; /* full path จาก bpf_d_path() */
};

/* Ring Buffer for streaming security alerts (1 MB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MB */
} lsm_events SEC(".maps");

/* Policy configuration map:
 * Key 0: Enforce mode
 *   0 = Enforce only non-root users (UID != 0 blocked)
 *   1 = Enforce all users including root (Block everyone)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} policy_map SEC(".maps");

/*
 * Inode-based policy: key = (s_dev ของ superblock, inode number)
 * ผูกกฎกับ "ตัวไฟล์" ไม่ใช่ "ชื่อไฟล์" -> hardlink / rename / symlink ไม่ทำให้หลุด
 * user space (main.go) เติมค่าจาก stat() ของไฟล์ที่ระบุด้วย -protect
 */
struct inode_key {
    __u64 ino;
    __u32 dev;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
} protected_inodes SEC(".maps");

/*
 * ตัดสินใจว่าไฟล์นี้ตรงกฎหรือไม่ (ไม่สนใจ UID) คืนค่า MATCH_* หรือ 0
 * ทุกการอ่าน kernel struct ใช้ BPF_CORE_READ() เพื่อให้ offset ถูก relocate
 * ตาม BTF ของเคอร์เนลที่รันจริง (CO-RE)
 */
static __always_inline __u32 match_file(struct file *file, struct inode_key *key)
{
    key->ino = BPF_CORE_READ(file, f_inode, i_ino);
    key->dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    key->pad = 0;

    /* 1) Inode match (แข็งแรงกว่า) */
    if (bpf_map_lookup_elem(&protected_inodes, key)) {
        return MATCH_INODE;
    }

    /* 2) Basename prefix match "secret*" (ตัวอย่างดั้งเดิม: ง่ายแต่หลบได้ ดู README) */
    const unsigned char *name_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!name_ptr) {
        return 0;
    }

    char fname[8] = {};
    long str_len = bpf_probe_read_kernel_str(fname, sizeof(fname), name_ptr);
    if (str_len < 7) {
        /* สั้นกว่า "secret" + '\0' -> ไม่ตรง */
        return 0;
    }

    if (fname[0] == 's' && fname[1] == 'e' && fname[2] == 'c' &&
        fname[3] == 'r' && fname[4] == 'e' && fname[5] == 't') {
        return MATCH_NAME;
    }
    return 0;
}

/*
 * ส่วนร่วมของทั้ง enforce (LSM) และ audit (fentry):
 * คืนค่า -EPERM ถ้าควร block, 0 ถ้าปล่อยผ่าน และส่ง alert เมื่อตรงกฎ
 */
static __always_inline int check_file_open(struct file *file, int enforce)
{
    struct inode_key key = {};
    __u32 reason = match_file(file, &key);
    if (!reason) {
        return 0;
    }

    /* bpf_get_current_uid_gid(): 32 บิตล่าง = real UID ใน init user namespace */
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    /* Read policy setting (default: 0 = block non-root only) */
    __u32 policy_key = 0;
    __u32 *enforce_mode = bpf_map_lookup_elem(&policy_map, &policy_key);
    __u32 block_all = enforce_mode ? *enforce_mode : 0;

    /* If policy is block_non_root (0) and UID is root (0), allow access */
    if (block_all == 0 && uid == 0) {
        return 0;
    }

    int ret = enforce ? -EPERM : 0;

    /* Access Denied (หรือ would-deny ในโหมด audit): Reserve alert in ring buffer */
    struct lsm_alert *alert = bpf_ringbuf_reserve(&lsm_events, sizeof(*alert), 0);
    if (alert) {
        alert->ino = key.ino;
        alert->dev = key.dev;
        alert->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        alert->uid = uid;
        alert->ret = ret;
        alert->reason = reason;
        alert->pad = 0;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        /*
         * bpf_d_path() คืน full path (ตาม mount namespace ของ caller) เรียกได้เฉพาะ
         * hook ที่อยู่ใน allowlist ของเคอร์เนล: security_file_open (fentry) และ
         * LSM hook file_open ผ่านเงื่อนไขนี้ (ตรวจแล้วว่า verifier ยอมรับบน Linux 7.0)
         */
        /* f_path ประกาศเป็น const ใน struct file ของเคอร์เนลใหม่ จึงต้อง cast */
        if (bpf_d_path((struct path *)&file->f_path, alert->path, sizeof(alert->path)) < 0) {
            alert->path[0] = '\0';
        }
        bpf_ringbuf_submit(alert, 0);
    }

    return ret;
}

/*
 * BPF LSM Hook: file_open (ENFORCE)
 * ถูกเรียกแบบ synchronous จาก security_file_open() ภายใน do_dentry_open()
 * ระหว่าง open()/openat() หลัง path lookup และ DAC permission check ผ่านแล้ว
 * แต่ก่อนที่ fd จะถูกคืนให้ process
 *
 * ทำงานจริงก็ต่อเมื่อ "bpf" อยู่ใน /sys/kernel/security/lsm เท่านั้น
 */
SEC("lsm/file_open")
int BPF_PROG(restrict_secret_files, struct file *file)
{
    /*
     * การคืนค่าลบ (-errno) จาก LSM hook ทำให้ syscall ล้มเหลวด้วย errno นั้น
     * -EPERM (= -1) -> open() คืน -1 และ errno = EPERM ("Operation not permitted")
     * เขียนเป็น -EPERM ชัดเจนแทน -1 เพื่อให้อ่านรู้เจตนา (ค่าตัวเลขเท่ากัน)
     */
    return check_file_open(file, 1);
}

/*
 * AUDIT fallback: fentry บน security_file_open()
 * ใช้เมื่อเคอร์เนลไม่ได้เปิด BPF LSM (เช่น Ubuntu ค่าเริ่มต้น) -- เห็น event
 * เดียวกันทุกอย่าง แต่ fentry "เปลี่ยนค่าที่ฟังก์ชันคืน" ไม่ได้ จึง block ไม่ได้
 */
SEC("fentry/security_file_open")
int BPF_PROG(audit_secret_files, struct file *file)
{
    check_file_open(file, 0);
    return 0;
}
