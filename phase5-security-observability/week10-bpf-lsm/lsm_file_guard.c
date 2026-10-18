// +build ignore

#include <linux/types.h>
#include <linux/bpf.h>

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef __u32 u32;
typedef __u64 u64;

/* Minimal CO-RE compatible struct definitions with preserve_access_index */

struct qstr {
    const unsigned char *name;
    unsigned int len;
} __attribute__((preserve_access_index));

struct dentry {
    struct qstr d_name;
    struct dentry *d_parent;
} __attribute__((preserve_access_index));

struct vfsmount {
    struct dentry *mnt_root;
} __attribute__((preserve_access_index));

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct inode {
    unsigned long i_ino;
    unsigned int i_mode;
    unsigned int i_uid;
    unsigned int i_gid;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    struct inode *f_inode;
    unsigned int f_flags;
    unsigned int f_mode;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Alert structure sent to User Space upon blocked file access */
struct lsm_alert {
    __u32 pid;
    __u32 uid;
    char  comm[16];
    char  filename[64];
    __s32 action; /* -1 for -EPERM (Blocked) */
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
 * BPF LSM Hook: file_open
 * Invoked synchronously inside the Linux kernel VFS security layer
 * when a process executes open() / openat() before file descriptors are assigned.
 */
SEC("lsm/file_open")
int BPF_PROG(restrict_secret_files, struct file *file)
{
    if (!file) {
        return 0;
    }

    /* Extract dentry and directory entry filename using CO-RE relocatable reads */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        return 0;
    }

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (!name_ptr) {
        return 0;
    }

    char fname[64] = {0};
    long str_len = bpf_probe_read_kernel_str(fname, sizeof(fname), name_ptr);
    if (str_len < 6) {
        /* Filename is shorter than "secret", allow immediately */
        return 0;
    }

    /* Check prefix matching: "secret" */
    if (fname[0] == 's' &&
        fname[1] == 'e' &&
        fname[2] == 'c' &&
        fname[3] == 'r' &&
        fname[4] == 'e' &&
        fname[5] == 't') {

        __u64 uid_gid = bpf_get_current_uid_gid();
        __u32 uid = (__u32)uid_gid;
        __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

        /* Read policy setting (default: 0 = block non-root only) */
        __u32 key = 0;
        __u32 *enforce_mode = bpf_map_lookup_elem(&policy_map, &key);
        __u32 block_all = 0;
        if (enforce_mode) {
            block_all = *enforce_mode;
        }

        /* If policy is block_non_root (0) and UID is root (0), allow access */
        if (block_all == 0 && uid == 0) {
            return 0;
        }

        /* Access Denied: Reserve alert in ring buffer */
        struct lsm_alert *alert = bpf_ringbuf_reserve(&lsm_events, sizeof(*alert), 0);
        if (alert) {
            alert->pid = pid;
            alert->uid = uid;
            alert->action = -1; /* -EPERM */
            bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
            __builtin_memcpy(alert->filename, fname, sizeof(alert->filename));
            bpf_ringbuf_submit(alert, 0);
        }

        /*
         * Returning a negative value (e.g. -1 for -EPERM) from an LSM hook
         * aborts the kernel system call synchronously, returning Operation Not Permitted
         * to the calling user-space application without any TOCTOU race conditions.
         */
        return -1; /* -EPERM */
    }

    return 0;
}
