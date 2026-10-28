//go:build ignore
// +build ignore

/*
 * Week 15: Reverse Shell & Interactive Threat Detector (CO-RE)
 *
 * สัญญาณที่ใช้ (signals) ณ จังหวะ tracepoint sched/sched_process_exec:
 *   1. ชื่อโปรแกรม (comm) ตรงกับรายชื่อ shell / network tool แบบ "ตรงทุกตัวอักษร" (exact match)
 *   2. ชื่อ parent (real_parent->comm) ตรงกับรายชื่อ daemon / web service แบบ exact match
 *   3. stdin/stdout/stderr (fd 0/1/2) ของโปรเซสใหม่เป็น "network socket" (AF_INET/AF_INET6)
 *      -> สัญญาณนี้ไม่ขึ้นกับชื่อไฟล์ จึงจับกรณี `cp /bin/sh /tmp/x` ได้
 *      -> ไม่นับ AF_UNIX เพราะ Node.js/libuv, systemd ฯลฯ ใช้ unix socketpair เป็น stdio ตามปกติ
 *
 * รายชื่อทั้งหมดถูกเติมจาก User Space ลง BPF Hash Map (ปรับได้โดยไม่ต้องคอมไพล์ใหม่)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* vmlinux.h ไม่มี #define จาก <linux/stat.h> จึงต้องประกาศเอง */
#define S_IFMT   00170000
#define S_IFSOCK 0140000
#define AF_INET  2
#define AF_INET6 10

#define MAX_FILENAME_LEN 128

/* ค่าใน map watch_names */
#define NAME_SHELL   1
#define NAME_NETTOOL 2

/* bit flags ใน threat_alert.flags */
#define F_SHELL         (1 << 0) /* comm อยู่ในรายชื่อ shell */
#define F_NETTOOL       (1 << 1) /* comm อยู่ในรายชื่อ network tool (nc, socat, ...) */
#define F_DAEMON_PARENT (1 << 2) /* parent อยู่ในรายชื่อ daemon */
#define F_STDIN_SOCK    (1 << 3) /* fd 0 เป็น AF_INET/AF_INET6 socket */
#define F_STDOUT_SOCK   (1 << 4) /* fd 1 เป็น AF_INET/AF_INET6 socket */
#define F_STDERR_SOCK   (1 << 5) /* fd 2 เป็น AF_INET/AF_INET6 socket */

/*
 * Security Alert Struct streamed over BPF Ring Buffer
 */
struct threat_alert {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 flags;
    __u8 pad[3];
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

/*
 * BPF Ring Buffer for instant security event dispatch
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB */
} threat_events SEC(".maps");

/* key = comm 16 ไบต์ (เติม \0 ท้าย) -> NAME_SHELL / NAME_NETTOOL */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} watch_names SEC(".maps");

/* key = comm ของ parent ที่ "ไม่ควร" spawn shell (nginx, httpd, ...) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} daemon_names SEC(".maps");

/*
 * ตรวจว่า file descriptor หมายเลข fd ของ task เป็น network socket (IPv4/IPv6) หรือไม่
 *   task->files->fdt->fd[fd]->f_inode->i_mode          : เป็น socket inode (S_IFSOCK)?
 *   file->private_data (struct socket *)->sk->skc_family : AF_INET / AF_INET6?
 * อ่านผ่าน CO-RE ทุกขั้น จึงทนต่อการเปลี่ยน layout ของ struct ระหว่างเวอร์ชันเคอร์เนล
 */
static __always_inline int fd_is_inet_socket(struct task_struct *task, unsigned int fd)
{
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) {
        return 0;
    }
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return 0;
    }
    if (fd >= BPF_CORE_READ(fdt, max_fds)) {
        return 0;
    }
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    struct file *f = NULL;
    if (bpf_core_read(&f, sizeof(f), &fd_array[fd]) || !f) {
        return 0;
    }
    umode_t mode = BPF_CORE_READ(f, f_inode, i_mode);
    if ((mode & S_IFMT) != S_IFSOCK) {
        return 0;
    }
    /* สำหรับ socket file, private_data ชี้ไปยัง struct socket */
    struct socket *sock = (struct socket *)BPF_CORE_READ(f, private_data);
    if (!sock) {
        return 0;
    }
    __u16 family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    return family == AF_INET || family == AF_INET6;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec_threat(struct trace_event_raw_sched_process_exec *ctx)
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u8 flags = 0;
    __u8 *kind = bpf_map_lookup_elem(&watch_names, &comm);
    if (kind) {
        flags |= (*kind == NAME_SHELL) ? F_SHELL : F_NETTOOL;
    }
    if (fd_is_inet_socket(task, 0)) flags |= F_STDIN_SOCK;
    if (fd_is_inet_socket(task, 1)) flags |= F_STDOUT_SOCK;
    if (fd_is_inet_socket(task, 2)) flags |= F_STDERR_SOCK;

    /* ไม่ใช่โปรแกรมที่สนใจ และ stdio ไม่ใช่ network socket -> ไม่ต้องรายงาน */
    if (flags == 0) {
        return 0;
    }

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    char pcomm[TASK_COMM_LEN] = {};
    __u32 ppid = 0;
    if (parent) {
        bpf_core_read_str(&pcomm, sizeof(pcomm), &parent->comm);
        ppid = BPF_CORE_READ(parent, tgid);
    }
    if (bpf_map_lookup_elem(&daemon_names, &pcomm)) {
        flags |= F_DAEMON_PARENT;
    }

    struct threat_alert *alert = bpf_ringbuf_reserve(&threat_events, sizeof(*alert), 0);
    if (!alert) {
        return 0;
    }

    alert->ts_ns = bpf_ktime_get_ns();
    alert->pid = bpf_get_current_pid_tgid() >> 32;
    alert->ppid = ppid;
    alert->uid = (__u32)bpf_get_current_uid_gid();
    alert->flags = flags;
    __builtin_memset(alert->pad, 0, sizeof(alert->pad));
    __builtin_memcpy(alert->comm, comm, sizeof(alert->comm));
    __builtin_memcpy(alert->pcomm, pcomm, sizeof(alert->pcomm));

    /*
     * __data_loc_filename: 16 บิตล่าง = offset ของสตริงนับจากต้น ctx, 16 บิตบน = ความยาว
     * ได้ path เต็มของไฟล์ที่ถูก exec (เช่น /tmp/x) ซึ่งเชื่อถือได้มากกว่า comm
     */
    unsigned int off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(alert->filename, sizeof(alert->filename), (void *)ctx + off);

    bpf_ringbuf_submit(alert, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
