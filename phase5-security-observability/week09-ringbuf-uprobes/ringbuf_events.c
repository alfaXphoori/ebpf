// +build ignore

#include <linux/types.h>
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Event Types */
#define EVENT_TYPE_EXECVE        1
#define EVENT_TYPE_TLS_PLAINTEXT 2

/* Security Event Payload structure sent over Ring Buffer */
struct sec_event {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    __u8  event_type;
    __u8  pad[3];
    __u32 data_len;
    char  comm[16];
    char  payload[128];
};

/* BPF_MAP_TYPE_RINGBUF: Shared multi-producer single-consumer ring buffer (16 MB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

/* Format for tracepoint/syscalls/sys_enter_execve */
struct trace_entry {
    short unsigned int type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter_execve {
    struct trace_entry ent;
    long int id;
    unsigned long args[6]; /* args[0] = filename, args[1] = argv, args[2] = envp */
    char __data[0];
};

/* Architecture register accessor fallbacks if not defined by bpf_tracing.h */
#if !defined(PT_REGS_PARM2)
#if defined(__TARGET_ARCH_x86)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#elif defined(__TARGET_ARCH_arm64)
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#else
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#endif
#endif

/* 1. Tracepoint Probe: Intercept process execution (sys_enter_execve) */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter_execve *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u64 ts_ns = bpf_ktime_get_ns();

    /* Reserve space in Ring Buffer (Zero-Copy Allocation) */
    struct sec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; /* Ring buffer is full; drop event gracefully */
    }

    e->pid = pid;
    e->uid = uid;
    e->ts_ns = ts_ns;
    e->event_type = EVENT_TYPE_EXECVE;
    e->pad[0] = 0;
    e->pad[1] = 0;
    e->pad[2] = 0;
    e->data_len = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* args[0] holds user-space pointer to filename */
    const char *filename_ptr = (const char *)ctx->args[0];
    long len = bpf_probe_read_user_str(e->payload, sizeof(e->payload), filename_ptr);
    if (len > 0) {
        e->data_len = (__u32)len;
    } else {
        e->payload[0] = '\0';
        e->data_len = 0;
    }

    /* Submit reserved record to user-space */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 2. Uprobe: Intercept OpenSSL SSL_write(void *ssl, const void *buf, int num) */
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0 || !buf) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u64 ts_ns = bpf_ktime_get_ns();

    /* Reserve record in Ring Buffer */
    struct sec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->uid = uid;
    e->ts_ns = ts_ns;
    e->event_type = EVENT_TYPE_TLS_PLAINTEXT;
    e->pad[0] = 0;
    e->pad[1] = 0;
    e->pad[2] = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Bound payload size strictly to avoid buffer overflow and satisfy eBPF verifier */
    __u32 copy_len = (__u32)num;
    if (copy_len > 127) {
        copy_len = 127;
    }
    copy_len &= 0x7F;
    e->data_len = copy_len;

    __builtin_memset(e->payload, 0, sizeof(e->payload));
    if (copy_len > 0) {
        bpf_probe_read_user(e->payload, copy_len, buf);
    }

    /* Submit to user-space */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
