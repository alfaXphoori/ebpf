//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * Audit event sent over RingBuffer whenever sys_bpf() is invoked
 */
struct bpf_audit_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u32 cmd;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB */
} bpf_audit_events SEC(".maps");

struct trace_bpf_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    int cmd;
    union bpf_attr *uattr;
    unsigned int size;
};

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_call(struct trace_bpf_args *ctx)
{
    struct bpf_audit_event *event = bpf_ringbuf_reserve(&bpf_audit_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->ts_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->cmd = ctx->cmd;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
