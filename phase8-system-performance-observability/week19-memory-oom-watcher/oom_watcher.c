//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * OOM Alert Event structure
 */
struct oom_alert {
    __u64 ts_ns;
    __u64 total_vm_kb;
    __u64 anon_rss_kb;
    __u32 victim_pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB */
} oom_events SEC(".maps");

/*
 * Hash map counting page faults per process comm
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u64);
} page_fault_counts SEC(".maps");

struct oom_mark_victim_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int pid;
    unsigned int comm_loc;
    unsigned long total_vm;
    unsigned long anon_rss;
    unsigned long file_rss;
    unsigned long shmem_rss;
    unsigned int uid;
    unsigned long pgtables;
    short oom_score_adj;
};

struct page_fault_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
};

SEC("tracepoint/oom/mark_victim")
int on_oom_mark_victim(struct oom_mark_victim_args *ctx)
{
    struct oom_alert *alert = bpf_ringbuf_reserve(&oom_events, sizeof(*alert), 0);
    if (!alert) {
        return 0;
    }

    alert->ts_ns = bpf_ktime_get_ns();
    alert->victim_pid = ctx->pid;
    alert->uid = ctx->uid;
    alert->total_vm_kb = ctx->total_vm;
    alert->anon_rss_kb = ctx->anon_rss;

    /* Read process name from tracepoint data location */
    bpf_probe_read_kernel_str(&alert->comm, sizeof(alert->comm),
                             (void *)ctx + (ctx->comm_loc & 0xffff));

    bpf_ringbuf_submit(alert, 0);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int on_user_page_fault(struct page_fault_args *ctx)
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    __u64 *val = bpf_map_lookup_elem(&page_fault_counts, &comm);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&page_fault_counts, &comm, &one, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
