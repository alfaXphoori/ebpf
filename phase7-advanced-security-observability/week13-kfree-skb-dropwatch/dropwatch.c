//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * Event structure sent via BPF Ring Buffer to User Space
 */
struct drop_event {
    __u32 pid;
    __u32 reason;
    __u64 location;
    __u16 protocol;
    char comm[TASK_COMM_LEN];
};

/*
 * BPF Ring Buffer for high-speed MPSC streaming of dropped packet telemetry
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB buffer */
} drop_events SEC(".maps");

/*
 * BPF Hash Map tracking cumulative drop count per drop reason
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* enum skb_drop_reason */
    __type(value, __u64); /* count */
} drop_reason_stats SEC(".maps");

/*
 * Tracepoint arguments structure for tracepoint/skb/kfree_skb
 */
struct kfree_skb_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    void *skbaddr;
    void *location;
    void *rx_sk;
    unsigned short protocol;
    unsigned int reason;
};

SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct kfree_skb_args *ctx)
{
    __u32 reason = ctx->reason;

    /* Filter out drops without reason or reason <= 1 (NOT_SPECIFIED) if desired */
    if (reason <= 1) {
        return 0;
    }

    /* Update cumulative drop statistics in BPF Hash Map */
    __u64 *count = bpf_map_lookup_elem(&drop_reason_stats, &reason);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&drop_reason_stats, &reason, &init_val, BPF_ANY);
    }

    /* Reserve slot in ring buffer */
    struct drop_event *event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->reason = reason;
    event->location = (__u64)ctx->location;
    event->protocol = ctx->protocol;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
