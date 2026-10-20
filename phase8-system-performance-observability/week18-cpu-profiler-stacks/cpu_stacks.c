//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef BPF_F_FAST_STACK_CMP
#define BPF_F_FAST_STACK_CMP (1ULL << 9)
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif

struct stack_key {
    __u32 pid;
    __s32 kernel_stack_id;
    __s32 user_stack_id;
    char comm[TASK_COMM_LEN];
};

/*
 * BPF_MAP_TYPE_STACK_TRACE: Kernel-managed storage for unwound IP stacks
 */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64)); /* Kernel max depth is 127 */
    __uint(max_entries, 10000);
} stack_traces SEC(".maps");

/*
 * Hash map aggregating sample counts per unique call chain
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct stack_key);
    __type(value, __u64);
} stack_counts SEC(".maps");

struct sched_switch_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int on_sched_switch(struct sched_switch_args *ctx)
{
    /* Profile the process yielding CPU */
    __u32 pid = ctx->prev_pid;
    if (pid == 0) {
        return 0; // Skip kernel idle process
    }

    struct stack_key key = {};
    key.pid = pid;
    __builtin_memcpy(key.comm, ctx->prev_comm, sizeof(key.comm));

    /* Unwind kernel call stack */
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_FAST_STACK_CMP);

    /* Unwind user space call stack */
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

    __u64 *val = bpf_map_lookup_elem(&stack_counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&stack_counts, &key, &one, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
