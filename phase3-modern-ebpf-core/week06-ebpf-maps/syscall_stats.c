#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Fallback definitions for BPF macros if compiling in environments with standalone headers
 */
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

/*
 * Struct representing per-process syscall statistics.
 * Explicitly aligned to match Go userspace struct layout:
 * - count: 8 bytes (offset 0)
 * - comm: 16 bytes (offset 8)
 * Total size: 24 bytes (8-byte aligned)
 */
struct proc_stat {
    __u64 count;
    char comm[16];
};

/*
 * BPF_MAP_TYPE_HASH: syscall_map
 * Hash table storing syscall frequencies indexed by process ID (PID).
 * Key: 32-bit unsigned integer (PID)
 * Value: struct proc_stat (invocation count + executable command name)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct proc_stat);
} syscall_map SEC(".maps");

/*
 * Tracepoint program attached to raw_syscalls/sys_enter
 * Triggers on every single system call executed by any user-space process on the host.
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int track_syscalls(void *ctx)
{
    /* Extract caller PID from upper 32 bits of 64-bit PID+TGID value */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    /* Look up the PID entry in the hash map */
    struct proc_stat *stat = bpf_map_lookup_elem(&syscall_map, &pid);
    if (stat) {
        /* Key already exists: atomically increment execution count */
        __sync_fetch_and_add(&stat->count, 1);
    } else {
        /* First time seeing this PID: initialize statistics */
        struct proc_stat init_stat = {};
        init_stat.count = 1;
        /* Retrieve the executable process name (up to 16 bytes, null-terminated) */
        bpf_get_current_comm(&init_stat.comm, sizeof(init_stat.comm));
        /* Insert the new entry into the hash map */
        bpf_map_update_elem(&syscall_map, &pid, &init_stat, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
