//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Fallback definitions for BPF map macros if compiling in minimal environment
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
 * BPF_MAP_TYPE_ARRAY: exec_count
 * Single-element array (max_entries = 1) storing the global count of execve calls.
 * Key: 32-bit unsigned integer (index 0)
 * Value: 64-bit unsigned integer (cumulative count)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");

/*
 * Tracepoint program attached to sys_enter_execve
 * Triggered whenever any process in the system executes the execve() syscall.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    __u32 key = 0;
    __u64 *val;

    /* Look up the counter slot at index 0 */
    val = bpf_map_lookup_elem(&exec_count, &key);
    if (val) {
        /* Atomically increment the counter to prevent race conditions across CPUs */
        __sync_fetch_and_add(val, 1);
    }

    /* Read caller PID (upper 32 bits of 64-bit PID+TGID) and log to kernel trace pipe */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    bpf_printk("execve called by PID %d\n", pid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
