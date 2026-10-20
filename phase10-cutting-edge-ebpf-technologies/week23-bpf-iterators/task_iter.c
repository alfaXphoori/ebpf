//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * BPF Iterator: iter/task
 * Traverses kernel task_struct list directly in kernel space,
 * formatting process telemetry into a seq_file stream.
 */
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;

    if (!task) {
        return 0;
    }

    /* Skip kernel threads (task->mm == NULL) to focus on user processes */
    if (!task->mm) {
        return 0;
    }

    __u32 pid = task->tgid;
    __u32 uid = 0;

    /* Read task real_cred UID */
    if (task->real_cred) {
        uid = task->real_cred->uid.val;
    }

    /* Read VM size in pages (total_vm * 4KB = VM size) */
    unsigned long vm_size_kb = 0;
    if (task->mm) {
        vm_size_kb = task->mm->total_vm << (12 - 10);
    }

    /* Print row to iterator stream */
    BPF_SEQ_PRINTF(seq, "%-8d %-8d %-10lu %-16s\n", pid, uid, vm_size_kb, task->comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
