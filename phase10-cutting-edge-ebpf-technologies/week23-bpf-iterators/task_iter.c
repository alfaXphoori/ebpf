//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* PF_KTHREAD จาก include/linux/sched.h (macro ไม่อยู่ใน vmlinux.h เพราะ BTF เก็บแค่ type) */
#define PF_KTHREAD 0x00200000

/*
 * BPF Iterator: iter/task
 * เคอร์เนลเรียกโปรแกรมนี้ 1 ครั้งต่อ task_struct 1 ตัว (ทุก "thread" ในระบบ)
 * และเรียกปิดท้ายอีก 1 ครั้งด้วย ctx->task == NULL
 * ผลลัพธ์ที่ BPF_SEQ_PRINTF() เขียน จะไปอยู่ใน seq_file buffer ที่ userspace read() ได้
 */
SEC("iter/task")
int dump_task(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;

    /* seq_num == 0 คือการเรียกครั้งแรกของ iteration นี้: พิมพ์หัวตารางจากฝั่งเคอร์เนลเลย */
    if (ctx->meta->seq_num == 0) {
        BPF_SEQ_PRINTF(seq, "%-8s %-8s %-8s %-12s %-16s\n",
                       "PID", "UID", "THREADS", "VM_SIZE_KB", "COMM");
    }

    /* ครั้งสุดท้าย task == NULL (end of iteration) */
    if (!task) {
        return 0;
    }

    /*
     * iter/task เดินทุก thread ไม่ใช่ทุก process: โปรเซสที่มี 20 threads จะถูกเรียก 20 ครั้ง
     * กรองให้เหลือเฉพาะ thread group leader (pid == tgid) เพื่อได้ 1 แถวต่อ 1 โปรเซส แบบ `ps -e`
     */
    if (task->pid != task->tgid) {
        return 0;
    }

    /* ข้าม kernel threads (PF_KTHREAD) และ task ที่ไม่มี mm (เช่น zombie) */
    if ((task->flags & PF_KTHREAD) || !task->mm) {
        return 0;
    }

    __u32 pid = task->tgid;
    __u32 uid = task->real_cred->uid.val;       /* kuid (มุมมองของ init user namespace) */
    int nr_threads = task->signal->nr_threads;  /* จำนวน thread ใน thread group */

    /* total_vm นับเป็นหน้า (page); x86_64 ใช้หน้า 4 KiB => KiB = pages << (12 - 10) */
    unsigned long vm_size_kb = task->mm->total_vm << (12 - 10);

    /*
     * ข้อจำกัดของ BPF_SEQ_PRINTF: รับอาร์กิวเมนต์ได้ไม่เกิน 12 ตัว และ %s
     * จะถูกอ่านแบบปลอดภัย (probe read) จาก task->comm ในหน่วยความจำเคอร์เนล
     */
    BPF_SEQ_PRINTF(seq, "%-8u %-8u %-8d %-12lu %-16s\n",
                   pid, uid, nr_threads, vm_size_kb, task->comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
