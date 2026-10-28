//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* bit ของ x86 page fault error_code (arch/x86/include/asm/trap_pf.h) */
#define X86_PF_WRITE (1UL << 1)

/* ค่า flags ที่บอก Userspace ว่าฟิลด์ใดมีจริงบนเคอร์เนลที่รันอยู่ */
#define OOM_HAS_RSS   (1U << 0) /* total_vm/anon_rss/file_rss/shmem_rss/pgtables */
#define OOM_HAS_UID   (1U << 1)
#define OOM_HAS_ADJ   (1U << 2) /* oom_score_adj */
#define OOM_HAS_COMM  (1U << 3) /* comm ของเหยื่ออ่านจาก tracepoint ได้ */

#define CGROUP_NAME_LEN 64

/*
 * OOM Alert Event structure (ส่งผ่าน Ring Buffer)
 */
struct oom_alert {
    __u64 ts_ns;
    __u64 total_vm_kb;
    __u64 anon_rss_kb;
    __u64 file_rss_kb;
    __u64 shmem_rss_kb;
    __u64 pgtables_kb;
    __u64 cgroup_id;      /* cgroup v2 ของ task ที่ "กระตุ้น" OOM (current) */
    __u32 victim_pid;
    __u32 uid;
    __u32 trigger_pid;    /* task ที่กำลังจองแรมแล้วเรียก OOM killer */
    __u32 flags;          /* OOM_HAS_* */
    __s16 oom_score_adj;
    __u16 pad[3];
    char comm[TASK_COMM_LEN];
    char trigger_comm[TASK_COMM_LEN];
    char cgroup_name[CGROUP_NAME_LEN]; /* ชื่อไดเรกทอรี cgroup v2 ชั้นสุดท้าย เช่น run-xxx.scope */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB */
} oom_events SEC(".maps");

/*
 * สถิติ Page Fault ต่อชื่อโปรเซส
 */
struct pf_stat {
    __u64 faults;
    __u64 write_faults;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, struct pf_stat);
} page_fault_counts SEC(".maps");

/*
 * CO-RE "flavor" ของ tracepoint context สำหรับ exceptions:page_fault_user
 * ชื่อหลัง "___" จะถูกตัดทิ้งตอน Relocation ทำให้โปรแกรมเดียวจับคู่ได้ทั้ง
 *   - trace_event_raw_x86_exceptions (เคอร์เนลรุ่นเก่า เช่น 6.8 ของ Ubuntu 24.04)
 *   - trace_event_raw_exceptions     (เคอร์เนลรุ่นใหม่ เช่น 7.0 ที่ใช้ทดสอบ)
 * preserve_access_index บอก clang ให้สร้าง CO-RE relocation ทุกครั้งที่อ้างฟิลด์
 */
struct trace_event_raw_x86_exceptions___old {
    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
} __attribute__((preserve_access_index));

struct trace_event_raw_exceptions___new {
    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
} __attribute__((preserve_access_index));

SEC("tracepoint/oom/mark_victim")
int on_oom_mark_victim(struct trace_event_raw_mark_victim *ctx)
{
    struct oom_alert *alert = bpf_ringbuf_reserve(&oom_events, sizeof(*alert), 0);
    if (!alert) {
        return 0;
    }
    __builtin_memset(alert, 0, sizeof(*alert));

    alert->ts_ns = bpf_ktime_get_ns();
    alert->victim_pid = ctx->pid;
    alert->trigger_pid = bpf_get_current_pid_tgid() >> 32;
    alert->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&alert->trigger_comm, sizeof(alert->trigger_comm));

    /*
     * อ่านชื่อ cgroup ตั้งแต่ในเคอร์เนล เพราะ transient scope อาจถูกลบทิ้ง
     * ก่อนที่ Userspace จะทันไปค้นหา path จาก cgroup id
     * task->cgroups->dfl_cgrp->kn->name ถูก Relocate ด้วย CO-RE ตาม BTF ของเคอร์เนลจริง
     */
    struct task_struct *task = bpf_get_current_task_btf();
    const char *cg_name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
    if (cg_name)
        bpf_probe_read_kernel_str(&alert->cgroup_name, sizeof(alert->cgroup_name), cg_name);

    /*
     * ฟิลด์ขยายของ mark_victim ถูกเพิ่มเข้ามาภายหลัง (เดิมมีแค่ pid)
     * bpf_core_field_exists() ถูกแก้เป็นค่าคงที่ 0/1 ตอนโหลด ตาม BTF ของเคอร์เนลจริง
     * กิ่งที่ไม่มีฟิลด์จะถูกตัดทิ้งโดยไม่ทำให้ Verifier ปฏิเสธ
     * หน่วยของ *_rss/total_vm/pgtables ใน tracepoint นี้คือ kB อยู่แล้ว
     */
    if (bpf_core_field_exists(ctx->total_vm)) {
        alert->total_vm_kb = ctx->total_vm;
        alert->anon_rss_kb = ctx->anon_rss;
        alert->file_rss_kb = ctx->file_rss;
        alert->shmem_rss_kb = ctx->shmem_rss;
        alert->pgtables_kb = ctx->pgtables;
        alert->flags |= OOM_HAS_RSS;
    }
    if (bpf_core_field_exists(ctx->uid)) {
        alert->uid = ctx->uid;
        alert->flags |= OOM_HAS_UID;
    }
    if (bpf_core_field_exists(ctx->oom_score_adj)) {
        alert->oom_score_adj = ctx->oom_score_adj;
        alert->flags |= OOM_HAS_ADJ;
    }
    if (bpf_core_field_exists(ctx->__data_loc_comm)) {
        /* __data_loc: 16 บิตล่าง = offset จากต้น record, 16 บิตบน = ความยาว */
        __u32 loc = ctx->__data_loc_comm;
        bpf_probe_read_kernel_str(&alert->comm, sizeof(alert->comm),
                                  (void *)ctx + (loc & 0xffff));
        alert->flags |= OOM_HAS_COMM;
    }

    bpf_ringbuf_submit(alert, 0);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int on_user_page_fault(void *ctx)
{
    unsigned long error_code = 0;

    /*
     * ใช้ BPF_CORE_READ (bpf_probe_read_kernel + CO-RE offset) แทนการอ่าน ctx ตรง ๆ
     * เพราะเมื่อมี 2 กิ่ง clang มักรวมการคำนวณ ctx + offset ไว้ใน register เดียว
     * แล้ว Verifier จะปฏิเสธด้วย "dereference of modified ctx ptr"
     */
    if (bpf_core_type_exists(struct trace_event_raw_exceptions___new)) {
        error_code = BPF_CORE_READ((struct trace_event_raw_exceptions___new *)ctx, error_code);
    } else if (bpf_core_type_exists(struct trace_event_raw_x86_exceptions___old)) {
        error_code = BPF_CORE_READ((struct trace_event_raw_x86_exceptions___old *)ctx, error_code);
    }

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    struct pf_stat *val = bpf_map_lookup_elem(&page_fault_counts, &comm);
    if (!val) {
        struct pf_stat zero = {};
        bpf_map_update_elem(&page_fault_counts, &comm, &zero, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&page_fault_counts, &comm);
        if (!val)
            return 0; /* map เต็ม */
    }
    __sync_fetch_and_add(&val->faults, 1);
    if (error_code & X86_PF_WRITE)
        __sync_fetch_and_add(&val->write_faults, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
