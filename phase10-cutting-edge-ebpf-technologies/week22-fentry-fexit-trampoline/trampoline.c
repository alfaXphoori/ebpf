//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * Event structure sent over Ring Buffer
 */
struct fexit_event {
    __u64 duration_ns;
    __u32 pid;
    __s32 ret;
    char comm[TASK_COMM_LEN];
    char filename[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB */
} fexit_events SEC(".maps");

/*
 * Hash map storing entry timestamp
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} start_map SEC(".maps");

/*
 * BPF Trampoline fentry: entry hook ของ do_sys_openat2
 * เคอร์เนล patch จุด ftrace (nop 5 ไบต์) ต้นฟังก์ชันให้ "call" ไปยัง trampoline ที่ JIT สร้างขึ้น
 * ไม่ใช่ "zero overhead": วัดจริงบน Linux 7.0 ด้วย bench/run_bench.sh ได้ระดับหลายสิบ ns
 * ต่อการเรียก (รวมเวลารันตัวโปรแกรม BPF เอง ~20 ns) ดูวิธีวัดและข้อควรระวังใน README
 */
SEC("fentry/do_sys_openat2")
int BPF_PROG(trace_openat2_entry, int dfd, const char *filename, struct open_how *how)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_map, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

/*
 * BPF Trampoline fexit: return hook ของ do_sys_openat2
 * ได้รับทั้งอาร์กิวเมนต์เดิมทุกตัว + ค่า return เป็นพารามิเตอร์ตัวสุดท้าย
 * ชนิดของ ret ต้องตรงกับ BTF ของเคอร์เนล: บน Linux 7.0 คือ
 *   static int do_sys_openat2(int dfd, const char __user *filename, struct open_how *how);
 * (ตรวจด้วย: sudo bpftrace -lv 'fexit:do_sys_openat2' -> int retval)
 */
SEC("fexit/do_sys_openat2")
int BPF_PROG(trace_openat2_exit, int dfd, const char *filename, struct open_how *how, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_ts = bpf_map_lookup_elem(&start_map, &pid_tgid);
    if (!start_ts) {
        return 0;
    }

    __u64 duration_ns = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&start_map, &pid_tgid);

    struct fexit_event *e = bpf_ringbuf_reserve(&fexit_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->duration_ns = duration_ns;
    e->pid = pid_tgid >> 32;
    e->ret = ret;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
