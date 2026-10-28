//go:build ignore
// +build ignore

/*
 * Week 16: eBPF Integrity Auditor - CO-RE edition
 *
 * มี 2 hook ให้เลือก (main.go เลือกให้อัตโนมัติ):
 *   1) fentry/__sys_bpf  (หลัก)    : รันเฉพาะเมื่อมีการเรียก bpf() เท่านั้น, ไม่ขึ้นกับสถาปัตยกรรม,
 *                                    เห็นทั้ง syscall ปกติ, compat (32-bit) และผู้เรียกจากในเคอร์เนล
 *   2) tracepoint/raw_syscalls/sys_enter (สำรอง): ใช้เมื่อ __sys_bpf ไม่สามารถ trace ได้
 *                                    กรองด้วยหมายเลข syscall ของสถาปัตยกรรมนั้น (Go เป็นผู้ตั้งค่า)
 *
 * ประวัติบั๊ก:
 *   - เวอร์ชันแรกประกาศ struct ของ syscalls/sys_enter_bpf เอง และวาง `cmd` ไว้ที่ offset 12
 *     แต่ของจริงอยู่ที่ offset 16 (args[0]) จึงอ่านได้ 0 เสมอ (ทุก event กลายเป็น BPF_MAP_CREATE)
 *   - บน Linux 7.0.0-38 ของเครื่องทดลอง พบว่า tracepoint ตระกูล syscalls:sys_enter_* บางตัว
 *     (เช่น sys_enter_execve) ทำงานเฉพาะบน CPU 0 (ยังไม่ทราบสาเหตุ) จึงเลิกพึ่ง sys_enter_bpf
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef BPF_OBJ_NAME_LEN
#define BPF_OBJ_NAME_LEN 16
#endif

#define SRC_FENTRY 1 /* event มาจาก fentry/__sys_bpf */
#define SRC_RAW    2 /* event มาจาก raw_syscalls/sys_enter */

/*
 * Audit event sent over RingBuffer whenever bpf() is invoked (64 bytes, no implicit padding)
 */
struct bpf_audit_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u32 cmd;        /* enum bpf_cmd */
    __u32 prog_type;  /* enum bpf_prog_type (เฉพาะ BPF_PROG_LOAD) */
    char comm[TASK_COMM_LEN];
    char prog_name[BPF_OBJ_NAME_LEN]; /* เฉพาะ BPF_PROG_LOAD */
    __u8 source;      /* SRC_FENTRY หรือ SRC_RAW */
    __u8 from_kernel; /* 1 = attr อยู่ในหน่วยความจำเคอร์เนล (ผู้เรียกจากในเคอร์เนล เช่น light skeleton) */
    __u8 pad[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB */
} bpf_audit_events SEC(".maps");

/*
 * หมายเลข syscall ของ bpf() ต่างกันตามสถาปัตยกรรม (x86_64 = 321, arm64 = 280)
 * ค่านี้อยู่ใน .rodata และถูกเขียนทับจาก Go ด้วย unix.SYS_BPF ก่อนโหลด
 */
volatile const __u32 bpf_syscall_nr = 321;

static __always_inline void emit_event(__u32 cmd, union bpf_attr *attr, __u8 from_kernel, __u8 source)
{
    struct bpf_audit_event *event = bpf_ringbuf_reserve(&bpf_audit_events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->ts_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->cmd = cmd;
    event->prog_type = 0;
    event->source = source;
    event->from_kernel = from_kernel;
    __builtin_memset(event->prog_name, 0, sizeof(event->prog_name));
    __builtin_memset(event->pad, 0, sizeof(event->pad));
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    if (cmd == BPF_PROG_LOAD && attr) {
        /*
         * อ่าน union bpf_attr แบบ best-effort ก่อนที่ __sys_bpf จะ copy attr จริง
         * ข้อควรระวัง: ผู้เรียกแก้ค่าในหน่วยความจำของตัวเองระหว่างนั้นได้ (TOCTOU)
         * ใช้เพื่อแสดงผล/บันทึกเท่านั้น ห้ามใช้ตัดสินใจบล็อก
         */
        if (from_kernel) {
            bpf_core_read(&event->prog_type, sizeof(event->prog_type), &attr->prog_type);
            bpf_core_read_str(event->prog_name, sizeof(event->prog_name), &attr->prog_name);
        } else {
            bpf_core_read_user(&event->prog_type, sizeof(event->prog_type), &attr->prog_type);
            bpf_core_read_user_str(event->prog_name, sizeof(event->prog_name), &attr->prog_name);
        }
    }

    bpf_ringbuf_submit(event, 0);
}

/*
 * Hook หลัก: fentry ที่ฟังก์ชันภายใน __sys_bpf(enum bpf_cmd cmd, bpfptr_t uattr, unsigned int size)
 * bpfptr_t (= sockptr_t) เป็น struct 16 ไบต์ที่ส่งแบบ by-value จึงต้องใช้ BPF_PROG2
 * ซึ่งรู้วิธีประกอบ struct argument จาก 2 register
 */
SEC("fentry/__sys_bpf")
int BPF_PROG2(audit_sys_bpf, enum bpf_cmd, cmd, bpfptr_t, uattr, unsigned int, size)
{
    if (uattr.is_kernel) {
        emit_event((__u32)cmd, (union bpf_attr *)uattr.kernel, 1, SRC_FENTRY);
    } else {
        emit_event((__u32)cmd, (union bpf_attr *)uattr.user, 0, SRC_FENTRY);
    }
    return 0;
}

/*
 * Hook สำรอง: raw_syscalls/sys_enter ทำงานกับ "ทุก" syscall ของทั้งเครื่อง
 * จึงต้องกรองด้วยหมายเลข syscall ให้เร็วที่สุด (บรรทัดแรก)
 * ข้อจำกัด: ไม่เห็น compat syscall (32-bit) ซึ่งใช้หมายเลขต่างกัน และไม่เห็นผู้เรียกจากในเคอร์เนล
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int audit_raw_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (ctx->id != bpf_syscall_nr) {
        return 0;
    }
    emit_event((__u32)ctx->args[0], (union bpf_attr *)ctx->args[1], 0, SRC_RAW);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
