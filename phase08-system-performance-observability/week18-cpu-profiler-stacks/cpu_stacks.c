//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* ค่า errno เป็น #define ในเคอร์เนล จึงไม่อยู่ใน vmlinux.h ต้องประกาศเอง */
#define EEXIST 17

/* ความลึกสูงสุดของ Stack ที่เก็บ (PERF_MAX_STACK_DEPTH ค่าเริ่มต้นของเคอร์เนลคือ 127) */
#define MAX_STACK_DEPTH 127

/*
 * ตัวกรองที่ Userspace เขียนก่อนโหลด (RewriteConstants) อยู่ใน .rodata
 * Verifier เห็นเป็นค่าคงที่ จึงตัดกิ่งที่ไม่ใช้ทิ้งได้
 */
const volatile __u32 targ_pid = 0;      /* 0 = ทุกโปรเซส */
const volatile __u8 include_idle = 0;   /* 1 = นับ Sample ของ idle task (PID 0) ด้วย */

struct stack_key {
    __u32 pid;
    __s32 kernel_stack_id;
    __s32 user_stack_id;
    char comm[TASK_COMM_LEN];
};

/*
 * BPF_MAP_TYPE_STACK_TRACE: เคอร์เนลเป็นผู้ Unwind และเก็บ IP ของแต่ละเฟรม
 * key = stack id (hash ของ IP ทั้งหมด), value = อาร์เรย์ IP ยาว MAX_STACK_DEPTH
 */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 16384);
} stack_traces SEC(".maps");

/*
 * Hash map รวมจำนวน Sample ต่อ (pid, kernel stack, user stack)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct stack_key);
    __type(value, __u64);
} stack_counts SEC(".maps");

/*
 * ตัวนับสถานะ (PERCPU เพื่อไม่ต้องใช้ Atomic):
 *   [0] samples ทั้งหมดที่โปรแกรมถูกเรียก
 *   [1] kernel stack ชน hash bucket (-EEXIST) -> stack นั้นสูญหาย
 *   [2] user stack ชน hash bucket (-EEXIST)
 *   [3] เก็บ count ไม่ได้เพราะ stack_counts เต็ม
 */
enum { STAT_SAMPLES, STAT_KERN_EEXIST, STAT_USER_EEXIST, STAT_COUNTS_FULL, STAT_MAX };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        (*v)++;
}

/*
 * SEC("perf_event"): ถูกเรียกทุกครั้งที่ perf event (CPU clock 99 Hz ต่อ CPU)
 * ครบรอบ ctx->regs คือ register ของงานที่ "กำลังรันอยู่บน CPU" ขณะถูกขัดจังหวะ
 * => นี่คือการสุ่มแบบ On-CPU ที่แท้จริง
 */
SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 tid = (__u32)id;

    stat_inc(STAT_SAMPLES);

    if (tid == 0 && !include_idle)
        return 0; /* idle task (swapper) = CPU ว่าง */
    if (targ_pid && tgid != targ_pid)
        return 0;

    struct stack_key key = {};
    key.pid = tgid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    /*
     * flags = 0 (ไม่ใช้ BPF_F_REUSE_STACKID / BPF_F_FAST_STACK_CMP):
     * - ถ้า Stack เดิมอยู่แล้ว -> คืน id เดิม
     * - ถ้า bucket ว่าง -> เก็บ stack ใหม่
     * - ถ้า bucket ถูก stack "อื่น" จองอยู่ -> คืน -EEXIST (เรานับไว้รายงาน)
     * การใช้ BPF_F_REUSE_STACKID จะเขียนทับ bucket ทำให้ id เก่าที่อยู่ใน
     * stack_counts ชี้ไปที่ stack ผิดตัว จึงไม่เหมาะกับการรวมผลแบบ Profiler
     */
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    if (key.kernel_stack_id == -EEXIST)
        stat_inc(STAT_KERN_EEXIST);

    /*
     * -EFAULT ของ user stack เป็นเรื่องปกติสำหรับ kernel thread (ไม่มี user context)
     */
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (key.user_stack_id == -EEXIST)
        stat_inc(STAT_USER_EEXIST);

    __u64 *val = bpf_map_lookup_elem(&stack_counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 one = 1;
        if (bpf_map_update_elem(&stack_counts, &key, &one, BPF_NOEXIST)) {
            /* อาจชนกับ CPU อื่นที่เพิ่ง Insert key เดียวกัน -> ลอง lookup อีกครั้ง */
            val = bpf_map_lookup_elem(&stack_counts, &key);
            if (val)
                __sync_fetch_and_add(val, 1);
            else
                stat_inc(STAT_COUNTS_FULL);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
