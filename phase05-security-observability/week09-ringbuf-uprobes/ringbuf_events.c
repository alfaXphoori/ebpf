//go:build ignore
// +build ignore

/*
 * CO-RE: ใช้ vmlinux.h (สร้างจาก BTF ของเคอร์เนลด้วย bpftool, อยู่ที่ repo root)
 * แทนการประกาศ struct ของเคอร์เนลเอง และห้าม include UAPI header (linux/...h) ปนกับ vmlinux.h
 * เพราะจะเกิด redefinition ของ type ซ้ำกัน
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define PAYLOAD_LEN 128

/* Event Types */
#define EVENT_TYPE_EXECVE        1
#define EVENT_TYPE_TLS_PLAINTEXT 2

/*
 * Security Event Payload structure sent over Ring Buffer
 * จัดเรียง field จากใหญ่ไปเล็ก (8 -> 4 -> 1 ไบต์) และเติม pad เองให้ครบ
 * เพื่อไม่ให้ compiler แทรก padding แอบแฝง: ขนาดรวม 176 ไบต์ ตรงกับ Go struct
 */
struct sec_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 data_len;
    __u8  event_type;
    __u8  pad[7];
    char  comm[TASK_COMM_LEN];
    char  payload[PAYLOAD_LEN];
};

/* BPF_MAP_TYPE_RINGBUF: Shared multi-producer single-consumer ring buffer (16 MB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

/*
 * อ่าน PID ของ parent ผ่าน CO-RE: task_struct เป็น kernel struct ที่ layout
 * เปลี่ยนได้ทุกเวอร์ชันเคอร์เนล BPF_CORE_READ() จะบันทึก relocation ไว้ใน .o
 * แล้ว libbpf/cilium-ebpf จะปรับ offset ให้ตรงกับ BTF ของเคอร์เนลที่รันจริงตอนโหลด
 */
static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline void fill_common(struct sec_event *e, __u8 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)(pid_tgid >> 32);
    e->ppid = get_ppid();
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->data_len = 0;
    e->event_type = type;
    __builtin_memset(e->pad, 0, sizeof(e->pad));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/*
 * 1a. Tracepoint (ค่าเริ่มต้น): sched/sched_process_exec
 *
 * ยิงหลัง execve() สำเร็จแล้ว (binary ถูกโหลดจริง) ctx คือ
 * struct trace_event_raw_sched_process_exec จาก vmlinux.h ซึ่ง filename เป็น
 * field แบบ __data_loc: 16 บิตล่างของ __data_loc_filename = offset ของสตริง
 * นับจากต้น ctx (16 บิตบน = ความยาว) สตริงอยู่ในหน่วยความจำเคอร์เนล
 * จึงอ่านด้วย bpf_probe_read_kernel_str()
 */
SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    /* Reserve space in Ring Buffer (เขียนลง buffer โดยตรง ไม่ต้องสร้างบน stack ก่อน) */
    struct sec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; /* Ring buffer is full; drop event gracefully */
    }

    fill_common(e, EVENT_TYPE_EXECVE);

    __u16 off = ctx->__data_loc_filename & 0xFFFF;
    long len = bpf_probe_read_kernel_str(e->payload, sizeof(e->payload), (void *)ctx + off);
    if (len > 0) {
        e->data_len = (__u32)len;
    } else {
        e->payload[0] = '\0';
    }

    /* Submit reserved record to user-space */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * 1b. Tracepoint (ทางเลือก -exec-hook=syscall): syscalls/sys_enter_execve
 *
 * ใช้ struct trace_event_raw_sys_enter จาก vmlinux.h (layout กลางของทุก
 * syscalls/sys_enter_* tracepoint): args[0] = filename, args[1] = argv, args[2] = envp
 * filename เป็น pointer ใน user space จึงต้องอ่านด้วย bpf_probe_read_user_str()
 * หมายเหตุ: ยิงก่อน execve ทำงาน (execve อาจล้มเหลวภายหลัง) และ user space
 * สามารถแก้ buffer หลังเราอ่านไปแล้วได้ (TOCTOU) -- ดู README หัวข้อ Limitations
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct sec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_common(e, EVENT_TYPE_EXECVE);

    /* args[0] holds user-space pointer to filename */
    const char *filename_ptr = (const char *)ctx->args[0];
    long len = bpf_probe_read_user_str(e->payload, sizeof(e->payload), filename_ptr);
    if (len > 0) {
        e->data_len = (__u32)len;
    } else {
        e->payload[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * 2. Uprobes: Intercept OpenSSL plaintext ก่อนถูกเข้ารหัส
 *
 *   int SSL_write(SSL *ssl, const void *buf, int num);                       (curl ใช้)
 *   int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written); (CPython ใช้)
 *
 * ทั้งสองฟังก์ชันมี buf เป็น argument ที่ 2 และความยาวเป็น argument ที่ 3
 * จึงใช้ logic ร่วมกันได้ BPF_UPROBE() (จาก bpf_tracing.h) แกะ argument จาก
 * struct pt_regs ตาม calling convention ของสถาปัตยกรรมที่กำหนดด้วย
 * -D__TARGET_ARCH_xxx (bpf2go -target native/amd64 ใส่ให้อัตโนมัติ)
 * บน x86_64: buf = %rsi, num = %rdx
 */
static __always_inline int handle_ssl_write(const void *buf, __u64 num)
{
    if (num == 0 || !buf) {
        return 0;
    }

    /* Reserve record in Ring Buffer */
    struct sec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_common(e, EVENT_TYPE_TLS_PLAINTEXT);

    /* Bound payload size strictly to avoid buffer overflow and satisfy eBPF verifier */
    __u32 copy_len = num > PAYLOAD_LEN - 1 ? PAYLOAD_LEN - 1 : (__u32)num;
    copy_len &= 0x7F; /* ให้ verifier เห็นขอบบนชัดเจน: 0..127 */

    __builtin_memset(e->payload, 0, sizeof(e->payload));
    if (copy_len > 0) {
        /*
         * bpf_probe_read_user() อาจล้มเหลวได้ (เช่น page ของ buf ยังไม่ถูก fault-in)
         * ถ้าล้มเหลวให้รายงาน data_len = 0 แทนที่จะส่ง buffer ศูนย์ล้วนพร้อมความยาวหลอก
         */
        if (bpf_probe_read_user(e->payload, copy_len, buf) == 0) {
            e->data_len = copy_len;
        }
    }

    /* Submit to user-space */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num)
{
    if (num <= 0) {
        return 0;
    }
    return handle_ssl_write(buf, (__u64)num);
}

SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex, void *ssl, const void *buf, __u64 num)
{
    return handle_ssl_write(buf, num);
}
