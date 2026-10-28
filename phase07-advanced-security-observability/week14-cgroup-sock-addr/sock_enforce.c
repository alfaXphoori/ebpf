//go:build ignore
// +build ignore

/*
 * Week 14: Socket Egress Enforcer (cgroup/connect4)
 *
 * หมายเหตุ: แล็บนี้ใช้ UAPI header <linux/bpf.h> แทน vmlinux.h โดยตั้งใจ
 * เพราะ context `struct bpf_sock_addr` เป็น Stable UAPI ABI ที่ verifier
 * เขียนคำสั่ง load/store ใหม่ (context rewrite) ไปยัง struct bpf_sock_addr_kern
 * ภายในเคอร์เนลให้เอง จึงไม่จำเป็นต้องใช้ CO-RE relocation
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define VERDICT_DENY  0 /* connect() คืนค่า -1 และ errno = EPERM */
#define VERDICT_ALLOW 1

#define MATCH_IP   1
#define MATCH_PORT 2

/*
 * BPF Hash Map storing blocked destination ports (TCP และ UDP connect())
 * Key: 16-bit port in host byte order
 * Value: 64-bit deny count
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u64);
} blocked_ports SEC(".maps");

/*
 * BPF Hash Map storing blocked destination IPv4 addresses
 * Key: 32-bit IPv4 in network byte order
 * Value: 64-bit deny count
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ips SEC(".maps");

/*
 * Audit event ส่งขึ้น User Space ทุกครั้งที่มีการปฏิเสธ connect()
 */
struct deny_event {
    __u32 pid;
    __u32 dst_ip;    /* network byte order */
    __u16 dst_port;  /* host byte order */
    __u8 sock_type;  /* 1 = SOCK_STREAM (TCP), 2 = SOCK_DGRAM (UDP) */
    __u8 match;      /* MATCH_IP หรือ MATCH_PORT */
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); /* 64KB เพียงพอสำหรับ audit log */
} deny_events SEC(".maps");

static __always_inline void emit_deny(__u32 dst_ip, __u16 dst_port, __u32 sock_type, __u8 match)
{
    struct deny_event *ev = bpf_ringbuf_reserve(&deny_events, sizeof(*ev), 0);
    if (!ev) {
        return; /* ring buffer เต็ม: ยังบล็อกตามนโยบาย แต่ audit event หาย */
    }
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->dst_ip = dst_ip;
    ev->dst_port = dst_port;
    ev->sock_type = (__u8)sock_type;
    ev->match = match;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
}

/*
 * cgroup/connect4 Hook:
 * ถูกเรียกใน connect() ของ socket AF_INET (TCP และ UDP)
 * ที่ "ถูกสร้าง" โดยโปรเซสภายใน cgroup เป้าหมาย (รวม cgroup ลูกหลาน)
 * - คืนค่า 0 => ปฏิเสธ: connect() ล้มเหลวด้วย EPERM ก่อนสร้างแพ็กเก็ต SYN
 * - คืนค่า 1 => อนุญาตให้ทำงานต่อตามปกติ
 */
SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    if (ctx->user_family != AF_INET) {
        return VERDICT_ALLOW;
    }

    __u32 dst_ip = ctx->user_ip4;
    /* user_port เป็น __u32 ที่เก็บพอร์ต 16 บิตแบบ network byte order ไว้ */
    __u16 dst_port = bpf_ntohs((__u16)ctx->user_port);

    /* Check if destination IP is blocked */
    __u64 *ip_drop_count = bpf_map_lookup_elem(&blocked_ips, &dst_ip);
    if (ip_drop_count) {
        __sync_fetch_and_add(ip_drop_count, 1);
        emit_deny(dst_ip, dst_port, ctx->type, MATCH_IP);
        return VERDICT_DENY;
    }

    /* Check if destination Port is blocked */
    __u64 *port_drop_count = bpf_map_lookup_elem(&blocked_ports, &dst_port);
    if (port_drop_count) {
        __sync_fetch_and_add(port_drop_count, 1);
        emit_deny(dst_ip, dst_port, ctx->type, MATCH_PORT);
        return VERDICT_DENY;
    }

    return VERDICT_ALLOW;
}

char LICENSE[] SEC("license") = "GPL";
