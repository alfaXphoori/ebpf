//go:build ignore
// +build ignore

/*
 * Week 13: Kernel Dropwatch (tracepoint skb:kfree_skb) - CO-RE edition
 *
 * ใช้ vmlinux.h แทนการประกาศ struct ของ tracepoint เอง เพื่อให้ libbpf/cilium-ebpf
 * ทำ CO-RE relocation ของ offset ฟิลด์ (เช่น `reason`) ให้ตรงกับเคอร์เนลที่รันจริง
 *   - Linux 6.8  (Ubuntu 24.04): ไม่มีฟิลด์ rx_sk  -> reason อยู่ offset 28
 *   - Linux 7.0  (Ubuntu 26.04): มีฟิลด์ rx_sk     -> reason อยู่ offset 36
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* enum skb_drop_reason: 0 = NOT_DROPPED_YET, 1 = CONSUMED (ไม่ใช่การดรอปจริง) */
#define DROP_REASON_FIRST_REAL_DROP 2

/*
 * Event structure sent via BPF Ring Buffer to User Space
 * (จัด layout ให้ไม่มี implicit padding เพื่อให้ฝั่ง Go decode ได้ตรงทุกไบต์)
 */
struct drop_event {
    __u64 location;  /* kernel instruction pointer ที่เรียก kfree_skb_reason() */
    __u32 pid;
    __u32 reason;    /* enum skb_drop_reason (16 บิตบน = subsystem id) */
    __u16 protocol;  /* ntohs(skb->protocol) -> host byte order, เช่น 0x0800 = IPv4 */
    __u8 has_rx_sk;  /* 1 = เคอร์เนลนี้มีฟิลด์ rx_sk ใน tracepoint */
    __u8 rx_sk_set;  /* 1 = แพ็กเก็ตนี้ผูกกับ socket ฝั่งรับ (rx_sk != NULL) */
    char comm[TASK_COMM_LEN];
    __u8 pad[4];
};

/*
 * BPF Ring Buffer for high-speed MPSC streaming of dropped packet telemetry
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4MB buffer */
} drop_events SEC(".maps");

/*
 * BPF Hash Map tracking cumulative drop count per drop reason
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* enum skb_drop_reason */
    __type(value, __u64); /* count */
} drop_reason_stats SEC(".maps");

/*
 * ctx เป็น struct trace_event_raw_kfree_skb จาก vmlinux.h
 * vmlinux.h เปิด preserve_access_index ให้ทุก struct อยู่แล้ว ดังนั้นการอ่าน
 * ctx->reason จะถูกคอมไพล์เป็น CO-RE relocation (ไม่ใช่ offset ตายตัว)
 */
SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    __u32 reason = ctx->reason;

    /* ข้าม NOT_DROPPED_YET (0) และ SKB_CONSUMED (1) ซึ่งไม่ใช่การดรอปผิดปกติ */
    if (reason < DROP_REASON_FIRST_REAL_DROP) {
        return 0;
    }

    /* Update cumulative drop statistics in BPF Hash Map */
    __u64 *count = bpf_map_lookup_elem(&drop_reason_stats, &reason);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&drop_reason_stats, &reason, &init_val, BPF_NOEXIST);
    }

    /* Reserve slot in ring buffer */
    struct drop_event *event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->reason = reason;
    event->location = (__u64)ctx->location;
    event->protocol = ctx->protocol;
    event->has_rx_sk = 0;
    event->rx_sk_set = 0;
    __builtin_memset(event->pad, 0, sizeof(event->pad));

    /*
     * CO-RE field existence: ฟิลด์ rx_sk เพิ่งถูกเพิ่มในเคอร์เนลรุ่นหลัง 6.8 (ราว 6.11)
     * บนเคอร์เนลที่ไม่มีฟิลด์นี้ loader จะแทนเงื่อนไขด้วยค่าคงที่ 0 และ
     * verifier ตัดโค้ดใน if ทิ้ง (dead code elimination) จึงโหลดผ่านทั้ง 6.8 และ 7.0
     */
    if (bpf_core_field_exists(ctx->rx_sk)) {
        event->has_rx_sk = 1;
        event->rx_sk_set = ctx->rx_sk != NULL;
    }

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
