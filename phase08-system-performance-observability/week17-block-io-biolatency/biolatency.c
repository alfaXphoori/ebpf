//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * ค่าคงที่ที่เป็น #define ในเคอร์เนลจะไม่อยู่ใน vmlinux.h (BTF เก็บได้แค่ type/enum)
 * จึงต้องประกาศเอง: REQ_OP_BITS = 8 (include/linux/blk_types.h)
 */
#define REQ_OP_MASK ((1U << 8) - 1)
#define MINORBITS   20
#define MKDEV(ma, mi) (((__u32)(ma) << MINORBITS) | (__u32)(mi))

#define MAX_SLOTS 32

/* หมวดของคำสั่ง I/O ที่เราแยก Histogram ให้ */
#define OP_READ  0
#define OP_WRITE 1
#define OP_OTHER 2 /* FLUSH, DISCARD, WRITE_ZEROES ฯลฯ */

/*
 * Key ของ Histogram: แยกตามดิสก์ (dev_t) x ประเภทคำสั่ง x ช่อง log2
 */
struct hist_key {
    __u32 dev;
    __u32 op;
    __u32 slot;
};

/*
 * Hash map เก็บเวลาเริ่มต้นของ Request ที่กำลัง In-flight
 * Key = ที่อยู่ของ struct request ในเคอร์เนล (ไม่ซ้ำกันขณะ In-flight)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u64);
} start_times SEC(".maps");

/*
 * Histogram แบบ Power-of-two (หน่วยไมโครวินาที) แยกตาม dev/op
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct hist_key);
    __type(value, __u64);
} io_latency_hist SEC(".maps");

/*
 * ตัวนับสะสม: [0] จำนวน Request ทั้งหมด, [1] Latency รวม (us)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} io_totals SEC(".maps");

/*
 * log2 แบบ Branch-free (เทคนิคเดียวกับ bits.bpf.h ของ libbpf-tools)
 * แต่ละขั้นเช็คว่าค่าใหญ่กว่า 2^16, 2^8, 2^4, 2^2, 2^1 หรือไม่ แล้ว Shift ลง
 * ใช้คำสั่งคงที่ ~15 คำสั่ง ไม่มี Loop ให้ Verifier ต้องไล่
 * ผลลัพธ์: log2(0) = 0, log2(1) = 0, log2(2..3) = 1, log2(4..7) = 2, ...
 */
static __always_inline __u32 log2_u32(__u32 v)
{
    __u32 shift, r;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);
    return r;
}

static __always_inline __u32 log2l(__u64 v)
{
    __u32 hi = v >> 32;

    if (hi)
        return log2_u32(hi) + 32;
    return log2_u32((__u32)v);
}

/*
 * tp_btf = BTF-enabled raw tracepoint: ได้อาร์กิวเมนต์จริงของ trace_block_rq_issue()
 * คือ struct request *rq (ไม่ใช่สำเนาฟิลด์แบบ tracepoint/ ปกติ)
 */
SEC("tp_btf/block_rq_issue")
int BPF_PROG(trace_rq_issue, struct request *rq)
{
    __u64 key = (__u64)rq;
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(trace_rq_complete, struct request *rq, int error, unsigned int nr_bytes)
{
    __u64 key = (__u64)rq;
    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
    if (!start_ts) {
        return 0; /* Request เริ่มก่อนที่เราจะ Attach */
    }

    __u64 delta_us = (bpf_ktime_get_ns() - *start_ts) / 1000;
    bpf_map_delete_elem(&start_times, &key);

    /* อ่านประเภทคำสั่งและดิสก์ปลายทางผ่าน CO-RE */
    __u32 opf = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
    struct hist_key hkey = {};
    hkey.op = opf == REQ_OP_READ ? OP_READ : (opf == REQ_OP_WRITE ? OP_WRITE : OP_OTHER);
    hkey.dev = MKDEV(BPF_CORE_READ(rq, q, disk, major),
                     BPF_CORE_READ(rq, q, disk, first_minor));

    __u32 slot = log2l(delta_us);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    hkey.slot = slot;

    /*
     * Lookup-or-init: สร้างช่องด้วยค่า 0 แบบ BPF_NOEXIST ก่อนแล้วค่อย Atomic add
     * ถ้า 2 CPU สร้างช่องเดียวกันพร้อมกัน ตัวหนึ่งจะ Insert ไม่สำเร็จ (-EEXIST)
     * แต่ทั้งคู่ยังเพิ่มค่าผ่าน __sync_fetch_and_add ได้ ไม่มี Sample หาย
     */
    __u64 *hist_val = bpf_map_lookup_elem(&io_latency_hist, &hkey);
    if (!hist_val) {
        __u64 zero = 0;
        bpf_map_update_elem(&io_latency_hist, &hkey, &zero, BPF_NOEXIST);
        hist_val = bpf_map_lookup_elem(&io_latency_hist, &hkey);
    }
    if (hist_val) {
        __sync_fetch_and_add(hist_val, 1);
    }

    /* Update totals: [0] count, [1] sum us */
    __u32 key_cnt = 0;
    __u64 *tot_cnt = bpf_map_lookup_elem(&io_totals, &key_cnt);
    if (tot_cnt) __sync_fetch_and_add(tot_cnt, 1);

    __u32 key_lat = 1;
    __u64 *tot_lat = bpf_map_lookup_elem(&io_totals, &key_lat);
    if (tot_lat) __sync_fetch_and_add(tot_lat, delta_us);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
