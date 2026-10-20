//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct req_key {
    __u32 dev;
    __u32 pad;
    __u64 sector;
};

/*
 * Hash map storing start timestamp of in-flight block I/O requests
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct req_key);
    __type(value, __u64);
} start_times SEC(".maps");

/*
 * Array map storing 32-bucket power-of-two microsecond latency histogram
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} io_latency_hist SEC(".maps");

/*
 * Cumulative I/O counters: [0] Total requests, [1] Total latency us
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} io_totals SEC(".maps");

struct block_rq_issue_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned int dev;
    unsigned int pad0;
    unsigned long long sector;
    unsigned int nr_sector;
    unsigned int bytes;
    unsigned short ioprio;
    char rwbs[10];
    char comm[16];
};

struct block_rq_complete_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned int dev;
    unsigned int pad0;
    unsigned long long sector;
    unsigned int nr_sector;
    int error;
    unsigned short ioprio;
    char rwbs[10];
};

static __always_inline __u32 log2l(__u64 val)
{
    __u32 r = 0;
    #pragma unroll
    for (int i = 0; i < 31; i++) {
        if (val >>= 1) {
            r++;
        }
    }
    return r >= 31 ? 31 : r;
}

SEC("tracepoint/block/block_rq_issue")
int trace_rq_issue(struct block_rq_issue_args *ctx)
{
    struct req_key key = {
        .dev = ctx->dev,
        .pad = 0,
        .sector = ctx->sector,
    };

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &key, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_rq_complete(struct block_rq_complete_args *ctx)
{
    struct req_key key = {
        .dev = ctx->dev,
        .pad = 0,
        .sector = ctx->sector,
    };

    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
    if (!start_ts) {
        return 0;
    }

    __u64 delta_us = (bpf_ktime_get_ns() - *start_ts) / 1000;
    bpf_map_delete_elem(&start_times, &key);

    /* Update histogram */
    __u32 bucket = log2l(delta_us);
    __u64 *hist_val = bpf_map_lookup_elem(&io_latency_hist, &bucket);
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
