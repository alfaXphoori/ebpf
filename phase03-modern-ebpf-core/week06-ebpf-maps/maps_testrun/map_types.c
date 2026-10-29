//go:build ignore
// +build ignore

/*
 * Week 06: a tiny XDP program used ONLY to unit-test map behaviour with
 * BPF_PROG_TEST_RUN (cilium/ebpf Program.Run). It is never attached to an
 * interface.
 *
 * Why XDP and not the tracepoint from syscall_stats.c?
 *   BPF_PROG_TEST_RUN is implemented only for some program types (XDP,
 *   sched_cls, socket_filter, raw_tracepoint, fentry/fexit, flow_dissector,
 *   ...). A "tracepoint/..." program cannot be test-run, so map logic that we
 *   want to test is put into an XDP program and fed with fake packets.
 *
 * Each run reads a 4-byte key from the first bytes of the "packet" and adds 1
 * to that key in three maps of different types (all max_entries = 8):
 *   hash_map   BPF_MAP_TYPE_HASH        - one shared value, full map rejects new keys
 *   percpu_map BPF_MAP_TYPE_PERCPU_HASH - one value per CPU, no atomics needed
 *   lru_map    BPF_MAP_TYPE_LRU_HASH    - full map evicts the least recently used key
 * Failed inserts are recorded in update_errs so the test can see -E2BIG.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_KEYS 8

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, __u32);
    __type(value, __u64);
} hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, __u32);
    __type(value, __u64);
} percpu_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_KEYS);
    __type(key, __u32);
    __type(value, __u64);
} lru_map SEC(".maps");

/* index 0 = hash_map, 1 = percpu_map, 2 = lru_map */
struct update_err {
    __u64 count;    /* how many bpf_map_update_elem() calls failed */
    __s64 last_err; /* last negative errno, e.g. -7 = -E2BIG (map full) */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, struct update_err);
} update_errs SEC(".maps");

static __always_inline void record_err(__u32 idx, long err)
{
    struct update_err *e = bpf_map_lookup_elem(&update_errs, &idx);
    if (!e)
        return;
    __sync_fetch_and_add(&e->count, 1);
    e->last_err = err;
}

/* shared value (HASH, LRU_HASH): other CPUs may write the same slot -> atomic add */
static __always_inline void bump_shared(void *map, __u32 *key, __u32 err_idx)
{
    __u64 *val = bpf_map_lookup_elem(map, key);
    if (val) {
        __sync_fetch_and_add(val, 1);
        return;
    }
    __u64 one = 1;
    long err = bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    if (err)
        record_err(err_idx, err);
}

/* per-CPU value: only this CPU writes its own copy -> plain ++ is safe */
static __always_inline void bump_percpu(void *map, __u32 *key, __u32 err_idx)
{
    __u64 *val = bpf_map_lookup_elem(map, key);
    if (val) {
        *val += 1;
        return;
    }
    __u64 one = 1;
    long err = bpf_map_update_elem(map, key, &one, BPF_NOEXIST);
    if (err)
        record_err(err_idx, err);
}

SEC("xdp")
int count_by_key(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* bounds check first - otherwise the verifier rejects the read below */
    if (data + sizeof(__u32) > data_end)
        return XDP_ABORTED;

    __u32 key;
    __builtin_memcpy(&key, data, sizeof(key));

    bump_shared(&hash_map, &key, 0);
    bump_percpu(&percpu_map, &key, 1);
    bump_shared(&lru_map, &key, 2);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
