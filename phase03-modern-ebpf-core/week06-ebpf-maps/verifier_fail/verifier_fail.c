//go:build ignore
// +build ignore

/*
 * Week 06 hands-on: programs that are INTENTIONALLY rejected by the eBPF verifier.
 *
 * clang compiles every program in this file without a single warning -
 * the bugs are only detected when the kernel verifier simulates the
 * bytecode at load time (BPF_PROG_LOAD). Load them with:
 *
 *   sudo ./bin/verifier_fail -case bounds     # missing packet bounds check
 *   sudo ./bin/verifier_fail -case nullcheck  # missing NULL check after map lookup
 *   sudo ./bin/verifier_fail -case fixed      # corrected version (loads OK)
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Per-interface packet counter. A HASH map is used on purpose: lookups in a
 * HASH map may always return NULL. (Recent kernels can prove that an ARRAY
 * lookup with a constant, in-range key is never NULL and would accept bug #2.)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    /* ingress ifindex */
    __type(value, __u64);  /* packets */
    __uint(max_entries, 64);
} pkt_count SEC(".maps");

/*
 * BUG #1: reads eth->h_proto without proving (eth + 1) <= data_end.
 * Expected verifier error: "invalid access to packet, off=12 size=2, R1(...r=0)"
 *   r=0 means: the verifier has proven 0 bytes of the packet are safe to read.
 */
SEC("xdp")
int xdp_no_bounds_check(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    /* MISSING: if ((void *)(eth + 1) > data_end) return XDP_PASS; */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    return XDP_DROP;
}

/*
 * BUG #2: dereferences the result of bpf_map_lookup_elem() without a NULL check.
 * Expected verifier error: "R0 invalid mem access 'map_value_or_null'"
 */
SEC("xdp")
int xdp_no_null_check(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);

    /* MISSING: if (!count) return XDP_PASS; */
    __sync_fetch_and_add(count, 1);

    return XDP_PASS;
}

/* FIXED: both checks present - the verifier accepts this program. */
SEC("xdp")
int xdp_fixed(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u32 key = ctx->ingress_ifindex;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (!count) {
        __u64 one = 1;
        bpf_map_update_elem(&pkt_count, &key, &one, BPF_NOEXIST);
        return XDP_PASS;
    }
    /* HASH map values are shared by all CPUs -> atomic add */
    __sync_fetch_and_add(count, 1);

    return XDP_PASS;
}
