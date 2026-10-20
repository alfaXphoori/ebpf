//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

/*
 * BPF_MAP_TYPE_XSKMAP: Routes packets from XDP queue into user-space AF_XDP sockets
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);   /* Queue ID */
    __type(value, __u32); /* Socket FD */
} xsks_map SEC(".maps");

/*
 * Cumulative metrics: [0] = redirected packets, [1] = fallback pass packets
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} xsk_stats SEC(".maps");

SEC("xdp")
int xsk_redirect_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 qid = ctx->rx_queue_index;

    /*
     * Attempt redirection into user space AF_XDP socket via XSKMAP.
     * If an XSK socket is bound to this queue, redirect directly into UMEM.
     */
    long ret = bpf_redirect_map(&xsks_map, qid, 0);
    if (ret == XDP_REDIRECT) {
        __u32 k0 = 0;
        __u64 *cnt = bpf_map_lookup_elem(&xsk_stats, &k0);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return XDP_REDIRECT;
    }

    __u32 k1 = 1;
    __u64 *pass_cnt = bpf_map_lookup_elem(&xsk_stats, &k1);
    if (pass_cnt) __sync_fetch_and_add(pass_cnt, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
