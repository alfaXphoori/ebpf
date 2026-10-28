//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

/*
 * BPF_MAP_TYPE_XSKMAP: Routes packets from XDP queue into user-space AF_XDP sockets
 *   key   = RX queue index of the NIC
 *   value = AF_XDP socket fd (written by user space, read back as socket id)
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);   /* Queue ID */
    __type(value, __u32); /* Socket FD */
} xsks_map SEC(".maps");

/*
 * Cumulative metrics (index layout shared with main.go)
 */
enum {
    STAT_REDIRECTED  = 0, /* IPv4/UDP redirected into the AF_XDP socket        */
    STAT_PASSED      = 1, /* not IPv4/UDP (ARP, ICMP, TCP...) -> kernel stack   */
    STAT_NO_XSK      = 2, /* IPv4/UDP but no socket bound to this queue -> PASS */
    STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} xsk_stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&xsk_stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

SEC("xdp")
int xsk_redirect_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /*
     * Only IPv4/UDP goes to user space. Everything else (ARP, ICMP, TCP)
     * continues to the normal kernel stack, so the interface stays reachable.
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) {
        stat_inc(STAT_PASSED);
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_UDP) {
        stat_inc(STAT_PASSED);
        return XDP_PASS;
    }

    __u32 qid = ctx->rx_queue_index;

    /*
     * Redirect into the AF_XDP socket bound to this RX queue.
     * The low bits of the flags argument are the action returned when the
     * key has no socket (kernel >= 5.3), so we get XDP_PASS instead of
     * XDP_ABORTED when user space has not inserted a socket yet.
     */
    long ret = bpf_redirect_map(&xsks_map, qid, XDP_PASS);
    if (ret == XDP_REDIRECT) {
        stat_inc(STAT_REDIRECTED);
        return XDP_REDIRECT;
    }

    stat_inc(STAT_NO_XSK);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
