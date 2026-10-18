// +build ignore

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Protocol indices in traffic_metrics map */
#define PROTO_INDEX_TCP   0
#define PROTO_INDEX_UDP   1
#define PROTO_INDEX_ICMP  2
#define PROTO_INDEX_OTHER 3

/* Structure representing aggregated telemetry per protocol */
struct proto_metric {
    __u64 packets;
    __u64 bytes;
};

/*
 * BPF_MAP_TYPE_PERCPU_ARRAY:
 * Allocates a separate array for each active CPU core in the system.
 * Eliminates atomic lock contention (cache bouncing) completely, achieving 10M+ PPS.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct proto_metric);
    __uint(max_entries, 4);
} traffic_metrics SEC(".maps");

/*
 * XDP Metrics Program:
 * Inspects all incoming network packets at the driver/NIC layer
 * and aggregates traffic volume by protocol into per-CPU arrays.
 */
SEC("xdp")
int xdp_metrics_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /*
     * 1. Ethernet Header Bounds Check:
     * Verifier requires proving that (eth + 1) does not exceed data_end
     * before reading any field of struct ethhdr.
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* Only inspect IPv4 traffic; pass ARP, IPv6, etc. as OTHER */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        __u32 proto_idx = PROTO_INDEX_OTHER;
        struct proto_metric *m = bpf_map_lookup_elem(&traffic_metrics, &proto_idx);
        if (m) {
            m->packets += 1;
            m->bytes += (__u64)(data_end - data);
        }
        return XDP_PASS;
    }

    /*
     * 2. IPv4 Header Bounds Check:
     * Verifier requires explicit bounds check on (iph + 1) <= data_end.
     */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    /* Map IP protocol to array index */
    __u32 proto_idx;
    switch (iph->protocol) {
    case IPPROTO_TCP:
        proto_idx = PROTO_INDEX_TCP;
        break;
    case IPPROTO_UDP:
        proto_idx = PROTO_INDEX_UDP;
        break;
    case IPPROTO_ICMP:
        proto_idx = PROTO_INDEX_ICMP;
        break;
    default:
        proto_idx = PROTO_INDEX_OTHER;
        break;
    }

    /*
     * 3. Lookup into Per-CPU array:
     * Returns a pointer to this CPU's local memory slot.
     * No atomics (LOCK XADD) needed! Normal increment is safe.
     */
    struct proto_metric *metric = bpf_map_lookup_elem(&traffic_metrics, &proto_idx);
    if (metric) {
        metric->packets += 1;
        metric->bytes += (__u64)(data_end - data);
    }

    return XDP_PASS;
}
