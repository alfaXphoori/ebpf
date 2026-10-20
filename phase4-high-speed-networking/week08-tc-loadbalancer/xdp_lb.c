//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Fallback definitions for stand-alone compiler environments
 */
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_TX
#define XDP_TX 3
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

/*
 * Backend server network identity (IP + MAC)
 */
struct backend_config {
    __u32 ip;                    /* IPv4 address in network byte order */
    unsigned char mac[ETH_ALEN]; /* Ethernet MAC address */
    __u16 pad;                   /* Explicit padding to guarantee 4-byte struct alignment */
};

/*
 * Load Balancer VIP & MAC configuration
 */
struct lb_config_t {
    __u32 vip;                   /* Virtual IP address in network byte order */
    unsigned char lb_mac[ETH_ALEN]; /* Load Balancer MAC address */
    __u16 pad;
};

/*
 * Real-time load balancer statistics
 */
struct lb_stats_t {
    __u64 rx_packets;
    __u64 forwarded_backend_0;
    __u64 forwarded_backend_1;
};

/*
 * Map storing target backend pool (2 backend servers)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct backend_config);
} backends SEC(".maps");

/*
 * Map storing VIP and LB interface MAC
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_config_t);
} lb_config SEC(".maps");

/*
 * Map tracking forwarding metrics
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_stats_t);
} lb_stats SEC(".maps");

/*
 * Incremental 16-bit 1's complement checksum update helper using bpf_csum_diff (RFC 1624)
 */
static __always_inline void csum_replace4_helper(__u16 *csum, __u32 from, __u32 to)
{
    __s64 diff = bpf_csum_diff((__be32 *)&from, sizeof(from),
                               (__be32 *)&to, sizeof(to),
                               ~(*csum));
    diff = (diff & 0xffff) + (diff >> 16);
    diff = (diff & 0xffff) + (diff >> 16);
    *csum = (__u16)~diff;
}

/*
 * L4 XDP Load Balancer
 * Intercepts traffic destined for VIP, selects backend based on client port hash,
 * rewrites L2/L3 headers, adjusts checksums, and hairpins packet back out via XDP_TX.
 */
SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Parse and validate Layer 2 Ethernet Header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /* 2. Parse and validate Layer 3 IPv4 Header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)iph + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    /* Only handle TCP traffic */
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    /* 3. Retrieve Load Balancer Configuration (VIP & LB MAC) */
    __u32 cfg_key = 0;
    struct lb_config_t *cfg = bpf_map_lookup_elem(&lb_config, &cfg_key);
    if (!cfg) {
        return XDP_PASS;
    }

    /* Only intercept packets targeting our Virtual IP */
    if (iph->daddr != cfg->vip) {
        return XDP_PASS;
    }

    /* 4. Parse and validate Layer 4 TCP Header */
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end) {
        return XDP_PASS;
    }

    /* Track ingress packets */
    struct lb_stats_t *stats = bpf_map_lookup_elem(&lb_stats, &cfg_key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
    }

    /*
     * 5. Select Backend via Flow Hash
     * Use client source port to determine backend server index (0 or 1).
     */
    __u32 backend_id = bpf_ntohs(tcph->source) % 2;
    struct backend_config *backend = bpf_map_lookup_elem(&backends, &backend_id);
    if (!backend) {
        return XDP_PASS;
    }

    /*
     * 6. Rewrite Layer 2 MAC addresses
     * Source MAC: becomes Load Balancer MAC
     * Dest MAC: becomes Target Backend MAC
     */
    __builtin_memcpy(eth->h_source, cfg->lb_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, backend->mac, ETH_ALEN);

    /*
     * 7. Rewrite Layer 3 Destination IP Address
     * Incrementally recalculate IP header checksum and TCP pseudo-header checksum.
     */
    __u32 old_daddr = iph->daddr;
    __u32 new_daddr = backend->ip;

    csum_replace4_helper(&iph->check, old_daddr, new_daddr);
    csum_replace4_helper(&tcph->check, old_daddr, new_daddr);
    iph->daddr = new_daddr;

    /* Update metrics */
    if (stats) {
        if (backend_id == 0) {
            __sync_fetch_and_add(&stats->forwarded_backend_0, 1);
        } else {
            __sync_fetch_and_add(&stats->forwarded_backend_1, 1);
        }
    }

    /*
     * 8. Hairpin Packet Out via XDP_TX
     * Transmit modified packet back out the same interface directly from driver!
     */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
