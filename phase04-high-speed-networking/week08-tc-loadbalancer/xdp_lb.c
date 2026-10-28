//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
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

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

/* IPv4 fragmentation flags (iph->frag_off, host byte order before bpf_htons) */
#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

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
    __u64 reverse_nat_packets;   /* Backend replies rewritten src backend IP -> VIP by TC */
};

/*
 * Connection tracking key: identifies one client <-> backend TCP flow.
 * Ports are kept in network byte order (copied straight from the TCP header).
 * Forward (XDP):  saddr=client_ip  sport=client_port  daddr=VIP         dport=service_port
 * Reply   (TC):   saddr=backend_ip sport=service_port daddr=client_ip   dport=client_port
 */
struct flow_key {
    __u32 client_ip;
    __u32 backend_ip;
    __u16 client_port;
    __u16 service_port;
};

/*
 * Connection tracking value: the VIP the client originally connected to,
 * so the reply path can restore it as the source address.
 */
struct flow_value {
    __u32 vip;
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
 * Map tracking active flows (written by XDP forward path, read by TC reverse path).
 * LRU_HASH evicts the least recently used flows automatically when full, so we
 * never need a userspace garbage collector for closed connections.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flows SEC(".maps");

/*
 * Incremental 16-bit 1's complement checksum update helper using bpf_csum_diff (RFC 1624)
 */
static __always_inline void csum_replace4_helper(__u16 *csum, __u32 from, __u32 to)
{
    /* Seed = ~HC as a 16-bit value (cast avoids sign/int promotion of ~) */
    __s64 diff = bpf_csum_diff((__be32 *)&from, sizeof(from),
                               (__be32 *)&to, sizeof(to),
                               (__u16)~(*csum));
    diff = (diff & 0xffff) + (diff >> 16);
    diff = (diff & 0xffff) + (diff >> 16);
    *csum = (__u16)~diff;
}

/*
 * Flow hash for backend selection (integer mixer "lowbias32", public domain)
 * Mixes client IP + client port + service port so that every bit of the input
 * affects the low bit we use for "% 2". Using the raw source port is NOT enough:
 * Linux connect() prefers EVEN ephemeral ports (since 4.2), so "sport % 2" would
 * send almost every connection to backend 0.
 */
static __always_inline __u32 flow_hash(__u32 saddr, __u16 sport, __u16 dport)
{
    __u32 h = saddr ^ (((__u32)sport << 16) | dport);
    h ^= h >> 16;
    h *= 0x7feb352d;
    h ^= h >> 15;
    h *= 0x846ca68b;
    h ^= h >> 16;
    return h;
}

/*
 * L4 XDP Load Balancer (forward path: client -> VIP -> backend)
 * Intercepts traffic destined for VIP, selects backend based on a flow hash,
 * records the flow, rewrites L2/L3 headers (DNAT), adjusts checksums, and hairpins
 * the packet back out via XDP_TX. The reply path is handled by tc_reverse_nat below.
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

    /*
     * Skip IP fragments: only the first fragment carries the TCP header, so the
     * remaining fragments could not be hashed to the same backend.
     */
    if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
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
     * Same (client IP, client port, service port) -> same hash -> same backend,
     * so every packet of one TCP connection lands on the same server.
     */
    __u32 backend_id = flow_hash(iph->saddr, tcph->source, tcph->dest) % 2;
    struct backend_config *backend = bpf_map_lookup_elem(&backends, &backend_id);
    if (!backend || backend->ip == 0) {
        return XDP_PASS;
    }

    /*
     * 6. Record the flow for the reverse (reply) path
     * Lookup first so established flows do not cost a map write per packet.
     */
    struct flow_key fkey = {
        .client_ip = iph->saddr,
        .backend_ip = backend->ip,
        .client_port = tcph->source,
        .service_port = tcph->dest,
    };
    if (!bpf_map_lookup_elem(&flows, &fkey)) {
        struct flow_value fval = { .vip = iph->daddr };
        bpf_map_update_elem(&flows, &fkey, &fval, BPF_ANY);
    }

    /*
     * 7. Rewrite Layer 2 MAC addresses
     * Source MAC: becomes Load Balancer MAC
     * Dest MAC: becomes Target Backend MAC
     */
    __builtin_memcpy(eth->h_source, cfg->lb_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, backend->mac, ETH_ALEN);

    /*
     * 8. Rewrite Layer 3 Destination IP Address (DNAT: VIP -> backend)
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
     * 9. Hairpin Packet Out via XDP_TX
     * Transmit modified packet back out the same interface directly from driver!
     */
    return XDP_TX;
}

/*
 * TC Reverse NAT (reply path: backend -> client)
 * Attached to TCX *ingress* of the same LB interface. Backends route replies back
 * through the LB (default gateway), so every reply carries src=backend_ip. If the
 * flow is known, rewrite the source address back to the VIP (SNAT) so the client's
 * TCP stack recognises the reply. The kernel then forwards it to the client.
 *
 * Unlike XDP, TC has skb-aware checksum helpers (bpf_l3_csum_replace /
 * bpf_l4_csum_replace) which also handle CHECKSUM_PARTIAL / CHECKSUM_COMPLETE.
 */
SEC("tc")
int tc_reverse_nat(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* 1. Parse and validate Layer 2 Ethernet Header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    /* 2. Parse and validate Layer 3 IPv4 Header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)iph + ip_hdr_len > data_end) {
        return TC_ACT_OK;
    }

    if (iph->protocol != IPPROTO_TCP || (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))) {
        return TC_ACT_OK;
    }

    /* 3. Parse and validate Layer 4 TCP Header */
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* 4. Is this a reply of a flow the XDP forward path created? */
    struct flow_key fkey = {
        .client_ip = iph->daddr,
        .backend_ip = iph->saddr,
        .client_port = tcph->dest,
        .service_port = tcph->source,
    };
    struct flow_value *flow = bpf_map_lookup_elem(&flows, &fkey);
    if (!flow) {
        return TC_ACT_OK;
    }

    __u32 old_saddr = iph->saddr;
    __u32 new_saddr = flow->vip;

    /*
     * 5. SNAT: backend IP -> VIP
     * Offsets are relative to skb->data (start of Ethernet header). The helpers
     * may reallocate packet memory, so all packet pointers are invalid afterwards.
     */
    __u32 ip_csum_off = ETH_HLEN + offsetof(struct iphdr, check);
    __u32 ip_saddr_off = ETH_HLEN + offsetof(struct iphdr, saddr);
    __u32 tcp_csum_off = ETH_HLEN + ip_hdr_len + offsetof(struct tcphdr, check);

    /* TCP checksum covers the pseudo-header (saddr/daddr) -> BPF_F_PSEUDO_HDR */
    if (bpf_l4_csum_replace(skb, tcp_csum_off, old_saddr, new_saddr,
                            BPF_F_PSEUDO_HDR | sizeof(new_saddr)) < 0) {
        return TC_ACT_OK;
    }
    if (bpf_l3_csum_replace(skb, ip_csum_off, old_saddr, new_saddr, sizeof(new_saddr)) < 0) {
        return TC_ACT_OK;
    }
    if (bpf_skb_store_bytes(skb, ip_saddr_off, &new_saddr, sizeof(new_saddr), 0) < 0) {
        return TC_ACT_OK;
    }

    /* Update metrics */
    __u32 cfg_key = 0;
    struct lb_stats_t *stats = bpf_map_lookup_elem(&lb_stats, &cfg_key);
    if (stats) {
        __sync_fetch_and_add(&stats->reverse_nat_packets, 1);
    }

    /* Hand the rewritten packet to the kernel, which routes it to the client */
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
