//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Fallback definitions for standard macros if headers are missing or standalone
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

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

/*
 * Statistics for dropped traffic per blocked IP address
 */
struct drop_stats {
    __u64 dropped_packets;
    __u64 dropped_bytes;
};

/*
 * BPF_MAP_TYPE_HASH: blocked_ips
 * Stores IPv4 addresses to block (in network byte order).
 * Key: __u32 (IPv4 source address)
 * Value: struct drop_stats (packet and byte counters)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct drop_stats);
} blocked_ips SEC(".maps");

/*
 * BPF_MAP_TYPE_PERCPU_ARRAY: proto_counters
 * Lock-free per-CPU packet counter indexed by IP protocol number (0-255).
 * Key: __u32 (IP protocol: TCP=6, UDP=17, ICMP=1, etc.)
 * Value: __u64 (packet count on each respective CPU)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} proto_counters SEC(".maps");

/*
 * XDP Packet Filter & Firewall Program
 * Operates at the lowest level of the Linux network driver before sk_buff allocation.
 */
SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    /* Extract memory boundaries for packet data */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /*
     * 1. Layer 2 Ethernet Header Parsing & Verifier Bounds Check
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* Only inspect IPv4 traffic; pass other protocols (e.g. ARP, IPv6) untouched */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /*
     * 2. Layer 3 IPv4 Header Parsing & Bounds Checking
     */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    /* Validate dynamic IP header length (IHL field contains count of 32-bit words) */
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)iph + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    /*
     * 3. Track Protocol Statistics in Per-CPU Array
     */
    __u32 proto = iph->protocol;
    if (proto < 256) {
        __u64 *proto_cnt = bpf_map_lookup_elem(&proto_counters, &proto);
        if (proto_cnt) {
            /* Per-CPU array maps do not require atomic synchronization */
            *proto_cnt += 1;
        }
    }

    /*
     * 4. Layer 4 Transport Header Parsing with Strict Bounds Checks
     */
    void *l4 = (void *)iph + ip_hdr_len;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) {
            return XDP_PASS;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) {
            return XDP_PASS;
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = l4;
        if ((void *)(icmph + 1) > data_end) {
            return XDP_PASS;
        }
    }

    /*
     * 5. Match Source IP Against Blocklist
     */
    __u32 saddr = iph->saddr;
    struct drop_stats *stats = bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (stats) {
        /* Atomically update packet and byte drop counters */
        __sync_fetch_and_add(&stats->dropped_packets, 1);
        __u64 pkt_len = (__u64)((char *)data_end - (char *)data);
        __sync_fetch_and_add(&stats->dropped_bytes, pkt_len);

        /* Drop packet immediately at the network driver level */
        return XDP_DROP;
    }

    /* Allow clean traffic to pass through the network stack */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
