//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Fallback definitions for standalone compiling environments
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

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/*
 * Per-destination port egress telemetry
 */
struct egress_stat {
    __u64 packets;
    __u64 bytes;
};

/*
 * BPF_MAP_TYPE_HASH: egress_stats
 * Tracks egress packet and byte volume classified by L4 destination port.
 * Key: __u16 (destination port in host byte order)
 * Value: struct egress_stat
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, struct egress_stat);
} egress_stats SEC(".maps");

/*
 * TC (Traffic Control) Egress Classifier & Packet Marker
 * Attached to the egress hook of an interface via TC / TCX.
 * Inspects all outbound packets, gathers port metrics, and tags packets with QoS metadata.
 */
SEC("tc")
int tc_egress_prog(struct __sk_buff *skb)
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

    /* 3. Parse Layer 4 Header to extract destination port */
    __u16 dport = 0;
    void *l4 = (void *)iph + ip_hdr_len;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) {
            return TC_ACT_OK;
        }
        dport = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) {
            return TC_ACT_OK;
        }
        dport = bpf_ntohs(udph->dest);
    } else {
        return TC_ACT_OK;
    }

    /*
     * 4. Update Egress Port Statistics
     */
    __u64 pkt_len = (__u64)((char *)data_end - (char *)data);
    struct egress_stat *stat = bpf_map_lookup_elem(&egress_stats, &dport);
    if (stat) {
        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, pkt_len);
    } else {
        struct egress_stat init_stat = {
            .packets = 1,
            .bytes = pkt_len,
        };
        /*
         * BPF_NOEXIST: if another CPU created the entry between our lookup and
         * this update, do not overwrite its counters; add to them instead.
         */
        if (bpf_map_update_elem(&egress_stats, &dport, &init_stat, BPF_NOEXIST) != 0) {
            stat = bpf_map_lookup_elem(&egress_stats, &dport);
            if (stat) {
                __sync_fetch_and_add(&stat->packets, 1);
                __sync_fetch_and_add(&stat->bytes, pkt_len);
            }
        }
    }

    /*
     * 5. QoS Packet Marking in sk_buff
     * Set packet mark (firewall/routing mark) and priority queue metadata.
     */
    skb->mark = 0x42;
    skb->priority = 1;

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
