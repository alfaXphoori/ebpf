//go:build ignore
// +build ignore

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Reason Codes */
#define REASON_BLACKLIST   1
#define REASON_SYN_FLOOD   2
#define REASON_ICMP_FLOOD  3
#define REASON_MANUAL_BAN  4

/* Metrics Indices */
#define METRIC_PASSED             0
#define METRIC_DROPPED_BLACKLIST  1
#define METRIC_DROPPED_RATELIMIT  2
#define METRIC_TOTAL_BYTES        3

/* Configuration Map Indices */
#define CONF_SYN_LIMIT    0
#define CONF_ICMP_LIMIT   1
#define CONF_AUTOBAN_EN   2
#define CONF_WINDOW_NS    3

/* Value struct for Blacklist Map */
struct block_entry {
    __u64 blocked_at_ns;
    __u64 drop_count;
    __u64 drop_bytes;
    __u32 reason;
    __u32 pad;
};

/* Value struct for Rate Tracker */
struct rate_state {
    __u64 window_start_ns;
    __u32 syn_count;
    __u32 icmp_count;
};

/* Event struct sent via Ring Buffer upon alert */
struct ips_alert {
    __u64 ts_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  reason;
    __u16 pad;
    __u32 pps;
};

/* 1. Blacklist LRU Hash Map: Key = IPv4 (be32), Value = struct block_entry */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct block_entry);
    __uint(max_entries, 65536);
} blacklist_map SEC(".maps");

/* 2. Rate Tracker LRU Hash Map: Key = IPv4 (be32), Value = struct rate_state */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct rate_state);
    __uint(max_entries, 65536);
} rate_tracker SEC(".maps");

/* 3. Per-CPU Telemetry Metrics: 0=Passed, 1=Drop BL, 2=Drop RateLimit, 3=Total Bytes */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} ips_metrics SEC(".maps");

/* 4. Security Alerts Ring Buffer (4 MB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MB */
} ips_events SEC(".maps");

/* 5. Configuration Map: 0=SYN Limit, 1=ICMP Limit, 2=Auto-ban, 3=Window NS */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} config_map SEC(".maps");

/* Helper to increment Per-CPU metrics safely */
static __always_inline void inc_metric(__u32 idx, __u64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&ips_metrics, &idx);
    if (val) {
        *val += delta;
    }
}

/*
 * Smart IPS XDP Main Kernel Program:
 * High-speed L3/L4 inspection, blacklisting, and adaptive flood rate limiting.
 */
SEC("xdp")
int xdp_smart_ips(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = (__u64)(data_end - data);

    /* 1. Ethernet Bounds Check */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    /* Only inspect IPv4 traffic */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_metric(METRIC_PASSED, 1);
        inc_metric(METRIC_TOTAL_BYTES, pkt_len);
        return XDP_PASS;
    }

    /* 2. IPv4 Bounds Check */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    /* Validate variable IPv4 Header Length (IHL) */
    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }
    if ((void *)iph + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u64 now = bpf_ktime_get_ns();

    /* 3. Check Blacklist Map */
    struct block_entry *b_entry = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (b_entry) {
        b_entry->drop_count++;
        b_entry->drop_bytes += pkt_len;
        inc_metric(METRIC_DROPPED_BLACKLIST, 1);
        inc_metric(METRIC_TOTAL_BYTES, pkt_len);
        return XDP_DROP;
    }

    /* 4. Dynamic Flood Rate Limiting for TCP SYN & ICMP */
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 is_syn = 0;
    __u8 is_icmp_echo = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void *)(tcph + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcph->source);
        dst_port = bpf_ntohs(tcph->dest);

        /* Inspect SYN flag without ACK */
        if (tcph->syn && !tcph->ack) {
            is_syn = 1;
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (void *)iph + ip_hdr_len;
        if ((void *)(icmph + 1) > data_end) {
            return XDP_PASS;
        }
        if (icmph->type == ICMP_ECHO) {
            is_icmp_echo = 1;
        }
    } else {
        /* Other protocols pass directly */
        inc_metric(METRIC_PASSED, 1);
        inc_metric(METRIC_TOTAL_BYTES, pkt_len);
        return XDP_PASS;
    }

    /* If neither SYN nor ICMP echo, pass */
    if (!is_syn && !is_icmp_echo) {
        inc_metric(METRIC_PASSED, 1);
        inc_metric(METRIC_TOTAL_BYTES, pkt_len);
        return XDP_PASS;
    }

    /* 5. Read Configuration Limits */
    __u32 syn_idx = CONF_SYN_LIMIT;
    __u32 icmp_idx = CONF_ICMP_LIMIT;
    __u32 win_idx = CONF_WINDOW_NS;
    __u64 *cfg_syn = bpf_map_lookup_elem(&config_map, &syn_idx);
    __u64 *cfg_icmp = bpf_map_lookup_elem(&config_map, &icmp_idx);
    __u64 *cfg_win = bpf_map_lookup_elem(&config_map, &win_idx);

    __u32 syn_threshold = cfg_syn ? (__u32)*cfg_syn : 100;
    __u32 icmp_threshold = cfg_icmp ? (__u32)*cfg_icmp : 50;
    __u64 window_ns = cfg_win ? *cfg_win : 1000000000ULL; /* 1 sec default */

    /* 6. Update Rate Tracker */
    struct rate_state *r_state = bpf_map_lookup_elem(&rate_tracker, &src_ip);
    struct rate_state initial_state = {0};

    if (!r_state) {
        initial_state.window_start_ns = now;
        if (is_syn) initial_state.syn_count = 1;
        if (is_icmp_echo) initial_state.icmp_count = 1;
        bpf_map_update_elem(&rate_tracker, &src_ip, &initial_state, BPF_ANY);
        inc_metric(METRIC_PASSED, 1);
        inc_metric(METRIC_TOTAL_BYTES, pkt_len);
        return XDP_PASS;
    }

    /* Check if 1-second sliding window expired */
    if (now - r_state->window_start_ns > window_ns) {
        r_state->window_start_ns = now;
        r_state->syn_count = 0;
        r_state->icmp_count = 0;
    }

    if (is_syn) {
        r_state->syn_count++;
    }
    if (is_icmp_echo) {
        r_state->icmp_count++;
    }

    /* 7. Threshold Violation Detection */
    __u8 violation_reason = 0;
    __u32 current_pps = 0;

    if (is_syn && r_state->syn_count > syn_threshold) {
        violation_reason = REASON_SYN_FLOOD;
        current_pps = r_state->syn_count;
    } else if (is_icmp_echo && r_state->icmp_count > icmp_threshold) {
        violation_reason = REASON_ICMP_FLOOD;
        current_pps = r_state->icmp_count;
    }

    if (violation_reason != 0) {
        /* Auto-Ban: Insert offending IP into Blacklist Map immediately */
        struct block_entry new_ban = {
            .blocked_at_ns = now,
            .drop_count = 1,
            .drop_bytes = pkt_len,
            .reason = violation_reason,
            .pad = 0,
        };
        bpf_map_update_elem(&blacklist_map, &src_ip, &new_ban, BPF_ANY);

        /* Stream alert via Ring Buffer to User Space */
        struct ips_alert *alert = bpf_ringbuf_reserve(&ips_events, sizeof(*alert), 0);
        if (alert) {
            alert->ts_ns = now;
            alert->src_ip = src_ip;
            alert->dst_ip = dst_ip;
            alert->src_port = src_port;
            alert->dst_port = dst_port;
            alert->proto = iph->protocol;
            alert->reason = violation_reason;
            alert->pad = 0;
            alert->pps = current_pps;
            bpf_ringbuf_submit(alert, 0);
        }

        inc_metric(METRIC_DROPPED_RATELIMIT, 1);
        inc_metric(METRIC_TOTAL_BYTES, pkt_len);
        return XDP_DROP;
    }

    /* Traffic within acceptable limits */
    inc_metric(METRIC_PASSED, 1);
    inc_metric(METRIC_TOTAL_BYTES, pkt_len);
    return XDP_PASS;
}
