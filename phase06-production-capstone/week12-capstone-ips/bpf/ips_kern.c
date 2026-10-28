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
#define METRIC_ALERTS_LOST        4   /* ringbuf full: alert could not be reserved */

/* Alert actions (what the data plane did to the offending source) */
#define ACTION_BANNED        1   /* inserted into blacklist_map (auto-ban enabled) */
#define ACTION_RATE_LIMITED  2   /* only packets above the threshold are dropped */

/* Configuration Map Indices */
#define CONF_SYN_LIMIT    0
#define CONF_ICMP_LIMIT   1
#define CONF_AUTOBAN_EN   2   /* 0 = rate-limit only, 1 = auto-ban offenders */
#define CONF_WINDOW_NS    3
#define CONF_BAN_TTL_NS   4   /* 0 = bans never expire in the data plane */
#define CONF_MAX          5

/* Defaults used when a config slot is still 0 (ARRAY maps are zero-initialised) */
#define DEFAULT_SYN_LIMIT   100
#define DEFAULT_ICMP_LIMIT  50
#define DEFAULT_WINDOW_NS   1000000000ULL /* 1 second */

/* Value struct for Blacklist Map */
struct block_entry {
    __u64 blocked_at_ns;   /* CLOCK_MONOTONIC (bpf_ktime_get_ns) - used for TTL expiry */
    __u64 drop_count;
    __u64 drop_bytes;
    __u32 reason;
    __u32 pad;
};

/* Value struct for Rate Tracker (Fixed / Tumbling Window counter) */
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
    __u8  action;   /* ACTION_BANNED or ACTION_RATE_LIMITED */
    __u8  pad;
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

/* 3. Per-CPU Telemetry Metrics: 0=Passed, 1=Drop BL, 2=Drop RateLimit, 3=Total Bytes, 4=Alerts Lost */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
} ips_metrics SEC(".maps");

/* 4. Security Alerts Ring Buffer (4 MB) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MB */
} ips_events SEC(".maps");

/* 5. Configuration Map: 0=SYN Limit, 1=ICMP Limit, 2=Auto-ban, 3=Window NS, 4=Ban TTL NS */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CONF_MAX);
} config_map SEC(".maps");

/*
 * Helper to increment Per-CPU metrics:
 * each CPU owns its own slot, so a plain += is safe (no atomics needed).
 */
static __always_inline void inc_metric(__u32 idx, __u64 delta)
{
    __u64 *val = bpf_map_lookup_elem(&ips_metrics, &idx);
    if (val) {
        *val += delta;
    }
}

/* Helper to read a config slot; returns 0 if the slot does not exist */
static __always_inline __u64 get_conf(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&config_map, &idx);
    return val ? *val : 0;
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

    /*
     * 3. Check Blacklist Map
     * blacklist_map is a shared (non per-CPU) hash: packets from the same source
     * can hit this entry on several CPUs at once, so the counters must be
     * updated with atomic adds (__sync_fetch_and_add -> BPF_ATOMIC_ADD).
     */
    struct block_entry *b_entry = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (b_entry) {
        __u64 ban_ttl = get_conf(CONF_BAN_TTL_NS);
        __u64 banned_for = now - b_entry->blocked_at_ns;

        /*
         * Data-plane TTL: an expired ban is ignored here even if the Go agent
         * has not yet removed it (e.g. its ringbuf alert was lost). The agent's
         * reaper deletes the stale entry on its next sweep.
         */
        if (ban_ttl == 0 || now < b_entry->blocked_at_ns || banned_for < ban_ttl) {
            __sync_fetch_and_add(&b_entry->drop_count, 1);
            __sync_fetch_and_add(&b_entry->drop_bytes, pkt_len);
            inc_metric(METRIC_DROPPED_BLACKLIST, 1);
            inc_metric(METRIC_TOTAL_BYTES, pkt_len);
            return XDP_DROP;
        }
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

    /* 5. Read Configuration (0 = not configured -> use default) */
    __u64 syn_threshold = get_conf(CONF_SYN_LIMIT);
    __u64 icmp_threshold = get_conf(CONF_ICMP_LIMIT);
    __u64 window_ns = get_conf(CONF_WINDOW_NS);
    __u64 autoban_en = get_conf(CONF_AUTOBAN_EN);

    if (syn_threshold == 0)
        syn_threshold = DEFAULT_SYN_LIMIT;
    if (icmp_threshold == 0)
        icmp_threshold = DEFAULT_ICMP_LIMIT;
    if (window_ns == 0)
        window_ns = DEFAULT_WINDOW_NS;

    /* 6. Update Rate Tracker */
    struct rate_state *r_state = bpf_map_lookup_elem(&rate_tracker, &src_ip);
    if (!r_state) {
        struct rate_state initial_state = {
            .window_start_ns = now,
        };
        /* BPF_NOEXIST: if another CPU created the entry first, keep its counters */
        bpf_map_update_elem(&rate_tracker, &src_ip, &initial_state, BPF_NOEXIST);
        r_state = bpf_map_lookup_elem(&rate_tracker, &src_ip);
        if (!r_state) {
            inc_metric(METRIC_PASSED, 1);
            inc_metric(METRIC_TOTAL_BYTES, pkt_len);
            return XDP_PASS;
        }
    }

    /*
     * Fixed (Tumbling) Window: counters are reset once the current window
     * is older than window_ns. Only the CPU that wins the compare-and-swap on
     * window_start_ns performs the reset, so concurrent CPUs cannot reset the
     * same window twice. (now < start can happen when another CPU just moved
     * the window forward with a slightly later timestamp - not an expiry.)
     */
    __u64 start = r_state->window_start_ns;
    if (now > start && now - start > window_ns) {
        if (__sync_val_compare_and_swap(&r_state->window_start_ns, start, now) == start) {
            r_state->syn_count = 0;
            r_state->icmp_count = 0;
        }
    }

    /* Atomic increment; the returned old value + 1 is this packet's position in the window */
    __u32 count;
    __u64 threshold;
    __u8 violation_reason;
    if (is_syn) {
        count = __sync_fetch_and_add(&r_state->syn_count, 1) + 1;
        threshold = syn_threshold;
        violation_reason = REASON_SYN_FLOOD;
    } else {
        count = __sync_fetch_and_add(&r_state->icmp_count, 1) + 1;
        threshold = icmp_threshold;
        violation_reason = REASON_ICMP_FLOOD;
    }

    /* 7. Threshold Violation Detection */
    if (count > threshold) {
        __u8 action = ACTION_RATE_LIMITED;

        if (autoban_en) {
            /* Auto-Ban: Insert offending IP into Blacklist Map immediately */
            struct block_entry new_ban = {
                .blocked_at_ns = now,
                .drop_count = 1,
                .drop_bytes = pkt_len,
                .reason = violation_reason,
                .pad = 0,
            };
            bpf_map_update_elem(&blacklist_map, &src_ip, &new_ban, BPF_ANY);
            action = ACTION_BANNED;
        }

        /*
         * Stream alert via Ring Buffer to User Space.
         * Rate-limit-only mode drops every packet above the threshold, so only
         * the first violating packet of each window raises an alert.
         */
        if (autoban_en || count == threshold + 1) {
            struct ips_alert *alert = bpf_ringbuf_reserve(&ips_events, sizeof(*alert), 0);
            if (alert) {
                alert->ts_ns = now;
                alert->src_ip = src_ip;
                alert->dst_ip = dst_ip;
                alert->src_port = src_port;
                alert->dst_port = dst_port;
                alert->proto = iph->protocol;
                alert->reason = violation_reason;
                alert->action = action;
                alert->pad = 0;
                alert->pps = count;
                bpf_ringbuf_submit(alert, 0);
            } else {
                /* Ring buffer full: the ban (if any) still carries blocked_at_ns,
                 * so TTL expiry does not depend on this alert being delivered. */
                inc_metric(METRIC_ALERTS_LOST, 1);
            }
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
