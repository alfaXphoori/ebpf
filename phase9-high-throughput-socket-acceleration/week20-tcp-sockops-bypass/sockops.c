//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

/*
 * 4-tuple key identifying active socket pairs
 */
struct sock_key {
    __u32 sip;
    __u32 dip;
    __u32 sport;
    __u32 dport;
};

/*
 * BPF_MAP_TYPE_SOCKHASH: In-kernel hash map holding active TCP socket references
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_hash SEC(".maps");

/*
 * Cumulative metrics: [0] = accelerated messages, [1] = accelerated bytes
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} bypass_stats SEC(".maps");

/*
 * Hook 1: BPF_PROG_TYPE_SOCK_OPS
 * Intercepts TCP connection lifecycle events to record socket descriptors
 */
SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *skops)
{
    if (skops->family != AF_INET) {
        return 0;
    }

    __u32 op = skops->op;

    /* Hook established sockets (both active outgoing and passive incoming) */
    if (op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        struct sock_key key = {
            .sip = skops->local_ip4,
            .dip = skops->remote_ip4,
            .sport = bpf_ntohl(skops->local_port),
            .dport = skops->remote_port >> 16,
        };

        /* Register socket into sock_hash */
        bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST);
    }

    return 0;
}

/*
 * Hook 2: BPF_PROG_TYPE_SK_MSG
 * Intercepts sendmsg() payload and redirects directly into peer socket queue
 */
SEC("sk_msg")
int bpf_sk_msg_handler(struct sk_msg_md *msg)
{
    if (msg->family != AF_INET) {
        return SK_PASS;
    }

    /* Reverse 4-tuple key to find the receiving peer's socket */
    struct sock_key key = {
        .sip = msg->remote_ip4,
        .dip = msg->local_ip4,
        .sport = msg->remote_port >> 16,
        .dport = bpf_ntohl(msg->local_port),
    };

    /* Update metrics */
    __u32 k0 = 0, k1 = 1;
    __u64 *msg_cnt = bpf_map_lookup_elem(&bypass_stats, &k0);
    if (msg_cnt) __sync_fetch_and_add(msg_cnt, 1);

    __u64 *byte_cnt = bpf_map_lookup_elem(&bypass_stats, &k1);
    if (byte_cnt) __sync_fetch_and_add(byte_cnt, msg->size);

    /*
     * Direct redirect into peer socket queue.
     * If the peer socket is not found, fallback to SK_PASS to let the standard
     * Linux network stack handle delivery safely.
     */
    long ret = bpf_msg_redirect_hash(msg, &sock_hash, &key, BPF_F_INGRESS);
    if (ret != SK_PASS) {
        return SK_PASS;
    }
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
