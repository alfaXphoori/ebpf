//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

/*
 * 4-tuple key identifying one end of a TCP connection.
 *
 * Encoding (IMPORTANT - must be identical in sockops and sk_msg):
 *   sip/dip   : IPv4 address in network byte order (as provided by the kernel)
 *   sport/dport: TCP port in HOST byte order
 *
 * Kernel UAPI quirk (struct bpf_sock_ops / struct sk_msg_md):
 *   local_port  -> host byte order        (e.g. 5201)
 *   remote_port -> network byte order,    use bpf_ntohl(remote_port)
 *                  stored in the upper 16 bits on little-endian
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
 * Cumulative metrics (index layout shared with main.go)
 */
enum {
    STAT_REDIRECT_MSGS  = 0, /* sendmsg() redirected socket-to-socket   */
    STAT_REDIRECT_BYTES = 1, /* bytes redirected                        */
    STAT_FALLBACK_MSGS  = 2, /* peer not in sock_hash -> normal TCP path */
    STAT_FALLBACK_BYTES = 3, /* bytes sent through the normal TCP path  */
    STAT_SOCKS_ADDED    = 4, /* established sockets inserted to map     */
    STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} bypass_stats SEC(".maps");

static __always_inline void stat_add(__u32 idx, __u64 val)
{
    __u64 *cnt = bpf_map_lookup_elem(&bypass_stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, val);
}

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
            .sport = skops->local_port,            /* already host order   */
            .dport = bpf_ntohl(skops->remote_port), /* network -> host order */
        };

        /* Register socket into sock_hash (this also attaches the sk_msg program to it) */
        if (bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST) == 0) {
            stat_add(STAT_SOCKS_ADDED, 1);
        }
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

    /*
     * Reverse 4-tuple: the PEER socket registered itself with
     * sip = our dip, sport = our dport, ... so swap local/remote.
     */
    struct sock_key key = {
        .sip = msg->remote_ip4,
        .dip = msg->local_ip4,
        .sport = bpf_ntohl(msg->remote_port), /* network -> host order */
        .dport = msg->local_port,             /* already host order   */
    };

    /*
     * Direct redirect into the peer socket's ingress queue.
     * bpf_msg_redirect_hash() returns SK_PASS on success, SK_DROP if the key
     * is not found. On failure we fall back to SK_PASS so the regular TCP/IP
     * stack delivers the data (e.g. remote peer, or connection established
     * before this program was attached).
     */
    long ret = bpf_msg_redirect_hash(msg, &sock_hash, &key, BPF_F_INGRESS);
    if (ret == SK_PASS) {
        stat_add(STAT_REDIRECT_MSGS, 1);
        stat_add(STAT_REDIRECT_BYTES, msg->size);
        return SK_PASS;
    }

    stat_add(STAT_FALLBACK_MSGS, 1);
    stat_add(STAT_FALLBACK_BYTES, msg->size);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
