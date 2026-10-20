//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

/*
 * BPF Hash Map storing blocked destination TCP ports
 * Key: 16-bit port in host byte order
 * Value: 64-bit drop count
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u64);
} blocked_ports SEC(".maps");

/*
 * BPF Hash Map storing blocked destination IPv4 addresses
 * Key: 32-bit IPv4 in network byte order
 * Value: 64-bit drop count
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ips SEC(".maps");

/*
 * cgroup/connect4 Hook:
 * Intercepts connect() syscall for IPv4 sockets inside the target cgroup.
 * Returning 0 denies the connection (syscall returns -EPERM).
 * Returning 1 permits the connection.
 */
SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    if (ctx->family != AF_INET) {
        return 1;
    }

    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = bpf_ntohs((__u16)ctx->user_port);

    /* Check if destination IP is blocked */
    __u64 *ip_drop_count = bpf_map_lookup_elem(&blocked_ips, &dst_ip);
    if (ip_drop_count) {
        __sync_fetch_and_add(ip_drop_count, 1);
        return 0; /* Deny: -EPERM */
    }

    /* Check if destination Port is blocked */
    __u64 *port_drop_count = bpf_map_lookup_elem(&blocked_ports, &dst_port);
    if (port_drop_count) {
        __sync_fetch_and_add(port_drop_count, 1);
        return 0; /* Deny: -EPERM */
    }

    return 1; /* Permit */
}

char LICENSE[] SEC("license") = "GPL";
