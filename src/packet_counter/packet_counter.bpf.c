// SPDX-License-Identifier: GPL-2.0
// packet_counter.bpf.c — XDP program that counts packets per IP protocol.
//
// Uses BPF_MAP_TYPE_ARRAY indexed by IP protocol number (0-255).
// Always returns XDP_PASS so packets continue normally.
//
// Rewritten from BCC-style (BPF_ARRAY macro) to libbpf-style BTF maps.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// libbpf-style map definition (replaces BCC BPF_ARRAY macro)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} proto_count SEC(".maps");

SEC("xdp")
int xdp_packet_counter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 proto = ip->protocol;
    if (proto >= 256)
        return XDP_PASS;

    __u64 *count = bpf_map_lookup_elem(&proto_count, &proto);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
