// SPDX-License-Identifier: GPL-2.0
// packet_counter.bpf.c — XDP program that counts packets per IP protocol.
//
// Uses BPF_ARRAY indexed by IP protocol number (0-255).
// Always returns XDP_PASS so packets continue normally.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// Protocol index constants (for well-known protocols)
#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP   17
#define PROTO_OTHER 255

BPF_ARRAY(proto_count, u64, 256);

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

    u32 proto = ip->protocol;
    u64 *count = proto_count.lookup(&proto);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return XDP_PASS;
}
