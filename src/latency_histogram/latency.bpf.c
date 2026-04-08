// SPDX-License-Identifier: GPL-2.0
// latency.bpf.c — Block I/O latency histogram with ring buffer events
//
// Attaches kprobes to blk_account_io_start and blk_account_io_done.
// Records per-request latency (ns) in a log2 histogram array AND
// emits individual latency events via a ring buffer.
//
// Upgraded from BCC-style (BPF_HASH, histogram macros) to libbpf CO-RE
// with vmlinux.h and BPF_MAP_TYPE_RINGBUF for event streaming.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct latency_event {
    __u64 delta_ns;
    __u32 slot;
};

// Map: u64 request pointer -> start timestamp (ns)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 4096);
} start_ts SEC(".maps");

// Log2 histogram: 64 buckets for latency in nanoseconds
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} io_latency_ns SEC(".maps");

// Ring buffer for streaming individual latency events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 r = 0;
    if (v >= (1ULL << 32)) { v >>= 32; r += 32; }
    if (v >= (1ULL << 16)) { v >>= 16; r += 16; }
    if (v >= (1ULL <<  8)) { v >>=  8; r +=  8; }
    if (v >= (1ULL <<  4)) { v >>=  4; r +=  4; }
    if (v >= (1ULL <<  2)) { v >>=  2; r +=  2; }
    if (v >= (1ULL <<  1)) {           r +=  1; }
    return r;
}

SEC("kprobe/blk_account_io_start")
int kprobe__blk_account_io_start(void *ctx)
{
    __u64 key = (__u64)(unsigned long)ctx;
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ts, &key, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/blk_account_io_done")
int kretprobe__blk_account_io_done(void *ctx)
{
    __u64 key = (__u64)(unsigned long)ctx;
    __u64 *tsp = bpf_map_lookup_elem(&start_ts, &key);
    if (!tsp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start_ts, &key);

    __u32 slot = log2_u64(delta);
    if (slot >= 64)
        slot = 63;

    __u64 *bucket = bpf_map_lookup_elem(&io_latency_ns, &slot);
    if (bucket)
        __sync_fetch_and_add(bucket, 1);

    struct latency_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->delta_ns = delta;
        e->slot     = slot;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
