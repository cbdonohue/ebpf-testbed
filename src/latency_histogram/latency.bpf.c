// SPDX-License-Identifier: GPL-2.0
// latency.bpf.c — Block I/O latency histogram
//
// Attaches kprobes to blk_mq_start_request and blk_mq_end_request.
// Records per-request latency (ns) in a log2 histogram array.
//
// Rewritten from BCC-style (BPF_HASH, BPF_HISTOGRAM macros) to libbpf-style.
// BPF_HISTOGRAM(io_latency_ns) — replaced with BPF_MAP_TYPE_ARRAY below.
// blk_account_io_start / blk_account_io_done — available as kprobe targets
// via the kprobe/blk_account_io_start and kretprobe/blk_account_io_done sections.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Map: u64 request pointer -> start timestamp (ns)
// Replaces BCC BPF_HASH(start_ts, struct request *, u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 4096);
} start_ts SEC(".maps");

// Log2 histogram: 64 buckets for latency in nanoseconds
// Replaces BCC BPF_HISTOGRAM(io_latency_ns, u64)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} io_latency_ns SEC(".maps");

// Compute log2 of a 64-bit value (returns 0 for 0)
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

// kprobe on blk_account_io_start — record start timestamp keyed by ctx pointer
SEC("kprobe/blk_account_io_start")
int kprobe__blk_account_io_start(void *ctx)
{
    __u64 key = (__u64)(unsigned long)ctx;
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ts, &key, &ts, BPF_ANY);
    return 0;
}

// kretprobe on blk_account_io_done — compute delta and update histogram
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
    if (bucket) {
        __sync_fetch_and_add(bucket, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
