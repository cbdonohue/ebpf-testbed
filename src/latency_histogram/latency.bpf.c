// SPDX-License-Identifier: GPL-2.0
// latency.bpf.c — Block I/O latency histogram
//
// Attaches kprobes to blk_account_io_start and blk_account_io_done.
// Records per-request latency (ns) in a log2 histogram (BPF_HISTOGRAM).
//
// Note: blk_account_io_start/done were renamed in kernel 5.14+.
// If your kernel is older, adjust to block_rq_insert / block_rq_complete
// tracepoints instead.

#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/time.h>

// Map: struct request* -> start timestamp (ns)
BPF_HASH(start_ts, struct request *, u64);

// Histogram of latencies in log2 buckets (nanoseconds)
BPF_HISTOGRAM(io_latency_ns, u64);

// kprobe: record start time keyed by request pointer
int kprobe__blk_account_io_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    start_ts.update(&req, &ts);
    return 0;
}

// kretprobe alternative entry point — same logic, different symbol name
// for kernels that export blk_account_io_merge_bio
int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req, int error)
{
    u64 *tsp = start_ts.lookup(&req);
    if (!tsp)
        return 0;

    u64 delta = bpf_ktime_get_ns() - *tsp;
    start_ts.delete(&req);

    // Store in log2 histogram (BCC macro handles bucket selection)
    io_latency_ns.increment(bpf_log2l(delta));
    return 0;
}
