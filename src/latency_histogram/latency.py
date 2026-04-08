#!/usr/bin/env python3
"""
latency.py — BCC loader for latency.bpf.c

Measures block I/O request latency and displays a log2 histogram.
Useful for understanding storage latency distribution (NVMe, HDD, etc.).
Must be run as root.

Usage:
    sudo python3 latency.py [interval_seconds]   (default: 5)
"""

import os
import sys
import time
from bcc import BPF

BPF_SRC = os.path.join(os.path.dirname(__file__), "latency.bpf.c")


def main():
    if os.geteuid() != 0:
        print("Error: must be run as root.", file=sys.stderr)
        sys.exit(1)

    interval = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    print("Loading block I/O latency eBPF program...")
    b = BPF(src_file=BPF_SRC)
    dist = b["io_latency_ns"]

    print(f"Tracing block I/O latency. Printing histogram every {interval}s.")
    print("Hit Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(interval)
            print("\n--- Block I/O Latency Histogram (nanoseconds, log2 scale) ---")
            dist.print_log2_hist("latency (ns)")
            dist.clear()
    except KeyboardInterrupt:
        print("\nDetaching...")
        print("\n--- Final Block I/O Latency Histogram ---")
        dist.print_log2_hist("latency (ns)")


if __name__ == "__main__":
    main()
