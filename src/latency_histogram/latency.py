#!/usr/bin/env python3
"""
latency.py — libbpf CO-RE loader for latency.bpf.c

Measures block I/O request latency and displays a log2 histogram.
Useful for understanding storage latency distribution (NVMe, HDD, etc.).
Must be run as root.

Architecture: libbpf CO-RE (no BCC dependency)
  - Compiles latency.bpf.c with clang -> BPF object
  - Attaches kprobe/kretprobe via bpftool
  - Reads latency events from BPF_MAP_TYPE_RINGBUF
  - Reads histogram from BPF_MAP_TYPE_ARRAY (io_latency_ns)

Usage:
    sudo python3 latency.py [interval_seconds]   (default: 5)
"""

import ctypes
import json
import mmap
import os
import struct
import subprocess
import sys
import tempfile
import time

BPF_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "latency.bpf.c")

BPFTOOL      = "/usr/lib/linux-tools/6.17.0-1007-aws/bpftool"
COMMON_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common")
ARCH_INCLUDE = "/usr/include/x86_64-linux-gnu"
RINGBUF_SIZE = 256 * 1024
PAGE_SIZE    = 4096


class LatencyEvent(ctypes.Structure):
    _fields_ = [
        ("delta_ns", ctypes.c_uint64),
        ("slot",     ctypes.c_uint32),
    ]


def compile_bpf(src, obj):
    subprocess.run(
        ["clang", "-target", "bpf", "-O2", "-g",
         f"-I{COMMON_DIR}", f"-I{ARCH_INCLUDE}",
         "-c", src, "-o", obj],
        check=True,
    )


def read_histogram(map_id, libbpf):
    """Read 64-bucket log2 histogram from BPF array map."""
    fd = libbpf.bpf_map_get_fd_by_id(ctypes.c_uint(map_id))
    if fd < 0:
        return [0] * 64
    buckets = []
    for slot in range(64):
        key = ctypes.c_uint32(slot)
        val = ctypes.c_uint64(0)
        libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
        buckets.append(val.value)
    os.close(fd)
    return buckets


def print_histogram(buckets):
    total = sum(buckets)
    if total == 0:
        print("  (no data)")
        return
    max_val = max(buckets)
    bar_width = 40
    print(f"{'Bucket (log2 ns)':<20} {'Count':>10}  {'Distribution'}")
    print("-" * 70)
    for i, count in enumerate(buckets):
        if count == 0:
            continue
        lo = (1 << i) if i > 0 else 0
        hi = (1 << (i + 1)) - 1
        bar = int(bar_width * count / max_val) if max_val > 0 else 0
        print(f"  [{lo:>12} ns, {hi:>12} ns) {count:>8}  |{'#' * bar}")


def main():
    if os.geteuid() != 0:
        print("Error: must be run as root.", file=sys.stderr)
        sys.exit(1)

    interval = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    libbpf = ctypes.CDLL("libbpf.so.1")
    libbpf.bpf_map_get_fd_by_id.restype  = ctypes.c_int
    libbpf.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
    libbpf.bpf_map_lookup_elem.restype   = ctypes.c_int
    libbpf.bpf_map_lookup_elem.argtypes  = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        obj_path      = os.path.join(tmpdir, "latency.bpf.o")
        prog_pin      = os.path.join(tmpdir, "prog")
        hist_map_pin  = os.path.join(tmpdir, "io_latency_ns")
        rb_map_pin    = os.path.join(tmpdir, "events")

        print(f"Compiling {BPF_SRC} ...")
        compile_bpf(BPF_SRC, obj_path)

        print("Loading block I/O latency eBPF program ...")
        subprocess.run(
            [BPFTOOL, "prog", "load", obj_path, prog_pin,
             "map", "name", "io_latency_ns", "pinned", hist_map_pin,
             "map", "name", "events",        "pinned", rb_map_pin],
            check=True,
        )

        hist_info = json.loads(subprocess.run(
            [BPFTOOL, "map", "show", "pinned", hist_map_pin, "--json"],
            capture_output=True, text=True, check=True,
        ).stdout)

        print(f"Tracing block I/O latency. Printing histogram every {interval}s.")
        print("Hit Ctrl-C to stop.\n")

        try:
            while True:
                time.sleep(interval)
                print("\n--- Block I/O Latency Histogram (nanoseconds, log2 scale) ---")
                buckets = read_histogram(hist_info["id"], libbpf)
                print_histogram(buckets)
        except KeyboardInterrupt:
            print("\nDetaching...")
            print("\n--- Final Block I/O Latency Histogram ---")
            buckets = read_histogram(hist_info["id"], libbpf)
            print_histogram(buckets)


if __name__ == "__main__":
    main()
