#!/usr/bin/env python3
"""
hello.py — BCC loader for hello.bpf.c

Loads the eBPF kprobe program and prints trace output.
Must be run as root.
"""

import os
import sys
from bcc import BPF

BPF_SRC = os.path.join(os.path.dirname(__file__), "hello.bpf.c")


def main():
    if os.geteuid() != 0:
        print("Error: must be run as root.", file=sys.stderr)
        sys.exit(1)

    print("Loading eBPF program from:", BPF_SRC)
    b = BPF(src_file=BPF_SRC)
    print("Attached kprobe on sys_clone. Tracing... Hit Ctrl-C to stop.\n")

    try:
        b.trace_print()
    except KeyboardInterrupt:
        print("\nDetaching...")


if __name__ == "__main__":
    main()
