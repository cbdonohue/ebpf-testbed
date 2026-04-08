#!/usr/bin/env python3
"""
syscall_tracer.py — BCC loader for syscall_tracer.bpf.c

Traces every execve() syscall system-wide and prints the process name,
PID, and the filename being executed. Must be run as root.
"""

import os
import sys
import ctypes
from bcc import BPF

BPF_SRC = os.path.join(os.path.dirname(__file__), "syscall_tracer.bpf.c")

TASK_COMM_LEN = 16


class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("pid",      ctypes.c_uint32),
        ("tgid",     ctypes.c_uint32),
        ("comm",     ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * 256),
    ]


def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents
    comm     = event.comm.decode("utf-8", errors="replace")
    filename = event.filename.decode("utf-8", errors="replace")
    print(f"PID={event.pid:<7} TGID={event.tgid:<7} COMM={comm:<16} FILE={filename}")


def main():
    if os.geteuid() != 0:
        print("Error: must be run as root.", file=sys.stderr)
        sys.exit(1)

    print("Loading eBPF syscall tracer...")
    b = BPF(src_file=BPF_SRC)
    b["exec_events"].open_perf_buffer(handle_event)

    print(f"{'PID':<12} {'TGID':<12} {'COMM':<20} FILE")
    print("-" * 70)
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")


if __name__ == "__main__":
    main()
