#!/usr/bin/env python3
"""
hello.py — libbpf CO-RE loader for hello.bpf.c

Compiles the eBPF kprobe, loads it via bpftool, and reads greeting events
from the ring buffer. Must be run as root.

Architecture: libbpf CO-RE (no BCC dependency)
  - Compiles hello.bpf.c with clang -> BPF object
  - Loads/attaches via bpftool + libbpf
  - Reads events from BPF_MAP_TYPE_RINGBUF
"""

import ctypes
import json
import mmap
import os
import struct
import subprocess
import sys
import tempfile

BPF_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hello.bpf.c")

BPFTOOL     = "/usr/lib/linux-tools/6.17.0-1007-aws/bpftool"
COMMON_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common")
ARCH_INCLUDE = "/usr/include/x86_64-linux-gnu"
RINGBUF_SIZE = 256 * 1024
PAGE_SIZE    = 4096
TASK_COMM_LEN = 16


class HelloEvent(ctypes.Structure):
    _fields_ = [
        ("pid",  ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


def compile_bpf(src, obj):
    subprocess.run(
        ["clang", "-target", "bpf", "-O2", "-g",
         f"-I{COMMON_DIR}", f"-I{ARCH_INCLUDE}",
         "-c", src, "-o", obj],
        check=True,
    )


def ringbuf_read_events(rb_fd, event_cls, callback):
    """Read events from a ring buffer fd until KeyboardInterrupt."""
    ev_size = ctypes.sizeof(event_cls)
    rb = mmap.mmap(rb_fd, RINGBUF_SIZE + 2 * PAGE_SIZE,
                   mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    try:
        import select
        while True:
            select.select([rb_fd], [], [], 0.2)
            rb.seek(0)
            cons = struct.unpack_from("Q", rb.read(8))[0]
            rb.seek(PAGE_SIZE)
            prod = struct.unpack_from("Q", rb.read(8))[0]
            while cons < prod:
                offset = 2 * PAGE_SIZE + (cons & (RINGBUF_SIZE - 1))
                rb.seek(offset)
                hdr_raw = rb.read(8)
                length, flags = struct.unpack_from("II", hdr_raw)
                data_len  = length & ~(1 << 31)
                discarded = bool(length & (1 << 31))
                if not discarded and data_len >= ev_size:
                    raw = rb.read(data_len)
                    ev  = event_cls.from_buffer_copy(raw[:ev_size])
                    callback(ev)
                cons += 8 + ((data_len + 7) & ~7)
                rb.seek(0)
                struct.pack_into("Q", rb, 0, cons)
    finally:
        rb.close()


def main():
    if os.geteuid() != 0:
        print("Error: must be run as root.", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        obj_path = os.path.join(tmpdir, "hello.bpf.o")
        prog_pin = os.path.join(tmpdir, "prog")
        map_pin  = os.path.join(tmpdir, "events")

        print(f"Compiling {BPF_SRC} ...")
        compile_bpf(BPF_SRC, obj_path)

        print("Loading eBPF program ...")
        subprocess.run(
            [BPFTOOL, "prog", "load", obj_path, prog_pin,
             "map", "name", "events", "pinned", map_pin],
            check=True,
        )
        subprocess.run(
            [BPFTOOL, "prog", "attach", "pinned", prog_pin,
             "kprobe", "__x64_sys_clone"],
        )

        info = json.loads(subprocess.run(
            [BPFTOOL, "map", "show", "pinned", map_pin, "--json"],
            capture_output=True, text=True, check=True,
        ).stdout)
        libbpf = ctypes.CDLL("libbpf.so.1")
        libbpf.bpf_map_get_fd_by_id.restype  = ctypes.c_int
        libbpf.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
        rb_fd = libbpf.bpf_map_get_fd_by_id(ctypes.c_uint(info["id"]))

        print("Attached kprobe on __x64_sys_clone. Hit Ctrl-C to stop.\n")
        print(f"{'PID':<10} COMM")
        print("-" * 30)

        def on_event(ev):
            comm = ev.comm.decode("utf-8", errors="replace").rstrip("\x00")
            print(f"{ev.pid:<10} {comm}")

        try:
            ringbuf_read_events(rb_fd, HelloEvent, on_event)
        except KeyboardInterrupt:
            print("\nDetaching...")
        finally:
            os.close(rb_fd)


if __name__ == "__main__":
    main()
