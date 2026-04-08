#!/usr/bin/env python3
"""
packet_counter.py — libbpf CO-RE loader for packet_counter.bpf.c

Attaches an XDP program to a network interface and displays
per-protocol packet counts. Must be run as root.

Architecture: libbpf CO-RE (no BCC dependency)
  - Compiles packet_counter.bpf.c with clang -> BPF object
  - Loads XDP program via bpftool
  - Reads proto_count BPF_MAP_TYPE_ARRAY directly via libbpf

Usage:
    sudo python3 packet_counter.py [interface]   (default: eth0)
"""

import ctypes
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

BPF_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "packet_counter.bpf.c")

BPFTOOL      = "/usr/lib/linux-tools/6.17.0-1007-aws/bpftool"
COMMON_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common")
ARCH_INCLUDE = "/usr/include/x86_64-linux-gnu"

PROTO_NAMES = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    47:  "GRE",
    50:  "ESP",
    58:  "ICMPv6",
    132: "SCTP",
}


def compile_bpf(src, obj):
    subprocess.run(
        ["clang", "-target", "bpf", "-O2", "-g",
         f"-I{COMMON_DIR}", f"-I{ARCH_INCLUDE}",
         "-c", src, "-o", obj],
        check=True,
    )


def read_proto_counts(map_id, libbpf):
    fd = libbpf.bpf_map_get_fd_by_id(ctypes.c_uint(map_id))
    counts = {}
    for proto in range(256):
        key = ctypes.c_uint32(proto)
        val = ctypes.c_uint64(0)
        ret = libbpf.bpf_map_lookup_elem(fd, ctypes.byref(key), ctypes.byref(val))
        if ret == 0 and val.value > 0:
            counts[proto] = val.value
    os.close(fd)
    return counts


def main():
    if os.geteuid() != 0:
        print("Error: must be run as root.", file=sys.stderr)
        sys.exit(1)

    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"

    libbpf = ctypes.CDLL("libbpf.so.1")
    libbpf.bpf_map_get_fd_by_id.restype  = ctypes.c_int
    libbpf.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
    libbpf.bpf_map_lookup_elem.restype   = ctypes.c_int
    libbpf.bpf_map_lookup_elem.argtypes  = [
        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        obj_path = os.path.join(tmpdir, "packet_counter.bpf.o")
        prog_pin = os.path.join(tmpdir, "prog")
        map_pin  = os.path.join(tmpdir, "proto_count")

        print(f"Compiling {BPF_SRC} ...")
        compile_bpf(BPF_SRC, obj_path)

        print(f"Loading XDP program on interface: {iface}")
        subprocess.run(
            [BPFTOOL, "prog", "load", obj_path, prog_pin,
             "map", "name", "proto_count", "pinned", map_pin],
            check=True,
        )
        # Attach XDP to interface
        xdp_id_out = subprocess.run(
            [BPFTOOL, "prog", "show", "pinned", prog_pin, "--json"],
            capture_output=True, text=True,
        ).stdout
        prog_id = json.loads(xdp_id_out).get("id")
        if prog_id:
            subprocess.run(
                ["ip", "link", "set", "dev", iface, "xdp",
                 "object", obj_path, "section", "xdp"],
            )

        map_info = json.loads(subprocess.run(
            [BPFTOOL, "map", "show", "pinned", map_pin, "--json"],
            capture_output=True, text=True, check=True,
        ).stdout)

        print("Counting packets per protocol. Hit Ctrl-C to stop.\n")

        try:
            while True:
                time.sleep(2)
                counts = read_proto_counts(map_info["id"], libbpf)
                if counts:
                    print(f"\n{'Protocol':<12} {'Packets':>12}")
                    print("-" * 26)
                    for proto, count in sorted(counts.items()):
                        name = PROTO_NAMES.get(proto, f"proto-{proto}")
                        print(f"{name:<12} {count:>12,}")
        except KeyboardInterrupt:
            print("\nDetaching XDP program...")
        finally:
            subprocess.run(
                ["ip", "link", "set", "dev", iface, "xdp", "off"],
            )


if __name__ == "__main__":
    main()
