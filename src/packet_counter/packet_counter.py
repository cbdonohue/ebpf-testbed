#!/usr/bin/env python3
"""
packet_counter.py — BCC loader for packet_counter.bpf.c

Attaches an XDP program to a network interface and displays
per-protocol packet counts. Must be run as root.

Usage:
    sudo python3 packet_counter.py [interface]   (default: eth0)
"""

import os
import sys
import time
import socket
from bcc import BPF

PROTO_NAMES = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    47:  "GRE",
    50:  "ESP",
    58:  "ICMPv6",
    132: "SCTP",
}

BPF_SRC = os.path.join(os.path.dirname(__file__), "packet_counter.bpf.c")


def main():
    if os.geteuid() != 0:
        print("Error: must be run as root.", file=sys.stderr)
        sys.exit(1)

    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    print(f"Loading XDP program on interface: {iface}")

    b = BPF(src_file=BPF_SRC)
    fn = b.load_func("xdp_packet_counter", BPF.XDP)
    b.attach_xdp(iface, fn, 0)

    proto_count = b["proto_count"]
    print("Counting packets per protocol. Hit Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(2)
            print(f"\n{'Protocol':<12} {'Packets':>12}")
            print("-" * 26)
            for proto_num in range(256):
                val = proto_count[proto_num].value
                if val > 0:
                    name = PROTO_NAMES.get(proto_num, f"proto-{proto_num}")
                    print(f"{name:<12} {val:>12,}")
    except KeyboardInterrupt:
        print("\nDetaching XDP program...")
    finally:
        b.remove_xdp(iface, 0)


if __name__ == "__main__":
    main()
