# ebpf-testbed

A collection of eBPF programs for learning and experimentation — covering XDP packet processing, kprobe-based syscall tracing, and block I/O latency histograms, all with Python userspace loaders via BCC.

## What is eBPF?

eBPF (extended Berkeley Packet Filter) is a Linux kernel technology that lets you run sandboxed programs in the kernel without changing kernel source code or loading kernel modules. Programs are verified for safety by the kernel before execution, then JIT-compiled for near-native performance. It powers tools like Cilium, Falco, bpftrace, and many observability platforms.

---

## Prerequisites

| Requirement | Details |
|---|---|
| Linux kernel | ≥ 5.4 (5.15+ recommended) |
| BCC | `python3-bpfcc` or built from source |
| Clang/LLVM | ≥ 10 (`clang`, `llvm`, `libclang-dev`) |
| Kernel headers | `linux-headers-$(uname -r)` |
| Python | 3.6+ |
| Root access | All loaders must run as root |

See [docs/setup.md](docs/setup.md) for full installation instructions.

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/cbdonohue/ebpf-testbed.git
cd ebpf-testbed

# Install Python dependencies
pip install -r requirements.txt

# Run the hello world example
cd src/hello_world
sudo python3 hello.py

# Run the syscall tracer
cd src/syscall_tracer
sudo python3 syscall_tracer.py

# Count packets per protocol on eth0
cd src/packet_counter
sudo python3 packet_counter.py eth0

# Block I/O latency histogram (refresh every 5s)
cd src/latency_histogram
sudo python3 latency.py

# Run static tests (no root needed)
make test
```

---

## Architecture

![eBPF Testbed Architecture](docs/architecture.png)

The diagram shows the full stack: Python BCC loaders in userspace compile `.bpf.c` programs via clang/llvm into eBPF bytecode, which passes through the kernel verifier before being attached to hook points (kprobe, XDP, tracepoint). Data flows back to userspace via BPF maps (shared kernel ↔ userspace memory).

---

## Programs

| Program | Type | What It Does |
|---|---|---|
| [hello_world](src/hello_world/) | kprobe | Attaches to `sys_clone`, prints "Hello from eBPF!" via `bpf_trace_printk` on every process spawn |
| [packet_counter](src/packet_counter/) | XDP | Parses Ethernet + IP headers, counts packets per IP protocol (TCP/UDP/ICMP/other) using `BPF_ARRAY` |
| [syscall_tracer](src/syscall_tracer/) | tracepoint | Hooks `sys_enter_execve`, captures process name + PID, emits to userspace via perf buffer |
| [latency_histogram](src/latency_histogram/) | kprobe/kretprobe | Measures block I/O request latency, stores in a log2 `BPF_HISTOGRAM` |

---

## Project Structure

```
ebpf-testbed/
├── README.md
├── Makefile
├── .gitignore
├── requirements.txt
├── src/
│   ├── hello_world/          # Minimal kprobe
│   ├── packet_counter/       # XDP packet stats
│   ├── syscall_tracer/       # execve tracing
│   └── latency_histogram/    # Block I/O latency
├── tests/
│   ├── test_syntax.py        # Static checks on .bpf.c files
│   └── test_loaders.py       # Smoke tests for Python loaders
└── docs/
    ├── setup.md              # Installation + kernel config
    └── examples.md           # Usage examples + expected output
```

---

## Documentation

- [Setup Guide](docs/setup.md) — kernel requirements, BCC install for Ubuntu 22.04/24.04, common issues
- [Usage Examples](docs/examples.md) — how to run each program with expected output

---

## License

GPL-2.0 — consistent with the Linux kernel's licensing requirements for eBPF programs.
