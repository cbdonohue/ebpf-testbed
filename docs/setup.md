# Setup Guide

## Kernel Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Kernel version | ≥ 5.8 | Ring buffer (`BPF_MAP_TYPE_RINGBUF`) requires 5.8+ |
| `CONFIG_BPF=y` | Required | Core eBPF support |
| `CONFIG_BPF_SYSCALL=y` | Required | Allows loading programs via `bpf()` syscall |
| `CONFIG_BPF_JIT=y` | Recommended | JIT compilation for performance |
| `CONFIG_KPROBES=y` | Required | kprobe attachment |
| `CONFIG_XDP_SOCKETS=y` | Required for XDP | AF_XDP sockets |
| `CONFIG_DEBUG_INFO_BTF=y` | **Required** | CO-RE / BTF type info for vmlinux.h and relocations |
| `CONFIG_HAVE_EBPF_JIT=y` | Recommended | Hardware JIT |

### Check Your Kernel

```bash
uname -r
# Should be 5.8+

# Verify BPF and BTF are enabled
grep -E "CONFIG_BPF|CONFIG_KPROBES|CONFIG_DEBUG_INFO_BTF" /boot/config-$(uname -r)

# Verify BTF is exported at runtime
ls -lh /sys/kernel/btf/vmlinux
```

---

## libbpf + bpftool Installation (CO-RE — no BCC needed)

### Ubuntu 22.04 / 24.04

```bash
sudo apt-get update
sudo apt-get install -y \
    libbpf-dev \
    linux-tools-$(uname -r) \
    clang llvm \
    linux-headers-$(uname -r)
```

> `linux-tools-$(uname -r)` provides `bpftool`.

### Generate vmlinux.h (once per machine)

`vmlinux.h` contains all kernel type definitions exported via BTF. It must be generated on the target machine:

```bash
BPFTOOL=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
# or: BPFTOOL=/usr/lib/linux-tools/$(uname -r)/bpftool

sudo $BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > src/common/vmlinux.h
wc -l src/common/vmlinux.h  # should be >50,000 lines for a typical kernel
```

This file is in `.gitignore` (kernel-specific) — regenerate it on each machine.

### Verify clang can compile BPF

```bash
clang --version    # should be ≥ 10, ideally 14+

# Test compile
clang -target bpf -O2 -g \
    -I src/common \
    -I /usr/include/x86_64-linux-gnu \
    -c src/hello_world/hello.bpf.c -o /tmp/hello.bpf.o && echo "✅ OK"
```

---

## Python Dependencies

No BCC required. The loaders use only the Python standard library (`ctypes`, `subprocess`, `mmap`, `struct`) plus `libbpf.so.1` from `libbpf-dev`:

```bash
# Confirm libbpf.so is present
ls /usr/lib/x86_64-linux-gnu/libbpf.so*
```

Install any additional Python test dependencies:

```bash
pip install -r requirements.txt
```

---

## Verifying the Setup

```bash
# Check bpftool works
bpftool version

# Check BTF is available
bpftool btf dump file /sys/kernel/btf/vmlinux | head -5

# Run static tests (no root needed)
python3 -m pytest tests/ -v

# Run the hello world loader
cd src/hello_world
sudo python3 hello.py
```

---

## Tested Configurations

| Distro | Kernel | libbpf | Status |
|---|---|---|---|
| Ubuntu 24.04 LTS | 6.8.x | 1.3.0 (apt) | ✅ Tested |
| Ubuntu 22.04 LTS | 5.15.x | 0.8.0 (apt) | ✅ Tested |
| Ubuntu (AWS) | 6.17.x | 1.3.0 (apt) | ✅ Tested |

---

## Common Issues

### `vmlinux.h: No such file or directory`

Run the `bpftool btf dump` command above to generate it. It must be created on the target machine.

### `cannot open BPF object file`

Make sure you're running as **root** (`sudo`).

### `failed to find kernel BTF` / BTF not exported

BTF must be compiled into the kernel (`CONFIG_DEBUG_INFO_BTF=y`). On Ubuntu:

```bash
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
# Should output: CONFIG_DEBUG_INFO_BTF=y
```

All Ubuntu kernels ≥ 5.15 include BTF. If not present, install a newer kernel package.

### XDP attach fails on `lo` or virtual interfaces

Some interfaces don't support native XDP. Try a physical or `veth` interface. Use generic XDP mode:

```bash
ip link set dev lo xdp obj packet_counter.bpf.o section xdp skb
```

### `bpftool: command not found`

```bash
sudo apt-get install linux-tools-$(uname -r)
# or check: ls /usr/lib/linux-tools/*/bpftool
```
