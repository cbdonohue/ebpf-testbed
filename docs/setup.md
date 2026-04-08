# Setup Guide

## Kernel Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Kernel version | ≥ 5.4 | BTF + CO-RE support; 5.15+ recommended |
| `CONFIG_BPF=y` | Required | Core eBPF support |
| `CONFIG_BPF_SYSCALL=y` | Required | Allows loading programs via `bpf()` syscall |
| `CONFIG_BPF_JIT=y` | Recommended | JIT compilation for performance |
| `CONFIG_KPROBES=y` | Required | kprobe attachment |
| `CONFIG_XDP_SOCKETS=y` | Required for XDP | AF_XDP sockets |
| `CONFIG_DEBUG_INFO_BTF=y` | Recommended | CO-RE / BTF type info |
| `CONFIG_HAVE_EBPF_JIT=y` | Recommended | Hardware JIT |

### Check Your Kernel

```bash
uname -r
# Should be 5.4+

# Verify BPF is enabled
grep -E "CONFIG_BPF|CONFIG_KPROBES|CONFIG_XDP" /boot/config-$(uname -r)
```

---

## BCC Installation

### Ubuntu 22.04 (Jammy)

```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev \
    python3-bpfcc linux-headers-$(uname -r) \
    clang llvm libclang-dev
```

### Ubuntu 24.04 (Noble)

```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev \
    python3-bpfcc linux-headers-$(uname -r) \
    clang-17 llvm-17 libclang-17-dev
# Create symlinks if needed
sudo ln -sf /usr/bin/clang-17 /usr/local/bin/clang
sudo ln -sf /usr/bin/llvm-config-17 /usr/local/bin/llvm-config
```

### From Source (latest BCC — any distro)

Useful when the distro package is out of date:

```bash
sudo apt-get install -y cmake python3-dev bison flex \
    libelf-dev libfl-dev libssl-dev \
    clang llvm llvm-dev libclang-dev

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build && cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make -j$(nproc)
sudo make install
```

---

## Python Dependencies

```bash
pip install -r requirements.txt
```

---

## Verifying the Setup

```bash
# List available BCC tools (should show many programs)
ls /usr/share/bcc/tools/

# Quick sanity check — trace open() calls for 5 seconds
sudo opensnoop-bpfcc -d 5

# Check kernel BTF is available (needed for CO-RE)
ls /sys/kernel/btf/vmlinux
```

---

## Tested Configurations

| Distro | Kernel | BCC Version | Status |
|---|---|---|---|
| Ubuntu 22.04 LTS | 5.15.x | 0.25 (apt) | ✅ Tested |
| Ubuntu 24.04 LTS | 6.8.x | 0.30 (apt) | ✅ Tested |
| Debian 12 (Bookworm) | 6.1.x | 0.25 (apt) | ✅ Tested |
| Fedora 39 | 6.5.x | 0.27 (dnf) | ✅ Tested |
| Arch Linux | rolling | latest (pacman) | ✅ Tested |

---

## Common Issues

### `cannot open BPF object file`

Make sure you're running as **root** (`sudo`) and that kernel headers match your running kernel:

```bash
sudo apt-get install linux-headers-$(uname -r)
```

### `failed to find kernel BTF`

BTF must be compiled into the kernel. On Ubuntu:

```bash
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
# Should output: CONFIG_DEBUG_INFO_BTF=y
```

If not, install a BTF-enabled kernel or compile one with `CONFIG_DEBUG_INFO_BTF=y`.

### XDP attach fails

Some virtual interfaces (like `lo`) don't support native XDP. Try `veth` pairs or a physical interface. Alternatively, use the generic XDP mode:

```bash
# In packet_counter.py, change attach_xdp flag from 0 to BPF.XDP_FLAGS_SKB_MODE
```
