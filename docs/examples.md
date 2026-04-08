# Usage Examples

All programs require **root privileges**. Run with `sudo`.

---

## hello_world

Attaches a kprobe to `sys_clone` and prints a message every time a new process is spawned.

```bash
cd src/hello_world
sudo python3 hello.py
```

**Expected output:**

```
Loading eBPF program from: /path/to/src/hello_world/hello.bpf.c
Attached kprobe on sys_clone. Tracing... Hit Ctrl-C to stop.

          <...>-1234  [003] .... Hello from eBPF! PID=1234
          bash-5678   [001] .... Hello from eBPF! PID=5678
```

The output is piped from the kernel's trace pipe (`/sys/kernel/debug/tracing/trace_pipe`).

---

## packet_counter

Attaches an XDP program to a network interface and counts packets by IP protocol.

```bash
cd src/packet_counter

# Attach to eth0 (default)
sudo python3 packet_counter.py

# Attach to a specific interface
sudo python3 packet_counter.py ens3
```

**Expected output (refreshed every 2 seconds):**

```
Protocol     Packets
--------------------------
ICMP               42
TCP            12,847
UDP             3,201
proto-17           88
```

**Tips:**
- Generate traffic with `ping`, `curl`, or `iperf3` to see counts change.
- Use `ip link show` to list available interfaces.
- If XDP native mode fails, edit the script to use `BPF.XDP_FLAGS_SKB_MODE`.

---

## syscall_tracer

Traces every `execve()` call system-wide — the syscall used to launch any new program.

```bash
cd src/syscall_tracer
sudo python3 syscall_tracer.py
```

**Expected output:**

```
PID          TGID         COMM                 FILE
----------------------------------------------------------------------
PID=12345   TGID=12345   COMM=bash            FILE=/usr/bin/ls
PID=12346   TGID=12346   COMM=sshd            FILE=/bin/bash
```

**Tips:**
- Open another terminal and run commands to generate events.
- Use `grep` to filter: `sudo python3 syscall_tracer.py | grep python`

---

## latency_histogram

Measures block I/O request latency from `blk_account_io_start` to `blk_account_io_done` and displays a log2 histogram.

```bash
cd src/latency_histogram

# Print histogram every 5 seconds (default)
sudo python3 latency.py

# Print every 10 seconds
sudo python3 latency.py 10
```

**Expected output:**

```
--- Block I/O Latency Histogram (nanoseconds, log2 scale) ---
latency (ns)        : count     distribution
         512 -> 1023    : 2        |                                      |
        1024 -> 2047    : 18       |***                                   |
        2048 -> 4095    : 87       |***************                       |
        4096 -> 8191    : 213      |************************************  |
        8192 -> 16383   : 241      |**************************************|
       16384 -> 32767   : 98       |****************                      |
       32768 -> 65535   : 12       |**                                    |
```

**Tips:**
- Generate disk I/O with `dd if=/dev/sda of=/dev/null bs=4k count=10000` or `fio`.
- NVMe drives will cluster in the microsecond range; HDDs in the millisecond range.
- The histogram auto-clears each interval so you see fresh data every cycle.

---

## Running the Test Suite

```bash
# From repo root
make test

# Or directly
python3 -m pytest tests/ -v
```

Tests don't require root or a running kernel — they perform static analysis only.
