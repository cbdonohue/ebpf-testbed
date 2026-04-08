// SPDX-License-Identifier: GPL-2.0
// hello.bpf.c — Minimal kprobe eBPF program
// Attaches to sys_clone and prints a greeting via bpf_trace_printk.

#include <uapi/linux/ptrace.h>

int kprobe__sys_clone(struct pt_regs *ctx)
{
    bpf_trace_printk("Hello from eBPF! PID=%d\\n", bpf_get_current_pid_tgid() >> 32);
    return 0;
}
