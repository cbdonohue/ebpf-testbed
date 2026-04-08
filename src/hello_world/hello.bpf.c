// SPDX-License-Identifier: GPL-2.0
// hello.bpf.c — Minimal kprobe eBPF program (libbpf-style)
// Attaches to sys_clone and prints a greeting via bpf_printk.
//
// Rewritten from BCC-style to compile with raw clang + libbpf headers.
// Previously used: #include <uapi/linux/ptrace.h> and kprobe__sys_clone macro.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// kprobe__sys_clone — attached via SEC("kprobe/__x64_sys_clone")
SEC("kprobe/__x64_sys_clone")
int kprobe__sys_clone(void *ctx)
{
    bpf_printk("Hello from eBPF! PID=%llu\n",
               bpf_get_current_pid_tgid() >> 32);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
