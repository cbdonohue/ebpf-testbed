// SPDX-License-Identifier: GPL-2.0
// hello.bpf.c — Minimal kprobe eBPF program (libbpf CO-RE style)
// Attaches to sys_clone and emits a greeting event via ring buffer.
//
// Upgraded from BCC-style to libbpf CO-RE with BPF_RINGBUF.
// Previously used: #include <uapi/linux/ptrace.h> and bpf_printk.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct hello_event {
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// kprobe__sys_clone — attached via SEC("kprobe/__x64_sys_clone")
SEC("kprobe/__x64_sys_clone")
int kprobe__sys_clone(void *ctx)
{
    struct hello_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
