// SPDX-License-Identifier: GPL-2.0
// syscall_tracer.bpf.c — Tracepoint on sys_enter_execve
//
// Captures process name (comm) and PID for every execve() call
// and emits the data via bpf_printk.
//
// Rewritten from BCC-style (TRACEPOINT_PROBE, BPF_PERF_OUTPUT macros)
// to libbpf-style with SEC("tracepoint/...") and standard helpers.
//
// BPF_PERF_OUTPUT(exec_events) — replaced with bpf_printk output below.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16

// Minimal tracepoint context for sys_enter_execve
// Matches the format in /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct sys_enter_execve_args {
    __u64 pad;         // common fields (8 bytes)
    const char *filename;
    const char * const *argv;
    const char * const *envp;
};

// sys_enter_execve tracepoint — replaces TRACEPOINT_PROBE(syscalls, sys_enter_execve)
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct sys_enter_execve_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid      = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    char filename[64] = {};
    bpf_probe_read_user_str(filename, sizeof(filename), ctx->filename);

    bpf_printk("execve: pid=%u comm=%s file=%s\n", tgid, comm, filename);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
