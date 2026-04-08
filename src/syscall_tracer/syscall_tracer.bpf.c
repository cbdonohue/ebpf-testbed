// SPDX-License-Identifier: GPL-2.0
// syscall_tracer.bpf.c — kprobe on sys_execve
//
// Captures process name (comm) and PID for every execve() call
// and emits the data to a perf buffer for userspace consumption.

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Data structure sent to userspace via perf buffer
struct exec_event {
    u32  pid;
    u32  tgid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct exec_event event = {};

    event.pid  = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // args->filename is the first argument to execve (path string)
    bpf_probe_read_user_str(event.filename, sizeof(event.filename),
                            (void *)args->filename);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
