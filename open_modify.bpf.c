// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define NAME_MAX 255

struct event {
    pid_t pid;
    uid_t uid;
    int ret;
    int flags;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

/* Ringbuffer used to send completed events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Temporary per-PID storage between enter/exit tracepoints */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, struct event);
} start SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int handle_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event event = {};
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    event.pid = pid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);

    bpf_map_update_elem(&start, &pid, &event, BPF_ANY);

    /* Hijack: overwrite the filename argument in user memory */
    char hijack[] = "hijacked";
    bpf_probe_write_user((char *)ctx->args[0], hijack, sizeof(hijack));

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int handle_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    struct event *eventp = bpf_map_lookup_elem(&start, &pid);
    if (!eventp)
        return 0;

    eventp->ret = ctx->ret;

    struct event *rb_event = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!rb_event) {
        bpf_map_delete_elem(&start, &pid);
        return 0;
    }

    *rb_event = *eventp;
    bpf_ringbuf_submit(rb_event, 0);

    bpf_map_delete_elem(&start, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
