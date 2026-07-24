cat << 'EOF' > open_modify.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define NAME_MAX 255

/* The compiler needs to see this struct clearly */
struct event {
    u32 pid;
    u32 uid;
    int ret;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

/* Define the map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Global variables for ecli to pick up */
bool rewrite = false;
bool targ_failed = false;
int target_pid = 0;

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (target_pid != 0 && pid != target_pid)
        return 0;

    /* The compiler looks for this exact pattern to generate metadata */
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->fname, sizeof(e->fname), (char *)ctx->args[0]);

    if (rewrite) {
        /* This is the hijack logic */
        bpf_probe_write_user((char*)ctx->args[0], "hijacked", 9);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF
