//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_EVENTS 256

struct event {
    u32 pid;
    u32 syscall;
    u64 ts;
};

struct flight_buffer {
    struct event events[MAX_EVENTS];
    u32 index;
    u32 frozen;
};

// PID -> rolling buffer
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct flight_buffer);
} flight SEC(".maps");

// Safe zero initializer
static const struct flight_buffer ZERO = {};

static __always_inline void freeze_pid(u32 pid)
{
    struct flight_buffer *fb = bpf_map_lookup_elem(&flight, &pid);
    if (!fb)
        return;

    fb->frozen = 1;
}

/*
 * Record syscalls into rolling buffer
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct flight_buffer *fb = bpf_map_lookup_elem(&flight, &pid);
    if (!fb) {
        bpf_map_update_elem(&flight, &pid, &ZERO, BPF_ANY);
        fb = bpf_map_lookup_elem(&flight, &pid);
        if (!fb)
            return 0;
    }

    if (fb->frozen)
        return 0;

    u32 i = fb->index % MAX_EVENTS;

    fb->events[i].pid = pid;
    fb->events[i].syscall = ctx->id;
    fb->events[i].ts = bpf_ktime_get_ns();

    fb->index += 1;
    return 0;
}

/*
 * Freeze immediately on SIGKILL / SIGSEGV
 */
SEC("tracepoint/signal/signal_deliver")
int handle_signal(struct trace_event_raw_signal_deliver *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (ctx->sig == 9 || ctx->sig == 11)
        freeze_pid(pid);

    return 0;
}

/*
 * Freeze on abnormal exit
 */
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct flight_buffer *fb = bpf_map_lookup_elem(&flight, &pid);
    if (!fb)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int exit_code = 0;

    bpf_core_read(&exit_code, sizeof(exit_code), &task->exit_code);

    int code = exit_code & 0xFF;
    int sig  = (exit_code >> 8) & 0xFF;

    if (code != 0 || sig == 9 || sig == 11)
        fb->frozen = 1;

    return 0;
}
