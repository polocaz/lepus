// cpu_latency_probe.c
// First real eBPF probe for Lepus: tracks scheduling latency per PID

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 delta_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
} start_time SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;

    // record when a PID is scheduled out
    bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);

    // get delta for the PID being scheduled in
    u64 *tsp = bpf_map_lookup_elem(&start_time, &next_pid);
    if (!tsp) return 0;

    u64 delta = ts - *tsp;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = next_pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->delta_ns = delta;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
