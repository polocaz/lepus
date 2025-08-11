#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Event structure (using proper Linux kernel types)
struct process_event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    __u64 timestamp;
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} EVENTS SEC(".maps");

// Tracepoint for process execution
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_process_exec(void *ctx) {
    struct process_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event data
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->ppid = pid_tgid & 0xFFFFFFFF; // Simplified for now
    event->timestamp = bpf_ktime_get_ns();
    
    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
