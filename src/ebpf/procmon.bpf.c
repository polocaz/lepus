#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Event structure (matches Rust struct)
struct process_event {
    u32 pid;
    u32 ppid;
    char comm[16];
    u64 timestamp;
};

// Ring buffer map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} EVENTS SEC(".maps");

// Tracepoint for process execution
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_process_exec(struct trace_event_raw_sys_enter* ctx) {
    struct process_event *event;
    struct task_struct *task;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);
    if (!event) {
        return 0; // Buffer full, drop event
    }
    
    // Get current task info
    task = (struct task_struct*)bpf_get_current_task();
    
    // Fill event data
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->timestamp = bpf_ktime_get_ns();
    
    // Get process name (command)
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";