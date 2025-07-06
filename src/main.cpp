#include <iostream>
#include <bpf/libbpf.h>
#include <unistd.h>

int main() {
    std::cout << "[lepus] Starting agent...\n";

    // Load BPF object
    struct bpf_object *obj = bpf_object__open_file("bpf/cpu_latency_probe.o", NULL);
    if (!obj) {
        std::cerr << "[lepus] Failed to open BPF object\n";
        return 1;
    }

    int err = bpf_object__load(obj);
    if (err) {
        std::cerr << "[lepus] Failed to load BPF program: " << strerror(-err) << "\n";
        return 1;
    }

    std::cout << "[lepus] eBPF probe loaded successfully\n";

    // TODO: Poll ring buffer and log data
    while (true) {
        sleep(5);
    }

    return 0;
}
