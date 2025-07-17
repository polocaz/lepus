# 🐇 Lepus - Lightweight Linux Telemetry Agent

Lepus is a high-performance Linux observability agent that uses **eBPF** to trace low-level kernel activity like CPU latency, thread stalls, and process hangs in real time. Designed for production use, it provides safe, dynamic introspection without kernel modules or system overhead.

> ⚙️ Built with C++, libbpf, and Prometheus — inspired by tools like `perf`, `bcc`, and `turbostat`.

---

## 🔍 Features

- ✅ Trace process scheduling delays using `sched:sched_switch`
- ✅ Detect long off-CPU times (thread stalls / hangs)
- ✅ Export metrics via Prometheus (textfile or HTTP)
- ✅ Zero overhead when idle (no polling)
- ✅ Ring-buffer–based event streaming to user space
- ✅ Clean, production-ready C++ daemon with multithreaded design
- ✅ Configurable thresholds and filters via YAML/TOML

---

## 📦 Architecture Overview

```txt
+-------------------------------+
| Lepus Daemon (C++)         |
| -------------------------- |
| ▸ BpfRunner Thread         | ---> Loads and polls eBPF ring buffer |
| ▸ MetricsExporter Thread   | ---> Exports metrics to Prometheus    |
| ▸ ConfigWatcher (optional) | ---> Reloads config on change         |
| ▸ SignalHandler            | ---> Handles SIGINT/SIGHUP            |
+-------------------------------+
             |
             v
    [ Prometheus textfile or HTTP ]
```

Each subsystem runs in a dedicated thread for isolation, performance, and testability.

---

## 🧩 Internal Modules

| Module            | Role                                             |
| ----------------- | ------------------------------------------------ |
| `BpfRunner`       | Loads BPF object, attaches probes, polls ringbuf |
| `MetricsExporter` | Periodically flushes events to `.prom` file      |
| `AgentConfig`     | Loads and validates TOML/YAML config             |
| `EventDispatcher` | Queues and processes events from BPF             |
| `SignalHandler`   | Gracefully shuts down all subsystems             |

---

## 🚀 Quickstart

> 🛑 Requirements: Linux 5.10+, `clang`, `libbpf`, and `cmake`

```bash
# Clone
git clone https://github.com/polocaz/lepus && cd lepus

# Build
mkdir build && cd build
cmake ..
make

# Run (requires sudo to attach eBPF probes)
sudo ./lepus-agent --config ../config/example.toml
```

---

## 📊 Example Output

```text
[lepus] Attached to sched:sched_switch
[lepus] Detected PID 3472 stalled for 512ms (comm: postgres)
[lepus] Exported metric: lepus_thread_latency_ns{pid=3472} 512000000
```

---

## 📁 Project Layout

```
lepus/
├── bpf/                # eBPF probe sources (sched, memory, uprobes)
├── src/                # Daemon implementation (C++)
│   ├── core/           # BpfRunner, MetricsExporter, SignalHandler, etc.
│   └── main.cpp        # Entry point
├── include/            # Public headers (AgentConfig, Event structs, etc.)
├── config/             # TOML/YAML config examples
├── tests/              # Unit and integration tests
├── packaging/          # RPM, DEB, and systemd unit files
├── scripts/            # Build, demo, and install helpers
└── docs/               # Developer and user guides
```

---

## 🔧 Configuration

Lepus supports TOML or YAML configuration files:

```toml
[agent]
poll_interval_ms = 500
threshold_ns = 250000000  # 250ms

[exporter]
mode = "textfile"
path = "/var/lib/lepus/metrics.prom"
```

---

## 🛠 Use Cases

- Detect latency spikes in high-performance servers
- Monitor critical threads for starvation or hangs
- Collect metrics for Kubernetes observability stacks
- Debug hard-to-trace off-CPU delays in production workloads

---

## 🎯 Roadmap

- ✅ eBPF CPU latency probe (`sched:sched_switch`)
- 🔄 Modular C++ agent with threading (`BpfRunner`, `MetricsExporter`)
- 🔜 Threshold-based alerting for hangs/stalls
- 🔜 Prometheus textfile and embedded HTTP exporter
- 🔜 Memory churn probe (kmalloc/kfree via tracepoints)
- 🔜 Optional kernel module fallback for older distros
- 🔜 Config hot-reloading via `inotify`
- 🔜 Grafana dashboards + JSON templates
- 🔜 Packaging: .deb, .rpm, and systemd unit
- 🔜 gRPC streaming + remote control (optional)

---

## 👨‍💻 Developer Setup

```bash
sudo apt install clang llvm libbpf-dev cmake
make
```

See [docs/dev_guide.md](docs/dev_guide.md) for full instructions.

---

## 📜 License

Licensed under the [GPLv2](LICENSE).

---

## ✨ Credits

- [libbpf](https://github.com/libbpf/libbpf)
- [BCC Tools](https://github.com/iovisor/bcc)
- [Brendan Gregg](http://www.brendangregg.com/) for the inspiration
