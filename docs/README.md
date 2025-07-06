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
- ✅ Clean, production-ready C++ daemon
- ✅ Configurable thresholds and filters via YAML/TOML

---

## 📦 Architecture Overview

```txt
+------------------+           +------------------------+
| eBPF Program     |           | Lepus Daemon (C++)     |
| (sched_switch)   |           |                        |
|                  |  <--->    |  - Loads eBPF ELF      |
| - Tracks latency |   Maps    |  - Polls ring buffer   |
| - Records events |           |  - Exports metrics     |
+------------------+           +------------------------+
                                  |
                             Prometheus / Logs
````

---

## 🚀 Quickstart

> 🛑 Requirements: Linux 5.10+, `clang`, `libbpf`, and `cmake`.

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
├── include/            # Public headers (AgentConfig, BPFProgram, etc.)
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

## 🎯 Roadmap

* [x] eBPF CPU latency probe
* [ ] Thread stall detection
* [ ] Memory churn analysis (via kmalloc/kfree)
* [ ] Optional LKM fallback for legacy systems
* [ ] gRPC telemetry streaming
* [ ] Grafana dashboard templates

---

## 👨‍💻 Developer Setup

```bash
sudo apt install clang llvm libbpf-dev cmake
make
```

See [docs/dev\_guide.md](docs/dev_guide.md) for full instructions.

---

## 📜 License

Licensed under the [GPLv2](LICENSE).

---

## ✨ Credits

* [libbpf](https://github.com/libbpf/libbpf)
* [BCC Tools](https://github.com/iovisor/bcc)
* [Brendan Gregg](http://www.brendangregg.com/) for the inspiration

```

---

## 📌 Suggestions

- Update the **repository URL**, your **GitHub name**, and paths
- Add **badges** for CI status, license, and kernel support if desired
- Include a **screenshot of a Grafana dashboard** when available

Would you like this written directly into a `docs/README.md` file or do you want to generate a short version for your GitHub summary box too?
```
