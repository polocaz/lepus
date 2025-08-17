use aya::{Bpf, maps::RingBuf, programs::TracePoint};
use std::{convert::TryInto, fs};
use tokio::{signal, time};

#[repr(C)]
struct ProcessEvent {
    pid: u32,
    ppid: u32,
    comm: [u8; 16],
    timestamp: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    println!("🦅 Lepus Elite Security Intelligence Platform");
    println!("📡 Starting kernel-level process monitoring...\n");

    // Check if running as root
    if unsafe { libc::getuid() } != 0 {
        return Err(anyhow::anyhow!(
            "❌ Must run as root (sudo) to load eBPF programs"
        ));
    }

    // Load eBPF program from file
    let ebpf_path = "ebpfs/process_monitor";
    println!("📂 Loading eBPF program from: {}", ebpf_path);

    let ebpf_data = fs::read(ebpf_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read eBPF program: {}. Did you run 'cargo xtask build-ebpf'?",
            e
        )
    })?;

    let mut bpf =
        Bpf::load(&ebpf_data).map_err(|e| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;

    println!("✅ eBPF program loaded successfully");

    // List available programs for debugging
    println!("📋 Available programs:");
    for (name, program) in bpf.programs() {
        println!("  - {}: {:?}", name, program.prog_type());
    }

    // Get the tracepoint program and LOAD it first
    let program: &mut TracePoint = bpf
        .program_mut("trace_process_exec")
        .ok_or_else(|| anyhow::anyhow!("Program 'trace_process_exec' not found"))?
        .try_into()
        .map_err(|e| anyhow::anyhow!("Failed to convert to TracePoint: {}", e))?;

    // IMPORTANT: Load the program into the kernel first
    println!("🔄 Loading program into kernel...");
    program
        .load()
        .map_err(|e| anyhow::anyhow!("Failed to load program into kernel: {}", e))?;

    println!("✅ Program loaded into kernel successfully");

    println!("🔗 Attempting to attach to tracepoint...");

    // Now try attaching to tracepoint
    let attach_result = program.attach("syscalls", "sys_enter_execve");

    match attach_result {
        Ok(_) => {
            println!("✅ eBPF program attached to sys_enter_execve");
        }
        Err(e) => {
            println!("⚠️  Failed to attach to sys_enter_execve: {}", e);
            println!("🔄 Trying alternative tracepoint...");

            // Try alternative tracepoint
            let alt_result = program.attach("syscalls", "sys_enter_execveat");
            match alt_result {
                Ok(_) => {
                    println!("✅ eBPF program attached to sys_enter_execveat");
                }
                Err(e2) => {
                    return Err(anyhow::anyhow!(
                        "❌ Failed to attach to both tracepoints:\n  - execve: {}\n  - execveat: {}",
                        e,
                        e2
                    ));
                }
            }
        }
    }

    // Access the ring buffer for events
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    println!("🔍 Monitoring process executions... Press Ctrl+C to stop\n");

    // Event processing loop
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("📋 Shutting down Lepus Elite...");
                break;
            }
            _ = async {
                if let Some(item) = ring_buf.next() {
                    let event = unsafe {
                        &*(item.as_ptr() as *const ProcessEvent)
                    };

                    let comm_str = String::from_utf8_lossy(&event.comm);
                    let comm = comm_str.trim_end_matches('\0');

                    println!("🎯 Process Event: PID={} PPID={} CMD={} TIME={}",
                        event.pid,
                        event.ppid,
                        comm,
                        event.timestamp
                    );
                }

                time::sleep(time::Duration::from_millis(10)).await;
            } => {}
        }
    }

    Ok(())
}
