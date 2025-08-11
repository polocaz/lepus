use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::TracePoint,
    Ebpf,  // Changed from Bpf to Ebpf
};
use aya_log::EbpfLogger;  // Updated from BpfLogger
use log::{info, warn};
use std::convert::TryInto;
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

    // Load the compiled eBPF program - FIX THE PATH
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/debug/process_monitor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/release/process_monitor"
    ))?;

    // Initialize logging - FIXED TYPE
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Load and attach the tracepoint program
    let program: &mut TracePoint = bpf.program_mut("trace_process_exec").unwrap().try_into()?;
    program.attach("syscalls", "sys_enter_execve")?;

    info!("✅ eBPF program attached to process execution events");

    // Access the ring buffer for events
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    info!("🔍 Monitoring process executions...");
    info!("📊 CPU overhead target: <1%");
    println!("Press Ctrl+C to stop\n");

    // Event processing loop
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("📋 Shutting down Lepus Elite...");
                break;
            }
            _ = async {
                // Poll for events from kernel
                if let Some(item) = ring_buf.next() {
                    let event = unsafe { 
                        &*(item.as_ptr() as *const ProcessEvent) 
                    };
                    
                    let comm = String::from_utf8_lossy(&event.comm)
                        .trim_end_matches('\0');
                    
                    println!("🎯 Process Event: PID={} PPID={} CMD={} TIME={}", 
                        event.pid, 
                        event.ppid, 
                        comm, 
                        event.timestamp
                    );
                }
                
                // Small delay to prevent busy waiting
                time::sleep(time::Duration::from_millis(10)).await;
            } => {}
        }
    }

    info!("👋 Lepus Elite terminated successfully");
    Ok(())
}
