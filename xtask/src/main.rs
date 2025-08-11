use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build tasks for Lepus Elite")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build eBPF programs
    BuildEbpf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf => build_ebpf(),
    }
}

fn build_ebpf() -> Result<()> {
    println!("🔨 Building eBPF programs...");
    
    // Ensure target directory exists
    std::fs::create_dir_all("target/bpfel-unknown-none/debug")?;
    std::fs::create_dir_all("target/bpfel-unknown-none/release")?;
    
    // Compile the eBPF program
    let output = Command::new("clang")
        .args([
            "-target", "bpf",
            "-D", "__TARGET_ARCH_x86",
            "-Wall",
            "-O2",
            "-g",
            "-c",
            "src/ebpf/process_monitor.bpf.c",
            "-o", "target/bpfel-unknown-none/debug/process_monitor"
        ])
        .output()
        .context("Failed to execute clang - ensure clang is installed")?;

    if !output.status.success() {
        eprintln!("❌ eBPF compilation failed:");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        return Err(anyhow::anyhow!("eBPF compilation failed"));
    }

    // Copy to release directory too
    std::fs::copy(
        "target/bpfel-unknown-none/debug/process_monitor",
        "target/bpfel-unknown-none/release/process_monitor"
    )?;

    println!("✅ eBPF programs built successfully");
    Ok(())
}
