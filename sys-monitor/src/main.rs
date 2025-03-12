use anyhow::Context;
use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;
use std::sync::Arc;
use tokio::sync::Mutex;

mod bpf;
mod ui;
mod trackers;

use ui::app::App;
use trackers::{memory::MemoryTracker, fd::FdTracker};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "sys-monitor")]
    name: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    
    env_logger::init();

    // Initialize BPF
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sys-monitor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sys-monitor"
    ))?;
    
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    
    // Initialize our application state
    let app = Arc::new(Mutex::new(App::new()));
    
    // Initialize trackers
    let memory_tracker = MemoryTracker::new();
    let fd_tracker = FdTracker::new();
    
    // Load and attach BPF programs
    bpf::load_and_attach(&mut bpf, app.clone(), memory_tracker, fd_tracker).await?;
    
    info!("Waiting for Ctrl-C...");
    
    // Start the UI
    ui::start_ui(app.clone()).await?;
    
    signal::ctrl_c().await.expect("failed to listen for ctrl-c event");
    info!("Exiting...");

    Ok(())
}