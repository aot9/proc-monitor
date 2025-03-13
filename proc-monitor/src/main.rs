use aya::{EbpfLoader,include_bytes_aligned};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

mod bpf;
mod ui;

use ui::app::App;

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    pid: u32,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let pid = Args::parse().pid;

    env_logger::init();

    let mut bpf = EbpfLoader::new()
        .set_global("PID", &pid, true)
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/proc-monitor"
        ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
        panic!("err");
    }

    let app = App::new();
    bpf::load_and_attach(&mut bpf, app.events.sender.clone()).await?;

    let _ = app.run(ratatui::init()).await;
    ratatui::restore();

    signal::ctrl_c().await.expect("failed to listen for ctrl-c event");

    info!("Exiting...");

    Ok(())
}