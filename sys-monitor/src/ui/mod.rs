use std::sync::Arc;
use anyhow::Result;
use tokio::sync::Mutex;
use tokio::task;

pub mod app;
pub mod event;
pub mod ui;

pub use app::App;
pub use event::EventHandler;

pub async fn start_ui(app: Arc<Mutex<App>>) -> Result<()> {
    // Clone Arc for UI thread
    let app_ui = app.clone();
    
    // Spawn UI thread
    let ui_handle = task::spawn_blocking(move || {
        ui::run(app_ui)
    });
    
    // Wait for UI thread to complete
    ui_handle.await??;
    
    Ok(())
}