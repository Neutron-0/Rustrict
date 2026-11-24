pub mod event_bus;
pub mod routes;
pub mod ws;

pub use event_bus::{EngineEvent, EventBus};
pub use routes::{create_app, AppState, StatusResponse};

use std::sync::Arc;

/// Runs the Axum REST & WebSocket server asynchronously until termination.
pub async fn run_server(port: u16, state: Arc<AppState>) -> Result<(), std::io::Error> {
    let app = create_app(state);
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!(
        "[SERVER] Rustrict API listening on http://127.0.0.1:{} (WebSocket /api/events & /api/ws)",
        port
    );
    axum::serve(listener, app).await
}

/// Spawns the Axum server on a background tokio task.
pub fn spawn_server_background(port: u16, state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_server(port, state).await {
            eprintln!("[SERVER ERR] Server on port {} halted: {}", port, e);
        }
    })
}

