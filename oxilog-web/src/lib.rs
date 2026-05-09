//! oxilog-web: read-only web UI for browsing captured session events.

pub mod application;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::info;

/// Configuration for the web server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to.
    pub bind: SocketAddr,
    /// Path to the SQLite database.
    pub db_path: String,
}

/// Start the web server with the given configuration.
///
/// # Errors
///
/// Returns an error if the server fails to bind or start.
pub async fn start_server(config: ServerConfig) -> Result<()> {
    let app = application::routes::router();

    let listener = TcpListener::bind(config.bind)
        .await
        .context("failed to bind TCP listener")?;

    info!(addr = %config.bind, "starting oxilog-web server");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    ctrl_c.await.ok();
    info!("shutdown signal received");
}
