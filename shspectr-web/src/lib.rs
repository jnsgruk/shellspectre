//! shspectr-web: read-only web UI for browsing captured session events.

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod presentation;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::info;

use application::state::AppState;
use infrastructure::database::create_pool;
use infrastructure::repositories::event::SqlEventRepository;

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
    let pool = create_pool(&config.db_path)?;
    let repo = Arc::new(SqlEventRepository::new(pool));
    let state = AppState { repo };

    let app = application::routes::router().with_state(state);

    let listener = TcpListener::bind(config.bind)
        .await
        .context("failed to bind TCP listener")?;

    info!(addr = %config.bind, "starting shspectr-web server");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

#[allow(clippy::expect_used)]
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = async { ctrl_c.await.ok(); } => {},
        () = terminate => {},
    }
}
