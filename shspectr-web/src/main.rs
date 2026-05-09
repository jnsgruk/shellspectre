//! Entry point for the shspectr-web server binary.

use std::net::SocketAddr;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

/// Read-only web UI for shspectr.
#[derive(Debug, Parser)]
#[command(name = "shspectr-web", about = "Read-only web UI for shspectr")]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value = "3000")]
    port: u16,

    /// Address to bind to.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Path to the SQLite database.
    #[arg(long, default_value = "shspectr.db")]
    db_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt::Subscriber::builder()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let bind: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;

    let config = shspectr_web::ServerConfig {
        bind,
        db_path: args.db_path,
    };

    shspectr_web::start_server(config).await
}
