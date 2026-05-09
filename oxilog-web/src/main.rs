//! Entry point for the oxilog-web server binary.

use std::net::SocketAddr;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

/// Read-only web UI for oxilog.
#[derive(Debug, Parser)]
#[command(name = "oxilog-web", about = "Read-only web UI for oxilog")]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value = "3000")]
    port: u16,

    /// Address to bind to.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Path to the SQLite database.
    #[arg(long, default_value = "oxilog.db")]
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

    let config = oxilog_web::ServerConfig {
        bind,
        db_path: args.db_path,
    };

    oxilog_web::start_server(config).await
}
