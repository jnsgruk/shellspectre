use anyhow::Result;
use clap::{Parser, ValueEnum};
use tracing_subscriber::{EnvFilter, fmt};

mod btf;
mod ebpf;
mod event;
mod filter;
mod handler;
mod session;
mod sink;
mod sqlite_sink;
mod stdout_sink;

#[cfg(feature = "web")]
use shspectr_web::ServerConfig;

/// Output sink for captured events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputSink {
    /// Print events as JSON to stdout.
    Stdout,
    /// Write events to a SQLite database.
    Sqlite,
}

#[derive(Debug, Parser)]
#[command(name = "shspectr", about = "Passive Linux session recorder")]
struct Cli {
    /// Only capture processes attached to a PTY
    #[arg(long)]
    filter_pty: bool,
    /// Only capture descendants of named processes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    filter_ancestor: Vec<String>,
    /// Output sink: stdout or sqlite (default: stdout)
    #[arg(long, default_value = "stdout")]
    output: OutputSink,
    /// SQLite database path (for sqlite output)
    #[arg(long, default_value = "shspectr.db")]
    db_path: String,
    /// Also start the web UI server (requires --output sqlite)
    #[cfg(feature = "web")]
    #[arg(long)]
    web: bool,
    /// Port for the embedded web UI (requires --web)
    #[cfg(feature = "web")]
    #[arg(long, default_value = "3000")]
    web_port: u16,
    /// Bind address for the embedded web UI (requires --web)
    #[cfg(feature = "web")]
    #[arg(long, default_value = "127.0.0.1")]
    web_bind: String,
}

fn main() -> Result<()> {
    fmt::Subscriber::builder()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    ebpf::check_capabilities()?;

    let cli = Cli::parse();

    let filter_config = filter::FilterConfig {
        filter_pty: cli.filter_pty,
        filter_ancestors: cli.filter_ancestor,
    };
    let sink: Box<dyn sink::Sink> = match cli.output {
        OutputSink::Stdout => Box::new(stdout_sink::StdoutSink),
        OutputSink::Sqlite => Box::new(sqlite_sink::SqliteSink::open(&cli.db_path)?),
    };

    #[cfg(feature = "web")]
    let web_config = {
        if cli.web {
            anyhow::ensure!(
                cli.output == OutputSink::Sqlite,
                "--web requires --output sqlite"
            );
            let addr: std::net::SocketAddr =
                format!("{}:{}", cli.web_bind, cli.web_port).parse()?;
            Some(ServerConfig {
                bind: addr,
                db_path: cli.db_path,
            })
        } else {
            None
        }
    };
    #[cfg(not(feature = "web"))]
    let web_config = ();

    ebpf::run(filter_config, sink, web_config)?;

    Ok(())
}
