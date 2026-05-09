use anyhow::{Context, Result};
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use clap::{Parser, Subcommand};
use shspectr_common::EventType;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

mod btf;
mod event;
mod filter;
mod session;
mod sqlite_sink;

#[cfg(feature = "web")]
use shspectr_web::ServerConfig;

#[derive(Debug, Parser)]
#[command(name = "shspectr", about = "Passive Linux session recorder")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start recording sessions
    Run {
        /// Only capture processes attached to a PTY
        #[arg(long)]
        filter_pty: bool,
        /// Only capture descendants of named processes (comma-separated)
        #[arg(long, value_delimiter = ',')]
        filter_ancestor: Vec<String>,
        /// Output sink: stdout or sqlite (default: stdout)
        #[arg(long, default_value = "stdout")]
        output: String,
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
    },
    /// Check kernel and BPF capability status
    Check,
    /// Start the web UI server
    #[cfg(feature = "web")]
    Web {
        /// Port to listen on
        #[arg(long, default_value = "3000")]
        port: u16,
        /// Address to bind to
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Path to the SQLite database
        #[arg(long, default_value = "shspectr.db")]
        db_path: String,
    },
}

fn main() -> Result<()> {
    fmt::Subscriber::builder()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            filter_pty,
            filter_ancestor,
            output,
            db_path,
            #[cfg(feature = "web")]
            web,
            #[cfg(feature = "web")]
            web_port,
            #[cfg(feature = "web")]
            web_bind,
        } => {
            let filter_config = filter::FilterConfig {
                filter_pty,
                filter_ancestors: filter_ancestor,
            };
            let sink = if output == "sqlite" {
                Some(sqlite_sink::SqliteSink::open(&db_path)?)
            } else {
                None
            };

            #[cfg(feature = "web")]
            let web_config = {
                if web {
                    anyhow::ensure!(output == "sqlite", "--web requires --output sqlite");
                    let addr: std::net::SocketAddr = format!("{web_bind}:{web_port}").parse()?;
                    Some(ServerConfig {
                        bind: addr,
                        db_path,
                    })
                } else {
                    None
                }
            };
            #[cfg(not(feature = "web"))]
            let web_config = ();

            run(filter_config, sink, web_config)?;
        }
        Command::Check => check_capabilities()?,
        #[cfg(feature = "web")]
        Command::Web {
            port,
            bind,
            db_path,
        } => {
            let addr: std::net::SocketAddr = format!("{bind}:{port}").parse()?;
            let config = shspectr_web::ServerConfig {
                bind: addr,
                db_path,
            };
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(shspectr_web::start_server(config))?;
        }
    }

    Ok(())
}

fn attach_tracepoint(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("{name} program not found"))?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", name)?;
    info!("attached {name} tracepoint");
    Ok(())
}

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn run(
    filter_config: filter::FilterConfig,
    sink: Option<sqlite_sink::SqliteSink>,
    #[cfg(feature = "web")] web_config: Option<ServerConfig>,
    #[cfg(not(feature = "web"))] _web_config: (),
) -> Result<()> {
    info!(
        filter_pty = filter_config.filter_pty,
        filter_ancestors = ?filter_config.filter_ancestors,
        "starting shspectr",
    );

    let ebpf_bytes = include_bytes_aligned::include_bytes_aligned!(
        16,
        "../../shspectr-ebpf/target/bpfel-unknown-none/release/shspectr-ebpf"
    );

    let mut ebpf = Ebpf::load(ebpf_bytes).context("failed to load eBPF program")?;

    attach_tracepoint(&mut ebpf, "sys_enter_execve")?;
    attach_tracepoint(&mut ebpf, "sys_exit_execve")?;
    attach_tracepoint(&mut ebpf, "sys_enter_exit_group")?;
    attach_tracepoint(&mut ebpf, "sys_enter_write")?;
    attach_tracepoint(&mut ebpf, "sys_enter_read")?;
    attach_tracepoint(&mut ebpf, "sys_exit_read")?;

    // Tell eBPF to skip events from our own process (avoids feedback loops).
    let mut self_tgid_map: aya::maps::Array<_, u32> = aya::maps::Array::try_from(
        ebpf.take_map("SELF_TGID")
            .context("SELF_TGID map not found")?,
    )?;
    self_tgid_map.set(0, std::process::id(), 0)?;

    // Resolve kernel struct field offsets from BTF and pass to eBPF.
    let offsets = btf::resolve_task_field_offsets()?;
    info!(
        ppid_offset = offsets.task_real_parent,
        euid_offset = offsets.cred_euid,
        tty_offset = offsets.signal_tty,
        "resolved kernel BTF offsets"
    );
    let mut offsets_map: aya::maps::Array<_, u64> =
        aya::maps::Array::try_from(ebpf.take_map("OFFSETS").context("OFFSETS map not found")?)?;
    for (idx, value) in (0u32..).zip(offsets.as_array()) {
        offsets_map.set(idx, value, 0)?;
    }

    // Open the ring buffer.
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(consume_events(
        ring_buf,
        filter_config,
        sink,
        #[cfg(feature = "web")]
        web_config,
    ))
}

#[allow(clippy::cognitive_complexity)]
async fn consume_events(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    filter_config: filter::FilterConfig,
    sink: Option<sqlite_sink::SqliteSink>,
    #[cfg(feature = "web")] web_config: Option<ServerConfig>,
) -> Result<()> {
    let token = CancellationToken::new();

    #[cfg(feature = "web")]
    if let Some(config) = web_config {
        let child_token = token.clone();
        tokio::spawn(async move {
            if let Err(e) = shspectr_web::start_server(config).await {
                tracing::error!(%e, "web server error");
            }
            child_token.cancel();
        });
    }

    // Always listen for Ctrl+C so the event loop exits cleanly even when the
    // web server is not running (or in addition to it).
    {
        let child_token = token.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            info!("shutdown signal received");
            child_token.cancel();
        });
    }

    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;
    let mut correlator = session::SessionCorrelator::new();

    info!("consuming events from ring buffer");

    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => {
                info!("shutting down event loop");
                break;
            }
            result = async_fd.readable() => {
                let mut guard = result?;
                while let Some(item) = ring_buf.next() {
                    handle_event(&item, &mut correlator, &filter_config, sink.as_ref());
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

fn handle_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: Option<&sqlite_sink::SqliteSink>,
) {
    let Some(header) = event::parse_header(data) else {
        tracing::warn!(len = data.len(), "event too short, skipping");
        return;
    };

    match header.event_type {
        EventType::Exec => handle_exec_event(data, correlator, filter_config, sink),
        EventType::Exit => handle_exit_event(data, correlator, filter_config, sink),
        EventType::Read | EventType::Write => {
            handle_io_event(data, correlator, filter_config, sink, header.event_type);
        }
    }
}

#[allow(clippy::cognitive_complexity)]
fn handle_exec_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: Option<&sqlite_sink::SqliteSink>,
) {
    let Some(exec) = event::parse_exec_event(data) else {
        tracing::warn!("exec event too short");
        return;
    };
    let event_info = session::EventInfo {
        pid: exec.pid,
        ppid: exec.ppid,
        tty_nr: exec.tty_nr,
        comm: exec.comm.clone(),
    };
    let session_id = correlator.on_exec(&event_info).to_string();

    if !filter_config.is_empty() {
        let ancestor_comms = correlator.ancestor_comms(exec.pid);
        let fi = filter::FilterInput {
            tty_nr: exec.tty_nr,
            comm: exec.comm.clone(),
            ancestor_comms,
        };
        if !filter::passes_filter(filter_config, &fi) {
            return;
        }
    }

    if sink.is_none() {
        info!(
            event = "exec",
            session_id = %session_id,
            pid = exec.pid,
            ppid = exec.ppid,
            uid = exec.uid,
            gid = exec.gid,
            euid = exec.euid,
            comm = %exec.comm,
            tty_nr = exec.tty_nr,
            cgroup_id = exec.cgroup_id,
            filename = %exec.filename,
            argv = ?exec.argv,
            retval = exec.retval,
        );
    }

    if let Some(db) = sink {
        let si = sqlite_sink::SessionInfo {
            session_id: &session_id,
            pid: exec.pid,
            comm: &exec.comm,
            uid: exec.uid,
            euid: exec.euid,
            tty_nr: exec.tty_nr,
            cgroup_id: exec.cgroup_id,
        };
        if let Err(e) = db.ensure_session(&si) {
            tracing::warn!(%e, "failed to ensure session");
        }
        if let Err(e) = db.insert_exec(&session_id, &exec) {
            tracing::warn!(%e, "failed to insert exec event");
        }
    }
}

#[allow(clippy::cognitive_complexity)]
fn handle_exit_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: Option<&sqlite_sink::SqliteSink>,
) {
    let Some(exit) = event::parse_exit_event(data) else {
        tracing::warn!("exit event too short");
        return;
    };
    let event_info = session::EventInfo {
        pid: exit.pid,
        ppid: exit.ppid,
        tty_nr: exit.tty_nr,
        comm: exit.comm.clone(),
    };
    let session_id = correlator.session_for(&event_info).to_string();

    if !filter_config.is_empty() {
        let ancestor_comms = correlator.ancestor_comms(exit.pid);
        let fi = filter::FilterInput {
            tty_nr: exit.tty_nr,
            comm: exit.comm.clone(),
            ancestor_comms,
        };
        if !filter::passes_filter(filter_config, &fi) {
            correlator.on_exit(exit.pid);
            return;
        }
    }

    correlator.on_exit(exit.pid);
    if sink.is_none() {
        info!(
            event = "exit",
            session_id = %session_id,
            pid = exit.pid,
            ppid = exit.ppid,
            uid = exit.uid,
            gid = exit.gid,
            euid = exit.euid,
            comm = %exit.comm,
            tty_nr = exit.tty_nr,
            cgroup_id = exit.cgroup_id,
            exit_code = exit.exit_code,
        );
    }

    if let Some(db) = sink
        && let Err(e) = db.insert_exit(&session_id, &exit)
    {
        tracing::warn!(%e, "failed to insert exit event");
    }
}

#[allow(clippy::cognitive_complexity)]
fn handle_io_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: Option<&sqlite_sink::SqliteSink>,
    event_type: EventType,
) {
    let Some(io) = event::parse_io_event(data) else {
        tracing::warn!("io event too short");
        return;
    };
    let event_info = session::EventInfo {
        pid: io.pid,
        ppid: io.ppid,
        tty_nr: io.tty_nr,
        comm: io.comm.clone(),
    };
    let session_id = correlator.session_for(&event_info).to_string();

    if !filter_config.is_empty() {
        let ancestor_comms = correlator.ancestor_comms(io.pid);
        let fi = filter::FilterInput {
            tty_nr: io.tty_nr,
            comm: io.comm.clone(),
            ancestor_comms,
        };
        if !filter::passes_filter(filter_config, &fi) {
            return;
        }
    }

    let data_str = String::from_utf8_lossy(&io.data);
    if sink.is_none() {
        info!(
            event = if event_type == EventType::Read { "read" } else { "write" },
            session_id = %session_id,
            pid = io.pid,
            ppid = io.ppid,
            uid = io.uid,
            gid = io.gid,
            euid = io.euid,
            comm = %io.comm,
            tty_nr = io.tty_nr,
            cgroup_id = io.cgroup_id,
            fd = io.fd,
            data_len = io.data.len(),
            count = io.count,
            data = %data_str,
        );
    }

    if let Some(db) = sink {
        let type_str = if event_type == EventType::Read {
            "read"
        } else {
            "write"
        };
        if let Err(e) = db.insert_io(&session_id, &io, type_str) {
            tracing::warn!(%e, "failed to insert io event");
        }
    }
}

#[allow(clippy::print_stdout)]
fn check_capabilities() -> Result<()> {
    use std::path::Path;

    // Check kernel version
    let kernel_version = std::fs::read_to_string("/proc/version")?;
    let kernel_line = kernel_version.lines().next().unwrap_or("unknown");
    println!("Kernel: {kernel_line}");

    // Check BTF support
    let btf_available = Path::new("/sys/kernel/btf/vmlinux").exists();
    println!(
        "BTF:    {}",
        if btf_available {
            "available"
        } else {
            "NOT available"
        }
    );

    // Check BPF filesystem
    let bpffs_mounted = Path::new("/sys/fs/bpf").exists();
    println!(
        "BPF fs: {}",
        if bpffs_mounted {
            "mounted"
        } else {
            "NOT mounted"
        }
    );

    // Check if running as root (simplistic capability check)
    // SAFETY: geteuid is a simple syscall with no preconditions
    let euid = unsafe { libc::geteuid() };
    println!(
        "Root:   {}",
        if euid == 0 {
            "yes"
        } else {
            "no (may need CAP_BPF + CAP_PERFMON)"
        }
    );

    Ok(())
}
