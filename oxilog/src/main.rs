use anyhow::{Context, Result};
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use clap::{Parser, Subcommand};
use oxilog_common::EventType;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

mod btf;
mod event;
mod filter;
mod session;

#[derive(Debug, Parser)]
#[command(name = "oxilog", about = "Passive Linux session recorder")]
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
    },
    /// Check kernel and BPF capability status
    Check,
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
        } => {
            let filter_config = filter::FilterConfig {
                filter_pty,
                filter_ancestors: filter_ancestor,
            };
            run(filter_config)?;
        }
        Command::Check => check_capabilities()?,
    }

    Ok(())
}

fn run(filter_config: filter::FilterConfig) -> Result<()> {
    info!(
        filter_pty = filter_config.filter_pty,
        filter_ancestors = ?filter_config.filter_ancestors,
        "starting oxilog",
    );

    let ebpf_bytes = include_bytes_aligned::include_bytes_aligned!(
        16,
        "../../oxilog-ebpf/target/bpfel-unknown-none/release/oxilog-ebpf"
    );

    let mut ebpf = Ebpf::load(ebpf_bytes).context("failed to load eBPF program")?;

    // Load and attach sys_enter_execve tracepoint.
    let enter_prog: &mut TracePoint = ebpf
        .program_mut("sys_enter_execve")
        .context("sys_enter_execve program not found")?
        .try_into()?;
    enter_prog.load()?;
    enter_prog.attach("syscalls", "sys_enter_execve")?;
    info!("attached sys_enter_execve tracepoint");

    // Load and attach sys_exit_execve tracepoint.
    let exit_prog: &mut TracePoint = ebpf
        .program_mut("sys_exit_execve")
        .context("sys_exit_execve program not found")?
        .try_into()?;
    exit_prog.load()?;
    exit_prog.attach("syscalls", "sys_exit_execve")?;
    info!("attached sys_exit_execve tracepoint");

    // Load and attach sys_enter_exit_group tracepoint.
    let exit_group_prog: &mut TracePoint = ebpf
        .program_mut("sys_enter_exit_group")
        .context("sys_enter_exit_group program not found")?
        .try_into()?;
    exit_group_prog.load()?;
    exit_group_prog.attach("syscalls", "sys_enter_exit_group")?;
    info!("attached sys_enter_exit_group tracepoint");

    // Load and attach sys_enter_write tracepoint.
    let write_prog: &mut TracePoint = ebpf
        .program_mut("sys_enter_write")
        .context("sys_enter_write program not found")?
        .try_into()?;
    write_prog.load()?;
    write_prog.attach("syscalls", "sys_enter_write")?;
    info!("attached sys_enter_write tracepoint");

    // Load and attach sys_enter_read tracepoint.
    let read_enter_prog: &mut TracePoint = ebpf
        .program_mut("sys_enter_read")
        .context("sys_enter_read program not found")?
        .try_into()?;
    read_enter_prog.load()?;
    read_enter_prog.attach("syscalls", "sys_enter_read")?;
    info!("attached sys_enter_read tracepoint");

    // Load and attach sys_exit_read tracepoint.
    let read_exit_prog: &mut TracePoint = ebpf
        .program_mut("sys_exit_read")
        .context("sys_exit_read program not found")?
        .try_into()?;
    read_exit_prog.load()?;
    read_exit_prog.attach("syscalls", "sys_exit_read")?;
    info!("attached sys_exit_read tracepoint");

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
    rt.block_on(consume_events(ring_buf, filter_config))
}

async fn consume_events(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    filter_config: filter::FilterConfig,
) -> Result<()> {
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;
    let mut correlator = session::SessionCorrelator::new();

    info!("consuming events from ring buffer");

    loop {
        // Wait for the ring buffer fd to become readable.
        let mut guard = async_fd.readable().await?;

        // Drain all available events.
        while let Some(item) = ring_buf.next() {
            handle_event(&item, &mut correlator, &filter_config);
        }

        guard.clear_ready();
    }
}

fn handle_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
) {
    let Some(header) = event::parse_header(data) else {
        tracing::warn!(len = data.len(), "event too short, skipping");
        return;
    };

    match header.event_type {
        EventType::Exec => handle_exec_event(data, correlator, filter_config),
        EventType::Exit => handle_exit_event(data, correlator, filter_config),
        EventType::Read | EventType::Write => {
            handle_io_event(data, correlator, filter_config, header.event_type);
        }
    }
}

fn handle_exec_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
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

fn handle_exit_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
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

fn handle_io_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
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
