use anyhow::{Context, Result};
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use clap::{Parser, Subcommand};
use oxilog_common::{EventHeader, EventType, offset_idx};
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

mod btf;

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
        Command::Run { filter_pty } => run(filter_pty)?,
        Command::Check => check_capabilities()?,
    }

    Ok(())
}

fn run(filter_pty: bool) -> Result<()> {
    info!(filter_pty, "starting oxilog");

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
    offsets_map.set(offset_idx::TASK_REAL_PARENT, offsets.task_real_parent, 0)?;
    offsets_map.set(offset_idx::TASK_TGID, offsets.task_tgid, 0)?;
    offsets_map.set(offset_idx::TASK_CRED, offsets.task_cred, 0)?;
    offsets_map.set(offset_idx::CRED_EUID, offsets.cred_euid, 0)?;
    offsets_map.set(offset_idx::TASK_SIGNAL, offsets.task_signal, 0)?;
    offsets_map.set(offset_idx::SIGNAL_TTY, offsets.signal_tty, 0)?;
    offsets_map.set(offset_idx::TTY_INDEX, offsets.tty_index, 0)?;

    // Open the ring buffer.
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(consume_events(ring_buf))
}

async fn consume_events(mut ring_buf: RingBuf<aya::maps::MapData>) -> Result<()> {
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;

    info!("consuming events from ring buffer");

    loop {
        // Wait for the ring buffer fd to become readable.
        let mut guard = async_fd.readable().await?;

        // Drain all available events.
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;
            if data.len() < core::mem::size_of::<EventHeader>() {
                tracing::warn!(len = data.len(), "event too short, skipping");
                continue;
            }

            // SAFETY: EventHeader is repr(C), we checked the minimum length,
            // and the ring buffer may not guarantee alignment so we use
            // read_unaligned.
            let header = unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<EventHeader>()) };

            match header.event_type {
                EventType::Exec => log_exec_event(&header, data),
                EventType::Read | EventType::Write | EventType::Exit => {
                    tracing::debug!(
                        event_type = ?header.event_type,
                        "unhandled event type"
                    );
                }
            }
        }

        guard.clear_ready();
    }
}

fn log_exec_event(header: &EventHeader, data: &[u8]) {
    use oxilog_common::ExecEvent;

    if data.len() < core::mem::size_of::<ExecEvent>() {
        tracing::warn!("exec event too short");
        return;
    }

    // SAFETY: We verified the data length; use read_unaligned for safety.
    let event = unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<ExecEvent>()) };

    let filename = cstr_from_bytes(&event.filename);
    let arg_count = event.argc as usize;
    let argv: Vec<String> = (0..arg_count.min(oxilog_common::MAX_ARGV_COUNT))
        .map(|i| cstr_from_bytes(&event.argv[i]))
        .collect();

    info!(
        event = "exec",
        pid = header.pid,
        ppid = header.ppid,
        uid = header.uid,
        gid = header.gid,
        euid = header.euid,
        comm = %cstr_from_bytes(&header.comm),
        tty_nr = header.tty_nr,
        cgroup_id = header.cgroup_id,
        filename = %filename,
        argv = ?argv,
        retval = event.retval,
    );
}

/// Extract a UTF-8 string from a null-terminated byte buffer.
fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
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
