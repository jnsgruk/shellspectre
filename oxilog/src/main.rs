use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

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
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run { filter_pty } => {
            info!(filter_pty, "starting oxilog");
            tracing::warn!("run mode not yet implemented");
        }
        Command::Check => {
            check_capabilities()?;
        }
    }

    Ok(())
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
