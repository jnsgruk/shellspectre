use anyhow::{Context, Result, bail};
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::filter;
use crate::handler;
use crate::session;
use crate::sink::Sink;

#[cfg(feature = "web")]
use shspectr_web::ServerConfig;

pub(crate) fn check_capabilities() -> Result<()> {
    use std::path::Path;

    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!(
            "BTF not available at /sys/kernel/btf/vmlinux — kernel must be built with CONFIG_DEBUG_INFO_BTF=y"
        );
    }

    if !Path::new("/sys/fs/bpf").exists() {
        bail!("BPF filesystem not mounted at /sys/fs/bpf");
    }

    // SAFETY: geteuid is a simple syscall with no preconditions
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("must run as root (or with CAP_BPF + CAP_PERFMON capabilities)");
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

fn load_ebpf_bytes() -> Result<Vec<u8>> {
    let path = ebpf_artifact_path();
    std::fs::read(&path).with_context(|| {
        format!(
            "failed to read eBPF artifact at {}; run `mise run build-ebpf` or `mise run build` first",
            path.display()
        )
    })
}

fn ebpf_artifact_path() -> std::path::PathBuf {
    let env_override = std::env::var("SHSPECTR_EBPF_PATH").ok();
    let current_exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("shspectr"));
    ebpf_artifact_path_from(env_override, &current_exe)
}

fn ebpf_artifact_path_from(
    env_override: Option<String>,
    current_exe: &std::path::Path,
) -> std::path::PathBuf {
    if let Some(path) = env_override.filter(|path| !path.is_empty()) {
        return std::path::PathBuf::from(path);
    }

    if current_exe
        .parent()
        .and_then(std::path::Path::file_name)
        .is_some_and(|name| name == "debug" || name == "release")
        && let Some(workspace_root) = current_exe
            .parent()
            .and_then(std::path::Path::parent)
            .and_then(std::path::Path::parent)
    {
        return workspace_root
            .join("shspectr-ebpf/target/bpfel-unknown-none/release/shspectr-ebpf");
    }

    current_exe
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(
            || {
                std::path::PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../shspectr-ebpf/target/bpfel-unknown-none/release/shspectr-ebpf"
                ))
            },
            |root| root.join("shspectr-ebpf"),
        )
}

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
pub(crate) fn run(
    filter_config: filter::FilterConfig,
    sink: Box<dyn Sink>,
    #[cfg(feature = "web")] web_config: Option<ServerConfig>,
    #[cfg(not(feature = "web"))] _web_config: (),
) -> Result<()> {
    info!(
        filter_pty = filter_config.filter_pty,
        filter_ancestors = ?filter_config.filter_ancestors,
        "starting shspectr",
    );

    let mut ebpf = Ebpf::load(&load_ebpf_bytes()?).context("failed to load eBPF program")?;

    // Tell eBPF to skip events from our own process (avoids feedback loops).
    let mut self_tgid_map: aya::maps::Array<_, u32> = aya::maps::Array::try_from(
        ebpf.take_map("SELF_TGID")
            .context("SELF_TGID map not found")?,
    )?;
    self_tgid_map.set(0, std::process::id(), 0)?;

    // Resolve kernel struct field offsets from BTF and pass to eBPF.
    let offsets = crate::btf::resolve_task_field_offsets()?;
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

    attach_tracepoint(&mut ebpf, "sys_enter_execve")?;
    attach_tracepoint(&mut ebpf, "sys_exit_execve")?;
    attach_tracepoint(&mut ebpf, "sys_enter_exit_group")?;
    attach_tracepoint(&mut ebpf, "sys_enter_write")?;
    attach_tracepoint(&mut ebpf, "sys_exit_write")?;
    attach_tracepoint(&mut ebpf, "sys_enter_read")?;
    attach_tracepoint(&mut ebpf, "sys_exit_read")?;

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
    sink: Box<dyn Sink>,
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
    let mut correlator = session::SessionCorrelator::default();

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
                    handler::handle_event(&item, &mut correlator, &filter_config, &*sink);
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ebpf_path_prefers_environment_override() {
        let path = super::ebpf_artifact_path_from(
            Some("/tmp/custom-ebpf".to_owned()),
            std::path::Path::new("/ignored/bin/shspectr"),
        );

        assert_eq!(path, std::path::PathBuf::from("/tmp/custom-ebpf"));
    }

    #[test]
    fn ebpf_path_falls_back_next_to_binary_tree() {
        let path = super::ebpf_artifact_path_from(
            None,
            std::path::Path::new("/opt/shspectr/bin/shspectr"),
        );

        assert_eq!(
            path,
            std::path::PathBuf::from("/opt/shspectr/shspectr-ebpf")
        );
    }

    #[test]
    fn ebpf_path_uses_workspace_layout_for_target_debug_binary() {
        let path = super::ebpf_artifact_path_from(
            None,
            std::path::Path::new("/home/jon/oxilog/target/debug/shspectr"),
        );

        assert_eq!(
            path,
            std::path::PathBuf::from(
                "/home/jon/oxilog/shspectr-ebpf/target/bpfel-unknown-none/release/shspectr-ebpf"
            )
        );
    }
}
