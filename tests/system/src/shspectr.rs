use anyhow::{Context, Result};
use openssh::Session;

use crate::ssh;

/// Path where the shspectr binary is pushed inside the VM.
pub const REMOTE_BIN: &str = "/usr/local/bin/shspectr";

/// Path where shspectr JSON output is written inside the VM.
const REMOTE_LOG: &str = "/tmp/shspectr.jsonl";

/// Start shspectr in the background, capturing JSON output to a file.
/// Returns the PID of the background process.
pub async fn start(session: &Session) -> Result<String> {
    start_with_args(session, "").await
}

/// Start shspectr with extra CLI args, capturing JSON output to a file.
/// Returns the PID of the background process.
pub async fn start_with_args(session: &Session, extra_args: &str) -> Result<String> {
    let pid = ssh::exec(
        session,
        &format!("RUST_LOG=info {REMOTE_BIN} run {extra_args} > {REMOTE_LOG} 2>&1 & echo $!"),
    )
    .await
    .context("start shspectr")?;
    // Give the BPF programs a moment to attach.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    Ok(pid.trim().to_string())
}

/// Stop shspectr by PID and return the captured JSON lines.
pub async fn stop_and_collect(session: &Session, pid: &str) -> Result<Vec<String>> {
    // Send SIGTERM and wait briefly for clean shutdown.
    let _ = ssh::exec(session, &format!("kill {pid} 2>/dev/null; sleep 1")).await;
    let output = ssh::exec(session, &format!("cat {REMOTE_LOG}"))
        .await
        .context("read shspectr output")?;
    Ok(output.lines().map(String::from).collect())
}
