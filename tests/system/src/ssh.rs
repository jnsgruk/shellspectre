use anyhow::{Context, Result};
use openssh::{KnownHosts, Session, SessionBuilder};

/// Create an async SSH session to the test VM.
pub async fn connect(ip: &str, key_path: &str) -> Result<Session> {
    let session = SessionBuilder::default()
        .known_hosts_check(KnownHosts::Accept)
        .keyfile(key_path)
        .user("root".to_string())
        .connect(ip)
        .await
        .context("SSH connect")?;
    Ok(session)
}

/// Execute a command over SSH and return stdout as a string.
pub async fn exec(session: &Session, cmd: &str) -> Result<String> {
    let output = session
        .command("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .context("SSH exec")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("command failed: {cmd}\nstderr: {stderr}");
    }
    let stdout = String::from_utf8(output.stdout).context("non-UTF8 output")?;
    Ok(stdout)
}
