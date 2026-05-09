use anyhow::{Context, Result};
use openssh::{KnownHosts, Session, SessionBuilder};
use std::fs::OpenOptions;
use std::process::Command;
use tempfile::Builder;

/// Create an async SSH session to the test VM.
pub async fn connect(ip: &str, key_path: &str) -> Result<Session> {
    let known_hosts = Builder::new()
        .prefix("shspectr-system-known-hosts-")
        .tempfile()
        .context("create isolated known_hosts file")?;
    let (_file, known_hosts_path) = known_hosts.keep().context("persist known_hosts file")?;
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&known_hosts_path)
        .context("reset isolated known_hosts file")?;

    let session = SessionBuilder::default()
        .known_hosts_check(KnownHosts::Accept)
        .user_known_hosts_file(&known_hosts_path)
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

/// Execute a command through the system ssh client with a forced PTY.
pub async fn exec_with_pty(ip: &str, key_path: &str, cmd: &str) -> Result<String> {
    let output = tokio::task::spawn_blocking({
        let args = ssh_command_args(ip, key_path, cmd, true);
        move || Command::new("ssh").args(&args).output()
    })
    .await
    .context("join ssh exec with pty")?
    .context("SSH exec with pty")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("command failed: {cmd}\nstderr: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout).context("non-UTF8 output")?;
    Ok(stdout)
}

fn ssh_command_args(ip: &str, key_path: &str, cmd: &str, force_tty: bool) -> Vec<String> {
    let mut args = vec![
        "-o".to_owned(),
        "StrictHostKeyChecking=no".to_owned(),
        "-o".to_owned(),
        "UserKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=5".to_owned(),
        "-o".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "-i".to_owned(),
        key_path.to_owned(),
    ];

    if force_tty {
        // -tt forces PTY allocation. BatchMode=yes conflicts with PTY
        // sessions on some SSH versions and can cause indefinite hangs, so
        // it is omitted here. ServerAliveInterval provides a safety timeout.
        args.extend([
            "-tt".to_owned(),
            "-o".to_owned(),
            "ServerAliveInterval=10".to_owned(),
            "-o".to_owned(),
            "ServerAliveCountMax=3".to_owned(),
        ]);
    } else {
        args.extend(["-o".to_owned(), "BatchMode=yes".to_owned()]);
    }

    args.push(format!("root@{ip}"));
    args.push("bash".to_owned());
    args.push("-lc".to_owned());
    args.push(cmd.to_owned());
    args
}

#[cfg(test)]
mod tests {
    #[test]
    fn pty_ssh_command_avoids_user_known_hosts() {
        let args = super::ssh_command_args("192.0.2.10", "/tmp/test key", "tty", true);

        assert!(args.iter().any(|arg| arg == "UserKnownHostsFile=/dev/null"));
        assert!(args.iter().any(|arg| arg == "-tt"));
    }

    #[test]
    fn pty_ssh_command_omits_batch_mode() {
        // BatchMode=yes conflicts with PTY allocation and can cause hangs.
        let args = super::ssh_command_args("192.0.2.10", "/tmp/test key", "tty", true);

        assert!(!args.iter().any(|arg| arg == "BatchMode=yes"));
    }

    #[test]
    fn non_pty_ssh_command_uses_batch_mode() {
        let args = super::ssh_command_args("192.0.2.10", "/tmp/test key", "echo hi", false);

        assert!(args.iter().any(|arg| arg == "BatchMode=yes"));
        assert!(!args.iter().any(|arg| arg == "-tt"));
    }

    #[test]
    fn ssh_command_args_include_tty_flags_when_requested() {
        let args = super::ssh_command_args("192.0.2.10", "/tmp/test key", "tty", true);

        assert!(args.iter().any(|arg| arg == "-tt"));
        assert!(args.iter().any(|arg| arg == "/tmp/test key"));
        assert!(args.iter().any(|arg| arg == "root@192.0.2.10"));
    }
}
