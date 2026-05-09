use anyhow::{Context, Result};
use openssh::Session;
use tokio::time::Duration;

use crate::ssh;

/// Path where the shspectr binary is pushed inside the VM.
pub const REMOTE_BIN: &str = "/usr/local/bin/shspectr";

/// Path where the eBPF artifact is pushed inside the VM.
pub const REMOTE_EBPF: &str = "/usr/local/lib/shspectr/shspectr-ebpf";

/// Local path to the compiled shspectr binary.
pub fn binary_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/shspectr")
}

/// Local path to the compiled eBPF artifact.
pub fn ebpf_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../shspectr-ebpf/target/bpfel-unknown-none/release/shspectr-ebpf")
}

/// Install the shspectr binary and eBPF artifact into the VM.
///
/// The artifact directory and systemd unit are baked into the base image,
/// so this only pushes the two binaries and sets permissions.
pub async fn install(session: &Session, vm: &crate::vm::TestVm) -> Result<()> {
    vm.push_file(&binary_path(), REMOTE_BIN)?;
    vm.push_file(&ebpf_path(), REMOTE_EBPF)?;
    ssh::exec(
        session,
        &format!("chmod +x {REMOTE_BIN} && chmod 644 {REMOTE_EBPF}"),
    )
    .await?;
    Ok(())
}

/// Path where shspectr JSON output is written inside the VM.
const REMOTE_LOG: &str = "/tmp/shspectr.jsonl";
const UNIT_NAME: &str = "shspectr-test.service";
const ENV_FILE: &str = "/etc/shspectr-test.env";

/// The log line that indicates shspectr is ready to record events.
const READINESS_MARKER: &str = "consuming events from ring buffer";

/// Start shspectr in the background, capturing JSON output to a file.
/// Returns the PID of the background process.
pub async fn start(session: &Session) -> Result<String> {
    start_with_args(session, "").await
}

/// Start shspectr with extra CLI args, capturing JSON output to a file.
/// Returns the PID of the background process.
pub async fn start_with_args(session: &Session, extra_args: &str) -> Result<String> {
    let pid = tokio::time::timeout(
        Duration::from_secs(15),
        ssh::exec(session, &start_command(extra_args)),
    )
    .await
    .context("timed out launching shspectr")??;
    let pid = pid.trim().to_string();
    wait_until_ready(session).await?;
    Ok(pid)
}

/// Stop shspectr by PID and return the captured JSON lines.
pub async fn stop_and_collect(session: &Session, pid: &str) -> Result<Vec<String>> {
    let output = ssh::exec(session, &stop_command(pid))
        .await
        .context("stop shspectr and read output")?;
    Ok(output.lines().map(String::from).collect())
}

/// Build the shell command to start shspectr via its pre-installed systemd unit.
///
/// The unit is baked into the base VM image. We write a drop-in environment
/// file with extra args, then start the service. No `daemon-reload` needed.
fn start_command(extra_args: &str) -> String {
    let args = extra_args.trim();
    format!(
        "systemctl stop {UNIT_NAME} 2>/dev/null || true; \
         systemctl reset-failed {UNIT_NAME} 2>/dev/null || true; \
         : > {REMOTE_LOG}; \
         printf 'SHSPECTR_EXTRA_ARGS={args}' > {ENV_FILE}; \
         systemctl start {UNIT_NAME} && \
         systemctl show -p MainPID --value {UNIT_NAME}"
    )
}

fn stop_command(pid: &str) -> String {
    format!(
        "systemctl stop {UNIT_NAME} 2>/dev/null || true; \
         for _ in $(seq 1 50); do \
           kill -0 {pid} 2>/dev/null || break; \
           sleep 0.1; \
         done; \
         systemctl reset-failed {UNIT_NAME} 2>/dev/null || true; \
         cat {REMOTE_LOG}"
    )
}

/// Wait for shspectr to become ready inside the VM.
///
/// Runs a single SSH command that polls the log file from *within* the VM,
/// avoiding repeated SSH round-trips.
async fn wait_until_ready(session: &Session) -> Result<()> {
    let script = format!(
        "for i in $(seq 1 100); do \
           grep -qF '{READINESS_MARKER}' {REMOTE_LOG} 2>/dev/null && exit 0; \
           pgrep -f '{REMOTE_BIN} run' >/dev/null 2>&1 || \
             {{ echo 'PROCESS_DIED'; cat {REMOTE_LOG} 2>/dev/null; exit 1; }}; \
           sleep 0.1; \
         done; \
         echo 'TIMEOUT'; cat {REMOTE_LOG} 2>/dev/null; exit 1"
    );
    let output = tokio::time::timeout(Duration::from_secs(15), ssh::exec(session, &script))
        .await
        .context("timed out waiting for shspectr readiness")?;

    match output {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("PROCESS_DIED") {
                anyhow::bail!("shspectr exited during startup:\n{msg}");
            }
            anyhow::bail!("shspectr did not become ready within 10s:\n{msg}");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn start_command_clears_log_and_writes_env_file() {
        let command = super::start_command("--filter-pty");

        assert!(
            command.contains("systemctl stop shspectr-test.service"),
            "should stop any previous instance"
        );
        assert!(
            command.contains(": > /tmp/shspectr.jsonl"),
            "should truncate the log file"
        );
        assert!(
            command.contains("printf 'SHSPECTR_EXTRA_ARGS=--filter-pty' > /etc/shspectr-test.env"),
            "should write extra args to env file"
        );
        assert!(
            command.contains("systemctl start shspectr-test.service"),
            "should start the unit"
        );
        assert!(
            command.ends_with("systemctl show -p MainPID --value shspectr-test.service"),
            "should return the PID"
        );
        // Should NOT contain heredoc or daemon-reload
        assert!(
            !command.contains("cat <<"),
            "should not generate unit file at runtime"
        );
        assert!(
            !command.contains("daemon-reload"),
            "should not need daemon-reload"
        );
    }

    #[test]
    fn start_command_with_empty_args_writes_empty_env() {
        let command = super::start_command("");

        assert!(
            command.contains("printf 'SHSPECTR_EXTRA_ARGS=' > /etc/shspectr-test.env"),
            "should write empty args"
        );
    }

    #[test]
    fn ebpf_path_points_to_release_artifact() {
        assert!(
            super::ebpf_path()
                .ends_with("shspectr-ebpf/target/bpfel-unknown-none/release/shspectr-ebpf")
        );
    }

    #[test]
    fn stop_command_uses_systemctl_and_polls_for_exit() {
        let command = super::stop_command("4242");

        assert!(
            command.contains("systemctl stop shspectr-test.service"),
            "should stop via systemctl"
        );
        assert!(
            command.contains("kill -0 4242 2>/dev/null || break"),
            "should poll for process exit"
        );
        assert!(
            command.contains("cat /tmp/shspectr.jsonl"),
            "should return log contents"
        );
    }
}
