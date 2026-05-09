use anyhow::Result;
use oxilog_system_tests::{oxilog, ssh, vm::TestVm};

/// Build the oxilog binary path relative to the workspace root.
fn oxilog_binary() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/oxilog")
}

#[tokio::test]
async fn filter_pty_only_captures_pty_processes() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    vm.push_file(&oxilog_binary(), oxilog::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", oxilog::REMOTE_BIN)).await?;

    // Start oxilog with --filter-pty.
    let pid = oxilog::start_with_args(&session, "--filter-pty").await?;

    // Run a command via SSH (which has a PTY).
    ssh::exec(&session, "ls /tmp").await?;

    let lines = oxilog::stop_and_collect(&session, &pid).await?;

    // Should have exec events (SSH session has a PTY).
    let exec_events: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("\"event\":\"exec\""))
        .collect();

    // All captured events should have a non-zero tty_nr.
    for line in &exec_events {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(tty) = v.get("tty_nr").and_then(|t| t.as_u64()) {
                assert_ne!(tty, 0, "with --filter-pty, events should have tty_nr != 0");
            }
        }
    }

    session.close().await?;
    vm.destroy()?;
    Ok(())
}
