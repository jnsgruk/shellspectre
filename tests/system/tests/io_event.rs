use anyhow::Result;
use oxilog_system_tests::{oxilog, ssh, vm::TestVm};

/// Build the oxilog binary path relative to the workspace root.
fn oxilog_binary() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/oxilog")
}

#[tokio::test]
async fn write_event_captures_echo_output() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    vm.push_file(&oxilog_binary(), oxilog::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", oxilog::REMOTE_BIN)).await?;

    let pid = oxilog::start(&session).await?;

    // Use /bin/echo (not builtin) to ensure it's a separate process
    // whose write to fd 1 we can capture.
    ssh::exec(&session, "/bin/echo 'oxilog-test-marker'").await?;

    let lines = oxilog::stop_and_collect(&session, &pid).await?;

    // Assert: write event containing our marker string.
    let has_write = lines
        .iter()
        .any(|line| line.contains("\"event\":\"write\"") && line.contains("oxilog-test-marker"));
    assert!(
        has_write,
        "expected a write event containing 'oxilog-test-marker' in output:\n{}",
        lines.join("\n")
    );

    session.close().await?;
    vm.destroy()?;
    Ok(())
}

#[tokio::test]
async fn read_event_captures_stdin() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    vm.push_file(&oxilog_binary(), oxilog::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", oxilog::REMOTE_BIN)).await?;

    let pid = oxilog::start(&session).await?;

    // Use dd which always does plain read() syscalls on fd 0.
    // Avoid cat/head which may use splice() for pipe optimization.
    ssh::exec(
        &session,
        "echo 'oxilog-stdin-marker' | /usr/bin/dd bs=100 count=1 2>/dev/null",
    )
    .await?;

    let lines = oxilog::stop_and_collect(&session, &pid).await?;

    // Assert: read event for cat containing our marker.
    let has_read = lines
        .iter()
        .any(|line| line.contains("\"event\":\"read\"") && line.contains("oxilog-stdin-marker"));
    assert!(
        has_read,
        "expected a read event containing 'oxilog-stdin-marker' in output:\n{}",
        lines.join("\n")
    );

    session.close().await?;
    vm.destroy()?;
    Ok(())
}
