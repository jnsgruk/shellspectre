use anyhow::Result;
use shspectr_system_tests::{shspectr, ssh, vm::TestVm};

/// Build the shspectr binary path relative to the workspace root.
fn shspectr_binary() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/shspectr")
}

#[tokio::test]
async fn write_event_captures_echo_output() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    vm.push_file(&shspectr_binary(), shspectr::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", shspectr::REMOTE_BIN)).await?;

    let pid = shspectr::start(&session).await?;

    // Use /bin/echo (not builtin) to ensure it's a separate process
    // whose write to fd 1 we can capture.
    ssh::exec(&session, "/bin/echo 'shspectr-test-marker'").await?;

    let lines = shspectr::stop_and_collect(&session, &pid).await?;

    // Assert: write event containing our marker string.
    let has_write = lines
        .iter()
        .any(|line| line.contains("\"event\":\"write\"") && line.contains("shspectr-test-marker"));
    assert!(
        has_write,
        "expected a write event containing 'shspectr-test-marker' in output:\n{}",
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

    vm.push_file(&shspectr_binary(), shspectr::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", shspectr::REMOTE_BIN)).await?;

    let pid = shspectr::start(&session).await?;

    // Use dd which always does plain read() syscalls on fd 0.
    // Avoid cat/head which may use splice() for pipe optimization.
    ssh::exec(
        &session,
        "echo 'shspectr-stdin-marker' | /usr/bin/dd bs=100 count=1 2>/dev/null",
    )
    .await?;

    let lines = shspectr::stop_and_collect(&session, &pid).await?;

    // Assert: read event for cat containing our marker.
    let has_read = lines
        .iter()
        .any(|line| line.contains("\"event\":\"read\"") && line.contains("shspectr-stdin-marker"));
    assert!(
        has_read,
        "expected a read event containing 'shspectr-stdin-marker' in output:\n{}",
        lines.join("\n")
    );

    session.close().await?;
    vm.destroy()?;
    Ok(())
}
