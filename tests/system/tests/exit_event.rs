use anyhow::Result;
use oxilog_system_tests::{oxilog, ssh, vm::TestVm};

/// Build the oxilog binary path relative to the workspace root.
fn oxilog_binary() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/oxilog")
}

#[tokio::test]
async fn exit_event_captures_exit_codes() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    vm.push_file(&oxilog_binary(), oxilog::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", oxilog::REMOTE_BIN)).await?;

    let pid = oxilog::start(&session).await?;

    // Run `true` (exit 0) and `false` (exit 1).
    // Wrap `false` so the SSH command itself doesn't fail.
    ssh::exec(&session, "/bin/true").await?;
    ssh::exec(&session, "/bin/false || true").await?;

    let lines = oxilog::stop_and_collect(&session, &pid).await?;

    // Assert: exit event with exit_code 0 from /bin/true.
    let has_exit_0 = lines.iter().any(|line| {
        line.contains("\"event\":\"exit\"")
            && line.contains("\"comm\":\"true\"")
            && line.contains("\"exit_code\":0")
    });
    assert!(
        has_exit_0,
        "expected an exit event with exit_code=0 for 'true' in output:\n{}",
        lines.join("\n")
    );

    // Assert: exit event with exit_code 1 from /bin/false.
    let has_exit_1 = lines.iter().any(|line| {
        line.contains("\"event\":\"exit\"")
            && line.contains("\"comm\":\"false\"")
            && line.contains("\"exit_code\":1")
    });
    assert!(
        has_exit_1,
        "expected an exit event with exit_code=1 for 'false' in output:\n{}",
        lines.join("\n")
    );

    session.close().await?;
    vm.destroy()?;
    Ok(())
}
