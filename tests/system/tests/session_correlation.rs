use anyhow::Result;
use oxilog_system_tests::{oxilog, ssh, vm::TestVm};

/// Build the oxilog binary path relative to the workspace root.
fn oxilog_binary() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/oxilog")
}

#[tokio::test]
async fn events_in_same_ssh_session_share_session_id() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    vm.push_file(&oxilog_binary(), oxilog::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", oxilog::REMOTE_BIN)).await?;

    // Start oxilog, run multiple commands in the same SSH session.
    let pid = oxilog::start(&session).await?;
    ssh::exec(&session, "ls /tmp").await?;
    ssh::exec(&session, "pwd").await?;
    ssh::exec(&session, "whoami").await?;
    let lines = oxilog::stop_and_collect(&session, &pid).await?;

    // Extract session_id from all exec events.
    let session_ids: Vec<String> = lines
        .iter()
        .filter(|line| line.contains("\"event\":\"exec\""))
        .filter(|line| {
            line.contains("/bin/ls") || line.contains("/bin/pwd") || line.contains("/bin/whoami")
        })
        .filter_map(|line| {
            // Parse the JSON to extract session_id.
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            v.get("session_id")
                .and_then(|s| s.as_str())
                .map(String::from)
        })
        .collect();

    assert!(
        session_ids.len() >= 3,
        "expected at least 3 exec events with session_id, got {}: {:?}",
        session_ids.len(),
        session_ids,
    );

    // All session IDs should be the same (same SSH session = same PTY).
    let first = &session_ids[0];
    assert!(
        first.starts_with("ox_"),
        "session_id should start with ox_: {first}"
    );
    for sid in &session_ids[1..] {
        assert_eq!(
            sid, first,
            "all events in same SSH session should share session_id"
        );
    }

    session.close().await?;
    vm.destroy()?;
    Ok(())
}
