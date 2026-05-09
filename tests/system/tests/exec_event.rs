use anyhow::Result;
use shspectr_system_tests::{shspectr, ssh, vm::TestVm};

/// Build the shspectr binary path relative to the workspace root.
fn shspectr_binary() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/shspectr")
}

#[tokio::test]
async fn exec_event_captures_ls() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    // Push the shspectr binary and make it executable.
    vm.push_file(&shspectr_binary(), shspectr::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", shspectr::REMOTE_BIN)).await?;

    // Start shspectr, run a command, then stop and collect output.
    let pid = shspectr::start(&session).await?;
    ssh::exec(&session, "ls /tmp").await?;
    let lines = shspectr::stop_and_collect(&session, &pid).await?;

    // Find at least one line mentioning "ls" with event_type Exec.
    let has_ls_exec = lines
        .iter()
        .any(|line| line.contains("\"event\":\"exec\"") && line.contains("/bin/ls"));

    assert!(
        has_ls_exec,
        "expected an exec event for 'ls' in output:\n{}",
        lines.join("\n")
    );

    session.close().await?;
    vm.destroy()?;
    Ok(())
}
