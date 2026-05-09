use anyhow::Result;
use oxilog_system_tests::{oxilog, ssh, vm::TestVm};

/// Build the oxilog binary path relative to the workspace root.
fn oxilog_binary() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../../target/debug/oxilog")
}

const REMOTE_DB: &str = "/tmp/oxilog-test.db";
const LOCAL_DB: &str = "/tmp/oxilog-test-pulled.db";

#[tokio::test]
async fn sqlite_sink_stores_events() -> Result<()> {
    let mut vm = TestVm::provision()?;
    let session = ssh::connect(&vm.ip, &vm.private_key_path).await?;

    vm.push_file(&oxilog_binary(), oxilog::REMOTE_BIN)?;
    ssh::exec(&session, &format!("chmod +x {}", oxilog::REMOTE_BIN)).await?;

    // Start oxilog with SQLite output.
    let pid = oxilog::start_with_args(&session, &format!("--output sqlite --db-path {REMOTE_DB}"))
        .await?;

    // Run commands.
    ssh::exec(&session, "ls /tmp").await?;
    ssh::exec(&session, "true").await?;
    ssh::exec(&session, "false || true").await?;

    let _lines = oxilog::stop_and_collect(&session, &pid).await?;

    // Pull the SQLite DB from the VM.
    vm.pull_file(REMOTE_DB, LOCAL_DB)?;

    // Open and query the DB.
    let conn = rusqlite::Connection::open(LOCAL_DB)?;

    // Should have at least one session.
    let session_count: i64 = conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
    assert!(
        session_count >= 1,
        "expected at least 1 session, got {session_count}"
    );

    // Should have exec events.
    let exec_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type = 'exec'",
        [],
        |r| r.get(0),
    )?;
    assert!(
        exec_count >= 1,
        "expected at least 1 exec event, got {exec_count}"
    );

    // Should have exit events.
    let exit_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type = 'exit'",
        [],
        |r| r.get(0),
    )?;
    assert!(
        exit_count >= 1,
        "expected at least 1 exit event, got {exit_count}"
    );

    // Events should reference valid sessions.
    let orphan_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events e LEFT JOIN sessions s ON e.session_id = s.id WHERE s.id IS NULL",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        orphan_count, 0,
        "no events should be orphaned from sessions"
    );

    // Clean up.
    std::fs::remove_file(LOCAL_DB).ok();
    session.close().await?;
    vm.destroy()?;
    Ok(())
}
