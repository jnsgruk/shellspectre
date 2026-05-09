use anyhow::Result;
use shspectr_system_tests::harness::TestHarness;

const REMOTE_DB: &str = "/tmp/shspectr-test.db";
const LOCAL_DB: &str = "/tmp/shspectr-test-pulled.db";
const LOCAL_WAL: &str = "/tmp/shspectr-test-pulled.db-wal";
const LOCAL_SHM: &str = "/tmp/shspectr-test-pulled.db-shm";

#[tokio::test]
async fn sqlite_sink_stores_events() -> Result<()> {
    let h = TestHarness::new().await?;

    let pid = h
        .start(&format!("--output sqlite --db-path {REMOTE_DB}"))
        .await?;

    h.exec("ls /tmp").await?;
    h.exec("/usr/bin/true").await?;
    h.exec("/usr/bin/false || /usr/bin/true").await?;

    let _lines = h.stop_and_collect(&pid).await?;

    // Pull the SQLite DB from the VM.
    h.with_vm(|vm| {
        vm.pull_file(REMOTE_DB, LOCAL_DB)?;
        let _ = vm.pull_file(&format!("{REMOTE_DB}-wal"), LOCAL_WAL);
        let _ = vm.pull_file(&format!("{REMOTE_DB}-shm"), LOCAL_SHM);
        Ok::<_, anyhow::Error>(())
    })?;

    let conn = rusqlite::Connection::open(LOCAL_DB)?;
    assert_schema_populated(&conn)?;
    assert_exit_codes_backfilled(&conn)?;

    // Clean up pulled files.
    std::fs::remove_file(LOCAL_DB).ok();
    std::fs::remove_file(LOCAL_WAL).ok();
    std::fs::remove_file(LOCAL_SHM).ok();

    h.close().await
}

fn assert_schema_populated(conn: &rusqlite::Connection) -> Result<()> {
    let session_count: i64 = conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
    assert!(
        session_count >= 1,
        "expected at least 1 session, got {session_count}"
    );

    let exec_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type = 'exec'",
        [],
        |r| r.get(0),
    )?;
    assert!(
        exec_count >= 1,
        "expected at least 1 exec event, got {exec_count}"
    );

    let exit_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type = 'exit'",
        [],
        |r| r.get(0),
    )?;
    assert!(
        exit_count >= 1,
        "expected at least 1 exit event, got {exit_count}"
    );

    let orphan_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events e LEFT JOIN sessions s ON e.session_id = s.id WHERE s.id IS NULL",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        orphan_count, 0,
        "no events should be orphaned from sessions"
    );

    let zero_execution_ids: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE execution_id = 0",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        zero_execution_ids, 0,
        "all persisted events should have non-zero execution_id"
    );

    let ended_session_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE ended_at IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    assert!(
        ended_session_count >= 1,
        "expected at least one completed session with ended_at set"
    );

    Ok(())
}

fn assert_exit_codes_backfilled(conn: &rusqlite::Connection) -> Result<()> {
    let ls_exit_code: i64 = conn.query_row(
        "SELECT exit_code FROM events WHERE event_type = 'exec' AND filename = '/usr/bin/ls' ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        ls_exit_code, 0,
        "ls exec row should have exit code backfilled"
    );

    let true_exit_code: i64 = conn.query_row(
        "SELECT exit_code FROM events WHERE event_type = 'exec' AND filename = '/usr/bin/true' ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        true_exit_code, 0,
        "true exec row should have exit code backfilled"
    );

    let false_exit_code: i64 = conn.query_row(
        "SELECT exit_code FROM events WHERE event_type = 'exec' AND filename = '/usr/bin/false' ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        false_exit_code, 1,
        "false exec row should have exit code backfilled"
    );

    Ok(())
}
