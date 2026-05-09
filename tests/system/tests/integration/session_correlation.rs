use anyhow::Result;
use shspectr_system_tests::harness::TestHarness;

#[tokio::test]
async fn events_in_same_ssh_session_share_session_id() -> Result<()> {
    let h = TestHarness::new().await?;

    let events = h
        .capture_default(|| async {
            h.exec_with_pty("ls /tmp >/dev/null; pwd >/dev/null; whoami >/dev/null")
                .await?;
            Ok(())
        })
        .await?;

    let session_ids: Vec<&str> = events
        .iter()
        .filter(|e| {
            e.is_exec()
                && e.filename.as_deref().is_some_and(|f| {
                    let name = f.rsplit('/').next().unwrap_or(f);
                    name == "ls" || name == "whoami"
                })
        })
        .filter_map(|e| e.session_id.as_deref())
        .collect();

    assert!(
        session_ids.len() >= 2,
        "expected at least 2 exec events with session_id, got {}: {session_ids:?}",
        session_ids.len(),
    );

    let first = session_ids[0];
    assert!(
        first.starts_with("ox_"),
        "session_id should start with ox_: {first}"
    );
    for sid in &session_ids[1..] {
        assert_eq!(
            *sid, first,
            "all events in same SSH session should share session_id"
        );
    }

    h.close().await
}
