use anyhow::Result;
use shspectr_system_tests::harness::TestHarness;

#[tokio::test]
async fn exec_event_captures_ls() -> Result<()> {
    let h = TestHarness::new().await?;

    let events = h
        .capture_default(|| async {
            h.exec("ls /tmp").await?;
            Ok(())
        })
        .await?;

    assert!(
        events
            .iter()
            .any(|e| e.is_exec() && e.filename.as_deref().is_some_and(|f| f.contains("ls"))),
        "expected an exec event for 'ls', got: {events:#?}"
    );

    h.close().await
}
