use anyhow::Result;
use shspectr_system_tests::harness::TestHarness;

#[tokio::test]
async fn exit_event_captures_exit_codes() -> Result<()> {
    let h = TestHarness::new().await?;

    let events = h
        .capture_default(|| async {
            h.exec("/bin/true").await?;
            h.exec("/bin/false || true").await?;
            Ok(())
        })
        .await?;

    assert!(
        events
            .iter()
            .any(|e| e.is_exit() && e.comm.as_deref() == Some("true") && e.exit_code == Some(0)),
        "expected an exit event with exit_code=0 for 'true', got: {events:#?}"
    );

    assert!(
        events
            .iter()
            .any(|e| e.is_exit() && e.comm.as_deref() == Some("false") && e.exit_code == Some(1)),
        "expected an exit event with exit_code=1 for 'false', got: {events:#?}"
    );

    h.close().await
}
