use anyhow::Result;
use shspectr_system_tests::harness::TestHarness;

#[tokio::test]
async fn write_event_captures_echo_output() -> Result<()> {
    let h = TestHarness::new().await?;

    let events = h
        .capture_default(|| async {
            h.exec("/bin/echo 'shspectr-test-marker'").await?;
            Ok(())
        })
        .await?;

    assert!(
        events.iter().any(|e| e.is_write()
            && e.data
                .as_deref()
                .is_some_and(|d| d.contains("shspectr-test-marker"))),
        "expected a write event containing 'shspectr-test-marker', got: {events:#?}"
    );

    h.close().await
}

#[tokio::test]
async fn read_event_captures_stdin() -> Result<()> {
    let h = TestHarness::new().await?;

    let events = h
        .capture_default(|| async {
            h.exec("echo 'shspectr-stdin-marker' | /usr/bin/dd bs=100 count=1 2>/dev/null")
                .await?;
            Ok(())
        })
        .await?;

    assert!(
        events.iter().any(|e| e.is_read()
            && e.data
                .as_deref()
                .is_some_and(|d| d.contains("shspectr-stdin-marker"))),
        "expected a read event containing 'shspectr-stdin-marker', got: {events:#?}"
    );

    h.close().await
}
