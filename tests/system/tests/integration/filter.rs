use anyhow::Result;
use shspectr_system_tests::harness::TestHarness;

#[tokio::test]
async fn filter_pty_only_captures_pty_processes() -> Result<()> {
    let h = TestHarness::new().await?;

    let events = h
        .capture("--filter-pty", || async {
            h.exec_with_pty("ls /tmp").await?;
            Ok(())
        })
        .await?;

    let exec_events: Vec<_> = events.iter().filter(|e| e.is_exec()).collect();

    for event in &exec_events {
        if let Some(tty) = event.tty_nr {
            assert_ne!(tty, 0, "with --filter-pty, events should have tty_nr != 0");
        }
    }

    h.close().await
}
