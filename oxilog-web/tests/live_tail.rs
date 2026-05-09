#![allow(clippy::expect_used)]
//! Integration tests for the SSE live tail endpoint.

mod support;

use rusqlite::params;

fn insert_test_session(conn: &rusqlite::Connection, id: &str) {
    conn.execute(
        "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
         VALUES (?1, datetime('now'), 100, 1000, 1000)",
        params![id],
    )
    .expect("insert test session");
}

fn insert_test_exec(
    conn: &rusqlite::Connection,
    session_id: &str,
    pid: u32,
    comm: &str,
) {
    let filename = format!("/usr/bin/{comm}");
    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm, filename, argv, exit_code) \
         VALUES (?1, 'exec', datetime('now'), ?2, 1, 1000, 1000, 1000, ?3, ?4, '[]', 0)",
        params![session_id, pid, comm, filename],
    )
    .expect("insert test exec event");
}

#[tokio::test]
async fn live_endpoint_returns_sse_content_type() {
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/events/live"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .expect("should have content-type")
        .to_str()
        .expect("content-type should be a string");
    assert!(
        ct.contains("text/event-stream"),
        "should be SSE content type, got: {ct}"
    );
}

#[tokio::test]
async fn live_endpoint_accepts_filter() {
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/events/live?q=comm:bash"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn live_endpoint_respects_last_event_id() {
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/events/live"))
        .header("last-event-id", "42")
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn live_endpoint_streams_new_events() {
    let (addr, pool) = support::start_test_server().await;

    // Seed initial data so max_event_id is set.
    {
        let conn = pool.get().expect("get conn");
        insert_test_session(&conn, "s1");
        insert_test_exec(&conn, "s1", 100, "ls");
    }

    // Connect to SSE endpoint.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/events/live"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    // Insert a new event while connected.
    {
        let conn = pool.get().expect("get conn");
        insert_test_exec(&conn, "s1", 200, "cat");
    }

    // Read some bytes from the stream — we should eventually get the new event.
    // Use a timeout to avoid hanging forever.
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        async {
            let mut text = String::new();
            let mut stream = resp.bytes_stream();
            use tokio_stream::StreamExt;
            // Read chunks until we find event data or exhaust patience.
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.expect("chunk error");
                text.push_str(&String::from_utf8_lossy(&chunk));
                if text.contains("datastar-patch-elements") {
                    break;
                }
            }
            text
        },
    )
    .await;

    match body {
        Ok(text) => {
            assert!(
                text.contains("datastar-patch-elements"),
                "should contain patch-elements event, got: {text}"
            );
            // Every HTML data line must carry the "elements " prefix so that
            // Datastar can distinguish HTML content from other directives.
            // Check that at least one data line has the prefix (not bare HTML).
            assert!(
                text.contains("data: elements "),
                "patch-elements data lines must be prefixed with 'elements ', got: {text}"
            );
            // The event row HTML should contain the command display.
            assert!(
                text.contains("/usr/bin/cat"),
                "should contain the event's filename in rendered HTML, got: {text}"
            );
        }
        Err(_) => panic!("timed out waiting for SSE event"),
    }
}

#[tokio::test]
async fn live_endpoint_with_filter_only_streams_matching() {
    let (addr, pool) = support::start_test_server().await;

    {
        let conn = pool.get().expect("get conn");
        insert_test_session(&conn, "s1");
    }

    // Connect filtering for comm:bash only.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/events/live?q=comm:bash"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    // Insert non-matching and matching events.
    {
        let conn = pool.get().expect("get conn");
        insert_test_exec(&conn, "s1", 100, "ls");
        insert_test_exec(&conn, "s1", 101, "bash");
    }

    let body = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        async {
            let mut text = String::new();
            let mut stream = resp.bytes_stream();
            use tokio_stream::StreamExt;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.expect("chunk error");
                text.push_str(&String::from_utf8_lossy(&chunk));
                if text.contains("datastar-patch-elements") {
                    break;
                }
            }
            text
        },
    )
    .await;

    match body {
        Ok(text) => {
            assert!(text.contains("bash"), "should contain bash event, got: {text}");
            assert!(
                text.contains("datastar-patch-elements"),
                "should have patch event"
            );
        }
        Err(_) => panic!("timed out waiting for filtered SSE event"),
    }
}
