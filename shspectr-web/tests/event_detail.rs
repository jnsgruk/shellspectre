#![allow(clippy::expect_used)]
//! Integration tests for the event detail endpoint.

mod support;

use rusqlite::params;
use shspectr_web::infrastructure::database::DbPool;

fn seed_event_with_io(pool: &DbPool) -> i64 {
    seed_event_with_io_for_session(pool, "s1")
}

fn seed_event_with_io_for_session(pool: &DbPool, session_id: &str) -> i64 {
    let conn = pool.get().expect("get conn");
    conn.execute(
        "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
         VALUES (?1, datetime('now'), 100, 1000, 1000)",
        params![session_id],
    )
    .expect("insert session");

    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, execution_id, pid, ppid, uid, gid, euid, comm, filename, argv, exit_code, tty_nr) \
         VALUES (?1, 0, '2026-05-10T14:32:01', 4821, 4821, 4800, 1000, 1000, 1000, 'cat', '/usr/bin/cat', \
                 '[\"cat\",\"secret.txt\"]', 0, ?2)",
        params![session_id, 0x8803u32], // pts/3
    )
    .expect("insert exec");

    let id: i64 = conn
        .query_row(
            "SELECT id FROM events WHERE event_type = 0 LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("get id");

    // Add I/O data.
    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, execution_id, pid, ppid, uid, gid, euid, fd, data, data_len, byte_count) \
         VALUES (?1, 3, '2026-05-10T14:32:02', 4821, 4821, 4800, 1000, 1000, 1000, 1, 'TOP SECRET\n', 11, 11)",
        params![session_id],
    )
    .expect("insert io");

    id
}

#[tokio::test]
async fn detail_returns_html_fragment() {
    let (addr, pool) = support::start_test_server().await;
    let id = seed_event_with_io(&pool);

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/events/{id}/detail"))
        .header("datastar-request", "true")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);

    let body = resp.text().await.expect("body");
    assert!(
        body.contains(&format!("detail-{id}")),
        "should contain detail element ID"
    );
    assert!(body.contains("pts/3"), "should show TTY");
    assert!(body.contains("4821"), "should show PID");
    assert!(body.contains("4800"), "should show PPID");
    assert!(body.contains("cat secret.txt"), "should show full command");
    assert!(body.contains("TOP SECRET"), "should show stdout data");
}

#[tokio::test]
async fn detail_not_found_returns_404() {
    let (addr, _pool) = support::start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/events/99999/detail"))
        .header("datastar-request", "true")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 404);
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("not found"),
        "should indicate event not found"
    );
}

#[tokio::test]
async fn detail_metadata_fields_present() {
    let (addr, pool) = support::start_test_server().await;
    let id = seed_event_with_io(&pool);

    let body = reqwest::get(format!("http://{addr}/api/v1/events/{id}/detail"))
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    // Check all metadata grid labels are present.
    for label in &[
        "Session:", "PID:", "PPID:", "UID:", "EUID:", "GID:", "TTY:", "Exit:",
    ] {
        assert!(body.contains(label), "should contain '{label}'");
    }
}

#[tokio::test]
async fn detail_no_io_shows_message() {
    let (addr, pool) = support::start_test_server().await;

    let conn = pool.get().expect("get conn");
    conn.execute(
        "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
         VALUES ('s2', datetime('now'), 100, 1000, 1000)",
        [],
    )
    .expect("insert session");
    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, execution_id, pid, ppid, uid, gid, euid, comm) \
         VALUES ('s2', 0, datetime('now'), 100, 100, 1, 1000, 1000, 1000, 'ls')",
        [],
    )
    .expect("insert event");
    let id: i64 = conn
        .query_row("SELECT id FROM events WHERE comm = 'ls'", [], |r| r.get(0))
        .expect("get id");
    drop(conn);

    let body = reqwest::get(format!("http://{addr}/api/v1/events/{id}/detail"))
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    assert!(
        body.contains("No I/O data captured"),
        "should show no-IO message"
    );
}

#[tokio::test]
async fn raw_stdout_returns_plain_text() {
    let (addr, pool) = support::start_test_server().await;
    let id = seed_event_with_io(&pool);

    let resp = reqwest::get(format!(
        "http://{addr}/api/v1/events/{id}/raw?stream=stdout"
    ))
    .await
    .expect("request");

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .expect("content-type")
        .to_str()
        .expect("str");
    assert!(ct.contains("text/plain"), "should be plain text: {ct}");
    let body = resp.text().await.expect("body");
    assert_eq!(body, "TOP SECRET\n");
}

#[tokio::test]
async fn raw_not_found_returns_404() {
    let (addr, _pool) = support::start_test_server().await;
    let resp = reqwest::get(format!("http://{addr}/api/v1/events/99999/raw"))
        .await
        .expect("request");
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn raw_invalid_stream_returns_400() {
    let (addr, pool) = support::start_test_server().await;
    let id = seed_event_with_io(&pool);

    let resp = reqwest::get(format!(
        "http://{addr}/api/v1/events/{id}/raw?stream=stderr"
    ))
    .await
    .expect("request");

    assert_eq!(resp.status(), 400);
    // Axum returns a 400 for invalid query parameter enum values.
    let body = resp.text().await.expect("body");
    assert!(
        body.contains("stream"),
        "error response should mention the invalid field: {body}"
    );
}

#[tokio::test]
async fn detail_uses_data_attributes_for_filters() {
    let (addr, pool) = support::start_test_server().await;
    let id = seed_event_with_io(&pool);

    let body = reqwest::get(format!("http://{addr}/api/v1/events/{id}/detail"))
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    assert!(body.contains("data-filter-key=\"session\""));
    assert!(body.contains("data-filter-key=\"pid\""));
    assert!(body.contains("data-filter-key=\"tty\""));
    assert!(body.contains("evt.currentTarget.dataset.filterKey"));
}

#[tokio::test]
async fn detail_does_not_embed_filter_values_in_javascript_strings() {
    let (addr, pool) = support::start_test_server().await;
    let id = seed_event_with_io_for_session(&pool, "s'1");

    let body = reqwest::get(format!("http://{addr}/api/v1/events/{id}/detail"))
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    assert!(body.contains("data-filter-value=\"s&#"));
    assert!(
        !body.contains("shspectrBuildQuery($_query, 'session', 's&#x27;1')"),
        "filter value should come from data attributes, not an inline JS string"
    );
}
