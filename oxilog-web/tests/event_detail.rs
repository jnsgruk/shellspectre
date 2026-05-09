#![allow(clippy::expect_used)]
//! Integration tests for the event detail endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use rusqlite::params;
use tokio::time::{Duration, sleep};

use oxilog_web::application::state::AppState;
use oxilog_web::infrastructure::database::{DbPool, create_test_pool};
use oxilog_web::infrastructure::repositories::event::SqlEventRepository;

async fn start_test_server() -> (SocketAddr, DbPool) {
    let pool = create_test_pool().expect("create test pool");
    let repo = Arc::new(SqlEventRepository::new(pool.clone()));
    let state = AppState { repo };

    let app = oxilog_web::application::routes::router().with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    sleep(Duration::from_millis(50)).await;
    (addr, pool)
}

fn seed_event_with_io(pool: &DbPool) -> i64 {
    let conn = pool.get().expect("get conn");
    conn.execute(
        "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
         VALUES ('s1', datetime('now'), 100, 1000, 1000)",
        [],
    )
    .expect("insert session");

    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm, filename, argv, exit_code, tty_nr) \
         VALUES ('s1', 'exec', '2026-05-10T14:32:01', 4821, 4800, 1000, 1000, 1000, 'cat', '/usr/bin/cat', \
                 '[\"cat\",\"secret.txt\"]', 0, ?1)",
        params![0x8803u32], // pts/3
    )
    .expect("insert exec");

    let id: i64 = conn
        .query_row(
            "SELECT id FROM events WHERE event_type = 'exec' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("get id");

    // Add I/O data.
    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, fd, data, data_len, byte_count) \
         VALUES ('s1', 'write', '2026-05-10T14:32:02', 4821, 4800, 1000, 1000, 1000, 1, 'TOP SECRET\n', 11, 11)",
        [],
    )
    .expect("insert io");

    id
}

#[tokio::test]
async fn detail_returns_html_fragment() {
    let (addr, pool) = start_test_server().await;
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
    assert!(body.contains(&format!("detail-{id}")), "should contain detail element ID");
    assert!(body.contains("pts/3"), "should show TTY");
    assert!(body.contains("4821"), "should show PID");
    assert!(body.contains("4800"), "should show PPID");
    assert!(body.contains("cat secret.txt"), "should show full command");
    assert!(body.contains("TOP SECRET"), "should show stdout data");
}

#[tokio::test]
async fn detail_not_found_returns_404() {
    let (addr, _pool) = start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/events/99999/detail"))
        .header("datastar-request", "true")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 404);
    let body = resp.text().await.expect("body");
    assert!(body.contains("not found"), "should indicate event not found");
}

#[tokio::test]
async fn detail_metadata_fields_present() {
    let (addr, pool) = start_test_server().await;
    let id = seed_event_with_io(&pool);

    let body = reqwest::get(format!("http://{addr}/api/v1/events/{id}/detail"))
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    // Check all metadata grid labels are present.
    for label in &["Session:", "PID:", "PPID:", "UID:", "EUID:", "GID:", "TTY:", "Exit:"] {
        assert!(body.contains(label), "should contain '{label}'");
    }
}

#[tokio::test]
async fn detail_no_io_shows_message() {
    let (addr, pool) = start_test_server().await;

    let conn = pool.get().expect("get conn");
    conn.execute(
        "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
         VALUES ('s2', datetime('now'), 100, 1000, 1000)",
        [],
    )
    .expect("insert session");
    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm) \
         VALUES ('s2', 'exec', datetime('now'), 100, 1, 1000, 1000, 1000, 'ls')",
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

    assert!(body.contains("No I/O data captured"), "should show no-IO message");
}
