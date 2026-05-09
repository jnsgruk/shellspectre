#![allow(clippy::expect_used)]
//! Integration tests for the event list API and page routes.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::time::{Duration, sleep};

use oxilog_web::application::state::AppState;
use oxilog_web::infrastructure::database::{DbPool, create_test_pool};
use oxilog_web::infrastructure::repositories::event::SqlEventRepository;

/// Spin up a test server with an in-memory DB and return (addr, pool).
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

fn seed_events(pool: &DbPool, count: u32) {
    let conn = pool.get().expect("get conn");
    conn.execute(
        "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
         VALUES ('s1', datetime('now'), 100, 1000, 1000)",
        [],
    )
    .expect("insert session");

    for i in 0..count {
        conn.execute(
            "INSERT INTO events \
             (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm, filename, argv, exit_code) \
             VALUES ('s1', 'exec', datetime('now'), ?1, 1, 1000, 1000, 1000, ?2, '/usr/bin/cmd', ?3, 0)",
            rusqlite::params![100 + i, format!("cmd{i}"), format!(r#"["cmd{i}"]"#)],
        )
        .expect("insert event");
    }
}

#[tokio::test]
async fn index_page_contains_event_table() {
    let (addr, pool) = start_test_server().await;
    seed_events(&pool, 3);

    let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("event-list-container"),
        "should contain event list"
    );
    assert!(body.contains("cmd0"), "should contain seeded event");
}

#[tokio::test]
async fn index_page_empty_state() {
    let (addr, _pool) = start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("No events found"), "should show empty state");
}

#[tokio::test]
async fn api_events_returns_json_without_datastar_header() {
    let (addr, pool) = start_test_server().await;
    seed_events(&pool, 2);

    let resp = reqwest::get(format!("http://{addr}/api/v1/events"))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("application/json"), "should return JSON: {ct}");

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total_items"], 2);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn api_events_returns_html_with_datastar_header() {
    let (addr, pool) = start_test_server().await;
    seed_events(&pool, 2);

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/events"))
        .header("datastar-request", "true")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/html"), "should return HTML fragment: {ct}");

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("event-list-container"),
        "should contain fragment wrapper"
    );
    assert!(body.contains("cmd0"), "should contain event data");
}

#[tokio::test]
async fn api_events_pagination() {
    let (addr, pool) = start_test_server().await;
    seed_events(&pool, 10);

    let resp: serde_json::Value =
        reqwest::get(format!("http://{addr}/api/v1/events?page=1&page_size=3"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    assert_eq!(resp["items"].as_array().unwrap().len(), 3);
    assert_eq!(resp["total_items"], 10);
    assert_eq!(resp["page"], 1);
    assert_eq!(resp["page_size"], 3);
}

#[tokio::test]
async fn api_events_filter() {
    let (addr, pool) = start_test_server().await;
    seed_events(&pool, 5);

    let resp: serde_json::Value =
        reqwest::get(format!("http://{addr}/api/v1/events?q=comm:cmd2"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    assert_eq!(resp["total_items"], 1);
    assert_eq!(resp["items"][0]["comm"], "cmd2");
}

#[tokio::test]
async fn api_events_page_size_clamped() {
    let (addr, pool) = start_test_server().await;
    seed_events(&pool, 2);

    // page_size=999 should be clamped to 100.
    let resp: serde_json::Value =
        reqwest::get(format!("http://{addr}/api/v1/events?page_size=999"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    assert_eq!(resp["page_size"], 100);
}
