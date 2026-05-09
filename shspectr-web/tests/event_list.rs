#![allow(clippy::expect_used)]
//! Integration tests for the event list API and page routes.

mod support;

use shspectr_web::infrastructure::database::DbPool;

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
             (session_id, event_type, timestamp, execution_id, pid, ppid, uid, gid, euid, comm, filename, argv, exit_code) \
             VALUES ('s1', 'exec', datetime('now'), ?1, ?1, 1, 1000, 1000, 1000, ?2, '/usr/bin/cmd', ?3, 0)",
            rusqlite::params![100 + i, format!("cmd{i}"), format!(r#"["cmd{i}"]"#)],
        )
        .expect("insert event");
    }
}

#[tokio::test]
async fn index_page_contains_event_table() {
    let (addr, pool) = support::start_test_server().await;
    seed_events(&pool, 3);

    let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("event-list-container"),
        "should contain event list"
    );
    assert!(
        body.contains("cmd0") || body.contains("/usr/bin/cmd"),
        "should contain seeded event"
    );
}

#[tokio::test]
async fn index_page_empty_state() {
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("No events found"), "should show empty state");
}

#[tokio::test]
async fn index_page_uses_data_attributes_for_request_urls() {
    let (addr, pool) = support::start_test_server().await;
    seed_events(&pool, 30);

    let resp = reqwest::get(format!("http://{addr}/?q=s'1")).await.unwrap();
    let body = resp.text().await.unwrap();

    assert!(
        body.contains("data-sort-url="),
        "should expose sort URLs via data attributes"
    );
    assert!(
        body.contains("data-next-url="),
        "should expose pagination URL via data attributes"
    );
    assert!(
        body.contains("data-filter-keyword="),
        "should expose autocomplete keywords via data attributes"
    );
    assert!(
        !body.contains("data-on:click=\"@get('"),
        "request URLs should not be embedded in inline JS strings"
    );
}

#[tokio::test]
async fn api_events_returns_json_without_datastar_header() {
    let (addr, pool) = support::start_test_server().await;
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
    let (addr, pool) = support::start_test_server().await;
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
    assert!(
        ct.contains("text/event-stream"),
        "should return SSE stream: {ct}"
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("event-list-container"),
        "should contain fragment wrapper"
    );
    assert!(
        body.contains("cmd0") || body.contains("/usr/bin/cmd") || body.contains("cmd"),
        "should contain event data"
    );
}

#[tokio::test]
async fn api_events_pagination() {
    let (addr, pool) = support::start_test_server().await;
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
    let (addr, pool) = support::start_test_server().await;
    seed_events(&pool, 5);

    let resp: serde_json::Value = reqwest::get(format!("http://{addr}/api/v1/events?q=comm:cmd2"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["total_items"], 1);
    assert_eq!(resp["items"][0]["comm"], "cmd2");
}

#[tokio::test]
async fn api_events_negation_filter() {
    let (addr, pool) = support::start_test_server().await;
    seed_events(&pool, 5);

    // `!comm:cmd2` should exclude cmd2, returning 4 events.
    let resp: serde_json::Value = reqwest::get(format!("http://{addr}/api/v1/events?q=!comm:cmd2"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["total_items"], 4);
    let comms: Vec<&str> = resp["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["comm"].as_str().unwrap())
        .collect();
    assert!(
        !comms.contains(&"cmd2"),
        "cmd2 should be excluded: {comms:?}"
    );
}

#[tokio::test]
async fn api_events_negation_glob_url_encoded() {
    let (addr, pool) = support::start_test_server().await;

    // Insert events with different comm values.
    let conn = pool.get().expect("get conn");
    conn.execute(
        "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
         VALUES ('s1', datetime('now'), 100, 1000, 1000)",
        [],
    )
    .expect("insert session");
    for (i, comm) in ["git", "git", "ps", "bash"].iter().enumerate() {
        conn.execute(
            "INSERT INTO events \
             (session_id, event_type, timestamp, execution_id, pid, ppid, uid, gid, euid, comm, filename, argv, exit_code) \
             VALUES ('s1', 'exec', datetime('now'), ?1, ?1, 1, 1000, 1000, 1000, ?2, '/usr/bin/cmd', '[]', 0)",
            rusqlite::params![100 + i as u32, comm],
        )
        .expect("insert event");
    }
    drop(conn);

    // encodeURIComponent('!comm:*git*') → '%21comm%3A%2Agit%2A'
    let resp: serde_json::Value =
        reqwest::get(format!("http://{addr}/api/v1/events?q=%21comm%3A%2Agit%2A"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    assert_eq!(resp["total_items"], 2, "should exclude git: {resp:#}");
    let comms: Vec<&str> = resp["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["comm"].as_str().unwrap())
        .collect();
    assert!(!comms.contains(&"git"), "git should be excluded: {comms:?}");
}

#[tokio::test]
async fn api_events_negation_filter_url_encoded() {
    let (addr, pool) = support::start_test_server().await;
    seed_events(&pool, 5);

    // URL-encoded `!comm:cmd2` → `%21comm%3Acmd2` (as sent by encodeURIComponent).
    let resp: serde_json::Value =
        reqwest::get(format!("http://{addr}/api/v1/events?q=%21comm%3Acmd2"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    assert_eq!(resp["total_items"], 4);
    let comms: Vec<&str> = resp["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["comm"].as_str().unwrap())
        .collect();
    assert!(
        !comms.contains(&"cmd2"),
        "cmd2 should be excluded: {comms:?}"
    );
}

#[tokio::test]
async fn api_events_page_size_clamped() {
    let (addr, pool) = support::start_test_server().await;
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
