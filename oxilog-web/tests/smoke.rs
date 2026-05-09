#![allow(clippy::expect_used)]
//! Smoke tests for the oxilog-web server.

use std::net::SocketAddr;

use tokio::time::{Duration, sleep};

#[tokio::test]
async fn server_serves_index_page() {
    let addr = start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "index page should return 200");
    let body = resp.text().await.expect("failed to read body");
    assert!(body.contains("oxilog"), "page should contain 'oxilog'");
    assert!(body.contains("datastar"), "page should load Datastar");
}

#[tokio::test]
async fn server_serves_css() {
    let addr = start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/static/css/styles.css"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "CSS route should return 200");
    let content_type = resp
        .headers()
        .get("content-type")
        .expect("should have content-type")
        .to_str()
        .expect("content-type should be a string");
    assert!(
        content_type.contains("text/css"),
        "content-type should be text/css"
    );
}

#[tokio::test]
async fn server_returns_404_for_unknown_routes() {
    let addr = start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/nonexistent"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 404, "unknown routes should return 404");
}

/// Spin up a test server on a random port and return its address.
async fn start_test_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().expect("failed to get local addr");

    let app = oxilog_web::application::routes::router();

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Give the server a moment to start.
    sleep(Duration::from_millis(50)).await;

    addr
}
