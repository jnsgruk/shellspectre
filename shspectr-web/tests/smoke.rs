#![allow(clippy::expect_used)]
//! Smoke tests for the shspectr-web server.

mod support;

#[tokio::test]
async fn server_serves_index_page() {
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200, "index page should return 200");
    let body = resp.text().await.expect("failed to read body");
    assert!(body.contains("shspectr"), "page should contain 'shspectr'");
    assert!(body.contains("datastar"), "page should load Datastar");
}

#[tokio::test]
async fn server_serves_css() {
    let (addr, _pool) = support::start_test_server().await;

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
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/nonexistent"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 404, "unknown routes should return 404");
}

#[tokio::test]
async fn not_found_page_is_styled_html() {
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/nonexistent"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 404);
    let body = resp.text().await.expect("failed to read body");
    assert!(body.contains("404"), "should contain status code");
    assert!(
        body.contains("Page not found"),
        "should contain error title"
    );
    assert!(body.contains("shspectr"), "should use base template");
}

#[tokio::test]
async fn responses_have_security_headers() {
    let (addr, _pool) = support::start_test_server().await;

    let resp = reqwest::get(format!("http://{addr}/"))
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    let csp = resp
        .headers()
        .get("content-security-policy")
        .expect("should have CSP header")
        .to_str()
        .expect("CSP should be a string");
    assert!(csp.contains("unsafe-eval"), "CSP should allow unsafe-eval");
    assert!(
        csp.contains("cdn.jsdelivr.net"),
        "CSP should allow Datastar CDN"
    );

    let xfo = resp
        .headers()
        .get("x-frame-options")
        .expect("should have X-Frame-Options")
        .to_str()
        .expect("XFO should be a string");
    assert_eq!(xfo, "DENY");

    let xcto = resp
        .headers()
        .get("x-content-type-options")
        .expect("should have X-Content-Type-Options")
        .to_str()
        .expect("XCTO should be a string");
    assert_eq!(xcto, "nosniff");
}
