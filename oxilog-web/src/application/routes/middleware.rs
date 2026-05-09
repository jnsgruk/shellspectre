//! Tower middleware for security headers and other concerns.

use axum::http::header::HeaderValue;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

const CSP_VALUE: HeaderValue = HeaderValue::from_static(
    "default-src 'self'; \
     script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdn.jsdelivr.net; \
     style-src 'self' 'unsafe-inline'; \
     connect-src 'self' https://cdn.jsdelivr.net; \
     img-src 'self'; \
     font-src 'self'",
);

/// Add security headers to every response.
///
/// CSP allows:
/// - `unsafe-eval` and `unsafe-inline` for Datastar v1 (it evaluates JS expressions
///   in `data-on-*` attributes).
/// - CDN source for the Datastar script tag.
/// - `connect-src 'self' https://cdn.jsdelivr.net` for SSE, Datastar requests, and source maps.
pub async fn security_headers(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert("content-security-policy", CSP_VALUE);
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt; // for `oneshot`

    async fn dummy_handler() -> &'static str {
        "ok"
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(dummy_handler))
            .layer(axum::middleware::from_fn(security_headers))
    }

    #[tokio::test]
    async fn adds_csp_header() {
        let resp = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let csp = resp.headers().get("content-security-policy").unwrap();
        let csp_str = csp.to_str().unwrap();
        assert!(
            csp_str.contains("unsafe-eval"),
            "CSP must allow unsafe-eval for Datastar"
        );
        assert!(
            csp_str.contains("cdn.jsdelivr.net"),
            "CSP must allow Datastar CDN"
        );
    }

    #[tokio::test]
    async fn adds_x_frame_options() {
        let resp = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let val = resp
            .headers()
            .get("x-frame-options")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(val, "DENY");
    }

    #[tokio::test]
    async fn adds_x_content_type_options() {
        let resp = app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let val = resp
            .headers()
            .get("x-content-type-options")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(val, "nosniff");
    }
}
