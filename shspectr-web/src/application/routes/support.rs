//! Datastar and response helpers.

use axum::http::HeaderMap;

/// Datastar v1 sends this header on fragment requests.
const DATASTAR_REQUEST_HEADER: &str = "datastar-request";

/// Check if the incoming request is a Datastar fragment request.
///
/// Datastar v1 adds a `datastar-request: true` header to all
/// `@get` / `@post` requests. When present, we return an HTML
/// fragment instead of JSON or a full page.
pub fn is_datastar_request(headers: &HeaderMap) -> bool {
    headers
        .get(DATASTAR_REQUEST_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "true")
}
