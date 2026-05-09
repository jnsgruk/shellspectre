//! Static asset routes (compiled CSS).

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};

use crate::application::state::AppState;

/// Compiled Tailwind CSS, embedded at build time.
const STYLES_CSS: &str = include_str!(env!("TAILWIND_CSS_PATH"));

async fn styles() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css")],
        STYLES_CSS,
    )
        .into_response()
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/static/css/styles.css", get(styles))
}
