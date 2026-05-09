//! Application page routes.

use askama::Template;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};

/// Compiled Tailwind CSS, embedded at build time.
const STYLES_CSS: &str = include_str!(env!("TAILWIND_CSS_PATH"));

#[derive(Template)]
#[template(path = "pages/index.html")]
struct IndexTemplate {
    styles: &'static str,
}

async fn index() -> Response {
    let template = IndexTemplate { styles: STYLES_CSS };
    match template.render() {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub fn routes() -> Router {
    Router::new().route("/", get(index))
}
