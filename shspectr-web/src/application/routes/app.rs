//! Application page routes.

use askama::Template;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};

use crate::application::state::AppState;
use crate::domain::filter::EventFilter;
use crate::domain::listing::ListRequest;
use crate::presentation::web::listing::{ListNavigator, Paginated};
use shspectr_common::FilterKeywordMeta;

/// Compiled Tailwind CSS, embedded at build time.
const STYLES_CSS: &str = include_str!(env!("TAILWIND_CSS_PATH"));

#[derive(Template)]
#[template(path = "pages/index.html")]
struct IndexTemplate {
    styles: &'static str,
    paginated: Paginated,
    nav: ListNavigator,
    initial_query: String,
    filter_keywords: &'static [FilterKeywordMeta],
}

async fn index(State(state): State<AppState>) -> Response {
    let filter = EventFilter::default();
    let req = ListRequest::default();

    let page = match state.repo.list(&req, &filter) {
        Ok(page) => page,
        Err(err) => {
            tracing::error!(%err, "failed to load initial events");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let paginated = Paginated::from_page(&page);
    let nav = ListNavigator::new(&filter, req.sort, req.direction, req.page_size);

    let template = IndexTemplate {
        styles: STYLES_CSS,
        paginated,
        nav,
        initial_query: String::new(),
        filter_keywords: shspectr_common::FILTER_KEYWORDS,
    };

    match template.render() {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(err) => {
            tracing::error!(%err, "failed to render index template");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "pages/error.html")]
struct ErrorTemplate {
    styles: &'static str,
    status_code: u16,
    title: &'static str,
    message: &'static str,
}

/// Fallback handler for unmatched routes (404).
pub async fn not_found() -> Response {
    let template = ErrorTemplate {
        styles: STYLES_CSS,
        status_code: 404,
        title: "Page not found",
        message: "The page you're looking for doesn't exist.",
    };
    match template.render() {
        Ok(html) => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Render a styled 500 error page.
#[allow(dead_code)]
pub fn internal_error() -> Response {
    let template = ErrorTemplate {
        styles: STYLES_CSS,
        status_code: 500,
        title: "Internal server error",
        message: "Something went wrong. Check the server logs for details.",
    };
    match template.render() {
        Ok(html) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn not_found_returns_styled_404() {
        let resp = not_found().await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
