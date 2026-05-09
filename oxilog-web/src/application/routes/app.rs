//! Application page routes.

use askama::Template;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};

use crate::application::state::AppState;
use crate::domain::event::EventFilter;
use crate::domain::listing::ListRequest;
use crate::presentation::web::listing::{ListNavigator, Paginated};

/// Compiled Tailwind CSS, embedded at build time.
const STYLES_CSS: &str = include_str!(env!("TAILWIND_CSS_PATH"));

#[derive(Template)]
#[template(path = "pages/index.html")]
struct IndexTemplate {
    styles: &'static str,
    paginated: Paginated,
    nav: ListNavigator,
    initial_query: String,
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

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(index))
}
