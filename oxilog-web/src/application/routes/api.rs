//! API route handlers.

use askama::Template;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use serde::Deserialize;

use crate::application::state::AppState;
use crate::domain::event::EventFilter;
use crate::domain::listing::{EventSortKey, ListRequest, SortDirection};
use crate::presentation::web::listing::{ListNavigator, Paginated};

use super::support::is_datastar_request;

/// Query parameters for the event list endpoint.
#[derive(Debug, Deserialize)]
pub struct EventListParams {
    /// Page number (1-indexed). Defaults to 1.
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page. Defaults to 25.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Sort column. Defaults to "timestamp".
    #[serde(default)]
    pub sort: EventSortKey,
    /// Sort direction. Defaults to "desc".
    #[serde(default)]
    pub dir: SortDirection,
    /// Filter query string.
    #[serde(default)]
    pub q: String,
}

const fn default_page() -> u32 {
    1
}
const fn default_page_size() -> u32 {
    25
}

/// Askama template for the event list + pagination fragment.
#[derive(Template)]
#[template(path = "partials/event_list.html")]
struct EventListFragment {
    paginated: Paginated,
    nav: ListNavigator,
}

/// `GET /api/v1/events`
///
/// - Datastar request -> returns HTML fragment (event table rows + pagination).
/// - Normal request -> returns JSON.
#[allow(clippy::cognitive_complexity)]
async fn list_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<EventListParams>,
) -> Response {
    let filter = EventFilter::parse(&params.q);

    let req = ListRequest {
        page: params.page.max(1),
        page_size: params.page_size.clamp(1, 100),
        sort: params.sort,
        direction: params.dir,
    };

    let page = match state.repo.list(&req, &filter) {
        Ok(page) => page,
        Err(err) => {
            tracing::error!(%err, "failed to list events");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if is_datastar_request(&headers) {
        let paginated = Paginated::from_page(&page);
        let nav = ListNavigator::new(&filter, params.sort, params.dir, req.page_size);
        let template = EventListFragment { paginated, nav };
        match template.render() {
            Ok(html) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response(),
            Err(err) => {
                tracing::error!(%err, "failed to render event list fragment");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        // JSON response for non-Datastar clients (API consumers, curl).
        match serde_json::to_string(&page) {
            Ok(json) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                json,
            )
                .into_response(),
            Err(err) => {
                tracing::error!(%err, "failed to serialize events");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/events", get(list_events))
}
