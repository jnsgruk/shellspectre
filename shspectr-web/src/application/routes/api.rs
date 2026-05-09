//! API route handlers.

use std::convert::Infallible;
use std::time::Duration;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::get};
use futures::StreamExt;
use serde::Deserialize;

use crate::application::state::AppState;
use crate::domain::filter::EventFilter;
use crate::domain::listing::{EventSortKey, ListRequest, Page, SortDirection};
use crate::presentation::web::event::{EventDetailView, EventSummaryView};
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
    /// If true, return only new rows for infinite scroll append.
    #[serde(default)]
    pub append: bool,
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

/// Askama template for appending rows (infinite scroll) — rows only.
#[derive(Template)]
#[template(path = "partials/event_rows_append.html")]
struct EventRowsAppendFragment {
    paginated: Paginated,
}

/// Askama template for the infinite scroll sentinel.
#[derive(Template)]
#[template(path = "partials/pagination.html")]
struct PaginationFragment {
    paginated: Paginated,
    nav: ListNavigator,
}

/// Build an SSE response that appends rows and updates the scroll sentinel.
fn infinite_scroll_response(
    page: &Page<crate::domain::event::EventSummary>,
    filter: &EventFilter,
    sort: EventSortKey,
    dir: SortDirection,
    page_size: u32,
) -> Response {
    let paginated = Paginated::from(page);
    let nav = ListNavigator::new(filter, sort, dir, page_size);

    let rows_template = EventRowsAppendFragment {
        paginated: Paginated::from(page),
    };
    let sentinel_template = PaginationFragment { paginated, nav };

    let rows_html = rows_template.render().unwrap_or_default();
    let sentinel_html = sentinel_template.render().unwrap_or_default();

    let rows_evt = Event::default()
        .event("datastar-patch-elements")
        .data(sse_patch_elements(
            &rows_html,
            "#event-rows",
            SseMergeMode::Append,
        ));

    let sentinel_evt = Event::default()
        .event("datastar-patch-elements")
        .data(sse_patch_elements(
            &sentinel_html,
            "#load-more-sentinel",
            SseMergeMode::Replace,
        ));

    let stream = tokio_stream::iter(vec![Ok::<_, Infallible>(rows_evt), Ok(sentinel_evt)]);

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
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
        if params.append {
            return infinite_scroll_response(
                &page,
                &filter,
                params.sort,
                params.dir,
                req.page_size,
            );
        }

        let paginated = Paginated::from_page_with_warnings(&page, filter.warnings.clone());
        let nav = ListNavigator::new(&filter, params.sort, params.dir, req.page_size);
        let template = EventListFragment { paginated, nav };
        match template.render() {
            Ok(html) => {
                let evt =
                    Event::default()
                        .event("datastar-patch-elements")
                        .data(sse_patch_elements(
                            &html,
                            "#event-list-container",
                            SseMergeMode::Outer,
                        ));
                let stream = tokio_stream::iter(vec![Ok::<_, Infallible>(evt)]);
                Sse::new(stream)
                    .keep_alive(KeepAlive::default())
                    .into_response()
            }
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

/// Datastar v1 SSE merge modes for `datastar-patch-elements`.
#[derive(Debug, Clone, Copy)]
enum SseMergeMode {
    /// Append elements inside the target.
    Append,
    /// Replace the target's inner HTML.
    Replace,
    /// Replace the target element itself (outerHTML).
    Outer,
    /// Prepend elements inside the target.
    Prepend,
}

impl SseMergeMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Append => "append",
            Self::Replace => "replace",
            Self::Outer => "outer",
            Self::Prepend => "prepend",
        }
    }
}

/// Format HTML as a Datastar v1 SSE `datastar-patch-elements` data payload.
fn sse_patch_elements(html: &str, selector: &str, mode: SseMergeMode) -> String {
    let elements: String = html
        .lines()
        .map(|line| format!("elements {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("selector {selector}\nmode {}\n{elements}", mode.as_str())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/events/live", get(live_events))
        .route("/api/v1/events/{id}/detail", get(get_event_detail))
        .route("/api/v1/events/{id}/raw", get(get_event_raw))
        .route("/api/v1/filters/keywords", get(filter_keywords))
}

/// Query parameters for the live events endpoint.
#[derive(Debug, Deserialize)]
pub struct LiveEventsParams {
    /// Filter query string.
    #[serde(default)]
    pub q: String,
}

/// Askama template for a single event row (reuses the existing partial).
#[derive(Template)]
#[template(path = "partials/event_row.html")]
struct EventRowFragment {
    event: EventSummaryView,
}

/// `GET /api/v1/events/live?q=...`
///
/// SSE stream that polls the database every 500ms for new events.
/// Sends `datastar-patch-elements` events containing `<tr>` HTML fragments.
///
/// Supports `Last-Event-ID` header for reconnection without duplicates.
async fn live_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<LiveEventsParams>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let filter = EventFilter::parse(&params.q);

    // Resume from Last-Event-ID if provided (reconnection support).
    let initial_id: i64 = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // If no Last-Event-ID, start from the current max id to avoid
    // dumping the entire history on first connect.
    let mut last_seen_id = if initial_id > 0 {
        initial_id
    } else {
        state.repo.max_event_id().unwrap_or(0)
    };

    let poll_interval = Duration::from_millis(500);
    let ticker = tokio::time::interval(poll_interval);
    let stream = tokio_stream::wrappers::IntervalStream::new(ticker);

    let mut live_count: u64 = 0;

    let event_stream = stream.flat_map(move |_| {
        let new_events = match state.repo.list_since(last_seen_id, &filter) {
            Ok(events) => events,
            Err(err) => {
                tracing::warn!(%err, last_seen_id, "failed to poll for new events");
                Vec::new()
            }
        };

        if new_events.is_empty() {
            return tokio_stream::iter(vec![Ok(Event::default().comment("keepalive"))]);
        }

        // Update high-water mark.
        if let Some(last) = new_events.last() {
            last_seen_id = last.id;
        }

        live_count += new_events.len() as u64;

        // Render each new event as an HTML table row.
        let mut fragments = String::new();
        for summary in &new_events {
            let view = EventSummaryView::from(summary);
            let template = EventRowFragment { event: view };
            if let Ok(html) = template.render() {
                fragments.push_str(&html);
            }
        }

        // Datastar v1 SSE patch-elements event format.
        // Each line of the HTML fragment must be prefixed with "elements ".
        // The axum SSE `Event::data()` method adds the `data: ` prefix per
        // line, so we only need to prepend "elements " to every HTML line.
        let elements_data: String = fragments
            .lines()
            .map(|line| format!("elements {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let merge_data = format!(
            "selector #event-rows\nmode {}\n{elements_data}",
            SseMergeMode::Prepend.as_str()
        );
        let merge_evt = Event::default()
            .event("datastar-patch-elements")
            .data(merge_data)
            .id(last_seen_id.to_string());

        // Update the live count signal.
        let signal_data = format!("signals {{_liveCount: {live_count}}}");
        let signal_evt = Event::default()
            .event("datastar-patch-signals")
            .data(signal_data);

        tokio_stream::iter(vec![Ok(merge_evt), Ok(signal_evt)])
    });

    Sse::new(event_stream).keep_alive(KeepAlive::default())
}

/// Which I/O stream to return in the raw endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    /// Standard input (fd 0).
    Stdin,
    /// Standard output/error (fd 1, 2).
    Stdout,
}

/// Query parameters for the raw IO endpoint.
#[derive(Debug, Deserialize)]
pub struct RawParams {
    /// Which stream to return.
    pub stream: Option<StreamKind>,
}

/// `GET /api/v1/events/{id}/raw?stream=stdout`
///
/// Returns the raw (plain text, ANSI stripped) IO data for an event.
/// Opens in a new browser tab via the "raw ↗" link in the detail panel.
async fn get_event_raw(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<RawParams>,
) -> Response {
    let detail = match state.repo.get_detail(id) {
        Ok(Some(d)) => d,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(%err, id, "failed to get event for raw view");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let stream = params.stream.unwrap_or(StreamKind::Stdout);
    let raw: String = match stream {
        StreamKind::Stdin => detail.stdin_data.iter().map(|c| c.data.as_str()).collect(),
        StreamKind::Stdout => detail.stdout_data.iter().map(|c| c.data.as_str()).collect(),
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        raw,
    )
        .into_response()
}

/// `GET /api/v1/filters/keywords`
///
/// Returns the filter keyword registry as JSON for autocompletion and help.
async fn filter_keywords() -> impl IntoResponse {
    let keywords: Vec<_> = shspectr_common::FILTER_KEYWORDS
        .iter()
        .map(|kw| {
            serde_json::json!({
                "keyword": kw.keyword,
                "description": kw.description,
                "value_type": kw.value_type,
                "example": kw.example,
                "supports_negation": kw.supports_negation,
            })
        })
        .collect();
    Json(keywords)
}

/// Askama template for the event detail fragment.
#[derive(Template)]
#[template(path = "partials/event_detail.html")]
struct EventDetailFragment {
    detail: EventDetailView,
}

/// `GET /api/v1/events/{id}/detail`
///
/// Returns an HTML fragment for the detail expansion panel.
/// If the event is not found, returns 404.
async fn get_event_detail(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let detail = match state.repo.get_detail(id) {
        Ok(Some(detail)) => detail,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                "<tr><td colspan=\"5\" class=\"px-3 py-4 text-center text-red-400\">Event not found.</td></tr>",
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!(%err, id, "failed to get event detail");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let view = EventDetailView::from(&detail);
    let template = EventDetailFragment { detail: view };

    match template.render() {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(err) => {
            tracing::error!(%err, "failed to render event detail fragment");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
