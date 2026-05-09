//! Route definitions for the web application.

mod api;
mod app;
mod middleware;
mod static_assets;
mod support;

use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use crate::application::state::AppState;

/// Build the application router.
///
/// The caller must provide `AppState` via `.with_state()`.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(app::routes())
        .merge(api::routes())
        .merge(static_assets::routes())
        .fallback(app::not_found)
        .layer(axum::middleware::from_fn(middleware::security_headers))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
}
