//! Route definitions for the web application.

mod api;
mod app;
mod static_assets;
mod support;

use axum::Router;

use crate::application::state::AppState;

/// Build the application router.
///
/// The caller must provide `AppState` via `.with_state()`.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(app::routes())
        .merge(api::routes())
        .merge(static_assets::routes())
}
