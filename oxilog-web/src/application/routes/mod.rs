//! Route definitions for the web application.

mod app;
mod static_assets;

use axum::Router;

/// Build the application router.
pub fn router() -> Router {
    Router::new()
        .merge(app::routes())
        .merge(static_assets::routes())
}
