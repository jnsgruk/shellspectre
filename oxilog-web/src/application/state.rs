//! Application state shared across all route handlers.

use std::sync::Arc;

use crate::domain::repositories::EventRepository;

/// Shared application state.
///
/// Wrapped in `Arc` and passed to the axum router via `.with_state()`.
/// Handlers receive it via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// Event repository (trait object for testability).
    pub repo: Arc<dyn EventRepository>,
}
