//! Repository traits for data access.

use anyhow::Result;

use super::event::{EventDetail, EventFilter, EventSummary};
use super::listing::{ListRequest, Page};

/// Read-only repository for querying events.
pub trait EventRepository: Send + Sync {
    /// Fetch a paginated, filtered, sorted list of event summaries.
    fn list(&self, req: &ListRequest, filter: &EventFilter) -> Result<Page<EventSummary>>;

    /// Fetch full detail for a single event by ID, including related I/O.
    fn get_detail(&self, id: i64) -> Result<Option<EventDetail>>;
}
