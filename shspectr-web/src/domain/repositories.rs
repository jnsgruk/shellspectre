//! Repository traits for data access.

use anyhow::Result;

use super::event::{EventDetail, EventSummary};
use super::filter::EventFilter;
use super::listing::{ListRequest, Page};

/// Read-only repository for querying events.
pub trait EventRepository: Send + Sync {
    /// Fetch a paginated, filtered, sorted list of event summaries.
    fn list(&self, req: &ListRequest, filter: &EventFilter) -> Result<Page<EventSummary>>;

    /// Fetch full detail for a single event by ID, including related I/O.
    fn get_detail(&self, id: i64) -> Result<Option<EventDetail>>;

    /// Fetch events with `id > after_id`, applying the given filter.
    /// Returns up to 100 events ordered by id ASC.
    fn list_since(&self, after_id: i64, filter: &EventFilter) -> Result<Vec<EventSummary>>;

    /// Get the maximum event id in the database, or 0 if empty.
    fn max_event_id(&self) -> Result<i64>;
}
