//! Pagination and navigation view models.

use crate::domain::event::EventFilter;
use crate::domain::listing::{EventSortKey, Page, SortDirection};
use crate::presentation::web::event::EventSummaryView;

/// Wraps a `Page<EventSummary>` with presentation-ready view models.
#[derive(Debug)]
pub struct Paginated {
    /// Formatted event rows.
    pub items: Vec<EventSummaryView>,
    /// Current page (1-indexed).
    pub page: u32,
    /// Items per page.
    pub page_size: u32,
    /// Total items across all pages.
    pub total_items: u64,
    /// Total number of pages.
    pub total_pages: u32,
    /// Whether there is a previous page.
    pub has_prev: bool,
    /// Whether there is a next page.
    pub has_next: bool,
    /// Filter parse warnings.
    pub warnings: Vec<String>,
}

impl Paginated {
    /// Create from a domain Page of `EventSummary`.
    pub fn from_page(page: &Page<crate::domain::event::EventSummary>) -> Self {
        Self {
            items: page
                .items
                .iter()
                .map(EventSummaryView::from_summary)
                .collect(),
            page: page.page,
            page_size: page.page_size,
            total_items: page.total_items,
            total_pages: page.total_pages(),
            has_prev: page.has_prev(),
            has_next: page.has_next(),
            warnings: Vec::new(),
        }
    }

    /// Create from a domain Page with filter warnings.
    pub fn from_page_with_warnings(
        page: &Page<crate::domain::event::EventSummary>,
        warnings: Vec<String>,
    ) -> Self {
        let mut p = Self::from_page(page);
        p.warnings = warnings;
        p
    }
}

/// Generates URL query strings for pagination and sorting navigation.
///
/// Used in templates to build `data-on:click` URLs.
#[derive(Debug)]
pub struct ListNavigator {
    /// Current filter query string (raw `q` param value), or empty.
    pub query: String,
    /// Current sort key.
    pub sort: EventSortKey,
    /// Current sort direction.
    pub direction: SortDirection,
    /// Current page size.
    pub page_size: u32,
}

impl ListNavigator {
    /// Build from current request parameters.
    pub fn new(
        filter: &EventFilter,
        sort: EventSortKey,
        direction: SortDirection,
        page_size: u32,
    ) -> Self {
        Self {
            query: filter.raw.clone().unwrap_or_default(),
            sort,
            direction,
            page_size,
        }
    }

    /// URL query string for a specific page (preserving current sort/filter).
    pub fn page_url(&self, page: u32) -> String {
        format!(
            "/api/v1/events?page={page}&page_size={}&sort={}&dir={}&q={}",
            self.page_size,
            self.sort_str(),
            self.dir_str(),
            urlencoded(&self.query),
        )
    }

    /// URL query string for sorting by a column.
    ///
    /// If the column is already the active sort, toggles direction.
    /// Otherwise, sorts by the new column in descending order.
    pub fn sort_url(&self, key: EventSortKey) -> String {
        let dir = if key == self.sort {
            self.direction.toggle()
        } else {
            SortDirection::Desc
        };
        format!(
            "/api/v1/events?page=1&page_size={}&sort={}&dir={}&q={}",
            self.page_size,
            sort_key_str(key),
            dir_str(dir),
            urlencoded(&self.query),
        )
    }

    /// Sort indicator for a column header: " \u{25b2}", " \u{25bc}", or "".
    pub fn sort_indicator(&self, key: EventSortKey) -> &'static str {
        if key == self.sort {
            match self.direction {
                SortDirection::Asc => " \u{25b2}",
                SortDirection::Desc => " \u{25bc}",
            }
        } else {
            ""
        }
    }

    // Convenience methods for templates (Askama can't use Rust enum variants directly).

    /// Sort URL for the timestamp column.
    pub fn sort_url_timestamp(&self) -> String {
        self.sort_url(EventSortKey::Timestamp)
    }

    /// Sort URL for the command column.
    pub fn sort_url_comm(&self) -> String {
        self.sort_url(EventSortKey::Comm)
    }

    /// Sort URL for the exit code column.
    pub fn sort_url_exit_code(&self) -> String {
        self.sort_url(EventSortKey::ExitCode)
    }

    /// Sort indicator for the timestamp column.
    pub fn sort_indicator_timestamp(&self) -> &'static str {
        self.sort_indicator(EventSortKey::Timestamp)
    }

    /// Sort indicator for the command column.
    pub fn sort_indicator_comm(&self) -> &'static str {
        self.sort_indicator(EventSortKey::Comm)
    }

    /// Sort indicator for the exit code column.
    pub fn sort_indicator_exit_code(&self) -> &'static str {
        self.sort_indicator(EventSortKey::ExitCode)
    }

    fn sort_str(&self) -> &'static str {
        sort_key_str(self.sort)
    }

    fn dir_str(&self) -> &'static str {
        dir_str(self.direction)
    }
}

fn sort_key_str(key: EventSortKey) -> &'static str {
    match key {
        EventSortKey::Timestamp => "timestamp",
        EventSortKey::Comm => "comm",
        EventSortKey::ExitCode => "exit_code",
    }
}

fn dir_str(dir: SortDirection) -> &'static str {
    match dir {
        SortDirection::Asc => "asc",
        SortDirection::Desc => "desc",
    }
}

/// Minimal URL encoding for the query parameter value.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('#', "%23")
}
