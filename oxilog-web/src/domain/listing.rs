//! Generic pagination and sorting types.

use serde::{Deserialize, Serialize};

/// Sort direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    /// Ascending order.
    Asc,
    /// Descending order.
    #[default]
    Desc,
}

impl SortDirection {
    /// Returns the SQL keyword for this direction.
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }

    /// Return the opposite direction.
    #[must_use]
    pub fn toggle(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }
}

/// Columns that events can be sorted by.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSortKey {
    /// Sort by timestamp.
    #[default]
    Timestamp,
    /// Sort by command name.
    Comm,
    /// Sort by exit code.
    ExitCode,
}

impl EventSortKey {
    /// Returns the SQL column name for this sort key.
    pub fn as_sql_column(self) -> &'static str {
        match self {
            Self::Timestamp => "timestamp",
            Self::Comm => "comm",
            Self::ExitCode => "exit_code",
        }
    }
}

/// A request for a paginated, sorted list.
#[derive(Debug, Clone)]
pub struct ListRequest {
    /// 1-indexed page number.
    pub page: u32,
    /// Items per page.
    pub page_size: u32,
    /// Column to sort by.
    pub sort: EventSortKey,
    /// Sort direction.
    pub direction: SortDirection,
}

impl Default for ListRequest {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 25,
            sort: EventSortKey::default(),
            direction: SortDirection::default(),
        }
    }
}

impl ListRequest {
    /// SQL OFFSET for this page.
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.page_size
    }
}

/// A page of results.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_field_names)]
pub struct Page<T> {
    /// The items on this page.
    pub items: Vec<T>,
    /// 1-indexed current page number.
    pub page: u32,
    /// Items per page.
    pub page_size: u32,
    /// Total number of items across all pages.
    pub total_items: u64,
}

impl<T> Page<T> {
    /// Total number of pages.
    pub fn total_pages(&self) -> u32 {
        if self.total_items == 0 {
            return 1;
        }
        let pages = self.total_items.div_ceil(u64::from(self.page_size));
        // Safe: page counts won't exceed u32 in practice.
        u32::try_from(pages).unwrap_or(u32::MAX)
    }

    /// Whether there is a next page.
    pub fn has_next(&self) -> bool {
        self.page < self.total_pages()
    }

    /// Whether there is a previous page.
    pub fn has_prev(&self) -> bool {
        self.page > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_total_pages_basic() {
        let page: Page<()> = Page {
            items: vec![],
            page: 1,
            page_size: 25,
            total_items: 100,
        };
        assert_eq!(page.total_pages(), 4);
    }

    #[test]
    fn page_total_pages_partial() {
        let page: Page<()> = Page {
            items: vec![],
            page: 1,
            page_size: 25,
            total_items: 101,
        };
        assert_eq!(page.total_pages(), 5, "101 items / 25 per page = 5 pages");
    }

    #[test]
    fn page_total_pages_zero_items() {
        let page: Page<()> = Page {
            items: vec![],
            page: 1,
            page_size: 25,
            total_items: 0,
        };
        assert_eq!(page.total_pages(), 1, "zero items should still be 1 page");
    }

    #[test]
    fn page_total_pages_exact() {
        let page: Page<()> = Page {
            items: vec![],
            page: 1,
            page_size: 10,
            total_items: 30,
        };
        assert_eq!(page.total_pages(), 3);
    }

    #[test]
    fn page_has_next() {
        let page: Page<()> = Page {
            items: vec![],
            page: 1,
            page_size: 25,
            total_items: 50,
        };
        assert!(page.has_next());
    }

    #[test]
    fn page_has_next_last_page() {
        let page: Page<()> = Page {
            items: vec![],
            page: 2,
            page_size: 25,
            total_items: 50,
        };
        assert!(!page.has_next(), "last page should not have next");
    }

    #[test]
    fn page_has_prev() {
        let page: Page<()> = Page {
            items: vec![],
            page: 2,
            page_size: 25,
            total_items: 50,
        };
        assert!(page.has_prev());
    }

    #[test]
    fn page_has_prev_first_page() {
        let page: Page<()> = Page {
            items: vec![],
            page: 1,
            page_size: 25,
            total_items: 50,
        };
        assert!(!page.has_prev(), "first page should not have prev");
    }

    #[test]
    fn list_request_offset() {
        let req = ListRequest {
            page: 3,
            page_size: 25,
            ..ListRequest::default()
        };
        assert_eq!(req.offset(), 50, "page 3 with 25/page should offset 50");
    }

    #[test]
    fn list_request_offset_page_one() {
        let req = ListRequest::default();
        assert_eq!(req.offset(), 0, "page 1 should offset 0");
    }

    #[test]
    fn list_request_offset_page_zero() {
        let req = ListRequest {
            page: 0,
            page_size: 25,
            ..ListRequest::default()
        };
        assert_eq!(req.offset(), 0, "page 0 should saturate to offset 0");
    }

    #[test]
    fn sort_direction_sql() {
        assert_eq!(SortDirection::Asc.as_sql(), "ASC");
        assert_eq!(SortDirection::Desc.as_sql(), "DESC");
    }

    #[test]
    fn event_sort_key_sql_column() {
        assert_eq!(EventSortKey::Timestamp.as_sql_column(), "timestamp");
        assert_eq!(EventSortKey::Comm.as_sql_column(), "comm");
        assert_eq!(EventSortKey::ExitCode.as_sql_column(), "exit_code");
    }
}
