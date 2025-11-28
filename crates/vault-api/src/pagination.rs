//! Pagination support.

use serde::{Deserialize, Serialize};

/// Pagination parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct Pagination {
    /// Page number (1-based).
    #[serde(default = "default_page")]
    pub page: u32,
    /// Page size.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Sort field.
    pub sort_by: Option<String>,
    /// Sort order (asc/desc).
    #[serde(default)]
    pub sort_order: SortOrder,
}

fn default_page() -> u32 {
    1
}

fn default_page_size() -> u32 {
    20
}

/// Sort order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    /// Ascending order.
    #[default]
    Asc,
    /// Descending order.
    Desc,
}

impl Pagination {
    /// Creates default pagination.
    pub fn new() -> Self {
        Self {
            page: 1,
            page_size: 20,
            sort_by: None,
            sort_order: SortOrder::Asc,
        }
    }

    /// Returns the offset for database queries.
    #[must_use]
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.page_size
    }

    /// Returns the limit for database queries.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.page_size.min(MAX_PAGE_SIZE)
    }

    /// Validates and sanitizes pagination parameters.
    pub fn sanitize(&mut self) {
        if self.page == 0 {
            self.page = 1;
        }
        if self.page_size == 0 {
            self.page_size = DEFAULT_PAGE_SIZE;
        }
        if self.page_size > MAX_PAGE_SIZE {
            self.page_size = MAX_PAGE_SIZE;
        }
    }
}

impl Default for Pagination {
    fn default() -> Self {
        Self::new()
    }
}

const DEFAULT_PAGE_SIZE: u32 = 20;
const MAX_PAGE_SIZE: u32 = 100;

/// Paged response wrapper.
#[derive(Debug, Serialize, Deserialize)]
pub struct PagedResponse<T> {
    /// Items on this page.
    pub items: Vec<T>,
    /// Pagination metadata.
    pub pagination: PageInfo,
}

/// Pagination metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct PageInfo {
    /// Current page number.
    pub page: u32,
    /// Page size.
    pub page_size: u32,
    /// Total number of items.
    pub total_items: u64,
    /// Total number of pages.
    pub total_pages: u32,
    /// Has previous page.
    pub has_previous: bool,
    /// Has next page.
    pub has_next: bool,
}

impl<T> PagedResponse<T> {
    /// Creates a new paged response.
    pub fn new(items: Vec<T>, pagination: &Pagination, total_items: u64) -> Self {
        let total_pages = if pagination.page_size > 0 {
            ((total_items as f64) / (pagination.page_size as f64)).ceil() as u32
        } else {
            0
        };

        Self {
            items,
            pagination: PageInfo {
                page: pagination.page,
                page_size: pagination.page_size,
                total_items,
                total_pages,
                has_previous: pagination.page > 1,
                has_next: pagination.page < total_pages,
            },
        }
    }

    /// Creates an empty paged response.
    pub fn empty(pagination: &Pagination) -> Self {
        Self::new(Vec::new(), pagination, 0)
    }

    /// Maps the items to a different type.
    pub fn map<U, F>(self, f: F) -> PagedResponse<U>
    where
        F: FnMut(T) -> U,
    {
        PagedResponse {
            items: self.items.into_iter().map(f).collect(),
            pagination: self.pagination,
        }
    }
}

/// Cursor-based pagination parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct CursorPagination {
    /// Cursor (opaque string).
    pub cursor: Option<String>,
    /// Number of items to return.
    #[serde(default = "default_page_size")]
    pub limit: u32,
    /// Direction (forward/backward).
    #[serde(default)]
    pub direction: CursorDirection,
}

/// Cursor direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CursorDirection {
    /// Forward pagination.
    #[default]
    Forward,
    /// Backward pagination.
    Backward,
}

impl CursorPagination {
    /// Creates default cursor pagination.
    pub fn new() -> Self {
        Self {
            cursor: None,
            limit: DEFAULT_PAGE_SIZE,
            direction: CursorDirection::Forward,
        }
    }

    /// Returns the limit for queries.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit.min(MAX_PAGE_SIZE)
    }
}

impl Default for CursorPagination {
    fn default() -> Self {
        Self::new()
    }
}

/// Cursor-based paged response.
#[derive(Debug, Serialize, Deserialize)]
pub struct CursorPagedResponse<T> {
    /// Items.
    pub items: Vec<T>,
    /// Next cursor (if more items exist).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Previous cursor (if backward navigation possible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_cursor: Option<String>,
    /// Has more items.
    pub has_more: bool,
}

impl<T> CursorPagedResponse<T> {
    /// Creates a new cursor paged response.
    pub fn new(items: Vec<T>, next_cursor: Option<String>, has_more: bool) -> Self {
        Self {
            items,
            next_cursor,
            previous_cursor: None,
            has_more,
        }
    }

    /// Creates an empty response.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            previous_cursor: None,
            has_more: false,
        }
    }

    /// Sets the previous cursor.
    pub fn with_previous_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.previous_cursor = Some(cursor.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_offset() {
        let mut pagination = Pagination {
            page: 1,
            page_size: 10,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        assert_eq!(pagination.offset(), 0);

        pagination.page = 2;
        assert_eq!(pagination.offset(), 10);

        pagination.page = 5;
        assert_eq!(pagination.offset(), 40);
    }

    #[test]
    fn test_pagination_sanitize() {
        let mut pagination = Pagination {
            page: 0,
            page_size: 500,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        pagination.sanitize();

        assert_eq!(pagination.page, 1);
        assert_eq!(pagination.page_size, MAX_PAGE_SIZE);
    }

    #[test]
    fn test_paged_response() {
        let pagination = Pagination {
            page: 2,
            page_size: 10,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        let items: Vec<i32> = (1..=10).collect();
        let response = PagedResponse::new(items, &pagination, 35);

        assert_eq!(response.pagination.page, 2);
        assert_eq!(response.pagination.total_items, 35);
        assert_eq!(response.pagination.total_pages, 4);
        assert!(response.pagination.has_previous);
        assert!(response.pagination.has_next);
    }

    #[test]
    fn test_paged_response_first_page() {
        let pagination = Pagination {
            page: 1,
            page_size: 20,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        let response: PagedResponse<i32> = PagedResponse::new(vec![], &pagination, 50);

        assert!(!response.pagination.has_previous);
        assert!(response.pagination.has_next);
    }

    #[test]
    fn test_paged_response_last_page() {
        let pagination = Pagination {
            page: 3,
            page_size: 20,
            sort_by: None,
            sort_order: SortOrder::Asc,
        };

        let response: PagedResponse<i32> = PagedResponse::new(vec![], &pagination, 50);

        assert!(response.pagination.has_previous);
        assert!(!response.pagination.has_next);
    }

    #[test]
    fn test_cursor_pagination() {
        let pagination = CursorPagination {
            cursor: Some("abc123".to_string()),
            limit: 25,
            direction: CursorDirection::Forward,
        };

        assert_eq!(pagination.limit(), 25);
        assert_eq!(pagination.cursor, Some("abc123".to_string()));
    }
}
