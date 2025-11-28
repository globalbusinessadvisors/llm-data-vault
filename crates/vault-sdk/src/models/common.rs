//! Common types used across the SDK.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Pagination parameters for list operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pagination {
    /// Maximum number of items to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Number of items to skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,

    /// Cursor for cursor-based pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl Pagination {
    /// Creates pagination with limit and offset.
    #[must_use]
    pub fn new(limit: u32, offset: u32) -> Self {
        Self {
            limit: Some(limit),
            offset: Some(offset),
            cursor: None,
        }
    }

    /// Creates cursor-based pagination.
    #[must_use]
    pub fn cursor(cursor: impl Into<String>) -> Self {
        Self {
            limit: None,
            offset: None,
            cursor: Some(cursor.into()),
        }
    }

    /// Sets the limit.
    #[must_use]
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Sets the offset.
    #[must_use]
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Sort order for list operations.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    /// Ascending order.
    #[default]
    Asc,
    /// Descending order.
    Desc,
}

impl std::fmt::Display for SortOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Asc => write!(f, "asc"),
            Self::Desc => write!(f, "desc"),
        }
    }
}

/// Paginated list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedList<T> {
    /// Items in this page.
    pub items: Vec<T>,

    /// Total number of items across all pages.
    pub total: u64,

    /// Whether there are more items.
    pub has_more: bool,

    /// Cursor for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> PaginatedList<T> {
    /// Creates an empty paginated list.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
            has_more: false,
            next_cursor: None,
        }
    }

    /// Creates a paginated list from items.
    #[must_use]
    pub fn from_items(items: Vec<T>, total: u64, has_more: bool) -> Self {
        Self {
            items,
            total,
            has_more,
            next_cursor: None,
        }
    }
}

impl<T> Default for PaginatedList<T> {
    fn default() -> Self {
        Self::empty()
    }
}

/// Health status of the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall status.
    pub status: ServiceStatus,

    /// Service version.
    pub version: String,

    /// Individual component statuses.
    #[serde(default)]
    pub components: Vec<ComponentHealth>,

    /// Server timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Service status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    /// Service is healthy.
    Healthy,
    /// Service is degraded but functional.
    Degraded,
    /// Service is unhealthy.
    Unhealthy,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

/// Health status of a component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name.
    pub name: String,

    /// Component status.
    pub status: ServiceStatus,

    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Response time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Metadata about a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetadata {
    /// When the resource was created.
    pub created_at: DateTime<Utc>,

    /// When the resource was last updated.
    pub updated_at: DateTime<Utc>,

    /// ID of the user who created this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,

    /// ID of the user who last updated this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,

    /// Resource version for optimistic locking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

/// User-defined labels for resources.
pub type Labels = std::collections::HashMap<String, String>;

/// User-defined annotations for resources.
pub type Annotations = std::collections::HashMap<String, String>;
