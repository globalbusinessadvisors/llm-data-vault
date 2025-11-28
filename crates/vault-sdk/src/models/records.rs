//! Record models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::common::{Labels, PaginatedList, SortOrder};

/// A record in a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Unique identifier.
    pub id: Uuid,

    /// Parent dataset ID.
    pub dataset_id: Uuid,

    /// Record content.
    pub content: RecordContent,

    /// Content hash for deduplication.
    pub content_hash: String,

    /// Record size in bytes.
    pub size_bytes: u64,

    /// Record status.
    pub status: RecordStatus,

    /// User-defined labels.
    #[serde(default)]
    pub labels: Labels,

    /// PII detection status.
    pub pii_status: PiiScanStatus,

    /// Number of PII entities found.
    #[serde(default)]
    pub pii_count: u64,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,

    /// Record version.
    pub version: u64,
}

/// Record content wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RecordContent {
    /// JSON content.
    #[serde(rename = "json")]
    Json(Value),

    /// Text content.
    #[serde(rename = "text")]
    Text(String),

    /// Binary content (base64 encoded).
    #[serde(rename = "binary")]
    Binary(String),

    /// Reference to stored content.
    #[serde(rename = "reference")]
    Reference {
        /// Content reference ID.
        content_id: String,
        /// Content type.
        content_type: String,
    },
}

impl RecordContent {
    /// Creates JSON content.
    #[must_use]
    pub fn json(value: Value) -> Self {
        Self::Json(value)
    }

    /// Creates text content.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text(text.into())
    }

    /// Creates binary content.
    #[must_use]
    pub fn binary(data: impl AsRef<[u8]>) -> Self {
        Self::Binary(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data.as_ref(),
        ))
    }
}

/// Record status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordStatus {
    /// Record is pending processing.
    Pending,
    /// Record is active.
    Active,
    /// Record is archived.
    Archived,
    /// Record is quarantined (e.g., due to PII).
    Quarantined,
    /// Record is deleted.
    Deleted,
}

impl Default for RecordStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for RecordStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Archived => write!(f, "archived"),
            Self::Quarantined => write!(f, "quarantined"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

impl std::str::FromStr for RecordStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "archived" => Ok(Self::Archived),
            "quarantined" => Ok(Self::Quarantined),
            "deleted" => Ok(Self::Deleted),
            _ => Err(format!("Unknown record status: {s}")),
        }
    }
}

/// PII scan status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PiiScanStatus {
    /// Not yet scanned.
    Pending,
    /// Scan in progress.
    Scanning,
    /// Scan complete, no PII found.
    Clean,
    /// Scan complete, PII found.
    Detected,
    /// Scan failed.
    Failed,
}

impl Default for PiiScanStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl std::fmt::Display for PiiScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Scanning => write!(f, "scanning"),
            Self::Clean => write!(f, "clean"),
            Self::Detected => write!(f, "detected"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for PiiScanStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "scanning" => Ok(Self::Scanning),
            "clean" => Ok(Self::Clean),
            "detected" => Ok(Self::Detected),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("Unknown PII scan status: {s}")),
        }
    }
}

/// Request to create a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordCreate {
    /// Record content.
    pub content: RecordContent,

    /// User-defined labels.
    #[serde(default)]
    pub labels: Labels,

    /// Whether to scan for PII immediately.
    #[serde(default = "default_true")]
    pub scan_pii: bool,

    /// Whether to auto-anonymize detected PII.
    #[serde(default)]
    pub auto_anonymize: bool,

    /// Idempotency key for deduplication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

fn default_true() -> bool {
    true
}

impl RecordCreate {
    /// Creates a new record with JSON content.
    #[must_use]
    pub fn json(content: Value) -> Self {
        Self {
            content: RecordContent::Json(content),
            labels: Labels::new(),
            scan_pii: true,
            auto_anonymize: false,
            idempotency_key: None,
        }
    }

    /// Creates a new record with text content.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: RecordContent::Text(text.into()),
            labels: Labels::new(),
            scan_pii: true,
            auto_anonymize: false,
            idempotency_key: None,
        }
    }

    /// Sets PII scanning.
    #[must_use]
    pub fn with_pii_scan(mut self, scan: bool) -> Self {
        self.scan_pii = scan;
        self
    }

    /// Enables auto-anonymization.
    #[must_use]
    pub fn with_auto_anonymize(mut self) -> Self {
        self.auto_anonymize = true;
        self
    }

    /// Adds a label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Sets idempotency key.
    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }
}

/// Request to update a record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordUpdate {
    /// New content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<RecordContent>,

    /// New labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Labels>,

    /// New status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<RecordStatus>,

    /// Expected version for optimistic locking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
}

impl RecordUpdate {
    /// Creates a new update request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets new content.
    #[must_use]
    pub fn with_content(mut self, content: RecordContent) -> Self {
        self.content = Some(content);
        self
    }

    /// Sets new labels.
    #[must_use]
    pub fn with_labels(mut self, labels: Labels) -> Self {
        self.labels = Some(labels);
        self
    }

    /// Sets new status.
    #[must_use]
    pub fn with_status(mut self, status: RecordStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets expected version for optimistic locking.
    #[must_use]
    pub fn with_expected_version(mut self, version: u64) -> Self {
        self.expected_version = Some(version);
        self
    }
}

/// Parameters for listing records.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RecordListParams {
    /// Filter by status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<RecordStatus>,

    /// Filter by PII status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_status: Option<PiiScanStatus>,

    /// Filter by label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Sort by field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,

    /// Sort order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<SortOrder>,

    /// Limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

impl RecordListParams {
    /// Creates new list parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by status.
    #[must_use]
    pub fn with_status(mut self, status: RecordStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filters by PII status.
    #[must_use]
    pub fn with_pii_status(mut self, status: PiiScanStatus) -> Self {
        self.pii_status = Some(status);
        self
    }

    /// Filters by label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Sets sort field and order.
    #[must_use]
    pub fn with_sort(mut self, field: impl Into<String>, order: SortOrder) -> Self {
        self.sort_by = Some(field.into());
        self.sort_order = Some(order);
        self
    }

    /// Sets pagination.
    #[must_use]
    pub fn with_pagination(mut self, limit: u32, offset: u32) -> Self {
        self.limit = Some(limit);
        self.offset = Some(offset);
        self
    }
}

/// Paginated list of records.
pub type RecordList = PaginatedList<Record>;

/// Bulk record creation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRecordCreate {
    /// Records to create.
    pub records: Vec<RecordCreate>,

    /// Continue on error.
    #[serde(default)]
    pub continue_on_error: bool,
}

/// Bulk operation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResult {
    /// Number of successful operations.
    pub succeeded: u64,

    /// Number of failed operations.
    pub failed: u64,

    /// Individual results.
    pub results: Vec<BulkItemResult>,
}

/// Result of a single bulk operation item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkItemResult {
    /// Index in the original request.
    pub index: usize,

    /// Whether the operation succeeded.
    pub success: bool,

    /// Created record ID (if successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,

    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
