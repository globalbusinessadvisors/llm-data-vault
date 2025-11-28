//! Dataset models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{Labels, PaginatedList, SortOrder};

/// A dataset in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Unique identifier.
    pub id: Uuid,

    /// Human-readable name.
    pub name: String,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Dataset format.
    pub format: DatasetFormat,

    /// Dataset status.
    pub status: DatasetStatus,

    /// Number of records.
    pub record_count: u64,

    /// Total size in bytes.
    pub size_bytes: u64,

    /// Schema definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<DatasetSchema>,

    /// User-defined labels.
    #[serde(default)]
    pub labels: Labels,

    /// When the dataset was created.
    pub created_at: DateTime<Utc>,

    /// When the dataset was last updated.
    pub updated_at: DateTime<Utc>,

    /// ID of the owner.
    pub owner_id: String,
}

/// Dataset format type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatasetFormat {
    /// JSON format.
    Json,
    /// JSON Lines format (one JSON object per line).
    Jsonl,
    /// CSV format.
    Csv,
    /// Parquet format.
    Parquet,
    /// Plain text format.
    Text,
    /// Custom/unknown format.
    Custom,
}

impl Default for DatasetFormat {
    fn default() -> Self {
        Self::Jsonl
    }
}

impl std::fmt::Display for DatasetFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Jsonl => write!(f, "jsonl"),
            Self::Csv => write!(f, "csv"),
            Self::Parquet => write!(f, "parquet"),
            Self::Text => write!(f, "text"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for DatasetFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "jsonl" => Ok(Self::Jsonl),
            "csv" => Ok(Self::Csv),
            "parquet" => Ok(Self::Parquet),
            "text" => Ok(Self::Text),
            "custom" => Ok(Self::Custom),
            _ => Err(format!("Unknown dataset format: {s}")),
        }
    }
}

/// Dataset status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatasetStatus {
    /// Dataset is being created/processed.
    Pending,
    /// Dataset is active and usable.
    Active,
    /// Dataset is archived (read-only).
    Archived,
    /// Dataset is being deleted.
    Deleting,
    /// Dataset processing failed.
    Failed,
}

impl Default for DatasetStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for DatasetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Archived => write!(f, "archived"),
            Self::Deleting => write!(f, "deleting"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for DatasetStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "archived" => Ok(Self::Archived),
            "deleting" => Ok(Self::Deleting),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("Unknown dataset status: {s}")),
        }
    }
}

/// Dataset schema definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSchema {
    /// Schema fields.
    pub fields: Vec<SchemaField>,

    /// Primary key fields.
    #[serde(default)]
    pub primary_key: Vec<String>,
}

/// A field in a dataset schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    /// Field name.
    pub name: String,

    /// Field data type.
    pub data_type: DataType,

    /// Whether the field is nullable.
    #[serde(default)]
    pub nullable: bool,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether this field may contain PII.
    #[serde(default)]
    pub pii_candidate: bool,
}

/// Data types for schema fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DataType {
    /// String type.
    String,
    /// Integer type.
    Integer,
    /// Float type.
    Float,
    /// Boolean type.
    Boolean,
    /// Date type.
    Date,
    /// DateTime type.
    Datetime,
    /// JSON object type.
    Object,
    /// Array type.
    Array,
    /// Binary data.
    Binary,
}

/// Request to create a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetCreate {
    /// Human-readable name.
    pub name: String,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Dataset format.
    #[serde(default)]
    pub format: DatasetFormat,

    /// Schema definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<DatasetSchema>,

    /// User-defined labels.
    #[serde(default)]
    pub labels: Labels,
}

impl DatasetCreate {
    /// Creates a new dataset creation request.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            format: DatasetFormat::default(),
            schema: None,
            labels: Labels::new(),
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the format.
    #[must_use]
    pub fn with_format(mut self, format: DatasetFormat) -> Self {
        self.format = format;
        self
    }

    /// Sets the schema.
    #[must_use]
    pub fn with_schema(mut self, schema: DatasetSchema) -> Self {
        self.schema = Some(schema);
        self
    }

    /// Adds a label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Request to update a dataset.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatasetUpdate {
    /// New name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// New description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// New labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Labels>,

    /// New status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<DatasetStatus>,
}

impl DatasetUpdate {
    /// Creates a new dataset update request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the labels.
    #[must_use]
    pub fn with_labels(mut self, labels: Labels) -> Self {
        self.labels = Some(labels);
        self
    }

    /// Sets the status.
    #[must_use]
    pub fn with_status(mut self, status: DatasetStatus) -> Self {
        self.status = Some(status);
        self
    }
}

/// Parameters for listing datasets.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DatasetListParams {
    /// Filter by status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<DatasetStatus>,

    /// Filter by format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<DatasetFormat>,

    /// Search by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,

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

impl DatasetListParams {
    /// Creates new list parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by status.
    #[must_use]
    pub fn with_status(mut self, status: DatasetStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filters by format.
    #[must_use]
    pub fn with_format(mut self, format: DatasetFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Searches by name.
    #[must_use]
    pub fn with_search(mut self, search: impl Into<String>) -> Self {
        self.search = Some(search.into());
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

/// Paginated list of datasets.
pub type DatasetList = PaginatedList<Dataset>;

/// Dataset statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetStats {
    /// Total number of records.
    pub record_count: u64,

    /// Total size in bytes.
    pub size_bytes: u64,

    /// PII detection statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_stats: Option<PiiStats>,

    /// Last scan timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scanned_at: Option<DateTime<Utc>>,
}

/// PII statistics for a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiStats {
    /// Total PII entities detected.
    pub total_entities: u64,

    /// Records with PII.
    pub records_with_pii: u64,

    /// Breakdown by PII type.
    #[serde(default)]
    pub by_type: std::collections::HashMap<String, u64>,
}
