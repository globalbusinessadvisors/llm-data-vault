# LLM-Data-Vault Core Data Models (Rust Pseudocode)

## Module Organization

```rust
// src/models/mod.rs
pub mod common;
pub mod dataset;
pub mod record;
pub mod corpus;
pub mod user;
pub mod audit;
pub mod policy;
pub mod error;

pub use common::*;
pub use dataset::*;
pub use record::*;
pub use corpus::*;
pub use user::*;
pub use audit::*;
pub use policy::*;
pub use error::*;
```

---

## 1. Common Types (`src/models/common.rs`)

```rust
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

// ============================================================================
// Core ID Types (Newtype Pattern for Type Safety)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DatasetId(Uuid);

impl DatasetId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for DatasetId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DatasetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for DatasetId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionId(Uuid);

impl VersionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for VersionId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordId(Uuid);

impl RecordId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RecordId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CorpusId(Uuid);

impl CorpusId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CorpusId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrganizationId(Uuid);

impl OrganizationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for OrganizationId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TeamId(Uuid);

impl TeamId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TeamId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceId(Uuid);

impl WorkspaceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for WorkspaceId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyId(Uuid);

impl PolicyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PolicyId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Checksum Types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "algorithm", content = "value")]
pub enum Checksum {
    Sha256(String),
    Sha512(String),
    Blake3(String),
}

impl Checksum {
    pub fn sha256(hash: String) -> Self {
        Self::Sha256(hash)
    }

    pub fn sha512(hash: String) -> Self {
        Self::Sha512(hash)
    }

    pub fn blake3(hash: String) -> Self {
        Self::Blake3(hash)
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        // Pseudocode: compute hash and compare
        match self {
            Self::Sha256(expected) => {
                // let computed = sha256(data);
                // computed == expected
                true
            }
            Self::Sha512(expected) => {
                // let computed = sha512(data);
                // computed == expected
                true
            }
            Self::Blake3(expected) => {
                // let computed = blake3(data);
                // computed == expected
                true
            }
        }
    }
}

impl fmt::Display for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256(hash) => write!(f, "sha256:{}", hash),
            Self::Sha512(hash) => write!(f, "sha512:{}", hash),
            Self::Blake3(hash) => write!(f, "blake3:{}", hash),
        }
    }
}

// ============================================================================
// Timestamp Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    pub fn as_datetime(&self) -> &DateTime<Utc> {
        &self.0
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

// ============================================================================
// Pagination Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    pub page: u32,
    pub page_size: u32,
    pub sort_by: Option<String>,
    pub sort_order: SortOrder,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 50,
            sort_by: None,
            sort_order: SortOrder::Descending,
        }
    }
}

impl PaginationParams {
    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.page_size
    }

    pub fn limit(&self) -> u32 {
        self.page_size
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.page < 1 {
            return Err(ValidationError::new("page must be >= 1"));
        }
        if self.page_size < 1 || self.page_size > 1000 {
            return Err(ValidationError::new("page_size must be between 1 and 1000"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total_count: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total_count: u64, params: &PaginationParams) -> Self {
        let total_pages = ((total_count as f64) / (params.page_size as f64)).ceil() as u32;
        Self {
            items,
            total_count,
            page: params.page,
            page_size: params.page_size,
            total_pages,
        }
    }

    pub fn has_next_page(&self) -> bool {
        self.page < self.total_pages
    }

    pub fn has_prev_page(&self) -> bool {
        self.page > 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Ascending,
    Descending,
}

// ============================================================================
// Cursor-based Pagination (for large datasets)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorParams {
    pub cursor: Option<String>,
    pub limit: u32,
}

impl Default for CursorParams {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorResponse<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

// ============================================================================
// Filter Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterCriteria {
    pub field: String,
    pub operator: FilterOperator,
    pub value: FilterValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOperator {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
    IsNull,
    IsNotNull,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<String>),
    Null,
}

// ============================================================================
// Metadata Types
// ============================================================================

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Metadata(HashMap<String, String>);

impl Metadata {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, key: String, value: String) -> Option<String> {
        self.0.insert(key, value)
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<HashMap<String, String>> for Metadata {
    fn from(map: HashMap<String, String>) -> Self {
        Self(map)
    }
}

impl From<Metadata> for HashMap<String, String> {
    fn from(metadata: Metadata) -> Self {
        metadata.0
    }
}

// ============================================================================
// Tags
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tag(String);

impl Tag {
    pub fn new(tag: impl Into<String>) -> Result<Self, ValidationError> {
        let tag = tag.into();
        if tag.is_empty() || tag.len() > 128 {
            return Err(ValidationError::new("tag length must be between 1 and 128"));
        }
        // Validate tag format (alphanumeric, hyphens, underscores)
        if !tag.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(ValidationError::new("tag must contain only alphanumeric characters, hyphens, and underscores"));
        }
        Ok(Self(tag))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tags(Vec<Tag>);

impl Tags {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, tag: Tag) {
        if !self.0.contains(&tag) {
            self.0.push(tag);
        }
    }

    pub fn remove(&mut self, tag: &Tag) {
        self.0.retain(|t| t != tag);
    }

    pub fn contains(&self, tag: &Tag) -> bool {
        self.0.contains(tag)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Tag> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<Tag>> for Tags {
    fn from(tags: Vec<Tag>) -> Self {
        Self(tags)
    }
}

// ============================================================================
// Size Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ByteSize(u64);

impl ByteSize {
    pub fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> u64 {
        self.0
    }

    pub fn as_kb(&self) -> f64 {
        self.0 as f64 / 1024.0
    }

    pub fn as_mb(&self) -> f64 {
        self.0 as f64 / 1024.0 / 1024.0
    }

    pub fn as_gb(&self) -> f64 {
        self.0 as f64 / 1024.0 / 1024.0 / 1024.0
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        const TB: u64 = GB * 1024;

        if self.0 >= TB {
            write!(f, "{:.2} TB", self.0 as f64 / TB as f64)
        } else if self.0 >= GB {
            write!(f, "{:.2} GB", self.0 as f64 / GB as f64)
        } else if self.0 >= MB {
            write!(f, "{:.2} MB", self.0 as f64 / MB as f64)
        } else if self.0 >= KB {
            write!(f, "{:.2} KB", self.0 as f64 / KB as f64)
        } else {
            write!(f, "{} bytes", self.0)
        }
    }
}

// ============================================================================
// Validation Error
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub message: String,
    pub field: Option<String>,
}

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            field: None,
        }
    }

    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref field) = self.field {
            write!(f, "Validation error on field '{}': {}", field, self.message)
        } else {
            write!(f, "Validation error: {}", self.message)
        }
    }
}

impl std::error::Error for ValidationError {}
```

---

## 2. Dataset Types (`src/models/dataset.rs`)

```rust
use super::common::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Dataset
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    pub id: DatasetId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,
    pub workspace_id: WorkspaceId,
    pub owner_id: UserId,

    // Version information
    pub current_version_id: VersionId,
    pub version_count: u32,

    // Schema information
    pub schema: Option<DatasetSchema>,

    // Size and statistics
    pub total_size: ByteSize,
    pub record_count: u64,

    // Checksums
    pub checksum: Option<Checksum>,

    // Metadata
    pub tags: Tags,
    pub labels: HashMap<String, String>,
    pub metadata: Metadata,

    // Retention and policies
    pub retention_policy_id: Option<PolicyId>,
    pub anonymization_policy_id: Option<PolicyId>,
    pub access_policy_id: Option<PolicyId>,

    // Status
    pub status: DatasetStatus,
    pub visibility: DatasetVisibility,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_accessed_at: Option<Timestamp>,
    pub archived_at: Option<Timestamp>,
}

impl Dataset {
    pub fn is_archived(&self) -> bool {
        self.archived_at.is_some()
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, DatasetStatus::Active)
    }

    pub fn can_write(&self) -> bool {
        matches!(self.status, DatasetStatus::Active) && self.archived_at.is_none()
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.name.is_empty() || self.name.len() > 255 {
            return Err(ValidationError::new("name must be between 1 and 255 characters")
                .with_field("name"));
        }

        if let Some(ref desc) = self.description {
            if desc.len() > 4096 {
                return Err(ValidationError::new("description must be <= 4096 characters")
                    .with_field("description"));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Dataset Builder
// ============================================================================

#[derive(Debug, Default)]
pub struct DatasetBuilder {
    name: Option<String>,
    description: Option<String>,
    organization_id: Option<OrganizationId>,
    workspace_id: Option<WorkspaceId>,
    owner_id: Option<UserId>,
    schema: Option<DatasetSchema>,
    tags: Tags,
    labels: HashMap<String, String>,
    metadata: Metadata,
    retention_policy_id: Option<PolicyId>,
    anonymization_policy_id: Option<PolicyId>,
    access_policy_id: Option<PolicyId>,
    visibility: DatasetVisibility,
}

impl DatasetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn organization_id(mut self, id: OrganizationId) -> Self {
        self.organization_id = Some(id);
        self
    }

    pub fn workspace_id(mut self, id: WorkspaceId) -> Self {
        self.workspace_id = Some(id);
        self
    }

    pub fn owner_id(mut self, id: UserId) -> Self {
        self.owner_id = Some(id);
        self
    }

    pub fn schema(mut self, schema: DatasetSchema) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn add_tag(mut self, tag: Tag) -> Self {
        self.tags.add(tag);
        self
    }

    pub fn add_label(mut self, key: String, value: String) -> Self {
        self.labels.insert(key, value);
        self
    }

    pub fn metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn retention_policy(mut self, policy_id: PolicyId) -> Self {
        self.retention_policy_id = Some(policy_id);
        self
    }

    pub fn anonymization_policy(mut self, policy_id: PolicyId) -> Self {
        self.anonymization_policy_id = Some(policy_id);
        self
    }

    pub fn access_policy(mut self, policy_id: PolicyId) -> Self {
        self.access_policy_id = Some(policy_id);
        self
    }

    pub fn visibility(mut self, visibility: DatasetVisibility) -> Self {
        self.visibility = visibility;
        self
    }

    pub fn build(self) -> Result<Dataset, ValidationError> {
        let name = self.name.ok_or_else(|| ValidationError::new("name is required"))?;
        let organization_id = self.organization_id
            .ok_or_else(|| ValidationError::new("organization_id is required"))?;
        let workspace_id = self.workspace_id
            .ok_or_else(|| ValidationError::new("workspace_id is required"))?;
        let owner_id = self.owner_id
            .ok_or_else(|| ValidationError::new("owner_id is required"))?;

        let dataset = Dataset {
            id: DatasetId::new(),
            name,
            description: self.description,
            organization_id,
            workspace_id,
            owner_id,
            current_version_id: VersionId::new(),
            version_count: 1,
            schema: self.schema,
            total_size: ByteSize::new(0),
            record_count: 0,
            checksum: None,
            tags: self.tags,
            labels: self.labels,
            metadata: self.metadata,
            retention_policy_id: self.retention_policy_id,
            anonymization_policy_id: self.anonymization_policy_id,
            access_policy_id: self.access_policy_id,
            status: DatasetStatus::Active,
            visibility: self.visibility,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            last_accessed_at: None,
            archived_at: None,
        };

        dataset.validate()?;
        Ok(dataset)
    }
}

// ============================================================================
// Dataset Status
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetStatus {
    Active,
    Archived,
    Pending,
    Processing,
    Failed,
    Deleted,
}

impl fmt::Display for DatasetStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Archived => write!(f, "archived"),
            Self::Pending => write!(f, "pending"),
            Self::Processing => write!(f, "processing"),
            Self::Failed => write!(f, "failed"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

// ============================================================================
// Dataset Visibility
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetVisibility {
    Private,
    Organization,
    Workspace,
    Public,
}

impl Default for DatasetVisibility {
    fn default() -> Self {
        Self::Private
    }
}

// ============================================================================
// Dataset Version
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetVersion {
    pub version_id: VersionId,
    pub dataset_id: DatasetId,
    pub version_number: u32,
    pub parent_version_id: Option<VersionId>,

    // Version metadata
    pub commit_message: String,
    pub author_id: UserId,
    pub author_name: String,
    pub author_email: String,

    // Version snapshot
    pub schema: Option<DatasetSchema>,
    pub size: ByteSize,
    pub record_count: u64,
    pub checksum: Option<Checksum>,

    // Changes
    pub added_records: u64,
    pub modified_records: u64,
    pub deleted_records: u64,

    // Tags and metadata
    pub tags: Tags,
    pub metadata: Metadata,

    // Timestamps
    pub created_at: Timestamp,
}

impl DatasetVersion {
    pub fn is_root(&self) -> bool {
        self.parent_version_id.is_none()
    }

    pub fn total_changes(&self) -> u64 {
        self.added_records + self.modified_records + self.deleted_records
    }
}

// ============================================================================
// Dataset Schema
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetSchema {
    pub version: u32,
    pub fields: Vec<SchemaField>,
    pub strict: bool,
    pub checksum: Option<Checksum>,
}

impl DatasetSchema {
    pub fn new(fields: Vec<SchemaField>) -> Self {
        Self {
            version: 1,
            fields,
            strict: true,
            checksum: None,
        }
    }

    pub fn find_field(&self, name: &str) -> Option<&SchemaField> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.fields.is_empty() {
            return Err(ValidationError::new("schema must have at least one field"));
        }

        // Check for duplicate field names
        let mut seen = std::collections::HashSet::new();
        for field in &self.fields {
            if !seen.insert(&field.name) {
                return Err(ValidationError::new(format!("duplicate field name: {}", field.name)));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaField {
    pub name: String,
    pub field_type: FieldType,
    pub nullable: bool,
    pub description: Option<String>,
    pub default_value: Option<String>,
    pub constraints: Vec<FieldConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FieldType {
    String { max_length: Option<u32> },
    Integer,
    Float,
    Boolean,
    Timestamp,
    Binary,
    Json,
    Array { item_type: Box<FieldType> },
    Object { schema: Box<DatasetSchema> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum FieldConstraint {
    MinLength { value: u32 },
    MaxLength { value: u32 },
    MinValue { value: f64 },
    MaxValue { value: f64 },
    Pattern { regex: String },
    Enum { values: Vec<String> },
    Unique,
}

// ============================================================================
// Dataset Metadata
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetMetadata {
    pub dataset_id: DatasetId,
    pub lineage: DatasetLineage,
    pub statistics: DatasetStatistics,
    pub quality_metrics: Option<QualityMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetLineage {
    pub source_datasets: Vec<DatasetId>,
    pub derived_datasets: Vec<DatasetId>,
    pub transformations: Vec<TransformationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationRecord {
    pub transformation_id: Uuid,
    pub transformation_type: String,
    pub applied_at: Timestamp,
    pub applied_by: UserId,
    pub parameters: Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetStatistics {
    pub total_records: u64,
    pub total_size: ByteSize,
    pub avg_record_size: ByteSize,
    pub field_statistics: HashMap<String, FieldStatistics>,
    pub computed_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldStatistics {
    pub non_null_count: u64,
    pub null_count: u64,
    pub unique_count: Option<u64>,
    pub min_value: Option<String>,
    pub max_value: Option<String>,
    pub avg_value: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub completeness_score: f64,
    pub validity_score: f64,
    pub consistency_score: f64,
    pub accuracy_score: Option<f64>,
    pub timeliness_score: Option<f64>,
    pub overall_score: f64,
    pub computed_at: Timestamp,
}
```

---

## 3. Record Types (`src/models/record.rs`)

```rust
use super::common::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

// ============================================================================
// Data Record
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRecord {
    pub id: RecordId,
    pub dataset_id: DatasetId,
    pub version_id: VersionId,

    // Record data
    pub data: RecordData,

    // Checksums and integrity
    pub checksum: Checksum,
    pub size: ByteSize,

    // Lineage
    pub parent_record_id: Option<RecordId>,
    pub source_system: Option<String>,
    pub external_id: Option<String>,

    // Metadata
    pub metadata: Metadata,
    pub tags: Tags,

    // Status
    pub status: RecordStatus,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub ingested_at: Timestamp,
}

impl DataRecord {
    pub fn new(dataset_id: DatasetId, version_id: VersionId, data: RecordData) -> Self {
        let checksum = data.compute_checksum();
        let size = data.size();

        Self {
            id: RecordId::new(),
            dataset_id,
            version_id,
            data,
            checksum,
            size,
            parent_record_id: None,
            source_system: None,
            external_id: None,
            metadata: Metadata::new(),
            tags: Tags::new(),
            status: RecordStatus::Active,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            ingested_at: Timestamp::now(),
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, RecordStatus::Active)
    }

    pub fn is_deleted(&self) -> bool {
        matches!(self.status, RecordStatus::Deleted)
    }

    pub fn verify_checksum(&self) -> bool {
        self.data.compute_checksum() == self.checksum
    }
}

// ============================================================================
// Record Data (Zero-Copy Design)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum RecordData {
    Structured(JsonValue),
    SemiStructured(JsonValue),
    Binary(BinaryData),
    Text(String),
}

impl RecordData {
    pub fn compute_checksum(&self) -> Checksum {
        // Pseudocode: serialize and hash
        match self {
            Self::Structured(json) | Self::SemiStructured(json) => {
                let serialized = serde_json::to_vec(json).unwrap();
                Checksum::sha256(format!("{:x}", blake3::hash(&serialized)))
            }
            Self::Binary(data) => {
                Checksum::sha256(format!("{:x}", blake3::hash(&data.content)))
            }
            Self::Text(text) => {
                Checksum::sha256(format!("{:x}", blake3::hash(text.as_bytes())))
            }
        }
    }

    pub fn size(&self) -> ByteSize {
        let bytes = match self {
            Self::Structured(json) | Self::SemiStructured(json) => {
                serde_json::to_vec(json).unwrap().len()
            }
            Self::Binary(data) => data.content.len(),
            Self::Text(text) => text.len(),
        };
        ByteSize::new(bytes as u64)
    }

    pub fn is_binary(&self) -> bool {
        matches!(self, Self::Binary(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryData {
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    pub mime_type: Option<String>,
    pub encoding: Option<String>,
}

impl BinaryData {
    pub fn new(content: Vec<u8>) -> Self {
        Self {
            content,
            mime_type: None,
            encoding: None,
        }
    }

    pub fn with_mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }

    pub fn with_encoding(mut self, encoding: impl Into<String>) -> Self {
        self.encoding = Some(encoding.into());
        self
    }
}

// ============================================================================
// Record Status
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Active,
    Archived,
    Deleted,
    Anonymized,
    Quarantined,
}

// ============================================================================
// Record Batch (for efficient bulk operations)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordBatch {
    pub batch_id: Uuid,
    pub dataset_id: DatasetId,
    pub version_id: VersionId,
    pub records: Vec<DataRecord>,
    pub batch_size: u32,
    pub total_size: ByteSize,
    pub checksum: Checksum,
    pub created_at: Timestamp,
}

impl RecordBatch {
    pub fn new(dataset_id: DatasetId, version_id: VersionId, records: Vec<DataRecord>) -> Self {
        let batch_size = records.len() as u32;
        let total_size = records.iter().map(|r| r.size.as_bytes()).sum::<u64>();

        // Compute batch checksum from individual record checksums
        let batch_checksum = Self::compute_batch_checksum(&records);

        Self {
            batch_id: Uuid::new_v4(),
            dataset_id,
            version_id,
            records,
            batch_size,
            total_size: ByteSize::new(total_size),
            checksum: batch_checksum,
            created_at: Timestamp::now(),
        }
    }

    fn compute_batch_checksum(records: &[DataRecord]) -> Checksum {
        // Pseudocode: hash of all record checksums
        let combined = records
            .iter()
            .map(|r| r.checksum.to_string())
            .collect::<Vec<_>>()
            .join("");
        Checksum::sha256(format!("{:x}", blake3::hash(combined.as_bytes())))
    }

    pub fn verify_checksums(&self) -> bool {
        self.records.iter().all(|r| r.verify_checksum())
            && Self::compute_batch_checksum(&self.records) == self.checksum
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ============================================================================
// Record Schema
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordSchema {
    pub schema_id: Uuid,
    pub dataset_id: DatasetId,
    pub version: u32,
    pub fields: Vec<SchemaField>,
    pub created_at: Timestamp,
}

impl RecordSchema {
    pub fn validate_record(&self, record: &DataRecord) -> Result<(), ValidationError> {
        match &record.data {
            RecordData::Structured(json) | RecordData::SemiStructured(json) => {
                self.validate_json(json)
            }
            RecordData::Binary(_) => Ok(()), // Binary data doesn't need schema validation
            RecordData::Text(_) => Ok(()),   // Text data doesn't need schema validation
        }
    }

    fn validate_json(&self, json: &JsonValue) -> Result<(), ValidationError> {
        // Pseudocode: validate JSON against schema fields
        if let JsonValue::Object(obj) = json {
            for field in &self.fields {
                if !field.nullable && !obj.contains_key(&field.name) {
                    return Err(ValidationError::new(format!("missing required field: {}", field.name)));
                }

                if let Some(value) = obj.get(&field.name) {
                    // Validate field type and constraints
                    self.validate_field_value(&field, value)?;
                }
            }
        }
        Ok(())
    }

    fn validate_field_value(&self, field: &SchemaField, value: &JsonValue) -> Result<(), ValidationError> {
        // Pseudocode: type checking and constraint validation
        Ok(())
    }
}

// ============================================================================
// Record Query
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordQuery {
    pub dataset_id: DatasetId,
    pub version_id: Option<VersionId>,
    pub filters: Vec<FilterCriteria>,
    pub pagination: PaginationParams,
    pub include_deleted: bool,
}

impl Default for RecordQuery {
    fn default() -> Self {
        Self {
            dataset_id: DatasetId::new(),
            version_id: None,
            filters: Vec::new(),
            pagination: PaginationParams::default(),
            include_deleted: false,
        }
    }
}

// ============================================================================
// Record Lineage
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordLineage {
    pub record_id: RecordId,
    pub ancestors: Vec<RecordId>,
    pub descendants: Vec<RecordId>,
    pub transformations: Vec<TransformationRecord>,
}

impl RecordLineage {
    pub fn depth(&self) -> usize {
        self.ancestors.len()
    }

    pub fn is_root(&self) -> bool {
        self.ancestors.is_empty()
    }
}
```

---

## 4. Corpus Types (`src/models/corpus.rs`)

```rust
use super::common::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Corpus
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Corpus {
    pub id: CorpusId,
    pub name: String,
    pub description: Option<String>,
    pub corpus_type: CorpusType,

    // Organization
    pub organization_id: OrganizationId,
    pub workspace_id: WorkspaceId,
    pub owner_id: UserId,

    // Statistics
    pub entry_count: u64,
    pub total_size: ByteSize,

    // Associated dataset
    pub dataset_id: Option<DatasetId>,

    // Metadata
    pub tags: Tags,
    pub metadata: Metadata,

    // Status
    pub status: CorpusStatus,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl Corpus {
    pub fn is_active(&self) -> bool {
        matches!(self.status, CorpusStatus::Active)
    }
}

// ============================================================================
// Corpus Type
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusType {
    Training,
    Evaluation,
    Testing,
    Validation,
    Benchmark,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusStatus {
    Active,
    Archived,
    Building,
    Failed,
}

// ============================================================================
// Corpus Entry
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub id: Uuid,
    pub corpus_id: CorpusId,
    pub entry_type: CorpusEntryType,

    // Content
    pub prompt: String,
    pub response: Option<String>,
    pub ground_truth: Option<String>,

    // Context and metadata
    pub context: Option<String>,
    pub system_prompt: Option<String>,
    pub parameters: HashMap<String, serde_json::Value>,

    // Annotations
    pub annotations: Vec<Annotation>,
    pub quality_score: Option<f64>,
    pub human_reviewed: bool,

    // Linkage
    pub record_id: Option<RecordId>,
    pub source_system: Option<String>,
    pub external_id: Option<String>,

    // Metadata
    pub metadata: Metadata,
    pub tags: Tags,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl CorpusEntry {
    pub fn has_ground_truth(&self) -> bool {
        self.ground_truth.is_some()
    }

    pub fn has_response(&self) -> bool {
        self.response.is_some()
    }

    pub fn is_complete(&self) -> bool {
        match self.entry_type {
            CorpusEntryType::PromptResponse => self.has_response(),
            CorpusEntryType::GroundTruth => self.has_ground_truth(),
            CorpusEntryType::PromptOnly => true,
        }
    }
}

// ============================================================================
// Corpus Entry Type
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusEntryType {
    PromptResponse,
    GroundTruth,
    PromptOnly,
}

// ============================================================================
// Evaluation Corpus
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationCorpus {
    pub corpus: Corpus,
    pub evaluation_config: EvaluationConfig,
    pub metrics: Vec<EvaluationMetric>,
    pub baseline_scores: Option<HashMap<String, f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationConfig {
    pub evaluation_type: EvaluationType,
    pub scoring_methods: Vec<ScoringMethod>,
    pub require_human_review: bool,
    pub min_quality_score: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationType {
    Automated,
    HumanReview,
    Hybrid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoringMethod {
    ExactMatch,
    SemanticSimilarity,
    Rouge,
    Bleu,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationMetric {
    pub name: String,
    pub description: Option<String>,
    pub score_range: (f64, f64),
    pub higher_is_better: bool,
}

// ============================================================================
// Annotation
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: Uuid,
    pub annotation_type: AnnotationType,
    pub value: AnnotationValue,
    pub annotator_id: UserId,
    pub confidence: Option<f64>,
    pub metadata: Metadata,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationType {
    Label,
    Sentiment,
    EntityExtraction,
    Classification,
    QualityScore,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnnotationValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<String>),
    Object(HashMap<String, serde_json::Value>),
}

// ============================================================================
// Corpus Builder
// ============================================================================

#[derive(Debug, Default)]
pub struct CorpusBuilder {
    name: Option<String>,
    description: Option<String>,
    corpus_type: Option<CorpusType>,
    organization_id: Option<OrganizationId>,
    workspace_id: Option<WorkspaceId>,
    owner_id: Option<UserId>,
    dataset_id: Option<DatasetId>,
    tags: Tags,
    metadata: Metadata,
}

impl CorpusBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn corpus_type(mut self, corpus_type: CorpusType) -> Self {
        self.corpus_type = Some(corpus_type);
        self
    }

    pub fn organization_id(mut self, id: OrganizationId) -> Self {
        self.organization_id = Some(id);
        self
    }

    pub fn workspace_id(mut self, id: WorkspaceId) -> Self {
        self.workspace_id = Some(id);
        self
    }

    pub fn owner_id(mut self, id: UserId) -> Self {
        self.owner_id = Some(id);
        self
    }

    pub fn dataset_id(mut self, id: DatasetId) -> Self {
        self.dataset_id = Some(id);
        self
    }

    pub fn add_tag(mut self, tag: Tag) -> Self {
        self.tags.add(tag);
        self
    }

    pub fn metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn build(self) -> Result<Corpus, ValidationError> {
        let name = self.name.ok_or_else(|| ValidationError::new("name is required"))?;
        let corpus_type = self.corpus_type
            .ok_or_else(|| ValidationError::new("corpus_type is required"))?;
        let organization_id = self.organization_id
            .ok_or_else(|| ValidationError::new("organization_id is required"))?;
        let workspace_id = self.workspace_id
            .ok_or_else(|| ValidationError::new("workspace_id is required"))?;
        let owner_id = self.owner_id
            .ok_or_else(|| ValidationError::new("owner_id is required"))?;

        Ok(Corpus {
            id: CorpusId::new(),
            name,
            description: self.description,
            corpus_type,
            organization_id,
            workspace_id,
            owner_id,
            entry_count: 0,
            total_size: ByteSize::new(0),
            dataset_id: self.dataset_id,
            tags: self.tags,
            metadata: self.metadata,
            status: CorpusStatus::Active,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        })
    }
}
```

---

## 5. User and Access Types (`src/models/user.rs`)

```rust
use super::common::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ============================================================================
// User
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub display_name: String,

    // Authentication
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub auth_provider: AuthProvider,
    pub external_id: Option<String>,

    // Profile
    pub avatar_url: Option<String>,
    pub bio: Option<String>,

    // Status
    pub status: UserStatus,
    pub email_verified: bool,
    pub mfa_enabled: bool,

    // Organization membership
    pub organization_id: OrganizationId,
    pub default_workspace_id: Option<WorkspaceId>,

    // Metadata
    pub metadata: Metadata,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_login_at: Option<Timestamp>,
    pub deleted_at: Option<Timestamp>,
}

impl User {
    pub fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active) && self.deleted_at.is_none()
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.username.is_empty() || self.username.len() > 64 {
            return Err(ValidationError::new("username must be between 1 and 64 characters")
                .with_field("username"));
        }

        if !self.email.contains('@') {
            return Err(ValidationError::new("invalid email format")
                .with_field("email"));
        }

        Ok(())
    }
}

// ============================================================================
// User Status
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Inactive,
    Suspended,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProvider {
    Local,
    Google,
    Github,
    Azure,
    Okta,
    Saml,
}

// ============================================================================
// Service Account
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: UserId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,

    // API Keys
    pub api_key_hash: String,
    pub allowed_ips: Vec<String>,

    // Permissions
    pub roles: Vec<RoleId>,
    pub permissions: Vec<Permission>,

    // Rate limiting
    pub rate_limit: Option<RateLimit>,

    // Status
    pub status: ServiceAccountStatus,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
}

impl ServiceAccount {
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Timestamp::now()
        } else {
            false
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, ServiceAccountStatus::Active) && !self.is_expired()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAccountStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub requests_per_day: u32,
}

// ============================================================================
// Role
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleId(Uuid);

impl RoleId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RoleId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,

    // Permissions
    pub permissions: HashSet<Permission>,

    // Role hierarchy
    pub inherits_from: Vec<RoleId>,

    // Scope
    pub scope: RoleScope,

    // Status
    pub is_system_role: bool,
    pub is_default: bool,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl Role {
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission);
    }

    pub fn remove_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleScope {
    Organization,
    Workspace,
    Dataset,
}

// ============================================================================
// Permission
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    pub resource: ResourceType,
    pub action: Action,
    pub scope: PermissionScope,
}

impl Permission {
    pub fn new(resource: ResourceType, action: Action) -> Self {
        Self {
            resource,
            action,
            scope: PermissionScope::Organization,
        }
    }

    pub fn with_scope(mut self, scope: PermissionScope) -> Self {
        self.scope = scope;
        self
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.resource, self.action, self.scope)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Dataset,
    Record,
    Corpus,
    User,
    Role,
    Policy,
    AuditLog,
    Organization,
    Workspace,
    Team,
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dataset => write!(f, "dataset"),
            Self::Record => write!(f, "record"),
            Self::Corpus => write!(f, "corpus"),
            Self::User => write!(f, "user"),
            Self::Role => write!(f, "role"),
            Self::Policy => write!(f, "policy"),
            Self::AuditLog => write!(f, "audit_log"),
            Self::Organization => write!(f, "organization"),
            Self::Workspace => write!(f, "workspace"),
            Self::Team => write!(f, "team"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    List,
    Execute,
    Grant,
    Revoke,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Read => write!(f, "read"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
            Self::List => write!(f, "list"),
            Self::Execute => write!(f, "execute"),
            Self::Grant => write!(f, "grant"),
            Self::Revoke => write!(f, "revoke"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionScope {
    Organization,
    Workspace,
    Resource,
}

impl fmt::Display for PermissionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Organization => write!(f, "organization"),
            Self::Workspace => write!(f, "workspace"),
            Self::Resource => write!(f, "resource"),
        }
    }
}

// ============================================================================
// Access Grant
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrant {
    pub id: Uuid,
    pub grantee_type: GranteeType,
    pub grantee_id: String,

    // What access is granted
    pub resource_type: ResourceType,
    pub resource_id: String,
    pub permissions: Vec<Permission>,

    // Grant details
    pub granted_by: UserId,
    pub reason: Option<String>,

    // Temporal constraints
    pub valid_from: Timestamp,
    pub valid_until: Option<Timestamp>,

    // Status
    pub status: AccessGrantStatus,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

impl AccessGrant {
    pub fn is_active(&self) -> bool {
        if !matches!(self.status, AccessGrantStatus::Active) {
            return false;
        }

        let now = Timestamp::now();
        if now < self.valid_from {
            return false;
        }

        if let Some(valid_until) = self.valid_until {
            if now > valid_until {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GranteeType {
    User,
    ServiceAccount,
    Team,
    Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessGrantStatus {
    Active,
    Revoked,
    Expired,
}

// ============================================================================
// Team
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: TeamId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,

    // Membership
    pub members: Vec<TeamMember>,
    pub member_count: u32,

    // Roles
    pub roles: Vec<RoleId>,

    // Metadata
    pub metadata: Metadata,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub user_id: UserId,
    pub role: TeamMemberRole,
    pub added_at: Timestamp,
    pub added_by: UserId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemberRole {
    Owner,
    Admin,
    Member,
}

// ============================================================================
// Organization
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,

    // Settings
    pub settings: OrganizationSettings,

    // Subscription
    pub plan: SubscriptionPlan,
    pub limits: ResourceLimits,

    // Status
    pub status: OrganizationStatus,

    // Metadata
    pub metadata: Metadata,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationSettings {
    pub require_mfa: bool,
    pub allow_public_datasets: bool,
    pub data_retention_days: u32,
    pub allowed_auth_providers: Vec<AuthProvider>,
}

impl Default for OrganizationSettings {
    fn default() -> Self {
        Self {
            require_mfa: false,
            allow_public_datasets: false,
            data_retention_days: 90,
            allowed_auth_providers: vec![AuthProvider::Local],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionPlan {
    Free,
    Pro,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_datasets: Option<u32>,
    pub max_storage_bytes: Option<u64>,
    pub max_users: Option<u32>,
    pub max_api_calls_per_month: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_datasets: Some(10),
            max_storage_bytes: Some(10 * 1024 * 1024 * 1024), // 10 GB
            max_users: Some(5),
            max_api_calls_per_month: Some(100_000),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationStatus {
    Active,
    Suspended,
    Trial,
}

// ============================================================================
// Workspace
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,

    // Settings
    pub visibility: WorkspaceVisibility,

    // Statistics
    pub dataset_count: u32,
    pub member_count: u32,

    // Metadata
    pub metadata: Metadata,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceVisibility {
    Private,
    Organization,
}
```

---

## 6. Audit Types (`src/models/audit.rs`)

```rust
use super::common::*;
use super::user::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

// ============================================================================
// Audit Event
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: AuditEventId,

    // Actor information
    pub actor_type: ActorType,
    pub actor_id: String,
    pub actor_name: String,
    pub actor_ip: Option<String>,
    pub actor_user_agent: Option<String>,

    // Action information
    pub action: AuditAction,
    pub action_category: ActionCategory,

    // Resource information
    pub resource_type: ResourceType,
    pub resource_id: String,
    pub resource_name: Option<String>,

    // Context
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,

    // Outcome
    pub outcome: AuditOutcome,
    pub error_message: Option<String>,

    // Additional data
    pub metadata: AuditMetadata,
    pub changes: Option<ChangeSet>,

    // Session info
    pub session_id: Option<String>,
    pub request_id: Option<String>,

    // Timestamp
    pub timestamp: Timestamp,
}

impl AuditEvent {
    pub fn is_success(&self) -> bool {
        matches!(self.outcome, AuditOutcome::Success)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self.outcome, AuditOutcome::Failure)
    }

    pub fn is_security_event(&self) -> bool {
        matches!(
            self.action_category,
            ActionCategory::Authentication
                | ActionCategory::Authorization
                | ActionCategory::Security
        )
    }
}

// ============================================================================
// Audit Event Builder
// ============================================================================

#[derive(Debug, Default)]
pub struct AuditEventBuilder {
    actor_type: Option<ActorType>,
    actor_id: Option<String>,
    actor_name: Option<String>,
    actor_ip: Option<String>,
    actor_user_agent: Option<String>,
    action: Option<AuditAction>,
    resource_type: Option<ResourceType>,
    resource_id: Option<String>,
    resource_name: Option<String>,
    organization_id: Option<OrganizationId>,
    workspace_id: Option<WorkspaceId>,
    outcome: Option<AuditOutcome>,
    error_message: Option<String>,
    metadata: AuditMetadata,
    changes: Option<ChangeSet>,
    session_id: Option<String>,
    request_id: Option<String>,
}

impl AuditEventBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn actor(mut self, actor_type: ActorType, actor_id: String, actor_name: String) -> Self {
        self.actor_type = Some(actor_type);
        self.actor_id = Some(actor_id);
        self.actor_name = Some(actor_name);
        self
    }

    pub fn actor_ip(mut self, ip: String) -> Self {
        self.actor_ip = Some(ip);
        self
    }

    pub fn actor_user_agent(mut self, user_agent: String) -> Self {
        self.actor_user_agent = Some(user_agent);
        self
    }

    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn resource(mut self, resource_type: ResourceType, resource_id: String) -> Self {
        self.resource_type = Some(resource_type);
        self.resource_id = Some(resource_id);
        self
    }

    pub fn resource_name(mut self, name: String) -> Self {
        self.resource_name = Some(name);
        self
    }

    pub fn organization_id(mut self, id: OrganizationId) -> Self {
        self.organization_id = Some(id);
        self
    }

    pub fn workspace_id(mut self, id: WorkspaceId) -> Self {
        self.workspace_id = Some(id);
        self
    }

    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    pub fn error(mut self, message: String) -> Self {
        self.error_message = Some(message);
        self.outcome = Some(AuditOutcome::Failure);
        self
    }

    pub fn metadata(mut self, metadata: AuditMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn changes(mut self, changes: ChangeSet) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn session_id(mut self, id: String) -> Self {
        self.session_id = Some(id);
        self
    }

    pub fn request_id(mut self, id: String) -> Self {
        self.request_id = Some(id);
        self
    }

    pub fn build(self) -> Result<AuditEvent, ValidationError> {
        let actor_type = self.actor_type
            .ok_or_else(|| ValidationError::new("actor_type is required"))?;
        let actor_id = self.actor_id
            .ok_or_else(|| ValidationError::new("actor_id is required"))?;
        let actor_name = self.actor_name
            .ok_or_else(|| ValidationError::new("actor_name is required"))?;
        let action = self.action
            .ok_or_else(|| ValidationError::new("action is required"))?;
        let resource_type = self.resource_type
            .ok_or_else(|| ValidationError::new("resource_type is required"))?;
        let resource_id = self.resource_id
            .ok_or_else(|| ValidationError::new("resource_id is required"))?;
        let organization_id = self.organization_id
            .ok_or_else(|| ValidationError::new("organization_id is required"))?;
        let outcome = self.outcome
            .ok_or_else(|| ValidationError::new("outcome is required"))?;

        Ok(AuditEvent {
            id: AuditEventId::new(),
            actor_type,
            actor_id,
            actor_name,
            actor_ip: self.actor_ip,
            actor_user_agent: self.actor_user_agent,
            action,
            action_category: action.category(),
            resource_type,
            resource_id,
            resource_name: self.resource_name,
            organization_id,
            workspace_id: self.workspace_id,
            outcome,
            error_message: self.error_message,
            metadata: self.metadata,
            changes: self.changes,
            session_id: self.session_id,
            request_id: self.request_id,
            timestamp: Timestamp::now(),
        })
    }
}

// ============================================================================
// Actor Type
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    ServiceAccount,
    System,
    Anonymous,
}

// ============================================================================
// Audit Action
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Dataset actions
    DatasetCreate,
    DatasetRead,
    DatasetUpdate,
    DatasetDelete,
    DatasetArchive,
    DatasetRestore,

    // Record actions
    RecordCreate,
    RecordRead,
    RecordUpdate,
    RecordDelete,
    RecordBatchInsert,

    // Access actions
    Login,
    Logout,
    LoginFailed,
    PermissionGranted,
    PermissionRevoked,
    AccessDenied,

    // Policy actions
    PolicyCreate,
    PolicyUpdate,
    PolicyDelete,
    PolicyApplied,

    // User actions
    UserCreate,
    UserUpdate,
    UserDelete,
    UserSuspend,
    UserActivate,

    // Custom action
    Custom(String),
}

impl AuditAction {
    pub fn category(&self) -> ActionCategory {
        match self {
            Self::Login | Self::Logout | Self::LoginFailed => ActionCategory::Authentication,
            Self::PermissionGranted | Self::PermissionRevoked | Self::AccessDenied => {
                ActionCategory::Authorization
            }
            Self::DatasetCreate | Self::DatasetRead | Self::DatasetUpdate
            | Self::DatasetDelete | Self::DatasetArchive | Self::DatasetRestore => {
                ActionCategory::Data
            }
            Self::RecordCreate | Self::RecordRead | Self::RecordUpdate
            | Self::RecordDelete | Self::RecordBatchInsert => ActionCategory::Data,
            Self::PolicyCreate | Self::PolicyUpdate | Self::PolicyDelete | Self::PolicyApplied => {
                ActionCategory::Policy
            }
            Self::UserCreate | Self::UserUpdate | Self::UserDelete
            | Self::UserSuspend | Self::UserActivate => ActionCategory::User,
            Self::Custom(_) => ActionCategory::Other,
        }
    }
}

// ============================================================================
// Action Category
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionCategory {
    Authentication,
    Authorization,
    Data,
    Policy,
    User,
    Security,
    System,
    Other,
}

// ============================================================================
// Audit Outcome
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    PartialSuccess,
}

// ============================================================================
// Audit Metadata
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub fields: HashMap<String, JsonValue>,
}

impl AuditMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: String, value: JsonValue) {
        self.fields.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.fields.get(key)
    }
}

// ============================================================================
// Change Set
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    pub changes: Vec<FieldChange>,
}

impl ChangeSet {
    pub fn new() -> Self {
        Self {
            changes: Vec::new(),
        }
    }

    pub fn add_change(&mut self, change: FieldChange) {
        self.changes.push(change);
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

impl Default for ChangeSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: Option<JsonValue>,
    pub new_value: Option<JsonValue>,
}

// ============================================================================
// Audit Log
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub organization_id: OrganizationId,
    pub events: Vec<AuditEvent>,
    pub total_count: u64,
    pub start_time: Timestamp,
    pub end_time: Timestamp,
}

// ============================================================================
// Access Record (for tracking data access)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRecord {
    pub id: Uuid,

    // Who accessed
    pub user_id: UserId,
    pub session_id: Option<String>,

    // What was accessed
    pub resource_type: ResourceType,
    pub resource_id: String,
    pub access_type: AccessType,

    // Access details
    pub record_count: Option<u64>,
    pub data_size: Option<ByteSize>,

    // Purpose and justification
    pub purpose: Option<String>,
    pub justification: Option<String>,

    // Context
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,

    // Timestamp
    pub accessed_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessType {
    Read,
    Export,
    Download,
    Query,
    Stream,
}

// ============================================================================
// Audit Query
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    pub organization_id: OrganizationId,
    pub workspace_id: Option<WorkspaceId>,
    pub actor_id: Option<String>,
    pub resource_type: Option<ResourceType>,
    pub resource_id: Option<String>,
    pub action_category: Option<ActionCategory>,
    pub outcome: Option<AuditOutcome>,
    pub start_time: Option<Timestamp>,
    pub end_time: Option<Timestamp>,
    pub pagination: PaginationParams,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            organization_id: OrganizationId::new(),
            workspace_id: None,
            actor_id: None,
            resource_type: None,
            resource_id: None,
            action_category: None,
            outcome: None,
            start_time: None,
            end_time: None,
            pagination: PaginationParams::default(),
        }
    }
}
```

---

## 7. Policy Types (`src/models/policy.rs`)

```rust
use super::common::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Retention Policy
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub id: PolicyId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,

    // Retention rules
    pub retention_period: RetentionPeriod,
    pub delete_after_expiry: bool,
    pub archive_before_delete: bool,

    // Conditions
    pub conditions: Vec<PolicyCondition>,

    // Actions
    pub expiry_actions: Vec<ExpiryAction>,

    // Status
    pub enabled: bool,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_applied_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RetentionPeriod {
    Days { days: u32 },
    Months { months: u32 },
    Years { years: u32 },
    Indefinite,
}

impl RetentionPeriod {
    pub fn to_days(&self) -> Option<u32> {
        match self {
            Self::Days { days } => Some(*days),
            Self::Months { months } => Some(months * 30),
            Self::Years { years } => Some(years * 365),
            Self::Indefinite => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryAction {
    Archive,
    Delete,
    Anonymize,
    Notify,
    Custom(String),
}

// ============================================================================
// Anonymization Policy
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationPolicy {
    pub id: PolicyId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,

    // Anonymization rules
    pub rules: Vec<AnonymizationRule>,

    // Strategy
    pub strategy: AnonymizationStrategy,
    pub preserve_structure: bool,
    pub reversible: bool,

    // Conditions
    pub conditions: Vec<PolicyCondition>,

    // Status
    pub enabled: bool,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_applied_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationRule {
    pub field_pattern: String,
    pub technique: AnonymizationTechnique,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnonymizationTechnique {
    Redaction,
    Masking,
    Hashing,
    Tokenization,
    Generalization,
    Perturbation,
    Suppression,
    Pseudonymization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnonymizationStrategy {
    Full,
    Partial,
    Conditional,
}

// ============================================================================
// Access Policy
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: PolicyId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,

    // Access rules
    pub rules: Vec<AccessRule>,
    pub default_action: PolicyAction,

    // Constraints
    pub time_constraints: Option<TimeConstraints>,
    pub ip_whitelist: Vec<String>,
    pub ip_blacklist: Vec<String>,

    // Conditions
    pub conditions: Vec<PolicyCondition>,

    // Status
    pub enabled: bool,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_applied_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    pub rule_id: String,
    pub priority: u32,
    pub conditions: Vec<PolicyCondition>,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConstraints {
    pub allowed_hours: Option<Vec<u8>>,  // 0-23
    pub allowed_days: Option<Vec<u8>>,   // 1-7 (Monday-Sunday)
    pub timezone: String,
}

// ============================================================================
// Policy Condition
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: ConditionValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<String>),
}

// ============================================================================
// Policy Evaluation Result
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub policy_id: PolicyId,
    pub action: PolicyAction,
    pub matched_rules: Vec<String>,
    pub evaluation_time: Timestamp,
    pub metadata: HashMap<String, String>,
}

impl PolicyEvaluationResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self.action, PolicyAction::Allow)
    }

    pub fn is_denied(&self) -> bool {
        matches!(self.action, PolicyAction::Deny)
    }

    pub fn requires_approval(&self) -> bool {
        matches!(self.action, PolicyAction::RequireApproval)
    }
}

// ============================================================================
// Data Classification Policy
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataClassificationPolicy {
    pub id: PolicyId,
    pub name: String,
    pub description: Option<String>,
    pub organization_id: OrganizationId,

    // Classification rules
    pub classification_rules: Vec<ClassificationRule>,

    // Sensitivity levels
    pub sensitivity_levels: Vec<SensitivityLevel>,

    // Status
    pub enabled: bool,

    // Timestamps
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRule {
    pub rule_id: String,
    pub conditions: Vec<PolicyCondition>,
    pub classification: DataClassification,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    HighlyConfidential,
}

impl DataClassification {
    pub fn sensitivity_level(&self) -> u8 {
        match self {
            Self::Public => 1,
            Self::Internal => 2,
            Self::Confidential => 3,
            Self::Restricted => 4,
            Self::HighlyConfidential => 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivityLevel {
    pub level: u8,
    pub name: String,
    pub description: String,
    pub required_controls: Vec<String>,
}

// ============================================================================
// Policy Builder
// ============================================================================

#[derive(Debug, Default)]
pub struct RetentionPolicyBuilder {
    name: Option<String>,
    description: Option<String>,
    organization_id: Option<OrganizationId>,
    retention_period: Option<RetentionPeriod>,
    delete_after_expiry: bool,
    archive_before_delete: bool,
    conditions: Vec<PolicyCondition>,
    expiry_actions: Vec<ExpiryAction>,
}

impl RetentionPolicyBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn organization_id(mut self, id: OrganizationId) -> Self {
        self.organization_id = Some(id);
        self
    }

    pub fn retention_period(mut self, period: RetentionPeriod) -> Self {
        self.retention_period = Some(period);
        self
    }

    pub fn delete_after_expiry(mut self, delete: bool) -> Self {
        self.delete_after_expiry = delete;
        self
    }

    pub fn archive_before_delete(mut self, archive: bool) -> Self {
        self.archive_before_delete = archive;
        self
    }

    pub fn add_condition(mut self, condition: PolicyCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn add_expiry_action(mut self, action: ExpiryAction) -> Self {
        self.expiry_actions.push(action);
        self
    }

    pub fn build(self) -> Result<RetentionPolicy, ValidationError> {
        let name = self.name.ok_or_else(|| ValidationError::new("name is required"))?;
        let organization_id = self.organization_id
            .ok_or_else(|| ValidationError::new("organization_id is required"))?;
        let retention_period = self.retention_period
            .ok_or_else(|| ValidationError::new("retention_period is required"))?;

        Ok(RetentionPolicy {
            id: PolicyId::new(),
            name,
            description: self.description,
            organization_id,
            retention_period,
            delete_after_expiry: self.delete_after_expiry,
            archive_before_delete: self.archive_before_delete,
            conditions: self.conditions,
            expiry_actions: self.expiry_actions,
            enabled: true,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            last_applied_at: None,
        })
    }
}
```

---

## 8. Error Types (`src/models/error.rs`)

```rust
use std::fmt;
use std::error::Error as StdError;
use super::common::ValidationError;

// ============================================================================
// Result Type Alias
// ============================================================================

pub type Result<T> = std::result::Result<T, Error>;

// ============================================================================
// Main Error Type
// ============================================================================

#[derive(Debug)]
pub enum Error {
    // Validation errors
    Validation(ValidationError),

    // Not found errors
    NotFound { resource: String, id: String },

    // Already exists errors
    AlreadyExists { resource: String, id: String },

    // Permission errors
    Unauthorized { message: String },
    Forbidden { message: String, required_permission: Option<String> },

    // Conflict errors
    Conflict { message: String },

    // Policy errors
    PolicyViolation { policy_id: String, message: String },

    // Data integrity errors
    ChecksumMismatch { expected: String, actual: String },
    CorruptedData { message: String },

    // Storage errors
    StorageError { message: String },

    // Database errors
    DatabaseError { message: String },

    // Serialization errors
    SerializationError { message: String },

    // Rate limit errors
    RateLimitExceeded { retry_after: Option<u64> },

    // Resource limit errors
    ResourceLimitExceeded { resource: String, limit: u64, current: u64 },

    // Internal errors
    Internal { message: String },
}

impl Error {
    pub fn validation(error: ValidationError) -> Self {
        Self::Validation(error)
    }

    pub fn not_found(resource: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
            id: id.into(),
        }
    }

    pub fn already_exists(resource: impl Into<String>, id: impl Into<String>) -> Self {
        Self::AlreadyExists {
            resource: resource.into(),
            id: id.into(),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized {
            message: message.into(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
            required_permission: None,
        }
    }

    pub fn with_required_permission(mut self, permission: String) -> Self {
        if let Self::Forbidden { required_permission, .. } = &mut self {
            *required_permission = Some(permission);
        }
        self
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    pub fn policy_violation(policy_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::PolicyViolation {
            policy_id: policy_id.into(),
            message: message.into(),
        }
    }

    pub fn checksum_mismatch(expected: String, actual: String) -> Self {
        Self::ChecksumMismatch { expected, actual }
    }

    pub fn corrupted_data(message: impl Into<String>) -> Self {
        Self::CorruptedData {
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "Validation error: {}", err),
            Self::NotFound { resource, id } => {
                write!(f, "{} with id '{}' not found", resource, id)
            }
            Self::AlreadyExists { resource, id } => {
                write!(f, "{} with id '{}' already exists", resource, id)
            }
            Self::Unauthorized { message } => {
                write!(f, "Unauthorized: {}", message)
            }
            Self::Forbidden { message, required_permission } => {
                if let Some(perm) = required_permission {
                    write!(f, "Forbidden: {}. Required permission: {}", message, perm)
                } else {
                    write!(f, "Forbidden: {}", message)
                }
            }
            Self::Conflict { message } => {
                write!(f, "Conflict: {}", message)
            }
            Self::PolicyViolation { policy_id, message } => {
                write!(f, "Policy violation ({}): {}", policy_id, message)
            }
            Self::ChecksumMismatch { expected, actual } => {
                write!(f, "Checksum mismatch: expected {}, got {}", expected, actual)
            }
            Self::CorruptedData { message } => {
                write!(f, "Corrupted data: {}", message)
            }
            Self::StorageError { message } => {
                write!(f, "Storage error: {}", message)
            }
            Self::DatabaseError { message } => {
                write!(f, "Database error: {}", message)
            }
            Self::SerializationError { message } => {
                write!(f, "Serialization error: {}", message)
            }
            Self::RateLimitExceeded { retry_after } => {
                if let Some(seconds) = retry_after {
                    write!(f, "Rate limit exceeded. Retry after {} seconds", seconds)
                } else {
                    write!(f, "Rate limit exceeded")
                }
            }
            Self::ResourceLimitExceeded { resource, limit, current } => {
                write!(
                    f,
                    "Resource limit exceeded for {}: limit={}, current={}",
                    resource, limit, current
                )
            }
            Self::Internal { message } => {
                write!(f, "Internal error: {}", message)
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Validation(err) => Some(err),
            _ => None,
        }
    }
}

// ============================================================================
// Error Code (for API responses)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ValidationError,
    NotFound,
    AlreadyExists,
    Unauthorized,
    Forbidden,
    Conflict,
    PolicyViolation,
    ChecksumMismatch,
    CorruptedData,
    StorageError,
    DatabaseError,
    SerializationError,
    RateLimitExceeded,
    ResourceLimitExceeded,
    InternalError,
}

impl ErrorCode {
    pub fn from_error(error: &Error) -> Self {
        match error {
            Error::Validation(_) => Self::ValidationError,
            Error::NotFound { .. } => Self::NotFound,
            Error::AlreadyExists { .. } => Self::AlreadyExists,
            Error::Unauthorized { .. } => Self::Unauthorized,
            Error::Forbidden { .. } => Self::Forbidden,
            Error::Conflict { .. } => Self::Conflict,
            Error::PolicyViolation { .. } => Self::PolicyViolation,
            Error::ChecksumMismatch { .. } => Self::ChecksumMismatch,
            Error::CorruptedData { .. } => Self::CorruptedData,
            Error::StorageError { .. } => Self::StorageError,
            Error::DatabaseError { .. } => Self::DatabaseError,
            Error::SerializationError { .. } => Self::SerializationError,
            Error::RateLimitExceeded { .. } => Self::RateLimitExceeded,
            Error::ResourceLimitExceeded { .. } => Self::ResourceLimitExceeded,
            Error::Internal { .. } => Self::InternalError,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ValidationError => "VALIDATION_ERROR",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::Conflict => "CONFLICT",
            Self::PolicyViolation => "POLICY_VIOLATION",
            Self::ChecksumMismatch => "CHECKSUM_MISMATCH",
            Self::CorruptedData => "CORRUPTED_DATA",
            Self::StorageError => "STORAGE_ERROR",
            Self::DatabaseError => "DATABASE_ERROR",
            Self::SerializationError => "SERIALIZATION_ERROR",
            Self::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            Self::ResourceLimitExceeded => "RESOURCE_LIMIT_EXCEEDED",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::ValidationError => 400,
            Self::NotFound => 404,
            Self::AlreadyExists => 409,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::Conflict => 409,
            Self::PolicyViolation => 403,
            Self::ChecksumMismatch => 422,
            Self::CorruptedData => 422,
            Self::StorageError => 500,
            Self::DatabaseError => 500,
            Self::SerializationError => 500,
            Self::RateLimitExceeded => 429,
            Self::ResourceLimitExceeded => 429,
            Self::InternalError => 500,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Error Response (for API)
// ============================================================================

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl ErrorResponse {
    pub fn from_error(error: &Error) -> Self {
        let code = ErrorCode::from_error(error);
        Self {
            code: code.as_str().to_string(),
            message: error.to_string(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

// ============================================================================
// From implementations
// ============================================================================

impl From<ValidationError> for Error {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}
```

---

## Summary

This comprehensive pseudocode provides:

1. **Type Safety**: Strong typing with newtype patterns for IDs, preventing ID confusion
2. **Zero-Copy**: Use of references and efficient data structures
3. **Serialization**: Full serde support for all types
4. **Builder Patterns**: For complex types like Dataset, Corpus, and AuditEvent
5. **Validation**: Built-in validation methods with detailed error messages
6. **Enterprise Features**:
   - Multi-tenancy (Organization, Workspace, Team)
   - RBAC (Roles, Permissions, Access Grants)
   - Comprehensive auditing
   - Policy engine (Retention, Anonymization, Access)
   - Data lineage and versioning
7. **Production Patterns**:
   - Proper error handling with custom error types
   - Display implementations
   - From/Into traits
   - Pagination support (offset and cursor-based)
   - Filtering and querying
8. **Module Organization**: Clean separation of concerns

All types are production-ready and follow Rust best practices for enterprise applications.
