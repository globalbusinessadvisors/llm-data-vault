//! Dataset entity and related types.

use crate::{
    DatasetId, KeyId, Metadata, SchemaId, TenantId, UserId, VersionId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A dataset is a collection of records with versioning and access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Unique identifier.
    pub id: DatasetId,

    /// Tenant this dataset belongs to.
    pub tenant_id: TenantId,

    /// Human-readable name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Optional schema reference.
    pub schema_id: Option<SchemaId>,

    /// Current (HEAD) version.
    pub current_version: VersionId,

    /// Status of the dataset.
    pub status: DatasetStatus,

    /// Tags for categorization.
    pub tags: Vec<Tag>,

    /// Custom metadata.
    pub metadata: Metadata,

    /// Encryption key used for this dataset.
    pub encryption_key_id: KeyId,

    /// Retention policy.
    pub retention_policy: Option<RetentionPolicy>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,

    /// User who created the dataset.
    pub created_by: UserId,

    /// User who last modified the dataset.
    pub updated_by: UserId,
}

impl Dataset {
    /// Creates a new dataset builder.
    #[must_use]
    pub fn builder() -> DatasetBuilder {
        DatasetBuilder::default()
    }

    /// Returns true if the dataset is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, DatasetStatus::Active)
    }

    /// Returns true if the dataset is archived.
    #[must_use]
    pub const fn is_archived(&self) -> bool {
        matches!(self.status, DatasetStatus::Archived)
    }

    /// Checks if the dataset has a specific tag.
    #[must_use]
    pub fn has_tag(&self, name: &str) -> bool {
        self.tags.iter().any(|t| t.name == name)
    }
}

/// Builder for creating datasets.
#[derive(Debug, Default)]
pub struct DatasetBuilder {
    tenant_id: Option<TenantId>,
    name: Option<String>,
    description: Option<String>,
    schema_id: Option<SchemaId>,
    tags: Vec<Tag>,
    metadata: HashMap<String, serde_json::Value>,
    encryption_key_id: Option<KeyId>,
    retention_policy: Option<RetentionPolicy>,
    created_by: Option<UserId>,
}

impl DatasetBuilder {
    /// Sets the tenant ID.
    #[must_use]
    pub fn tenant_id(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Sets the name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the schema ID.
    #[must_use]
    pub fn schema_id(mut self, schema_id: SchemaId) -> Self {
        self.schema_id = Some(schema_id);
        self
    }

    /// Adds a tag.
    #[must_use]
    pub fn tag(mut self, tag: Tag) -> Self {
        self.tags.push(tag);
        self
    }

    /// Adds multiple tags.
    #[must_use]
    pub fn tags(mut self, tags: impl IntoIterator<Item = Tag>) -> Self {
        self.tags.extend(tags);
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Sets the encryption key ID.
    #[must_use]
    pub fn encryption_key_id(mut self, key_id: KeyId) -> Self {
        self.encryption_key_id = Some(key_id);
        self
    }

    /// Sets the retention policy.
    #[must_use]
    pub fn retention_policy(mut self, policy: RetentionPolicy) -> Self {
        self.retention_policy = Some(policy);
        self
    }

    /// Sets the creator.
    #[must_use]
    pub fn created_by(mut self, user_id: UserId) -> Self {
        self.created_by = Some(user_id);
        self
    }

    /// Builds the dataset.
    ///
    /// # Panics
    /// Panics if required fields are not set.
    #[must_use]
    pub fn build(self) -> Dataset {
        let now = Utc::now();
        let id = DatasetId::new();
        let version_id = VersionId::new();
        let user_id = self.created_by.unwrap_or_else(UserId::new);

        Dataset {
            id,
            tenant_id: self.tenant_id.expect("tenant_id is required"),
            name: self.name.expect("name is required"),
            description: self.description,
            schema_id: self.schema_id,
            current_version: version_id,
            status: DatasetStatus::Active,
            tags: self.tags,
            metadata: Metadata::new(self.metadata),
            encryption_key_id: self.encryption_key_id.expect("encryption_key_id is required"),
            retention_policy: self.retention_policy,
            created_at: now,
            updated_at: now,
            created_by: user_id,
            updated_by: user_id,
        }
    }
}

/// Status of a dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatasetStatus {
    /// Dataset is active and accessible.
    Active,
    /// Dataset is archived (read-only).
    Archived,
    /// Dataset is being deleted.
    Deleting,
    /// Dataset is in an error state.
    Error,
    /// Dataset is locked (e.g., for maintenance).
    Locked,
}

impl Default for DatasetStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// A tag for categorizing resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    /// Tag name (key).
    pub name: String,
    /// Optional tag value.
    pub value: Option<String>,
}

impl Tag {
    /// Creates a new tag with just a name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: None,
        }
    }

    /// Creates a new tag with name and value.
    #[must_use]
    pub fn with_value(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
        }
    }
}

impl From<&str> for Tag {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for Tag {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// Retention policy for a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Number of days to retain data.
    pub retention_days: u32,

    /// Whether to automatically delete after retention period.
    pub auto_delete: bool,

    /// Whether to archive before deletion.
    pub archive_before_delete: bool,

    /// Legal hold (prevents deletion).
    pub legal_hold: bool,

    /// Compliance framework requirements.
    pub compliance_frameworks: Vec<String>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retention_days: 365,
            auto_delete: false,
            archive_before_delete: true,
            legal_hold: false,
            compliance_frameworks: Vec::new(),
        }
    }
}

/// Statistics about a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetStats {
    /// Total number of records.
    pub record_count: u64,

    /// Total size in bytes.
    pub size_bytes: u64,

    /// Number of versions.
    pub version_count: u32,

    /// Last access time.
    pub last_accessed: Option<DateTime<Utc>>,

    /// Number of queries in the last 24 hours.
    pub queries_24h: u64,
}

impl Default for DatasetStats {
    fn default() -> Self {
        Self {
            record_count: 0,
            size_bytes: 0,
            version_count: 1,
            last_accessed: None,
            queries_24h: 0,
        }
    }
}

/// Summary of a dataset for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSummary {
    /// Dataset ID.
    pub id: DatasetId,
    /// Dataset name.
    pub name: String,
    /// Dataset status.
    pub status: DatasetStatus,
    /// Tags.
    pub tags: Vec<Tag>,
    /// Record count.
    pub record_count: u64,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_builder() {
        let tenant_id = TenantId::new();
        let key_id = KeyId::new();
        let user_id = UserId::new();

        let dataset = Dataset::builder()
            .tenant_id(tenant_id)
            .name("test-dataset")
            .description("A test dataset")
            .tag(Tag::new("environment"))
            .tag(Tag::with_value("team", "ml"))
            .encryption_key_id(key_id)
            .created_by(user_id)
            .build();

        assert_eq!(dataset.name, "test-dataset");
        assert_eq!(dataset.tags.len(), 2);
        assert!(dataset.is_active());
    }

    #[test]
    fn test_dataset_has_tag() {
        let tenant_id = TenantId::new();
        let key_id = KeyId::new();

        let dataset = Dataset::builder()
            .tenant_id(tenant_id)
            .name("test")
            .tag(Tag::new("production"))
            .encryption_key_id(key_id)
            .build();

        assert!(dataset.has_tag("production"));
        assert!(!dataset.has_tag("development"));
    }
}
