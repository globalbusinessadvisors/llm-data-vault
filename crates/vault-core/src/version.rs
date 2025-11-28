//! Version control types for datasets.

use crate::{ContentHash, DatasetId, UserId, VersionId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A version of a dataset (like a Git commit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    /// Unique version identifier.
    pub id: VersionId,

    /// Dataset this version belongs to.
    pub dataset_id: DatasetId,

    /// Sequential version number (1, 2, 3, ...).
    pub version_number: u32,

    /// Content hash of the version tree.
    pub tree_hash: ContentHash,

    /// Parent version(s) - usually one, but can be multiple for merges.
    pub parents: Vec<VersionId>,

    /// Human-readable description.
    pub description: Option<String>,

    /// Summary of changes.
    pub change_summary: String,

    /// Version tags (e.g., "production", "v1.0.0").
    pub tags: Vec<String>,

    /// Custom metadata.
    pub metadata: HashMap<String, serde_json::Value>,

    /// Statistics about this version.
    pub stats: VersionStats,

    /// Author of this version.
    pub author: VersionAuthor,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl Version {
    /// Creates a new version builder.
    #[must_use]
    pub fn builder() -> VersionBuilder {
        VersionBuilder::default()
    }

    /// Returns true if this is the initial version (no parents).
    #[must_use]
    pub fn is_initial(&self) -> bool {
        self.parents.is_empty()
    }

    /// Returns true if this is a merge commit (multiple parents).
    #[must_use]
    pub fn is_merge(&self) -> bool {
        self.parents.len() > 1
    }

    /// Returns true if this version has a specific tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

/// Builder for versions.
#[derive(Debug, Default)]
pub struct VersionBuilder {
    dataset_id: Option<DatasetId>,
    version_number: Option<u32>,
    tree_hash: Option<ContentHash>,
    parents: Vec<VersionId>,
    description: Option<String>,
    change_summary: Option<String>,
    tags: Vec<String>,
    metadata: HashMap<String, serde_json::Value>,
    author: Option<VersionAuthor>,
}

impl VersionBuilder {
    /// Sets the dataset ID.
    #[must_use]
    pub fn dataset_id(mut self, id: DatasetId) -> Self {
        self.dataset_id = Some(id);
        self
    }

    /// Sets the version number.
    #[must_use]
    pub fn version_number(mut self, number: u32) -> Self {
        self.version_number = Some(number);
        self
    }

    /// Sets the tree hash.
    #[must_use]
    pub fn tree_hash(mut self, hash: ContentHash) -> Self {
        self.tree_hash = Some(hash);
        self
    }

    /// Sets the parent version.
    #[must_use]
    pub fn parent(mut self, parent: VersionId) -> Self {
        self.parents.push(parent);
        self
    }

    /// Sets multiple parent versions.
    #[must_use]
    pub fn parents(mut self, parents: Vec<VersionId>) -> Self {
        self.parents = parents;
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets the change summary.
    #[must_use]
    pub fn change_summary(mut self, summary: impl Into<String>) -> Self {
        self.change_summary = Some(summary.into());
        self
    }

    /// Adds a tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Sets the author.
    #[must_use]
    pub fn author(mut self, author: VersionAuthor) -> Self {
        self.author = Some(author);
        self
    }

    /// Builds the version.
    #[must_use]
    pub fn build(self) -> Version {
        Version {
            id: VersionId::new(),
            dataset_id: self.dataset_id.expect("dataset_id is required"),
            version_number: self.version_number.expect("version_number is required"),
            tree_hash: self.tree_hash.expect("tree_hash is required"),
            parents: self.parents,
            description: self.description,
            change_summary: self.change_summary.unwrap_or_else(|| "No summary".to_string()),
            tags: self.tags,
            metadata: self.metadata,
            stats: VersionStats::default(),
            author: self.author.expect("author is required"),
            created_at: Utc::now(),
        }
    }
}

/// Author information for a version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionAuthor {
    /// User ID.
    pub user_id: UserId,
    /// User name.
    pub name: String,
    /// User email.
    pub email: Option<String>,
}

impl VersionAuthor {
    /// Creates a new author.
    #[must_use]
    pub fn new(user_id: UserId, name: impl Into<String>) -> Self {
        Self {
            user_id,
            name: name.into(),
            email: None,
        }
    }

    /// Creates a new author with email.
    #[must_use]
    pub fn with_email(user_id: UserId, name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            user_id,
            name: name.into(),
            email: Some(email.into()),
        }
    }
}

/// Statistics about a version.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionStats {
    /// Total number of records.
    pub record_count: u64,
    /// Total size in bytes.
    pub size_bytes: u64,
    /// Number of records added since parent.
    pub records_added: u64,
    /// Number of records modified since parent.
    pub records_modified: u64,
    /// Number of records deleted since parent.
    pub records_deleted: u64,
}

/// Difference between two versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDiff {
    /// Source version.
    pub from_version: VersionId,
    /// Target version.
    pub to_version: VersionId,
    /// Added records.
    pub added: Vec<DiffEntry>,
    /// Modified records.
    pub modified: Vec<DiffEntry>,
    /// Deleted records.
    pub deleted: Vec<DiffEntry>,
    /// Statistics.
    pub stats: DiffStats,
}

/// An entry in a diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Record identifier or path.
    pub path: String,
    /// Content hash before change (None if added).
    pub old_hash: Option<ContentHash>,
    /// Content hash after change (None if deleted).
    pub new_hash: Option<ContentHash>,
    /// Type of change.
    pub change_type: ChangeType,
}

/// Type of change in a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    /// Record was added.
    Added,
    /// Record was modified.
    Modified,
    /// Record was deleted.
    Deleted,
    /// Record was renamed.
    Renamed,
}

/// Statistics for a diff.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffStats {
    /// Number of additions.
    pub additions: u64,
    /// Number of modifications.
    pub modifications: u64,
    /// Number of deletions.
    pub deletions: u64,
    /// Bytes added.
    pub bytes_added: u64,
    /// Bytes removed.
    pub bytes_removed: u64,
}

/// A branch pointing to a version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    /// Branch name.
    pub name: String,
    /// Dataset this branch belongs to.
    pub dataset_id: DatasetId,
    /// Current HEAD version.
    pub head: VersionId,
    /// Whether this is the default branch.
    pub is_default: bool,
    /// Protection rules.
    pub protection: Option<BranchProtection>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Branch protection rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchProtection {
    /// Require reviews before merge.
    pub require_reviews: bool,
    /// Minimum number of reviews.
    pub required_reviews: u32,
    /// Allowed merge strategies.
    pub allowed_merge_strategies: Vec<MergeStrategy>,
    /// Users who can bypass protection.
    pub bypass_users: Vec<UserId>,
}

/// Merge strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /// Create a merge commit.
    Merge,
    /// Fast-forward if possible.
    FastForward,
    /// Squash all commits.
    Squash,
    /// Rebase commits.
    Rebase,
}

impl Default for MergeStrategy {
    fn default() -> Self {
        Self::Merge
    }
}

/// A tag pointing to a specific version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionTag {
    /// Tag name.
    pub name: String,
    /// Dataset this tag belongs to.
    pub dataset_id: DatasetId,
    /// Tagged version.
    pub version_id: VersionId,
    /// Tag message/description.
    pub message: Option<String>,
    /// Tagger information.
    pub tagger: VersionAuthor,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashAlgorithm;

    #[test]
    fn test_version_builder() {
        let dataset_id = DatasetId::new();
        let user_id = UserId::new();

        let version = Version::builder()
            .dataset_id(dataset_id)
            .version_number(1)
            .tree_hash(ContentHash::new(HashAlgorithm::Blake3, "test".to_string()))
            .change_summary("Initial version")
            .author(VersionAuthor::new(user_id, "Test User"))
            .build();

        assert!(version.is_initial());
        assert!(!version.is_merge());
        assert_eq!(version.version_number, 1);
    }

    #[test]
    fn test_version_with_parent() {
        let dataset_id = DatasetId::new();
        let parent_id = VersionId::new();
        let user_id = UserId::new();

        let version = Version::builder()
            .dataset_id(dataset_id)
            .version_number(2)
            .tree_hash(ContentHash::new(HashAlgorithm::Blake3, "test".to_string()))
            .parent(parent_id)
            .change_summary("Second version")
            .author(VersionAuthor::new(user_id, "Test User"))
            .build();

        assert!(!version.is_initial());
        assert!(!version.is_merge());
        assert_eq!(version.parents.len(), 1);
    }
}
