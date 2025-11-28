//! Commit objects.

use crate::{VersionError, VersionResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Commit identifier (content hash).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitId(String);

impl CommitId {
    /// Creates from a hash string.
    pub fn from_hash(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    /// Computes commit ID from content.
    pub fn from_content(content: &[u8]) -> Self {
        Self(blake3::hash(content).to_hex().to_string())
    }

    /// Returns the hash string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the short form (first 7 chars).
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..7.min(self.0.len())]
    }
}

impl std::fmt::Display for CommitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CommitId {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 7 {
            return Err(VersionError::InvalidRef(format!(
                "Commit ID too short: {}",
                s
            )));
        }
        // Validate hex
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VersionError::InvalidRef(format!(
                "Invalid commit ID format: {}",
                s
            )));
        }
        Ok(Self(s.to_string()))
    }
}

/// Commit author information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    /// Author name.
    pub name: String,
    /// Author email.
    pub email: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Author {
    /// Creates a new author.
    pub fn new(name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Creates with specific timestamp.
    pub fn at(
        name: impl Into<String>,
        email: impl Into<String>,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            timestamp,
        }
    }
}

impl std::fmt::Display for Author {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <{}>", self.name, self.email)
    }
}

/// A commit object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Commit ID (computed on creation).
    #[serde(skip)]
    id: Option<CommitId>,
    /// Tree hash (root of the snapshot).
    pub tree: String,
    /// Parent commit IDs.
    pub parents: Vec<CommitId>,
    /// Author.
    pub author: Author,
    /// Committer (may differ from author).
    pub committer: Author,
    /// Commit message.
    pub message: String,
    /// Commit timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Dataset ID this commit belongs to.
    pub dataset_id: String,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl Commit {
    /// Returns the commit ID.
    pub fn id(&self) -> Option<&CommitId> {
        self.id.as_ref()
    }

    /// Computes and sets the commit ID.
    pub fn compute_id(&mut self) -> CommitId {
        let content = self.to_content_bytes();
        let id = CommitId::from_content(&content);
        self.id = Some(id.clone());
        id
    }

    /// Serializes commit for ID computation.
    fn to_content_bytes(&self) -> Vec<u8> {
        // Deterministic serialization for ID computation
        let mut content = String::new();
        content.push_str(&format!("tree {}\n", self.tree));
        for parent in &self.parents {
            content.push_str(&format!("parent {}\n", parent));
        }
        content.push_str(&format!(
            "author {} {}\n",
            self.author,
            self.author.timestamp.timestamp()
        ));
        content.push_str(&format!(
            "committer {} {}\n",
            self.committer,
            self.committer.timestamp.timestamp()
        ));
        content.push_str(&format!("dataset {}\n", self.dataset_id));
        content.push('\n');
        content.push_str(&self.message);
        content.into_bytes()
    }

    /// Returns the first parent (for linear history).
    #[must_use]
    pub fn parent(&self) -> Option<&CommitId> {
        self.parents.first()
    }

    /// Checks if this is a merge commit.
    #[must_use]
    pub fn is_merge(&self) -> bool {
        self.parents.len() > 1
    }

    /// Checks if this is a root commit (no parents).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.parents.is_empty()
    }

    /// Returns a short summary of the message.
    #[must_use]
    pub fn summary(&self) -> &str {
        self.message.lines().next().unwrap_or("")
    }
}

/// Commit builder for constructing commits.
pub struct CommitBuilder {
    tree: Option<String>,
    parents: Vec<CommitId>,
    author: Option<Author>,
    committer: Option<Author>,
    message: Option<String>,
    dataset_id: Option<String>,
    metadata: HashMap<String, String>,
}

impl CommitBuilder {
    /// Creates a new commit builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: None,
            parents: Vec::new(),
            author: None,
            committer: None,
            message: None,
            dataset_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Sets the tree hash.
    #[must_use]
    pub fn tree(mut self, tree: impl Into<String>) -> Self {
        self.tree = Some(tree.into());
        self
    }

    /// Adds a parent commit.
    #[must_use]
    pub fn parent(mut self, parent: CommitId) -> Self {
        self.parents.push(parent);
        self
    }

    /// Sets parents.
    #[must_use]
    pub fn parents(mut self, parents: impl IntoIterator<Item = CommitId>) -> Self {
        self.parents = parents.into_iter().collect();
        self
    }

    /// Sets the author.
    #[must_use]
    pub fn author(mut self, author: Author) -> Self {
        self.author = Some(author);
        self
    }

    /// Sets the committer.
    #[must_use]
    pub fn committer(mut self, committer: Author) -> Self {
        self.committer = Some(committer);
        self
    }

    /// Sets the message.
    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Sets the dataset ID.
    #[must_use]
    pub fn dataset(mut self, dataset_id: impl Into<String>) -> Self {
        self.dataset_id = Some(dataset_id.into());
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Builds the commit.
    pub fn build(self) -> VersionResult<Commit> {
        let tree = self
            .tree
            .ok_or_else(|| VersionError::InvalidCommit("Missing tree".to_string()))?;

        let author = self
            .author
            .ok_or_else(|| VersionError::InvalidCommit("Missing author".to_string()))?;

        let message = self
            .message
            .ok_or_else(|| VersionError::InvalidCommit("Missing message".to_string()))?;

        let dataset_id = self
            .dataset_id
            .ok_or_else(|| VersionError::InvalidCommit("Missing dataset ID".to_string()))?;

        let committer = self.committer.unwrap_or_else(|| author.clone());

        let mut commit = Commit {
            id: None,
            tree,
            parents: self.parents,
            author,
            committer,
            message,
            timestamp: chrono::Utc::now(),
            dataset_id,
            metadata: self.metadata,
        };

        commit.compute_id();

        Ok(commit)
    }
}

impl Default for CommitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_id() {
        let id = CommitId::from_hash("abc1234567890");
        assert_eq!(id.short(), "abc1234");
    }

    #[test]
    fn test_commit_builder() {
        let commit = CommitBuilder::new()
            .tree("tree-hash-123")
            .author(Author::new("John Doe", "john@example.com"))
            .message("Initial commit")
            .dataset("dataset-123")
            .build()
            .unwrap();

        assert!(commit.id().is_some());
        assert!(commit.is_root());
        assert_eq!(commit.summary(), "Initial commit");
    }

    #[test]
    fn test_commit_with_parent() {
        let parent_id = CommitId::from_hash("parent123456789");

        let commit = CommitBuilder::new()
            .tree("tree-hash-456")
            .parent(parent_id.clone())
            .author(Author::new("Jane Doe", "jane@example.com"))
            .message("Second commit")
            .dataset("dataset-123")
            .build()
            .unwrap();

        assert!(!commit.is_root());
        assert_eq!(commit.parent(), Some(&parent_id));
    }

    #[test]
    fn test_merge_commit() {
        let parent1 = CommitId::from_hash("parent1abcdefg");
        let parent2 = CommitId::from_hash("parent2hijklmn");

        let commit = CommitBuilder::new()
            .tree("merged-tree-hash")
            .parents([parent1, parent2])
            .author(Author::new("Merger", "merger@example.com"))
            .message("Merge branch 'feature'")
            .dataset("dataset-123")
            .build()
            .unwrap();

        assert!(commit.is_merge());
        assert_eq!(commit.parents.len(), 2);
    }

    #[test]
    fn test_commit_id_deterministic() {
        let author = Author::at(
            "Test",
            "test@example.com",
            chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );

        let mut commit1 = Commit {
            id: None,
            tree: "tree123".to_string(),
            parents: vec![],
            author: author.clone(),
            committer: author.clone(),
            message: "Test".to_string(),
            timestamp: chrono::Utc::now(),
            dataset_id: "ds-123".to_string(),
            metadata: HashMap::new(),
        };

        let mut commit2 = commit1.clone();

        let id1 = commit1.compute_id();
        let id2 = commit2.compute_id();

        assert_eq!(id1, id2);
    }
}
