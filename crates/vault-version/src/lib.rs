//! Git-like versioning and data lineage for LLM Data Vault.
//!
//! This crate provides:
//! - Immutable versioned snapshots
//! - Branching and merging
//! - Data lineage tracking
//! - Change history and audit trail

pub mod error;
pub mod commit;
pub mod branch;
pub mod tree;
pub mod diff;
pub mod lineage;
pub mod history;

pub use error::{VersionError, VersionResult};
pub use commit::{Commit, CommitBuilder, CommitId, Author};
pub use branch::{Branch, BranchManager, RefType};
pub use tree::{Tree, TreeEntry, TreeBuilder, EntryType};
pub use diff::{Diff, DiffEntry, DiffType, DiffOptions};
pub use lineage::{Lineage, LineageNode, LineageEdge, LineageType};
pub use history::{History, HistoryEntry, HistoryQuery};

/// Re-export storage content address.
pub use vault_storage::ContentAddress;

/// Version reference (branch name or commit ID).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VersionRef {
    /// Branch reference.
    Branch(String),
    /// Tag reference.
    Tag(String),
    /// Commit ID reference.
    Commit(CommitId),
    /// HEAD reference.
    Head,
    /// Relative reference (HEAD~n).
    Relative(Box<VersionRef>, usize),
}

impl VersionRef {
    /// Creates a branch reference.
    pub fn branch(name: impl Into<String>) -> Self {
        Self::Branch(name.into())
    }

    /// Creates a tag reference.
    pub fn tag(name: impl Into<String>) -> Self {
        Self::Tag(name.into())
    }

    /// Creates a commit reference.
    pub fn commit(id: CommitId) -> Self {
        Self::Commit(id)
    }

    /// Creates a relative reference.
    pub fn parent(base: Self, n: usize) -> Self {
        Self::Relative(Box::new(base), n)
    }
}

impl std::fmt::Display for VersionRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Branch(name) => write!(f, "refs/heads/{}", name),
            Self::Tag(name) => write!(f, "refs/tags/{}", name),
            Self::Commit(id) => write!(f, "{}", id),
            Self::Head => write!(f, "HEAD"),
            Self::Relative(base, n) => write!(f, "{}~{}", base, n),
        }
    }
}

impl std::str::FromStr for VersionRef {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "HEAD" {
            return Ok(Self::Head);
        }

        if let Some(branch) = s.strip_prefix("refs/heads/") {
            return Ok(Self::Branch(branch.to_string()));
        }

        if let Some(tag) = s.strip_prefix("refs/tags/") {
            return Ok(Self::Tag(tag.to_string()));
        }

        // Check for relative reference
        if let Some(pos) = s.rfind('~') {
            let base = s[..pos].parse()?;
            let n: usize = s[pos + 1..].parse().map_err(|_| {
                VersionError::InvalidRef(format!("Invalid relative offset: {}", &s[pos + 1..]))
            })?;
            return Ok(Self::Relative(Box::new(base), n));
        }

        // Assume it's a commit ID
        Ok(Self::Commit(CommitId::from_str(s)?))
    }
}

/// Version control configuration.
#[derive(Debug, Clone)]
pub struct VersionConfig {
    /// Default branch name.
    pub default_branch: String,
    /// Max commits to keep in memory.
    pub max_cached_commits: usize,
    /// Enable automatic garbage collection.
    pub auto_gc: bool,
    /// GC threshold (unreachable objects).
    pub gc_threshold: usize,
}

impl Default for VersionConfig {
    fn default() -> Self {
        Self {
            default_branch: "main".to_string(),
            max_cached_commits: 1000,
            auto_gc: true,
            gc_threshold: 100,
        }
    }
}
