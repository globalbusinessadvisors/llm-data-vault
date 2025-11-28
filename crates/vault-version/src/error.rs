//! Version control error types.

use thiserror::Error;

/// Version control result type.
pub type VersionResult<T> = Result<T, VersionError>;

/// Version control errors.
#[derive(Error, Debug)]
pub enum VersionError {
    /// Commit not found.
    #[error("Commit not found: {0}")]
    CommitNotFound(String),

    /// Branch not found.
    #[error("Branch not found: {0}")]
    BranchNotFound(String),

    /// Tag not found.
    #[error("Tag not found: {0}")]
    TagNotFound(String),

    /// Invalid reference.
    #[error("Invalid reference: {0}")]
    InvalidRef(String),

    /// Reference already exists.
    #[error("Reference already exists: {0}")]
    RefExists(String),

    /// Branch protected.
    #[error("Branch is protected: {0}")]
    BranchProtected(String),

    /// Merge conflict.
    #[error("Merge conflict: {0}")]
    MergeConflict(String),

    /// Invalid tree.
    #[error("Invalid tree: {0}")]
    InvalidTree(String),

    /// Object not found.
    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    /// Invalid commit.
    #[error("Invalid commit: {0}")]
    InvalidCommit(String),

    /// Empty commit.
    #[error("Empty commit: no changes to commit")]
    EmptyCommit,

    /// Lineage error.
    #[error("Lineage error: {0}")]
    LineageError(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl VersionError {
    /// Returns the error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::CommitNotFound(_) => "COMMIT_NOT_FOUND",
            Self::BranchNotFound(_) => "BRANCH_NOT_FOUND",
            Self::TagNotFound(_) => "TAG_NOT_FOUND",
            Self::InvalidRef(_) => "INVALID_REF",
            Self::RefExists(_) => "REF_EXISTS",
            Self::BranchProtected(_) => "BRANCH_PROTECTED",
            Self::MergeConflict(_) => "MERGE_CONFLICT",
            Self::InvalidTree(_) => "INVALID_TREE",
            Self::ObjectNotFound(_) => "OBJECT_NOT_FOUND",
            Self::InvalidCommit(_) => "INVALID_COMMIT",
            Self::EmptyCommit => "EMPTY_COMMIT",
            Self::LineageError(_) => "LINEAGE_ERROR",
            Self::Storage(_) => "STORAGE_ERROR",
            Self::Serialization(_) => "SERIALIZATION_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

impl From<vault_storage::StorageError> for VersionError {
    fn from(e: vault_storage::StorageError) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for VersionError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
