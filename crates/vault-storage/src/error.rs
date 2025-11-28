//! Storage error types.

use thiserror::Error;

/// Storage result type.
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage errors.
#[derive(Error, Debug)]
pub enum StorageError {
    /// Object not found.
    #[error("Object not found: {0}")]
    NotFound(String),

    /// Object already exists.
    #[error("Object already exists: {0}")]
    AlreadyExists(String),

    /// Invalid content address.
    #[error("Invalid content address: {0}")]
    InvalidAddress(String),

    /// Object too large.
    #[error("Object too large: {size} bytes (max: {max})")]
    ObjectTooLarge { size: usize, max: usize },

    /// Checksum mismatch.
    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    /// Chunk error.
    #[error("Chunk error: {0}")]
    ChunkError(String),

    /// Missing chunks.
    #[error("Missing chunks: {0:?}")]
    MissingChunks(Vec<String>),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Backend error.
    #[error("Backend error: {0}")]
    Backend(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Encryption error.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Compression error.
    #[error("Compression error: {0}")]
    Compression(String),

    /// Cache error.
    #[error("Cache error: {0}")]
    Cache(String),

    /// Timeout error.
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Quota exceeded.
    #[error("Storage quota exceeded: {used} / {limit}")]
    QuotaExceeded { used: u64, limit: u64 },

    /// Permission denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Internal error.
    #[error("Internal storage error: {0}")]
    Internal(String),
}

impl StorageError {
    /// Returns true if the error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::Backend(_) | Self::Timeout(_) | Self::Internal(_)
        )
    }

    /// Returns the error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "STORAGE_NOT_FOUND",
            Self::AlreadyExists(_) => "STORAGE_ALREADY_EXISTS",
            Self::InvalidAddress(_) => "STORAGE_INVALID_ADDRESS",
            Self::ObjectTooLarge { .. } => "STORAGE_OBJECT_TOO_LARGE",
            Self::ChecksumMismatch { .. } => "STORAGE_CHECKSUM_MISMATCH",
            Self::ChunkError(_) => "STORAGE_CHUNK_ERROR",
            Self::MissingChunks(_) => "STORAGE_MISSING_CHUNKS",
            Self::Io(_) => "STORAGE_IO_ERROR",
            Self::Serialization(_) => "STORAGE_SERIALIZATION_ERROR",
            Self::Backend(_) => "STORAGE_BACKEND_ERROR",
            Self::Configuration(_) => "STORAGE_CONFIG_ERROR",
            Self::Encryption(_) => "STORAGE_ENCRYPTION_ERROR",
            Self::Compression(_) => "STORAGE_COMPRESSION_ERROR",
            Self::Cache(_) => "STORAGE_CACHE_ERROR",
            Self::Timeout(_) => "STORAGE_TIMEOUT",
            Self::QuotaExceeded { .. } => "STORAGE_QUOTA_EXCEEDED",
            Self::PermissionDenied(_) => "STORAGE_PERMISSION_DENIED",
            Self::Internal(_) => "STORAGE_INTERNAL_ERROR",
        }
    }
}
