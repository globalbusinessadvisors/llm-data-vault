//! Migration error types.

/// Migration error type.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// Database connection error.
    #[error("Database connection error: {0}")]
    Connection(#[from] sqlx::Error),

    /// Migration execution error.
    #[error("Migration failed: {message}")]
    Migration {
        /// Error message.
        message: String,
        /// Migration version that failed.
        version: Option<i64>,
    },

    /// Migration not found.
    #[error("Migration not found: version {version}")]
    NotFound {
        /// Missing migration version.
        version: i64,
    },

    /// Invalid migration state.
    #[error("Invalid migration state: {0}")]
    InvalidState(String),

    /// Checksum mismatch.
    #[error("Migration checksum mismatch for version {version}: {message}")]
    ChecksumMismatch {
        /// Migration version.
        version: i64,
        /// Error message.
        message: String,
    },

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

impl MigrationError {
    /// Creates a migration error.
    pub fn migration(message: impl Into<String>, version: Option<i64>) -> Self {
        Self::Migration {
            message: message.into(),
            version,
        }
    }

    /// Creates a not found error.
    pub fn not_found(version: i64) -> Self {
        Self::NotFound { version }
    }

    /// Creates an invalid state error.
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::InvalidState(message.into())
    }

    /// Creates a config error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Creates a checksum mismatch error.
    pub fn checksum_mismatch(version: i64, message: impl Into<String>) -> Self {
        Self::ChecksumMismatch {
            version,
            message: message.into(),
        }
    }
}

/// Result type for migrations.
pub type Result<T> = std::result::Result<T, MigrationError>;
