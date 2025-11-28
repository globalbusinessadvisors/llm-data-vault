//! Storage backends for LLM Data Vault.
//!
//! This crate provides content-addressable storage with support for
//! multiple backends including in-memory, filesystem, and S3.

pub mod error;
pub mod backend;
pub mod content;
pub mod chunk;
pub mod cache;
pub mod metadata;

pub use error::{StorageError, StorageResult};
pub use backend::{StorageBackend, StorageStats};
pub use content::{ContentStore, ContentAddress, ContentMetadata, HashAlgorithm};
pub use chunk::{ChunkManager, ChunkConfig, Chunk};
pub use cache::{StorageCache, CacheConfig};
pub use metadata::{StorageMetadata, ObjectInfo};

// Re-export backends
pub use backend::memory::InMemoryBackend;
pub use backend::filesystem::FilesystemBackend;

#[cfg(feature = "aws-s3")]
pub use backend::s3::S3Backend;

/// Storage configuration.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Maximum object size (default: 100MB).
    pub max_object_size: usize,
    /// Chunk size for large objects (default: 4MB).
    pub chunk_size: usize,
    /// Enable compression.
    pub compression: bool,
    /// Enable encryption at rest.
    pub encryption: bool,
    /// Cache configuration.
    pub cache: Option<CacheConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_object_size: 100 * 1024 * 1024, // 100MB
            chunk_size: 4 * 1024 * 1024,         // 4MB
            compression: true,
            encryption: true,
            cache: Some(CacheConfig::default()),
        }
    }
}
