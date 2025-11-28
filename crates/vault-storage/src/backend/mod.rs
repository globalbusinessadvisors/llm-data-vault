//! Storage backend traits and implementations.

pub mod memory;
pub mod filesystem;

#[cfg(feature = "aws-s3")]
pub mod s3;

use crate::{StorageError, StorageResult};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Storage backend trait.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Returns the backend name.
    fn name(&self) -> &str;

    /// Stores data at the given key.
    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()>;

    /// Retrieves data by key.
    async fn get(&self, key: &str) -> StorageResult<Bytes>;

    /// Deletes data by key.
    async fn delete(&self, key: &str) -> StorageResult<()>;

    /// Checks if a key exists.
    async fn exists(&self, key: &str) -> StorageResult<bool>;

    /// Lists keys with an optional prefix.
    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>>;

    /// Returns metadata for a key.
    async fn head(&self, key: &str) -> StorageResult<ObjectMetadata>;

    /// Copies data from one key to another.
    async fn copy(&self, src: &str, dst: &str) -> StorageResult<()> {
        let data = self.get(src).await?;
        self.put(dst, data).await
    }

    /// Moves data from one key to another.
    async fn rename(&self, src: &str, dst: &str) -> StorageResult<()> {
        self.copy(src, dst).await?;
        self.delete(src).await
    }

    /// Returns storage statistics.
    async fn stats(&self) -> StorageResult<StorageStats>;
}

/// Object metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Size in bytes.
    pub size: u64,
    /// Content type (MIME).
    pub content_type: Option<String>,
    /// Last modified timestamp.
    pub last_modified: chrono::DateTime<chrono::Utc>,
    /// ETag/checksum.
    pub etag: Option<String>,
    /// Custom metadata.
    pub metadata: HashMap<String, String>,
}

impl Default for ObjectMetadata {
    fn default() -> Self {
        Self {
            size: 0,
            content_type: None,
            last_modified: chrono::Utc::now(),
            etag: None,
            metadata: HashMap::new(),
        }
    }
}

/// Storage statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total number of objects.
    pub object_count: u64,
    /// Total size in bytes.
    pub total_size: u64,
    /// Available space (if known).
    pub available_space: Option<u64>,
    /// Backend-specific stats.
    pub custom: HashMap<String, serde_json::Value>,
}

/// Multi-backend storage that routes to different backends.
pub struct MultiBackend {
    backends: HashMap<String, Box<dyn StorageBackend>>,
    default_backend: String,
    routing_rules: Vec<RoutingRule>,
}

/// Routing rule for multi-backend storage.
#[derive(Debug, Clone)]
pub struct RoutingRule {
    /// Key prefix to match.
    pub prefix: String,
    /// Target backend name.
    pub backend: String,
}

impl MultiBackend {
    /// Creates a new multi-backend storage.
    pub fn new(default_backend: String) -> Self {
        Self {
            backends: HashMap::new(),
            default_backend,
            routing_rules: Vec::new(),
        }
    }

    /// Adds a backend.
    pub fn add_backend(
        &mut self,
        name: impl Into<String>,
        backend: Box<dyn StorageBackend>,
    ) {
        self.backends.insert(name.into(), backend);
    }

    /// Adds a routing rule.
    pub fn add_rule(&mut self, rule: RoutingRule) {
        self.routing_rules.push(rule);
    }

    /// Gets the backend for a key.
    fn get_backend(&self, key: &str) -> StorageResult<&dyn StorageBackend> {
        // Check routing rules
        for rule in &self.routing_rules {
            if key.starts_with(&rule.prefix) {
                if let Some(backend) = self.backends.get(&rule.backend) {
                    return Ok(backend.as_ref());
                }
            }
        }

        // Use default backend
        self.backends
            .get(&self.default_backend)
            .map(|b| b.as_ref())
            .ok_or_else(|| {
                StorageError::Configuration(format!(
                    "Default backend '{}' not found",
                    self.default_backend
                ))
            })
    }
}

#[async_trait]
impl StorageBackend for MultiBackend {
    fn name(&self) -> &str {
        "multi"
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        self.get_backend(key)?.put(key, data).await
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        self.get_backend(key)?.get(key).await
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.get_backend(key)?.delete(key).await
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        self.get_backend(key)?.exists(key).await
    }

    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        // List from all backends and merge
        let mut all_keys = Vec::new();
        for backend in self.backends.values() {
            let keys = backend.list(prefix).await?;
            all_keys.extend(keys);
        }
        all_keys.sort();
        all_keys.dedup();
        Ok(all_keys)
    }

    async fn head(&self, key: &str) -> StorageResult<ObjectMetadata> {
        self.get_backend(key)?.head(key).await
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let mut total = StorageStats::default();
        for (name, backend) in &self.backends {
            let stats = backend.stats().await?;
            total.object_count += stats.object_count;
            total.total_size += stats.total_size;
            total.custom.insert(
                name.clone(),
                serde_json::to_value(&stats).unwrap_or_default(),
            );
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_metadata_default() {
        let meta = ObjectMetadata::default();
        assert_eq!(meta.size, 0);
        assert!(meta.content_type.is_none());
    }
}
