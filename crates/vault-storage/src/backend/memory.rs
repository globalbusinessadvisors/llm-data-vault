//! In-memory storage backend.

use crate::{StorageError, StorageResult};
use super::{ObjectMetadata, StorageBackend, StorageStats};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// In-memory storage backend.
pub struct InMemoryBackend {
    data: DashMap<String, StoredObject>,
    total_size: AtomicU64,
    max_size: Option<u64>,
}

struct StoredObject {
    data: Bytes,
    metadata: ObjectMetadata,
}

impl InMemoryBackend {
    /// Creates a new in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: DashMap::new(),
            total_size: AtomicU64::new(0),
            max_size: None,
        }
    }

    /// Creates with a maximum size limit.
    #[must_use]
    pub fn with_max_size(max_size: u64) -> Self {
        Self {
            data: DashMap::new(),
            total_size: AtomicU64::new(0),
            max_size: Some(max_size),
        }
    }

    /// Clears all data.
    pub fn clear(&self) {
        self.data.clear();
        self.total_size.store(0, Ordering::SeqCst);
    }

    /// Returns the current total size.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.total_size.load(Ordering::SeqCst)
    }

    /// Returns the number of objects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for InMemoryBackend {
    fn name(&self) -> &str {
        "memory"
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        let size = data.len() as u64;

        // Check max size
        if let Some(max) = self.max_size {
            let current = self.total_size.load(Ordering::SeqCst);
            if current + size > max {
                return Err(StorageError::QuotaExceeded {
                    used: current + size,
                    limit: max,
                });
            }
        }

        // Remove old object size if exists
        if let Some(old) = self.data.get(key) {
            self.total_size
                .fetch_sub(old.data.len() as u64, Ordering::SeqCst);
        }

        let metadata = ObjectMetadata {
            size,
            content_type: None,
            last_modified: chrono::Utc::now(),
            etag: Some(blake3::hash(&data).to_hex().to_string()),
            metadata: Default::default(),
        };

        self.data.insert(
            key.to_string(),
            StoredObject { data, metadata },
        );

        self.total_size.fetch_add(size, Ordering::SeqCst);
        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        self.data
            .get(key)
            .map(|obj| obj.data.clone())
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        if let Some((_, obj)) = self.data.remove(key) {
            self.total_size
                .fetch_sub(obj.data.len() as u64, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        Ok(self.data.contains_key(key))
    }

    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let keys: Vec<String> = match prefix {
            Some(p) => self
                .data
                .iter()
                .filter(|r| r.key().starts_with(p))
                .map(|r| r.key().clone())
                .collect(),
            None => self.data.iter().map(|r| r.key().clone()).collect(),
        };
        Ok(keys)
    }

    async fn head(&self, key: &str) -> StorageResult<ObjectMetadata> {
        self.data
            .get(key)
            .map(|obj| obj.metadata.clone())
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats {
            object_count: self.data.len() as u64,
            total_size: self.total_size.load(Ordering::SeqCst),
            available_space: self.max_size.map(|max| {
                max.saturating_sub(self.total_size.load(Ordering::SeqCst))
            }),
            custom: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_put_get() {
        let backend = InMemoryBackend::new();
        let data = Bytes::from("test data");

        backend.put("key1", data.clone()).await.unwrap();
        let retrieved = backend.get("key1").await.unwrap();

        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_not_found() {
        let backend = InMemoryBackend::new();
        let result = backend.get("nonexistent").await;

        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_delete() {
        let backend = InMemoryBackend::new();
        backend.put("key1", Bytes::from("data")).await.unwrap();

        assert!(backend.exists("key1").await.unwrap());
        backend.delete("key1").await.unwrap();
        assert!(!backend.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_list_with_prefix() {
        let backend = InMemoryBackend::new();
        backend.put("prefix/a", Bytes::from("a")).await.unwrap();
        backend.put("prefix/b", Bytes::from("b")).await.unwrap();
        backend.put("other/c", Bytes::from("c")).await.unwrap();

        let keys = backend.list(Some("prefix/")).await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_max_size() {
        let backend = InMemoryBackend::with_max_size(100);

        backend.put("key1", Bytes::from(vec![0u8; 50])).await.unwrap();
        backend.put("key2", Bytes::from(vec![0u8; 40])).await.unwrap();

        let result = backend.put("key3", Bytes::from(vec![0u8; 20])).await;
        assert!(matches!(result, Err(StorageError::QuotaExceeded { .. })));
    }

    #[tokio::test]
    async fn test_stats() {
        let backend = InMemoryBackend::new();
        backend.put("key1", Bytes::from("data1")).await.unwrap();
        backend.put("key2", Bytes::from("data2")).await.unwrap();

        let stats = backend.stats().await.unwrap();
        assert_eq!(stats.object_count, 2);
        assert_eq!(stats.total_size, 10);
    }
}
