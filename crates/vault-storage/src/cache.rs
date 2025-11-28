//! Storage caching layer.

use crate::{StorageBackend, StorageError, StorageResult};
use super::backend::{ObjectMetadata, StorageStats};
use async_trait::async_trait;
use bytes::Bytes;
use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of cached objects.
    pub max_objects: usize,
    /// Maximum cache size in bytes.
    pub max_size: usize,
    /// TTL for cached objects.
    pub ttl: Duration,
    /// Cache negative lookups (not found).
    pub cache_negative: bool,
    /// Negative lookup TTL.
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_objects: 10_000,
            max_size: 256 * 1024 * 1024, // 256MB
            ttl: Duration::from_secs(3600),
            cache_negative: true,
            negative_ttl: Duration::from_secs(60),
        }
    }
}

/// Cached object entry.
struct CacheEntry {
    data: Option<Bytes>, // None = negative cache
    metadata: Option<ObjectMetadata>,
    cached_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    fn is_negative(&self) -> bool {
        self.data.is_none()
    }
}

/// Storage cache layer.
pub struct StorageCache {
    backend: Arc<dyn StorageBackend>,
    cache: RwLock<LruCache<String, CacheEntry>>,
    config: CacheConfig,
    current_size: RwLock<usize>,
    stats: RwLock<CacheStats>,
}

/// Cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Cache hits.
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Evictions.
    pub evictions: u64,
    /// Current cached objects.
    pub cached_objects: usize,
    /// Current cache size in bytes.
    pub cached_size: usize,
}

impl CacheStats {
    /// Returns the hit rate.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl StorageCache {
    /// Creates a new cache layer.
    pub fn new(backend: Arc<dyn StorageBackend>, config: CacheConfig) -> Self {
        let max_objects = NonZeroUsize::new(config.max_objects).unwrap_or(NonZeroUsize::MIN);

        Self {
            backend,
            cache: RwLock::new(LruCache::new(max_objects)),
            config,
            current_size: RwLock::new(0),
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Returns cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        let mut stats = self.stats.read().clone();
        stats.cached_objects = self.cache.read().len();
        stats.cached_size = *self.current_size.read();
        stats
    }

    /// Clears the cache.
    pub fn clear(&self) {
        self.cache.write().clear();
        *self.current_size.write() = 0;
    }

    /// Invalidates a specific key.
    pub fn invalidate(&self, key: &str) {
        let mut cache = self.cache.write();
        if let Some(entry) = cache.pop(key) {
            if let Some(data) = &entry.data {
                *self.current_size.write() -= data.len();
            }
        }
    }

    /// Invalidates all keys matching a prefix.
    pub fn invalidate_prefix(&self, prefix: &str) {
        let mut cache = self.cache.write();
        let mut size_reduction = 0usize;

        // Collect keys to remove
        let keys_to_remove: Vec<String> = cache
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_remove {
            if let Some(entry) = cache.pop(&key) {
                if let Some(data) = &entry.data {
                    size_reduction += data.len();
                }
            }
        }

        *self.current_size.write() -= size_reduction;
    }

    /// Ensures cache doesn't exceed size limit.
    fn enforce_size_limit(&self) {
        let mut cache = self.cache.write();
        let mut current_size = self.current_size.write();
        let mut stats = self.stats.write();

        while *current_size > self.config.max_size && !cache.is_empty() {
            if let Some((_, entry)) = cache.pop_lru() {
                if let Some(data) = &entry.data {
                    *current_size -= data.len();
                }
                stats.evictions += 1;
            }
        }
    }
}

#[async_trait]
impl StorageBackend for StorageCache {
    fn name(&self) -> &str {
        "cache"
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        // Write through to backend
        self.backend.put(key, data.clone()).await?;

        // Update cache
        let entry = CacheEntry {
            data: Some(data.clone()),
            metadata: Some(ObjectMetadata {
                size: data.len() as u64,
                content_type: None,
                last_modified: chrono::Utc::now(),
                etag: Some(blake3::hash(&data).to_hex().to_string()),
                metadata: Default::default(),
            }),
            cached_at: Instant::now(),
            ttl: self.config.ttl,
        };

        {
            let mut cache = self.cache.write();

            // Remove old entry size
            if let Some(old) = cache.get(key) {
                if let Some(old_data) = &old.data {
                    *self.current_size.write() -= old_data.len();
                }
            }

            // Add new entry
            *self.current_size.write() += data.len();
            cache.put(key.to_string(), entry);
        }

        self.enforce_size_limit();

        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        // Check cache first
        {
            let mut cache = self.cache.write();
            if let Some(entry) = cache.get(key) {
                if !entry.is_expired() {
                    self.stats.write().hits += 1;

                    if entry.is_negative() {
                        return Err(StorageError::NotFound(key.to_string()));
                    }

                    if let Some(ref data) = entry.data {
                        return Ok(data.clone());
                    }
                }
            }
        }

        self.stats.write().misses += 1;

        // Fetch from backend
        match self.backend.get(key).await {
            Ok(data) => {
                // Cache the result
                let entry = CacheEntry {
                    data: Some(data.clone()),
                    metadata: None,
                    cached_at: Instant::now(),
                    ttl: self.config.ttl,
                };

                {
                    let mut cache = self.cache.write();
                    *self.current_size.write() += data.len();
                    cache.put(key.to_string(), entry);
                }

                self.enforce_size_limit();

                Ok(data)
            }
            Err(StorageError::NotFound(k)) => {
                // Cache negative result
                if self.config.cache_negative {
                    let entry = CacheEntry {
                        data: None,
                        metadata: None,
                        cached_at: Instant::now(),
                        ttl: self.config.negative_ttl,
                    };

                    self.cache.write().put(key.to_string(), entry);
                }

                Err(StorageError::NotFound(k))
            }
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        // Delete from backend
        self.backend.delete(key).await?;

        // Invalidate cache
        self.invalidate(key);

        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.peek(key) {
                if !entry.is_expired() {
                    return Ok(!entry.is_negative());
                }
            }
        }

        self.backend.exists(key).await
    }

    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        // Always go to backend for list operations
        self.backend.list(prefix).await
    }

    async fn head(&self, key: &str) -> StorageResult<ObjectMetadata> {
        // Check cache for metadata
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.peek(key) {
                if !entry.is_expired() && !entry.is_negative() {
                    if let Some(ref meta) = entry.metadata {
                        return Ok(meta.clone());
                    }
                }
            }
        }

        self.backend.head(key).await
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let mut stats = self.backend.stats().await?;

        // Add cache stats
        let cache_stats = self.cache_stats();
        stats.custom.insert(
            "cache".to_string(),
            serde_json::json!({
                "hits": cache_stats.hits,
                "misses": cache_stats.misses,
                "hit_rate": cache_stats.hit_rate(),
                "cached_objects": cache_stats.cached_objects,
                "cached_size": cache_stats.cached_size,
                "evictions": cache_stats.evictions,
            }),
        );

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryBackend;

    fn create_cache() -> StorageCache {
        let backend = Arc::new(InMemoryBackend::new());
        StorageCache::new(
            backend,
            CacheConfig {
                max_objects: 100,
                max_size: 1024 * 1024,
                ttl: Duration::from_secs(60),
                cache_negative: true,
                negative_ttl: Duration::from_secs(10),
            },
        )
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let cache = create_cache();

        cache.put("key1", Bytes::from("value1")).await.unwrap();

        // First get - should be from cache
        let value = cache.get("key1").await.unwrap();
        assert_eq!(value, Bytes::from("value1"));

        let stats = cache.cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = create_cache();

        // Put directly to backend
        cache.backend.put("key1", Bytes::from("value1")).await.unwrap();

        // Get through cache - should miss first
        let value = cache.get("key1").await.unwrap();
        assert_eq!(value, Bytes::from("value1"));

        let stats = cache.cache_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);

        // Second get - should hit
        let _ = cache.get("key1").await.unwrap();
        let stats = cache.cache_stats();
        assert_eq!(stats.hits, 1);
    }

    #[tokio::test]
    async fn test_negative_cache() {
        let cache = create_cache();

        // First miss
        assert!(cache.get("nonexistent").await.is_err());

        // Second miss should be from negative cache
        assert!(cache.get("nonexistent").await.is_err());

        let stats = cache.cache_stats();
        assert_eq!(stats.misses, 1); // Only one actual miss
        assert_eq!(stats.hits, 1);   // Second was a cache hit (negative)
    }

    #[tokio::test]
    async fn test_invalidation() {
        let cache = create_cache();

        cache.put("key1", Bytes::from("value1")).await.unwrap();
        cache.invalidate("key1");

        // Should miss now
        let _ = cache.get("key1").await.unwrap();
        let stats = cache.cache_stats();
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_prefix_invalidation() {
        let cache = create_cache();

        cache.put("prefix/a", Bytes::from("a")).await.unwrap();
        cache.put("prefix/b", Bytes::from("b")).await.unwrap();
        cache.put("other/c", Bytes::from("c")).await.unwrap();

        cache.invalidate_prefix("prefix/");

        // prefix/* should miss
        let _ = cache.get("prefix/a").await.unwrap();
        let _ = cache.get("prefix/b").await.unwrap();

        // other/* should hit
        let _ = cache.get("other/c").await.unwrap();

        let stats = cache.cache_stats();
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.hits, 1);
    }
}
