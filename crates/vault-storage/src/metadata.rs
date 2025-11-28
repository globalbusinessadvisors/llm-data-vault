//! Storage metadata management.

use crate::{ContentAddress, StorageBackend, StorageError, StorageResult};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Storage metadata for objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    /// Object key.
    pub key: String,
    /// Content address (if content-addressable).
    pub content_address: Option<ContentAddress>,
    /// Size in bytes.
    pub size: u64,
    /// Content type (MIME).
    pub content_type: Option<String>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last modified timestamp.
    pub modified_at: chrono::DateTime<chrono::Utc>,
    /// ETag/version.
    pub etag: Option<String>,
    /// Encryption info.
    pub encryption: Option<EncryptionInfo>,
    /// Compression info.
    pub compression: Option<CompressionInfo>,
    /// Custom metadata.
    pub custom: HashMap<String, String>,
    /// Tags.
    pub tags: HashMap<String, String>,
}

impl StorageMetadata {
    /// Creates new metadata.
    #[must_use]
    pub fn new(key: impl Into<String>, size: u64) -> Self {
        let now = chrono::Utc::now();
        Self {
            key: key.into(),
            content_address: None,
            size,
            content_type: None,
            created_at: now,
            modified_at: now,
            etag: None,
            encryption: None,
            compression: None,
            custom: HashMap::new(),
            tags: HashMap::new(),
        }
    }

    /// Sets content address.
    #[must_use]
    pub fn with_content_address(mut self, address: ContentAddress) -> Self {
        self.content_address = Some(address);
        self
    }

    /// Sets content type.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Sets encryption info.
    #[must_use]
    pub fn with_encryption(mut self, encryption: EncryptionInfo) -> Self {
        self.encryption = Some(encryption);
        self
    }

    /// Adds custom metadata.
    #[must_use]
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    /// Adds a tag.
    #[must_use]
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }
}

/// Encryption information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// Encryption algorithm.
    pub algorithm: String,
    /// Key ID used.
    pub key_id: String,
    /// IV/nonce (base64).
    pub iv: Option<String>,
}

/// Compression information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionInfo {
    /// Compression algorithm.
    pub algorithm: String,
    /// Original size before compression.
    pub original_size: u64,
    /// Compressed size.
    pub compressed_size: u64,
}

impl CompressionInfo {
    /// Returns the compression ratio.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.original_size == 0 {
            1.0
        } else {
            self.compressed_size as f64 / self.original_size as f64
        }
    }

    /// Returns space savings percentage.
    #[must_use]
    pub fn savings(&self) -> f64 {
        1.0 - self.ratio()
    }
}

/// Object info returned by list operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectInfo {
    /// Object key.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// Last modified timestamp.
    pub last_modified: chrono::DateTime<chrono::Utc>,
    /// ETag.
    pub etag: Option<String>,
    /// Is this a directory/prefix?
    pub is_prefix: bool,
}

/// Metadata store.
pub struct MetadataStore {
    backend: Arc<dyn StorageBackend>,
    prefix: String,
}

impl MetadataStore {
    /// Creates a new metadata store.
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self {
            backend,
            prefix: "_metadata/".to_string(),
        }
    }

    /// Creates with custom prefix.
    pub fn with_prefix(backend: Arc<dyn StorageBackend>, prefix: impl Into<String>) -> Self {
        Self {
            backend,
            prefix: prefix.into(),
        }
    }

    /// Returns the metadata key for an object key.
    fn metadata_key(&self, key: &str) -> String {
        format!("{}{}.json", self.prefix, key)
    }

    /// Stores metadata.
    pub async fn put(&self, metadata: &StorageMetadata) -> StorageResult<()> {
        let key = self.metadata_key(&metadata.key);
        let data = serde_json::to_vec(metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.backend.put(&key, Bytes::from(data)).await
    }

    /// Retrieves metadata.
    pub async fn get(&self, key: &str) -> StorageResult<StorageMetadata> {
        let meta_key = self.metadata_key(key);
        let data = self.backend.get(&meta_key).await?;
        serde_json::from_slice(&data).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Deletes metadata.
    pub async fn delete(&self, key: &str) -> StorageResult<()> {
        let meta_key = self.metadata_key(key);
        self.backend.delete(&meta_key).await
    }

    /// Checks if metadata exists.
    pub async fn exists(&self, key: &str) -> StorageResult<bool> {
        let meta_key = self.metadata_key(key);
        self.backend.exists(&meta_key).await
    }

    /// Lists all metadata keys.
    pub async fn list(&self) -> StorageResult<Vec<String>> {
        let keys = self.backend.list(Some(&self.prefix)).await?;
        Ok(keys
            .into_iter()
            .filter_map(|k| {
                k.strip_prefix(&self.prefix)
                    .and_then(|s| s.strip_suffix(".json"))
                    .map(String::from)
            })
            .collect())
    }

    /// Updates metadata fields.
    pub async fn update<F>(&self, key: &str, f: F) -> StorageResult<StorageMetadata>
    where
        F: FnOnce(&mut StorageMetadata),
    {
        let mut metadata = self.get(key).await?;
        f(&mut metadata);
        metadata.modified_at = chrono::Utc::now();
        self.put(&metadata).await?;
        Ok(metadata)
    }

    /// Searches metadata by tags.
    pub async fn find_by_tag(&self, tag_key: &str, tag_value: &str) -> StorageResult<Vec<String>> {
        let keys = self.list().await?;
        let mut matches = Vec::new();

        for key in keys {
            if let Ok(meta) = self.get(&key).await {
                if meta.tags.get(tag_key) == Some(&tag_value.to_string()) {
                    matches.push(key);
                }
            }
        }

        Ok(matches)
    }

    /// Searches metadata by custom field.
    pub async fn find_by_custom(
        &self,
        field_key: &str,
        field_value: &str,
    ) -> StorageResult<Vec<String>> {
        let keys = self.list().await?;
        let mut matches = Vec::new();

        for key in keys {
            if let Ok(meta) = self.get(&key).await {
                if meta.custom.get(field_key) == Some(&field_value.to_string()) {
                    matches.push(key);
                }
            }
        }

        Ok(matches)
    }
}

/// Index for efficient metadata queries.
pub struct MetadataIndex {
    /// Tag index: tag_key -> tag_value -> object_keys.
    tags: HashMap<String, HashMap<String, Vec<String>>>,
    /// Custom field index.
    custom: HashMap<String, HashMap<String, Vec<String>>>,
    /// Content type index.
    content_types: HashMap<String, Vec<String>>,
}

impl MetadataIndex {
    /// Creates a new empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tags: HashMap::new(),
            custom: HashMap::new(),
            content_types: HashMap::new(),
        }
    }

    /// Indexes metadata.
    pub fn index(&mut self, metadata: &StorageMetadata) {
        let key = metadata.key.clone();

        // Index tags
        for (tag_key, tag_value) in &metadata.tags {
            self.tags
                .entry(tag_key.clone())
                .or_default()
                .entry(tag_value.clone())
                .or_default()
                .push(key.clone());
        }

        // Index custom fields
        for (field_key, field_value) in &metadata.custom {
            self.custom
                .entry(field_key.clone())
                .or_default()
                .entry(field_value.clone())
                .or_default()
                .push(key.clone());
        }

        // Index content type
        if let Some(ref ct) = metadata.content_type {
            self.content_types
                .entry(ct.clone())
                .or_default()
                .push(key);
        }
    }

    /// Removes metadata from index.
    pub fn remove(&mut self, metadata: &StorageMetadata) {
        let key = &metadata.key;

        // Remove from tag index
        for (tag_key, tag_value) in &metadata.tags {
            if let Some(values) = self.tags.get_mut(tag_key) {
                if let Some(keys) = values.get_mut(tag_value) {
                    keys.retain(|k| k != key);
                }
            }
        }

        // Remove from custom index
        for (field_key, field_value) in &metadata.custom {
            if let Some(values) = self.custom.get_mut(field_key) {
                if let Some(keys) = values.get_mut(field_value) {
                    keys.retain(|k| k != key);
                }
            }
        }

        // Remove from content type index
        if let Some(ref ct) = metadata.content_type {
            if let Some(keys) = self.content_types.get_mut(ct) {
                keys.retain(|k| k != key);
            }
        }
    }

    /// Finds by tag.
    pub fn find_by_tag(&self, tag_key: &str, tag_value: &str) -> Vec<String> {
        self.tags
            .get(tag_key)
            .and_then(|v| v.get(tag_value))
            .cloned()
            .unwrap_or_default()
    }

    /// Finds by custom field.
    pub fn find_by_custom(&self, field_key: &str, field_value: &str) -> Vec<String> {
        self.custom
            .get(field_key)
            .and_then(|v| v.get(field_value))
            .cloned()
            .unwrap_or_default()
    }

    /// Finds by content type.
    pub fn find_by_content_type(&self, content_type: &str) -> Vec<String> {
        self.content_types.get(content_type).cloned().unwrap_or_default()
    }
}

impl Default for MetadataIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryBackend;

    #[tokio::test]
    async fn test_metadata_store() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = MetadataStore::new(backend);

        let metadata = StorageMetadata::new("test/key", 1024)
            .with_content_type("text/plain")
            .with_tag("env", "test")
            .with_custom("field1", "value1");

        store.put(&metadata).await.unwrap();

        let retrieved = store.get("test/key").await.unwrap();
        assert_eq!(retrieved.size, 1024);
        assert_eq!(retrieved.tags.get("env"), Some(&"test".to_string()));
    }

    #[tokio::test]
    async fn test_metadata_update() {
        let backend = Arc::new(InMemoryBackend::new());
        let store = MetadataStore::new(backend);

        let metadata = StorageMetadata::new("key", 100);
        store.put(&metadata).await.unwrap();

        let updated = store
            .update("key", |m| {
                m.size = 200;
                m.tags.insert("updated".to_string(), "true".to_string());
            })
            .await
            .unwrap();

        assert_eq!(updated.size, 200);
        assert_eq!(updated.tags.get("updated"), Some(&"true".to_string()));
    }

    #[test]
    fn test_metadata_index() {
        let mut index = MetadataIndex::new();

        let meta1 = StorageMetadata::new("obj1", 100)
            .with_tag("env", "prod")
            .with_content_type("application/json");

        let meta2 = StorageMetadata::new("obj2", 200)
            .with_tag("env", "prod")
            .with_content_type("text/plain");

        let meta3 = StorageMetadata::new("obj3", 300)
            .with_tag("env", "dev")
            .with_content_type("application/json");

        index.index(&meta1);
        index.index(&meta2);
        index.index(&meta3);

        let prod = index.find_by_tag("env", "prod");
        assert_eq!(prod.len(), 2);

        let json = index.find_by_content_type("application/json");
        assert_eq!(json.len(), 2);
    }

    #[test]
    fn test_compression_info() {
        let info = CompressionInfo {
            algorithm: "gzip".to_string(),
            original_size: 1000,
            compressed_size: 400,
        };

        assert!((info.ratio() - 0.4).abs() < 0.001);
        assert!((info.savings() - 0.6).abs() < 0.001);
    }
}
