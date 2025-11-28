//! Content-addressable storage.

use crate::{
    ChunkConfig, ChunkManager, StorageBackend, StorageError, StorageResult,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Content address (hash-based identifier).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentAddress {
    /// Hash algorithm used.
    pub algorithm: HashAlgorithm,
    /// Hash value as hex string.
    pub hash: String,
}

impl ContentAddress {
    /// Creates a new content address from data.
    #[must_use]
    pub fn from_data(algorithm: HashAlgorithm, data: &[u8]) -> Self {
        let hash = match algorithm {
            HashAlgorithm::Blake3 => blake3::hash(data).to_hex().to_string(),
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(data);
                format!("{:x}", hasher.finalize())
            }
        };

        Self { algorithm, hash }
    }

    /// Creates from an existing hash.
    #[must_use]
    pub fn new(algorithm: HashAlgorithm, hash: impl Into<String>) -> Self {
        Self {
            algorithm,
            hash: hash.into(),
        }
    }

    /// Returns the storage key for this address.
    #[must_use]
    pub fn to_key(&self) -> String {
        let prefix = match self.algorithm {
            HashAlgorithm::Blake3 => "blake3",
            HashAlgorithm::Sha256 => "sha256",
        };
        // Use first 4 chars as directory sharding
        let (shard, rest) = self.hash.split_at(4.min(self.hash.len()));
        format!("{}/{}/{}", prefix, shard, rest)
    }

    /// Parses from a storage key.
    pub fn from_key(key: &str) -> StorageResult<Self> {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() != 3 {
            return Err(StorageError::InvalidAddress(format!(
                "Invalid key format: {}",
                key
            )));
        }

        let algorithm = match parts[0] {
            "blake3" => HashAlgorithm::Blake3,
            "sha256" => HashAlgorithm::Sha256,
            _ => {
                return Err(StorageError::InvalidAddress(format!(
                    "Unknown algorithm: {}",
                    parts[0]
                )))
            }
        };

        let hash = format!("{}{}", parts[1], parts[2]);

        Ok(Self { algorithm, hash })
    }

    /// Verifies that data matches this address.
    #[must_use]
    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = Self::from_data(self.algorithm, data);
        computed.hash == self.hash
    }
}

impl std::fmt::Display for ContentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hash)
    }
}

impl std::str::FromStr for ContentAddress {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (algo, hash) = s
            .split_once(':')
            .ok_or_else(|| StorageError::InvalidAddress(s.to_string()))?;

        let algorithm = algo.parse()?;
        Ok(Self {
            algorithm,
            hash: hash.to_string(),
        })
    }
}

/// Hash algorithm for content addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// BLAKE3 (fast, secure).
    Blake3,
    /// SHA-256 (widely compatible).
    Sha256,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Blake3
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blake3 => write!(f, "blake3"),
            Self::Sha256 => write!(f, "sha256"),
        }
    }
}

impl std::str::FromStr for HashAlgorithm {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            _ => Err(StorageError::InvalidAddress(format!(
                "Unknown hash algorithm: {}",
                s
            ))),
        }
    }
}

/// Content metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Content address.
    pub address: ContentAddress,
    /// Size in bytes.
    pub size: u64,
    /// Content type (MIME).
    pub content_type: Option<String>,
    /// Is chunked storage.
    pub chunked: bool,
    /// Chunk addresses (if chunked).
    pub chunks: Vec<ContentAddress>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Custom metadata.
    pub metadata: std::collections::HashMap<String, String>,
}

impl ContentMetadata {
    /// Creates metadata for non-chunked content.
    #[must_use]
    pub fn new(address: ContentAddress, size: u64) -> Self {
        Self {
            address,
            size,
            content_type: None,
            chunked: false,
            chunks: Vec::new(),
            created_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Creates metadata for chunked content.
    #[must_use]
    pub fn chunked(address: ContentAddress, size: u64, chunks: Vec<ContentAddress>) -> Self {
        Self {
            address,
            size,
            content_type: None,
            chunked: true,
            chunks,
            created_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        }
    }
}

/// Content-addressable storage.
pub struct ContentStore {
    backend: Arc<dyn StorageBackend>,
    chunk_manager: ChunkManager,
    algorithm: HashAlgorithm,
    chunk_threshold: usize,
}

impl ContentStore {
    /// Creates a new content store.
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self {
            backend: backend.clone(),
            chunk_manager: ChunkManager::new(backend, ChunkConfig::default()),
            algorithm: HashAlgorithm::default(),
            chunk_threshold: 4 * 1024 * 1024, // 4MB
        }
    }

    /// Creates with custom configuration.
    pub fn with_config(
        backend: Arc<dyn StorageBackend>,
        algorithm: HashAlgorithm,
        chunk_config: ChunkConfig,
    ) -> Self {
        Self {
            backend: backend.clone(),
            chunk_manager: ChunkManager::new(backend, chunk_config.clone()),
            algorithm,
            chunk_threshold: chunk_config.target_size,
        }
    }

    /// Stores content and returns its address.
    pub async fn put(&self, data: &[u8]) -> StorageResult<ContentMetadata> {
        let address = ContentAddress::from_data(self.algorithm, data);

        // Check if already exists (deduplication)
        if self.exists(&address).await? {
            return self.get_metadata(&address).await;
        }

        if data.len() > self.chunk_threshold {
            // Store as chunks
            let chunks = self.chunk_manager.store_chunked(data).await?;
            let chunk_addresses: Vec<ContentAddress> = chunks
                .iter()
                .map(|c| ContentAddress::new(self.algorithm, c.hash.clone()))
                .collect();

            let metadata = ContentMetadata::chunked(address, data.len() as u64, chunk_addresses);
            self.store_metadata(&metadata).await?;

            Ok(metadata)
        } else {
            // Store as single object
            let key = address.to_key();
            self.backend.put(&key, Bytes::copy_from_slice(data)).await?;

            let metadata = ContentMetadata::new(address, data.len() as u64);
            self.store_metadata(&metadata).await?;

            Ok(metadata)
        }
    }

    /// Retrieves content by address.
    pub async fn get(&self, address: &ContentAddress) -> StorageResult<Bytes> {
        let metadata = self.get_metadata(address).await?;

        let data = if metadata.chunked {
            // Reassemble from chunks
            let chunk_hashes: Vec<String> = metadata
                .chunks
                .iter()
                .map(|c| c.hash.clone())
                .collect();
            self.chunk_manager.retrieve_chunked(&chunk_hashes).await?
        } else {
            // Single object
            let key = address.to_key();
            self.backend.get(&key).await?
        };

        // Verify content
        if !address.verify(&data) {
            return Err(StorageError::ChecksumMismatch {
                expected: address.hash.clone(),
                actual: blake3::hash(&data).to_hex().to_string(),
            });
        }

        Ok(data)
    }

    /// Deletes content by address.
    pub async fn delete(&self, address: &ContentAddress) -> StorageResult<()> {
        let metadata = self.get_metadata(address).await?;

        if metadata.chunked {
            // Delete chunks
            for chunk in &metadata.chunks {
                let key = chunk.to_key();
                let _ = self.backend.delete(&key).await;
            }
        } else {
            // Delete single object
            let key = address.to_key();
            self.backend.delete(&key).await?;
        }

        // Delete metadata
        let meta_key = format!("{}.meta", address.to_key());
        self.backend.delete(&meta_key).await?;

        Ok(())
    }

    /// Checks if content exists.
    pub async fn exists(&self, address: &ContentAddress) -> StorageResult<bool> {
        let key = address.to_key();
        self.backend.exists(&key).await
    }

    /// Gets content metadata.
    pub async fn get_metadata(&self, address: &ContentAddress) -> StorageResult<ContentMetadata> {
        let meta_key = format!("{}.meta", address.to_key());

        match self.backend.get(&meta_key).await {
            Ok(data) => {
                serde_json::from_slice(&data)
                    .map_err(|e| StorageError::Serialization(e.to_string()))
            }
            Err(StorageError::NotFound(_)) => {
                // Try to reconstruct metadata from object
                let key = address.to_key();
                if self.backend.exists(&key).await? {
                    let obj_meta = self.backend.head(&key).await?;
                    Ok(ContentMetadata::new(address.clone(), obj_meta.size))
                } else {
                    Err(StorageError::NotFound(address.to_string()))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Stores content metadata.
    async fn store_metadata(&self, metadata: &ContentMetadata) -> StorageResult<()> {
        let meta_key = format!("{}.meta", metadata.address.to_key());
        let data = serde_json::to_vec(metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.backend.put(&meta_key, Bytes::from(data)).await
    }

    /// Verifies content integrity.
    pub async fn verify(&self, address: &ContentAddress) -> StorageResult<bool> {
        match self.get(address).await {
            Ok(_) => Ok(true),
            Err(StorageError::ChecksumMismatch { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Lists all content addresses.
    pub async fn list(&self) -> StorageResult<Vec<ContentAddress>> {
        let keys = self.backend.list(None).await?;

        let mut addresses = Vec::new();
        for key in keys {
            if !key.ends_with(".meta") {
                if let Ok(addr) = ContentAddress::from_key(&key) {
                    addresses.push(addr);
                }
            }
        }

        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryBackend;

    fn create_store() -> ContentStore {
        let backend = Arc::new(InMemoryBackend::new());
        ContentStore::new(backend)
    }

    #[tokio::test]
    async fn test_put_get() {
        let store = create_store();
        let data = b"Hello, World!";

        let metadata = store.put(data).await.unwrap();
        let retrieved = store.get(&metadata.address).await.unwrap();

        assert_eq!(retrieved.as_ref(), data);
    }

    #[tokio::test]
    async fn test_deduplication() {
        let store = create_store();
        let data = b"Duplicate content";

        let meta1 = store.put(data).await.unwrap();
        let meta2 = store.put(data).await.unwrap();

        assert_eq!(meta1.address, meta2.address);
    }

    #[tokio::test]
    async fn test_content_address() {
        let data = b"test";
        let addr = ContentAddress::from_data(HashAlgorithm::Blake3, data);

        assert!(addr.verify(data));
        assert!(!addr.verify(b"different"));
    }

    #[tokio::test]
    async fn test_key_conversion() {
        let addr = ContentAddress::new(HashAlgorithm::Blake3, "abcd1234567890");
        let key = addr.to_key();
        let parsed = ContentAddress::from_key(&key).unwrap();

        assert_eq!(addr, parsed);
    }

    #[tokio::test]
    async fn test_delete() {
        let store = create_store();
        let data = b"To delete";

        let metadata = store.put(data).await.unwrap();
        assert!(store.exists(&metadata.address).await.unwrap());

        store.delete(&metadata.address).await.unwrap();
        assert!(!store.exists(&metadata.address).await.unwrap());
    }
}
