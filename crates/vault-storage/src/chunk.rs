//! Chunked storage for large objects.

use crate::{StorageBackend, StorageError, StorageResult};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Chunk configuration.
#[derive(Debug, Clone)]
pub struct ChunkConfig {
    /// Target chunk size in bytes.
    pub target_size: usize,
    /// Minimum chunk size.
    pub min_size: usize,
    /// Maximum chunk size.
    pub max_size: usize,
    /// Use content-defined chunking.
    pub content_defined: bool,
    /// Compression enabled.
    pub compression: bool,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            target_size: 4 * 1024 * 1024, // 4MB
            min_size: 1 * 1024 * 1024,    // 1MB
            max_size: 8 * 1024 * 1024,    // 8MB
            content_defined: false,
            compression: false,
        }
    }
}

impl ChunkConfig {
    /// Creates a new chunk config with target size.
    pub fn new(target_size: usize) -> Self {
        Self {
            target_size,
            min_size: target_size / 4,
            max_size: target_size * 2,
            ..Default::default()
        }
    }
}

/// A chunk of data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Chunk index.
    pub index: usize,
    /// Chunk hash (BLAKE3).
    pub hash: String,
    /// Original size before compression.
    pub original_size: usize,
    /// Stored size (may differ if compressed).
    pub stored_size: usize,
    /// Offset in original data.
    pub offset: usize,
}

impl Chunk {
    /// Returns the storage key for this chunk.
    #[must_use]
    pub fn key(&self) -> String {
        let (shard, rest) = self.hash.split_at(4.min(self.hash.len()));
        format!("chunks/{}/{}", shard, rest)
    }
}

/// Chunk manifest for a chunked object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkManifest {
    /// Total size of original data.
    pub total_size: u64,
    /// Hash of the complete data.
    pub content_hash: String,
    /// List of chunks.
    pub chunks: Vec<Chunk>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ChunkManifest {
    /// Returns the storage key for this manifest.
    #[must_use]
    pub fn key(&self) -> String {
        let (shard, rest) = self.content_hash.split_at(4.min(self.content_hash.len()));
        format!("manifests/{}/{}", shard, rest)
    }

    /// Validates that all chunks are present and in order.
    pub fn validate(&self) -> StorageResult<()> {
        let mut expected_offset = 0usize;

        for (i, chunk) in self.chunks.iter().enumerate() {
            if chunk.index != i {
                return Err(StorageError::ChunkError(format!(
                    "Chunk index mismatch: expected {}, got {}",
                    i, chunk.index
                )));
            }

            if chunk.offset != expected_offset {
                return Err(StorageError::ChunkError(format!(
                    "Chunk offset mismatch at {}: expected {}, got {}",
                    i, expected_offset, chunk.offset
                )));
            }

            expected_offset += chunk.original_size;
        }

        if expected_offset as u64 != self.total_size {
            return Err(StorageError::ChunkError(format!(
                "Total size mismatch: expected {}, got {}",
                self.total_size, expected_offset
            )));
        }

        Ok(())
    }
}

/// Chunk manager for splitting and reassembling large objects.
pub struct ChunkManager {
    backend: Arc<dyn StorageBackend>,
    config: ChunkConfig,
}

impl ChunkManager {
    /// Creates a new chunk manager.
    pub fn new(backend: Arc<dyn StorageBackend>, config: ChunkConfig) -> Self {
        Self { backend, config }
    }

    /// Splits data into chunks.
    #[must_use]
    pub fn split(&self, data: &[u8]) -> Vec<ChunkInfo> {
        if self.config.content_defined {
            self.content_defined_split(data)
        } else {
            self.fixed_size_split(data)
        }
    }

    /// Fixed-size chunking.
    fn fixed_size_split(&self, data: &[u8]) -> Vec<ChunkInfo> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        let mut index = 0;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = remaining.min(self.config.target_size);

            let chunk_data = &data[offset..offset + chunk_size];
            let hash = blake3::hash(chunk_data).to_hex().to_string();

            chunks.push(ChunkInfo {
                index,
                hash,
                data: Bytes::copy_from_slice(chunk_data),
                offset,
            });

            offset += chunk_size;
            index += 1;
        }

        chunks
    }

    /// Content-defined chunking using rolling hash.
    fn content_defined_split(&self, data: &[u8]) -> Vec<ChunkInfo> {
        let mut chunks = Vec::new();
        let mut offset = 0;
        let mut index = 0;
        let mut chunk_start = 0;

        // Simple rolling hash (Rabin-like)
        let window_size = 48;
        let mask = (1u64 << 22) - 1; // ~4MB average chunks

        if data.len() < window_size {
            // Too small for CDC, return as single chunk
            let hash = blake3::hash(data).to_hex().to_string();
            return vec![ChunkInfo {
                index: 0,
                hash,
                data: Bytes::copy_from_slice(data),
                offset: 0,
            }];
        }

        let mut hash_value = 0u64;

        // Initialize hash with first window
        for &byte in data.iter().take(window_size) {
            hash_value = hash_value.wrapping_mul(256).wrapping_add(byte as u64);
        }

        while offset < data.len() {
            let current_size = offset - chunk_start;

            // Check boundary conditions
            let is_boundary = (hash_value & mask) == 0;
            let at_min = current_size >= self.config.min_size;
            let at_max = current_size >= self.config.max_size;
            let at_end = offset >= data.len() - 1;

            if (is_boundary && at_min) || at_max || at_end {
                let end = if at_end { data.len() } else { offset };
                let chunk_data = &data[chunk_start..end];
                let chunk_hash = blake3::hash(chunk_data).to_hex().to_string();

                chunks.push(ChunkInfo {
                    index,
                    hash: chunk_hash,
                    data: Bytes::copy_from_slice(chunk_data),
                    offset: chunk_start,
                });

                chunk_start = end;
                index += 1;

                if at_end {
                    break;
                }
            }

            // Update rolling hash
            offset += 1;
            if offset < data.len() {
                if offset >= window_size {
                    let out_byte = data[offset - window_size] as u64;
                    hash_value = hash_value.wrapping_sub(
                        out_byte.wrapping_mul(256u64.wrapping_pow(window_size as u32 - 1)),
                    );
                }
                hash_value = hash_value
                    .wrapping_mul(256)
                    .wrapping_add(data[offset] as u64);
            }
        }

        chunks
    }

    /// Stores data as chunks.
    pub async fn store_chunked(&self, data: &[u8]) -> StorageResult<Vec<Chunk>> {
        let chunk_infos = self.split(data);
        let mut chunks = Vec::with_capacity(chunk_infos.len());

        for info in chunk_infos {
            let chunk = Chunk {
                index: info.index,
                hash: info.hash.clone(),
                original_size: info.data.len(),
                stored_size: info.data.len(),
                offset: info.offset,
            };

            // Store chunk
            let key = chunk.key();
            self.backend.put(&key, info.data).await?;

            chunks.push(chunk);
        }

        Ok(chunks)
    }

    /// Retrieves and reassembles chunked data.
    pub async fn retrieve_chunked(&self, chunk_hashes: &[String]) -> StorageResult<Bytes> {
        let mut data = Vec::new();

        for hash in chunk_hashes {
            let (shard, rest) = hash.split_at(4.min(hash.len()));
            let key = format!("chunks/{}/{}", shard, rest);

            let chunk_data = self.backend.get(&key).await?;

            // Verify chunk
            let computed_hash = blake3::hash(&chunk_data).to_hex().to_string();
            if computed_hash != *hash {
                return Err(StorageError::ChecksumMismatch {
                    expected: hash.clone(),
                    actual: computed_hash,
                });
            }

            data.extend_from_slice(&chunk_data);
        }

        Ok(Bytes::from(data))
    }

    /// Stores a manifest.
    pub async fn store_manifest(&self, manifest: &ChunkManifest) -> StorageResult<()> {
        let data = serde_json::to_vec(manifest)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.backend.put(&manifest.key(), Bytes::from(data)).await
    }

    /// Retrieves a manifest.
    pub async fn get_manifest(&self, content_hash: &str) -> StorageResult<ChunkManifest> {
        let (shard, rest) = content_hash.split_at(4.min(content_hash.len()));
        let key = format!("manifests/{}/{}", shard, rest);

        let data = self.backend.get(&key).await?;
        serde_json::from_slice(&data).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Deletes all chunks for a manifest.
    pub async fn delete_chunked(&self, chunk_hashes: &[String]) -> StorageResult<()> {
        for hash in chunk_hashes {
            let (shard, rest) = hash.split_at(4.min(hash.len()));
            let key = format!("chunks/{}/{}", shard, rest);
            self.backend.delete(&key).await?;
        }
        Ok(())
    }
}

/// Chunk info during splitting.
#[derive(Debug)]
pub struct ChunkInfo {
    /// Chunk index.
    pub index: usize,
    /// Chunk hash.
    pub hash: String,
    /// Chunk data.
    pub data: Bytes,
    /// Offset in original data.
    pub offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryBackend;

    fn create_manager() -> ChunkManager {
        let backend = Arc::new(InMemoryBackend::new());
        ChunkManager::new(backend, ChunkConfig::new(1024)) // 1KB chunks for testing
    }

    #[test]
    fn test_fixed_split() {
        let manager = create_manager();
        let data = vec![0u8; 3000]; // 3KB

        let chunks = manager.split(&data);

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].data.len(), 1024);
        assert_eq!(chunks[1].data.len(), 1024);
        assert_eq!(chunks[2].data.len(), 952);
    }

    #[tokio::test]
    async fn test_store_retrieve() {
        let manager = create_manager();
        let data = vec![42u8; 5000];

        let chunks = manager.store_chunked(&data).await.unwrap();
        assert!(chunks.len() > 1);

        let hashes: Vec<String> = chunks.iter().map(|c| c.hash.clone()).collect();
        let retrieved = manager.retrieve_chunked(&hashes).await.unwrap();

        assert_eq!(retrieved.as_ref(), data.as_slice());
    }

    #[test]
    fn test_manifest_validation() {
        let manifest = ChunkManifest {
            total_size: 100,
            content_hash: "test".to_string(),
            chunks: vec![
                Chunk {
                    index: 0,
                    hash: "h1".to_string(),
                    original_size: 50,
                    stored_size: 50,
                    offset: 0,
                },
                Chunk {
                    index: 1,
                    hash: "h2".to_string(),
                    original_size: 50,
                    stored_size: 50,
                    offset: 50,
                },
            ],
            created_at: chrono::Utc::now(),
        };

        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_manifest_validation_fails() {
        let manifest = ChunkManifest {
            total_size: 100,
            content_hash: "test".to_string(),
            chunks: vec![Chunk {
                index: 0,
                hash: "h1".to_string(),
                original_size: 50, // Only 50, but total says 100
                stored_size: 50,
                offset: 0,
            }],
            created_at: chrono::Utc::now(),
        };

        assert!(manifest.validate().is_err());
    }
}
