# LLM-Data-Vault Pseudocode: Storage Layer

**Document:** 02-storage-layer.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines the storage layer architecture for LLM-Data-Vault, featuring:
- Pluggable storage backends (S3, Azure Blob, GCS, Local)
- Content-addressable storage with deduplication
- Chunked storage for large files
- Caching layer with LRU eviction

---

## 1. Storage Traits and Core Types

```rust
// src/storage/mod.rs

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;

// ============================================================================
// Core Storage Trait
// ============================================================================

#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store data with the given key
    async fn put(
        &self,
        key: &StorageKey,
        data: Bytes,
        options: PutOptions,
    ) -> Result<StorageReceipt, StorageError>;

    /// Store data from a stream (for large files)
    async fn put_stream(
        &self,
        key: &StorageKey,
        stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
        options: PutOptions,
    ) -> Result<StorageReceipt, StorageError>;

    /// Retrieve data by key
    async fn get(&self, key: &StorageKey) -> Result<Bytes, StorageError>;

    /// Retrieve data as a stream
    async fn get_stream(
        &self,
        key: &StorageKey,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>, StorageError>;

    /// Retrieve a range of bytes
    async fn get_range(
        &self,
        key: &StorageKey,
        range: ByteRange,
    ) -> Result<Bytes, StorageError>;

    /// Delete data by key
    async fn delete(&self, key: &StorageKey) -> Result<(), StorageError>;

    /// Check if key exists
    async fn exists(&self, key: &StorageKey) -> Result<bool, StorageError>;

    /// Get object metadata
    async fn head(&self, key: &StorageKey) -> Result<ObjectMetadata, StorageError>;

    /// List objects with prefix
    async fn list(
        &self,
        prefix: &str,
        options: ListOptions,
    ) -> Result<ListResult, StorageError>;

    /// Copy object
    async fn copy(
        &self,
        source: &StorageKey,
        destination: &StorageKey,
    ) -> Result<StorageReceipt, StorageError>;

    /// Health check
    async fn health_check(&self) -> Result<HealthStatus, StorageError>;

    /// Get backend type identifier
    fn backend_type(&self) -> &'static str;
}

// ============================================================================
// Storage Types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageKey {
    pub bucket: String,
    pub path: String,
}

impl StorageKey {
    pub fn new(bucket: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            path: path.into(),
        }
    }

    pub fn from_content_hash(bucket: &str, hash: &ContentHash) -> Self {
        // Sharded path: first 2 chars as directory
        let hex = hash.to_hex();
        let path = format!("{}/{}/{}", &hex[0..2], &hex[2..4], hex);
        Self::new(bucket, path)
    }

    pub fn full_path(&self) -> String {
        format!("{}/{}", self.bucket, self.path)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    pub content_type: Option<String>,
    pub metadata: HashMap<String, String>,
    pub encryption: Option<EncryptionConfig>,
    pub storage_class: Option<StorageClass>,
    pub cache_control: Option<String>,
    pub if_none_match: bool,  // Only write if doesn't exist
}

#[derive(Debug, Clone, Copy)]
pub enum StorageClass {
    Standard,
    InfrequentAccess,
    Archive,
    DeepArchive,
}

#[derive(Debug, Clone)]
pub struct StorageReceipt {
    pub key: StorageKey,
    pub etag: String,
    pub version_id: Option<String>,
    pub size: u64,
    pub checksum: Checksum,
    pub stored_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ObjectMetadata {
    pub key: StorageKey,
    pub size: u64,
    pub etag: String,
    pub content_type: Option<String>,
    pub last_modified: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
    pub storage_class: StorageClass,
    pub encryption: Option<EncryptionInfo>,
}

#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    pub end: Option<u64>,
}

impl ByteRange {
    pub fn from_start(start: u64) -> Self {
        Self { start, end: None }
    }

    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end: Some(end) }
    }

    pub fn to_header(&self) -> String {
        match self.end {
            Some(end) => format!("bytes={}-{}", self.start, end),
            None => format!("bytes={}-", self.start),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub max_keys: Option<u32>,
    pub continuation_token: Option<String>,
    pub delimiter: Option<String>,
    pub start_after: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ListResult {
    pub objects: Vec<ObjectMetadata>,
    pub common_prefixes: Vec<String>,
    pub continuation_token: Option<String>,
    pub is_truncated: bool,
}

// ============================================================================
// Storage Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Object not found: {key}")]
    NotFound { key: String },

    #[error("Access denied: {message}")]
    AccessDenied { message: String },

    #[error("Object already exists: {key}")]
    AlreadyExists { key: String },

    #[error("Invalid key: {message}")]
    InvalidKey { message: String },

    #[error("Connection error: {message}")]
    Connection {
        message: String,
        #[source] source: Option<Box<dyn std::error::Error + Send + Sync>>,
        retryable: bool,
    },

    #[error("Timeout after {duration:?}")]
    Timeout { duration: Duration },

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Backend error: {message}")]
    Backend {
        message: String,
        #[source] source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Configuration error: {message}")]
    Configuration { message: String },
}

impl StorageError {
    pub fn is_retryable(&self) -> bool {
        match self {
            StorageError::Connection { retryable, .. } => *retryable,
            StorageError::Timeout { .. } => true,
            _ => false,
        }
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, StorageError::NotFound { .. })
    }
}
```

---

## 2. S3 Backend Implementation

```rust
// src/storage/s3.rs

use aws_sdk_s3::{Client, Config};
use aws_sdk_s3::primitives::ByteStream;

pub struct S3StorageBackend {
    client: Client,
    config: S3Config,
    metrics: Arc<StorageMetrics>,
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub region: String,
    pub endpoint: Option<String>,  // For MinIO compatibility
    pub bucket: String,
    pub prefix: Option<String>,
    pub multipart_threshold: ByteSize,  // Default: 5MB
    pub multipart_chunk_size: ByteSize, // Default: 8MB
    pub max_concurrent_uploads: usize,  // Default: 4
    pub timeout: Duration,
    pub retry_config: RetryConfig,
    pub server_side_encryption: Option<ServerSideEncryption>,
}

#[derive(Debug, Clone)]
pub enum ServerSideEncryption {
    Aes256,
    KMS { key_id: String },
}

impl S3StorageBackend {
    pub async fn new(config: S3Config) -> Result<Self, StorageError> {
        let aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .load()
            .await;

        let mut s3_config = Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()));

        if let Some(ref endpoint) = config.endpoint {
            s3_config = s3_config
                .endpoint_url(endpoint)
                .force_path_style(true);  // Required for MinIO
        }

        let client = Client::from_conf(s3_config.build());

        Ok(Self {
            client,
            config,
            metrics: Arc::new(StorageMetrics::new("s3")),
        })
    }

    fn full_key(&self, key: &StorageKey) -> String {
        match &self.config.prefix {
            Some(prefix) => format!("{}/{}", prefix, key.path),
            None => key.path.clone(),
        }
    }
}

#[async_trait]
impl StorageBackend for S3StorageBackend {
    async fn put(
        &self,
        key: &StorageKey,
        data: Bytes,
        options: PutOptions,
    ) -> Result<StorageReceipt, StorageError> {
        let _timer = self.metrics.operation_timer("put");
        let size = data.len() as u64;

        // Use multipart upload for large files
        if size > self.config.multipart_threshold.as_bytes() {
            return self.multipart_upload(key, data, options).await;
        }

        let mut request = self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(self.full_key(key))
            .body(ByteStream::from(data.to_vec()));

        if let Some(ct) = options.content_type {
            request = request.content_type(ct);
        }

        // Apply server-side encryption
        if let Some(ref sse) = self.config.server_side_encryption {
            request = match sse {
                ServerSideEncryption::Aes256 => {
                    request.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256)
                }
                ServerSideEncryption::KMS { key_id } => {
                    request
                        .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
                        .ssekms_key_id(key_id)
                }
            };
        }

        // Apply custom metadata
        for (k, v) in options.metadata {
            request = request.metadata(k, v);
        }

        let result = request
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        self.metrics.record_bytes_written(size);

        Ok(StorageReceipt {
            key: key.clone(),
            etag: result.e_tag().unwrap_or_default().to_string(),
            version_id: result.version_id().map(|s| s.to_string()),
            size,
            checksum: Checksum::sha256(&data),
            stored_at: Utc::now(),
        })
    }

    async fn get(&self, key: &StorageKey) -> Result<Bytes, StorageError> {
        let _timer = self.metrics.operation_timer("get");

        let result = self.client
            .get_object()
            .bucket(&self.config.bucket)
            .key(self.full_key(key))
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        let data = result.body
            .collect()
            .await
            .map_err(|e| StorageError::Backend {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?
            .into_bytes();

        self.metrics.record_bytes_read(data.len() as u64);
        Ok(Bytes::from(data.to_vec()))
    }

    async fn get_stream(
        &self,
        key: &StorageKey,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>, StorageError> {
        let result = self.client
            .get_object()
            .bucket(&self.config.bucket)
            .key(self.full_key(key))
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        let stream = result.body
            .map(|chunk| {
                chunk
                    .map(|b| Bytes::from(b.to_vec()))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            });

        Ok(Box::pin(stream))
    }

    async fn get_range(
        &self,
        key: &StorageKey,
        range: ByteRange,
    ) -> Result<Bytes, StorageError> {
        let result = self.client
            .get_object()
            .bucket(&self.config.bucket)
            .key(self.full_key(key))
            .range(range.to_header())
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        let data = result.body
            .collect()
            .await
            .map_err(|e| StorageError::Backend {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?
            .into_bytes();

        Ok(Bytes::from(data.to_vec()))
    }

    async fn delete(&self, key: &StorageKey) -> Result<(), StorageError> {
        let _timer = self.metrics.operation_timer("delete");

        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(self.full_key(key))
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        self.metrics.increment_deletes();
        Ok(())
    }

    async fn exists(&self, key: &StorageKey) -> Result<bool, StorageError> {
        match self.head(key).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn head(&self, key: &StorageKey) -> Result<ObjectMetadata, StorageError> {
        let result = self.client
            .head_object()
            .bucket(&self.config.bucket)
            .key(self.full_key(key))
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        Ok(ObjectMetadata {
            key: key.clone(),
            size: result.content_length().unwrap_or(0) as u64,
            etag: result.e_tag().unwrap_or_default().to_string(),
            content_type: result.content_type().map(|s| s.to_string()),
            last_modified: result.last_modified()
                .and_then(|dt| DateTime::from_timestamp(dt.secs(), 0))
                .unwrap_or_else(Utc::now),
            metadata: result.metadata().cloned().unwrap_or_default(),
            storage_class: StorageClass::Standard,
            encryption: None,
        })
    }

    async fn list(
        &self,
        prefix: &str,
        options: ListOptions,
    ) -> Result<ListResult, StorageError> {
        let mut request = self.client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .prefix(prefix);

        if let Some(max_keys) = options.max_keys {
            request = request.max_keys(max_keys as i32);
        }
        if let Some(ref token) = options.continuation_token {
            request = request.continuation_token(token);
        }
        if let Some(ref delimiter) = options.delimiter {
            request = request.delimiter(delimiter);
        }

        let result = request.send().await.map_err(|e| self.map_s3_error(e))?;

        let objects = result.contents()
            .iter()
            .map(|obj| ObjectMetadata {
                key: StorageKey::new(&self.config.bucket, obj.key().unwrap_or_default()),
                size: obj.size().unwrap_or(0) as u64,
                etag: obj.e_tag().unwrap_or_default().to_string(),
                content_type: None,
                last_modified: obj.last_modified()
                    .and_then(|dt| DateTime::from_timestamp(dt.secs(), 0))
                    .unwrap_or_else(Utc::now),
                metadata: HashMap::new(),
                storage_class: StorageClass::Standard,
                encryption: None,
            })
            .collect();

        let common_prefixes = result.common_prefixes()
            .iter()
            .filter_map(|cp| cp.prefix().map(|s| s.to_string()))
            .collect();

        Ok(ListResult {
            objects,
            common_prefixes,
            continuation_token: result.next_continuation_token().map(|s| s.to_string()),
            is_truncated: result.is_truncated().unwrap_or(false),
        })
    }

    async fn copy(
        &self,
        source: &StorageKey,
        destination: &StorageKey,
    ) -> Result<StorageReceipt, StorageError> {
        let copy_source = format!("{}/{}", self.config.bucket, self.full_key(source));

        let result = self.client
            .copy_object()
            .bucket(&self.config.bucket)
            .copy_source(&copy_source)
            .key(self.full_key(destination))
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        let metadata = self.head(destination).await?;

        Ok(StorageReceipt {
            key: destination.clone(),
            etag: result.copy_object_result()
                .and_then(|r| r.e_tag())
                .unwrap_or_default()
                .to_string(),
            version_id: result.version_id().map(|s| s.to_string()),
            size: metadata.size,
            checksum: Checksum::sha256(&[]), // Would need to read to compute
            stored_at: Utc::now(),
        })
    }

    async fn health_check(&self) -> Result<HealthStatus, StorageError> {
        let start = Instant::now();

        // List objects with max 1 to test connectivity
        let _ = self.client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .max_keys(1)
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        Ok(HealthStatus {
            healthy: true,
            latency: start.elapsed(),
            message: None,
        })
    }

    fn backend_type(&self) -> &'static str {
        "s3"
    }
}

impl S3StorageBackend {
    /// Multipart upload for large files
    async fn multipart_upload(
        &self,
        key: &StorageKey,
        data: Bytes,
        options: PutOptions,
    ) -> Result<StorageReceipt, StorageError> {
        let full_key = self.full_key(key);
        let chunk_size = self.config.multipart_chunk_size.as_bytes() as usize;
        let total_size = data.len();

        // Initiate multipart upload
        let create_result = self.client
            .create_multipart_upload()
            .bucket(&self.config.bucket)
            .key(&full_key)
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        let upload_id = create_result.upload_id()
            .ok_or(StorageError::Backend {
                message: "No upload ID returned".into(),
                source: None,
            })?;

        // Upload parts in parallel with semaphore
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_uploads));
        let mut part_futures = Vec::new();
        let mut part_number = 1;

        for chunk_start in (0..total_size).step_by(chunk_size) {
            let chunk_end = std::cmp::min(chunk_start + chunk_size, total_size);
            let chunk = data.slice(chunk_start..chunk_end);

            let client = self.client.clone();
            let bucket = self.config.bucket.clone();
            let key = full_key.clone();
            let upload_id = upload_id.to_string();
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let pn = part_number;

            part_futures.push(tokio::spawn(async move {
                let _permit = permit;
                let result = client
                    .upload_part()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .part_number(pn)
                    .body(ByteStream::from(chunk.to_vec()))
                    .send()
                    .await?;

                Ok::<_, aws_sdk_s3::Error>((pn, result.e_tag().unwrap_or_default().to_string()))
            }));

            part_number += 1;
        }

        // Wait for all parts and collect ETags
        let mut completed_parts = Vec::new();
        for future in part_futures {
            let (part_num, etag) = future.await
                .map_err(|e| StorageError::Backend {
                    message: format!("Part upload task failed: {}", e),
                    source: None,
                })?
                .map_err(|e| self.map_s3_error(e))?;

            completed_parts.push(
                aws_sdk_s3::types::CompletedPart::builder()
                    .part_number(part_num)
                    .e_tag(etag)
                    .build()
            );
        }

        // Sort parts by part number
        completed_parts.sort_by_key(|p| p.part_number());

        // Complete multipart upload
        let completed_upload = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        let complete_result = self.client
            .complete_multipart_upload()
            .bucket(&self.config.bucket)
            .key(&full_key)
            .upload_id(upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await
            .map_err(|e| self.map_s3_error(e))?;

        Ok(StorageReceipt {
            key: key.clone(),
            etag: complete_result.e_tag().unwrap_or_default().to_string(),
            version_id: complete_result.version_id().map(|s| s.to_string()),
            size: total_size as u64,
            checksum: Checksum::sha256(&data),
            stored_at: Utc::now(),
        })
    }

    fn map_s3_error(&self, error: impl std::error::Error) -> StorageError {
        let message = error.to_string();

        if message.contains("NoSuchKey") || message.contains("NotFound") {
            StorageError::NotFound { key: "unknown".into() }
        } else if message.contains("AccessDenied") {
            StorageError::AccessDenied { message }
        } else if message.contains("timeout") || message.contains("Timeout") {
            StorageError::Timeout { duration: self.config.timeout }
        } else {
            StorageError::Backend {
                message,
                source: Some(Box::new(error)),
            }
        }
    }
}
```

---

## 3. Content-Addressable Storage

```rust
// src/storage/cas.rs

/// Content-Addressable Storage layer
/// Provides deduplication and integrity verification
pub struct ContentAddressableStore {
    backend: Arc<dyn StorageBackend>,
    bucket: String,
    algorithm: HashAlgorithm,
    metrics: Arc<CASMetrics>,
}

impl ContentAddressableStore {
    pub fn new(
        backend: Arc<dyn StorageBackend>,
        bucket: String,
        algorithm: HashAlgorithm,
    ) -> Self {
        Self {
            backend,
            bucket,
            algorithm,
            metrics: Arc::new(CASMetrics::new()),
        }
    }

    /// Store content and return its content hash
    /// Automatically deduplicates identical content
    pub async fn put(&self, data: Bytes) -> Result<ContentHash, StorageError> {
        let hash = ContentHash::compute(&data, self.algorithm);
        let key = StorageKey::from_content_hash(&self.bucket, &hash);

        // Check if already exists (deduplication)
        if self.backend.exists(&key).await? {
            self.metrics.record_deduplicated(data.len() as u64);
            return Ok(hash);
        }

        // Store with integrity metadata
        let options = PutOptions {
            metadata: HashMap::from([
                ("x-content-hash".to_string(), hash.to_string()),
                ("x-content-size".to_string(), data.len().to_string()),
            ]),
            ..Default::default()
        };

        self.backend.put(&key, data, options).await?;
        self.metrics.record_stored(data.len() as u64);

        Ok(hash)
    }

    /// Retrieve content by hash with integrity verification
    pub async fn get(&self, hash: &ContentHash) -> Result<Bytes, StorageError> {
        let key = StorageKey::from_content_hash(&self.bucket, hash);
        let data = self.backend.get(&key).await?;

        // Verify integrity
        let computed_hash = ContentHash::compute(&data, self.algorithm);
        if &computed_hash != hash {
            return Err(StorageError::ChecksumMismatch {
                expected: hash.to_string(),
                actual: computed_hash.to_string(),
            });
        }

        self.metrics.record_retrieved(data.len() as u64);
        Ok(data)
    }

    /// Check if content exists
    pub async fn exists(&self, hash: &ContentHash) -> Result<bool, StorageError> {
        let key = StorageKey::from_content_hash(&self.bucket, hash);
        self.backend.exists(&key).await
    }

    /// Delete content (use with caution - may break references)
    pub async fn delete(&self, hash: &ContentHash) -> Result<(), StorageError> {
        let key = StorageKey::from_content_hash(&self.bucket, hash);
        self.backend.delete(&key).await
    }

    /// Get storage statistics
    pub fn stats(&self) -> CASStats {
        CASStats {
            total_stored: self.metrics.total_stored(),
            total_retrieved: self.metrics.total_retrieved(),
            bytes_deduplicated: self.metrics.bytes_deduplicated(),
            deduplication_ratio: self.metrics.deduplication_ratio(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CASStats {
    pub total_stored: u64,
    pub total_retrieved: u64,
    pub bytes_deduplicated: u64,
    pub deduplication_ratio: f64,
}
```

---

## 4. Chunked Storage Manager

```rust
// src/storage/chunked.rs

/// Manages large files by splitting into chunks
pub struct ChunkManager {
    cas: Arc<ContentAddressableStore>,
    chunk_size: ByteSize,
    max_concurrent: usize,
    compression: Option<CompressionType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkManifest {
    pub id: Uuid,
    pub total_size: u64,
    pub chunk_count: usize,
    pub chunk_size: u64,
    pub chunks: Vec<ChunkInfo>,
    pub checksum: Checksum,
    pub compression: Option<CompressionType>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub index: usize,
    pub hash: ContentHash,
    pub size: u64,
    pub offset: u64,
}

impl ChunkManager {
    pub fn new(
        cas: Arc<ContentAddressableStore>,
        chunk_size: ByteSize,
        max_concurrent: usize,
    ) -> Self {
        Self {
            cas,
            chunk_size,
            max_concurrent,
            compression: None,
        }
    }

    pub fn with_compression(mut self, compression: CompressionType) -> Self {
        self.compression = Some(compression);
        self
    }

    /// Store large data as chunks, returns manifest
    pub async fn store(&self, data: Bytes) -> Result<ChunkManifest, StorageError> {
        let total_size = data.len() as u64;
        let chunk_size = self.chunk_size.as_bytes() as usize;
        let total_checksum = Checksum::sha256(&data);

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut chunk_futures = Vec::new();
        let mut offset = 0u64;

        for (index, chunk_start) in (0..data.len()).step_by(chunk_size).enumerate() {
            let chunk_end = std::cmp::min(chunk_start + chunk_size, data.len());
            let mut chunk_data = data.slice(chunk_start..chunk_end);

            // Apply compression if configured
            if let Some(compression) = self.compression {
                chunk_data = self.compress(&chunk_data, compression)?;
            }

            let cas = self.cas.clone();
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let chunk_offset = offset;
            let original_size = (chunk_end - chunk_start) as u64;

            chunk_futures.push(tokio::spawn(async move {
                let _permit = permit;
                let hash = cas.put(chunk_data.clone()).await?;
                Ok::<_, StorageError>(ChunkInfo {
                    index,
                    hash,
                    size: chunk_data.len() as u64,
                    offset: chunk_offset,
                })
            }));

            offset += original_size;
        }

        // Collect results
        let mut chunks = Vec::with_capacity(chunk_futures.len());
        for future in chunk_futures {
            let chunk_info = future.await
                .map_err(|e| StorageError::Backend {
                    message: format!("Chunk upload task failed: {}", e),
                    source: None,
                })??;
            chunks.push(chunk_info);
        }

        // Sort by index to ensure correct order
        chunks.sort_by_key(|c| c.index);

        Ok(ChunkManifest {
            id: Uuid::new_v4(),
            total_size,
            chunk_count: chunks.len(),
            chunk_size: self.chunk_size.as_bytes(),
            chunks,
            checksum: total_checksum,
            compression: self.compression,
            created_at: Utc::now(),
        })
    }

    /// Reassemble data from chunk manifest
    pub async fn retrieve(&self, manifest: &ChunkManifest) -> Result<Bytes, StorageError> {
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut chunk_futures = Vec::new();

        for chunk in &manifest.chunks {
            let cas = self.cas.clone();
            let hash = chunk.hash.clone();
            let index = chunk.index;
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let compression = manifest.compression;

            chunk_futures.push(tokio::spawn(async move {
                let _permit = permit;
                let mut data = cas.get(&hash).await?;

                // Decompress if needed
                if let Some(compression) = compression {
                    data = decompress(&data, compression)?;
                }

                Ok::<_, StorageError>((index, data))
            }));
        }

        // Collect and reassemble
        let mut chunk_data: Vec<(usize, Bytes)> = Vec::with_capacity(chunk_futures.len());
        for future in chunk_futures {
            let result = future.await
                .map_err(|e| StorageError::Backend {
                    message: format!("Chunk retrieval task failed: {}", e),
                    source: None,
                })??;
            chunk_data.push(result);
        }

        // Sort by index and concatenate
        chunk_data.sort_by_key(|(index, _)| *index);

        let mut assembled = BytesMut::with_capacity(manifest.total_size as usize);
        for (_, data) in chunk_data {
            assembled.extend_from_slice(&data);
        }

        let result = assembled.freeze();

        // Verify integrity
        let computed_checksum = Checksum::sha256(&result);
        if computed_checksum != manifest.checksum {
            return Err(StorageError::ChecksumMismatch {
                expected: manifest.checksum.to_hex(),
                actual: computed_checksum.to_hex(),
            });
        }

        Ok(result)
    }

    /// Stream chunks for memory-efficient retrieval
    pub fn stream(
        &self,
        manifest: &ChunkManifest,
    ) -> impl Stream<Item = Result<Bytes, StorageError>> + '_ {
        let chunks = manifest.chunks.clone();
        let compression = manifest.compression;

        futures::stream::iter(chunks)
            .then(move |chunk| {
                let cas = self.cas.clone();
                async move {
                    let mut data = cas.get(&chunk.hash).await?;
                    if let Some(comp) = compression {
                        data = decompress(&data, comp)?;
                    }
                    Ok(data)
                }
            })
    }

    fn compress(&self, data: &Bytes, compression: CompressionType) -> Result<Bytes, StorageError> {
        match compression {
            CompressionType::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                Ok(Bytes::from(encoder.finish()?))
            }
            CompressionType::Zstd => {
                let compressed = zstd::encode_all(data.as_ref(), 3)?;
                Ok(Bytes::from(compressed))
            }
            CompressionType::Lz4 => {
                let compressed = lz4::block::compress(data, None, true)?;
                Ok(Bytes::from(compressed))
            }
            _ => Ok(data.clone()),
        }
    }
}

fn decompress(data: &Bytes, compression: CompressionType) -> Result<Bytes, StorageError> {
    match compression {
        CompressionType::Gzip => {
            let mut decoder = GzDecoder::new(data.as_ref());
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(Bytes::from(decompressed))
        }
        CompressionType::Zstd => {
            let decompressed = zstd::decode_all(data.as_ref())?;
            Ok(Bytes::from(decompressed))
        }
        CompressionType::Lz4 => {
            let decompressed = lz4::block::decompress(data, None)?;
            Ok(Bytes::from(decompressed))
        }
        _ => Ok(data.clone()),
    }
}
```

---

## 5. Storage Cache Layer

```rust
// src/storage/cache.rs

use lru::LruCache;
use std::num::NonZeroUsize;

/// Caching layer wrapping a storage backend
pub struct CachedStorage {
    backend: Arc<dyn StorageBackend>,
    cache: Arc<RwLock<LruCache<StorageKey, CacheEntry>>>,
    config: CacheConfig,
    metrics: Arc<CacheMetrics>,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_size: ByteSize,
    pub max_entries: usize,
    pub ttl: Duration,
    pub mode: CacheMode,
}

#[derive(Debug, Clone, Copy)]
pub enum CacheMode {
    ReadThrough,   // Read from cache, fallback to backend
    WriteThrough,  // Write to both cache and backend
    WriteBack,     // Write to cache, async flush to backend
}

struct CacheEntry {
    data: Bytes,
    size: u64,
    inserted_at: Instant,
    last_accessed: Instant,
    dirty: bool,
}

impl CachedStorage {
    pub fn new(backend: Arc<dyn StorageBackend>, config: CacheConfig) -> Self {
        let cache = LruCache::new(
            NonZeroUsize::new(config.max_entries).unwrap()
        );

        Self {
            backend,
            cache: Arc::new(RwLock::new(cache)),
            config,
            metrics: Arc::new(CacheMetrics::new()),
        }
    }

    /// Invalidate a cache entry
    pub async fn invalidate(&self, key: &StorageKey) {
        let mut cache = self.cache.write().await;
        cache.pop(key);
    }

    /// Clear entire cache
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Flush dirty entries to backend (for WriteBack mode)
    pub async fn flush(&self) -> Result<(), StorageError> {
        if !matches!(self.config.mode, CacheMode::WriteBack) {
            return Ok(());
        }

        let dirty_entries: Vec<(StorageKey, Bytes)> = {
            let cache = self.cache.read().await;
            cache.iter()
                .filter(|(_, entry)| entry.dirty)
                .map(|(key, entry)| (key.clone(), entry.data.clone()))
                .collect()
        };

        for (key, data) in dirty_entries {
            self.backend.put(&key, data, PutOptions::default()).await?;

            // Mark as clean
            let mut cache = self.cache.write().await;
            if let Some(entry) = cache.get_mut(&key) {
                entry.dirty = false;
            }
        }

        Ok(())
    }

    fn is_expired(&self, entry: &CacheEntry) -> bool {
        entry.inserted_at.elapsed() > self.config.ttl
    }
}

#[async_trait]
impl StorageBackend for CachedStorage {
    async fn put(
        &self,
        key: &StorageKey,
        data: Bytes,
        options: PutOptions,
    ) -> Result<StorageReceipt, StorageError> {
        let size = data.len() as u64;

        match self.config.mode {
            CacheMode::WriteThrough => {
                // Write to backend first
                let receipt = self.backend.put(key, data.clone(), options).await?;

                // Then update cache
                let mut cache = self.cache.write().await;
                cache.put(key.clone(), CacheEntry {
                    data,
                    size,
                    inserted_at: Instant::now(),
                    last_accessed: Instant::now(),
                    dirty: false,
                });

                Ok(receipt)
            }
            CacheMode::WriteBack => {
                // Write to cache only, mark dirty
                let mut cache = self.cache.write().await;
                cache.put(key.clone(), CacheEntry {
                    data: data.clone(),
                    size,
                    inserted_at: Instant::now(),
                    last_accessed: Instant::now(),
                    dirty: true,
                });

                Ok(StorageReceipt {
                    key: key.clone(),
                    etag: "cached".to_string(),
                    version_id: None,
                    size,
                    checksum: Checksum::sha256(&data),
                    stored_at: Utc::now(),
                })
            }
            CacheMode::ReadThrough => {
                // Write directly to backend
                self.backend.put(key, data, options).await
            }
        }
    }

    async fn get(&self, key: &StorageKey) -> Result<Bytes, StorageError> {
        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(entry) = cache.get_mut(key) {
                if !self.is_expired(entry) {
                    entry.last_accessed = Instant::now();
                    self.metrics.record_hit();
                    return Ok(entry.data.clone());
                }
                // Entry expired, remove it
                cache.pop(key);
            }
        }

        self.metrics.record_miss();

        // Fetch from backend
        let data = self.backend.get(key).await?;

        // Populate cache
        {
            let mut cache = self.cache.write().await;
            cache.put(key.clone(), CacheEntry {
                data: data.clone(),
                size: data.len() as u64,
                inserted_at: Instant::now(),
                last_accessed: Instant::now(),
                dirty: false,
            });
        }

        Ok(data)
    }

    async fn delete(&self, key: &StorageKey) -> Result<(), StorageError> {
        // Remove from cache
        self.invalidate(key).await;

        // Delete from backend
        self.backend.delete(key).await
    }

    async fn exists(&self, key: &StorageKey) -> Result<bool, StorageError> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.peek(key) {
                if !self.is_expired(entry) {
                    return Ok(true);
                }
            }
        }

        // Check backend
        self.backend.exists(key).await
    }

    async fn head(&self, key: &StorageKey) -> Result<ObjectMetadata, StorageError> {
        self.backend.head(key).await
    }

    async fn list(
        &self,
        prefix: &str,
        options: ListOptions,
    ) -> Result<ListResult, StorageError> {
        // List always goes to backend
        self.backend.list(prefix, options).await
    }

    async fn get_stream(
        &self,
        key: &StorageKey,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>, StorageError> {
        // Streaming bypasses cache
        self.backend.get_stream(key).await
    }

    async fn put_stream(
        &self,
        key: &StorageKey,
        stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
        options: PutOptions,
    ) -> Result<StorageReceipt, StorageError> {
        // Streaming bypasses cache
        self.backend.put_stream(key, stream, options).await
    }

    async fn get_range(
        &self,
        key: &StorageKey,
        range: ByteRange,
    ) -> Result<Bytes, StorageError> {
        // Range requests bypass cache
        self.backend.get_range(key, range).await
    }

    async fn copy(
        &self,
        source: &StorageKey,
        destination: &StorageKey,
    ) -> Result<StorageReceipt, StorageError> {
        let receipt = self.backend.copy(source, destination).await?;

        // Invalidate destination in cache
        self.invalidate(destination).await;

        Ok(receipt)
    }

    async fn health_check(&self) -> Result<HealthStatus, StorageError> {
        self.backend.health_check().await
    }

    fn backend_type(&self) -> &'static str {
        "cached"
    }
}
```

---

## 6. Storage Factory and Configuration

```rust
// src/storage/factory.rs

pub struct StorageFactory;

impl StorageFactory {
    pub async fn create(config: StorageConfig) -> Result<Arc<dyn StorageBackend>, StorageError> {
        let backend: Arc<dyn StorageBackend> = match config.backend {
            BackendType::S3 => {
                let s3_config = config.s3.ok_or(StorageError::Configuration {
                    message: "S3 config required".into(),
                })?;
                Arc::new(S3StorageBackend::new(s3_config).await?)
            }
            BackendType::Azure => {
                let azure_config = config.azure.ok_or(StorageError::Configuration {
                    message: "Azure config required".into(),
                })?;
                Arc::new(AzureStorageBackend::new(azure_config).await?)
            }
            BackendType::GCS => {
                let gcs_config = config.gcs.ok_or(StorageError::Configuration {
                    message: "GCS config required".into(),
                })?;
                Arc::new(GCSStorageBackend::new(gcs_config).await?)
            }
            BackendType::Local => {
                let local_config = config.local.ok_or(StorageError::Configuration {
                    message: "Local config required".into(),
                })?;
                Arc::new(LocalStorageBackend::new(local_config)?)
            }
        };

        // Wrap with cache if configured
        let backend = if let Some(cache_config) = config.cache {
            Arc::new(CachedStorage::new(backend, cache_config))
        } else {
            backend
        };

        Ok(backend)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub backend: BackendType,
    pub s3: Option<S3Config>,
    pub azure: Option<AzureConfig>,
    pub gcs: Option<GCSConfig>,
    pub local: Option<LocalConfig>,
    pub cache: Option<CacheConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum BackendType {
    S3,
    Azure,
    GCS,
    Local,
}
```

---

## Summary

This document defines the storage layer for LLM-Data-Vault:

| Component | Purpose |
|-----------|---------|
| **StorageBackend Trait** | Abstract interface for all storage operations |
| **S3StorageBackend** | AWS S3 / MinIO implementation with multipart upload |
| **ContentAddressableStore** | Deduplication via content hashing |
| **ChunkManager** | Large file handling with parallel chunk operations |
| **CachedStorage** | LRU cache layer with multiple caching modes |
| **StorageFactory** | Configuration-driven backend instantiation |

**Key Features:**
- Pluggable backend architecture
- Automatic deduplication
- Parallel operations with semaphore control
- Integrity verification at every layer
- Streaming support for large files
- Configurable caching

---

*Next Document: [03-encryption-security.md](./03-encryption-security.md)*
