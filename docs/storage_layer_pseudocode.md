# LLM-Data-Vault Storage Layer - Production-Ready Pseudocode

## Core Types and Error Handling

```rust
//==============================================================================
// ERROR TYPES
//==============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum StorageErrorKind {
    NotFound,
    PermissionDenied,
    InvalidKey,
    IntegrityCheckFailed,
    NetworkError,
    BackendError,
    ConfigurationError,
    SerializationError,
    ChunkingError,
    CacheError,
    QuotaExceeded,
    Timeout,
}

#[derive(Debug)]
struct StorageError {
    kind: StorageErrorKind,
    message: String,
    source: Option<Box<dyn Error + Send + Sync>>,
    context: HashMap<String, String>,
    retry_after: Option<Duration>,
}

impl StorageError {
    fn new(kind: StorageErrorKind, message: impl Into<String>) -> Self;
    fn with_source(self, source: impl Error + Send + Sync + 'static) -> Self;
    fn with_context(self, key: impl Into<String>, value: impl Into<String>) -> Self;
    fn with_retry_after(self, duration: Duration) -> Self;
    fn is_retryable(&self) -> bool;
}

type Result<T> = std::result::Result<T, StorageError>;

//==============================================================================
// CORE TYPES
//==============================================================================

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct StorageKey {
    // Content-addressable hash (SHA-256)
    hash: Hash256,
    // Optional logical path for human-readable organization
    path: Option<String>,
    // Namespace for multi-tenancy
    namespace: String,
}

impl StorageKey {
    fn new(namespace: impl Into<String>, hash: Hash256) -> Self;
    fn with_path(self, path: impl Into<String>) -> Self;
    fn from_content(namespace: impl Into<String>, content: &[u8]) -> Self;
    fn to_backend_key(&self, backend_type: BackendType) -> String;
}

#[derive(Debug, Clone)]
struct Hash256([u8; 32]);

impl Hash256 {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
    fn from_hex(hex: &str) -> Result<Self>;
    fn to_hex(&self) -> String;
    fn as_bytes(&self) -> &[u8];
}

#[derive(Debug, Clone)]
struct StorageReceipt {
    key: StorageKey,
    size_bytes: u64,
    content_hash: Hash256,
    etag: Option<String>,
    version_id: Option<String>,
    uploaded_at: DateTime<Utc>,
    backend_metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct ObjectMetadata {
    key: StorageKey,
    size_bytes: u64,
    content_type: Option<String>,
    content_hash: Hash256,
    created_at: DateTime<Utc>,
    last_modified: DateTime<Utc>,
    custom_metadata: HashMap<String, String>,
    encryption_info: Option<EncryptionInfo>,
}

#[derive(Debug, Clone)]
struct EncryptionInfo {
    algorithm: String,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ListOptions {
    max_keys: Option<usize>,
    continuation_token: Option<String>,
    include_metadata: bool,
}

struct StorageIterator {
    // Internal stream of object listings
    inner: Pin<Box<dyn Stream<Item = Result<ObjectMetadata>> + Send>>,
}

impl StorageIterator {
    async fn next(&mut self) -> Option<Result<ObjectMetadata>>;
    fn into_stream(self) -> impl Stream<Item = Result<ObjectMetadata>>;
}

//==============================================================================
// STORAGE BACKEND TRAIT
//==============================================================================

#[async_trait]
trait StorageBackend: Send + Sync {
    /// Store data with the given key
    async fn put(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt>;

    /// Store data with custom metadata
    async fn put_with_metadata(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        metadata: HashMap<String, String>,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt>;

    /// Retrieve data for the given key
    async fn get(&self, key: &StorageKey) -> Result<Box<dyn AsyncRead + Send + Unpin>>;

    /// Retrieve a specific byte range
    async fn get_range(
        &self,
        key: &StorageKey,
        range: Range<u64>,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>>;

    /// Delete object
    async fn delete(&self, key: &StorageKey) -> Result<()>;

    /// Check if object exists
    async fn exists(&self, key: &StorageKey) -> Result<bool>;

    /// List objects with prefix
    async fn list(&self, prefix: &str, options: ListOptions) -> Result<StorageIterator>;

    /// Get object metadata without downloading content
    async fn get_metadata(&self, key: &StorageKey) -> Result<ObjectMetadata>;

    /// Copy object within the same backend
    async fn copy(&self, source: &StorageKey, dest: &StorageKey) -> Result<StorageReceipt>;

    /// Health check
    async fn health_check(&self) -> Result<HealthStatus>;

    /// Get backend metrics
    fn get_metrics(&self) -> BackendMetrics;

    /// Backend type identifier
    fn backend_type(&self) -> BackendType;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendType {
    S3,
    AzureBlob,
    GCS,
    MinIO,
    LocalFilesystem,
}

#[derive(Debug, Clone)]
struct HealthStatus {
    healthy: bool,
    latency_ms: Option<u64>,
    last_error: Option<String>,
    checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
struct BackendMetrics {
    total_requests: u64,
    failed_requests: u64,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    avg_latency_ms: f64,
    cache_hits: u64,
    cache_misses: u64,
}

//==============================================================================
// STORAGE CONFIGURATION
//==============================================================================

#[derive(Debug, Clone)]
struct StorageConfig {
    backend: BackendConfig,
    retry_policy: RetryPolicy,
    timeout_config: TimeoutConfig,
    chunk_config: ChunkConfig,
    cache_config: Option<CacheConfig>,
    encryption_config: Option<EncryptionConfig>,
    compression_config: Option<CompressionConfig>,
}

#[derive(Debug, Clone)]
enum BackendConfig {
    S3(S3Config),
    AzureBlob(AzureBlobConfig),
    GCS(GCSConfig),
    MinIO(MinIOConfig),
    LocalFilesystem(LocalFilesystemConfig),
}

#[derive(Debug, Clone)]
struct S3Config {
    region: String,
    bucket: String,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    endpoint: Option<String>, // For S3-compatible services
    use_path_style: bool,     // For MinIO compatibility
    server_side_encryption: Option<S3Encryption>,
    connection_pool_size: usize,
    multipart_threshold: u64, // Default: 5MB
    multipart_chunk_size: u64, // Default: 8MB
}

#[derive(Debug, Clone)]
enum S3Encryption {
    AES256,
    KMS { key_id: Option<String> },
}

#[derive(Debug, Clone)]
struct AzureBlobConfig {
    account_name: String,
    account_key: Option<String>,
    container_name: String,
    endpoint: Option<String>,
    connection_pool_size: usize,
}

#[derive(Debug, Clone)]
struct GCSConfig {
    project_id: String,
    bucket: String,
    credentials_path: Option<PathBuf>,
    endpoint: Option<String>,
    connection_pool_size: usize,
}

#[derive(Debug, Clone)]
struct MinIOConfig {
    endpoint: String,
    access_key: String,
    secret_key: String,
    bucket: String,
    region: Option<String>,
    use_ssl: bool,
    connection_pool_size: usize,
}

#[derive(Debug, Clone)]
struct LocalFilesystemConfig {
    root_path: PathBuf,
    create_dirs: bool,
    sync_on_write: bool,
}

#[derive(Debug, Clone)]
struct RetryPolicy {
    max_retries: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    backoff_multiplier: f64,
    jitter: bool,
    retryable_errors: Vec<StorageErrorKind>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
            retryable_errors: vec![
                StorageErrorKind::NetworkError,
                StorageErrorKind::Timeout,
            ],
        }
    }
}

#[derive(Debug, Clone)]
struct TimeoutConfig {
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(300),
            write_timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Clone)]
struct ChunkConfig {
    chunk_size: u64,           // Default: 64MB
    min_chunk_threshold: u64,  // Don't chunk files smaller than this
    max_parallel_chunks: usize, // Default: 4
    verify_chunks: bool,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            chunk_size: 64 * 1024 * 1024, // 64MB
            min_chunk_threshold: 128 * 1024 * 1024, // 128MB
            max_parallel_chunks: 4,
            verify_chunks: true,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheConfig {
    max_size_bytes: u64,
    eviction_policy: EvictionPolicy,
    write_mode: CacheWriteMode,
    ttl: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
enum EvictionPolicy {
    LRU,
    LFU,
    FIFO,
}

#[derive(Debug, Clone, Copy)]
enum CacheWriteMode {
    WriteThrough,
    WriteBack { flush_interval: Duration },
}

#[derive(Debug, Clone)]
struct EncryptionConfig {
    algorithm: EncryptionAlgorithm,
    key_provider: KeyProvider,
}

#[derive(Debug, Clone)]
enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone)]
enum KeyProvider {
    Static { key: Vec<u8> },
    KMS { key_id: String, endpoint: String },
    EnvVar { var_name: String },
}

#[derive(Debug, Clone)]
struct CompressionConfig {
    algorithm: CompressionAlgorithm,
    level: u32,
    min_size_threshold: u64, // Don't compress files smaller than this
}

#[derive(Debug, Clone, Copy)]
enum CompressionAlgorithm {
    Gzip,
    Zstd,
    Lz4,
}

//==============================================================================
// S3 STORAGE BACKEND IMPLEMENTATION
//==============================================================================

struct S3StorageBackend {
    config: S3Config,
    client: S3Client,
    connection_pool: ConnectionPool,
    retry_policy: RetryPolicy,
    timeout_config: TimeoutConfig,
    metrics: Arc<RwLock<BackendMetrics>>,
}

impl S3StorageBackend {
    async fn new(config: S3Config, retry_policy: RetryPolicy, timeout_config: TimeoutConfig) -> Result<Self> {
        // Initialize S3 client with connection pooling
        let http_client = Self::create_http_client(&config, &timeout_config)?;

        let credentials_provider = if let (Some(access_key), Some(secret_key)) =
            (&config.access_key_id, &config.secret_access_key) {
            StaticCredentialsProvider::new(access_key, secret_key)
        } else {
            // Use default credential chain (environment, instance profile, etc.)
            DefaultCredentialsProvider::new().await?
        };

        let region = Region::new(&config.region);

        let s3_config_builder = aws_sdk_s3::Config::builder()
            .region(region)
            .credentials_provider(credentials_provider)
            .http_client(http_client.clone());

        // Apply custom endpoint for MinIO/S3-compatible services
        let s3_config_builder = if let Some(endpoint) = &config.endpoint {
            s3_config_builder.endpoint_url(endpoint)
        } else {
            s3_config_builder
        };

        // Apply path-style addressing if needed
        let s3_config_builder = if config.use_path_style {
            s3_config_builder.force_path_style(true)
        } else {
            s3_config_builder
        };

        let s3_config = s3_config_builder.build();
        let client = S3Client::from_conf(s3_config);

        Ok(Self {
            config,
            client,
            connection_pool: ConnectionPool::new(config.connection_pool_size),
            retry_policy,
            timeout_config,
            metrics: Arc::new(RwLock::new(BackendMetrics::default())),
        })
    }

    fn create_http_client(config: &S3Config, timeout_config: &TimeoutConfig) -> Result<HttpClient> {
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        let http_client = HyperClientBuilder::new()
            .pool_max_idle_per_host(config.connection_pool_size)
            .pool_idle_timeout(Duration::from_secs(30))
            .connect_timeout(timeout_config.connect_timeout)
            .read_timeout(timeout_config.read_timeout)
            .build(connector);

        Ok(http_client)
    }

    async fn put_small_object(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<StorageReceipt> {
        let backend_key = key.to_backend_key(BackendType::S3);

        // Read entire content into memory for small objects
        let mut buffer = Vec::new();
        let mut reader = BufReader::new(data);
        reader.read_to_end(&mut buffer).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to read data")
                .with_source(e))?;

        let content_hash = Hash256::from_bytes(&Self::compute_sha256(&buffer))?;

        let mut put_object_request = self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&backend_key)
            .body(ByteStream::from(buffer.clone()));

        // Add metadata
        if let Some(meta) = metadata {
            for (k, v) in meta {
                put_object_request = put_object_request.metadata(k, v);
            }
        }

        // Add content hash as metadata
        put_object_request = put_object_request
            .metadata("content-hash", content_hash.to_hex());

        // Apply server-side encryption
        put_object_request = self.apply_encryption(put_object_request);

        // Execute with retry
        let output = self.retry_operation(|| async {
            put_object_request.clone().send().await
                .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "S3 PutObject failed")
                    .with_source(e))
        }).await?;

        self.update_metrics(|m| {
            m.total_requests += 1;
            m.bytes_uploaded += buffer.len() as u64;
        });

        Ok(StorageReceipt {
            key: key.clone(),
            size_bytes: buffer.len() as u64,
            content_hash,
            etag: output.e_tag().map(String::from),
            version_id: output.version_id().map(String::from),
            uploaded_at: Utc::now(),
            backend_metadata: HashMap::new(),
        })
    }

    async fn put_multipart_object(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<StorageReceipt> {
        let backend_key = key.to_backend_key(BackendType::S3);

        // Initiate multipart upload
        let mut create_request = self.client
            .create_multipart_upload()
            .bucket(&self.config.bucket)
            .key(&backend_key);

        if let Some(meta) = &metadata {
            for (k, v) in meta {
                create_request = create_request.metadata(k.clone(), v.clone());
            }
        }

        create_request = self.apply_encryption_multipart(create_request);

        let create_output = self.retry_operation(|| async {
            create_request.clone().send().await
                .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to create multipart upload")
                    .with_source(e))
        }).await?;

        let upload_id = create_output.upload_id()
            .ok_or_else(|| StorageError::new(StorageErrorKind::BackendError, "No upload ID returned"))?;

        // Upload parts
        let mut reader = BufReader::new(data);
        let mut part_number = 1;
        let mut completed_parts = Vec::new();
        let mut total_bytes = 0u64;
        let mut hasher = Sha256::new();

        loop {
            let mut chunk = vec![0u8; self.config.multipart_chunk_size as usize];
            let mut bytes_read = 0;

            // Read one chunk
            while bytes_read < chunk.len() {
                match reader.read(&mut chunk[bytes_read..]).await {
                    Ok(0) => break, // EOF
                    Ok(n) => bytes_read += n,
                    Err(e) => {
                        // Abort multipart upload on error
                        let _ = self.abort_multipart_upload(&backend_key, upload_id).await;
                        return Err(StorageError::new(StorageErrorKind::BackendError, "Failed to read chunk")
                            .with_source(e));
                    }
                }
            }

            if bytes_read == 0 {
                break; // No more data
            }

            chunk.truncate(bytes_read);
            hasher.update(&chunk);
            total_bytes += bytes_read as u64;

            // Upload part with retry
            let upload_result = self.retry_operation(|| {
                let chunk_clone = chunk.clone();
                let backend_key = backend_key.clone();
                let upload_id = upload_id.to_string();

                async move {
                    self.client
                        .upload_part()
                        .bucket(&self.config.bucket)
                        .key(&backend_key)
                        .upload_id(&upload_id)
                        .part_number(part_number)
                        .body(ByteStream::from(chunk_clone))
                        .send()
                        .await
                        .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to upload part")
                            .with_source(e))
                }
            }).await;

            match upload_result {
                Ok(output) => {
                    completed_parts.push(CompletedPart {
                        part_number: Some(part_number),
                        e_tag: output.e_tag().map(String::from),
                    });
                    part_number += 1;
                }
                Err(e) => {
                    // Abort multipart upload on error
                    let _ = self.abort_multipart_upload(&backend_key, upload_id).await;
                    return Err(e);
                }
            }
        }

        // Complete multipart upload
        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        let complete_output = self.retry_operation(|| async {
            self.client
                .complete_multipart_upload()
                .bucket(&self.config.bucket)
                .key(&backend_key)
                .upload_id(upload_id)
                .multipart_upload(completed_upload.clone())
                .send()
                .await
                .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to complete multipart upload")
                    .with_source(e))
        }).await?;

        let content_hash = Hash256::from_bytes(&hasher.finalize())?;

        self.update_metrics(|m| {
            m.total_requests += part_number as u64;
            m.bytes_uploaded += total_bytes;
        });

        Ok(StorageReceipt {
            key: key.clone(),
            size_bytes: total_bytes,
            content_hash,
            etag: complete_output.e_tag().map(String::from),
            version_id: complete_output.version_id().map(String::from),
            uploaded_at: Utc::now(),
            backend_metadata: HashMap::new(),
        })
    }

    async fn abort_multipart_upload(&self, key: &str, upload_id: &str) -> Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to abort multipart upload")
                .with_source(e))?;
        Ok(())
    }

    fn apply_encryption(&self, request: PutObjectFluentBuilder) -> PutObjectFluentBuilder {
        match &self.config.server_side_encryption {
            Some(S3Encryption::AES256) => {
                request.server_side_encryption(ServerSideEncryption::Aes256)
            }
            Some(S3Encryption::KMS { key_id }) => {
                let mut req = request.server_side_encryption(ServerSideEncryption::AwsKms);
                if let Some(kid) = key_id {
                    req = req.ssekms_key_id(kid);
                }
                req
            }
            None => request,
        }
    }

    fn apply_encryption_multipart(&self, request: CreateMultipartUploadFluentBuilder) -> CreateMultipartUploadFluentBuilder {
        match &self.config.server_side_encryption {
            Some(S3Encryption::AES256) => {
                request.server_side_encryption(ServerSideEncryption::Aes256)
            }
            Some(S3Encryption::KMS { key_id }) => {
                let mut req = request.server_side_encryption(ServerSideEncryption::AwsKms);
                if let Some(kid) = key_id {
                    req = req.ssekms_key_id(kid);
                }
                req
            }
            None => request,
        }
    }

    async fn retry_operation<F, Fut, T>(&self, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        let mut backoff = self.retry_policy.initial_backoff;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) if attempt >= self.retry_policy.max_retries || !e.is_retryable() => {
                    self.update_metrics(|m| m.failed_requests += 1);
                    return Err(e);
                }
                Err(_) => {
                    attempt += 1;

                    // Apply jitter if configured
                    let actual_backoff = if self.retry_policy.jitter {
                        let jitter = rand::random::<f64>() * 0.3; // +/- 30%
                        Duration::from_secs_f64(backoff.as_secs_f64() * (1.0 + jitter - 0.15))
                    } else {
                        backoff
                    };

                    sleep(actual_backoff).await;

                    // Exponential backoff
                    backoff = std::cmp::min(
                        Duration::from_secs_f64(backoff.as_secs_f64() * self.retry_policy.backoff_multiplier),
                        self.retry_policy.max_backoff,
                    );
                }
            }
        }
    }

    fn compute_sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn update_metrics<F>(&self, f: F)
    where
        F: FnOnce(&mut BackendMetrics),
    {
        if let Ok(mut metrics) = self.metrics.write() {
            f(&mut metrics);
        }
    }
}

#[async_trait]
impl StorageBackend for S3StorageBackend {
    async fn put(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt> {
        self.put_with_metadata(key, data, HashMap::new(), size_hint).await
    }

    async fn put_with_metadata(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        metadata: HashMap<String, String>,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt> {
        let should_multipart = size_hint
            .map(|size| size >= self.config.multipart_threshold)
            .unwrap_or(false);

        if should_multipart {
            self.put_multipart_object(key, data, size_hint, Some(metadata)).await
        } else {
            self.put_small_object(key, data, Some(metadata)).await
        }
    }

    async fn get(&self, key: &StorageKey) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let backend_key = key.to_backend_key(BackendType::S3);

        let output = self.retry_operation(|| async {
            self.client
                .get_object()
                .bucket(&self.config.bucket)
                .key(&backend_key)
                .send()
                .await
                .map_err(|e| {
                    if e.is_no_such_key() {
                        StorageError::new(StorageErrorKind::NotFound, "Object not found")
                            .with_context("key", backend_key.clone())
                    } else {
                        StorageError::new(StorageErrorKind::BackendError, "S3 GetObject failed")
                            .with_source(e)
                    }
                })
        }).await?;

        self.update_metrics(|m| {
            m.total_requests += 1;
            if let Some(len) = output.content_length() {
                m.bytes_downloaded += len as u64;
            }
        });

        Ok(Box::new(output.body.into_async_read()))
    }

    async fn get_range(
        &self,
        key: &StorageKey,
        range: Range<u64>,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let backend_key = key.to_backend_key(BackendType::S3);
        let range_header = format!("bytes={}-{}", range.start, range.end - 1);

        let output = self.retry_operation(|| async {
            self.client
                .get_object()
                .bucket(&self.config.bucket)
                .key(&backend_key)
                .range(&range_header)
                .send()
                .await
                .map_err(|e| {
                    if e.is_no_such_key() {
                        StorageError::new(StorageErrorKind::NotFound, "Object not found")
                            .with_context("key", backend_key.clone())
                    } else {
                        StorageError::new(StorageErrorKind::BackendError, "S3 GetObject failed")
                            .with_source(e)
                    }
                })
        }).await?;

        self.update_metrics(|m| {
            m.total_requests += 1;
            m.bytes_downloaded += (range.end - range.start);
        });

        Ok(Box::new(output.body.into_async_read()))
    }

    async fn delete(&self, key: &StorageKey) -> Result<()> {
        let backend_key = key.to_backend_key(BackendType::S3);

        self.retry_operation(|| async {
            self.client
                .delete_object()
                .bucket(&self.config.bucket)
                .key(&backend_key)
                .send()
                .await
                .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "S3 DeleteObject failed")
                    .with_source(e))
        }).await?;

        self.update_metrics(|m| m.total_requests += 1);
        Ok(())
    }

    async fn exists(&self, key: &StorageKey) -> Result<bool> {
        let backend_key = key.to_backend_key(BackendType::S3);

        let result = self.retry_operation(|| async {
            self.client
                .head_object()
                .bucket(&self.config.bucket)
                .key(&backend_key)
                .send()
                .await
        }).await;

        self.update_metrics(|m| m.total_requests += 1);

        match result {
            Ok(_) => Ok(true),
            Err(e) if e.kind == StorageErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn list(&self, prefix: &str, options: ListOptions) -> Result<StorageIterator> {
        let bucket = self.config.bucket.clone();
        let client = self.client.clone();
        let prefix = prefix.to_string();

        let stream = stream::unfold(
            (Some(options.continuation_token), false),
            move |(continuation_token, done)| {
                let bucket = bucket.clone();
                let client = client.clone();
                let prefix = prefix.clone();
                let max_keys = options.max_keys;

                async move {
                    if done {
                        return None;
                    }

                    let mut request = client
                        .list_objects_v2()
                        .bucket(&bucket)
                        .prefix(&prefix);

                    if let Some(token) = continuation_token {
                        request = request.continuation_token(token);
                    }

                    if let Some(max) = max_keys {
                        request = request.max_keys(max as i32);
                    }

                    match request.send().await {
                        Ok(output) => {
                            let objects = output.contents().unwrap_or_default();
                            let next_token = output.next_continuation_token().map(String::from);
                            let is_truncated = output.is_truncated().unwrap_or(false);

                            let items: Vec<_> = objects.iter().map(|obj| {
                                // Parse StorageKey from backend key
                                let key_str = obj.key().unwrap_or_default();
                                // Implementation would parse the key format

                                Ok(ObjectMetadata {
                                    key: StorageKey::new("default", Hash256::from_hex(&key_str)?),
                                    size_bytes: obj.size() as u64,
                                    content_type: None,
                                    content_hash: Hash256::from_hex(&key_str)?,
                                    created_at: obj.last_modified()
                                        .map(|dt| DateTime::from(dt))
                                        .unwrap_or_else(Utc::now),
                                    last_modified: obj.last_modified()
                                        .map(|dt| DateTime::from(dt))
                                        .unwrap_or_else(Utc::now),
                                    custom_metadata: HashMap::new(),
                                    encryption_info: None,
                                })
                            }).collect();

                            Some((
                                stream::iter(items),
                                (next_token, !is_truncated),
                            ))
                        }
                        Err(e) => {
                            let error = StorageError::new(
                                StorageErrorKind::BackendError,
                                "S3 ListObjects failed"
                            ).with_source(e);
                            Some((
                                stream::iter(vec![Err(error)]),
                                (None, true),
                            ))
                        }
                    }
                }
            },
        ).flatten();

        Ok(StorageIterator {
            inner: Box::pin(stream),
        })
    }

    async fn get_metadata(&self, key: &StorageKey) -> Result<ObjectMetadata> {
        let backend_key = key.to_backend_key(BackendType::S3);

        let output = self.retry_operation(|| async {
            self.client
                .head_object()
                .bucket(&self.config.bucket)
                .key(&backend_key)
                .send()
                .await
                .map_err(|e| {
                    if e.is_no_such_key() {
                        StorageError::new(StorageErrorKind::NotFound, "Object not found")
                            .with_context("key", backend_key.clone())
                    } else {
                        StorageError::new(StorageErrorKind::BackendError, "S3 HeadObject failed")
                            .with_source(e)
                    }
                })
        }).await?;

        self.update_metrics(|m| m.total_requests += 1);

        let content_hash = output.metadata()
            .and_then(|m| m.get("content-hash"))
            .and_then(|h| Hash256::from_hex(h).ok())
            .unwrap_or_else(|| key.hash.clone());

        Ok(ObjectMetadata {
            key: key.clone(),
            size_bytes: output.content_length() as u64,
            content_type: output.content_type().map(String::from),
            content_hash,
            created_at: output.last_modified()
                .map(|dt| DateTime::from(dt))
                .unwrap_or_else(Utc::now),
            last_modified: output.last_modified()
                .map(|dt| DateTime::from(dt))
                .unwrap_or_else(Utc::now),
            custom_metadata: output.metadata()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default(),
            encryption_info: output.server_side_encryption()
                .map(|alg| EncryptionInfo {
                    algorithm: format!("{:?}", alg),
                    key_id: output.ssekms_key_id().map(String::from),
                }),
        })
    }

    async fn copy(&self, source: &StorageKey, dest: &StorageKey) -> Result<StorageReceipt> {
        let source_key = source.to_backend_key(BackendType::S3);
        let dest_key = dest.to_backend_key(BackendType::S3);
        let copy_source = format!("{}/{}", self.config.bucket, source_key);

        let output = self.retry_operation(|| async {
            self.client
                .copy_object()
                .bucket(&self.config.bucket)
                .key(&dest_key)
                .copy_source(&copy_source)
                .send()
                .await
                .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "S3 CopyObject failed")
                    .with_source(e))
        }).await?;

        // Get metadata to create receipt
        let metadata = self.get_metadata(dest).await?;

        Ok(StorageReceipt {
            key: dest.clone(),
            size_bytes: metadata.size_bytes,
            content_hash: metadata.content_hash,
            etag: output.copy_object_result()
                .and_then(|r| r.e_tag())
                .map(String::from),
            version_id: output.version_id().map(String::from),
            uploaded_at: Utc::now(),
            backend_metadata: HashMap::new(),
        })
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let start = Instant::now();

        let result = timeout(
            Duration::from_secs(5),
            self.client.list_buckets().send()
        ).await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(_)) => Ok(HealthStatus {
                healthy: true,
                latency_ms: Some(latency_ms),
                last_error: None,
                checked_at: Utc::now(),
            }),
            Ok(Err(e)) => Ok(HealthStatus {
                healthy: false,
                latency_ms: Some(latency_ms),
                last_error: Some(format!("{:?}", e)),
                checked_at: Utc::now(),
            }),
            Err(_) => Ok(HealthStatus {
                healthy: false,
                latency_ms: None,
                last_error: Some("Health check timeout".to_string()),
                checked_at: Utc::now(),
            }),
        }
    }

    fn get_metrics(&self) -> BackendMetrics {
        self.metrics.read()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    fn backend_type(&self) -> BackendType {
        BackendType::S3
    }
}

//==============================================================================
// CONTENT-ADDRESSABLE STORAGE
//==============================================================================

struct ContentAddressableStore {
    backend: Arc<dyn StorageBackend>,
    namespace: String,
    verification_enabled: bool,
    deduplication_enabled: bool,
    metrics: Arc<RwLock<CASMetrics>>,
}

#[derive(Debug, Clone, Default)]
struct CASMetrics {
    deduplicated_bytes: u64,
    integrity_checks_passed: u64,
    integrity_checks_failed: u64,
}

impl ContentAddressableStore {
    fn new(
        backend: Arc<dyn StorageBackend>,
        namespace: impl Into<String>,
        verification_enabled: bool,
        deduplication_enabled: bool,
    ) -> Self {
        Self {
            backend,
            namespace: namespace.into(),
            verification_enabled,
            deduplication_enabled,
            metrics: Arc::new(RwLock::new(CASMetrics::default())),
        }
    }

    async fn store(&self, data: impl AsyncRead + Send + Unpin) -> Result<StorageReceipt> {
        // Read and hash the data
        let mut buffer = Vec::new();
        let mut reader = BufReader::new(data);
        reader.read_to_end(&mut buffer).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to read data")
                .with_source(e))?;

        let content_hash = Self::compute_content_hash(&buffer);
        let key = StorageKey::new(&self.namespace, content_hash.clone());

        // Check for existing object if deduplication is enabled
        if self.deduplication_enabled {
            if self.backend.exists(&key).await? {
                // Object already exists, return existing receipt
                let metadata = self.backend.get_metadata(&key).await?;

                self.update_metrics(|m| m.deduplicated_bytes += buffer.len() as u64);

                return Ok(StorageReceipt {
                    key,
                    size_bytes: metadata.size_bytes,
                    content_hash,
                    etag: None,
                    version_id: None,
                    uploaded_at: metadata.last_modified,
                    backend_metadata: HashMap::new(),
                });
            }
        }

        // Store the object
        let reader = Cursor::new(buffer.clone());
        let mut metadata = HashMap::new();
        metadata.insert("content-addressable".to_string(), "true".to_string());
        metadata.insert("sha256".to_string(), content_hash.to_hex());

        self.backend.put_with_metadata(&key, reader, metadata, Some(buffer.len() as u64)).await
    }

    async fn retrieve(&self, hash: &Hash256) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let key = StorageKey::new(&self.namespace, hash.clone());
        let mut reader = self.backend.get(&key).await?;

        if !self.verification_enabled {
            return Ok(reader);
        }

        // Read and verify content hash
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to read data")
                .with_source(e))?;

        let computed_hash = Self::compute_content_hash(&buffer);

        if &computed_hash != hash {
            self.update_metrics(|m| m.integrity_checks_failed += 1);
            return Err(StorageError::new(
                StorageErrorKind::IntegrityCheckFailed,
                format!("Content hash mismatch: expected {}, got {}", hash.to_hex(), computed_hash.to_hex())
            ));
        }

        self.update_metrics(|m| m.integrity_checks_passed += 1);

        Ok(Box::new(Cursor::new(buffer)))
    }

    async fn exists(&self, hash: &Hash256) -> Result<bool> {
        let key = StorageKey::new(&self.namespace, hash.clone());
        self.backend.exists(&key).await
    }

    async fn delete(&self, hash: &Hash256) -> Result<()> {
        let key = StorageKey::new(&self.namespace, hash.clone());
        self.backend.delete(&key).await
    }

    fn compute_content_hash(data: &[u8]) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Hash256::from_bytes(&hasher.finalize()).expect("SHA-256 should always produce 32 bytes")
    }

    fn update_metrics<F>(&self, f: F)
    where
        F: FnOnce(&mut CASMetrics),
    {
        if let Ok(mut metrics) = self.metrics.write() {
            f(&mut metrics);
        }
    }

    fn get_metrics(&self) -> CASMetrics {
        self.metrics.read()
            .map(|m| m.clone())
            .unwrap_or_default()
    }
}

//==============================================================================
// CHUNKED STORAGE MANAGER
//==============================================================================

struct ChunkManager {
    backend: Arc<dyn StorageBackend>,
    config: ChunkConfig,
    namespace: String,
    metrics: Arc<RwLock<ChunkMetrics>>,
}

#[derive(Debug, Clone, Default)]
struct ChunkMetrics {
    total_chunks_uploaded: u64,
    total_chunks_downloaded: u64,
    parallel_upload_count: u64,
    chunk_verification_failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkManifest {
    object_id: String,
    total_size: u64,
    chunk_size: u64,
    chunks: Vec<ChunkInfo>,
    content_hash: Hash256,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkInfo {
    index: u64,
    offset: u64,
    size: u64,
    hash: Hash256,
    storage_key: StorageKey,
}

impl ChunkManager {
    fn new(
        backend: Arc<dyn StorageBackend>,
        config: ChunkConfig,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            config,
            namespace: namespace.into(),
            metrics: Arc::new(RwLock::new(ChunkMetrics::default())),
        }
    }

    async fn store_chunked(
        &self,
        object_id: impl Into<String>,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<ChunkManifest> {
        let object_id = object_id.into();

        // Determine if we should chunk
        let should_chunk = size_hint
            .map(|size| size >= self.config.min_chunk_threshold)
            .unwrap_or(false);

        if !should_chunk {
            // Store as single object
            return self.store_single_chunk(object_id, data, size_hint).await;
        }

        // Chunk and upload in parallel
        let mut reader = BufReader::new(data);
        let mut chunks = Vec::new();
        let mut chunk_index = 0u64;
        let mut total_offset = 0u64;
        let mut overall_hasher = Sha256::new();

        // Create semaphore for limiting parallel uploads
        let semaphore = Arc::new(Semaphore::new(self.config.max_parallel_chunks));
        let mut upload_tasks = Vec::new();

        loop {
            // Read one chunk
            let mut chunk_buffer = vec![0u8; self.config.chunk_size as usize];
            let mut bytes_read = 0;

            while bytes_read < chunk_buffer.len() {
                match reader.read(&mut chunk_buffer[bytes_read..]).await {
                    Ok(0) => break, // EOF
                    Ok(n) => bytes_read += n,
                    Err(e) => {
                        return Err(StorageError::new(
                            StorageErrorKind::ChunkingError,
                            "Failed to read chunk"
                        ).with_source(e));
                    }
                }
            }

            if bytes_read == 0 {
                break; // No more data
            }

            chunk_buffer.truncate(bytes_read);
            overall_hasher.update(&chunk_buffer);

            // Compute chunk hash
            let chunk_hash = Self::compute_chunk_hash(&chunk_buffer);

            // Create storage key for chunk
            let chunk_key = StorageKey::new(
                format!("{}/chunks", self.namespace),
                chunk_hash.clone()
            ).with_path(format!("{}/chunk_{:06}", object_id, chunk_index));

            let chunk_info = ChunkInfo {
                index: chunk_index,
                offset: total_offset,
                size: bytes_read as u64,
                hash: chunk_hash,
                storage_key: chunk_key.clone(),
            };

            chunks.push(chunk_info.clone());

            // Upload chunk in parallel
            let backend = self.backend.clone();
            let semaphore = semaphore.clone();
            let verify_enabled = self.config.verify_chunks;

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let reader = Cursor::new(chunk_buffer.clone());
                let mut metadata = HashMap::new();
                metadata.insert("chunk-index".to_string(), chunk_index.to_string());
                metadata.insert("chunk-hash".to_string(), chunk_info.hash.to_hex());

                backend.put_with_metadata(
                    &chunk_key,
                    reader,
                    metadata,
                    Some(bytes_read as u64)
                ).await?;

                // Verify chunk if enabled
                if verify_enabled {
                    let retrieved = backend.get(&chunk_key).await?;
                    let mut verify_buffer = Vec::new();
                    let mut verify_reader = BufReader::new(retrieved);
                    verify_reader.read_to_end(&mut verify_buffer).await
                        .map_err(|e| StorageError::new(
                            StorageErrorKind::ChunkingError,
                            "Failed to verify chunk"
                        ).with_source(e))?;

                    let verify_hash = Self::compute_chunk_hash(&verify_buffer);
                    if verify_hash != chunk_info.hash {
                        return Err(StorageError::new(
                            StorageErrorKind::IntegrityCheckFailed,
                            format!("Chunk {} verification failed", chunk_index)
                        ));
                    }
                }

                Ok::<_, StorageError>(())
            });

            upload_tasks.push(task);

            chunk_index += 1;
            total_offset += bytes_read as u64;
        }

        // Wait for all uploads to complete
        for task in upload_tasks {
            task.await
                .map_err(|e| StorageError::new(
                    StorageErrorKind::ChunkingError,
                    "Chunk upload task failed"
                ).with_source(e))??;
        }

        self.update_metrics(|m| {
            m.total_chunks_uploaded += chunk_index;
            m.parallel_upload_count += 1;
        });

        // Create manifest
        let content_hash = Hash256::from_bytes(&overall_hasher.finalize())
            .expect("SHA-256 should always produce 32 bytes");

        let manifest = ChunkManifest {
            object_id: object_id.clone(),
            total_size: total_offset,
            chunk_size: self.config.chunk_size,
            chunks,
            content_hash,
            created_at: Utc::now(),
        };

        // Store manifest
        self.store_manifest(&object_id, &manifest).await?;

        Ok(manifest)
    }

    async fn store_single_chunk(
        &self,
        object_id: String,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<ChunkManifest> {
        // Read entire content
        let mut buffer = Vec::new();
        let mut reader = BufReader::new(data);
        reader.read_to_end(&mut buffer).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to read data")
                .with_source(e))?;

        let content_hash = Self::compute_chunk_hash(&buffer);
        let chunk_key = StorageKey::new(
            format!("{}/chunks", self.namespace),
            content_hash.clone()
        ).with_path(format!("{}/chunk_000000", object_id));

        let reader = Cursor::new(buffer.clone());
        self.backend.put(&chunk_key, reader, Some(buffer.len() as u64)).await?;

        let chunk_info = ChunkInfo {
            index: 0,
            offset: 0,
            size: buffer.len() as u64,
            hash: content_hash.clone(),
            storage_key: chunk_key,
        };

        let manifest = ChunkManifest {
            object_id: object_id.clone(),
            total_size: buffer.len() as u64,
            chunk_size: buffer.len() as u64,
            chunks: vec![chunk_info],
            content_hash,
            created_at: Utc::now(),
        };

        self.store_manifest(&object_id, &manifest).await?;

        Ok(manifest)
    }

    async fn retrieve_chunked(&self, object_id: &str) -> Result<impl AsyncRead + Send + Unpin> {
        // Load manifest
        let manifest = self.load_manifest(object_id).await?;

        // Create a stream that reads chunks in order
        let backend = self.backend.clone();
        let chunks = manifest.chunks.clone();
        let verify_enabled = self.config.verify_chunks;
        let metrics = self.metrics.clone();

        let stream = stream::iter(chunks)
            .then(move |chunk_info| {
                let backend = backend.clone();
                let metrics = metrics.clone();

                async move {
                    // Download chunk
                    let mut reader = backend.get(&chunk_info.storage_key).await?;
                    let mut buffer = Vec::new();
                    reader.read_to_end(&mut buffer).await
                        .map_err(|e| StorageError::new(
                            StorageErrorKind::ChunkingError,
                            "Failed to read chunk"
                        ).with_source(e))?;

                    // Verify chunk integrity if enabled
                    if verify_enabled {
                        let computed_hash = Self::compute_chunk_hash(&buffer);
                        if computed_hash != chunk_info.hash {
                            if let Ok(mut m) = metrics.write() {
                                m.chunk_verification_failures += 1;
                            }
                            return Err(StorageError::new(
                                StorageErrorKind::IntegrityCheckFailed,
                                format!("Chunk {} integrity check failed", chunk_info.index)
                            ));
                        }
                    }

                    if let Ok(mut m) = metrics.write() {
                        m.total_chunks_downloaded += 1;
                    }

                    Ok::<_, StorageError>(buffer)
                }
            })
            .try_collect::<Vec<Vec<u8>>>()
            .await?;

        // Concatenate all chunks
        let combined: Vec<u8> = stream.into_iter().flatten().collect();

        // Verify overall content hash if enabled
        if self.config.verify_chunks {
            let computed_hash = Self::compute_chunk_hash(&combined);
            if computed_hash != manifest.content_hash {
                return Err(StorageError::new(
                    StorageErrorKind::IntegrityCheckFailed,
                    "Overall content hash mismatch"
                ));
            }
        }

        Ok(Cursor::new(combined))
    }

    async fn store_manifest(&self, object_id: &str, manifest: &ChunkManifest) -> Result<()> {
        let manifest_key = self.get_manifest_key(object_id);
        let manifest_json = serde_json::to_vec(manifest)
            .map_err(|e| StorageError::new(
                StorageErrorKind::SerializationError,
                "Failed to serialize manifest"
            ).with_source(e))?;

        let reader = Cursor::new(manifest_json.clone());
        self.backend.put(&manifest_key, reader, Some(manifest_json.len() as u64)).await?;

        Ok(())
    }

    async fn load_manifest(&self, object_id: &str) -> Result<ChunkManifest> {
        let manifest_key = self.get_manifest_key(object_id);
        let mut reader = self.backend.get(&manifest_key).await?;

        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await
            .map_err(|e| StorageError::new(
                StorageErrorKind::BackendError,
                "Failed to read manifest"
            ).with_source(e))?;

        serde_json::from_slice(&buffer)
            .map_err(|e| StorageError::new(
                StorageErrorKind::SerializationError,
                "Failed to deserialize manifest"
            ).with_source(e))
    }

    async fn delete_chunked(&self, object_id: &str) -> Result<()> {
        // Load manifest
        let manifest = self.load_manifest(object_id).await?;

        // Delete all chunks in parallel
        let tasks: Vec<_> = manifest.chunks.iter()
            .map(|chunk_info| {
                let backend = self.backend.clone();
                let key = chunk_info.storage_key.clone();
                async move {
                    backend.delete(&key).await
                }
            })
            .collect();

        // Wait for all deletions
        let results = join_all(tasks).await;

        // Collect any errors
        let errors: Vec<_> = results.into_iter()
            .filter_map(|r| r.err())
            .collect();

        if !errors.is_empty() {
            return Err(StorageError::new(
                StorageErrorKind::BackendError,
                format!("Failed to delete {} chunks", errors.len())
            ));
        }

        // Delete manifest
        let manifest_key = self.get_manifest_key(object_id);
        self.backend.delete(&manifest_key).await?;

        Ok(())
    }

    fn get_manifest_key(&self, object_id: &str) -> StorageKey {
        let manifest_hash = Self::compute_chunk_hash(object_id.as_bytes());
        StorageKey::new(
            format!("{}/manifests", self.namespace),
            manifest_hash
        ).with_path(format!("{}/manifest.json", object_id))
    }

    fn compute_chunk_hash(data: &[u8]) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Hash256::from_bytes(&hasher.finalize()).expect("SHA-256 should always produce 32 bytes")
    }

    fn update_metrics<F>(&self, f: F)
    where
        F: FnOnce(&mut ChunkMetrics),
    {
        if let Ok(mut metrics) = self.metrics.write() {
            f(&mut metrics);
        }
    }

    fn get_metrics(&self) -> ChunkMetrics {
        self.metrics.read()
            .map(|m| m.clone())
            .unwrap_or_default()
    }
}

//==============================================================================
// STORAGE CACHE LAYER
//==============================================================================

struct CacheLayer {
    backend: Arc<dyn StorageBackend>,
    cache: Arc<RwLock<LRUCache>>,
    config: CacheConfig,
    write_buffer: Arc<RwLock<HashMap<StorageKey, CachedObject>>>,
    metrics: Arc<RwLock<CacheMetrics>>,
    flush_task: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct CachedObject {
    data: Vec<u8>,
    metadata: ObjectMetadata,
    cached_at: DateTime<Utc>,
    dirty: bool,
}

struct LRUCache {
    entries: HashMap<StorageKey, CachedObject>,
    access_order: VecDeque<StorageKey>,
    current_size: u64,
    max_size: u64,
}

impl LRUCache {
    fn new(max_size: u64) -> Self {
        Self {
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            current_size: 0,
            max_size,
        }
    }

    fn get(&mut self, key: &StorageKey) -> Option<&CachedObject> {
        if self.entries.contains_key(key) {
            // Move to front (most recently used)
            self.access_order.retain(|k| k != key);
            self.access_order.push_front(key.clone());
            self.entries.get(key)
        } else {
            None
        }
    }

    fn put(&mut self, key: StorageKey, object: CachedObject) -> Vec<(StorageKey, CachedObject)> {
        let object_size = object.data.len() as u64;
        let mut evicted = Vec::new();

        // Evict entries if necessary
        while self.current_size + object_size > self.max_size && !self.access_order.is_empty() {
            if let Some(old_key) = self.access_order.pop_back() {
                if let Some(old_object) = self.entries.remove(&old_key) {
                    self.current_size -= old_object.data.len() as u64;
                    evicted.push((old_key, old_object));
                }
            }
        }

        // Insert new entry
        if object_size <= self.max_size {
            self.access_order.push_front(key.clone());
            self.entries.insert(key, object);
            self.current_size += object_size;
        }

        evicted
    }

    fn remove(&mut self, key: &StorageKey) -> Option<CachedObject> {
        self.access_order.retain(|k| k != key);
        if let Some(object) = self.entries.remove(key) {
            self.current_size -= object.data.len() as u64;
            Some(object)
        } else {
            None
        }
    }

    fn size(&self) -> u64 {
        self.current_size
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Clone, Default)]
struct CacheMetrics {
    hits: u64,
    misses: u64,
    evictions: u64,
    write_backs: u64,
    current_size: u64,
    current_entries: u64,
}

impl CacheLayer {
    fn new(backend: Arc<dyn StorageBackend>, config: CacheConfig) -> Self {
        let cache = Arc::new(RwLock::new(LRUCache::new(config.max_size_bytes)));
        let write_buffer = Arc::new(RwLock::new(HashMap::new()));
        let metrics = Arc::new(RwLock::new(CacheMetrics::default()));

        let mut instance = Self {
            backend,
            cache,
            config: config.clone(),
            write_buffer,
            metrics,
            flush_task: None,
        };

        // Start background flush task for write-back mode
        if let CacheWriteMode::WriteBack { flush_interval } = config.write_mode {
            instance.flush_task = Some(instance.start_flush_task(flush_interval));
        }

        instance
    }

    async fn get(&self, key: &StorageKey) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get(key) {
                self.update_metrics(|m| {
                    m.hits += 1;
                });
                return Ok(Box::new(Cursor::new(cached.data.clone())));
            }
        }

        // Cache miss - fetch from backend
        self.update_metrics(|m| m.misses += 1);

        let mut reader = self.backend.get(key).await?;
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to read from backend")
                .with_source(e))?;

        // Get metadata
        let metadata = self.backend.get_metadata(key).await?;

        // Store in cache
        let cached_object = CachedObject {
            data: buffer.clone(),
            metadata,
            cached_at: Utc::now(),
            dirty: false,
        };

        let evicted = {
            let mut cache = self.cache.write().await;
            cache.put(key.clone(), cached_object)
        };

        // Handle evicted objects
        self.handle_evictions(evicted).await?;

        self.update_cache_size_metrics().await;

        Ok(Box::new(Cursor::new(buffer)))
    }

    async fn put(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt> {
        // Read data
        let mut buffer = Vec::new();
        let mut reader = BufReader::new(data);
        reader.read_to_end(&mut buffer).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to read data")
                .with_source(e))?;

        match self.config.write_mode {
            CacheWriteMode::WriteThrough => {
                // Write to backend immediately
                let backend_reader = Cursor::new(buffer.clone());
                let receipt = self.backend.put(key, backend_reader, size_hint).await?;

                // Update cache
                let cached_object = CachedObject {
                    data: buffer,
                    metadata: ObjectMetadata {
                        key: key.clone(),
                        size_bytes: receipt.size_bytes,
                        content_type: None,
                        content_hash: receipt.content_hash.clone(),
                        created_at: receipt.uploaded_at,
                        last_modified: receipt.uploaded_at,
                        custom_metadata: HashMap::new(),
                        encryption_info: None,
                    },
                    cached_at: Utc::now(),
                    dirty: false,
                };

                let evicted = {
                    let mut cache = self.cache.write().await;
                    cache.put(key.clone(), cached_object)
                };

                self.handle_evictions(evicted).await?;
                self.update_cache_size_metrics().await;

                Ok(receipt)
            }
            CacheWriteMode::WriteBack { .. } => {
                // Write to cache and buffer
                let content_hash = Self::compute_hash(&buffer);
                let cached_object = CachedObject {
                    data: buffer.clone(),
                    metadata: ObjectMetadata {
                        key: key.clone(),
                        size_bytes: buffer.len() as u64,
                        content_type: None,
                        content_hash: content_hash.clone(),
                        created_at: Utc::now(),
                        last_modified: Utc::now(),
                        custom_metadata: HashMap::new(),
                        encryption_info: None,
                    },
                    cached_at: Utc::now(),
                    dirty: true,
                };

                // Add to write buffer
                {
                    let mut write_buffer = self.write_buffer.write().await;
                    write_buffer.insert(key.clone(), cached_object.clone());
                }

                // Add to cache
                let evicted = {
                    let mut cache = self.cache.write().await;
                    cache.put(key.clone(), cached_object)
                };

                self.handle_evictions(evicted).await?;
                self.update_cache_size_metrics().await;

                Ok(StorageReceipt {
                    key: key.clone(),
                    size_bytes: buffer.len() as u64,
                    content_hash,
                    etag: None,
                    version_id: None,
                    uploaded_at: Utc::now(),
                    backend_metadata: HashMap::new(),
                })
            }
        }
    }

    async fn flush(&self) -> Result<()> {
        let dirty_objects = {
            let mut write_buffer = self.write_buffer.write().await;
            std::mem::take(&mut *write_buffer)
        };

        for (key, object) in dirty_objects {
            if object.dirty {
                let reader = Cursor::new(object.data);
                self.backend.put(&key, reader, Some(object.metadata.size_bytes)).await?;

                self.update_metrics(|m| m.write_backs += 1);
            }
        }

        Ok(())
    }

    async fn invalidate(&self, key: &StorageKey) -> Result<()> {
        // Remove from cache
        {
            let mut cache = self.cache.write().await;
            cache.remove(key);
        }

        // Remove from write buffer and flush if dirty
        let object = {
            let mut write_buffer = self.write_buffer.write().await;
            write_buffer.remove(key)
        };

        if let Some(obj) = object {
            if obj.dirty {
                let reader = Cursor::new(obj.data);
                self.backend.put(key, reader, Some(obj.metadata.size_bytes)).await?;
            }
        }

        self.update_cache_size_metrics().await;

        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        // Flush all dirty objects
        self.flush().await?;

        // Clear cache
        {
            let mut cache = self.cache.write().await;
            *cache = LRUCache::new(self.config.max_size_bytes);
        }

        self.update_cache_size_metrics().await;

        Ok(())
    }

    fn start_flush_task(&self, flush_interval: Duration) -> JoinHandle<()> {
        let write_buffer = self.write_buffer.clone();
        let backend = self.backend.clone();
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(flush_interval);

            loop {
                interval.tick().await;

                // Get dirty objects
                let dirty_objects = {
                    let write_buffer = write_buffer.read().await;
                    write_buffer.clone()
                };

                // Flush dirty objects
                for (key, object) in dirty_objects {
                    if object.dirty {
                        let reader = Cursor::new(object.data.clone());
                        if let Ok(_) = backend.put(&key, reader, Some(object.metadata.size_bytes)).await {
                            // Remove from write buffer after successful flush
                            let mut wb = write_buffer.write().await;
                            wb.remove(&key);

                            if let Ok(mut m) = metrics.write() {
                                m.write_backs += 1;
                            }
                        }
                    }
                }
            }
        })
    }

    async fn handle_evictions(&self, evicted: Vec<(StorageKey, CachedObject)>) -> Result<()> {
        for (key, object) in evicted {
            self.update_metrics(|m| m.evictions += 1);

            // If object is dirty, write it back
            if object.dirty {
                let reader = Cursor::new(object.data);
                self.backend.put(&key, reader, Some(object.metadata.size_bytes)).await?;

                self.update_metrics(|m| m.write_backs += 1);
            }
        }

        Ok(())
    }

    async fn update_cache_size_metrics(&self) {
        let (size, entries) = {
            let cache = self.cache.read().await;
            (cache.size(), cache.len())
        };

        self.update_metrics(|m| {
            m.current_size = size;
            m.current_entries = entries as u64;
        });
    }

    fn compute_hash(data: &[u8]) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Hash256::from_bytes(&hasher.finalize()).expect("SHA-256 should always produce 32 bytes")
    }

    fn update_metrics<F>(&self, f: F)
    where
        F: FnOnce(&mut CacheMetrics),
    {
        if let Ok(mut metrics) = self.metrics.write() {
            f(&mut metrics);
        }
    }

    fn get_metrics(&self) -> CacheMetrics {
        self.metrics.read()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Flush all pending writes
        self.flush().await?;

        // Cancel flush task
        if let Some(task) = self.flush_task.take() {
            task.abort();
        }

        Ok(())
    }
}

#[async_trait]
impl StorageBackend for CacheLayer {
    async fn put(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt> {
        self.put(key, data, size_hint).await
    }

    async fn put_with_metadata(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        metadata: HashMap<String, String>,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt> {
        // For simplicity, delegate to backend directly for metadata puts
        self.backend.put_with_metadata(key, data, metadata, size_hint).await
    }

    async fn get(&self, key: &StorageKey) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        self.get(key).await
    }

    async fn get_range(
        &self,
        key: &StorageKey,
        range: Range<u64>,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        // Range reads bypass cache
        self.backend.get_range(key, range).await
    }

    async fn delete(&self, key: &StorageKey) -> Result<()> {
        self.invalidate(key).await?;
        self.backend.delete(key).await
    }

    async fn exists(&self, key: &StorageKey) -> Result<bool> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if cache.entries.contains_key(key) {
                return Ok(true);
            }
        }

        // Check backend
        self.backend.exists(key).await
    }

    async fn list(&self, prefix: &str, options: ListOptions) -> Result<StorageIterator> {
        // List operations bypass cache
        self.backend.list(prefix, options).await
    }

    async fn get_metadata(&self, key: &StorageKey) -> Result<ObjectMetadata> {
        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get(key) {
                return Ok(cached.metadata.clone());
            }
        }

        // Fetch from backend
        self.backend.get_metadata(key).await
    }

    async fn copy(&self, source: &StorageKey, dest: &StorageKey) -> Result<StorageReceipt> {
        // Invalidate destination if it exists in cache
        self.invalidate(dest).await?;

        self.backend.copy(source, dest).await
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        self.backend.health_check().await
    }

    fn get_metrics(&self) -> BackendMetrics {
        self.backend.get_metrics()
    }

    fn backend_type(&self) -> BackendType {
        self.backend.backend_type()
    }
}

//==============================================================================
// LOCAL FILESYSTEM BACKEND IMPLEMENTATION
//==============================================================================

struct LocalFilesystemBackend {
    config: LocalFilesystemConfig,
    metrics: Arc<RwLock<BackendMetrics>>,
}

impl LocalFilesystemBackend {
    async fn new(config: LocalFilesystemConfig) -> Result<Self> {
        if config.create_dirs {
            tokio::fs::create_dir_all(&config.root_path).await
                .map_err(|e| StorageError::new(
                    StorageErrorKind::ConfigurationError,
                    "Failed to create root directory"
                ).with_source(e))?;
        }

        Ok(Self {
            config,
            metrics: Arc::new(RwLock::new(BackendMetrics::default())),
        })
    }

    fn get_file_path(&self, key: &StorageKey) -> PathBuf {
        let hash_hex = key.hash.to_hex();

        // Use first 2 chars for subdirectory to avoid too many files in one dir
        let prefix = &hash_hex[..2];
        let suffix = &hash_hex[2..];

        self.config.root_path
            .join(&key.namespace)
            .join(prefix)
            .join(suffix)
    }

    fn update_metrics<F>(&self, f: F)
    where
        F: FnOnce(&mut BackendMetrics),
    {
        if let Ok(mut metrics) = self.metrics.write() {
            f(&mut metrics);
        }
    }
}

#[async_trait]
impl StorageBackend for LocalFilesystemBackend {
    async fn put(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt> {
        let file_path = self.get_file_path(key);

        // Create parent directories
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| StorageError::new(
                    StorageErrorKind::BackendError,
                    "Failed to create parent directories"
                ).with_source(e))?;
        }

        // Write file
        let mut file = tokio::fs::File::create(&file_path).await
            .map_err(|e| StorageError::new(
                StorageErrorKind::BackendError,
                "Failed to create file"
            ).with_source(e))?;

        let mut reader = BufReader::new(data);
        let bytes_written = tokio::io::copy(&mut reader, &mut file).await
            .map_err(|e| StorageError::new(
                StorageErrorKind::BackendError,
                "Failed to write file"
            ).with_source(e))?;

        // Sync to disk if configured
        if self.config.sync_on_write {
            file.sync_all().await
                .map_err(|e| StorageError::new(
                    StorageErrorKind::BackendError,
                    "Failed to sync file"
                ).with_source(e))?;
        }

        self.update_metrics(|m| {
            m.total_requests += 1;
            m.bytes_uploaded += bytes_written;
        });

        Ok(StorageReceipt {
            key: key.clone(),
            size_bytes: bytes_written,
            content_hash: key.hash.clone(),
            etag: None,
            version_id: None,
            uploaded_at: Utc::now(),
            backend_metadata: HashMap::new(),
        })
    }

    async fn put_with_metadata(
        &self,
        key: &StorageKey,
        data: impl AsyncRead + Send + Unpin,
        metadata: HashMap<String, String>,
        size_hint: Option<u64>,
    ) -> Result<StorageReceipt> {
        // Store metadata in extended attributes or separate file
        let receipt = self.put(key, data, size_hint).await?;

        // Store metadata as JSON in .meta file
        if !metadata.is_empty() {
            let meta_path = self.get_file_path(key).with_extension("meta");
            let meta_json = serde_json::to_string(&metadata)
                .map_err(|e| StorageError::new(
                    StorageErrorKind::SerializationError,
                    "Failed to serialize metadata"
                ).with_source(e))?;

            tokio::fs::write(&meta_path, meta_json).await
                .map_err(|e| StorageError::new(
                    StorageErrorKind::BackendError,
                    "Failed to write metadata"
                ).with_source(e))?;
        }

        Ok(receipt)
    }

    async fn get(&self, key: &StorageKey) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let file_path = self.get_file_path(key);

        let file = tokio::fs::File::open(&file_path).await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::new(StorageErrorKind::NotFound, "File not found")
                        .with_context("path", file_path.display().to_string())
                } else {
                    StorageError::new(StorageErrorKind::BackendError, "Failed to open file")
                        .with_source(e)
                }
            })?;

        let metadata = file.metadata().await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to get file metadata")
                .with_source(e))?;

        self.update_metrics(|m| {
            m.total_requests += 1;
            m.bytes_downloaded += metadata.len();
        });

        Ok(Box::new(file))
    }

    async fn get_range(
        &self,
        key: &StorageKey,
        range: Range<u64>,
    ) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let file_path = self.get_file_path(key);

        let mut file = tokio::fs::File::open(&file_path).await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::new(StorageErrorKind::NotFound, "File not found")
                } else {
                    StorageError::new(StorageErrorKind::BackendError, "Failed to open file")
                        .with_source(e)
                }
            })?;

        // Seek to start of range
        file.seek(SeekFrom::Start(range.start)).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to seek")
                .with_source(e))?;

        // Take only the requested range
        let range_size = range.end - range.start;
        let limited_reader = file.take(range_size);

        self.update_metrics(|m| {
            m.total_requests += 1;
            m.bytes_downloaded += range_size;
        });

        Ok(Box::new(limited_reader))
    }

    async fn delete(&self, key: &StorageKey) -> Result<()> {
        let file_path = self.get_file_path(key);

        tokio::fs::remove_file(&file_path).await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::new(StorageErrorKind::NotFound, "File not found")
                } else {
                    StorageError::new(StorageErrorKind::BackendError, "Failed to delete file")
                        .with_source(e)
                }
            })?;

        // Also delete metadata file if it exists
        let meta_path = file_path.with_extension("meta");
        let _ = tokio::fs::remove_file(&meta_path).await;

        self.update_metrics(|m| m.total_requests += 1);

        Ok(())
    }

    async fn exists(&self, key: &StorageKey) -> Result<bool> {
        let file_path = self.get_file_path(key);
        Ok(file_path.exists())
    }

    async fn list(&self, prefix: &str, options: ListOptions) -> Result<StorageIterator> {
        let root_path = self.config.root_path.join(prefix);

        let entries = tokio::fs::read_dir(&root_path).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to list directory")
                .with_source(e))?;

        // Convert to stream (simplified implementation)
        let stream = stream::unfold(entries, |mut entries| async move {
            match entries.next_entry().await {
                Ok(Some(entry)) => {
                    // Convert entry to ObjectMetadata
                    // This is a simplified version
                    None
                }
                _ => None,
            }
        });

        Ok(StorageIterator {
            inner: Box::pin(stream),
        })
    }

    async fn get_metadata(&self, key: &StorageKey) -> Result<ObjectMetadata> {
        let file_path = self.get_file_path(key);

        let metadata = tokio::fs::metadata(&file_path).await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::new(StorageErrorKind::NotFound, "File not found")
                } else {
                    StorageError::new(StorageErrorKind::BackendError, "Failed to get metadata")
                        .with_source(e)
                }
            })?;

        // Load custom metadata if exists
        let custom_metadata = {
            let meta_path = file_path.with_extension("meta");
            if meta_path.exists() {
                let meta_json = tokio::fs::read_to_string(&meta_path).await.ok();
                meta_json.and_then(|json| serde_json::from_str(&json).ok())
                    .unwrap_or_default()
            } else {
                HashMap::new()
            }
        };

        Ok(ObjectMetadata {
            key: key.clone(),
            size_bytes: metadata.len(),
            content_type: None,
            content_hash: key.hash.clone(),
            created_at: metadata.created()
                .ok()
                .and_then(|t| DateTime::from_timestamp(t.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64, 0))
                .unwrap_or_else(Utc::now),
            last_modified: metadata.modified()
                .ok()
                .and_then(|t| DateTime::from_timestamp(t.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64, 0))
                .unwrap_or_else(Utc::now),
            custom_metadata,
            encryption_info: None,
        })
    }

    async fn copy(&self, source: &StorageKey, dest: &StorageKey) -> Result<StorageReceipt> {
        let source_path = self.get_file_path(source);
        let dest_path = self.get_file_path(dest);

        // Create parent directories
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| StorageError::new(
                    StorageErrorKind::BackendError,
                    "Failed to create parent directories"
                ).with_source(e))?;
        }

        // Copy file
        tokio::fs::copy(&source_path, &dest_path).await
            .map_err(|e| StorageError::new(StorageErrorKind::BackendError, "Failed to copy file")
                .with_source(e))?;

        // Copy metadata file if exists
        let source_meta = source_path.with_extension("meta");
        let dest_meta = dest_path.with_extension("meta");
        if source_meta.exists() {
            let _ = tokio::fs::copy(&source_meta, &dest_meta).await;
        }

        let metadata = self.get_metadata(dest).await?;

        Ok(StorageReceipt {
            key: dest.clone(),
            size_bytes: metadata.size_bytes,
            content_hash: dest.hash.clone(),
            etag: None,
            version_id: None,
            uploaded_at: Utc::now(),
            backend_metadata: HashMap::new(),
        })
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let start = Instant::now();

        let result = tokio::fs::metadata(&self.config.root_path).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(metadata) if metadata.is_dir() => Ok(HealthStatus {
                healthy: true,
                latency_ms: Some(latency_ms),
                last_error: None,
                checked_at: Utc::now(),
            }),
            Ok(_) => Ok(HealthStatus {
                healthy: false,
                latency_ms: Some(latency_ms),
                last_error: Some("Root path is not a directory".to_string()),
                checked_at: Utc::now(),
            }),
            Err(e) => Ok(HealthStatus {
                healthy: false,
                latency_ms: Some(latency_ms),
                last_error: Some(format!("{:?}", e)),
                checked_at: Utc::now(),
            }),
        }
    }

    fn get_metrics(&self) -> BackendMetrics {
        self.metrics.read()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    fn backend_type(&self) -> BackendType {
        BackendType::LocalFilesystem
    }
}

//==============================================================================
// STORAGE FACTORY
//==============================================================================

struct StorageFactory;

impl StorageFactory {
    async fn create_backend(config: &StorageConfig) -> Result<Arc<dyn StorageBackend>> {
        let backend: Arc<dyn StorageBackend> = match &config.backend {
            BackendConfig::S3(s3_config) => {
                Arc::new(
                    S3StorageBackend::new(
                        s3_config.clone(),
                        config.retry_policy.clone(),
                        config.timeout_config.clone()
                    ).await?
                )
            }
            BackendConfig::LocalFilesystem(fs_config) => {
                Arc::new(LocalFilesystemBackend::new(fs_config.clone()).await?)
            }
            BackendConfig::MinIO(minio_config) => {
                // MinIO uses S3-compatible API
                let s3_config = S3Config {
                    region: minio_config.region.clone().unwrap_or_else(|| "us-east-1".to_string()),
                    bucket: minio_config.bucket.clone(),
                    access_key_id: Some(minio_config.access_key.clone()),
                    secret_access_key: Some(minio_config.secret_key.clone()),
                    endpoint: Some(minio_config.endpoint.clone()),
                    use_path_style: true,
                    server_side_encryption: None,
                    connection_pool_size: minio_config.connection_pool_size,
                    multipart_threshold: 5 * 1024 * 1024,
                    multipart_chunk_size: 8 * 1024 * 1024,
                };

                Arc::new(
                    S3StorageBackend::new(
                        s3_config,
                        config.retry_policy.clone(),
                        config.timeout_config.clone()
                    ).await?
                )
            }
            // Implementations for Azure Blob and GCS would go here
            _ => {
                return Err(StorageError::new(
                    StorageErrorKind::ConfigurationError,
                    "Backend type not implemented"
                ));
            }
        };

        // Wrap with cache if configured
        let backend = if let Some(cache_config) = &config.cache_config {
            Arc::new(CacheLayer::new(backend, cache_config.clone())) as Arc<dyn StorageBackend>
        } else {
            backend
        };

        Ok(backend)
    }

    async fn create_content_addressable_store(
        config: &StorageConfig,
        namespace: impl Into<String>,
    ) -> Result<ContentAddressableStore> {
        let backend = Self::create_backend(config).await?;

        Ok(ContentAddressableStore::new(
            backend,
            namespace,
            true,  // Enable verification
            true,  // Enable deduplication
        ))
    }

    async fn create_chunk_manager(
        config: &StorageConfig,
        namespace: impl Into<String>,
    ) -> Result<ChunkManager> {
        let backend = Self::create_backend(config).await?;

        Ok(ChunkManager::new(
            backend,
            config.chunk_config.clone(),
            namespace,
        ))
    }
}

//==============================================================================
// HIGH-LEVEL STORAGE SERVICE
//==============================================================================

struct StorageService {
    backend: Arc<dyn StorageBackend>,
    cas_store: ContentAddressableStore,
    chunk_manager: ChunkManager,
}

impl StorageService {
    async fn new(config: StorageConfig) -> Result<Self> {
        let backend = StorageFactory::create_backend(&config).await?;
        let cas_store = ContentAddressableStore::new(
            backend.clone(),
            "cas",
            true,
            true,
        );
        let chunk_manager = ChunkManager::new(
            backend.clone(),
            config.chunk_config,
            "chunks",
        );

        Ok(Self {
            backend,
            cas_store,
            chunk_manager,
        })
    }

    async fn store_content_addressed(&self, data: impl AsyncRead + Send + Unpin) -> Result<Hash256> {
        let receipt = self.cas_store.store(data).await?;
        Ok(receipt.content_hash)
    }

    async fn retrieve_content_addressed(&self, hash: &Hash256) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        self.cas_store.retrieve(hash).await
    }

    async fn store_large_object(
        &self,
        id: impl Into<String>,
        data: impl AsyncRead + Send + Unpin,
        size_hint: Option<u64>,
    ) -> Result<ChunkManifest> {
        self.chunk_manager.store_chunked(id, data, size_hint).await
    }

    async fn retrieve_large_object(&self, id: &str) -> Result<impl AsyncRead + Send + Unpin> {
        self.chunk_manager.retrieve_chunked(id).await
    }

    async fn delete_large_object(&self, id: &str) -> Result<()> {
        self.chunk_manager.delete_chunked(id).await
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        self.backend.health_check().await
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Gracefully shutdown components
        if let Some(cache_layer) = self.backend.as_any().downcast_ref::<CacheLayer>() {
            cache_layer.shutdown().await?;
        }
        Ok(())
    }
}

//==============================================================================
// USAGE EXAMPLES
//==============================================================================

async fn example_usage() -> Result<()> {
    // Configure S3 backend
    let config = StorageConfig {
        backend: BackendConfig::S3(S3Config {
            region: "us-east-1".to_string(),
            bucket: "my-llm-vault".to_string(),
            access_key_id: None, // Use default credential chain
            secret_access_key: None,
            endpoint: None,
            use_path_style: false,
            server_side_encryption: Some(S3Encryption::KMS { key_id: None }),
            connection_pool_size: 10,
            multipart_threshold: 5 * 1024 * 1024,
            multipart_chunk_size: 8 * 1024 * 1024,
        }),
        retry_policy: RetryPolicy::default(),
        timeout_config: TimeoutConfig::default(),
        chunk_config: ChunkConfig::default(),
        cache_config: Some(CacheConfig {
            max_size_bytes: 1024 * 1024 * 1024, // 1GB cache
            eviction_policy: EvictionPolicy::LRU,
            write_mode: CacheWriteMode::WriteThrough,
            ttl: None,
        }),
        encryption_config: None,
        compression_config: None,
    };

    // Create storage service
    let mut service = StorageService::new(config).await?;

    // Store content-addressed data
    let data = b"Hello, World!";
    let hash = service.store_content_addressed(Cursor::new(data)).await?;
    println!("Stored with hash: {}", hash.to_hex());

    // Retrieve content-addressed data
    let mut reader = service.retrieve_content_addressed(&hash).await?;
    let mut retrieved = Vec::new();
    reader.read_to_end(&mut retrieved).await.unwrap();
    assert_eq!(retrieved, data);

    // Store large object with chunking
    let large_data = vec![0u8; 100 * 1024 * 1024]; // 100MB
    let manifest = service.store_large_object(
        "my-large-file",
        Cursor::new(large_data.clone()),
        Some(large_data.len() as u64)
    ).await?;
    println!("Stored {} chunks", manifest.chunks.len());

    // Retrieve large object
    let mut reader = service.retrieve_large_object("my-large-file").await?;
    let mut retrieved_large = Vec::new();
    reader.read_to_end(&mut retrieved_large).await.unwrap();
    assert_eq!(retrieved_large, large_data);

    // Health check
    let health = service.health_check().await?;
    println!("Storage health: {:?}", health);

    // Graceful shutdown
    service.shutdown().await?;

    Ok(())
}
```
