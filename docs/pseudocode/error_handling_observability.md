# Error Handling and Observability System - Pseudocode

Enterprise-grade error handling, metrics, tracing, and health monitoring for LLM-Data-Vault.

## 1. Error Type Hierarchy

```rust
//==============================================================================
// DOMAIN-SPECIFIC ERROR TYPES
//==============================================================================

use thiserror::Error;
use std::fmt;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Top-level error type with full context and observability integration
#[derive(Debug, Error)]
pub enum VaultError {
    /// Storage backend errors
    #[error("Storage error: {message}")]
    Storage {
        message: String,
        kind: StorageErrorKind,
        backend: StorageBackend,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        retryable: bool,
        context: ErrorContext,
    },

    /// Authentication failures
    #[error("Authentication failed: {reason}")]
    Authentication {
        reason: String,
        provider: AuthProvider,
        user_identifier: Option<String>,
        context: ErrorContext,
    },

    /// Authorization/permission denied
    #[error("Authorization denied: {reason}")]
    Authorization {
        reason: String,
        required_permission: Permission,
        actual_permissions: Vec<Permission>,
        resource_id: ResourceId,
        user_id: UserId,
        context: ErrorContext,
    },

    /// Input validation errors
    #[error("Validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
        violations: Vec<ValidationViolation>,
        invalid_value: Option<String>,  // Sanitized
        context: ErrorContext,
    },

    /// Encryption/Decryption errors
    #[error("Cryptographic operation failed: {operation}")]
    Cryptographic {
        operation: CryptoOperation,
        algorithm: String,
        key_id: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        context: ErrorContext,
    },

    /// KMS provider errors
    #[error("KMS error: {message}")]
    Kms {
        message: String,
        provider: KmsProvider,
        key_id: String,
        operation: KmsOperation,
        retryable: bool,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        context: ErrorContext,
    },

    /// Database operation errors
    #[error("Database error: {message}")]
    Database {
        message: String,
        operation: DbOperation,
        table: Option<String>,
        retryable: bool,
        constraint_violation: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        context: ErrorContext,
    },

    /// Rate limiting errors
    #[error("Rate limit exceeded: {limit_type}")]
    RateLimit {
        limit_type: RateLimitType,
        limit: u64,
        current: u64,
        reset_at: DateTime<Utc>,
        retry_after: Duration,
        context: ErrorContext,
    },

    /// Resource not found
    #[error("Resource not found: {resource_type} with id {resource_id}")]
    NotFound {
        resource_type: ResourceType,
        resource_id: String,
        context: ErrorContext,
    },

    /// Resource already exists (conflict)
    #[error("Resource conflict: {resource_type} already exists")]
    Conflict {
        resource_type: ResourceType,
        resource_id: String,
        existing_resource: Option<String>,
        context: ErrorContext,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Configuration {
        message: String,
        config_key: String,
        expected_type: Option<String>,
        context: ErrorContext,
    },

    /// Network/connectivity errors
    #[error("Network error: {message}")]
    Network {
        message: String,
        endpoint: Option<String>,
        retryable: bool,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        context: ErrorContext,
    },

    /// Timeout errors
    #[error("Operation timed out: {operation}")]
    Timeout {
        operation: String,
        duration: Duration,
        deadline: DateTime<Utc>,
        context: ErrorContext,
    },

    /// Internal server errors
    #[error("Internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        context: ErrorContext,
    },

    /// External service errors
    #[error("External service error: {service}")]
    ExternalService {
        service: String,
        operation: String,
        status_code: Option<u16>,
        retryable: bool,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        context: ErrorContext,
    },

    /// Quota/capacity errors
    #[error("Quota exceeded: {quota_type}")]
    QuotaExceeded {
        quota_type: QuotaType,
        limit: u64,
        current: u64,
        context: ErrorContext,
    },
}

/// Storage error variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageErrorKind {
    ConnectionFailed,
    WriteFailure,
    ReadFailure,
    DeleteFailure,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    InsufficientSpace,
    Corruption,
    Timeout,
}

/// Storage backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackend {
    S3,
    AzureBlob,
    GoogleCloudStorage,
    Local,
    Custom(String),
}

/// Authentication providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthProvider {
    ApiKey,
    Jwt,
    OAuth2,
    Saml,
    Custom(String),
}

/// Cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoOperation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    KeyDerivation,
    HashGeneration,
}

/// KMS operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KmsOperation {
    GenerateKey,
    EncryptKey,
    DecryptKey,
    RotateKey,
    DescribeKey,
    CreateAlias,
}

/// Database operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbOperation {
    Insert,
    Update,
    Delete,
    Select,
    Transaction,
    Migration,
}

/// Rate limit types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitType {
    RequestsPerSecond,
    RequestsPerMinute,
    RequestsPerHour,
    BytesPerSecond,
    ConcurrentRequests,
}

/// Quota types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuotaType {
    Storage,
    Requests,
    Bandwidth,
    Datasets,
    Users,
}

/// Validation violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationViolation {
    pub field: String,
    pub constraint: String,
    pub actual_value: Option<String>,  // Sanitized
    pub expected: String,
}

//==============================================================================
// ERROR CONTEXT
//==============================================================================

/// Rich error context for debugging and observability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Unique request identifier
    pub request_id: RequestId,

    /// Distributed trace ID
    pub trace_id: TraceId,

    /// Current span ID
    pub span_id: SpanId,

    /// User who initiated the request
    pub user_id: Option<UserId>,

    /// Resource being operated on
    pub resource_id: Option<ResourceId>,

    /// Operation being performed
    pub operation: String,

    /// When the error occurred
    pub timestamp: DateTime<Utc>,

    /// Additional metadata
    pub metadata: HashMap<String, Value>,

    /// Source location (file, line)
    pub source_location: Option<SourceLocation>,

    /// Environment (production, staging, dev)
    pub environment: String,

    /// Service version
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

impl ErrorContext {
    /// Create new error context from current request
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            request_id: RequestId::current(),
            trace_id: TraceId::current(),
            span_id: SpanId::current(),
            user_id: current_user_id(),
            resource_id: None,
            operation: operation.into(),
            timestamp: Utc::now(),
            metadata: HashMap::new(),
            source_location: Some(SourceLocation::caller()),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "unknown".into()),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Add metadata to context
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set resource ID
    pub fn with_resource(mut self, resource_id: ResourceId) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    /// Set user ID
    pub fn with_user(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }
}

//==============================================================================
// ERROR CHAIN AND ROOT CAUSE ANALYSIS
//==============================================================================

/// Error chain for tracing root causes
pub trait ErrorChain {
    /// Iterate through the error chain
    fn chain(&self) -> ErrorChainIterator;

    /// Get the root cause error
    fn root_cause(&self) -> &(dyn std::error::Error + 'static);

    /// Add context to this error
    fn with_context<C: Into<ErrorContext>>(self, context: C) -> Self;

    /// Get all error messages in the chain
    fn messages(&self) -> Vec<String>;

    /// Check if error chain contains specific error type
    fn contains<E: std::error::Error + 'static>(&self) -> bool;
}

impl ErrorChain for VaultError {
    fn chain(&self) -> ErrorChainIterator {
        ErrorChainIterator {
            current: Some(self as &(dyn std::error::Error + 'static)),
        }
    }

    fn root_cause(&self) -> &(dyn std::error::Error + 'static) {
        let mut source = self as &(dyn std::error::Error + 'static);
        while let Some(s) = source.source() {
            source = s;
        }
        source
    }

    fn with_context<C: Into<ErrorContext>>(mut self, context: C) -> Self {
        let ctx = context.into();
        match &mut self {
            VaultError::Storage { context: c, .. } => *c = ctx,
            VaultError::Authentication { context: c, .. } => *c = ctx,
            VaultError::Authorization { context: c, .. } => *c = ctx,
            VaultError::Validation { context: c, .. } => *c = ctx,
            VaultError::Cryptographic { context: c, .. } => *c = ctx,
            VaultError::Kms { context: c, .. } => *c = ctx,
            VaultError::Database { context: c, .. } => *c = ctx,
            VaultError::RateLimit { context: c, .. } => *c = ctx,
            VaultError::NotFound { context: c, .. } => *c = ctx,
            VaultError::Conflict { context: c, .. } => *c = ctx,
            VaultError::Configuration { context: c, .. } => *c = ctx,
            VaultError::Network { context: c, .. } => *c = ctx,
            VaultError::Timeout { context: c, .. } => *c = ctx,
            VaultError::Internal { context: c, .. } => *c = ctx,
            VaultError::ExternalService { context: c, .. } => *c = ctx,
            VaultError::QuotaExceeded { context: c, .. } => *c = ctx,
        }
        self
    }

    fn messages(&self) -> Vec<String> {
        self.chain().map(|e| e.to_string()).collect()
    }

    fn contains<E: std::error::Error + 'static>(&self) -> bool {
        self.chain().any(|e| e.downcast_ref::<E>().is_some())
    }
}

pub struct ErrorChainIterator<'a> {
    current: Option<&'a (dyn std::error::Error + 'static)>,
}

impl<'a> Iterator for ErrorChainIterator<'a> {
    type Item = &'a (dyn std::error::Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        self.current = current.source();
        Some(current)
    }
}

//==============================================================================
// RESULT EXTENSIONS
//==============================================================================

/// Ergonomic result handling extensions
pub trait ResultExt<T, E> {
    /// Add error context
    fn context<C: Into<ErrorContext>>(self, context: C) -> Result<T, VaultError>;

    /// Add error context lazily
    fn with_context<C, F>(self, f: F) -> Result<T, VaultError>
    where
        C: Into<ErrorContext>,
        F: FnOnce() -> C;

    /// Retry if predicate matches
    fn retry_if<P>(self, predicate: P) -> RetryableResult<T, E>
    where
        P: Fn(&E) -> bool;

    /// Use default value if predicate matches
    fn or_default_if<P>(self, predicate: P, default: T) -> Result<T, E>
    where
        P: Fn(&E) -> bool;

    /// Log error and continue
    fn log_error(self, message: &str) -> Result<T, E>;

    /// Record error metric
    fn record_error_metric(self, operation: &str) -> Result<T, E>;

    /// Add span event on error
    fn span_error(self) -> Result<T, E>;
}

impl<T, E: Into<VaultError>> ResultExt<T, E> for Result<T, E> {
    fn context<C: Into<ErrorContext>>(self, context: C) -> Result<T, VaultError> {
        self.map_err(|e| e.into().with_context(context))
    }

    fn with_context<C, F>(self, f: F) -> Result<T, VaultError>
    where
        C: Into<ErrorContext>,
        F: FnOnce() -> C,
    {
        self.map_err(|e| e.into().with_context(f()))
    }

    fn retry_if<P>(self, predicate: P) -> RetryableResult<T, E>
    where
        P: Fn(&E) -> bool,
    {
        match self {
            Ok(value) => RetryableResult::Ok(value),
            Err(e) if predicate(&e) => RetryableResult::Retry(e),
            Err(e) => RetryableResult::Fatal(e),
        }
    }

    fn or_default_if<P>(self, predicate: P, default: T) -> Result<T, E>
    where
        P: Fn(&E) -> bool,
    {
        match self {
            Ok(value) => Ok(value),
            Err(e) if predicate(&e) => Ok(default),
            Err(e) => Err(e),
        }
    }

    fn log_error(self, message: &str) -> Result<T, E> {
        if let Err(ref e) = self {
            log::error!("{}: {:?}", message, e);
        }
        self
    }

    fn record_error_metric(self, operation: &str) -> Result<T, E> {
        if let Err(ref e) = self {
            METRICS.record_error(&format!("{:?}", e), operation);
        }
        self
    }

    fn span_error(self) -> Result<T, E> {
        if let Err(ref e) = self {
            if let Some(span) = current_span() {
                span.record_error(format!("{:?}", e));
            }
        }
        self
    }
}

/// Retryable result type
pub enum RetryableResult<T, E> {
    Ok(T),
    Retry(E),
    Fatal(E),
}

//==============================================================================
// RETRY STRATEGIES
//==============================================================================

/// Retry policy configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_attempts: u32,

    /// Initial backoff duration
    pub initial_backoff: Duration,

    /// Maximum backoff duration
    pub max_backoff: Duration,

    /// Backoff multiplier
    pub backoff_multiplier: f64,

    /// Add jitter to backoff
    pub jitter: bool,

    /// Timeout for each attempt
    pub timeout: Option<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
            timeout: Some(Duration::from_secs(30)),
        }
    }
}

impl RetryPolicy {
    /// Calculate backoff duration for attempt
    pub fn backoff_duration(&self, attempt: u32) -> Duration {
        let mut duration = self.initial_backoff.mul_f64(self.backoff_multiplier.powi(attempt as i32));

        if duration > self.max_backoff {
            duration = self.max_backoff;
        }

        if self.jitter {
            let jitter = rand::random::<f64>() * 0.3;  // ±30% jitter
            duration = duration.mul_f64(1.0 + jitter - 0.15);
        }

        duration
    }
}

/// Retry operation with policy
pub async fn retry_with_policy<T, E, F, Fut>(
    policy: &RetryPolicy,
    operation: F,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut attempt = 0;

    loop {
        attempt += 1;

        let result = if let Some(timeout) = policy.timeout {
            tokio::time::timeout(timeout, operation()).await
                .map_err(|_| {
                    log::warn!("Attempt {} timed out after {:?}", attempt, timeout);
                    // Return timeout error
                })
                .and_then(|r| r)
        } else {
            operation().await
        };

        match result {
            Ok(value) => {
                if attempt > 1 {
                    log::info!("Operation succeeded after {} attempts", attempt);
                }
                return Ok(value);
            }
            Err(e) if attempt >= policy.max_attempts => {
                log::error!("Operation failed after {} attempts: {:?}", attempt, e);
                return Err(e);
            }
            Err(e) => {
                let backoff = policy.backoff_duration(attempt - 1);
                log::warn!(
                    "Attempt {} failed: {:?}. Retrying in {:?}",
                    attempt, e, backoff
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Check if error is retryable
pub fn is_retryable(error: &VaultError) -> bool {
    match error {
        VaultError::Storage { retryable, .. } => *retryable,
        VaultError::Kms { retryable, .. } => *retryable,
        VaultError::Database { retryable, .. } => *retryable,
        VaultError::Network { retryable, .. } => *retryable,
        VaultError::ExternalService { retryable, .. } => *retryable,
        VaultError::Timeout { .. } => true,
        VaultError::RateLimit { .. } => true,
        _ => false,
    }
}

//==============================================================================
// METRICS SYSTEM
//==============================================================================

use prometheus::{
    Counter, CounterVec, Histogram, HistogramVec, Gauge, GaugeVec,
    Registry, Opts, HistogramOpts, IntCounter, IntCounterVec,
};

/// Global metrics registry
pub struct MetricsRegistry {
    /// Underlying Prometheus registry
    registry: Registry,

    // Counters
    requests_total: IntCounterVec,
    errors_total: IntCounterVec,
    storage_operations_total: IntCounterVec,
    storage_bytes_total: CounterVec,

    // Histograms
    request_duration_seconds: HistogramVec,
    storage_operation_duration_seconds: HistogramVec,
    record_size_bytes: HistogramVec,
    encryption_duration_seconds: HistogramVec,

    // Gauges
    active_connections: IntGauge,
    cache_size_bytes: IntGauge,
    cache_entries: IntGauge,
    queue_depth: IntGaugeVec,
    active_requests: IntGaugeVec,
}

impl MetricsRegistry {
    /// Create new metrics registry
    pub fn new() -> Result<Self, VaultError> {
        let registry = Registry::new();

        // Initialize counters
        let requests_total = IntCounterVec::new(
            Opts::new("vault_requests_total", "Total number of requests"),
            &["method", "path", "status"],
        )?;

        let errors_total = IntCounterVec::new(
            Opts::new("vault_errors_total", "Total number of errors"),
            &["error_type", "operation", "retryable"],
        )?;

        let storage_operations_total = IntCounterVec::new(
            Opts::new("vault_storage_operations_total", "Total storage operations"),
            &["backend", "operation", "status"],
        )?;

        let storage_bytes_total = CounterVec::new(
            Opts::new("vault_storage_bytes_total", "Total bytes transferred"),
            &["backend", "operation"],
        )?;

        // Initialize histograms
        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "vault_request_duration_seconds",
                "Request duration in seconds",
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["method", "path"],
        )?;

        let storage_operation_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "vault_storage_operation_duration_seconds",
                "Storage operation duration in seconds",
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
            &["backend", "operation"],
        )?;

        let record_size_bytes = HistogramVec::new(
            HistogramOpts::new(
                "vault_record_size_bytes",
                "Record size in bytes",
            ).buckets(vec![
                1024.0,           // 1 KB
                10240.0,          // 10 KB
                102400.0,         // 100 KB
                1048576.0,        // 1 MB
                10485760.0,       // 10 MB
                104857600.0,      // 100 MB
            ]),
            &["operation"],
        )?;

        let encryption_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "vault_encryption_duration_seconds",
                "Encryption/decryption duration in seconds",
            ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]),
            &["operation", "algorithm"],
        )?;

        // Initialize gauges
        let active_connections = IntGauge::new(
            "vault_active_connections",
            "Number of active connections",
        )?;

        let cache_size_bytes = IntGauge::new(
            "vault_cache_size_bytes",
            "Cache size in bytes",
        )?;

        let cache_entries = IntGauge::new(
            "vault_cache_entries",
            "Number of cache entries",
        )?;

        let queue_depth = IntGaugeVec::new(
            Opts::new("vault_queue_depth", "Queue depth"),
            &["queue_name"],
        )?;

        let active_requests = IntGaugeVec::new(
            Opts::new("vault_active_requests", "Active requests"),
            &["method", "path"],
        )?;

        // Register all metrics
        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(errors_total.clone()))?;
        registry.register(Box::new(storage_operations_total.clone()))?;
        registry.register(Box::new(storage_bytes_total.clone()))?;
        registry.register(Box::new(request_duration_seconds.clone()))?;
        registry.register(Box::new(storage_operation_duration_seconds.clone()))?;
        registry.register(Box::new(record_size_bytes.clone()))?;
        registry.register(Box::new(encryption_duration_seconds.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(cache_size_bytes.clone()))?;
        registry.register(Box::new(cache_entries.clone()))?;
        registry.register(Box::new(queue_depth.clone()))?;
        registry.register(Box::new(active_requests.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            errors_total,
            storage_operations_total,
            storage_bytes_total,
            request_duration_seconds,
            storage_operation_duration_seconds,
            record_size_bytes,
            encryption_duration_seconds,
            active_connections,
            cache_size_bytes,
            cache_entries,
            queue_depth,
            active_requests,
        })
    }

    /// Get Prometheus registry for exposition
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

/// Metrics collector trait
pub trait MetricsCollector {
    /// Record HTTP request
    fn record_request(&self, method: &str, path: &str, status: u16, duration: Duration);

    /// Record error occurrence
    fn record_error(&self, error_type: &str, operation: &str, retryable: bool);

    /// Record storage operation
    fn record_storage_operation(
        &self,
        backend: &str,
        operation: &str,
        bytes: u64,
        duration: Duration,
        success: bool,
    );

    /// Record encryption operation
    fn record_encryption(&self, operation: &str, algorithm: &str, duration: Duration);

    /// Record record size
    fn record_record_size(&self, operation: &str, bytes: u64);

    /// Set gauge value
    fn set_gauge(&self, name: &str, value: i64, labels: &[(&str, &str)]);

    /// Increment gauge
    fn inc_gauge(&self, name: &str, labels: &[(&str, &str)]);

    /// Decrement gauge
    fn dec_gauge(&self, name: &str, labels: &[(&str, &str)]);
}

impl MetricsCollector for MetricsRegistry {
    fn record_request(&self, method: &str, path: &str, status: u16, duration: Duration) {
        self.requests_total
            .with_label_values(&[method, path, &status.to_string()])
            .inc();

        self.request_duration_seconds
            .with_label_values(&[method, path])
            .observe(duration.as_secs_f64());
    }

    fn record_error(&self, error_type: &str, operation: &str, retryable: bool) {
        self.errors_total
            .with_label_values(&[error_type, operation, &retryable.to_string()])
            .inc();
    }

    fn record_storage_operation(
        &self,
        backend: &str,
        operation: &str,
        bytes: u64,
        duration: Duration,
        success: bool,
    ) {
        let status = if success { "success" } else { "failure" };

        self.storage_operations_total
            .with_label_values(&[backend, operation, status])
            .inc();

        self.storage_bytes_total
            .with_label_values(&[backend, operation])
            .inc_by(bytes as f64);

        self.storage_operation_duration_seconds
            .with_label_values(&[backend, operation])
            .observe(duration.as_secs_f64());
    }

    fn record_encryption(&self, operation: &str, algorithm: &str, duration: Duration) {
        self.encryption_duration_seconds
            .with_label_values(&[operation, algorithm])
            .observe(duration.as_secs_f64());
    }

    fn record_record_size(&self, operation: &str, bytes: u64) {
        self.record_size_bytes
            .with_label_values(&[operation])
            .observe(bytes as f64);
    }

    fn set_gauge(&self, name: &str, value: i64, labels: &[(&str, &str)]) {
        match name {
            "active_connections" => self.active_connections.set(value),
            "cache_size_bytes" => self.cache_size_bytes.set(value),
            "cache_entries" => self.cache_entries.set(value),
            "queue_depth" => {
                if let Some((_, queue_name)) = labels.first() {
                    self.queue_depth.with_label_values(&[queue_name]).set(value);
                }
            }
            _ => {}
        }
    }

    fn inc_gauge(&self, name: &str, labels: &[(&str, &str)]) {
        match name {
            "active_connections" => self.active_connections.inc(),
            "cache_entries" => self.cache_entries.inc(),
            "active_requests" => {
                if labels.len() >= 2 {
                    self.active_requests
                        .with_label_values(&[labels[0].1, labels[1].1])
                        .inc();
                }
            }
            _ => {}
        }
    }

    fn dec_gauge(&self, name: &str, labels: &[(&str, &str)]) {
        match name {
            "active_connections" => self.active_connections.dec(),
            "cache_entries" => self.cache_entries.dec(),
            "active_requests" => {
                if labels.len() >= 2 {
                    self.active_requests
                        .with_label_values(&[labels[0].1, labels[1].1])
                        .dec();
                }
            }
            _ => {}
        }
    }
}

/// Global metrics instance
lazy_static! {
    pub static ref METRICS: MetricsRegistry = MetricsRegistry::new()
        .expect("Failed to initialize metrics registry");
}

//==============================================================================
// DISTRIBUTED TRACING
//==============================================================================

use opentelemetry::{
    trace::{Tracer as OtelTracer, TracerProvider, Span as OtelSpan},
    Context as OtelContext,
    KeyValue,
};

/// Tracing configuration
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Service name for traces
    pub service_name: String,

    /// Trace exporter backend
    pub exporter: TracingExporter,

    /// Sampling ratio (0.0 - 1.0)
    pub sampling_ratio: f64,

    /// Trace context propagation format
    pub propagation: PropagationFormat,

    /// Endpoint for trace export
    pub endpoint: Option<String>,

    /// Batch size for export
    pub batch_size: usize,

    /// Export timeout
    pub export_timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum TracingExporter {
    Jaeger,
    Zipkin,
    Otlp,
    Stdout,
    None,
}

#[derive(Debug, Clone)]
pub enum PropagationFormat {
    W3C,           // W3C Trace Context
    B3,            // Zipkin B3
    Jaeger,        // Jaeger propagation
    TraceContext,  // OpenTelemetry trace context
}

/// Distributed tracer
pub struct Tracer {
    config: TracingConfig,
    provider: TracerProvider,
    tracer: Box<dyn OtelTracer + Send + Sync>,
}

impl Tracer {
    /// Initialize tracer with configuration
    pub fn new(config: TracingConfig) -> Result<Self, VaultError> {
        let provider = match config.exporter {
            TracingExporter::Jaeger => {
                opentelemetry_jaeger::new_pipeline()
                    .with_service_name(&config.service_name)
                    .with_agent_endpoint(config.endpoint.as_deref().unwrap_or("localhost:6831"))
                    .install_batch(opentelemetry::runtime::Tokio)?
            }
            TracingExporter::Otlp => {
                opentelemetry_otlp::new_pipeline()
                    .tracing()
                    .with_exporter(
                        opentelemetry_otlp::new_exporter()
                            .tonic()
                            .with_endpoint(config.endpoint.as_deref().unwrap_or("http://localhost:4317"))
                    )
                    .install_batch(opentelemetry::runtime::Tokio)?
            }
            TracingExporter::Stdout => {
                opentelemetry_stdout::new_pipeline()
                    .install_simple()
            }
            TracingExporter::None => {
                // No-op tracer
                opentelemetry::sdk::trace::TracerProvider::default()
            }
            _ => todo!("Implement other exporters"),
        };

        let tracer = provider.tracer(&config.service_name);

        Ok(Self {
            config,
            provider,
            tracer: Box::new(tracer),
        })
    }

    /// Start a new span
    pub fn start_span(&self, name: &str) -> Span {
        let otel_span = self.tracer.start(name);
        Span::new(otel_span)
    }

    /// Get current span from context
    pub fn current_span(&self) -> Option<Span> {
        let ctx = OtelContext::current();
        let otel_span = ctx.span();
        Some(Span::new(otel_span.clone()))
    }

    /// Inject trace context into carrier
    pub fn inject_context<C: Carrier>(&self, carrier: &mut C) {
        let ctx = OtelContext::current();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&ctx, carrier);
        });
    }

    /// Extract trace context from carrier
    pub fn extract_context<C: Carrier>(&self, carrier: &C) -> Option<SpanContext> {
        let ctx = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(carrier)
        });

        let span = ctx.span();
        let span_ctx = span.span_context();

        Some(SpanContext {
            trace_id: TraceId(span_ctx.trace_id().to_string()),
            span_id: SpanId(span_ctx.span_id().to_string()),
            trace_flags: span_ctx.trace_flags(),
            is_remote: span_ctx.is_remote(),
        })
    }
}

/// Trace span
pub struct Span {
    inner: Box<dyn OtelSpan + Send + Sync>,
    start_time: Instant,
    attributes: HashMap<String, Value>,
    events: Vec<SpanEvent>,
}

impl Span {
    fn new(inner: impl OtelSpan + Send + Sync + 'static) -> Self {
        Self {
            inner: Box::new(inner),
            start_time: Instant::now(),
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Set span attribute
    pub fn set_attribute(&mut self, key: &str, value: impl Into<Value>) {
        let val = value.into();
        self.attributes.insert(key.to_string(), val.clone());
        self.inner.set_attribute(KeyValue::new(key.to_string(), format!("{:?}", val)));
    }

    /// Add span event
    pub fn add_event(&mut self, name: &str, attributes: HashMap<String, Value>) {
        let event = SpanEvent {
            name: name.to_string(),
            timestamp: Utc::now(),
            attributes: attributes.clone(),
        };
        self.events.push(event);

        let kvs: Vec<KeyValue> = attributes
            .into_iter()
            .map(|(k, v)| KeyValue::new(k, format!("{:?}", v)))
            .collect();

        self.inner.add_event(name.to_string(), kvs);
    }

    /// Record error in span
    pub fn record_error(&mut self, error: impl std::fmt::Display) {
        self.inner.record_error(&error.to_string());
        self.set_attribute("error", true);
        self.set_attribute("error.message", error.to_string());
    }

    /// Set span status
    pub fn set_status(&mut self, status: SpanStatus) {
        use opentelemetry::trace::Status;
        let otel_status = match status {
            SpanStatus::Ok => Status::Ok,
            SpanStatus::Error => Status::Error {
                description: "Error occurred".into()
            },
        };
        self.inner.set_status(otel_status);
    }

    /// End span
    pub fn end(self) {
        self.inner.end();
    }

    /// Get span context
    pub fn context(&self) -> SpanContext {
        let span_ctx = self.inner.span_context();
        SpanContext {
            trace_id: TraceId(span_ctx.trace_id().to_string()),
            span_id: SpanId(span_ctx.span_id().to_string()),
            trace_flags: span_ctx.trace_flags(),
            is_remote: span_ctx.is_remote(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpanContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub trace_flags: u8,
    pub is_remote: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp: DateTime<Utc>,
    pub attributes: HashMap<String, Value>,
}

#[derive(Debug, Clone, Copy)]
pub enum SpanStatus {
    Ok,
    Error,
}

/// Carrier for trace context propagation
pub trait Carrier {
    fn set(&mut self, key: String, value: String);
    fn get(&self, key: &str) -> Option<&str>;
    fn keys(&self) -> Vec<&str>;
}

/// HTTP headers carrier
impl Carrier for http::HeaderMap {
    fn set(&mut self, key: String, value: String) {
        if let (Ok(name), Ok(val)) = (
            http::header::HeaderName::from_bytes(key.as_bytes()),
            http::header::HeaderValue::from_str(&value),
        ) {
            self.insert(name, val);
        }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.keys().map(|k| k.as_str()).collect()
    }
}

/// Global tracer instance
lazy_static! {
    pub static ref TRACER: Tracer = Tracer::new(TracingConfig {
        service_name: "llm-data-vault".to_string(),
        exporter: TracingExporter::Otlp,
        sampling_ratio: 1.0,
        propagation: PropagationFormat::W3C,
        endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
        batch_size: 512,
        export_timeout: Duration::from_secs(30),
    }).expect("Failed to initialize tracer");
}

//==============================================================================
// STRUCTURED LOGGING
//==============================================================================

use serde_json::json;
use tracing::{info, warn, error, debug, trace};
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Log level filter
    pub level: LogLevel,

    /// Log output format
    pub format: LogFormat,

    /// Log output destination
    pub output: LogOutput,

    /// Include trace IDs in logs
    pub include_trace: bool,

    /// Mask sensitive fields
    pub sensitive_field_masking: bool,

    /// Pretty print in dev mode
    pub pretty_print: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

#[derive(Debug, Clone)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File(PathBuf),
    Both(PathBuf),
}

/// Structured log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp (ISO 8601)
    pub timestamp: DateTime<Utc>,

    /// Log level
    pub level: String,

    /// Log message
    pub message: String,

    /// Log target (module path)
    pub target: String,

    /// Request ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Trace ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Span ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,

    /// User ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Additional structured fields
    #[serde(flatten)]
    pub fields: HashMap<String, Value>,
}

/// Initialize logging system
pub fn init_logging(config: LogConfig) -> Result<(), VaultError> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::new(match config.level {
                LogLevel::Trace => "trace",
                LogLevel::Debug => "debug",
                LogLevel::Info => "info",
                LogLevel::Warn => "warn",
                LogLevel::Error => "error",
            })
        });

    let subscriber = tracing_subscriber::registry()
        .with(filter);

    match config.format {
        LogFormat::Json => {
            let json_layer = fmt::layer()
                .json()
                .with_current_span(config.include_trace)
                .with_span_list(config.include_trace);

            subscriber.with(json_layer).init();
        }
        LogFormat::Pretty => {
            let pretty_layer = fmt::layer()
                .pretty()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true);

            subscriber.with(pretty_layer).init();
        }
        LogFormat::Compact => {
            let compact_layer = fmt::layer().compact();
            subscriber.with(compact_layer).init();
        }
    }

    Ok(())
}

/// Sensitive field masking
pub fn mask_sensitive_value(value: &str) -> String {
    if value.len() <= 8 {
        "***".to_string()
    } else {
        format!("{}...{}", &value[..4], &value[value.len()-4..])
    }
}

/// Check if field should be masked
pub fn is_sensitive_field(field_name: &str) -> bool {
    const SENSITIVE_FIELDS: &[&str] = &[
        "password",
        "secret",
        "token",
        "api_key",
        "private_key",
        "access_key",
        "credential",
        "authorization",
    ];

    let lower = field_name.to_lowercase();
    SENSITIVE_FIELDS.iter().any(|&f| lower.contains(f))
}

/// Log macros with context
#[macro_export]
macro_rules! log_info {
    ($($key:ident = $value:expr),* $(,)?, $msg:expr) => {{
        let span = $crate::observability::current_span();
        tracing::info!(
            request_id = ?$crate::observability::RequestId::current(),
            trace_id = ?span.as_ref().map(|s| s.context().trace_id),
            span_id = ?span.as_ref().map(|s| s.context().span_id),
            $($key = $value,)*
            $msg
        );
    }};
}

#[macro_export]
macro_rules! log_error {
    ($($key:ident = $value:expr),* $(,)?, $msg:expr) => {{
        let span = $crate::observability::current_span();
        tracing::error!(
            request_id = ?$crate::observability::RequestId::current(),
            trace_id = ?span.as_ref().map(|s| s.context().trace_id),
            span_id = ?span.as_ref().map(|s| s.context().span_id),
            $($key = $value,)*
            $msg
        );

        // Record error in metrics
        $crate::observability::METRICS.record_error(
            stringify!($msg),
            "unknown",
            false,
        );
    }};
}

#[macro_export]
macro_rules! log_warn {
    ($($key:ident = $value:expr),* $(,)?, $msg:expr) => {{
        let span = $crate::observability::current_span();
        tracing::warn!(
            request_id = ?$crate::observability::RequestId::current(),
            trace_id = ?span.as_ref().map(|s| s.context().trace_id),
            span_id = ?span.as_ref().map(|s| s.context().span_id),
            $($key = $value,)*
            $msg
        );
    }};
}

#[macro_export]
macro_rules! log_debug {
    ($($key:ident = $value:expr),* $(,)?, $msg:expr) => {{
        tracing::debug!(
            $($key = $value,)*
            $msg
        );
    }};
}

//==============================================================================
// HEALTH CHECK SYSTEM
//==============================================================================

/// Health checker trait
#[async_trait::async_trait]
pub trait HealthChecker: Send + Sync {
    /// Check if service is alive (basic process health)
    async fn liveness(&self) -> HealthStatus;

    /// Check if service is ready to accept traffic
    async fn readiness(&self) -> HealthStatus;

    /// Check if service has completed startup
    async fn startup(&self) -> HealthStatus;
}

/// Health status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health state
    pub status: HealthState,

    /// Individual component health checks
    pub checks: Vec<ComponentHealth>,

    /// Service version
    pub version: String,

    /// Service uptime
    pub uptime: Duration,

    /// Timestamp of health check
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,

    /// Component health state
    pub status: HealthState,

    /// Status message
    pub message: Option<String>,

    /// Last successful check time
    pub last_check: DateTime<Utc>,

    /// Check latency
    pub latency: Option<Duration>,

    /// Additional metadata
    pub metadata: HashMap<String, Value>,
}

/// Aggregated health checker
pub struct VaultHealthChecker {
    checkers: Vec<Box<dyn ComponentHealthChecker>>,
    start_time: Instant,
    startup_complete: Arc<AtomicBool>,
}

impl VaultHealthChecker {
    pub fn new() -> Self {
        Self {
            checkers: Vec::new(),
            start_time: Instant::now(),
            startup_complete: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Register component health checker
    pub fn register(&mut self, checker: Box<dyn ComponentHealthChecker>) {
        self.checkers.push(checker);
    }

    /// Mark startup as complete
    pub fn complete_startup(&self) {
        self.startup_complete.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl HealthChecker for VaultHealthChecker {
    async fn liveness(&self) -> HealthStatus {
        // Liveness is simple - if we can respond, we're alive
        HealthStatus {
            status: HealthState::Healthy,
            checks: vec![
                ComponentHealth {
                    name: "process".to_string(),
                    status: HealthState::Healthy,
                    message: Some("Process is running".to_string()),
                    last_check: Utc::now(),
                    latency: None,
                    metadata: HashMap::new(),
                }
            ],
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: self.start_time.elapsed(),
            timestamp: Utc::now(),
        }
    }

    async fn readiness(&self) -> HealthStatus {
        let mut checks = Vec::new();
        let mut overall_status = HealthState::Healthy;

        // Check all components
        for checker in &self.checkers {
            let start = Instant::now();
            let component_status = checker.check().await;
            let latency = start.elapsed();

            let mut component = component_status;
            component.latency = Some(latency);

            // Aggregate status
            match component.status {
                HealthState::Unhealthy => overall_status = HealthState::Unhealthy,
                HealthState::Degraded if overall_status == HealthState::Healthy => {
                    overall_status = HealthState::Degraded;
                }
                _ => {}
            }

            checks.push(component);
        }

        HealthStatus {
            status: overall_status,
            checks,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: self.start_time.elapsed(),
            timestamp: Utc::now(),
        }
    }

    async fn startup(&self) -> HealthStatus {
        if !self.startup_complete.load(Ordering::SeqCst) {
            return HealthStatus {
                status: HealthState::Unhealthy,
                checks: vec![
                    ComponentHealth {
                        name: "startup".to_string(),
                        status: HealthState::Unhealthy,
                        message: Some("Startup not complete".to_string()),
                        last_check: Utc::now(),
                        latency: None,
                        metadata: HashMap::new(),
                    }
                ],
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime: self.start_time.elapsed(),
                timestamp: Utc::now(),
            };
        }

        // After startup, same as readiness
        self.readiness().await
    }
}

/// Component-level health checker
#[async_trait::async_trait]
pub trait ComponentHealthChecker: Send + Sync {
    async fn check(&self) -> ComponentHealth;
}

/// Database health checker
pub struct DatabaseHealthChecker {
    pool: Arc<DatabasePool>,
}

#[async_trait::async_trait]
impl ComponentHealthChecker for DatabaseHealthChecker {
    async fn check(&self) -> ComponentHealth {
        match self.pool.execute("SELECT 1").await {
            Ok(_) => ComponentHealth {
                name: "database".to_string(),
                status: HealthState::Healthy,
                message: Some("Database connection OK".to_string()),
                last_check: Utc::now(),
                latency: None,
                metadata: hashmap! {
                    "active_connections".to_string() => json!(self.pool.active_connections()),
                    "idle_connections".to_string() => json!(self.pool.idle_connections()),
                },
            },
            Err(e) => ComponentHealth {
                name: "database".to_string(),
                status: HealthState::Unhealthy,
                message: Some(format!("Database check failed: {}", e)),
                last_check: Utc::now(),
                latency: None,
                metadata: HashMap::new(),
            },
        }
    }
}

/// Storage backend health checker
pub struct StorageHealthChecker {
    backend: Arc<dyn StorageBackend>,
}

#[async_trait::async_trait]
impl ComponentHealthChecker for StorageHealthChecker {
    async fn check(&self) -> ComponentHealth {
        // Attempt to list objects or perform a lightweight operation
        match self.backend.health_check().await {
            Ok(_) => ComponentHealth {
                name: format!("storage_{}", self.backend.name()),
                status: HealthState::Healthy,
                message: Some("Storage backend accessible".to_string()),
                last_check: Utc::now(),
                latency: None,
                metadata: HashMap::new(),
            },
            Err(e) => ComponentHealth {
                name: format!("storage_{}", self.backend.name()),
                status: HealthState::Unhealthy,
                message: Some(format!("Storage check failed: {}", e)),
                last_check: Utc::now(),
                latency: None,
                metadata: HashMap::new(),
            },
        }
    }
}

/// KMS health checker
pub struct KmsHealthChecker {
    provider: Arc<dyn KmsProvider>,
}

#[async_trait::async_trait]
impl ComponentHealthChecker for KmsHealthChecker {
    async fn check(&self) -> ComponentHealth {
        match self.provider.health_check().await {
            Ok(_) => ComponentHealth {
                name: "kms".to_string(),
                status: HealthState::Healthy,
                message: Some("KMS provider accessible".to_string()),
                last_check: Utc::now(),
                latency: None,
                metadata: HashMap::new(),
            },
            Err(e) => ComponentHealth {
                name: "kms".to_string(),
                status: HealthState::Unhealthy,
                message: Some(format!("KMS check failed: {}", e)),
                last_check: Utc::now(),
                latency: None,
                metadata: HashMap::new(),
            },
        }
    }
}

/// Memory usage health checker
pub struct MemoryHealthChecker {
    threshold_percent: f64,
}

#[async_trait::async_trait]
impl ComponentHealthChecker for MemoryHealthChecker {
    async fn check(&self) -> ComponentHealth {
        let memory_info = sys_info::mem_info().unwrap();
        let used_percent = (memory_info.total - memory_info.avail) as f64 / memory_info.total as f64 * 100.0;

        let status = if used_percent > self.threshold_percent {
            HealthState::Degraded
        } else {
            HealthState::Healthy
        };

        ComponentHealth {
            name: "memory".to_string(),
            status,
            message: Some(format!("Memory usage: {:.2}%", used_percent)),
            last_check: Utc::now(),
            latency: None,
            metadata: hashmap! {
                "total_mb".to_string() => json!(memory_info.total / 1024),
                "available_mb".to_string() => json!(memory_info.avail / 1024),
                "used_percent".to_string() => json!(used_percent),
            },
        }
    }
}

//==============================================================================
// ALERTING SYSTEM
//==============================================================================

/// Alert rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Unique rule identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Alert condition
    pub condition: AlertCondition,

    /// Alert severity
    pub severity: AlertSeverity,

    /// Notification channels
    pub channels: Vec<AlertChannel>,

    /// Minimum time between alerts
    pub cooldown: Duration,

    /// Additional annotations
    pub annotations: HashMap<String, String>,

    /// Last fired timestamp
    #[serde(skip)]
    pub last_fired: Option<Instant>,
}

/// Alert condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    /// Metric threshold
    MetricThreshold {
        metric: String,
        operator: ComparisonOperator,
        threshold: f64,
        duration: Duration,
    },

    /// Error rate
    ErrorRate {
        threshold_percent: f64,
        window: Duration,
    },

    /// Health check failure
    HealthCheckFailed {
        component: String,
        consecutive_failures: u32,
    },

    /// Custom condition
    Custom {
        expression: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equal,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    Error,
    Warning,
    Info,
}

/// Alert notification channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertChannel {
    PagerDuty {
        routing_key: String,
    },

    Slack {
        webhook_url: Url,
        channel: String,
        mention_users: Vec<String>,
    },

    Email {
        recipients: Vec<String>,
        smtp_config: SmtpConfig,
    },

    Webhook {
        url: Url,
        method: HttpMethod,
        headers: HashMap<String, String>,
        body_template: String,
    },

    Opsgenie {
        api_key: String,
        team: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
}

/// Alert manager
pub struct AlertManager {
    rules: Vec<AlertRule>,
    alert_history: Arc<RwLock<VecDeque<AlertEvent>>>,
}

impl AlertManager {
    pub fn new(rules: Vec<AlertRule>) -> Self {
        Self {
            rules,
            alert_history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
        }
    }

    /// Evaluate all alert rules
    pub async fn evaluate_rules(&mut self) -> Result<(), VaultError> {
        for rule in &mut self.rules {
            if self.should_evaluate(rule) {
                if self.evaluate_condition(&rule.condition).await? {
                    self.fire_alert(rule).await?;
                    rule.last_fired = Some(Instant::now());
                }
            }
        }
        Ok(())
    }

    fn should_evaluate(&self, rule: &AlertRule) -> bool {
        if let Some(last_fired) = rule.last_fired {
            last_fired.elapsed() >= rule.cooldown
        } else {
            true
        }
    }

    async fn evaluate_condition(&self, condition: &AlertCondition) -> Result<bool, VaultError> {
        match condition {
            AlertCondition::MetricThreshold { metric, operator, threshold, duration } => {
                // Query metrics from registry
                let value = self.query_metric(metric, *duration).await?;
                Ok(self.compare_values(value, *operator, *threshold))
            }

            AlertCondition::ErrorRate { threshold_percent, window } => {
                let error_rate = self.calculate_error_rate(*window).await?;
                Ok(error_rate > *threshold_percent)
            }

            AlertCondition::HealthCheckFailed { component, consecutive_failures } => {
                let failures = self.get_consecutive_failures(component).await?;
                Ok(failures >= *consecutive_failures)
            }

            AlertCondition::Custom { expression } => {
                // Evaluate custom expression
                self.evaluate_custom_expression(expression).await
            }
        }
    }

    async fn fire_alert(&self, rule: &AlertRule) -> Result<(), VaultError> {
        let event = AlertEvent {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity,
            timestamp: Utc::now(),
            message: self.render_alert_message(rule),
            annotations: rule.annotations.clone(),
        };

        // Add to history
        {
            let mut history = self.alert_history.write().await;
            history.push_back(event.clone());
            if history.len() > 1000 {
                history.pop_front();
            }
        }

        // Send to all channels
        for channel in &rule.channels {
            if let Err(e) = self.send_alert(channel, &event).await {
                log::error!("Failed to send alert to {:?}: {}", channel, e);
            }
        }

        Ok(())
    }

    async fn send_alert(&self, channel: &AlertChannel, event: &AlertEvent) -> Result<(), VaultError> {
        match channel {
            AlertChannel::PagerDuty { routing_key } => {
                self.send_pagerduty_alert(routing_key, event).await
            }

            AlertChannel::Slack { webhook_url, channel, mention_users } => {
                self.send_slack_alert(webhook_url, channel, mention_users, event).await
            }

            AlertChannel::Email { recipients, smtp_config } => {
                self.send_email_alert(recipients, smtp_config, event).await
            }

            AlertChannel::Webhook { url, method, headers, body_template } => {
                self.send_webhook_alert(url, method, headers, body_template, event).await
            }

            AlertChannel::Opsgenie { api_key, team } => {
                self.send_opsgenie_alert(api_key, team.as_deref(), event).await
            }
        }
    }

    fn render_alert_message(&self, rule: &AlertRule) -> String {
        format!(
            "[{}] {} - Condition: {:?}",
            rule.severity,
            rule.name,
            rule.condition
        )
    }

    fn compare_values(&self, value: f64, operator: ComparisonOperator, threshold: f64) -> bool {
        match operator {
            ComparisonOperator::GreaterThan => value > threshold,
            ComparisonOperator::LessThan => value < threshold,
            ComparisonOperator::Equal => (value - threshold).abs() < f64::EPSILON,
            ComparisonOperator::GreaterThanOrEqual => value >= threshold,
            ComparisonOperator::LessThanOrEqual => value <= threshold,
        }
    }

    async fn query_metric(&self, metric: &str, duration: Duration) -> Result<f64, VaultError> {
        // Implementation would query Prometheus or metrics registry
        todo!("Query metric from registry")
    }

    async fn calculate_error_rate(&self, window: Duration) -> Result<f64, VaultError> {
        // Calculate error rate from metrics
        todo!("Calculate error rate")
    }

    async fn get_consecutive_failures(&self, component: &str) -> Result<u32, VaultError> {
        // Get consecutive health check failures
        todo!("Get consecutive failures")
    }

    async fn evaluate_custom_expression(&self, expression: &str) -> Result<bool, VaultError> {
        // Evaluate custom expression
        todo!("Evaluate custom expression")
    }

    async fn send_pagerduty_alert(&self, routing_key: &str, event: &AlertEvent) -> Result<(), VaultError> {
        // Send to PagerDuty Events API
        todo!("Send PagerDuty alert")
    }

    async fn send_slack_alert(
        &self,
        webhook_url: &Url,
        channel: &str,
        mention_users: &[String],
        event: &AlertEvent,
    ) -> Result<(), VaultError> {
        let mentions = mention_users
            .iter()
            .map(|u| format!("<@{}>", u))
            .collect::<Vec<_>>()
            .join(" ");

        let payload = json!({
            "channel": channel,
            "text": format!("{} {}", mentions, event.message),
            "attachments": [{
                "color": match event.severity {
                    AlertSeverity::Critical => "danger",
                    AlertSeverity::Error => "warning",
                    AlertSeverity::Warning => "warning",
                    AlertSeverity::Info => "good",
                },
                "fields": [
                    {
                        "title": "Severity",
                        "value": format!("{:?}", event.severity),
                        "short": true
                    },
                    {
                        "title": "Time",
                        "value": event.timestamp.to_rfc3339(),
                        "short": true
                    }
                ]
            }]
        });

        // Send HTTP POST to webhook
        todo!("Send Slack webhook")
    }

    async fn send_email_alert(
        &self,
        recipients: &[String],
        smtp_config: &SmtpConfig,
        event: &AlertEvent,
    ) -> Result<(), VaultError> {
        // Send email via SMTP
        todo!("Send email alert")
    }

    async fn send_webhook_alert(
        &self,
        url: &Url,
        method: &HttpMethod,
        headers: &HashMap<String, String>,
        body_template: &str,
        event: &AlertEvent,
    ) -> Result<(), VaultError> {
        // Send custom webhook
        todo!("Send webhook alert")
    }

    async fn send_opsgenie_alert(
        &self,
        api_key: &str,
        team: Option<&str>,
        event: &AlertEvent,
    ) -> Result<(), VaultError> {
        // Send to Opsgenie API
        todo!("Send Opsgenie alert")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub annotations: HashMap<String, String>,
}

//==============================================================================
// PANIC HANDLING
//==============================================================================

/// Install panic handler
pub fn install_panic_handler() {
    let default_panic = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |panic_info| {
        // Log panic
        let payload = panic_info.payload();
        let message = if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };

        let location = panic_info.location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        log::error!(
            "PANIC occurred: {} at {}",
            message,
            location
        );

        // Record panic metric
        METRICS.record_error("panic", "runtime", false);

        // Send alert for critical panics
        if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
            // Trigger critical alert
        }

        // Call default panic handler
        default_panic(panic_info);
    }));
}

//==============================================================================
// GRACEFUL SHUTDOWN
//==============================================================================

/// Shutdown coordinator
pub struct ShutdownCoordinator {
    signal: Arc<Notify>,
    timeout: Duration,
    hooks: Arc<RwLock<Vec<Box<dyn ShutdownHook>>>>,
}

impl ShutdownCoordinator {
    pub fn new(timeout: Duration) -> Self {
        Self {
            signal: Arc::new(Notify::new()),
            timeout,
            hooks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register shutdown hook
    pub async fn register_hook(&self, hook: Box<dyn ShutdownHook>) {
        self.hooks.write().await.push(hook);
    }

    /// Wait for shutdown signal
    pub async fn wait_for_signal(&self) {
        self.signal.notified().await;
    }

    /// Trigger shutdown
    pub fn trigger(&self) {
        self.signal.notify_waiters();
    }

    /// Execute graceful shutdown
    pub async fn shutdown(&self) -> Result<(), VaultError> {
        log::info!("Initiating graceful shutdown...");

        let hooks = self.hooks.read().await;

        // Execute all shutdown hooks with timeout
        let shutdown_future = async {
            for hook in hooks.iter() {
                if let Err(e) = hook.on_shutdown().await {
                    log::error!("Shutdown hook failed: {}", e);
                }
            }
        };

        match tokio::time::timeout(self.timeout, shutdown_future).await {
            Ok(_) => {
                log::info!("Graceful shutdown completed");
                Ok(())
            }
            Err(_) => {
                log::error!("Graceful shutdown timed out after {:?}", self.timeout);
                Err(VaultError::Timeout {
                    operation: "graceful_shutdown".to_string(),
                    duration: self.timeout,
                    deadline: Utc::now() + chrono::Duration::from_std(self.timeout).unwrap(),
                    context: ErrorContext::new("shutdown"),
                })
            }
        }
    }

    /// Install signal handlers
    pub fn install_signal_handlers(self: Arc<Self>) {
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigterm = signal(SignalKind::terminate())
                .expect("Failed to install SIGTERM handler");
            let mut sigint = signal(SignalKind::interrupt())
                .expect("Failed to install SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    log::info!("Received SIGTERM");
                }
                _ = sigint.recv() => {
                    log::info!("Received SIGINT");
                }
            }

            self.trigger();
            let _ = self.shutdown().await;
        });
    }
}

#[async_trait::async_trait]
pub trait ShutdownHook: Send + Sync {
    async fn on_shutdown(&self) -> Result<(), VaultError>;
}

//==============================================================================
// DEBUG DIAGNOSTICS
//==============================================================================

/// Diagnostics endpoint
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticsReport {
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub uptime: Duration,
    pub health: HealthStatus,
    pub metrics_summary: MetricsSummary,
    pub active_spans: Vec<SpanInfo>,
    pub recent_errors: Vec<ErrorSummary>,
    pub system_info: SystemInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSummary {
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub avg_request_duration: Duration,
    pub p95_request_duration: Duration,
    pub p99_request_duration: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpanInfo {
    pub trace_id: String,
    pub span_id: String,
    pub name: String,
    pub duration: Option<Duration>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorSummary {
    pub timestamp: DateTime<Utc>,
    pub error_type: String,
    pub message: String,
    pub operation: String,
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub cpu_count: usize,
    pub memory_total: u64,
    pub memory_available: u64,
    pub load_average: (f64, f64, f64),
}

/// Generate diagnostics report
pub async fn generate_diagnostics(
    health_checker: &VaultHealthChecker,
    start_time: Instant,
) -> Result<DiagnosticsReport, VaultError> {
    let health = health_checker.readiness().await;
    let system_info = get_system_info()?;

    Ok(DiagnosticsReport {
        timestamp: Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: start_time.elapsed(),
        health,
        metrics_summary: get_metrics_summary(),
        active_spans: get_active_spans(),
        recent_errors: get_recent_errors(),
        system_info,
    })
}

fn get_system_info() -> Result<SystemInfo, VaultError> {
    let hostname = hostname::get()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .to_string();

    let mem_info = sys_info::mem_info()?;
    let load_avg = sys_info::loadavg()?;

    Ok(SystemInfo {
        hostname,
        cpu_count: num_cpus::get(),
        memory_total: mem_info.total * 1024,
        memory_available: mem_info.avail * 1024,
        load_average: (load_avg.one, load_avg.five, load_avg.fifteen),
    })
}

fn get_metrics_summary() -> MetricsSummary {
    // Query metrics from registry
    MetricsSummary {
        total_requests: 0,
        total_errors: 0,
        error_rate: 0.0,
        avg_request_duration: Duration::from_secs(0),
        p95_request_duration: Duration::from_secs(0),
        p99_request_duration: Duration::from_secs(0),
    }
}

fn get_active_spans() -> Vec<SpanInfo> {
    // Get active spans from tracer
    Vec::new()
}

fn get_recent_errors() -> Vec<ErrorSummary> {
    // Get recent errors from error tracking
    Vec::new()
}

//==============================================================================
// PERFORMANCE PROFILING
//==============================================================================

/// Profiling configuration
#[derive(Debug, Clone)]
pub struct ProfilingConfig {
    pub enabled: bool,
    pub sample_rate: f64,
    pub output_path: PathBuf,
    pub profile_types: Vec<ProfileType>,
}

#[derive(Debug, Clone, Copy)]
pub enum ProfileType {
    Cpu,
    Memory,
    Allocations,
    BlockingIO,
}

/// Profiler integration
pub struct Profiler {
    config: ProfilingConfig,
}

impl Profiler {
    pub fn new(config: ProfilingConfig) -> Self {
        Self { config }
    }

    /// Start profiling
    pub fn start(&self) -> Result<(), VaultError> {
        if !self.config.enabled {
            return Ok(());
        }

        for profile_type in &self.config.profile_types {
            match profile_type {
                ProfileType::Cpu => self.start_cpu_profiling()?,
                ProfileType::Memory => self.start_memory_profiling()?,
                ProfileType::Allocations => self.start_allocation_profiling()?,
                ProfileType::BlockingIO => self.start_io_profiling()?,
            }
        }

        Ok(())
    }

    /// Stop profiling and generate report
    pub fn stop(&self) -> Result<PathBuf, VaultError> {
        // Generate profiling report
        Ok(self.config.output_path.clone())
    }

    fn start_cpu_profiling(&self) -> Result<(), VaultError> {
        // Start CPU profiling with pprof
        todo!("Start CPU profiling")
    }

    fn start_memory_profiling(&self) -> Result<(), VaultError> {
        // Start memory profiling
        todo!("Start memory profiling")
    }

    fn start_allocation_profiling(&self) -> Result<(), VaultError> {
        // Start allocation profiling
        todo!("Start allocation profiling")
    }

    fn start_io_profiling(&self) -> Result<(), VaultError> {
        // Start I/O profiling
        todo!("Start I/O profiling")
    }
}

//==============================================================================
// INITIALIZATION
//==============================================================================

/// Initialize observability system
pub async fn init_observability(
    log_config: LogConfig,
    tracing_config: TracingConfig,
) -> Result<(), VaultError> {
    // Install panic handler
    install_panic_handler();

    // Initialize logging
    init_logging(log_config)?;

    // Initialize tracing
    let _tracer = Tracer::new(tracing_config)?;

    log::info!("Observability system initialized");

    Ok(())
}
```

## Usage Examples

### Error Handling

```rust
// Create error with context
fn process_record(record_id: &RecordId) -> Result<(), VaultError> {
    let context = ErrorContext::new("process_record")
        .with_resource(record_id.clone())
        .with_metadata("dataset_id", dataset_id);

    storage.get(record_id)
        .await
        .context(context)?;

    Ok(())
}

// Retry on transient errors
let result = retry_with_policy(&RetryPolicy::default(), || async {
    storage.put(key, value).await
}).await?;

// Chain error context
dataset_service.create(params)
    .with_context(|| ErrorContext::new("api.create_dataset")
        .with_user(current_user.id)
        .with_metadata("project", project_id))
    .record_error_metric("create_dataset")
    .span_error()?;
```

### Metrics Collection

```rust
// Record request
let start = Instant::now();
let result = handle_request().await;
METRICS.record_request(
    "POST",
    "/api/v1/datasets",
    result.status_code(),
    start.elapsed(),
);

// Record storage operation
METRICS.record_storage_operation(
    "s3",
    "put",
    record_size,
    operation_duration,
    true,
);

// Update gauge
METRICS.inc_gauge("active_requests", &[("method", "POST"), ("path", "/upload")]);
defer! {
    METRICS.dec_gauge("active_requests", &[("method", "POST"), ("path", "/upload")]);
}
```

### Distributed Tracing

```rust
// Start span
let mut span = TRACER.start_span("process_dataset");
span.set_attribute("dataset.id", dataset_id.to_string());
span.set_attribute("dataset.size", record_count);

// Nested spans
let mut encryption_span = TRACER.start_span("encrypt_records");
encryption_span.set_attribute("algorithm", "AES-256-GCM");
// ... perform encryption
encryption_span.set_status(SpanStatus::Ok);
encryption_span.end();

// Error handling
if let Err(e) = operation().await {
    span.record_error(&e);
    span.set_status(SpanStatus::Error);
    return Err(e);
}

span.end();
```

### Health Checks

```rust
// Register health checkers
let mut health_checker = VaultHealthChecker::new();
health_checker.register(Box::new(DatabaseHealthChecker { pool }));
health_checker.register(Box::new(StorageHealthChecker { backend }));
health_checker.register(Box::new(KmsHealthChecker { provider }));
health_checker.register(Box::new(MemoryHealthChecker { threshold_percent: 90.0 }));

// Check readiness
let status = health_checker.readiness().await;
if status.status != HealthState::Healthy {
    log::warn!("Service not ready: {:?}", status);
}
```

### Graceful Shutdown

```rust
let shutdown = Arc::new(ShutdownCoordinator::new(Duration::from_secs(30)));

// Register shutdown hooks
shutdown.register_hook(Box::new(ServerShutdownHook { server })).await;
shutdown.register_hook(Box::new(PoolShutdownHook { pool })).await;

// Install signal handlers
shutdown.clone().install_signal_handlers();

// Wait for shutdown
shutdown.wait_for_signal().await;
log::info!("Shutdown signal received");
```
