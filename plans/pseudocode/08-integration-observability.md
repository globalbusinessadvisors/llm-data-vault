# LLM-Data-Vault Pseudocode: Integration & Observability

**Document:** 08-integration-observability.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines integration interfaces and observability:
- Event system (CloudEvents)
- Module integrations (LLM-Registry, Policy-Engine, etc.)
- Webhook system
- Metrics, tracing, and logging

---

## 1. Event System

```rust
// src/integration/events/mod.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// CloudEvents-Compliant Event Structure
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEvent {
    #[serde(rename = "specversion")]
    pub spec_version: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub time: DateTime<Utc>,
    #[serde(rename = "datacontenttype")]
    pub data_content_type: String,
    pub data: serde_json::Value,
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

impl VaultEvent {
    pub fn new(event_type: VaultEventType, data: impl Serialize) -> Self {
        Self {
            spec_version: "1.0".to_string(),
            id: Uuid::new_v4().to_string(),
            source: "llm-data-vault".to_string(),
            event_type: event_type.to_string(),
            subject: None,
            time: Utc::now(),
            data_content_type: "application/json".to_string(),
            data: serde_json::to_value(data).unwrap_or_default(),
            extensions: HashMap::new(),
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_extension(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.extensions.insert(key.into(), v);
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultEventType {
    // Dataset events
    DatasetCreated,
    DatasetUpdated,
    DatasetDeleted,
    DatasetArchived,

    // Version events
    VersionCreated,
    VersionTagged,
    BranchCreated,
    BranchMerged,

    // Record events
    RecordsIngested,
    RecordsDeleted,
    RecordsExported,

    // Anonymization events
    AnonymizationStarted,
    AnonymizationCompleted,
    PIIDetected,

    // Access events
    AccessGranted,
    AccessRevoked,
    AccessDenied,

    // Policy events
    PolicyViolation,
    RetentionExpired,
    ComplianceAlert,

    // System events
    HealthDegraded,
    HealthRestored,
}

impl std::fmt::Display for VaultEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            VaultEventType::DatasetCreated => "llm.data-vault.dataset.created",
            VaultEventType::DatasetUpdated => "llm.data-vault.dataset.updated",
            VaultEventType::DatasetDeleted => "llm.data-vault.dataset.deleted",
            VaultEventType::VersionCreated => "llm.data-vault.version.created",
            VaultEventType::RecordsIngested => "llm.data-vault.records.ingested",
            VaultEventType::AnonymizationCompleted => "llm.data-vault.anonymization.completed",
            VaultEventType::AccessGranted => "llm.data-vault.access.granted",
            VaultEventType::PolicyViolation => "llm.data-vault.policy.violation",
            _ => "llm.data-vault.unknown",
        };
        write!(f, "{}", s)
    }
}

// ============================================================================
// Event Publisher
// ============================================================================

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: VaultEvent) -> Result<(), EventError>;
    async fn publish_batch(&self, events: Vec<VaultEvent>) -> Result<BatchPublishResult, EventError>;
    fn publisher_type(&self) -> &'static str;
}

#[derive(Debug, Clone)]
pub struct BatchPublishResult {
    pub successful: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

// ============================================================================
// Kafka Publisher
// ============================================================================

pub struct KafkaEventPublisher {
    producer: FutureProducer,
    config: KafkaConfig,
    metrics: Arc<EventMetrics>,
}

#[derive(Debug, Clone)]
pub struct KafkaConfig {
    pub brokers: Vec<String>,
    pub topic_prefix: String,
    pub client_id: String,
    pub acks: KafkaAcks,
    pub retries: u32,
    pub batch_size: usize,
    pub linger_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum KafkaAcks {
    None,
    Leader,
    All,
}

impl KafkaEventPublisher {
    pub fn new(config: KafkaConfig) -> Result<Self, EventError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", config.brokers.join(","))
            .set("client.id", &config.client_id)
            .set("acks", config.acks.to_string())
            .set("retries", config.retries.to_string())
            .set("batch.size", config.batch_size.to_string())
            .set("linger.ms", config.linger_ms.to_string())
            .create()
            .map_err(|e| EventError::Configuration { message: e.to_string() })?;

        Ok(Self {
            producer,
            config,
            metrics: Arc::new(EventMetrics::new("kafka")),
        })
    }

    fn topic_for_event(&self, event_type: &str) -> String {
        format!("{}.{}", self.config.topic_prefix, event_type.replace('.', "-"))
    }
}

#[async_trait]
impl EventPublisher for KafkaEventPublisher {
    async fn publish(&self, event: VaultEvent) -> Result<(), EventError> {
        let _timer = self.metrics.operation_timer("publish");

        let topic = self.topic_for_event(&event.event_type);
        let key = event.subject.clone().unwrap_or_else(|| event.id.clone());
        let payload = serde_json::to_string(&event)
            .map_err(|e| EventError::Serialization { message: e.to_string() })?;

        let record = FutureRecord::to(&topic)
            .key(&key)
            .payload(&payload);

        self.producer
            .send(record, Duration::from_secs(5))
            .await
            .map_err(|(e, _)| EventError::PublishFailed { message: e.to_string() })?;

        self.metrics.record_published();
        Ok(())
    }

    async fn publish_batch(&self, events: Vec<VaultEvent>) -> Result<BatchPublishResult, EventError> {
        let mut successful = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        for event in events {
            match self.publish(event).await {
                Ok(_) => successful += 1,
                Err(e) => {
                    failed += 1;
                    errors.push(e.to_string());
                }
            }
        }

        Ok(BatchPublishResult { successful, failed, errors })
    }

    fn publisher_type(&self) -> &'static str {
        "kafka"
    }
}

// ============================================================================
// Event Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Serialization error: {message}")]
    Serialization { message: String },

    #[error("Publish failed: {message}")]
    PublishFailed { message: String },

    #[error("Connection error: {message}")]
    Connection { message: String },
}
```

---

## 2. Module Integrations

```rust
// src/integration/registry.rs

/// Integration with LLM-Registry for metadata synchronization
pub struct RegistryIntegration {
    client: RegistryClient,
    config: RegistryConfig,
    event_publisher: Arc<dyn EventPublisher>,
}

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub endpoint: String,
    pub api_key: SecureString,
    pub sync_mode: SyncMode,
    pub sync_interval: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum SyncMode {
    Push,       // Push changes to registry
    Pull,       // Pull from registry
    Bidirectional,
}

impl RegistryIntegration {
    pub async fn new(config: RegistryConfig, event_publisher: Arc<dyn EventPublisher>) -> Result<Self, IntegrationError> {
        let client = RegistryClient::new(&config.endpoint, &config.api_key)?;

        Ok(Self {
            client,
            config,
            event_publisher,
        })
    }

    /// Register a dataset with the model registry
    pub async fn register_dataset(&self, dataset: &Dataset) -> Result<RegistrationId, IntegrationError> {
        let metadata = DatasetMetadataDto {
            id: dataset.id.0.to_string(),
            name: dataset.name.clone(),
            version: dataset.current_version.0.to_string(),
            schema_hash: dataset.schema.as_ref().map(|s| compute_schema_hash(s)),
            record_count: 0, // Would be fetched
            created_at: dataset.created_at,
            tags: dataset.tags.iter().map(|t| t.key.clone()).collect(),
        };

        let response = self.client
            .post("/api/v1/datasets")
            .json(&metadata)
            .send()
            .await
            .map_err(|e| IntegrationError::RequestFailed { message: e.to_string() })?;

        let registration: RegistrationResponse = response.json().await
            .map_err(|e| IntegrationError::ResponseParseFailed { message: e.to_string() })?;

        Ok(RegistrationId(registration.id))
    }

    /// Link dataset to a model
    pub async fn link_to_model(
        &self,
        dataset_id: &DatasetId,
        model_id: &str,
        relationship: DatasetModelRelationship,
    ) -> Result<(), IntegrationError> {
        let link = DatasetModelLinkDto {
            dataset_id: dataset_id.0.to_string(),
            model_id: model_id.to_string(),
            relationship: relationship.to_string(),
            linked_at: Utc::now(),
        };

        self.client
            .post(&format!("/api/v1/models/{}/datasets", model_id))
            .json(&link)
            .send()
            .await
            .map_err(|e| IntegrationError::RequestFailed { message: e.to_string() })?;

        Ok(())
    }

    /// Sync metadata changes
    pub async fn sync(&self) -> Result<SyncResult, IntegrationError> {
        match self.config.sync_mode {
            SyncMode::Push => self.push_sync().await,
            SyncMode::Pull => self.pull_sync().await,
            SyncMode::Bidirectional => {
                let push_result = self.push_sync().await?;
                let pull_result = self.pull_sync().await?;
                Ok(SyncResult {
                    pushed: push_result.pushed,
                    pulled: pull_result.pulled,
                    conflicts: push_result.conflicts + pull_result.conflicts,
                })
            }
        }
    }

    async fn push_sync(&self) -> Result<SyncResult, IntegrationError> {
        // Implementation for pushing local changes to registry
        Ok(SyncResult::default())
    }

    async fn pull_sync(&self) -> Result<SyncResult, IntegrationError> {
        // Implementation for pulling changes from registry
        Ok(SyncResult::default())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DatasetModelRelationship {
    TrainingData,
    EvaluationData,
    ValidationData,
    TestData,
}

#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts: usize,
}

// ============================================================================
// Policy Engine Integration
// ============================================================================

// src/integration/policy_engine.rs

pub struct PolicyEngineIntegration {
    client: PolicyEngineClient,
    cache: Arc<RwLock<PolicyCache>>,
    config: PolicyEngineConfig,
}

#[derive(Debug, Clone)]
pub struct PolicyEngineConfig {
    pub endpoint: String,
    pub cache_ttl: Duration,
    pub timeout: Duration,
}

impl PolicyEngineIntegration {
    pub async fn new(config: PolicyEngineConfig) -> Result<Self, IntegrationError> {
        let client = PolicyEngineClient::new(&config.endpoint)?;

        Ok(Self {
            client,
            cache: Arc::new(RwLock::new(PolicyCache::new(config.cache_ttl))),
            config,
        })
    }

    /// Evaluate access request against policies
    pub async fn evaluate_access(&self, request: &AccessEvaluationRequest) -> Result<PolicyDecision, IntegrationError> {
        // Check cache first
        let cache_key = self.compute_cache_key(request);
        if let Some(decision) = self.check_cache(&cache_key).await {
            return Ok(decision);
        }

        let response = self.client
            .post("/api/v1/evaluate/access")
            .json(request)
            .timeout(self.config.timeout)
            .send()
            .await
            .map_err(|e| IntegrationError::RequestFailed { message: e.to_string() })?;

        let decision: PolicyDecision = response.json().await
            .map_err(|e| IntegrationError::ResponseParseFailed { message: e.to_string() })?;

        // Update cache
        self.update_cache(&cache_key, &decision).await;

        Ok(decision)
    }

    /// Get applicable policies for a resource
    pub async fn get_applicable_policies(&self, resource: &ResourceId) -> Result<Vec<Policy>, IntegrationError> {
        let response = self.client
            .get(&format!("/api/v1/policies/applicable/{}", resource.0))
            .send()
            .await
            .map_err(|e| IntegrationError::RequestFailed { message: e.to_string() })?;

        let policies: Vec<Policy> = response.json().await
            .map_err(|e| IntegrationError::ResponseParseFailed { message: e.to_string() })?;

        Ok(policies)
    }

    /// Report a policy violation
    pub async fn report_violation(&self, violation: &PolicyViolationReport) -> Result<(), IntegrationError> {
        self.client
            .post("/api/v1/violations")
            .json(violation)
            .send()
            .await
            .map_err(|e| IntegrationError::RequestFailed { message: e.to_string() })?;

        Ok(())
    }

    fn compute_cache_key(&self, request: &AccessEvaluationRequest) -> String {
        format!("{}:{}:{}", request.principal_id, request.action, request.resource_id)
    }

    async fn check_cache(&self, key: &str) -> Option<PolicyDecision> {
        let cache = self.cache.read().await;
        cache.get(key)
    }

    async fn update_cache(&self, key: &str, decision: &PolicyDecision) {
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), decision.clone());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessEvaluationRequest {
    pub principal_id: String,
    pub action: String,
    pub resource_id: String,
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_policies: Vec<String>,
    pub obligations: Vec<PolicyObligation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyObligation {
    pub action: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

// ============================================================================
// Governance Dashboard Integration
// ============================================================================

// src/integration/governance.rs

pub struct GovernanceIntegration {
    client: GovernanceClient,
    event_buffer: Arc<RwLock<Vec<AuditEvent>>>,
    config: GovernanceConfig,
}

#[derive(Debug, Clone)]
pub struct GovernanceConfig {
    pub endpoint: String,
    pub buffer_size: usize,
    pub flush_interval: Duration,
}

impl GovernanceIntegration {
    pub async fn new(config: GovernanceConfig) -> Result<Self, IntegrationError> {
        let client = GovernanceClient::new(&config.endpoint)?;

        let integration = Self {
            client,
            event_buffer: Arc::new(RwLock::new(Vec::with_capacity(config.buffer_size))),
            config,
        };

        // Start background flush task
        integration.start_flush_task();

        Ok(integration)
    }

    /// Emit an audit event
    pub async fn emit_audit_event(&self, event: AuditEvent) -> Result<(), IntegrationError> {
        let mut buffer = self.event_buffer.write().await;
        buffer.push(event);

        // Flush if buffer is full
        if buffer.len() >= self.config.buffer_size {
            let events = std::mem::take(&mut *buffer);
            drop(buffer);
            self.flush_events(events).await?;
        }

        Ok(())
    }

    /// Generate compliance report
    pub async fn generate_report(&self, report_type: ReportType, params: ReportParams) -> Result<ComplianceReport, IntegrationError> {
        let response = self.client
            .post(&format!("/api/v1/reports/{}", report_type))
            .json(&params)
            .send()
            .await
            .map_err(|e| IntegrationError::RequestFailed { message: e.to_string() })?;

        let report: ComplianceReport = response.json().await
            .map_err(|e| IntegrationError::ResponseParseFailed { message: e.to_string() })?;

        Ok(report)
    }

    fn start_flush_task(&self) {
        let buffer = self.event_buffer.clone();
        let client = self.client.clone();
        let interval = self.config.flush_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                let events = {
                    let mut buffer = buffer.write().await;
                    std::mem::take(&mut *buffer)
                };

                if !events.is_empty() {
                    if let Err(e) = Self::flush_events_internal(&client, events).await {
                        tracing::error!("Failed to flush audit events: {}", e);
                    }
                }
            }
        });
    }

    async fn flush_events(&self, events: Vec<AuditEvent>) -> Result<(), IntegrationError> {
        Self::flush_events_internal(&self.client, events).await
    }

    async fn flush_events_internal(client: &GovernanceClient, events: Vec<AuditEvent>) -> Result<(), IntegrationError> {
        client
            .post("/api/v1/audit/events/batch")
            .json(&events)
            .send()
            .await
            .map_err(|e| IntegrationError::RequestFailed { message: e.to_string() })?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ReportType {
    GdprArticle30,
    Soc2,
    Hipaa,
    AccessSummary,
    DataInventory,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportParams {
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    pub scope: Option<String>,
    pub format: ReportFormat,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum ReportFormat {
    Pdf,
    Json,
    Csv,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComplianceReport {
    pub id: String,
    pub report_type: String,
    pub generated_at: DateTime<Utc>,
    pub content: serde_json::Value,
    pub download_url: Option<String>,
}
```

---

## 3. Webhook System

```rust
// src/integration/webhooks.rs

pub struct WebhookManager {
    store: Arc<dyn WebhookStore>,
    http_client: reqwest::Client,
    retry_queue: Arc<RetryQueue>,
    config: WebhookConfig,
    metrics: Arc<WebhookMetrics>,
}

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub max_retries: u32,
    pub retry_delay: Duration,
    pub timeout: Duration,
    pub max_concurrent: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: WebhookId,
    pub url: String,
    pub events: Vec<VaultEventType>,
    pub secret: SecureString,
    pub headers: HashMap<String, String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: WebhookId,
    pub event_id: String,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub response_code: Option<u16>,
    pub response_body: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

impl WebhookManager {
    pub fn new(store: Arc<dyn WebhookStore>, config: WebhookConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap();

        Self {
            store,
            http_client,
            retry_queue: Arc::new(RetryQueue::new()),
            config,
            metrics: Arc::new(WebhookMetrics::new()),
        }
    }

    /// Register a new webhook
    pub async fn register(&self, webhook: Webhook) -> Result<WebhookId, WebhookError> {
        // Validate URL
        let url = reqwest::Url::parse(&webhook.url)
            .map_err(|_| WebhookError::InvalidUrl { url: webhook.url.clone() })?;

        if url.scheme() != "https" {
            return Err(WebhookError::InsecureUrl { url: webhook.url.clone() });
        }

        self.store.create(&webhook).await?;

        Ok(webhook.id)
    }

    /// Trigger webhooks for an event
    pub async fn trigger(&self, event: &VaultEvent) -> Result<(), WebhookError> {
        let event_type = VaultEventType::from_str(&event.event_type)
            .unwrap_or(VaultEventType::DatasetCreated);

        let webhooks = self.store.find_by_event_type(event_type).await?;

        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        let mut handles = Vec::new();

        for webhook in webhooks {
            if !webhook.enabled {
                continue;
            }

            let http_client = self.http_client.clone();
            let event = event.clone();
            let permit = semaphore.clone();
            let config = self.config.clone();
            let store = self.store.clone();
            let metrics = self.metrics.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                Self::deliver(&http_client, &webhook, &event, &config, &store, &metrics).await
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }

    async fn deliver(
        http_client: &reqwest::Client,
        webhook: &Webhook,
        event: &VaultEvent,
        config: &WebhookConfig,
        store: &Arc<dyn WebhookStore>,
        metrics: &Arc<WebhookMetrics>,
    ) -> Result<(), WebhookError> {
        let payload = serde_json::to_string(event)
            .map_err(|e| WebhookError::SerializationFailed { message: e.to_string() })?;

        // Compute HMAC signature
        let signature = Self::compute_signature(&payload, webhook.secret.expose_secret());

        let delivery = WebhookDelivery {
            id: Uuid::new_v4(),
            webhook_id: webhook.id,
            event_id: event.id.clone(),
            status: DeliveryStatus::Pending,
            attempts: 0,
            response_code: None,
            response_body: None,
            delivered_at: None,
            created_at: Utc::now(),
        };

        store.create_delivery(&delivery).await?;

        let mut attempts = 0;
        let mut last_error = None;

        while attempts < config.max_retries {
            attempts += 1;

            let mut request = http_client
                .post(&webhook.url)
                .header("Content-Type", "application/json")
                .header("X-Webhook-Signature", &signature)
                .header("X-Webhook-Id", webhook.id.0.to_string())
                .header("X-Event-Id", &event.id)
                .body(payload.clone());

            for (key, value) in &webhook.headers {
                request = request.header(key.as_str(), value.as_str());
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        store.update_delivery(&delivery.id, DeliveryStatus::Delivered, Some(status.as_u16()), None).await?;
                        metrics.record_delivery_success();
                        return Ok(());
                    } else {
                        let body = response.text().await.ok();
                        last_error = Some(WebhookError::DeliveryFailed {
                            status_code: status.as_u16(),
                            body,
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(WebhookError::RequestFailed { message: e.to_string() });
                }
            }

            // Wait before retry
            if attempts < config.max_retries {
                tokio::time::sleep(config.retry_delay * attempts).await;
            }
        }

        store.update_delivery(&delivery.id, DeliveryStatus::Failed, None, last_error.as_ref().map(|e| e.to_string())).await?;
        metrics.record_delivery_failure();

        Err(last_error.unwrap_or(WebhookError::MaxRetriesExceeded))
    }

    fn compute_signature(payload: &str, secret: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());

        let result = mac.finalize();
        format!("sha256={}", hex::encode(result.into_bytes()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("Invalid URL: {url}")]
    InvalidUrl { url: String },

    #[error("Insecure URL (HTTPS required): {url}")]
    InsecureUrl { url: String },

    #[error("Serialization failed: {message}")]
    SerializationFailed { message: String },

    #[error("Request failed: {message}")]
    RequestFailed { message: String },

    #[error("Delivery failed with status {status_code}")]
    DeliveryFailed { status_code: u16, body: Option<String> },

    #[error("Maximum retries exceeded")]
    MaxRetriesExceeded,

    #[error("Store error: {message}")]
    StoreError { message: String },
}
```

---

## 4. Observability

```rust
// src/observability/mod.rs

// ============================================================================
// Metrics
// ============================================================================

pub struct MetricsRegistry {
    registry: prometheus::Registry,

    // Request metrics
    pub http_requests_total: IntCounterVec,
    pub http_request_duration: HistogramVec,
    pub grpc_requests_total: IntCounterVec,

    // Storage metrics
    pub storage_operations_total: IntCounterVec,
    pub storage_bytes_total: IntCounterVec,
    pub storage_latency: HistogramVec,

    // Anonymization metrics
    pub pii_detections_total: IntCounterVec,
    pub anonymization_duration: HistogramVec,

    // System metrics
    pub active_connections: IntGauge,
    pub queue_depth: IntGaugeVec,
    pub cache_hits_total: IntCounter,
    pub cache_misses_total: IntCounter,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let registry = prometheus::Registry::new();

        let http_requests_total = IntCounterVec::new(
            Opts::new("http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        ).unwrap();

        let http_request_duration = HistogramVec::new(
            HistogramOpts::new("http_request_duration_seconds", "HTTP request duration")
                .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["method", "path"],
        ).unwrap();

        let storage_operations_total = IntCounterVec::new(
            Opts::new("storage_operations_total", "Total storage operations"),
            &["backend", "operation", "status"],
        ).unwrap();

        let storage_bytes_total = IntCounterVec::new(
            Opts::new("storage_bytes_total", "Total bytes transferred"),
            &["backend", "direction"],
        ).unwrap();

        let storage_latency = HistogramVec::new(
            HistogramOpts::new("storage_latency_seconds", "Storage operation latency")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["backend", "operation"],
        ).unwrap();

        let pii_detections_total = IntCounterVec::new(
            Opts::new("pii_detections_total", "Total PII detections"),
            &["pii_type", "detector"],
        ).unwrap();

        let anonymization_duration = HistogramVec::new(
            HistogramOpts::new("anonymization_duration_seconds", "Anonymization duration")
                .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]),
            &["strategy"],
        ).unwrap();

        let active_connections = IntGauge::new(
            "active_connections",
            "Number of active connections",
        ).unwrap();

        let queue_depth = IntGaugeVec::new(
            Opts::new("queue_depth", "Queue depth"),
            &["queue_name"],
        ).unwrap();

        let cache_hits_total = IntCounter::new("cache_hits_total", "Total cache hits").unwrap();
        let cache_misses_total = IntCounter::new("cache_misses_total", "Total cache misses").unwrap();

        // Register all metrics
        registry.register(Box::new(http_requests_total.clone())).unwrap();
        registry.register(Box::new(http_request_duration.clone())).unwrap();
        registry.register(Box::new(storage_operations_total.clone())).unwrap();
        registry.register(Box::new(storage_bytes_total.clone())).unwrap();
        registry.register(Box::new(storage_latency.clone())).unwrap();
        registry.register(Box::new(pii_detections_total.clone())).unwrap();
        registry.register(Box::new(anonymization_duration.clone())).unwrap();
        registry.register(Box::new(active_connections.clone())).unwrap();
        registry.register(Box::new(queue_depth.clone())).unwrap();
        registry.register(Box::new(cache_hits_total.clone())).unwrap();
        registry.register(Box::new(cache_misses_total.clone())).unwrap();

        Self {
            registry,
            http_requests_total,
            http_request_duration,
            grpc_requests_total: IntCounterVec::new(
                Opts::new("grpc_requests_total", "Total gRPC requests"),
                &["method", "status"],
            ).unwrap(),
            storage_operations_total,
            storage_bytes_total,
            storage_latency,
            pii_detections_total,
            anonymization_duration,
            active_connections,
            queue_depth,
            cache_hits_total,
            cache_misses_total,
        }
    }

    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }
}

// ============================================================================
// Tracing
// ============================================================================

pub fn init_tracing(config: &TracingConfig) -> Result<(), TracingError> {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&config.otlp_endpoint),
        )
        .with_trace_config(
            opentelemetry::sdk::trace::config()
                .with_sampler(opentelemetry::sdk::trace::Sampler::TraceIdRatioBased(config.sampling_ratio))
                .with_resource(opentelemetry::sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", config.service_name.clone()),
                    opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                ])),
        )
        .install_batch(opentelemetry::runtime::Tokio)
        .map_err(|e| TracingError::InitFailed { message: e.to_string() })?;

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let subscriber = tracing_subscriber::registry()
        .with(telemetry)
        .with(tracing_subscriber::fmt::layer().json())
        .with(EnvFilter::from_default_env());

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| TracingError::InitFailed { message: e.to_string() })?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct TracingConfig {
    pub service_name: String,
    pub otlp_endpoint: String,
    pub sampling_ratio: f64,
}

// ============================================================================
// Structured Logging
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,
}

pub fn init_logging(config: &LogConfig) -> Result<(), LogError> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.level));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    let fmt_layer = match config.format {
        LogFormat::Json => fmt_layer.json().boxed(),
        LogFormat::Pretty => fmt_layer.pretty().boxed(),
        LogFormat::Compact => fmt_layer.compact().boxed(),
    };

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| LogError::InitFailed { message: e.to_string() })?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: String,
    pub format: LogFormat,
    pub output: LogOutput,
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
    File(PathBuf),
    Both(PathBuf),
}

// ============================================================================
// Health Checks
// ============================================================================

pub struct HealthChecker {
    checks: Vec<Box<dyn HealthCheck>>,
}

#[async_trait]
pub trait HealthCheck: Send + Sync {
    fn name(&self) -> &str;
    async fn check(&self) -> HealthCheckResult;
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    pub fn add_check(&mut self, check: Box<dyn HealthCheck>) {
        self.checks.push(check);
    }

    pub async fn check_all(&self) -> Vec<HealthCheckResult> {
        let mut results = Vec::new();

        for check in &self.checks {
            let start = Instant::now();
            let result = check.check().await;
            let latency = start.elapsed().as_millis() as u64;

            results.push(HealthCheckResult {
                name: check.name().to_string(),
                status: result.status,
                latency_ms: latency,
                message: result.message,
                details: result.details,
            });
        }

        results
    }

    pub async fn is_healthy(&self) -> bool {
        let results = self.check_all().await;
        results.iter().all(|r| !matches!(r.status, HealthStatus::Unhealthy))
    }

    pub async fn is_ready(&self) -> bool {
        let results = self.check_all().await;
        results.iter().all(|r| matches!(r.status, HealthStatus::Healthy))
    }
}

// Database health check
pub struct DatabaseHealthCheck {
    pool: PgPool,
}

#[async_trait]
impl HealthCheck for DatabaseHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    async fn check(&self) -> HealthCheckResult {
        match sqlx::query("SELECT 1").execute(&self.pool).await {
            Ok(_) => HealthCheckResult {
                name: self.name().to_string(),
                status: HealthStatus::Healthy,
                latency_ms: 0,
                message: None,
                details: None,
            },
            Err(e) => HealthCheckResult {
                name: self.name().to_string(),
                status: HealthStatus::Unhealthy,
                latency_ms: 0,
                message: Some(e.to_string()),
                details: None,
            },
        }
    }
}
```

---

## Summary

This document defines integration and observability for LLM-Data-Vault:

| Component | Purpose |
|-----------|---------|
| **Event System** | CloudEvents-compliant event publishing |
| **Module Integrations** | Registry, Policy Engine, Governance |
| **Webhook System** | External notifications with HMAC signing |
| **Observability** | Metrics, tracing, logging, health checks |

**Key Features:**
- Kafka event publishing
- Policy evaluation caching
- Buffered audit event streaming
- Webhook delivery with retries
- Prometheus metrics
- OpenTelemetry tracing
- Kubernetes-compatible health checks

---

*Index Document: [00-index.md](./00-index.md)*
