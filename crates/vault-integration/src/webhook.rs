//! Webhook configuration and management.

use crate::{EventType, IntegrationError, IntegrationResult};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use url::Url;
use uuid::Uuid;

/// Webhook secret for signing payloads.
#[derive(Clone)]
pub struct WebhookSecret {
    /// Secret key bytes.
    secret: Vec<u8>,
}

impl WebhookSecret {
    /// Creates from a string.
    pub fn from_string(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into().into_bytes(),
        }
    }

    /// Creates from raw bytes.
    pub fn from_bytes(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    /// Generates a new random secret.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let secret: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        Self { secret }
    }

    /// Signs a payload.
    pub fn sign(&self, payload: &[u8]) -> String {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC can take key of any size");
        mac.update(payload);

        let result = mac.finalize();
        format!("sha256={}", hex::encode(result.into_bytes()))
    }

    /// Verifies a signature.
    pub fn verify(&self, payload: &[u8], signature: &str) -> bool {
        let expected = self.sign(payload);
        // Constant-time comparison
        constant_time_eq(expected.as_bytes(), signature.as_bytes())
    }

    /// Returns the secret as a hex string (for display).
    pub fn to_hex(&self) -> String {
        hex::encode(&self.secret)
    }
}

impl std::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebhookSecret([REDACTED])")
    }
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Webhook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Request timeout in seconds.
    pub timeout_seconds: u64,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Initial retry delay in seconds.
    pub initial_retry_delay_seconds: u64,
    /// Maximum retry delay in seconds.
    pub max_retry_delay_seconds: u64,
    /// Retry backoff multiplier.
    pub retry_backoff_multiplier: f64,
    /// Include signature header.
    pub include_signature: bool,
    /// Custom headers.
    pub custom_headers: Vec<(String, String)>,
    /// Content type.
    pub content_type: String,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_retries: 3,
            initial_retry_delay_seconds: 1,
            max_retry_delay_seconds: 300,
            retry_backoff_multiplier: 2.0,
            include_signature: true,
            custom_headers: Vec::new(),
            content_type: "application/json".to_string(),
        }
    }
}

/// Webhook status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookStatus {
    /// Webhook is active.
    Active,
    /// Webhook is paused.
    Paused,
    /// Webhook is disabled due to errors.
    Disabled,
    /// Webhook is pending verification.
    PendingVerification,
}

/// A webhook definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    /// Webhook ID.
    pub id: String,
    /// Webhook name.
    pub name: String,
    /// Target URL.
    pub url: String,
    /// Event types to receive.
    pub event_types: HashSet<EventType>,
    /// Webhook status.
    pub status: WebhookStatus,
    /// Configuration.
    pub config: WebhookConfig,
    /// Secret for signing (not serialized).
    #[serde(skip)]
    pub secret: Option<WebhookSecret>,
    /// Created timestamp.
    pub created_at: DateTime<Utc>,
    /// Updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// Created by user ID.
    pub created_by: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Filter expression (optional).
    pub filter: Option<String>,
    /// Tenant ID (for multi-tenancy).
    pub tenant_id: Option<String>,
    /// Consecutive failure count.
    pub consecutive_failures: u32,
    /// Last successful delivery.
    pub last_success: Option<DateTime<Utc>>,
    /// Last failed delivery.
    pub last_failure: Option<DateTime<Utc>>,
    /// Total deliveries attempted.
    pub total_deliveries: u64,
    /// Successful deliveries.
    pub successful_deliveries: u64,
    /// Failed deliveries.
    pub failed_deliveries: u64,
}

impl Webhook {
    /// Creates a new webhook.
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> IntegrationResult<Self> {
        let url_str = url.into();

        // Validate URL
        let parsed = Url::parse(&url_str)?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(IntegrationError::InvalidUrl(
                "Webhook URL must use HTTP or HTTPS".to_string(),
            ));
        }

        let now = Utc::now();
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            url: url_str,
            event_types: HashSet::new(),
            status: WebhookStatus::Active,
            config: WebhookConfig::default(),
            secret: Some(WebhookSecret::generate()),
            created_at: now,
            updated_at: now,
            created_by: None,
            description: None,
            filter: None,
            tenant_id: None,
            consecutive_failures: 0,
            last_success: None,
            last_failure: None,
            total_deliveries: 0,
            successful_deliveries: 0,
            failed_deliveries: 0,
        })
    }

    /// Subscribes to an event type.
    #[must_use]
    pub fn subscribe(mut self, event_type: EventType) -> Self {
        self.event_types.insert(event_type);
        self
    }

    /// Subscribes to multiple event types.
    #[must_use]
    pub fn subscribe_all(mut self, event_types: impl IntoIterator<Item = EventType>) -> Self {
        self.event_types.extend(event_types);
        self
    }

    /// Subscribes to all events in a category.
    #[must_use]
    pub fn subscribe_category(self, category: &str) -> Self {
        let events = match category {
            "dataset" => vec![
                EventType::DatasetCreated,
                EventType::DatasetUpdated,
                EventType::DatasetDeleted,
                EventType::DatasetArchived,
                EventType::DatasetRestored,
            ],
            "record" => vec![
                EventType::RecordCreated,
                EventType::RecordUpdated,
                EventType::RecordDeleted,
                EventType::RecordAccessed,
            ],
            "version" => vec![
                EventType::CommitCreated,
                EventType::BranchCreated,
                EventType::BranchDeleted,
                EventType::TagCreated,
                EventType::MergeCompleted,
            ],
            "access" => vec![
                EventType::AccessGranted,
                EventType::AccessRevoked,
                EventType::RoleAssigned,
                EventType::RoleRemoved,
                EventType::PermissionDenied,
            ],
            "security" => vec![
                EventType::EncryptionCompleted,
                EventType::DecryptionCompleted,
                EventType::KeyRotated,
                EventType::AnomalyDetected,
            ],
            "compliance" => vec![
                EventType::PiiDetected,
                EventType::AnonymizationApplied,
                EventType::DataExportRequested,
                EventType::DataDeletionRequested,
            ],
            _ => vec![],
        };
        self.subscribe_all(events)
    }

    /// Sets the configuration.
    #[must_use]
    pub fn with_config(mut self, config: WebhookConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the secret.
    #[must_use]
    pub fn with_secret(mut self, secret: WebhookSecret) -> Self {
        self.secret = Some(secret);
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the filter expression.
    #[must_use]
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    /// Sets the tenant ID.
    #[must_use]
    pub fn for_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Checks if webhook should receive an event.
    pub fn should_receive(&self, event_type: EventType) -> bool {
        if self.status != WebhookStatus::Active {
            return false;
        }

        // Empty set means all events
        if self.event_types.is_empty() {
            return true;
        }

        self.event_types.contains(&event_type)
    }

    /// Records a successful delivery.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_success = Some(Utc::now());
        self.total_deliveries += 1;
        self.successful_deliveries += 1;
        self.updated_at = Utc::now();

        // Re-enable if it was disabled
        if self.status == WebhookStatus::Disabled {
            self.status = WebhookStatus::Active;
        }
    }

    /// Records a failed delivery.
    pub fn record_failure(&mut self, disable_threshold: u32) {
        self.consecutive_failures += 1;
        self.last_failure = Some(Utc::now());
        self.total_deliveries += 1;
        self.failed_deliveries += 1;
        self.updated_at = Utc::now();

        // Disable after too many consecutive failures
        if self.consecutive_failures >= disable_threshold {
            self.status = WebhookStatus::Disabled;
        }
    }

    /// Returns the success rate.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_deliveries == 0 {
            return 1.0;
        }
        self.successful_deliveries as f64 / self.total_deliveries as f64
    }

    /// Pauses the webhook.
    pub fn pause(&mut self) {
        self.status = WebhookStatus::Paused;
        self.updated_at = Utc::now();
    }

    /// Resumes the webhook.
    pub fn resume(&mut self) {
        self.status = WebhookStatus::Active;
        self.updated_at = Utc::now();
    }

    /// Disables the webhook.
    pub fn disable(&mut self) {
        self.status = WebhookStatus::Disabled;
        self.updated_at = Utc::now();
    }
}

/// Webhook builder for fluent construction.
pub struct WebhookBuilder {
    name: String,
    url: String,
    event_types: HashSet<EventType>,
    config: WebhookConfig,
    secret: Option<WebhookSecret>,
    description: Option<String>,
    filter: Option<String>,
    tenant_id: Option<String>,
}

impl WebhookBuilder {
    /// Creates a new builder.
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            event_types: HashSet::new(),
            config: WebhookConfig::default(),
            secret: None,
            description: None,
            filter: None,
            tenant_id: None,
        }
    }

    /// Adds an event type.
    #[must_use]
    pub fn event(mut self, event_type: EventType) -> Self {
        self.event_types.insert(event_type);
        self
    }

    /// Adds multiple event types.
    #[must_use]
    pub fn events(mut self, events: impl IntoIterator<Item = EventType>) -> Self {
        self.event_types.extend(events);
        self
    }

    /// Sets configuration.
    #[must_use]
    pub fn config(mut self, config: WebhookConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets secret.
    #[must_use]
    pub fn secret(mut self, secret: WebhookSecret) -> Self {
        self.secret = Some(secret);
        self
    }

    /// Sets description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets filter.
    #[must_use]
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    /// Sets tenant.
    #[must_use]
    pub fn tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Builds the webhook.
    pub fn build(self) -> IntegrationResult<Webhook> {
        let mut webhook = Webhook::new(self.name, self.url)?;
        webhook.event_types = self.event_types;
        webhook.config = self.config;
        webhook.secret = self.secret.or(webhook.secret);
        webhook.description = self.description;
        webhook.filter = self.filter;
        webhook.tenant_id = self.tenant_id;
        Ok(webhook)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_creation() {
        let webhook = Webhook::new("test", "https://example.com/webhook").unwrap();

        assert!(!webhook.id.is_empty());
        assert_eq!(webhook.name, "test");
        assert_eq!(webhook.status, WebhookStatus::Active);
        assert!(webhook.secret.is_some());
    }

    #[test]
    fn test_webhook_invalid_url() {
        let result = Webhook::new("test", "ftp://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_subscribe() {
        let webhook = Webhook::new("test", "https://example.com/webhook")
            .unwrap()
            .subscribe(EventType::DatasetCreated)
            .subscribe(EventType::DatasetUpdated);

        assert!(webhook.should_receive(EventType::DatasetCreated));
        assert!(webhook.should_receive(EventType::DatasetUpdated));
        assert!(!webhook.should_receive(EventType::RecordCreated));
    }

    #[test]
    fn test_webhook_subscribe_category() {
        let webhook = Webhook::new("test", "https://example.com/webhook")
            .unwrap()
            .subscribe_category("dataset");

        assert!(webhook.should_receive(EventType::DatasetCreated));
        assert!(webhook.should_receive(EventType::DatasetDeleted));
        assert!(!webhook.should_receive(EventType::RecordCreated));
    }

    #[test]
    fn test_webhook_secret_sign_verify() {
        let secret = WebhookSecret::from_string("my-secret-key");
        let payload = b"test payload";

        let signature = secret.sign(payload);
        assert!(signature.starts_with("sha256="));
        assert!(secret.verify(payload, &signature));
        assert!(!secret.verify(b"wrong payload", &signature));
    }

    #[test]
    fn test_webhook_failure_tracking() {
        let mut webhook = Webhook::new("test", "https://example.com/webhook").unwrap();

        // Record some failures
        for _ in 0..5 {
            webhook.record_failure(10);
        }

        assert_eq!(webhook.consecutive_failures, 5);
        assert_eq!(webhook.status, WebhookStatus::Active);

        // Record enough failures to disable
        for _ in 0..5 {
            webhook.record_failure(10);
        }

        assert_eq!(webhook.status, WebhookStatus::Disabled);

        // Success should re-enable
        webhook.record_success();
        assert_eq!(webhook.status, WebhookStatus::Active);
        assert_eq!(webhook.consecutive_failures, 0);
    }

    #[test]
    fn test_webhook_builder() {
        let webhook = WebhookBuilder::new("test", "https://example.com/webhook")
            .event(EventType::DatasetCreated)
            .event(EventType::DatasetUpdated)
            .description("Test webhook")
            .tenant("tenant-123")
            .build()
            .unwrap();

        assert_eq!(webhook.event_types.len(), 2);
        assert_eq!(webhook.description, Some("Test webhook".to_string()));
        assert_eq!(webhook.tenant_id, Some("tenant-123".to_string()));
    }
}
