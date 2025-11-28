//! Webhook models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::PaginatedList;

/// A webhook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    /// Unique identifier.
    pub id: Uuid,

    /// Human-readable name.
    pub name: String,

    /// Webhook URL.
    pub url: String,

    /// Events to subscribe to.
    pub events: Vec<WebhookEvent>,

    /// Whether the webhook is active.
    pub active: bool,

    /// Secret for signature verification (masked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_preview: Option<String>,

    /// When the webhook was created.
    pub created_at: DateTime<Utc>,

    /// When the webhook was last updated.
    pub updated_at: DateTime<Utc>,

    /// Last successful delivery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_delivery_at: Option<DateTime<Utc>>,

    /// Delivery statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<WebhookStats>,
}

/// Webhook event types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    /// Dataset created.
    #[serde(rename = "dataset.created")]
    DatasetCreated,
    /// Dataset updated.
    #[serde(rename = "dataset.updated")]
    DatasetUpdated,
    /// Dataset deleted.
    #[serde(rename = "dataset.deleted")]
    DatasetDeleted,
    /// Record created.
    #[serde(rename = "record.created")]
    RecordCreated,
    /// Record updated.
    #[serde(rename = "record.updated")]
    RecordUpdated,
    /// Record deleted.
    #[serde(rename = "record.deleted")]
    RecordDeleted,
    /// PII detected.
    #[serde(rename = "pii.detected")]
    PiiDetected,
    /// Record quarantined.
    #[serde(rename = "record.quarantined")]
    RecordQuarantined,
    /// Bulk import completed.
    #[serde(rename = "import.completed")]
    ImportCompleted,
    /// Export completed.
    #[serde(rename = "export.completed")]
    ExportCompleted,
}

impl std::fmt::Display for WebhookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DatasetCreated => write!(f, "dataset.created"),
            Self::DatasetUpdated => write!(f, "dataset.updated"),
            Self::DatasetDeleted => write!(f, "dataset.deleted"),
            Self::RecordCreated => write!(f, "record.created"),
            Self::RecordUpdated => write!(f, "record.updated"),
            Self::RecordDeleted => write!(f, "record.deleted"),
            Self::PiiDetected => write!(f, "pii.detected"),
            Self::RecordQuarantined => write!(f, "record.quarantined"),
            Self::ImportCompleted => write!(f, "import.completed"),
            Self::ExportCompleted => write!(f, "export.completed"),
        }
    }
}

/// Webhook delivery statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookStats {
    /// Total deliveries attempted.
    pub total_deliveries: u64,
    /// Successful deliveries.
    pub successful_deliveries: u64,
    /// Failed deliveries.
    pub failed_deliveries: u64,
    /// Average response time in milliseconds.
    pub avg_response_time_ms: u64,
}

/// Request to create a webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookCreate {
    /// Human-readable name.
    pub name: String,

    /// Webhook URL.
    pub url: String,

    /// Events to subscribe to.
    pub events: Vec<WebhookEvent>,

    /// Secret for signature verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Custom headers to include.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

impl WebhookCreate {
    /// Creates a new webhook.
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>, events: Vec<WebhookEvent>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            events,
            secret: None,
            headers: std::collections::HashMap::new(),
        }
    }

    /// Sets the secret.
    #[must_use]
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// Adds a custom header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

/// Request to update a webhook.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookUpdate {
    /// New name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// New URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// New events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<WebhookEvent>>,

    /// New active status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

impl WebhookUpdate {
    /// Creates a new update request.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the URL.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets the events.
    #[must_use]
    pub fn with_events(mut self, events: Vec<WebhookEvent>) -> Self {
        self.events = Some(events);
        self
    }

    /// Sets the active status.
    #[must_use]
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = Some(active);
        self
    }
}

/// Paginated list of webhooks.
pub type WebhookList = PaginatedList<Webhook>;

/// A webhook delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Unique delivery ID.
    pub id: Uuid,

    /// Webhook ID.
    pub webhook_id: Uuid,

    /// Event type.
    pub event: WebhookEvent,

    /// Delivery status.
    pub status: DeliveryStatus,

    /// HTTP status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,

    /// Response body (truncated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,

    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Response time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,

    /// Number of retry attempts.
    pub retry_count: u32,

    /// Next retry time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,

    /// When the delivery was created.
    pub created_at: DateTime<Utc>,

    /// When the delivery was completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Delivery status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    /// Pending delivery.
    Pending,
    /// Delivery in progress.
    InProgress,
    /// Delivered successfully.
    Delivered,
    /// Delivery failed.
    Failed,
    /// Retrying.
    Retrying,
}

impl std::fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Delivered => write!(f, "delivered"),
            Self::Failed => write!(f, "failed"),
            Self::Retrying => write!(f, "retrying"),
        }
    }
}

/// Webhook payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Event ID.
    pub id: String,

    /// Event type.
    #[serde(rename = "type")]
    pub event_type: String,

    /// Event timestamp.
    pub created_at: DateTime<Utc>,

    /// Event data.
    pub data: serde_json::Value,
}

/// Rotate secret response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSecretResponse {
    /// New secret (only shown once).
    pub secret: String,

    /// When the new secret becomes active.
    pub active_at: DateTime<Utc>,

    /// When the old secret expires.
    pub old_secret_expires_at: DateTime<Utc>,
}
