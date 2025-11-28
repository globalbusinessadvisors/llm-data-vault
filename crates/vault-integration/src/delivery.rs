//! Webhook delivery management.

use crate::{Event, IntegrationError, IntegrationResult, Webhook, WebhookConfig};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Pending delivery.
    Pending,
    /// In progress.
    InProgress,
    /// Successfully delivered.
    Delivered,
    /// Delivery failed, will retry.
    Failed,
    /// Permanently failed after all retries.
    PermanentlyFailed,
    /// Cancelled.
    Cancelled,
}

/// A delivery attempt record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAttempt {
    /// Attempt number (1-based).
    pub attempt_number: u32,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// HTTP status code (if received).
    pub http_status: Option<u16>,
    /// Response body (truncated).
    pub response_body: Option<String>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Success flag.
    pub success: bool,
}

/// A webhook delivery record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Delivery ID.
    pub id: String,
    /// Webhook ID.
    pub webhook_id: String,
    /// Event ID.
    pub event_id: String,
    /// Event type.
    pub event_type: String,
    /// Delivery status.
    pub status: DeliveryStatus,
    /// Delivery attempts.
    pub attempts: Vec<DeliveryAttempt>,
    /// Created timestamp.
    pub created_at: DateTime<Utc>,
    /// Updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// Next retry time (if applicable).
    pub next_retry: Option<DateTime<Utc>>,
    /// Payload (JSON).
    pub payload: String,
}

impl WebhookDelivery {
    /// Creates a new delivery record.
    pub fn new(webhook_id: impl Into<String>, event: &Event) -> IntegrationResult<Self> {
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            webhook_id: webhook_id.into(),
            event_id: event.id().to_string(),
            event_type: event.event_type().to_string(),
            status: DeliveryStatus::Pending,
            attempts: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            next_retry: None,
            payload: event.to_json()?,
        })
    }

    /// Returns the current attempt count.
    #[must_use]
    pub fn attempt_count(&self) -> u32 {
        self.attempts.len() as u32
    }

    /// Records a successful attempt.
    pub fn record_success(&mut self, http_status: u16, response: Option<String>, duration_ms: u64) {
        self.attempts.push(DeliveryAttempt {
            attempt_number: self.attempt_count() + 1,
            timestamp: Utc::now(),
            http_status: Some(http_status),
            response_body: response,
            error: None,
            duration_ms,
            success: true,
        });
        self.status = DeliveryStatus::Delivered;
        self.updated_at = Utc::now();
        self.next_retry = None;
    }

    /// Records a failed attempt.
    pub fn record_failure(
        &mut self,
        http_status: Option<u16>,
        error: String,
        duration_ms: u64,
        max_retries: u32,
        config: &WebhookConfig,
    ) {
        let attempt_number = self.attempt_count() + 1;

        self.attempts.push(DeliveryAttempt {
            attempt_number,
            timestamp: Utc::now(),
            http_status,
            response_body: None,
            error: Some(error),
            duration_ms,
            success: false,
        });

        if attempt_number >= max_retries {
            self.status = DeliveryStatus::PermanentlyFailed;
            self.next_retry = None;
        } else {
            self.status = DeliveryStatus::Failed;
            // Calculate next retry time with exponential backoff
            let delay = self.calculate_retry_delay(attempt_number, config);
            self.next_retry = Some(Utc::now() + chrono::Duration::seconds(delay as i64));
        }

        self.updated_at = Utc::now();
    }

    /// Calculates retry delay with exponential backoff.
    fn calculate_retry_delay(&self, attempt: u32, config: &WebhookConfig) -> u64 {
        let base = config.initial_retry_delay_seconds as f64;
        let multiplier = config.retry_backoff_multiplier;
        let max = config.max_retry_delay_seconds;

        let delay = base * multiplier.powi(attempt as i32 - 1);
        (delay as u64).min(max)
    }

    /// Returns the last error message.
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.attempts
            .iter()
            .rev()
            .find_map(|a| a.error.as_deref())
    }
}

/// Delivery request.
#[derive(Debug)]
pub struct DeliveryRequest {
    /// Webhook.
    pub webhook: Webhook,
    /// Event.
    pub event: Event,
    /// Delivery record (for retries).
    pub delivery: Option<WebhookDelivery>,
}

/// Delivery result.
#[derive(Debug)]
pub struct DeliveryResult {
    /// Delivery ID.
    pub delivery_id: String,
    /// Webhook ID.
    pub webhook_id: String,
    /// Success flag.
    pub success: bool,
    /// HTTP status.
    pub http_status: Option<u16>,
    /// Error message.
    pub error: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// Delivery manager for handling webhook deliveries.
pub struct DeliveryManager {
    /// HTTP client.
    client: Client,
    /// Default configuration.
    default_config: WebhookConfig,
    /// Delivery channel sender.
    sender: mpsc::Sender<DeliveryRequest>,
    /// Delivery records.
    deliveries: parking_lot::RwLock<HashMap<String, WebhookDelivery>>,
}

impl DeliveryManager {
    /// Creates a new delivery manager.
    pub fn new(queue_size: usize) -> (Self, mpsc::Receiver<DeliveryRequest>) {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let (sender, receiver) = mpsc::channel(queue_size);

        let manager = Self {
            client,
            default_config: WebhookConfig::default(),
            sender,
            deliveries: parking_lot::RwLock::new(HashMap::new()),
        };

        (manager, receiver)
    }

    /// Queues a delivery.
    pub async fn queue_delivery(&self, webhook: Webhook, event: Event) -> IntegrationResult<String> {
        let delivery = WebhookDelivery::new(&webhook.id, &event)?;
        let delivery_id = delivery.id.clone();

        // Store delivery record
        self.deliveries.write().insert(delivery_id.clone(), delivery.clone());

        // Queue for processing
        self.sender
            .send(DeliveryRequest {
                webhook,
                event,
                delivery: Some(delivery),
            })
            .await
            .map_err(|_| IntegrationError::ChannelClosed)?;

        Ok(delivery_id)
    }

    /// Delivers an event to a webhook.
    pub async fn deliver(&self, webhook: &Webhook, event: &Event) -> DeliveryResult {
        let start = std::time::Instant::now();
        let delivery_id = Uuid::new_v4().to_string();

        // Prepare payload
        let payload = match event.to_json() {
            Ok(p) => p,
            Err(e) => {
                return DeliveryResult {
                    delivery_id,
                    webhook_id: webhook.id.clone(),
                    success: false,
                    http_status: None,
                    error: Some(format!("Serialization error: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        // Build request
        let mut request = self
            .client
            .post(&webhook.url)
            .header("Content-Type", &webhook.config.content_type)
            .header("X-Webhook-ID", &webhook.id)
            .header("X-Event-ID", event.id())
            .header("X-Event-Type", event.event_type().to_string())
            .header("X-Delivery-ID", &delivery_id)
            .header("X-Timestamp", event.timestamp().to_rfc3339());

        // Add signature if configured
        if webhook.config.include_signature {
            if let Some(ref secret) = webhook.secret {
                let signature = secret.sign(payload.as_bytes());
                request = request.header("X-Webhook-Signature", signature);
            }
        }

        // Add custom headers
        for (key, value) in &webhook.config.custom_headers {
            request = request.header(key.as_str(), value.as_str());
        }

        // Send request
        let timeout = Duration::from_secs(webhook.config.timeout_seconds);
        let result = tokio::time::timeout(timeout, request.body(payload).send()).await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                let success = response.status().is_success();

                DeliveryResult {
                    delivery_id,
                    webhook_id: webhook.id.clone(),
                    success,
                    http_status: Some(status),
                    error: if success {
                        None
                    } else {
                        Some(format!("HTTP {}", status))
                    },
                    duration_ms,
                }
            }
            Ok(Err(e)) => DeliveryResult {
                delivery_id,
                webhook_id: webhook.id.clone(),
                success: false,
                http_status: None,
                error: Some(e.to_string()),
                duration_ms,
            },
            Err(_) => DeliveryResult {
                delivery_id,
                webhook_id: webhook.id.clone(),
                success: false,
                http_status: None,
                error: Some("Request timed out".to_string()),
                duration_ms,
            },
        }
    }

    /// Gets a delivery record by ID.
    pub fn get_delivery(&self, id: &str) -> Option<WebhookDelivery> {
        self.deliveries.read().get(id).cloned()
    }

    /// Lists deliveries for a webhook.
    pub fn list_deliveries(&self, webhook_id: &str, limit: usize) -> Vec<WebhookDelivery> {
        self.deliveries
            .read()
            .values()
            .filter(|d| d.webhook_id == webhook_id)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Lists failed deliveries that need retry.
    pub fn list_pending_retries(&self) -> Vec<WebhookDelivery> {
        let now = Utc::now();
        self.deliveries
            .read()
            .values()
            .filter(|d| {
                d.status == DeliveryStatus::Failed
                    && d.next_retry.map_or(false, |t| t <= now)
            })
            .cloned()
            .collect()
    }

    /// Updates a delivery record.
    pub fn update_delivery(&self, delivery: WebhookDelivery) {
        self.deliveries.write().insert(delivery.id.clone(), delivery);
    }

    /// Removes old delivery records.
    pub fn cleanup_old_deliveries(&self, max_age: chrono::Duration) {
        let cutoff = Utc::now() - max_age;
        self.deliveries.write().retain(|_, d| d.created_at > cutoff);
    }
}

/// Delivery worker for processing the delivery queue.
pub struct DeliveryWorker {
    /// Delivery manager.
    manager: Arc<DeliveryManager>,
    /// Webhook lookup function.
    webhook_lookup: Box<dyn Fn(&str) -> Option<Webhook> + Send + Sync>,
}

impl DeliveryWorker {
    /// Creates a new delivery worker.
    pub fn new<F>(manager: Arc<DeliveryManager>, webhook_lookup: F) -> Self
    where
        F: Fn(&str) -> Option<Webhook> + Send + Sync + 'static,
    {
        Self {
            manager,
            webhook_lookup: Box::new(webhook_lookup),
        }
    }

    /// Runs the delivery worker.
    pub async fn run(&self, mut receiver: mpsc::Receiver<DeliveryRequest>) {
        info!("Delivery worker started");

        while let Some(request) = receiver.recv().await {
            self.process_delivery(request).await;
        }

        info!("Delivery worker stopped");
    }

    /// Processes a single delivery.
    async fn process_delivery(&self, request: DeliveryRequest) {
        let webhook = request.webhook;
        let event = request.event;
        let mut delivery = request.delivery.unwrap_or_else(|| {
            WebhookDelivery::new(&webhook.id, &event).expect("Failed to create delivery")
        });

        debug!(
            delivery_id = %delivery.id,
            webhook_id = %webhook.id,
            event_id = %event.id(),
            "Processing delivery"
        );

        // Update status to in-progress
        delivery.status = DeliveryStatus::InProgress;
        self.manager.update_delivery(delivery.clone());

        // Attempt delivery
        let result = self.manager.deliver(&webhook, &event).await;

        if result.success {
            delivery.record_success(
                result.http_status.unwrap_or(200),
                None,
                result.duration_ms,
            );
            debug!(
                delivery_id = %delivery.id,
                "Delivery successful"
            );
        } else {
            delivery.record_failure(
                result.http_status,
                result.error.unwrap_or_else(|| "Unknown error".to_string()),
                result.duration_ms,
                webhook.config.max_retries,
                &webhook.config,
            );

            if delivery.status == DeliveryStatus::PermanentlyFailed {
                error!(
                    delivery_id = %delivery.id,
                    webhook_id = %webhook.id,
                    "Delivery permanently failed after {} attempts",
                    delivery.attempt_count()
                );
            } else {
                warn!(
                    delivery_id = %delivery.id,
                    next_retry = ?delivery.next_retry,
                    "Delivery failed, will retry"
                );
            }
        }

        self.manager.update_delivery(delivery);
    }

    /// Processes pending retries.
    pub async fn process_retries(&self) {
        let pending = self.manager.list_pending_retries();

        for delivery in pending {
            // Look up the webhook
            let webhook = match (self.webhook_lookup)(&delivery.webhook_id) {
                Some(w) => w,
                None => {
                    warn!(
                        delivery_id = %delivery.id,
                        webhook_id = %delivery.webhook_id,
                        "Webhook not found for retry"
                    );
                    continue;
                }
            };

            // Parse the event from stored payload
            let event = match Event::from_json(&delivery.payload) {
                Ok(e) => e,
                Err(e) => {
                    error!(
                        delivery_id = %delivery.id,
                        error = %e,
                        "Failed to parse stored event"
                    );
                    continue;
                }
            };

            // Queue for retry
            let _ = self.manager.queue_delivery(webhook, event).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{DatasetEventPayload, EventMetadata, EventPayload, EventType};

    fn create_test_event() -> Event {
        Event::new(
            EventMetadata::new(EventType::DatasetCreated, "test"),
            EventPayload::Dataset(DatasetEventPayload {
                dataset_id: "ds-123".to_string(),
                name: Some("test".to_string()),
                schema_version: None,
                record_count: None,
                size_bytes: None,
                previous: None,
            }),
        )
    }

    fn create_test_webhook() -> Webhook {
        Webhook::new("test", "https://example.com/webhook").unwrap()
    }

    #[test]
    fn test_webhook_delivery_creation() {
        let event = create_test_event();
        let delivery = WebhookDelivery::new("webhook-123", &event).unwrap();

        assert_eq!(delivery.webhook_id, "webhook-123");
        assert_eq!(delivery.event_id, event.id());
        assert_eq!(delivery.status, DeliveryStatus::Pending);
        assert!(delivery.attempts.is_empty());
    }

    #[test]
    fn test_webhook_delivery_record_success() {
        let event = create_test_event();
        let mut delivery = WebhookDelivery::new("webhook-123", &event).unwrap();

        delivery.record_success(200, Some("OK".to_string()), 150);

        assert_eq!(delivery.status, DeliveryStatus::Delivered);
        assert_eq!(delivery.attempt_count(), 1);
        assert!(delivery.attempts[0].success);
    }

    #[test]
    fn test_webhook_delivery_record_failure() {
        let event = create_test_event();
        let mut delivery = WebhookDelivery::new("webhook-123", &event).unwrap();
        let config = WebhookConfig::default();

        delivery.record_failure(Some(500), "Server error".to_string(), 100, 3, &config);

        assert_eq!(delivery.status, DeliveryStatus::Failed);
        assert_eq!(delivery.attempt_count(), 1);
        assert!(!delivery.attempts[0].success);
        assert!(delivery.next_retry.is_some());
    }

    #[test]
    fn test_webhook_delivery_permanent_failure() {
        let event = create_test_event();
        let mut delivery = WebhookDelivery::new("webhook-123", &event).unwrap();
        let config = WebhookConfig {
            max_retries: 2,
            ..Default::default()
        };

        // First failure
        delivery.record_failure(Some(500), "Error 1".to_string(), 100, 2, &config);
        assert_eq!(delivery.status, DeliveryStatus::Failed);

        // Second failure - should be permanent
        delivery.record_failure(Some(500), "Error 2".to_string(), 100, 2, &config);
        assert_eq!(delivery.status, DeliveryStatus::PermanentlyFailed);
        assert!(delivery.next_retry.is_none());
    }

    #[test]
    fn test_retry_delay_calculation() {
        let event = create_test_event();
        let delivery = WebhookDelivery::new("webhook-123", &event).unwrap();
        let config = WebhookConfig {
            initial_retry_delay_seconds: 1,
            retry_backoff_multiplier: 2.0,
            max_retry_delay_seconds: 60,
            ..Default::default()
        };

        // 1 * 2^0 = 1
        assert_eq!(delivery.calculate_retry_delay(1, &config), 1);
        // 1 * 2^1 = 2
        assert_eq!(delivery.calculate_retry_delay(2, &config), 2);
        // 1 * 2^2 = 4
        assert_eq!(delivery.calculate_retry_delay(3, &config), 4);
        // 1 * 2^5 = 32
        assert_eq!(delivery.calculate_retry_delay(6, &config), 32);
        // 1 * 2^6 = 64, but capped at 60
        assert_eq!(delivery.calculate_retry_delay(7, &config), 60);
    }

    #[tokio::test]
    async fn test_delivery_manager_queue() {
        let (manager, _receiver) = DeliveryManager::new(100);

        let webhook = create_test_webhook();
        let event = create_test_event();

        let delivery_id = manager.queue_delivery(webhook, event).await.unwrap();

        assert!(!delivery_id.is_empty());

        let delivery = manager.get_delivery(&delivery_id).unwrap();
        assert_eq!(delivery.status, DeliveryStatus::Pending);
    }
}
