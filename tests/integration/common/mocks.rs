//! Mock implementations for testing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use serde_json::Value;

/// Mock webhook server for testing webhook deliveries.
#[derive(Debug, Default)]
pub struct MockWebhookServer {
    /// Received requests.
    requests: RwLock<Vec<WebhookRequest>>,
    /// Response to return.
    response: RwLock<MockResponse>,
    /// Request counter.
    request_count: AtomicUsize,
}

/// Recorded webhook request.
#[derive(Debug, Clone)]
pub struct WebhookRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Mock response configuration.
#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status: u16,
    pub body: Value,
    pub delay_ms: Option<u64>,
}

impl Default for MockResponse {
    fn default() -> Self {
        Self {
            status: 200,
            body: serde_json::json!({"status": "ok"}),
            delay_ms: None,
        }
    }
}

impl MockWebhookServer {
    /// Creates a new mock webhook server.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the response to return.
    pub fn set_response(&self, response: MockResponse) {
        *self.response.write() = response;
    }

    /// Sets response status code.
    pub fn set_status(&self, status: u16) {
        self.response.write().status = status;
    }

    /// Records a request.
    pub fn record_request(&self, request: WebhookRequest) {
        self.requests.write().push(request);
        self.request_count.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns all recorded requests.
    pub fn requests(&self) -> Vec<WebhookRequest> {
        self.requests.read().clone()
    }

    /// Returns the request count.
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    /// Clears recorded requests.
    pub fn clear(&self) {
        self.requests.write().clear();
        self.request_count.store(0, Ordering::SeqCst);
    }

    /// Returns the last request.
    pub fn last_request(&self) -> Option<WebhookRequest> {
        self.requests.read().last().cloned()
    }

    /// Waits for a specific number of requests.
    pub async fn wait_for_requests(&self, count: usize, timeout_ms: u64) -> bool {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        while start.elapsed() < timeout {
            if self.request_count() >= count {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }
}

/// Mock email service for testing notifications.
#[derive(Debug, Default)]
pub struct MockEmailService {
    /// Sent emails.
    emails: RwLock<Vec<MockEmail>>,
}

/// Mock email.
#[derive(Debug, Clone)]
pub struct MockEmail {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl MockEmailService {
    /// Creates a new mock email service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a sent email.
    pub fn send(&self, to: &str, subject: &str, body: &str) {
        self.emails.write().push(MockEmail {
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            timestamp: chrono::Utc::now(),
        });
    }

    /// Returns all sent emails.
    pub fn emails(&self) -> Vec<MockEmail> {
        self.emails.read().clone()
    }

    /// Returns emails sent to a specific address.
    pub fn emails_to(&self, address: &str) -> Vec<MockEmail> {
        self.emails
            .read()
            .iter()
            .filter(|e| e.to == address)
            .cloned()
            .collect()
    }

    /// Clears sent emails.
    pub fn clear(&self) {
        self.emails.write().clear();
    }

    /// Returns the last sent email.
    pub fn last_email(&self) -> Option<MockEmail> {
        self.emails.read().last().cloned()
    }
}

/// Mock audit logger for testing audit events.
#[derive(Debug, Default)]
pub struct MockAuditLogger {
    /// Logged events.
    events: RwLock<Vec<AuditEvent>>,
}

/// Mock audit event.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: String,
    pub user_id: Option<String>,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub action: String,
    pub details: Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl MockAuditLogger {
    /// Creates a new mock audit logger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Logs an audit event.
    pub fn log(&self, event: AuditEvent) {
        self.events.write().push(event);
    }

    /// Returns all logged events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.read().clone()
    }

    /// Returns events by type.
    pub fn events_of_type(&self, event_type: &str) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Returns events for a specific user.
    pub fn events_for_user(&self, user_id: &str) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.user_id.as_deref() == Some(user_id))
            .cloned()
            .collect()
    }

    /// Clears logged events.
    pub fn clear(&self) {
        self.events.write().clear();
    }

    /// Returns the event count.
    pub fn count(&self) -> usize {
        self.events.read().len()
    }
}

/// Mock rate limiter for testing.
#[derive(Debug)]
pub struct MockRateLimiter {
    /// Whether to allow requests.
    allow: RwLock<bool>,
    /// Number of requests made.
    requests: AtomicUsize,
}

impl Default for MockRateLimiter {
    fn default() -> Self {
        Self {
            allow: RwLock::new(true),
            requests: AtomicUsize::new(0),
        }
    }
}

impl MockRateLimiter {
    /// Creates a new mock rate limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether to allow requests.
    pub fn set_allow(&self, allow: bool) {
        *self.allow.write() = allow;
    }

    /// Checks if a request is allowed.
    pub fn check(&self) -> bool {
        self.requests.fetch_add(1, Ordering::SeqCst);
        *self.allow.read()
    }

    /// Returns the request count.
    pub fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Resets the request count.
    pub fn reset(&self) {
        self.requests.store(0, Ordering::SeqCst);
    }
}

/// Mock KMS for testing encryption.
#[derive(Debug, Default)]
pub struct MockKms {
    /// Stored keys.
    keys: RwLock<HashMap<String, Vec<u8>>>,
}

impl MockKms {
    /// Creates a new mock KMS.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates a data key.
    pub fn generate_data_key(&self, key_id: &str) -> (Vec<u8>, Vec<u8>) {
        let plaintext = vec![0u8; 32]; // 256-bit key
        let ciphertext = format!("encrypted:{}", key_id).into_bytes();

        self.keys.write().insert(key_id.to_string(), plaintext.clone());

        (plaintext, ciphertext)
    }

    /// Decrypts a data key.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let ciphertext_str = String::from_utf8_lossy(ciphertext);
        if let Some(key_id) = ciphertext_str.strip_prefix("encrypted:") {
            self.keys.read().get(key_id).cloned()
        } else {
            None
        }
    }

    /// Clears all keys.
    pub fn clear(&self) {
        self.keys.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_webhook_server() {
        let server = MockWebhookServer::new();

        server.record_request(WebhookRequest {
            method: "POST".to_string(),
            path: "/webhook".to_string(),
            headers: HashMap::new(),
            body: serde_json::json!({"test": true}),
            timestamp: chrono::Utc::now(),
        });

        assert_eq!(server.request_count(), 1);
        assert!(server.last_request().is_some());
    }

    #[test]
    fn test_mock_email_service() {
        let service = MockEmailService::new();

        service.send("test@example.com", "Test Subject", "Test Body");

        assert_eq!(service.emails().len(), 1);
        assert_eq!(service.emails_to("test@example.com").len(), 1);
    }

    #[test]
    fn test_mock_audit_logger() {
        let logger = MockAuditLogger::new();

        logger.log(AuditEvent {
            event_type: "login".to_string(),
            user_id: Some("user1".to_string()),
            resource_type: "auth".to_string(),
            resource_id: None,
            action: "login".to_string(),
            details: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        });

        assert_eq!(logger.count(), 1);
        assert_eq!(logger.events_of_type("login").len(), 1);
    }
}
