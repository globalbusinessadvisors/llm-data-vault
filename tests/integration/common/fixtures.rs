//! Test fixtures for integration tests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// Test user credentials.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: String,
    pub email: String,
    pub password: String,
    pub name: String,
    pub roles: Vec<String>,
}

impl TestUser {
    /// Creates a test admin user.
    pub fn admin() -> Self {
        Self {
            id: "user_admin_001".to_string(),
            email: "admin@test.local".to_string(),
            password: "AdminPassword123!".to_string(),
            name: "Test Admin".to_string(),
            roles: vec!["admin".to_string()],
        }
    }

    /// Creates a regular test user.
    pub fn regular() -> Self {
        Self {
            id: "user_regular_001".to_string(),
            email: "user@test.local".to_string(),
            password: "UserPassword123!".to_string(),
            name: "Test User".to_string(),
            roles: vec!["user".to_string()],
        }
    }

    /// Creates a read-only test user.
    pub fn readonly() -> Self {
        Self {
            id: "user_readonly_001".to_string(),
            email: "readonly@test.local".to_string(),
            password: "ReadOnlyPass123!".to_string(),
            name: "Read Only User".to_string(),
            roles: vec!["reader".to_string()],
        }
    }

    /// Creates a unique test user with random ID.
    pub fn unique() -> Self {
        let id = Uuid::new_v4().to_string();
        Self {
            id: format!("user_{}", &id[..8]),
            email: format!("test_{}@test.local", &id[..8]),
            password: "TestPassword123!".to_string(),
            name: format!("Test User {}", &id[..8]),
            roles: vec!["user".to_string()],
        }
    }
}

/// Test dataset fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestDataset {
    pub name: String,
    pub description: Option<String>,
    pub schema: Option<serde_json::Value>,
    pub tags: Vec<String>,
}

impl TestDataset {
    /// Creates a basic test dataset.
    pub fn basic() -> Self {
        Self {
            name: "Test Dataset".to_string(),
            description: Some("A test dataset for integration testing".to_string()),
            schema: None,
            tags: vec!["test".to_string()],
        }
    }

    /// Creates a dataset with schema.
    pub fn with_schema() -> Self {
        Self {
            name: "Structured Dataset".to_string(),
            description: Some("Dataset with JSON schema".to_string()),
            schema: Some(json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "label": { "type": "string" },
                    "score": { "type": "number", "minimum": 0, "maximum": 1 }
                },
                "required": ["text", "label"]
            })),
            tags: vec!["test".to_string(), "schema".to_string()],
        }
    }

    /// Creates an ML training dataset.
    pub fn ml_training() -> Self {
        Self {
            name: "ML Training Data".to_string(),
            description: Some("Training data for machine learning models".to_string()),
            schema: Some(json!({
                "type": "object",
                "properties": {
                    "input": { "type": "string" },
                    "output": { "type": "string" },
                    "metadata": { "type": "object" }
                },
                "required": ["input", "output"]
            })),
            tags: vec!["ml".to_string(), "training".to_string()],
        }
    }

    /// Creates a unique dataset with random name.
    pub fn unique() -> Self {
        let id = Uuid::new_v4().to_string();
        Self {
            name: format!("Dataset {}", &id[..8]),
            description: Some(format!("Test dataset {}", id)),
            schema: None,
            tags: vec!["test".to_string(), "unique".to_string()],
        }
    }
}

/// Test record fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRecord {
    pub data: serde_json::Value,
    pub metadata: Option<serde_json::Value>,
}

impl TestRecord {
    /// Creates a simple text record.
    pub fn simple_text(text: &str) -> Self {
        Self {
            data: json!({
                "text": text
            }),
            metadata: None,
        }
    }

    /// Creates a labeled record.
    pub fn labeled(text: &str, label: &str) -> Self {
        Self {
            data: json!({
                "text": text,
                "label": label
            }),
            metadata: Some(json!({
                "source": "test"
            })),
        }
    }

    /// Creates an ML training record.
    pub fn ml_training(input: &str, output: &str) -> Self {
        Self {
            data: json!({
                "input": input,
                "output": output
            }),
            metadata: Some(json!({
                "model": "test",
                "timestamp": Utc::now().to_rfc3339()
            })),
        }
    }

    /// Creates a record with PII for testing detection.
    pub fn with_email_pii() -> Self {
        Self {
            data: json!({
                "text": "Contact john.doe@example.com for more information."
            }),
            metadata: None,
        }
    }

    /// Creates a record with multiple PII types.
    pub fn with_multiple_pii() -> Self {
        Self {
            data: json!({
                "text": "John Smith (SSN: 123-45-6789) can be reached at john@example.com or 555-123-4567."
            }),
            metadata: None,
        }
    }

    /// Creates a record with no PII.
    pub fn no_pii() -> Self {
        Self {
            data: json!({
                "text": "The quick brown fox jumps over the lazy dog."
            }),
            metadata: None,
        }
    }

    /// Creates a batch of records for testing.
    pub fn batch(count: usize) -> Vec<Self> {
        (0..count)
            .map(|i| Self::simple_text(&format!("Record content {}", i)))
            .collect()
    }
}

/// Test webhook fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestWebhook {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
}

impl TestWebhook {
    /// Creates a basic webhook.
    pub fn basic(url: &str) -> Self {
        Self {
            name: "Test Webhook".to_string(),
            url: url.to_string(),
            events: vec!["record.created".to_string()],
            secret: "test_webhook_secret_12345".to_string(),
        }
    }

    /// Creates a webhook for all events.
    pub fn all_events(url: &str) -> Self {
        Self {
            name: "All Events Webhook".to_string(),
            url: url.to_string(),
            events: vec![
                "dataset.created".to_string(),
                "dataset.updated".to_string(),
                "dataset.deleted".to_string(),
                "record.created".to_string(),
                "record.updated".to_string(),
                "record.deleted".to_string(),
                "pii.detected".to_string(),
            ],
            secret: "webhook_secret_all_events".to_string(),
        }
    }
}

/// PII test samples for detection testing.
pub mod pii_samples {
    /// Samples containing email addresses.
    pub const EMAILS: &[&str] = &[
        "Contact me at john.doe@example.com",
        "Send feedback to support@company.org",
        "Email: user+tag@subdomain.domain.co.uk",
    ];

    /// Samples containing phone numbers.
    pub const PHONES: &[&str] = &[
        "Call us at 555-123-4567",
        "Phone: (555) 123-4567",
        "Contact: +1-555-123-4567",
        "Mobile: 555.123.4567",
    ];

    /// Samples containing SSNs.
    pub const SSNS: &[&str] = &[
        "SSN: 123-45-6789",
        "Social Security Number: 987-65-4321",
        "My SSN is 111-22-3333",
    ];

    /// Samples containing credit card numbers.
    pub const CREDIT_CARDS: &[&str] = &[
        "Card: 4111-1111-1111-1111",
        "Credit card number: 4111111111111111",
        "Visa: 4111 1111 1111 1111",
    ];

    /// Samples containing IP addresses.
    pub const IP_ADDRESSES: &[&str] = &[
        "Server IP: 192.168.1.100",
        "Connect to 10.0.0.1",
        "IPv4 address: 172.16.0.1",
    ];

    /// Clean text samples (no PII).
    pub const CLEAN_TEXT: &[&str] = &[
        "The weather is nice today.",
        "Machine learning models can be trained on large datasets.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    ];

    /// Mixed content with multiple PII types.
    pub const MIXED_PII: &str =
        "Customer John Smith (SSN: 123-45-6789) can be reached at john.smith@example.com or 555-123-4567. \
         Payment was processed with card 4111-1111-1111-1111 from IP 192.168.1.100.";
}

/// API response fixtures for mocking.
pub mod api_responses {
    use serde_json::{json, Value};

    /// Successful login response.
    pub fn login_success() -> Value {
        json!({
            "success": true,
            "data": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
                "user": {
                    "id": "user_001",
                    "email": "test@example.com",
                    "name": "Test User",
                    "roles": ["user"]
                }
            }
        })
    }

    /// Dataset created response.
    pub fn dataset_created(id: &str) -> Value {
        json!({
            "success": true,
            "data": {
                "id": id,
                "name": "Test Dataset",
                "description": "Test description",
                "schema_version": "1.0",
                "record_count": 0,
                "size_bytes": 0,
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:00:00Z",
                "created_by": "user_001",
                "status": "active",
                "tags": ["test"]
            }
        })
    }

    /// Error response.
    pub fn error(code: &str, message: &str) -> Value {
        json!({
            "success": false,
            "error": {
                "code": code,
                "message": message
            }
        })
    }
}
