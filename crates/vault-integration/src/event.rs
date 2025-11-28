//! Event types and payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Event type categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Dataset events
    /// Dataset created.
    DatasetCreated,
    /// Dataset updated.
    DatasetUpdated,
    /// Dataset deleted.
    DatasetDeleted,
    /// Dataset archived.
    DatasetArchived,
    /// Dataset restored.
    DatasetRestored,

    // Record events
    /// Record created.
    RecordCreated,
    /// Record updated.
    RecordUpdated,
    /// Record deleted.
    RecordDeleted,
    /// Record accessed.
    RecordAccessed,

    // Version events
    /// Commit created.
    CommitCreated,
    /// Branch created.
    BranchCreated,
    /// Branch deleted.
    BranchDeleted,
    /// Tag created.
    TagCreated,
    /// Merge completed.
    MergeCompleted,

    // Access events
    /// User granted access.
    AccessGranted,
    /// User access revoked.
    AccessRevoked,
    /// Role assigned.
    RoleAssigned,
    /// Role removed.
    RoleRemoved,
    /// Permission denied.
    PermissionDenied,

    // Security events
    /// Encryption completed.
    EncryptionCompleted,
    /// Decryption completed.
    DecryptionCompleted,
    /// Key rotated.
    KeyRotated,
    /// Anomaly detected.
    AnomalyDetected,

    // Compliance events
    /// PII detected.
    PiiDetected,
    /// Anonymization applied.
    AnonymizationApplied,
    /// Data export requested.
    DataExportRequested,
    /// Data deletion requested.
    DataDeletionRequested,

    // System events
    /// System started.
    SystemStarted,
    /// System stopped.
    SystemStopped,
    /// Health check failed.
    HealthCheckFailed,
    /// Maintenance started.
    MaintenanceStarted,

    // Webhook events
    /// Webhook created.
    WebhookCreated,
    /// Webhook updated.
    WebhookUpdated,
    /// Webhook deleted.
    WebhookDeleted,
    /// Webhook delivery failed.
    WebhookDeliveryFailed,

    // Custom event
    /// Custom event type.
    Custom,
}

impl EventType {
    /// Returns the event category.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::DatasetCreated
            | Self::DatasetUpdated
            | Self::DatasetDeleted
            | Self::DatasetArchived
            | Self::DatasetRestored => "dataset",

            Self::RecordCreated
            | Self::RecordUpdated
            | Self::RecordDeleted
            | Self::RecordAccessed => "record",

            Self::CommitCreated
            | Self::BranchCreated
            | Self::BranchDeleted
            | Self::TagCreated
            | Self::MergeCompleted => "version",

            Self::AccessGranted
            | Self::AccessRevoked
            | Self::RoleAssigned
            | Self::RoleRemoved
            | Self::PermissionDenied => "access",

            Self::EncryptionCompleted
            | Self::DecryptionCompleted
            | Self::KeyRotated
            | Self::AnomalyDetected => "security",

            Self::PiiDetected
            | Self::AnonymizationApplied
            | Self::DataExportRequested
            | Self::DataDeletionRequested => "compliance",

            Self::SystemStarted
            | Self::SystemStopped
            | Self::HealthCheckFailed
            | Self::MaintenanceStarted => "system",

            Self::WebhookCreated
            | Self::WebhookUpdated
            | Self::WebhookDeleted
            | Self::WebhookDeliveryFailed => "webhook",

            Self::Custom => "custom",
        }
    }

    /// Returns true if this event type requires audit logging.
    #[must_use]
    pub fn requires_audit(&self) -> bool {
        matches!(
            self,
            Self::DatasetDeleted
                | Self::RecordDeleted
                | Self::AccessGranted
                | Self::AccessRevoked
                | Self::PermissionDenied
                | Self::KeyRotated
                | Self::AnomalyDetected
                | Self::DataExportRequested
                | Self::DataDeletionRequested
        )
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::DatasetCreated => "dataset.created",
            Self::DatasetUpdated => "dataset.updated",
            Self::DatasetDeleted => "dataset.deleted",
            Self::DatasetArchived => "dataset.archived",
            Self::DatasetRestored => "dataset.restored",
            Self::RecordCreated => "record.created",
            Self::RecordUpdated => "record.updated",
            Self::RecordDeleted => "record.deleted",
            Self::RecordAccessed => "record.accessed",
            Self::CommitCreated => "commit.created",
            Self::BranchCreated => "branch.created",
            Self::BranchDeleted => "branch.deleted",
            Self::TagCreated => "tag.created",
            Self::MergeCompleted => "merge.completed",
            Self::AccessGranted => "access.granted",
            Self::AccessRevoked => "access.revoked",
            Self::RoleAssigned => "role.assigned",
            Self::RoleRemoved => "role.removed",
            Self::PermissionDenied => "permission.denied",
            Self::EncryptionCompleted => "encryption.completed",
            Self::DecryptionCompleted => "decryption.completed",
            Self::KeyRotated => "key.rotated",
            Self::AnomalyDetected => "anomaly.detected",
            Self::PiiDetected => "pii.detected",
            Self::AnonymizationApplied => "anonymization.applied",
            Self::DataExportRequested => "data_export.requested",
            Self::DataDeletionRequested => "data_deletion.requested",
            Self::SystemStarted => "system.started",
            Self::SystemStopped => "system.stopped",
            Self::HealthCheckFailed => "health_check.failed",
            Self::MaintenanceStarted => "maintenance.started",
            Self::WebhookCreated => "webhook.created",
            Self::WebhookUpdated => "webhook.updated",
            Self::WebhookDeleted => "webhook.deleted",
            Self::WebhookDeliveryFailed => "webhook.delivery_failed",
            Self::Custom => "custom",
        };
        write!(f, "{}", name)
    }
}

/// Event metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Event ID.
    pub id: String,
    /// Event type.
    pub event_type: EventType,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Source service.
    pub source: String,
    /// Tenant ID (for multi-tenancy).
    pub tenant_id: Option<String>,
    /// User ID who triggered the event.
    pub user_id: Option<String>,
    /// Correlation ID for tracing.
    pub correlation_id: Option<String>,
    /// Causation ID (ID of event that caused this).
    pub causation_id: Option<String>,
    /// Custom event type name (for Custom events).
    pub custom_type: Option<String>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl EventMetadata {
    /// Creates new event metadata.
    pub fn new(event_type: EventType, source: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: Utc::now(),
            source: source.into(),
            tenant_id: None,
            user_id: None,
            correlation_id: None,
            causation_id: None,
            custom_type: None,
            metadata: HashMap::new(),
        }
    }

    /// Sets the tenant ID.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the user ID.
    #[must_use]
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Sets the correlation ID.
    #[must_use]
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Sets the causation ID.
    #[must_use]
    pub fn with_causation_id(mut self, id: impl Into<String>) -> Self {
        self.causation_id = Some(id.into());
        self
    }

    /// Adds custom metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Event payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventPayload {
    /// Dataset event payload.
    Dataset(DatasetEventPayload),
    /// Record event payload.
    Record(RecordEventPayload),
    /// Version event payload.
    Version(VersionEventPayload),
    /// Access event payload.
    Access(AccessEventPayload),
    /// Security event payload.
    Security(SecurityEventPayload),
    /// Compliance event payload.
    Compliance(ComplianceEventPayload),
    /// System event payload.
    System(SystemEventPayload),
    /// Webhook event payload.
    Webhook(WebhookEventPayload),
    /// Custom JSON payload.
    Custom(serde_json::Value),
}

/// Dataset event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetEventPayload {
    /// Dataset ID.
    pub dataset_id: String,
    /// Dataset name.
    pub name: Option<String>,
    /// Schema version.
    pub schema_version: Option<String>,
    /// Record count.
    pub record_count: Option<u64>,
    /// Size in bytes.
    pub size_bytes: Option<u64>,
    /// Previous state (for updates).
    pub previous: Option<Box<DatasetEventPayload>>,
}

/// Record event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordEventPayload {
    /// Dataset ID.
    pub dataset_id: String,
    /// Record ID.
    pub record_id: String,
    /// Record version.
    pub version: Option<u64>,
    /// Content hash.
    pub content_hash: Option<String>,
    /// Record size.
    pub size_bytes: Option<u64>,
    /// Fields changed (for updates).
    pub changed_fields: Option<Vec<String>>,
}

/// Version event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionEventPayload {
    /// Dataset ID.
    pub dataset_id: String,
    /// Commit ID.
    pub commit_id: Option<String>,
    /// Branch name.
    pub branch: Option<String>,
    /// Tag name.
    pub tag: Option<String>,
    /// Parent commits.
    pub parents: Option<Vec<String>>,
    /// Commit message.
    pub message: Option<String>,
}

/// Access event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEventPayload {
    /// Subject ID (user or service).
    pub subject_id: String,
    /// Subject type.
    pub subject_type: String,
    /// Resource ID.
    pub resource_id: String,
    /// Resource type.
    pub resource_type: String,
    /// Action.
    pub action: String,
    /// Role (for role events).
    pub role: Option<String>,
    /// Reason (for denial or revocation).
    pub reason: Option<String>,
}

/// Security event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventPayload {
    /// Resource ID.
    pub resource_id: String,
    /// Resource type.
    pub resource_type: String,
    /// Key ID (for key events).
    pub key_id: Option<String>,
    /// Algorithm used.
    pub algorithm: Option<String>,
    /// Anomaly type.
    pub anomaly_type: Option<String>,
    /// Severity.
    pub severity: Option<String>,
    /// Details.
    pub details: Option<String>,
}

/// Compliance event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEventPayload {
    /// Dataset ID.
    pub dataset_id: String,
    /// Record ID (if applicable).
    pub record_id: Option<String>,
    /// PII types detected.
    pub pii_types: Option<Vec<String>>,
    /// Anonymization strategy applied.
    pub strategy: Option<String>,
    /// Request ID (for export/deletion).
    pub request_id: Option<String>,
    /// Requester info.
    pub requester: Option<String>,
    /// Framework (GDPR, HIPAA, etc.).
    pub framework: Option<String>,
}

/// System event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEventPayload {
    /// Service name.
    pub service: String,
    /// Version.
    pub version: Option<String>,
    /// Health status.
    pub status: Option<String>,
    /// Error message.
    pub error: Option<String>,
    /// Maintenance type.
    pub maintenance_type: Option<String>,
    /// Duration estimate (seconds).
    pub estimated_duration: Option<u64>,
}

/// Webhook event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEventPayload {
    /// Webhook ID.
    pub webhook_id: String,
    /// Webhook URL.
    pub url: Option<String>,
    /// Event types subscribed.
    pub event_types: Option<Vec<String>>,
    /// Delivery status.
    pub delivery_status: Option<String>,
    /// HTTP status code.
    pub http_status: Option<u16>,
    /// Error message.
    pub error: Option<String>,
    /// Retry count.
    pub retry_count: Option<u32>,
}

/// A complete event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event metadata.
    #[serde(flatten)]
    pub metadata: EventMetadata,
    /// Event payload.
    pub payload: EventPayload,
}

impl Event {
    /// Creates a new event.
    pub fn new(metadata: EventMetadata, payload: EventPayload) -> Self {
        Self { metadata, payload }
    }

    /// Creates a dataset event.
    pub fn dataset(event_type: EventType, source: impl Into<String>, payload: DatasetEventPayload) -> Self {
        Self::new(
            EventMetadata::new(event_type, source),
            EventPayload::Dataset(payload),
        )
    }

    /// Creates a record event.
    pub fn record(event_type: EventType, source: impl Into<String>, payload: RecordEventPayload) -> Self {
        Self::new(
            EventMetadata::new(event_type, source),
            EventPayload::Record(payload),
        )
    }

    /// Creates a version event.
    pub fn version(event_type: EventType, source: impl Into<String>, payload: VersionEventPayload) -> Self {
        Self::new(
            EventMetadata::new(event_type, source),
            EventPayload::Version(payload),
        )
    }

    /// Creates an access event.
    pub fn access(event_type: EventType, source: impl Into<String>, payload: AccessEventPayload) -> Self {
        Self::new(
            EventMetadata::new(event_type, source),
            EventPayload::Access(payload),
        )
    }

    /// Creates a security event.
    pub fn security(event_type: EventType, source: impl Into<String>, payload: SecurityEventPayload) -> Self {
        Self::new(
            EventMetadata::new(event_type, source),
            EventPayload::Security(payload),
        )
    }

    /// Creates a compliance event.
    pub fn compliance(event_type: EventType, source: impl Into<String>, payload: ComplianceEventPayload) -> Self {
        Self::new(
            EventMetadata::new(event_type, source),
            EventPayload::Compliance(payload),
        )
    }

    /// Creates a system event.
    pub fn system(event_type: EventType, source: impl Into<String>, payload: SystemEventPayload) -> Self {
        Self::new(
            EventMetadata::new(event_type, source),
            EventPayload::System(payload),
        )
    }

    /// Returns the event ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.metadata.id
    }

    /// Returns the event type.
    #[must_use]
    pub fn event_type(&self) -> EventType {
        self.metadata.event_type
    }

    /// Returns the timestamp.
    #[must_use]
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.metadata.timestamp
    }

    /// Serializes to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Serializes to JSON bytes.
    pub fn to_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Deserializes from JSON.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_display() {
        assert_eq!(EventType::DatasetCreated.to_string(), "dataset.created");
        assert_eq!(EventType::RecordUpdated.to_string(), "record.updated");
    }

    #[test]
    fn test_event_type_category() {
        assert_eq!(EventType::DatasetCreated.category(), "dataset");
        assert_eq!(EventType::AccessGranted.category(), "access");
        assert_eq!(EventType::KeyRotated.category(), "security");
    }

    #[test]
    fn test_event_creation() {
        let payload = DatasetEventPayload {
            dataset_id: "ds-123".to_string(),
            name: Some("test".to_string()),
            schema_version: None,
            record_count: Some(100),
            size_bytes: None,
            previous: None,
        };

        let event = Event::dataset(EventType::DatasetCreated, "test-service", payload);

        assert_eq!(event.event_type(), EventType::DatasetCreated);
        assert!(!event.id().is_empty());
    }

    #[test]
    fn test_event_serialization() {
        let payload = DatasetEventPayload {
            dataset_id: "ds-123".to_string(),
            name: Some("test".to_string()),
            schema_version: None,
            record_count: Some(100),
            size_bytes: None,
            previous: None,
        };

        let event = Event::dataset(EventType::DatasetCreated, "test-service", payload);
        let json = event.to_json().unwrap();

        assert!(json.contains("dataset.created") || json.contains("DatasetCreated"));
        assert!(json.contains("ds-123"));
    }

    #[test]
    fn test_event_requires_audit() {
        assert!(EventType::DatasetDeleted.requires_audit());
        assert!(EventType::AccessRevoked.requires_audit());
        assert!(!EventType::DatasetCreated.requires_audit());
        assert!(!EventType::RecordAccessed.requires_audit());
    }
}
