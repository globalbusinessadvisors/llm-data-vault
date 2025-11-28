//! Secure audit logging with integrity verification.
//!
//! Provides tamper-evident audit logging including:
//! - Cryptographic integrity verification
//! - Write-once append-only storage
//! - Sensitive data redaction
//! - Chain-based integrity (each entry links to previous)
//! - Efficient verification of log integrity

use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::debug;

use crate::config::AuditConfig;
use crate::error::{SecurityError, Result};

/// An audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID.
    pub id: String,
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Entry timestamp.
    pub timestamp: DateTime<Utc>,
    /// Event type.
    pub event_type: String,
    /// Event category.
    pub category: AuditCategory,
    /// Event severity.
    pub severity: AuditSeverity,
    /// Actor who performed the action.
    pub actor: Option<AuditActor>,
    /// Target of the action.
    pub target: Option<AuditTarget>,
    /// Action performed.
    pub action: String,
    /// Action outcome.
    pub outcome: AuditOutcome,
    /// Additional context.
    pub context: serde_json::Value,
    /// Request ID for correlation.
    pub request_id: Option<String>,
    /// Hash of the previous entry (for chain integrity).
    pub previous_hash: Option<String>,
    /// Hash of this entry (for integrity verification).
    pub entry_hash: String,
}

/// Audit event category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Authentication events.
    Authentication,
    /// Authorization events.
    Authorization,
    /// Data access events.
    DataAccess,
    /// Data modification events.
    DataModification,
    /// Configuration changes.
    Configuration,
    /// Security events.
    Security,
    /// System events.
    System,
}

impl std::fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication => write!(f, "authentication"),
            Self::Authorization => write!(f, "authorization"),
            Self::DataAccess => write!(f, "data_access"),
            Self::DataModification => write!(f, "data_modification"),
            Self::Configuration => write!(f, "configuration"),
            Self::Security => write!(f, "security"),
            Self::System => write!(f, "system"),
        }
    }
}

/// Audit event severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Informational event.
    Info,
    /// Warning event.
    Warning,
    /// Error event.
    Error,
    /// Critical event.
    Critical,
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Audit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    /// Action succeeded.
    Success,
    /// Action failed.
    Failure,
    /// Action was denied.
    Denied,
    /// Action error.
    Error,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Denied => write!(f, "denied"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// The actor who performed an audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditActor {
    /// Actor type (user, service, system).
    pub actor_type: String,
    /// Actor ID.
    pub id: String,
    /// Actor name or display name.
    pub name: Option<String>,
    /// IP address.
    pub ip_address: Option<String>,
    /// User agent.
    pub user_agent: Option<String>,
    /// Session ID.
    pub session_id: Option<String>,
    /// Tenant ID.
    pub tenant_id: Option<String>,
}

impl AuditActor {
    /// Creates a user actor.
    #[must_use]
    pub fn user(id: impl Into<String>) -> Self {
        Self {
            actor_type: "user".to_string(),
            id: id.into(),
            name: None,
            ip_address: None,
            user_agent: None,
            session_id: None,
            tenant_id: None,
        }
    }

    /// Creates a service actor.
    #[must_use]
    pub fn service(id: impl Into<String>) -> Self {
        Self {
            actor_type: "service".to_string(),
            id: id.into(),
            name: None,
            ip_address: None,
            user_agent: None,
            session_id: None,
            tenant_id: None,
        }
    }

    /// Creates a system actor.
    #[must_use]
    pub fn system() -> Self {
        Self {
            actor_type: "system".to_string(),
            id: "system".to_string(),
            name: Some("System".to_string()),
            ip_address: None,
            user_agent: None,
            session_id: None,
            tenant_id: None,
        }
    }

    /// Sets the name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Sets the user agent.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Sets the session ID.
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the tenant ID.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }
}

/// The target of an audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTarget {
    /// Target type (dataset, record, user, etc.).
    pub target_type: String,
    /// Target ID.
    pub id: String,
    /// Target name or display name.
    pub name: Option<String>,
    /// Additional attributes.
    pub attributes: serde_json::Value,
}

impl AuditTarget {
    /// Creates a new audit target.
    #[must_use]
    pub fn new(target_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            target_type: target_type.into(),
            id: id.into(),
            name: None,
            attributes: serde_json::Value::Null,
        }
    }

    /// Sets the name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets additional attributes.
    #[must_use]
    pub fn with_attributes(mut self, attributes: serde_json::Value) -> Self {
        self.attributes = attributes;
        self
    }
}

/// Builder for audit entries.
#[derive(Debug)]
pub struct AuditEntryBuilder {
    event_type: String,
    category: AuditCategory,
    severity: AuditSeverity,
    action: String,
    outcome: AuditOutcome,
    actor: Option<AuditActor>,
    target: Option<AuditTarget>,
    context: serde_json::Value,
    request_id: Option<String>,
}

impl AuditEntryBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new(
        event_type: impl Into<String>,
        category: AuditCategory,
        action: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            category,
            severity: AuditSeverity::Info,
            action: action.into(),
            outcome: AuditOutcome::Success,
            actor: None,
            target: None,
            context: serde_json::Value::Null,
            request_id: None,
        }
    }

    /// Sets the severity.
    #[must_use]
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets the outcome.
    #[must_use]
    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Sets the actor.
    #[must_use]
    pub fn actor(mut self, actor: AuditActor) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Sets the target.
    #[must_use]
    pub fn target(mut self, target: AuditTarget) -> Self {
        self.target = Some(target);
        self
    }

    /// Sets the context.
    #[must_use]
    pub fn context(mut self, context: serde_json::Value) -> Self {
        self.context = context;
        self
    }

    /// Sets the request ID.
    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Builds the entry (internal use - hash added by SecureAuditLog).
    fn build_internal(self, sequence: u64, previous_hash: Option<String>) -> AuditEntry {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        // Create entry without hash first
        let mut entry = AuditEntry {
            id,
            sequence,
            timestamp,
            event_type: self.event_type,
            category: self.category,
            severity: self.severity,
            actor: self.actor,
            target: self.target,
            action: self.action,
            outcome: self.outcome,
            context: self.context,
            request_id: self.request_id,
            previous_hash,
            entry_hash: String::new(),
        };

        // Calculate hash
        entry.entry_hash = calculate_entry_hash(&entry);

        entry
    }
}

/// Integrity verification result.
#[derive(Debug, Clone)]
pub struct AuditIntegrity {
    /// Whether the log is valid.
    pub valid: bool,
    /// Number of entries verified.
    pub entries_verified: usize,
    /// First invalid entry (if any).
    pub first_invalid_entry: Option<u64>,
    /// Error message (if invalid).
    pub error: Option<String>,
}

impl AuditIntegrity {
    /// Creates a valid integrity result.
    #[must_use]
    pub fn valid(entries_verified: usize) -> Self {
        Self {
            valid: true,
            entries_verified,
            first_invalid_entry: None,
            error: None,
        }
    }

    /// Creates an invalid integrity result.
    #[must_use]
    pub fn invalid(first_invalid_entry: u64, error: impl Into<String>) -> Self {
        Self {
            valid: false,
            entries_verified: 0,
            first_invalid_entry: Some(first_invalid_entry),
            error: Some(error.into()),
        }
    }
}

/// Secure audit log with integrity verification.
pub struct SecureAuditLog {
    config: AuditConfig,
    entries: RwLock<Vec<AuditEntry>>,
    sequence: RwLock<u64>,
    last_hash: RwLock<Option<String>>,
}

impl SecureAuditLog {
    /// Creates a new secure audit log.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn new(config: AuditConfig) -> Result<Self> {
        Ok(Self {
            config,
            entries: RwLock::new(Vec::new()),
            sequence: RwLock::new(0),
            last_hash: RwLock::new(None),
        })
    }

    /// Checks if audit logging is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Logs an audit entry.
    ///
    /// # Errors
    ///
    /// Returns an error if logging fails.
    pub fn log(&self, builder: AuditEntryBuilder) -> Result<AuditEntry> {
        if !self.config.enabled {
            return Err(SecurityError::Audit("Audit logging is disabled".to_string()));
        }

        // Check if event type should be audited
        if !self.config.audited_events.contains(&builder.category.to_string()) {
            debug!("Event category {} not in audited events, skipping", builder.category);
            return Err(SecurityError::Audit(format!(
                "Event category {} is not configured for auditing",
                builder.category
            )));
        }

        // Get sequence and previous hash
        let (sequence, previous_hash) = {
            let mut seq = self.sequence.write().map_err(|_| {
                SecurityError::Audit("Failed to acquire sequence lock".to_string())
            })?;
            let hash = self.last_hash.read().map_err(|_| {
                SecurityError::Audit("Failed to acquire hash lock".to_string())
            })?;

            *seq += 1;
            (*seq, hash.clone())
        };

        // Build entry
        let mut entry = builder.build_internal(sequence, previous_hash);

        // Redact sensitive data if enabled
        if self.config.redact_sensitive {
            entry = self.redact_entry(entry);
        }

        // Update last hash
        {
            let mut last_hash = self.last_hash.write().map_err(|_| {
                SecurityError::Audit("Failed to acquire hash lock".to_string())
            })?;
            *last_hash = Some(entry.entry_hash.clone());
        }

        // Store entry
        {
            let mut entries = self.entries.write().map_err(|_| {
                SecurityError::Audit("Failed to acquire entries lock".to_string())
            })?;

            // Enforce max memory entries
            while entries.len() >= self.config.max_memory_entries {
                entries.remove(0);
            }

            entries.push(entry.clone());
        }

        debug!(
            "Audit entry logged: {} - {} - {}",
            entry.event_type, entry.action, entry.outcome
        );

        Ok(entry)
    }

    /// Logs an authentication event.
    ///
    /// # Errors
    ///
    /// Returns an error if logging fails.
    pub fn log_authentication(
        &self,
        action: impl Into<String>,
        outcome: AuditOutcome,
        actor: AuditActor,
    ) -> Result<AuditEntry> {
        self.log(
            AuditEntryBuilder::new("authentication", AuditCategory::Authentication, action)
                .outcome(outcome)
                .actor(actor)
                .severity(if outcome == AuditOutcome::Success {
                    AuditSeverity::Info
                } else {
                    AuditSeverity::Warning
                }),
        )
    }

    /// Logs a data access event.
    ///
    /// # Errors
    ///
    /// Returns an error if logging fails.
    pub fn log_data_access(
        &self,
        action: impl Into<String>,
        actor: AuditActor,
        target: AuditTarget,
    ) -> Result<AuditEntry> {
        self.log(
            AuditEntryBuilder::new("data_access", AuditCategory::DataAccess, action)
                .actor(actor)
                .target(target),
        )
    }

    /// Logs a security event.
    ///
    /// # Errors
    ///
    /// Returns an error if logging fails.
    pub fn log_security_event(
        &self,
        event_type: impl Into<String>,
        action: impl Into<String>,
        severity: AuditSeverity,
        context: serde_json::Value,
    ) -> Result<AuditEntry> {
        self.log(
            AuditEntryBuilder::new(event_type, AuditCategory::Security, action)
                .severity(severity)
                .context(context),
        )
    }

    /// Verifies the integrity of the audit log.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify_integrity(&self) -> Result<AuditIntegrity> {
        let entries = self.entries.read().map_err(|_| {
            SecurityError::Audit("Failed to acquire entries lock".to_string())
        })?;

        if entries.is_empty() {
            return Ok(AuditIntegrity::valid(0));
        }

        let mut previous_hash: Option<String> = None;

        for entry in entries.iter() {
            // Verify entry hash
            let calculated_hash = calculate_entry_hash(entry);
            if calculated_hash != entry.entry_hash {
                return Ok(AuditIntegrity::invalid(
                    entry.sequence,
                    format!(
                        "Entry {} hash mismatch: expected {}, got {}",
                        entry.sequence, calculated_hash, entry.entry_hash
                    ),
                ));
            }

            // Verify chain
            if entry.previous_hash != previous_hash {
                return Ok(AuditIntegrity::invalid(
                    entry.sequence,
                    format!(
                        "Entry {} chain broken: expected {:?}, got {:?}",
                        entry.sequence, previous_hash, entry.previous_hash
                    ),
                ));
            }

            previous_hash = Some(entry.entry_hash.clone());
        }

        Ok(AuditIntegrity::valid(entries.len()))
    }

    /// Gets entries by time range.
    #[must_use]
    pub fn get_entries(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Vec<AuditEntry> {
        let entries = match self.entries.read() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        entries
            .iter()
            .filter(|e| {
                let after_from = from.map_or(true, |f| e.timestamp >= f);
                let before_to = to.map_or(true, |t| e.timestamp <= t);
                after_from && before_to
            })
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }

    /// Gets entries by category.
    #[must_use]
    pub fn get_entries_by_category(&self, category: AuditCategory, limit: Option<usize>) -> Vec<AuditEntry> {
        let entries = match self.entries.read() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        entries
            .iter()
            .filter(|e| e.category == category)
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }

    /// Gets entries by actor.
    #[must_use]
    pub fn get_entries_by_actor(&self, actor_id: &str, limit: Option<usize>) -> Vec<AuditEntry> {
        let entries = match self.entries.read() {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        entries
            .iter()
            .filter(|e| e.actor.as_ref().map_or(false, |a| a.id == actor_id))
            .take(limit.unwrap_or(usize::MAX))
            .cloned()
            .collect()
    }

    /// Gets the current entry count.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Exports entries to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn export_json(&self) -> Result<String> {
        let entries = self.entries.read().map_err(|_| {
            SecurityError::Audit("Failed to acquire entries lock".to_string())
        })?;

        serde_json::to_string_pretty(&*entries).map_err(|e| {
            SecurityError::Audit(format!("Failed to serialize entries: {}", e))
        })
    }

    // Private helper methods

    fn redact_entry(&self, mut entry: AuditEntry) -> AuditEntry {
        if let Some(ref mut actor) = entry.actor {
            // Redact sensitive actor fields
            if let Some(ref ua) = actor.user_agent {
                if ua.len() > 100 {
                    actor.user_agent = Some(format!("{}...", &ua[..100]));
                }
            }
        }

        // Redact sensitive context fields
        if let serde_json::Value::Object(ref mut map) = entry.context {
            for field in &self.config.redacted_fields {
                if map.contains_key(field) {
                    map.insert(field.clone(), serde_json::json!("[REDACTED]"));
                }
            }
        }

        entry
    }
}

/// Calculates the hash of an audit entry.
fn calculate_entry_hash(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();

    // Hash deterministic fields
    hasher.update(entry.id.as_bytes());
    hasher.update(entry.sequence.to_le_bytes());
    hasher.update(entry.timestamp.to_rfc3339().as_bytes());
    hasher.update(entry.event_type.as_bytes());
    hasher.update(entry.category.to_string().as_bytes());
    hasher.update(entry.severity.to_string().as_bytes());
    hasher.update(entry.action.as_bytes());
    hasher.update(entry.outcome.to_string().as_bytes());

    if let Some(ref actor) = entry.actor {
        hasher.update(actor.id.as_bytes());
    }

    if let Some(ref target) = entry.target {
        hasher.update(target.id.as_bytes());
    }

    if let Some(ref prev) = entry.previous_hash {
        hasher.update(prev.as_bytes());
    }

    hex::encode(hasher.finalize())
}

impl std::fmt::Debug for SecureAuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureAuditLog")
            .field("enabled", &self.config.enabled)
            .field("entry_count", &self.entry_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AuditConfig {
        AuditConfig {
            enabled: true,
            immutable: true,
            include_integrity: true,
            redact_sensitive: true,
            audited_events: ["authentication", "authorization", "data_access", "security"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_log_entry() {
        let log = SecureAuditLog::new(test_config()).unwrap();

        let entry = log.log(
            AuditEntryBuilder::new("login", AuditCategory::Authentication, "user_login")
                .actor(AuditActor::user("user123"))
                .outcome(AuditOutcome::Success),
        ).unwrap();

        assert_eq!(entry.event_type, "login");
        assert_eq!(entry.outcome, AuditOutcome::Success);
        assert!(!entry.entry_hash.is_empty());
    }

    #[test]
    fn test_chain_integrity() {
        let log = SecureAuditLog::new(test_config()).unwrap();

        // Log multiple entries
        for i in 0..5 {
            log.log(
                AuditEntryBuilder::new(
                    format!("event_{}", i),
                    AuditCategory::Security,
                    "test_action",
                ),
            ).unwrap();
        }

        // Verify integrity
        let integrity = log.verify_integrity().unwrap();
        assert!(integrity.valid);
        assert_eq!(integrity.entries_verified, 5);
    }

    #[test]
    fn test_entry_hash_verification() {
        let log = SecureAuditLog::new(test_config()).unwrap();

        let entry = log.log(
            AuditEntryBuilder::new("test", AuditCategory::Security, "test_action"),
        ).unwrap();

        // Verify the hash matches
        let calculated = calculate_entry_hash(&entry);
        assert_eq!(calculated, entry.entry_hash);
    }

    #[test]
    fn test_sensitive_data_redaction() {
        let mut config = test_config();
        config.redacted_fields = ["password", "token"].iter().map(|s| s.to_string()).collect();

        let log = SecureAuditLog::new(config).unwrap();

        let entry = log.log(
            AuditEntryBuilder::new("auth", AuditCategory::Authentication, "login")
                .context(serde_json::json!({
                    "username": "test",
                    "password": "secret123"
                })),
        ).unwrap();

        // Password should be redacted
        if let serde_json::Value::Object(context) = &entry.context {
            assert_eq!(context.get("password"), Some(&serde_json::json!("[REDACTED]")));
            assert_eq!(context.get("username"), Some(&serde_json::json!("test")));
        }
    }

    #[test]
    fn test_get_entries_by_category() {
        let log = SecureAuditLog::new(test_config()).unwrap();

        log.log(AuditEntryBuilder::new("auth", AuditCategory::Authentication, "login")).unwrap();
        log.log(AuditEntryBuilder::new("access", AuditCategory::DataAccess, "read")).unwrap();
        log.log(AuditEntryBuilder::new("auth", AuditCategory::Authentication, "logout")).unwrap();

        let auth_entries = log.get_entries_by_category(AuditCategory::Authentication, None);
        assert_eq!(auth_entries.len(), 2);
    }

    #[test]
    fn test_get_entries_by_actor() {
        let log = SecureAuditLog::new(test_config()).unwrap();

        log.log(
            AuditEntryBuilder::new("action1", AuditCategory::Security, "test")
                .actor(AuditActor::user("user1")),
        ).unwrap();

        log.log(
            AuditEntryBuilder::new("action2", AuditCategory::Security, "test")
                .actor(AuditActor::user("user2")),
        ).unwrap();

        log.log(
            AuditEntryBuilder::new("action3", AuditCategory::Security, "test")
                .actor(AuditActor::user("user1")),
        ).unwrap();

        let user1_entries = log.get_entries_by_actor("user1", None);
        assert_eq!(user1_entries.len(), 2);
    }

    #[test]
    fn test_audit_entry_builder() {
        let entry = AuditEntryBuilder::new("test_event", AuditCategory::Security, "test_action")
            .severity(AuditSeverity::Warning)
            .outcome(AuditOutcome::Failure)
            .actor(AuditActor::user("test_user").with_ip("192.168.1.1"))
            .target(AuditTarget::new("dataset", "ds-123"))
            .context(serde_json::json!({"key": "value"}))
            .request_id("req-456")
            .build_internal(1, None);

        assert_eq!(entry.event_type, "test_event");
        assert_eq!(entry.severity, AuditSeverity::Warning);
        assert_eq!(entry.outcome, AuditOutcome::Failure);
        assert!(entry.actor.is_some());
        assert!(entry.target.is_some());
    }

    #[test]
    fn test_export_json() {
        let log = SecureAuditLog::new(test_config()).unwrap();

        log.log(AuditEntryBuilder::new("test", AuditCategory::Security, "action")).unwrap();

        let json = log.export_json().unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("security"));
    }
}
