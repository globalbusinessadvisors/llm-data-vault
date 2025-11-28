//! Access audit logging.

use crate::{AuthContext, AuthRequest, AuthResponse, DecisionSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event ID.
    pub id: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event type.
    pub event_type: AuditEventType,
    /// User ID.
    pub user_id: String,
    /// User roles at time of event.
    pub user_roles: Vec<String>,
    /// Tenant ID.
    pub tenant_id: Option<String>,
    /// Action attempted.
    pub action: String,
    /// Resource accessed.
    pub resource: String,
    /// Resource type.
    pub resource_type: String,
    /// Decision made.
    pub decision: AuditDecision,
    /// Decision reason.
    pub reason: Option<String>,
    /// Decision source.
    pub decision_source: String,
    /// Request context.
    pub context: HashMap<String, String>,
    /// Client IP.
    pub client_ip: Option<String>,
    /// User agent.
    pub user_agent: Option<String>,
    /// Session ID.
    pub session_id: Option<String>,
    /// Request ID.
    pub request_id: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
}

/// Audit event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Authentication attempt.
    Authentication,
    /// Authorization check.
    Authorization,
    /// Resource access.
    ResourceAccess,
    /// Permission change.
    PermissionChange,
    /// Role assignment.
    RoleAssignment,
    /// Token issued.
    TokenIssued,
    /// Token revoked.
    TokenRevoked,
    /// Policy change.
    PolicyChange,
}

/// Audit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    /// Access allowed.
    Allowed,
    /// Access denied.
    Denied,
    /// Error occurred.
    Error,
}

impl AuditEvent {
    /// Creates a new audit event.
    pub fn new(event_type: AuditEventType, user_id: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type,
            user_id: user_id.into(),
            user_roles: Vec::new(),
            tenant_id: None,
            action: String::new(),
            resource: String::new(),
            resource_type: String::new(),
            decision: AuditDecision::Allowed,
            reason: None,
            decision_source: String::new(),
            context: HashMap::new(),
            client_ip: None,
            user_agent: None,
            session_id: None,
            request_id: None,
            duration_ms: None,
        }
    }

    /// Creates from authorization context and response.
    pub fn from_authorization(
        auth: &AuthContext,
        request: &AuthRequest,
        response: &AuthResponse,
    ) -> Self {
        let mut event = Self::new(AuditEventType::Authorization, &auth.user_id);

        event.user_roles = auth.roles.clone();
        event.tenant_id = auth.tenant_id.clone();
        event.action = request.action.clone();
        event.resource = request.resource.to_string();
        event.resource_type = request.resource.resource_type.to_string();
        event.decision = if response.allowed {
            AuditDecision::Allowed
        } else {
            AuditDecision::Denied
        };
        event.reason = response.reason.clone();
        event.decision_source = format!("{:?}", response.decision_source);
        event.context = request.context.clone();

        event
    }

    /// Sets client IP.
    #[must_use]
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Sets user agent.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Sets session ID.
    #[must_use]
    pub fn with_session_id(mut self, sid: impl Into<String>) -> Self {
        self.session_id = Some(sid.into());
        self
    }

    /// Sets request ID.
    #[must_use]
    pub fn with_request_id(mut self, rid: impl Into<String>) -> Self {
        self.request_id = Some(rid.into());
        self
    }

    /// Sets duration.
    #[must_use]
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }
}

/// Audit log sink trait.
pub trait AuditSink: Send + Sync {
    /// Records an audit event.
    fn record(&self, event: &AuditEvent);

    /// Flushes any buffered events.
    fn flush(&self);
}

/// In-memory audit sink (for testing/development).
pub struct InMemoryAuditSink {
    events: RwLock<Vec<AuditEvent>>,
    max_events: usize,
}

impl InMemoryAuditSink {
    /// Creates a new in-memory sink.
    pub fn new(max_events: usize) -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            max_events,
        }
    }

    /// Returns all events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.read().clone()
    }

    /// Clears all events.
    pub fn clear(&self) {
        self.events.write().clear();
    }

    /// Returns events filtered by user.
    pub fn events_for_user(&self, user_id: &str) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.user_id == user_id)
            .cloned()
            .collect()
    }

    /// Returns events filtered by resource.
    pub fn events_for_resource(&self, resource: &str) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.resource == resource)
            .cloned()
            .collect()
    }

    /// Returns denied events.
    pub fn denied_events(&self) -> Vec<AuditEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.decision == AuditDecision::Denied)
            .cloned()
            .collect()
    }
}

impl AuditSink for InMemoryAuditSink {
    fn record(&self, event: &AuditEvent) {
        let mut events = self.events.write();
        events.push(event.clone());

        // Trim if over limit
        if events.len() > self.max_events {
            events.remove(0);
        }
    }

    fn flush(&self) {
        // No-op for in-memory
    }
}

/// Console audit sink (logs to tracing).
pub struct ConsoleAuditSink;

impl AuditSink for ConsoleAuditSink {
    fn record(&self, event: &AuditEvent) {
        match event.decision {
            AuditDecision::Allowed => {
                tracing::info!(
                    user_id = %event.user_id,
                    action = %event.action,
                    resource = %event.resource,
                    decision = "allowed",
                    source = %event.decision_source,
                    "Access audit"
                );
            }
            AuditDecision::Denied => {
                tracing::warn!(
                    user_id = %event.user_id,
                    action = %event.action,
                    resource = %event.resource,
                    decision = "denied",
                    reason = ?event.reason,
                    source = %event.decision_source,
                    "Access audit"
                );
            }
            AuditDecision::Error => {
                tracing::error!(
                    user_id = %event.user_id,
                    action = %event.action,
                    resource = %event.resource,
                    decision = "error",
                    reason = ?event.reason,
                    "Access audit"
                );
            }
        }
    }

    fn flush(&self) {
        // No-op for console
    }
}

/// Access audit service.
pub struct AccessAudit {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl AccessAudit {
    /// Creates a new audit service.
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    /// Adds a sink.
    pub fn add_sink(&mut self, sink: Arc<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    /// Records an event to all sinks.
    pub fn record(&self, event: &AuditEvent) {
        for sink in &self.sinks {
            sink.record(event);
        }
    }

    /// Records an authorization event.
    pub fn record_authorization(
        &self,
        auth: &AuthContext,
        request: &AuthRequest,
        response: &AuthResponse,
    ) {
        let event = AuditEvent::from_authorization(auth, request, response);
        self.record(&event);
    }

    /// Records a token issued event.
    pub fn record_token_issued(&self, user_id: &str, token_type: &str) {
        let mut event = AuditEvent::new(AuditEventType::TokenIssued, user_id);
        event.action = "issue_token".to_string();
        event.resource = token_type.to_string();
        event.resource_type = "token".to_string();
        self.record(&event);
    }

    /// Records a role assignment event.
    pub fn record_role_assignment(
        &self,
        admin_user: &str,
        target_user: &str,
        role: &str,
        assigned: bool,
    ) {
        let mut event = AuditEvent::new(AuditEventType::RoleAssignment, admin_user);
        event.action = if assigned { "assign_role" } else { "revoke_role" }.to_string();
        event.resource = target_user.to_string();
        event.resource_type = "user".to_string();
        event.context.insert("role".to_string(), role.to_string());
        self.record(&event);
    }

    /// Flushes all sinks.
    pub fn flush(&self) {
        for sink in &self.sinks {
            sink.flush();
        }
    }
}

impl Default for AccessAudit {
    fn default() -> Self {
        Self::new()
    }
}

/// Audit query for searching events.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Filter by user ID.
    pub user_id: Option<String>,
    /// Filter by tenant ID.
    pub tenant_id: Option<String>,
    /// Filter by event type.
    pub event_type: Option<AuditEventType>,
    /// Filter by decision.
    pub decision: Option<AuditDecision>,
    /// Filter by action.
    pub action: Option<String>,
    /// Filter by resource type.
    pub resource_type: Option<String>,
    /// Start time.
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    /// End time.
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Limit results.
    pub limit: Option<usize>,
    /// Offset.
    pub offset: Option<usize>,
}

impl AuditQuery {
    /// Creates a new query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by user.
    #[must_use]
    pub fn for_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Filters by tenant.
    #[must_use]
    pub fn for_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Filters by event type.
    #[must_use]
    pub fn of_type(mut self, event_type: AuditEventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Filters by decision.
    #[must_use]
    pub fn with_decision(mut self, decision: AuditDecision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Filters by time range.
    #[must_use]
    pub fn in_time_range(
        mut self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Sets pagination.
    #[must_use]
    pub fn paginate(mut self, limit: usize, offset: usize) -> Self {
        self.limit = Some(limit);
        self.offset = Some(offset);
        self
    }

    /// Matches an event against this query.
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(ref user_id) = self.user_id {
            if &event.user_id != user_id {
                return false;
            }
        }

        if let Some(ref tenant_id) = self.tenant_id {
            if event.tenant_id.as_ref() != Some(tenant_id) {
                return false;
            }
        }

        if let Some(event_type) = self.event_type {
            if event.event_type != event_type {
                return false;
            }
        }

        if let Some(decision) = self.decision {
            if event.decision != decision {
                return false;
            }
        }

        if let Some(ref action) = self.action {
            if &event.action != action {
                return false;
            }
        }

        if let Some(ref resource_type) = self.resource_type {
            if &event.resource_type != resource_type {
                return false;
            }
        }

        if let Some(start) = self.start_time {
            if event.timestamp < start {
                return false;
            }
        }

        if let Some(end) = self.end_time {
            if event.timestamp > end {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceId;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(AuditEventType::Authorization, "user123")
            .with_client_ip("192.168.1.1")
            .with_request_id("req-123");

        assert_eq!(event.user_id, "user123");
        assert_eq!(event.client_ip, Some("192.168.1.1".to_string()));
        assert_eq!(event.request_id, Some("req-123".to_string()));
    }

    #[test]
    fn test_in_memory_sink() {
        let sink = InMemoryAuditSink::new(100);

        let event = AuditEvent::new(AuditEventType::Authorization, "user123");
        sink.record(&event);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_id, "user123");
    }

    #[test]
    fn test_in_memory_sink_limit() {
        let sink = InMemoryAuditSink::new(5);

        for i in 0..10 {
            let event = AuditEvent::new(AuditEventType::Authorization, format!("user{}", i));
            sink.record(&event);
        }

        let events = sink.events();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].user_id, "user5"); // First 5 were trimmed
    }

    #[test]
    fn test_audit_query() {
        let query = AuditQuery::new()
            .for_user("user123")
            .with_decision(AuditDecision::Denied);

        let event1 = AuditEvent::new(AuditEventType::Authorization, "user123");
        let mut event1 = event1;
        event1.decision = AuditDecision::Denied;

        let event2 = AuditEvent::new(AuditEventType::Authorization, "user456");

        assert!(query.matches(&event1));
        assert!(!query.matches(&event2));
    }

    #[test]
    fn test_access_audit_service() {
        let mut audit = AccessAudit::new();
        audit.add_sink(Arc::new(InMemoryAuditSink::new(100)));

        let auth = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["admin".to_string()],
            permissions: Vec::new(),
            tenant_id: None,
            metadata: HashMap::new(),
            claims: None,
        };

        let request = AuthRequest::new("read", ResourceId::new(crate::ResourceType::Dataset));
        let response = AuthResponse::allow();

        audit.record_authorization(&auth, &request, &response);
    }
}
