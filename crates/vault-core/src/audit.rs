//! Audit logging types.

use crate::{AuditEventId, RequestId, TenantId, UserId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// An audit event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: AuditEventId,

    /// Tenant where the event occurred.
    pub tenant_id: TenantId,

    /// Type of event.
    pub event_type: AuditEventType,

    /// Event category.
    pub category: AuditCategory,

    /// Information about the actor.
    pub actor: ActorInfo,

    /// Information about the resource.
    pub resource: ResourceInfo,

    /// Action performed.
    pub action: String,

    /// Result of the action.
    pub result: ActionResult,

    /// Request context.
    pub request: RequestContext,

    /// Additional event data.
    pub data: HashMap<String, serde_json::Value>,

    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
}

impl AuditEvent {
    /// Creates a new audit event builder.
    #[must_use]
    pub fn builder() -> AuditEventBuilder {
        AuditEventBuilder::default()
    }
}

/// Builder for audit events.
#[derive(Debug, Default)]
pub struct AuditEventBuilder {
    tenant_id: Option<TenantId>,
    event_type: Option<AuditEventType>,
    category: Option<AuditCategory>,
    actor: Option<ActorInfo>,
    resource: Option<ResourceInfo>,
    action: Option<String>,
    result: Option<ActionResult>,
    request: Option<RequestContext>,
    data: HashMap<String, serde_json::Value>,
}

impl AuditEventBuilder {
    /// Sets the tenant ID.
    #[must_use]
    pub fn tenant_id(mut self, id: TenantId) -> Self {
        self.tenant_id = Some(id);
        self
    }

    /// Sets the event type.
    #[must_use]
    pub fn event_type(mut self, event_type: AuditEventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Sets the category.
    #[must_use]
    pub fn category(mut self, category: AuditCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Sets the actor.
    #[must_use]
    pub fn actor(mut self, actor: ActorInfo) -> Self {
        self.actor = Some(actor);
        self
    }

    /// Sets the resource.
    #[must_use]
    pub fn resource(mut self, resource: ResourceInfo) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Sets the action.
    #[must_use]
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Sets the result.
    #[must_use]
    pub fn result(mut self, result: ActionResult) -> Self {
        self.result = Some(result);
        self
    }

    /// Sets the request context.
    #[must_use]
    pub fn request(mut self, request: RequestContext) -> Self {
        self.request = Some(request);
        self
    }

    /// Adds data.
    #[must_use]
    pub fn data(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.data.insert(key.into(), value);
        self
    }

    /// Builds the audit event.
    #[must_use]
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: AuditEventId::new(),
            tenant_id: self.tenant_id.expect("tenant_id is required"),
            event_type: self.event_type.expect("event_type is required"),
            category: self.category.unwrap_or(AuditCategory::DataAccess),
            actor: self.actor.expect("actor is required"),
            resource: self.resource.expect("resource is required"),
            action: self.action.expect("action is required"),
            result: self.result.unwrap_or(ActionResult::Success),
            request: self.request.unwrap_or_default(),
            data: self.data,
            timestamp: Utc::now(),
        }
    }
}

/// Type of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Data events
    /// Dataset created.
    DatasetCreated,
    /// Dataset updated.
    DatasetUpdated,
    /// Dataset deleted.
    DatasetDeleted,
    /// Records added.
    RecordsAdded,
    /// Records queried.
    RecordsQueried,
    /// Records deleted.
    RecordsDeleted,
    /// Data exported.
    DataExported,

    // Security events
    /// Anonymization applied.
    AnonymizationApplied,
    /// PII detected.
    PiiDetected,
    /// Encryption key rotated.
    KeyRotated,

    // Access events
    /// Access granted.
    AccessGranted,
    /// Access denied.
    AccessDenied,
    /// Login successful.
    LoginSuccess,
    /// Login failed.
    LoginFailed,
    /// Logout.
    Logout,

    // Policy events
    /// Policy violated.
    PolicyViolation,
    /// Policy created.
    PolicyCreated,
    /// Policy updated.
    PolicyUpdated,

    // Admin events
    /// Configuration changed.
    ConfigurationChanged,
    /// User created.
    UserCreated,
    /// User updated.
    UserUpdated,
    /// User deleted.
    UserDeleted,
    /// Role assigned.
    RoleAssigned,
    /// Role revoked.
    RoleRevoked,
}

impl AuditEventType {
    /// Returns the category for this event type.
    #[must_use]
    pub const fn category(&self) -> AuditCategory {
        match self {
            Self::DatasetCreated
            | Self::DatasetUpdated
            | Self::DatasetDeleted
            | Self::RecordsAdded
            | Self::RecordsQueried
            | Self::RecordsDeleted
            | Self::DataExported => AuditCategory::DataAccess,

            Self::AnonymizationApplied | Self::PiiDetected | Self::KeyRotated => {
                AuditCategory::Security
            }

            Self::AccessGranted
            | Self::AccessDenied
            | Self::LoginSuccess
            | Self::LoginFailed
            | Self::Logout => AuditCategory::Authentication,

            Self::PolicyViolation | Self::PolicyCreated | Self::PolicyUpdated => {
                AuditCategory::Policy
            }

            Self::ConfigurationChanged
            | Self::UserCreated
            | Self::UserUpdated
            | Self::UserDeleted
            | Self::RoleAssigned
            | Self::RoleRevoked => AuditCategory::Administration,
        }
    }
}

/// Category of audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Data access events.
    DataAccess,
    /// Security events.
    Security,
    /// Authentication events.
    Authentication,
    /// Policy events.
    Policy,
    /// Administrative events.
    Administration,
}

/// Information about the actor performing an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorInfo {
    /// User ID (if authenticated user).
    pub user_id: Option<UserId>,
    /// Service account name (if service).
    pub service_account: Option<String>,
    /// API key ID (if using API key).
    pub api_key_id: Option<String>,
    /// IP address.
    pub ip_address: Option<IpAddr>,
    /// User agent string.
    pub user_agent: Option<String>,
    /// Authentication method used.
    pub auth_method: Option<AuthMethod>,
}

impl ActorInfo {
    /// Creates actor info for a user.
    #[must_use]
    pub fn user(user_id: UserId) -> Self {
        Self {
            user_id: Some(user_id),
            service_account: None,
            api_key_id: None,
            ip_address: None,
            user_agent: None,
            auth_method: None,
        }
    }

    /// Creates actor info for a service.
    #[must_use]
    pub fn service(name: impl Into<String>) -> Self {
        Self {
            user_id: None,
            service_account: Some(name.into()),
            api_key_id: None,
            ip_address: None,
            user_agent: None,
            auth_method: None,
        }
    }

    /// Creates actor info for anonymous access.
    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            user_id: None,
            service_account: None,
            api_key_id: None,
            ip_address: None,
            user_agent: None,
            auth_method: None,
        }
    }

    /// Sets the IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Sets the user agent.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Sets the auth method.
    #[must_use]
    pub fn with_auth_method(mut self, method: AuthMethod) -> Self {
        self.auth_method = Some(method);
        self
    }
}

/// Authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// JWT token.
    Jwt,
    /// API key.
    ApiKey,
    /// OAuth2.
    OAuth2,
    /// SAML.
    Saml,
    /// mTLS.
    MTls,
    /// Session cookie.
    Session,
}

/// Information about the resource being accessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Resource type (e.g., "dataset", "user").
    pub resource_type: String,
    /// Resource ID.
    pub resource_id: String,
    /// Resource name (for readability).
    pub resource_name: Option<String>,
    /// Parent resource (if applicable).
    pub parent: Option<Box<ResourceInfo>>,
}

impl ResourceInfo {
    /// Creates new resource info.
    #[must_use]
    pub fn new(resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            resource_name: None,
            parent: None,
        }
    }

    /// Sets the resource name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.resource_name = Some(name.into());
        self
    }

    /// Sets the parent resource.
    #[must_use]
    pub fn with_parent(mut self, parent: ResourceInfo) -> Self {
        self.parent = Some(Box::new(parent));
        self
    }
}

/// Result of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResult {
    /// Action succeeded.
    Success,
    /// Action failed.
    Failure,
    /// Action partially succeeded.
    Partial,
    /// Action was denied.
    Denied,
}

impl Default for ActionResult {
    fn default() -> Self {
        Self::Success
    }
}

/// Request context for audit events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    /// Request ID.
    pub request_id: Option<RequestId>,
    /// HTTP method.
    pub method: Option<String>,
    /// Request path.
    pub path: Option<String>,
    /// Query parameters (sanitized).
    pub query_params: Option<HashMap<String, String>>,
    /// Request duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// HTTP status code.
    pub status_code: Option<u16>,
}

impl RequestContext {
    /// Creates a new request context.
    #[must_use]
    pub fn new(request_id: RequestId) -> Self {
        Self {
            request_id: Some(request_id),
            ..Default::default()
        }
    }

    /// Sets the HTTP method.
    #[must_use]
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets the request path.
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the duration.
    #[must_use]
    pub fn duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Sets the status code.
    #[must_use]
    pub fn status_code(mut self, code: u16) -> Self {
        self.status_code = Some(code);
        self
    }
}

/// Query parameters for searching audit events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Start time.
    pub start_time: Option<DateTime<Utc>>,
    /// End time.
    pub end_time: Option<DateTime<Utc>>,
    /// Event types to include.
    pub event_types: Option<Vec<AuditEventType>>,
    /// Categories to include.
    pub categories: Option<Vec<AuditCategory>>,
    /// User ID filter.
    pub user_id: Option<UserId>,
    /// Resource type filter.
    pub resource_type: Option<String>,
    /// Resource ID filter.
    pub resource_id: Option<String>,
    /// Result filter.
    pub result: Option<ActionResult>,
    /// Pagination cursor.
    pub cursor: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_builder() {
        let tenant_id = TenantId::new();
        let user_id = UserId::new();

        let event = AuditEvent::builder()
            .tenant_id(tenant_id)
            .event_type(AuditEventType::DatasetCreated)
            .actor(ActorInfo::user(user_id))
            .resource(ResourceInfo::new("dataset", "ds-123").with_name("Test Dataset"))
            .action("create")
            .result(ActionResult::Success)
            .data("record_count", serde_json::json!(100))
            .build();

        assert_eq!(event.event_type, AuditEventType::DatasetCreated);
        assert_eq!(event.result, ActionResult::Success);
    }

    #[test]
    fn test_event_type_category() {
        assert_eq!(
            AuditEventType::DatasetCreated.category(),
            AuditCategory::DataAccess
        );
        assert_eq!(
            AuditEventType::LoginFailed.category(),
            AuditCategory::Authentication
        );
    }
}
