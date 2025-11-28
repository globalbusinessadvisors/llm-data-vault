//! Access control (RBAC/ABAC) for LLM Data Vault.
//!
//! This crate provides comprehensive access control with:
//! - Role-Based Access Control (RBAC)
//! - Attribute-Based Access Control (ABAC)
//! - Policy-based authorization
//! - JWT token management

pub mod error;
pub mod rbac;
pub mod abac;
pub mod policy;
pub mod token;
pub mod authorizer;
pub mod audit;

pub use error::{AccessError, AccessResult};
pub use rbac::{Role, Permission, RbacManager};
pub use abac::{Attribute, AttributeValue, AbacPolicy, AbacEngine, AbacContext};
pub use policy::{Policy, PolicyEngine, PolicyDecision, Effect};
pub use token::{TokenManager, TokenClaims, TokenConfig};
pub use authorizer::{Authorizer, AuthContext, AuthRequest, AuthResponse, DecisionSource};
pub use audit::{AccessAudit, AuditEvent};

/// Common resource types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// Dataset resource.
    Dataset,
    /// Record resource.
    Record,
    /// Schema resource.
    Schema,
    /// Key resource.
    Key,
    /// User resource.
    User,
    /// Role resource.
    Role,
    /// Policy resource.
    Policy,
    /// Audit log resource.
    AuditLog,
    /// System configuration.
    System,
    /// Custom resource.
    Custom(String),
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dataset => write!(f, "dataset"),
            Self::Record => write!(f, "record"),
            Self::Schema => write!(f, "schema"),
            Self::Key => write!(f, "key"),
            Self::User => write!(f, "user"),
            Self::Role => write!(f, "role"),
            Self::Policy => write!(f, "policy"),
            Self::AuditLog => write!(f, "audit_log"),
            Self::System => write!(f, "system"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Common actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// Create resource.
    Create,
    /// Read resource.
    Read,
    /// Update resource.
    Update,
    /// Delete resource.
    Delete,
    /// List resources.
    List,
    /// Execute operation.
    Execute,
    /// Admin operation.
    Admin,
    /// Custom action.
    Custom(String),
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Read => write!(f, "read"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
            Self::List => write!(f, "list"),
            Self::Execute => write!(f, "execute"),
            Self::Admin => write!(f, "admin"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Resource identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceId {
    /// Resource type.
    pub resource_type: ResourceType,
    /// Resource ID (optional for type-level permissions).
    pub id: Option<String>,
    /// Tenant ID.
    pub tenant_id: Option<String>,
}

impl ResourceId {
    /// Creates a new resource ID.
    pub fn new(resource_type: ResourceType) -> Self {
        Self {
            resource_type,
            id: None,
            tenant_id: None,
        }
    }

    /// Creates with specific ID.
    pub fn with_id(resource_type: ResourceType, id: impl Into<String>) -> Self {
        Self {
            resource_type,
            id: Some(id.into()),
            tenant_id: None,
        }
    }

    /// Sets tenant ID.
    #[must_use]
    pub fn in_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Returns the resource string representation.
    #[must_use]
    pub fn to_resource_string(&self) -> String {
        let mut s = self.resource_type.to_string();
        if let Some(ref id) = self.id {
            s.push(':');
            s.push_str(id);
        }
        if let Some(ref tenant) = self.tenant_id {
            s = format!("{}@{}", s, tenant);
        }
        s
    }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_resource_string())
    }
}
