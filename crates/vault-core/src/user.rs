//! User types and authentication.

use crate::{RoleId, TenantId, UserId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A user in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user identifier.
    pub id: UserId,

    /// Tenant this user belongs to.
    pub tenant_id: TenantId,

    /// Username (unique within tenant).
    pub username: String,

    /// Email address.
    pub email: String,

    /// Display name.
    pub display_name: Option<String>,

    /// User status.
    pub status: UserStatus,

    /// Assigned roles.
    pub roles: Vec<RoleId>,

    /// Direct permissions (in addition to role permissions).
    pub direct_permissions: HashSet<Permission>,

    /// User preferences.
    pub preferences: UserPreferences,

    /// Last login time.
    pub last_login: Option<DateTime<Utc>>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Creates a new user builder.
    #[must_use]
    pub fn builder() -> UserBuilder {
        UserBuilder::default()
    }

    /// Returns true if the user is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active)
    }

    /// Returns the display name or username.
    #[must_use]
    pub fn display_name_or_username(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.username)
    }
}

/// Builder for users.
#[derive(Debug, Default)]
pub struct UserBuilder {
    tenant_id: Option<TenantId>,
    username: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
    roles: Vec<RoleId>,
    direct_permissions: HashSet<Permission>,
}

impl UserBuilder {
    /// Sets the tenant ID.
    #[must_use]
    pub fn tenant_id(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Sets the username.
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Sets the email.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Sets the display name.
    #[must_use]
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Adds a role.
    #[must_use]
    pub fn role(mut self, role_id: RoleId) -> Self {
        self.roles.push(role_id);
        self
    }

    /// Adds a direct permission.
    #[must_use]
    pub fn permission(mut self, permission: Permission) -> Self {
        self.direct_permissions.insert(permission);
        self
    }

    /// Builds the user.
    #[must_use]
    pub fn build(self) -> User {
        let now = Utc::now();
        User {
            id: UserId::new(),
            tenant_id: self.tenant_id.expect("tenant_id is required"),
            username: self.username.expect("username is required"),
            email: self.email.expect("email is required"),
            display_name: self.display_name,
            status: UserStatus::Active,
            roles: self.roles,
            direct_permissions: self.direct_permissions,
            preferences: UserPreferences::default(),
            last_login: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// User status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    /// User is active.
    Active,
    /// User is inactive/disabled.
    Inactive,
    /// User is pending activation.
    Pending,
    /// User is locked out.
    Locked,
}

impl Default for UserStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// User preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserPreferences {
    /// Preferred timezone.
    pub timezone: Option<String>,
    /// Preferred language.
    pub language: Option<String>,
    /// UI theme.
    pub theme: Option<String>,
    /// Notification settings.
    pub notifications: NotificationPreferences,
}

/// Notification preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationPreferences {
    /// Email notifications enabled.
    pub email_enabled: bool,
    /// Events to notify about.
    pub notify_events: Vec<String>,
}

/// A permission in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    /// Resource type (e.g., "dataset", "user", "*").
    pub resource: String,
    /// Action (e.g., "read", "write", "delete", "*").
    pub action: String,
    /// Optional scope (e.g., specific dataset ID, "own", "*").
    pub scope: Option<String>,
}

impl Permission {
    /// Creates a new permission.
    #[must_use]
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            scope: None,
        }
    }

    /// Creates a new permission with scope.
    #[must_use]
    pub fn with_scope(
        resource: impl Into<String>,
        action: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            scope: Some(scope.into()),
        }
    }

    /// Creates a wildcard permission for a resource.
    #[must_use]
    pub fn wildcard(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: "*".to_string(),
            scope: None,
        }
    }

    /// Creates a super admin permission (all resources, all actions).
    #[must_use]
    pub fn super_admin() -> Self {
        Self {
            resource: "*".to_string(),
            action: "*".to_string(),
            scope: None,
        }
    }

    /// Checks if this permission implies another permission.
    #[must_use]
    pub fn implies(&self, other: &Permission) -> bool {
        // Check resource
        let resource_match = self.resource == "*" || self.resource == other.resource;

        // Check action
        let action_match = self.action == "*" || self.action == other.action;

        // Check scope
        let scope_match = match (&self.scope, &other.scope) {
            (None, _) => true,                          // No scope means all scopes
            (Some(s), _) if s == "*" => true,           // Wildcard scope
            (Some(s1), Some(s2)) => s1 == s2,           // Exact match
            (Some(_), None) => false,                   // Scoped doesn't imply unscoped
        };

        resource_match && action_match && scope_match
    }

    /// Converts to permission string (e.g., "dataset:read:own").
    #[must_use]
    pub fn to_string_notation(&self) -> String {
        match &self.scope {
            Some(scope) => format!("{}:{}:{}", self.resource, self.action, scope),
            None => format!("{}:{}", self.resource, self.action),
        }
    }

    /// Parses from permission string.
    #[must_use]
    pub fn from_string_notation(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.len() {
            2 => Some(Self::new(parts[0], parts[1])),
            3 => Some(Self::with_scope(parts[0], parts[1], parts[2])),
            _ => None,
        }
    }
}

/// Common permissions.
pub mod permissions {
    use super::Permission;

    /// Read datasets.
    pub fn dataset_read() -> Permission {
        Permission::new("dataset", "read")
    }

    /// Write datasets.
    pub fn dataset_write() -> Permission {
        Permission::new("dataset", "write")
    }

    /// Delete datasets.
    pub fn dataset_delete() -> Permission {
        Permission::new("dataset", "delete")
    }

    /// Read own datasets.
    pub fn dataset_read_own() -> Permission {
        Permission::with_scope("dataset", "read", "own")
    }

    /// Write own datasets.
    pub fn dataset_write_own() -> Permission {
        Permission::with_scope("dataset", "write", "own")
    }

    /// Manage users.
    pub fn user_manage() -> Permission {
        Permission::wildcard("user")
    }

    /// View audit logs.
    pub fn audit_read() -> Permission {
        Permission::new("audit", "read")
    }

    /// Admin permission.
    pub fn admin() -> Permission {
        Permission::super_admin()
    }
}

/// An API key for programmatic access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// API key ID.
    pub id: String,
    /// User this key belongs to.
    pub user_id: UserId,
    /// Key name.
    pub name: String,
    /// Key prefix (first 8 chars, for identification).
    pub prefix: String,
    /// Hashed key (for verification).
    #[serde(skip_serializing)]
    pub key_hash: String,
    /// Permissions for this key.
    pub permissions: HashSet<Permission>,
    /// Expiration time (if any).
    pub expires_at: Option<DateTime<Utc>>,
    /// Last used time.
    pub last_used: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl ApiKey {
    /// Checks if the key is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| exp < Utc::now())
    }
}

/// Session information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID.
    pub id: String,
    /// User ID.
    pub user_id: UserId,
    /// Session token hash.
    #[serde(skip_serializing)]
    pub token_hash: String,
    /// IP address.
    pub ip_address: Option<String>,
    /// User agent.
    pub user_agent: Option<String>,
    /// Expiration time.
    pub expires_at: DateTime<Utc>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl Session {
    /// Checks if the session is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_builder() {
        let tenant_id = TenantId::new();
        let user = User::builder()
            .tenant_id(tenant_id)
            .username("testuser")
            .email("test@example.com")
            .display_name("Test User")
            .build();

        assert_eq!(user.username, "testuser");
        assert!(user.is_active());
    }

    #[test]
    fn test_permission_implies() {
        let admin = Permission::super_admin();
        let read = Permission::new("dataset", "read");

        assert!(admin.implies(&read));
        assert!(!read.implies(&admin));

        let wildcard = Permission::wildcard("dataset");
        assert!(wildcard.implies(&read));
        assert!(wildcard.implies(&Permission::new("dataset", "delete")));
    }

    #[test]
    fn test_permission_string_notation() {
        let perm = Permission::with_scope("dataset", "read", "own");
        assert_eq!(perm.to_string_notation(), "dataset:read:own");

        let parsed = Permission::from_string_notation("dataset:write").unwrap();
        assert_eq!(parsed.resource, "dataset");
        assert_eq!(parsed.action, "write");
    }
}
