//! Authentication and authorization models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::PaginatedList;

/// A user in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier.
    pub id: Uuid,

    /// Username.
    pub username: String,

    /// Email address.
    pub email: String,

    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// User roles.
    pub roles: Vec<String>,

    /// Whether the user is active.
    pub active: bool,

    /// When the user was created.
    pub created_at: DateTime<Utc>,

    /// When the user last logged in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Token response from authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Access token.
    pub access_token: String,

    /// Token type (usually "Bearer").
    pub token_type: String,

    /// Expiration time in seconds.
    pub expires_in: u64,

    /// Refresh token (if enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Token scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Login credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Username or email.
    pub username: String,

    /// Password.
    pub password: String,

    /// MFA code (if required).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
}

impl LoginRequest {
    /// Creates a new login request.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            mfa_code: None,
        }
    }

    /// Adds MFA code.
    #[must_use]
    pub fn with_mfa(mut self, code: impl Into<String>) -> Self {
        self.mfa_code = Some(code.into());
        self
    }
}

/// Refresh token request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    /// Refresh token.
    pub refresh_token: String,
}

/// An API key for programmatic access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier.
    pub id: Uuid,

    /// Human-readable name.
    pub name: String,

    /// Key prefix for identification.
    pub prefix: String,

    /// Permissions granted to this key.
    pub permissions: Vec<String>,

    /// Rate limit (requests per minute).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<u32>,

    /// Allowed IP addresses.
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// Whether the key is active.
    pub active: bool,

    /// When the key was created.
    pub created_at: DateTime<Utc>,

    /// When the key was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// When the key expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to create an API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCreate {
    /// Human-readable name.
    pub name: String,

    /// Permissions to grant.
    pub permissions: Vec<String>,

    /// Rate limit (requests per minute).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<u32>,

    /// Allowed IP addresses.
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// Expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ApiKeyCreate {
    /// Creates a new API key request.
    #[must_use]
    pub fn new(name: impl Into<String>, permissions: Vec<String>) -> Self {
        Self {
            name: name.into(),
            permissions,
            rate_limit: None,
            allowed_ips: Vec::new(),
            expires_at: None,
        }
    }

    /// Sets rate limit.
    #[must_use]
    pub fn with_rate_limit(mut self, limit: u32) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Sets allowed IPs.
    #[must_use]
    pub fn with_allowed_ips(mut self, ips: Vec<String>) -> Self {
        self.allowed_ips = ips;
        self
    }

    /// Sets expiration time.
    #[must_use]
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// Response when creating an API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCreateResponse {
    /// Created API key metadata.
    pub api_key: ApiKey,

    /// The secret key (only shown once).
    pub secret: String,
}

/// Paginated list of API keys.
pub type ApiKeyList = PaginatedList<ApiKey>;

/// Available permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Permission identifier.
    pub id: String,

    /// Human-readable name.
    pub name: String,

    /// Description.
    pub description: String,

    /// Resource type this permission applies to.
    pub resource: String,
}

/// Role definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role identifier.
    pub id: String,

    /// Human-readable name.
    pub name: String,

    /// Description.
    pub description: String,

    /// Permissions included in this role.
    pub permissions: Vec<String>,

    /// Whether this is a built-in role.
    pub builtin: bool,
}

/// Current user's session info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// User information.
    pub user: User,

    /// Current session ID.
    pub session_id: String,

    /// Session expiration.
    pub expires_at: DateTime<Utc>,

    /// Effective permissions.
    pub permissions: Vec<String>,
}
