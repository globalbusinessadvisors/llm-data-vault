//! Access control error types.

use thiserror::Error;

/// Access control result type.
pub type AccessResult<T> = Result<T, AccessError>;

/// Access control errors.
#[derive(Error, Debug)]
pub enum AccessError {
    /// Access denied.
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Unauthorized (not authenticated).
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden (authenticated but not authorized).
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Invalid token.
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Token expired.
    #[error("Token expired")]
    TokenExpired,

    /// Role not found.
    #[error("Role not found: {0}")]
    RoleNotFound(String),

    /// Permission not found.
    #[error("Permission not found: {0}")]
    PermissionNotFound(String),

    /// Policy not found.
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    /// Invalid policy.
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    /// Policy evaluation error.
    #[error("Policy evaluation error: {0}")]
    PolicyEvaluation(String),

    /// Resource not found.
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    /// Invalid attribute.
    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AccessError {
    /// Returns the error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::AccessDenied(_) => "ACCESS_DENIED",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::InvalidToken(_) => "INVALID_TOKEN",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::RoleNotFound(_) => "ROLE_NOT_FOUND",
            Self::PermissionNotFound(_) => "PERMISSION_NOT_FOUND",
            Self::PolicyNotFound(_) => "POLICY_NOT_FOUND",
            Self::InvalidPolicy(_) => "INVALID_POLICY",
            Self::PolicyEvaluation(_) => "POLICY_EVALUATION_ERROR",
            Self::ResourceNotFound(_) => "RESOURCE_NOT_FOUND",
            Self::InvalidAttribute(_) => "INVALID_ATTRIBUTE",
            Self::Configuration(_) => "CONFIG_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// Returns the HTTP status code.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::AccessDenied(_) | Self::Forbidden(_) => 403,
            Self::Unauthorized(_) | Self::InvalidToken(_) | Self::TokenExpired => 401,
            Self::RoleNotFound(_) | Self::PermissionNotFound(_) | Self::PolicyNotFound(_) | Self::ResourceNotFound(_) => 404,
            Self::InvalidPolicy(_) | Self::InvalidAttribute(_) | Self::Configuration(_) => 400,
            Self::PolicyEvaluation(_) | Self::Internal(_) => 500,
        }
    }
}
