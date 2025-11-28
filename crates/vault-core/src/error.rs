//! Error types for the LLM Data Vault.
//!
//! This module defines a comprehensive error hierarchy following best practices
//! for Rust error handling.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Result type alias using `VaultError`.
pub type VaultResult<T> = Result<T, VaultError>;

/// Main error type for the LLM Data Vault.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Authentication errors (1000-1999).
    #[error("authentication error: {0}")]
    Authentication(#[from] AuthenticationError),

    /// Authorization errors (2000-2999).
    #[error("authorization error: {0}")]
    Authorization(#[from] AuthorizationError),

    /// Validation errors (3000-3999).
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Data/Resource errors (4000-4999).
    #[error("data error: {0}")]
    Data(#[from] DataError),

    /// Cryptography errors (5000-5999).
    #[error("cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    /// Anonymization errors (6000-6999).
    #[error("anonymization error: {0}")]
    Anonymization(#[from] AnonymizationError),

    /// Storage errors (7000-7999).
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// System errors (9000-9999).
    #[error("system error: {0}")]
    System(#[from] SystemError),
}

impl VaultError {
    /// Returns the error code for this error.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Authentication(e) => e.code(),
            Self::Authorization(e) => e.code(),
            Self::Validation(e) => e.code(),
            Self::Data(e) => e.code(),
            Self::Crypto(e) => e.code(),
            Self::Anonymization(e) => e.code(),
            Self::Storage(e) => e.code(),
            Self::System(e) => e.code(),
        }
    }

    /// Returns the HTTP status code for this error.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::Authentication(_) => 401,
            Self::Authorization(_) => 403,
            Self::Validation(_) => 400,
            Self::Data(e) => e.http_status(),
            Self::Crypto(_) => 500,
            Self::Anonymization(_) => 422,
            Self::Storage(_) => 500,
            Self::System(_) => 500,
        }
    }
}

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthenticationError {
    /// Invalid credentials.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Token expired.
    #[error("token has expired")]
    TokenExpired,

    /// Token invalid.
    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// Missing token.
    #[error("authentication token required")]
    MissingToken,

    /// Invalid API key.
    #[error("invalid API key")]
    InvalidApiKey,

    /// MFA required.
    #[error("multi-factor authentication required")]
    MfaRequired,

    /// Session expired.
    #[error("session has expired")]
    SessionExpired,
}

impl AuthenticationError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidCredentials => ErrorCode::new(1001),
            Self::TokenExpired => ErrorCode::new(1002),
            Self::InvalidToken(_) => ErrorCode::new(1003),
            Self::MissingToken => ErrorCode::new(1004),
            Self::InvalidApiKey => ErrorCode::new(1005),
            Self::MfaRequired => ErrorCode::new(1006),
            Self::SessionExpired => ErrorCode::new(1007),
        }
    }
}

/// Authorization errors.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// Access denied.
    #[error("access denied")]
    AccessDenied,

    /// Insufficient permissions.
    #[error("insufficient permissions: {required}")]
    InsufficientPermissions {
        /// The required permission.
        required: String,
    },

    /// Resource forbidden.
    #[error("access to resource forbidden")]
    ResourceForbidden,

    /// Policy violation.
    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// Role not found.
    #[error("role not found: {0}")]
    RoleNotFound(String),

    /// Circular role inheritance.
    #[error("circular role inheritance detected")]
    CircularInheritance,
}

impl AuthorizationError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::AccessDenied => ErrorCode::new(2001),
            Self::InsufficientPermissions { .. } => ErrorCode::new(2002),
            Self::ResourceForbidden => ErrorCode::new(2003),
            Self::PolicyViolation(_) => ErrorCode::new(2004),
            Self::RoleNotFound(_) => ErrorCode::new(2005),
            Self::CircularInheritance => ErrorCode::new(2006),
        }
    }
}

/// Validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Invalid input.
    #[error("invalid input: {field}: {message}")]
    InvalidInput {
        /// The field that failed validation.
        field: String,
        /// The validation error message.
        message: String,
    },

    /// Schema violation.
    #[error("schema violation: {0}")]
    SchemaViolation(String),

    /// Required field missing.
    #[error("required field missing: {0}")]
    RequiredField(String),

    /// Invalid format.
    #[error("invalid format for {field}: expected {expected}")]
    InvalidFormat {
        /// The field name.
        field: String,
        /// The expected format.
        expected: String,
    },

    /// Value out of range.
    #[error("value out of range for {field}: {message}")]
    OutOfRange {
        /// The field name.
        field: String,
        /// The error message.
        message: String,
    },

    /// Multiple validation errors.
    #[error("multiple validation errors")]
    Multiple(Vec<FieldError>),
}

impl ValidationError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidInput { .. } => ErrorCode::new(3001),
            Self::SchemaViolation(_) => ErrorCode::new(3002),
            Self::RequiredField(_) => ErrorCode::new(3003),
            Self::InvalidFormat { .. } => ErrorCode::new(3004),
            Self::OutOfRange { .. } => ErrorCode::new(3005),
            Self::Multiple(_) => ErrorCode::new(3006),
        }
    }
}

/// A single field validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldError {
    /// The field path.
    pub field: String,
    /// The constraint that was violated.
    pub constraint: String,
    /// Human-readable message.
    pub message: String,
    /// The rejected value (if safe to include).
    pub rejected_value: Option<serde_json::Value>,
}

/// Data/Resource errors.
#[derive(Debug, Error)]
pub enum DataError {
    /// Resource not found.
    #[error("{resource_type} not found: {id}")]
    NotFound {
        /// The type of resource.
        resource_type: String,
        /// The resource ID.
        id: String,
    },

    /// Resource already exists.
    #[error("{resource_type} already exists: {id}")]
    AlreadyExists {
        /// The type of resource.
        resource_type: String,
        /// The resource ID.
        id: String,
    },

    /// Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Integrity error.
    #[error("data integrity error: {0}")]
    IntegrityError(String),

    /// Version mismatch.
    #[error("version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Expected version.
        expected: String,
        /// Actual version.
        actual: String,
    },

    /// Reference error.
    #[error("referenced resource not found: {0}")]
    ReferenceError(String),
}

impl DataError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::NotFound { .. } => ErrorCode::new(4001),
            Self::AlreadyExists { .. } => ErrorCode::new(4002),
            Self::Conflict(_) => ErrorCode::new(4003),
            Self::IntegrityError(_) => ErrorCode::new(4004),
            Self::VersionMismatch { .. } => ErrorCode::new(4005),
            Self::ReferenceError(_) => ErrorCode::new(4006),
        }
    }

    /// Returns the HTTP status code.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::NotFound { .. } => 404,
            Self::AlreadyExists { .. } => 409,
            Self::Conflict(_) => 409,
            Self::IntegrityError(_) => 422,
            Self::VersionMismatch { .. } => 409,
            Self::ReferenceError(_) => 422,
        }
    }
}

/// Cryptography errors.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Key not found.
    #[error("encryption key not found: {0}")]
    KeyNotFound(String),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Invalid key.
    #[error("invalid encryption key: {0}")]
    InvalidKey(String),

    /// KMS error.
    #[error("KMS error: {0}")]
    KmsError(String),

    /// Hash verification failed.
    #[error("hash verification failed")]
    HashVerificationFailed,
}

impl CryptoError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::EncryptionFailed(_) => ErrorCode::new(5001),
            Self::DecryptionFailed(_) => ErrorCode::new(5002),
            Self::KeyNotFound(_) => ErrorCode::new(5003),
            Self::KeyGenerationFailed(_) => ErrorCode::new(5004),
            Self::InvalidKey(_) => ErrorCode::new(5005),
            Self::KmsError(_) => ErrorCode::new(5006),
            Self::HashVerificationFailed => ErrorCode::new(5007),
        }
    }
}

/// Anonymization errors.
#[derive(Debug, Error)]
pub enum AnonymizationError {
    /// PII detection failed.
    #[error("PII detection failed: {0}")]
    DetectionFailed(String),

    /// Tokenization failed.
    #[error("tokenization failed: {0}")]
    TokenizationFailed(String),

    /// Token not found.
    #[error("token not found: {0}")]
    TokenNotFound(String),

    /// Invalid anonymization strategy.
    #[error("invalid anonymization strategy: {0}")]
    InvalidStrategy(String),

    /// Policy not found.
    #[error("anonymization policy not found: {0}")]
    PolicyNotFound(String),

    /// Reversibility error.
    #[error("cannot reverse anonymization: {0}")]
    IrreversibleError(String),
}

impl AnonymizationError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::DetectionFailed(_) => ErrorCode::new(6001),
            Self::TokenizationFailed(_) => ErrorCode::new(6002),
            Self::TokenNotFound(_) => ErrorCode::new(6003),
            Self::InvalidStrategy(_) => ErrorCode::new(6004),
            Self::PolicyNotFound(_) => ErrorCode::new(6005),
            Self::IrreversibleError(_) => ErrorCode::new(6006),
        }
    }
}

/// Storage errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Backend error.
    #[error("storage backend error: {0}")]
    BackendError(String),

    /// Connection error.
    #[error("storage connection error: {0}")]
    ConnectionError(String),

    /// IO error.
    #[error("storage IO error: {0}")]
    IoError(String),

    /// Integrity error.
    #[error("storage integrity error: {0}")]
    IntegrityError(String),

    /// Capacity exceeded.
    #[error("storage capacity exceeded")]
    CapacityExceeded,

    /// Object too large.
    #[error("object too large: {size} bytes (max: {max})")]
    ObjectTooLarge {
        /// The object size.
        size: u64,
        /// Maximum allowed size.
        max: u64,
    },
}

impl StorageError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::BackendError(_) => ErrorCode::new(7001),
            Self::ConnectionError(_) => ErrorCode::new(7002),
            Self::IoError(_) => ErrorCode::new(7003),
            Self::IntegrityError(_) => ErrorCode::new(7004),
            Self::CapacityExceeded => ErrorCode::new(7005),
            Self::ObjectTooLarge { .. } => ErrorCode::new(7006),
        }
    }
}

/// System errors.
#[derive(Debug, Error)]
pub enum SystemError {
    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Service unavailable.
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Timeout.
    #[error("operation timed out")]
    Timeout,

    /// External service error.
    #[error("external service error: {service}: {message}")]
    ExternalService {
        /// Service name.
        service: String,
        /// Error message.
        message: String,
    },
}

impl SystemError {
    /// Returns the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Internal(_) => ErrorCode::new(9001),
            Self::ServiceUnavailable(_) => ErrorCode::new(9002),
            Self::Database(_) => ErrorCode::new(9003),
            Self::Configuration(_) => ErrorCode::new(9004),
            Self::RateLimitExceeded => ErrorCode::new(9005),
            Self::Timeout => ErrorCode::new(9006),
            Self::ExternalService { .. } => ErrorCode::new(9007),
        }
    }
}

/// Error code with numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCode(u16);

impl ErrorCode {
    /// Creates a new error code.
    #[must_use]
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    /// Returns the numeric code.
    #[must_use]
    pub const fn as_u16(&self) -> u16 {
        self.0
    }

    /// Returns the code as a formatted string.
    #[must_use]
    pub fn to_code_string(&self) -> String {
        format!("VAULT_{:04}", self.0)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VAULT_{:04}", self.0)
    }
}

/// API error response (RFC 7807 Problem Details).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    /// URI reference identifying the problem type.
    #[serde(rename = "type")]
    pub error_type: String,

    /// Short, human-readable summary.
    pub title: String,

    /// HTTP status code.
    pub status: u16,

    /// Human-readable explanation.
    pub detail: String,

    /// URI reference for the specific occurrence.
    pub instance: String,

    /// Machine-readable error code.
    pub code: String,

    /// Request ID for tracing.
    pub trace_id: String,

    /// Timestamp of the error.
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Field-level errors (for validation).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldError>,
}

impl ApiErrorResponse {
    /// Creates a new API error response from a vault error.
    #[must_use]
    pub fn from_error(error: &VaultError, trace_id: &str, instance: &str) -> Self {
        Self {
            error_type: format!(
                "https://api.llm-data-vault.com/errors/{}",
                error.code().to_code_string()
            ),
            title: error.to_string(),
            status: error.http_status(),
            detail: error.to_string(),
            instance: instance.to_string(),
            code: error.code().to_code_string(),
            trace_id: trace_id.to_string(),
            timestamp: chrono::Utc::now(),
            errors: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_format() {
        let code = ErrorCode::new(1001);
        assert_eq!(code.to_code_string(), "VAULT_1001");
    }

    #[test]
    fn test_authentication_error() {
        let err = VaultError::Authentication(AuthenticationError::TokenExpired);
        assert_eq!(err.http_status(), 401);
        assert_eq!(err.code().as_u16(), 1002);
    }

    #[test]
    fn test_data_not_found_error() {
        let err = VaultError::Data(DataError::NotFound {
            resource_type: "Dataset".to_string(),
            id: "test-id".to_string(),
        });
        assert_eq!(err.http_status(), 404);
    }
}
