//! Security error types.

use std::fmt;

/// Security error type.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    /// Configuration error.
    #[error("Configuration error: {message}")]
    Configuration {
        /// Error message.
        message: String,
        /// Field that caused the error.
        field: Option<String>,
    },

    /// Secret management error.
    #[error("Secret error: {0}")]
    Secret(String),

    /// Encryption error.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error.
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Signature error.
    #[error("Signature error: {0}")]
    Signature(String),

    /// Invalid signature.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Signature expired.
    #[error("Signature expired: signed at {signed_at}, expired after {valid_for_secs}s")]
    SignatureExpired {
        /// When the request was signed.
        signed_at: chrono::DateTime<chrono::Utc>,
        /// How long the signature was valid for.
        valid_for_secs: u64,
    },

    /// Replay attack detected.
    #[error("Replay attack detected: nonce {nonce} already used")]
    ReplayAttack {
        /// The nonce that was reused.
        nonce: String,
    },

    /// Session error.
    #[error("Session error: {0}")]
    Session(String),

    /// Session not found.
    #[error("Session not found: {session_id}")]
    SessionNotFound {
        /// The session ID that was not found.
        session_id: String,
    },

    /// Session expired.
    #[error("Session expired: {session_id}")]
    SessionExpired {
        /// The session ID that expired.
        session_id: String,
    },

    /// Input validation error.
    #[error("Validation error: {message}")]
    Validation {
        /// Error message.
        message: String,
        /// Field that failed validation.
        field: Option<String>,
        /// Validation rule that failed.
        rule: Option<String>,
    },

    /// Input sanitization error.
    #[error("Sanitization error: {0}")]
    Sanitization(String),

    /// Threat detected.
    #[error("Threat detected: {threat_type} - {message}")]
    ThreatDetected {
        /// Type of threat.
        threat_type: String,
        /// Threat level.
        level: ThreatLevel,
        /// Threat message.
        message: String,
    },

    /// IP blocked.
    #[error("IP address blocked: {ip}")]
    IpBlocked {
        /// The blocked IP address.
        ip: String,
        /// Reason for blocking.
        reason: Option<String>,
    },

    /// Rate limited.
    #[error("Rate limit exceeded: {limit} requests per {window_secs}s")]
    RateLimited {
        /// The rate limit.
        limit: u32,
        /// The window in seconds.
        window_secs: u64,
        /// When the limit resets.
        reset_at: chrono::DateTime<chrono::Utc>,
    },

    /// Audit error.
    #[error("Audit error: {0}")]
    Audit(String),

    /// Integrity check failed.
    #[error("Integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    /// Access denied.
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Internal error.
    #[error("Internal security error: {0}")]
    Internal(String),
}

/// Threat level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ThreatLevel {
    /// Low threat level - informational.
    Low,
    /// Medium threat level - requires attention.
    Medium,
    /// High threat level - immediate action needed.
    High,
    /// Critical threat level - system at risk.
    Critical,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl SecurityError {
    /// Creates a configuration error.
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
            field: None,
        }
    }

    /// Creates a configuration error with a field.
    pub fn configuration_field(message: impl Into<String>, field: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Creates a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            field: None,
            rule: None,
        }
    }

    /// Creates a validation error with field and rule.
    pub fn validation_field(
        message: impl Into<String>,
        field: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        Self::Validation {
            message: message.into(),
            field: Some(field.into()),
            rule: Some(rule.into()),
        }
    }

    /// Creates a threat detected error.
    pub fn threat(
        threat_type: impl Into<String>,
        level: ThreatLevel,
        message: impl Into<String>,
    ) -> Self {
        Self::ThreatDetected {
            threat_type: threat_type.into(),
            level,
            message: message.into(),
        }
    }

    /// Returns true if this is a critical security error.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::ThreatDetected { level: ThreatLevel::Critical, .. }
            | Self::IntegrityCheckFailed(_)
            | Self::ReplayAttack { .. }
        )
    }

    /// Returns the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> http::StatusCode {
        match self {
            Self::Configuration { .. } => http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Secret(_) | Self::Encryption(_) | Self::Decryption(_) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::Signature(_) | Self::InvalidSignature(_) => http::StatusCode::UNAUTHORIZED,
            Self::SignatureExpired { .. } => http::StatusCode::UNAUTHORIZED,
            Self::ReplayAttack { .. } => http::StatusCode::FORBIDDEN,
            Self::Session(_) | Self::SessionNotFound { .. } | Self::SessionExpired { .. } => {
                http::StatusCode::UNAUTHORIZED
            }
            Self::Validation { .. } | Self::Sanitization(_) => http::StatusCode::BAD_REQUEST,
            Self::ThreatDetected { .. } | Self::IpBlocked { .. } => http::StatusCode::FORBIDDEN,
            Self::RateLimited { .. } => http::StatusCode::TOO_MANY_REQUESTS,
            Self::Audit(_) | Self::IntegrityCheckFailed(_) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::AccessDenied(_) => http::StatusCode::FORBIDDEN,
            Self::Internal(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Result type for security operations.
pub type Result<T> = std::result::Result<T, SecurityError>;

impl From<vault_crypto::CryptoError> for SecurityError {
    fn from(err: vault_crypto::CryptoError) -> Self {
        Self::Encryption(err.to_string())
    }
}
