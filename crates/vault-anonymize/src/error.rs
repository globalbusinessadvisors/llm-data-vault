//! Anonymization error types.

use thiserror::Error;

/// Anonymization result type.
pub type AnonymizeResult<T> = Result<T, AnonymizeError>;

/// Anonymization errors.
#[derive(Error, Debug)]
pub enum AnonymizeError {
    /// Detection failed.
    #[error("PII detection failed: {0}")]
    DetectionFailed(String),

    /// Invalid pattern.
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),

    /// Pattern compilation error.
    #[error("Pattern compilation error: {0}")]
    PatternCompilation(String),

    /// Anonymization strategy error.
    #[error("Anonymization strategy error: {0}")]
    StrategyError(String),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Unsupported PII type.
    #[error("Unsupported PII type: {0}")]
    UnsupportedPiiType(String),

    /// Encryption error.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error.
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Token mapping error.
    #[error("Token mapping error: {0}")]
    TokenMapping(String),

    /// Context error.
    #[error("Context error: {0}")]
    Context(String),

    /// Validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl AnonymizeError {
    /// Returns the error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DetectionFailed(_) => "ANON_DETECTION_FAILED",
            Self::InvalidPattern(_) => "ANON_INVALID_PATTERN",
            Self::PatternCompilation(_) => "ANON_PATTERN_COMPILATION",
            Self::StrategyError(_) => "ANON_STRATEGY_ERROR",
            Self::InvalidConfig(_) => "ANON_INVALID_CONFIG",
            Self::UnsupportedPiiType(_) => "ANON_UNSUPPORTED_TYPE",
            Self::Encryption(_) => "ANON_ENCRYPTION_ERROR",
            Self::Decryption(_) => "ANON_DECRYPTION_ERROR",
            Self::TokenMapping(_) => "ANON_TOKEN_MAPPING",
            Self::Context(_) => "ANON_CONTEXT_ERROR",
            Self::Validation(_) => "ANON_VALIDATION_ERROR",
            Self::Internal(_) => "ANON_INTERNAL_ERROR",
        }
    }

    /// Returns true if the error is recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::DetectionFailed(_) | Self::Context(_) | Self::TokenMapping(_)
        )
    }
}

impl From<regex::Error> for AnonymizeError {
    fn from(e: regex::Error) -> Self {
        Self::PatternCompilation(e.to_string())
    }
}
