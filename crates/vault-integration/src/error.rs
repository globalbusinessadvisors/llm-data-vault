//! Integration error types.

use thiserror::Error;

/// Integration result type.
pub type IntegrationResult<T> = Result<T, IntegrationError>;

/// Integration errors.
#[derive(Error, Debug)]
pub enum IntegrationError {
    /// Webhook delivery failed.
    #[error("Webhook delivery failed: {0}")]
    DeliveryFailed(String),

    /// Webhook not found.
    #[error("Webhook not found: {0}")]
    WebhookNotFound(String),

    /// Subscription not found.
    #[error("Subscription not found: {0}")]
    SubscriptionNotFound(String),

    /// Invalid webhook URL.
    #[error("Invalid webhook URL: {0}")]
    InvalidUrl(String),

    /// Invalid event type.
    #[error("Invalid event type: {0}")]
    InvalidEventType(String),

    /// Handler error.
    #[error("Handler error: {0}")]
    HandlerError(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// HTTP error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// Timeout error.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Rate limited.
    #[error("Rate limited: {0}")]
    RateLimited(String),

    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Channel closed.
    #[error("Channel closed")]
    ChannelClosed,

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntegrationError {
    /// Returns the error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::DeliveryFailed(_) => "DELIVERY_FAILED",
            Self::WebhookNotFound(_) => "WEBHOOK_NOT_FOUND",
            Self::SubscriptionNotFound(_) => "SUBSCRIPTION_NOT_FOUND",
            Self::InvalidUrl(_) => "INVALID_URL",
            Self::InvalidEventType(_) => "INVALID_EVENT_TYPE",
            Self::HandlerError(_) => "HANDLER_ERROR",
            Self::Serialization(_) => "SERIALIZATION_ERROR",
            Self::Http(_) => "HTTP_ERROR",
            Self::Timeout(_) => "TIMEOUT",
            Self::RateLimited(_) => "RATE_LIMITED",
            Self::SignatureInvalid(_) => "SIGNATURE_INVALID",
            Self::ChannelClosed => "CHANNEL_CLOSED",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// Returns true if the error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::DeliveryFailed(_)
                | Self::Http(_)
                | Self::Timeout(_)
                | Self::RateLimited(_)
        )
    }
}

impl From<serde_json::Error> for IntegrationError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<reqwest::Error> for IntegrationError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            Self::Timeout(e.to_string())
        } else {
            Self::Http(e.to_string())
        }
    }
}

impl From<url::ParseError> for IntegrationError {
    fn from(e: url::ParseError) -> Self {
        Self::InvalidUrl(e.to_string())
    }
}
