//! Error types for the Vault SDK.
//!
//! This module provides comprehensive error types that map to both
//! API errors and client-side issues.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The main error type for all SDK operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request was malformed or contained invalid data.
    #[error("Bad request: {message}")]
    BadRequest {
        /// Error message describing what was invalid.
        message: String,
        /// Field-level validation errors, if any.
        #[source]
        details: Option<ValidationErrors>,
    },

    /// Authentication failed - invalid or missing credentials.
    #[error("Unauthorized: {message}")]
    Unauthorized {
        /// Error message.
        message: String,
    },

    /// The authenticated user lacks permission for this operation.
    #[error("Forbidden: {message}")]
    Forbidden {
        /// Error message describing missing permissions.
        message: String,
    },

    /// The requested resource was not found.
    #[error("Not found: {resource_type} with id '{resource_id}'")]
    NotFound {
        /// Type of resource (e.g., "dataset", "record").
        resource_type: String,
        /// ID of the resource that was not found.
        resource_id: String,
    },

    /// The request conflicts with existing state.
    #[error("Conflict: {message}")]
    Conflict {
        /// Error message describing the conflict.
        message: String,
    },

    /// The request payload was too large.
    #[error("Payload too large: maximum size is {max_size} bytes")]
    PayloadTooLarge {
        /// Maximum allowed size in bytes.
        max_size: u64,
    },

    /// Too many requests - rate limited.
    #[error("Rate limited: retry after {retry_after_secs} seconds")]
    RateLimited {
        /// Number of seconds to wait before retrying.
        retry_after_secs: u64,
    },

    /// Server-side error occurred.
    #[error("Server error: {message}")]
    ServerError {
        /// Error message from server.
        message: String,
        /// Optional request ID for support.
        request_id: Option<String>,
    },

    /// Service is temporarily unavailable.
    #[error("Service unavailable: {message}")]
    ServiceUnavailable {
        /// Error message.
        message: String,
    },

    /// Network or connection error.
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Request timed out.
    #[error("Request timed out after {timeout_secs} seconds")]
    Timeout {
        /// Timeout duration in seconds.
        timeout_secs: u64,
    },

    /// Error building the client configuration.
    #[error("Configuration error: {message}")]
    Configuration {
        /// Error message.
        message: String,
    },

    /// Error serializing request or deserializing response.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid URL provided.
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// IO error during streaming operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Creates a bad request error with optional validation details.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest {
            message: message.into(),
            details: None,
        }
    }

    /// Creates a bad request error with validation errors.
    pub fn validation(message: impl Into<String>, errors: Vec<FieldError>) -> Self {
        Self::BadRequest {
            message: message.into(),
            details: Some(ValidationErrors { errors }),
        }
    }

    /// Creates an unauthorized error.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized {
            message: message.into(),
        }
    }

    /// Creates a forbidden error.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }

    /// Creates a not found error.
    pub fn not_found(resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        Self::NotFound {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
        }
    }

    /// Creates a conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    /// Creates a server error.
    pub fn server_error(message: impl Into<String>, request_id: Option<String>) -> Self {
        Self::ServerError {
            message: message.into(),
            request_id,
        }
    }

    /// Creates a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Returns true if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. }
                | Self::ServerError { .. }
                | Self::ServiceUnavailable { .. }
                | Self::Timeout { .. }
                | Self::Network(_)
        )
    }

    /// Returns the HTTP status code if applicable.
    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest { .. } => Some(400),
            Self::Unauthorized { .. } => Some(401),
            Self::Forbidden { .. } => Some(403),
            Self::NotFound { .. } => Some(404),
            Self::Conflict { .. } => Some(409),
            Self::PayloadTooLarge { .. } => Some(413),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { .. } => Some(500),
            Self::ServiceUnavailable { .. } => Some(503),
            _ => None,
        }
    }

    /// Returns the request ID if available.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::ServerError { request_id, .. } => request_id.as_deref(),
            _ => None,
        }
    }
}

/// Field-level validation errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationErrors {
    /// List of field errors.
    pub errors: Vec<FieldError>,
}

impl std::error::Error for ValidationErrors {}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, error) in self.errors.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            write!(f, "{}: {}", error.field, error.message)?;
        }
        Ok(())
    }
}

/// A validation error for a specific field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldError {
    /// The field name that has an error.
    pub field: String,
    /// The error message.
    pub message: String,
    /// The error code, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl FieldError {
    /// Creates a new field error.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            code: None,
        }
    }

    /// Creates a new field error with a code.
    pub fn with_code(
        field: impl Into<String>,
        message: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            code: Some(code.into()),
        }
    }
}

/// API error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Error type/code.
    pub error: String,
    /// Human-readable message.
    pub message: String,
    /// HTTP status code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Request ID for support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Field validation errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<FieldError>>,
}

impl ApiError {
    /// Converts this API error to an SDK error.
    #[must_use]
    pub fn into_error(self) -> Error {
        let status = self.status.unwrap_or(500);

        match status {
            400 => Error::BadRequest {
                message: self.message,
                details: self.details.map(|errors| ValidationErrors { errors }),
            },
            401 => Error::Unauthorized {
                message: self.message,
            },
            403 => Error::Forbidden {
                message: self.message,
            },
            404 => Error::NotFound {
                resource_type: "resource".to_string(),
                resource_id: self.error,
            },
            409 => Error::Conflict {
                message: self.message,
            },
            413 => Error::PayloadTooLarge { max_size: 0 },
            429 => Error::RateLimited { retry_after_secs: 60 },
            503 => Error::ServiceUnavailable {
                message: self.message,
            },
            _ => Error::ServerError {
                message: self.message,
                request_id: self.request_id,
            },
        }
    }
}

/// Result type alias for SDK operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_retryable() {
        assert!(Error::RateLimited { retry_after_secs: 60 }.is_retryable());
        assert!(Error::ServerError {
            message: "test".into(),
            request_id: None
        }
        .is_retryable());
        assert!(Error::ServiceUnavailable {
            message: "test".into()
        }
        .is_retryable());
        assert!(Error::Timeout { timeout_secs: 30 }.is_retryable());

        assert!(!Error::Unauthorized {
            message: "test".into()
        }
        .is_retryable());
        assert!(!Error::NotFound {
            resource_type: "dataset".into(),
            resource_id: "123".into()
        }
        .is_retryable());
    }

    #[test]
    fn test_error_status_code() {
        assert_eq!(
            Error::BadRequest {
                message: "test".into(),
                details: None
            }
            .status_code(),
            Some(400)
        );
        assert_eq!(
            Error::Unauthorized {
                message: "test".into()
            }
            .status_code(),
            Some(401)
        );
        assert_eq!(
            Error::NotFound {
                resource_type: "dataset".into(),
                resource_id: "123".into()
            }
            .status_code(),
            Some(404)
        );
        assert_eq!(
            Error::RateLimited { retry_after_secs: 60 }.status_code(),
            Some(429)
        );
    }

    #[test]
    fn test_validation_errors_display() {
        let errors = ValidationErrors {
            errors: vec![
                FieldError::new("name", "is required"),
                FieldError::new("email", "is invalid"),
            ],
        };

        assert_eq!(errors.to_string(), "name: is required; email: is invalid");
    }
}
