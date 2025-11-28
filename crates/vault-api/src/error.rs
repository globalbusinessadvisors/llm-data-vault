//! API error types.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// API result type.
pub type ApiResult<T> = Result<T, ApiError>;

/// API error.
#[derive(Error, Debug)]
pub enum ApiError {
    /// Bad request (400).
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Validation error (400).
    #[error("Validation error")]
    ValidationError(ValidationErrors),

    /// Unauthorized (401).
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden (403).
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Not found (404).
    #[error("Not found: {0}")]
    NotFound(String),

    /// Conflict (409).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Gone (410).
    #[error("Gone: {0}")]
    Gone(String),

    /// Unprocessable entity (422).
    #[error("Unprocessable entity: {0}")]
    UnprocessableEntity(String),

    /// Rate limited (429).
    #[error("Rate limited: {0}")]
    RateLimited(String),

    /// Internal server error (500).
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Service unavailable (503).
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Gateway timeout (504).
    #[error("Gateway timeout: {0}")]
    GatewayTimeout(String),
}

/// Validation errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationErrors {
    /// Field-specific errors.
    pub fields: HashMap<String, Vec<String>>,
}

impl ValidationErrors {
    /// Creates empty validation errors.
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Adds a field error.
    pub fn add(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.fields
            .entry(field.into())
            .or_default()
            .push(message.into());
    }

    /// Returns true if there are no errors.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl Default for ValidationErrors {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let errors: Vec<String> = self
            .fields
            .iter()
            .flat_map(|(field, msgs)| msgs.iter().map(move |m| format!("{}: {}", field, m)))
            .collect();
        write!(f, "{}", errors.join(", "))
    }
}

impl ApiError {
    /// Returns the HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::ValidationError(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Gone(_) => StatusCode::GONE,
            Self::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::GatewayTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// Returns the error code.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::ValidationError(_) => "VALIDATION_ERROR",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::Gone(_) => "GONE",
            Self::UnprocessableEntity(_) => "UNPROCESSABLE_ENTITY",
            Self::RateLimited(_) => "RATE_LIMITED",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            Self::GatewayTimeout(_) => "GATEWAY_TIMEOUT",
        }
    }

    /// Creates a not found error for a resource.
    pub fn not_found_resource(resource: &str, id: &str) -> Self {
        Self::NotFound(format!("{} with id '{}' not found", resource, id))
    }
}

/// Error response body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
    /// Validation errors (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<HashMap<String, Vec<String>>>,
    /// Request ID for tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code().to_string();

        let (message, errors) = match &self {
            Self::ValidationError(v) => (v.to_string(), Some(v.fields.clone())),
            _ => (self.to_string(), None),
        };

        let body = ErrorResponse {
            code,
            message,
            errors,
            request_id: None, // Will be set by middleware
            timestamp: chrono::Utc::now(),
        };

        (status, Json(body)).into_response()
    }
}

// Conversions from other error types
impl From<vault_core::VaultError> for ApiError {
    fn from(e: vault_core::VaultError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<vault_storage::StorageError> for ApiError {
    fn from(e: vault_storage::StorageError) -> Self {
        match e {
            vault_storage::StorageError::NotFound(msg) => Self::NotFound(msg),
            vault_storage::StorageError::AlreadyExists(msg) => Self::Conflict(msg),
            _ => Self::Internal(e.to_string()),
        }
    }
}

impl From<vault_access::AccessError> for ApiError {
    fn from(e: vault_access::AccessError) -> Self {
        match e {
            vault_access::AccessError::Unauthorized(msg) => Self::Unauthorized(msg),
            vault_access::AccessError::Forbidden(msg) => Self::Forbidden(msg),
            vault_access::AccessError::TokenExpired => Self::Unauthorized("Token expired".to_string()),
            vault_access::AccessError::InvalidToken(msg) => Self::Unauthorized(msg),
            _ => Self::Internal(e.to_string()),
        }
    }
}

impl From<vault_version::VersionError> for ApiError {
    fn from(e: vault_version::VersionError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        Self::BadRequest(format!("JSON parsing error: {}", e))
    }
}

impl From<validator::ValidationErrors> for ApiError {
    fn from(e: validator::ValidationErrors) -> Self {
        let mut errors = ValidationErrors::new();
        for (field, field_errors) in e.field_errors() {
            for error in field_errors {
                let message = error
                    .message
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| format!("Validation failed: {:?}", error.code));
                errors.add(field.to_string(), message);
            }
        }
        Self::ValidationError(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_status_codes() {
        assert_eq!(
            ApiError::BadRequest("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Unauthorized("test".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::NotFound("test".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::Internal("test".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_validation_errors() {
        let mut errors = ValidationErrors::new();
        errors.add("name", "is required");
        errors.add("email", "is invalid");

        assert!(!errors.is_empty());
        assert!(errors.to_string().contains("name"));
        assert!(errors.to_string().contains("email"));
    }

    #[test]
    fn test_not_found_resource() {
        let error = ApiError::not_found_resource("Dataset", "ds-123");
        assert!(error.to_string().contains("Dataset"));
        assert!(error.to_string().contains("ds-123"));
    }
}
