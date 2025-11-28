//! API response types.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// Standard API response wrapper.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Success flag.
    pub success: bool,
    /// Response data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Response metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ResponseMeta>,
}

/// Response metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseMeta {
    /// Request ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// API version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Processing time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_time_ms: Option<u64>,
}

impl<T> ApiResponse<T> {
    /// Creates a success response with data.
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
            meta: Some(ResponseMeta {
                request_id: None,
                timestamp: chrono::Utc::now(),
                version: None,
                processing_time_ms: None,
            }),
        }
    }

    /// Creates a success response with a message.
    pub fn success_message(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: true,
            data: None,
            message: Some(message.into()),
            meta: Some(ResponseMeta {
                request_id: None,
                timestamp: chrono::Utc::now(),
                version: None,
                processing_time_ms: None,
            }),
        }
    }

    /// Adds a request ID to the response.
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        if let Some(ref mut meta) = self.meta {
            meta.request_id = Some(request_id.into());
        }
        self
    }

    /// Adds processing time to the response.
    pub fn with_processing_time(mut self, ms: u64) -> Self {
        if let Some(ref mut meta) = self.meta {
            meta.processing_time_ms = Some(ms);
        }
        self
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// JSON response helper.
#[derive(Debug)]
pub struct JsonResponse<T>(pub T, pub StatusCode);

impl<T> JsonResponse<T> {
    /// Creates a 200 OK response.
    pub fn ok(data: T) -> Self {
        Self(data, StatusCode::OK)
    }

    /// Creates a 201 Created response.
    pub fn created(data: T) -> Self {
        Self(data, StatusCode::CREATED)
    }

    /// Creates a 202 Accepted response.
    pub fn accepted(data: T) -> Self {
        Self(data, StatusCode::ACCEPTED)
    }
}

impl<T: Serialize> IntoResponse for JsonResponse<T> {
    fn into_response(self) -> Response {
        (self.1, Json(self.0)).into_response()
    }
}

/// Empty success response (204 No Content).
pub struct NoContent;

impl IntoResponse for NoContent {
    fn into_response(self) -> Response {
        StatusCode::NO_CONTENT.into_response()
    }
}

/// Created response with location header.
pub struct Created<T> {
    /// Response body.
    pub body: T,
    /// Location header value.
    pub location: String,
}

impl<T> Created<T> {
    /// Creates a new Created response.
    pub fn new(body: T, location: impl Into<String>) -> Self {
        Self {
            body,
            location: location.into(),
        }
    }
}

impl<T: Serialize> IntoResponse for Created<T> {
    fn into_response(self) -> Response {
        (
            StatusCode::CREATED,
            [("Location", self.location)],
            Json(self.body),
        )
            .into_response()
    }
}

/// Streaming response.
pub struct StreamingResponse<S> {
    /// The stream.
    stream: S,
    /// Content type.
    content_type: String,
}

impl<S> StreamingResponse<S> {
    /// Creates a new streaming response.
    pub fn new(stream: S, content_type: impl Into<String>) -> Self {
        Self {
            stream,
            content_type: content_type.into(),
        }
    }

    /// Creates a JSON lines stream.
    pub fn json_lines(stream: S) -> Self {
        Self::new(stream, "application/x-ndjson")
    }
}

/// Health check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Status.
    pub status: HealthStatus,
    /// Service name.
    pub service: String,
    /// Version.
    pub version: String,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
    /// Component health checks.
    pub checks: Vec<HealthCheck>,
}

/// Health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is healthy.
    Healthy,
    /// Service is degraded but functional.
    Degraded,
    /// Service is unhealthy.
    Unhealthy,
}

/// Individual health check result.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Component name.
    pub name: String,
    /// Status.
    pub status: HealthStatus,
    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Response time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<u64>,
}

impl HealthResponse {
    /// Creates a healthy response.
    pub fn healthy(service: impl Into<String>, version: impl Into<String>, uptime: u64) -> Self {
        Self {
            status: HealthStatus::Healthy,
            service: service.into(),
            version: version.into(),
            uptime_seconds: uptime,
            checks: Vec::new(),
        }
    }

    /// Adds a health check.
    pub fn with_check(mut self, check: HealthCheck) -> Self {
        // Update overall status based on checks
        if check.status == HealthStatus::Unhealthy {
            self.status = HealthStatus::Unhealthy;
        } else if check.status == HealthStatus::Degraded && self.status == HealthStatus::Healthy {
            self.status = HealthStatus::Degraded;
        }
        self.checks.push(check);
        self
    }
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> Response {
        let status_code = match self.status {
            HealthStatus::Healthy => StatusCode::OK,
            HealthStatus::Degraded => StatusCode::OK,
            HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        };

        (status_code, Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_success() {
        let response: ApiResponse<&str> = ApiResponse::success("test");
        assert!(response.success);
        assert_eq!(response.data, Some("test"));
    }

    #[test]
    fn test_json_response() {
        let response = JsonResponse::created("resource");
        assert_eq!(response.1, StatusCode::CREATED);
    }

    #[test]
    fn test_health_response() {
        let health = HealthResponse::healthy("test-service", "1.0.0", 3600)
            .with_check(HealthCheck {
                name: "database".to_string(),
                status: HealthStatus::Healthy,
                message: None,
                response_time_ms: Some(5),
            });

        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.checks.len(), 1);
    }

    #[test]
    fn test_health_degraded() {
        let health = HealthResponse::healthy("test-service", "1.0.0", 3600)
            .with_check(HealthCheck {
                name: "cache".to_string(),
                status: HealthStatus::Degraded,
                message: Some("High latency".to_string()),
                response_time_ms: Some(500),
            });

        assert_eq!(health.status, HealthStatus::Degraded);
    }
}
