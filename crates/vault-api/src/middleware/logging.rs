//! Request logging middleware.

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{info, span, warn, Level, Span};
use uuid::Uuid;

/// Logging middleware.
#[derive(Clone, Default)]
pub struct LoggingMiddleware {
    /// Include request body in logs.
    pub log_body: bool,
    /// Include response body in logs.
    pub log_response: bool,
    /// Log slow requests (threshold in ms).
    pub slow_request_threshold_ms: Option<u64>,
}

impl LoggingMiddleware {
    /// Creates a new logging middleware.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables body logging.
    pub fn with_body_logging(mut self) -> Self {
        self.log_body = true;
        self
    }

    /// Sets slow request threshold.
    pub fn with_slow_request_threshold(mut self, threshold_ms: u64) -> Self {
        self.slow_request_threshold_ms = Some(threshold_ms);
        self
    }
}

/// Logging layer function.
pub async fn logging_layer(req: Request, next: Next) -> Response {
    let request_id = extract_or_generate_request_id(&req);
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());

    // Extract headers for logging
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let content_length = req
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    let start = Instant::now();

    // Create request span
    let span = span!(
        Level::INFO,
        "request",
        request_id = %request_id,
        method = %method,
        path = %path,
    );

    let _guard = span.enter();

    info!(
        query = ?query,
        user_agent = ?user_agent,
        content_length = ?content_length,
        "Request started"
    );

    // Process request
    let response = next.run(req).await;

    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();

    // Log response
    if status >= 500 {
        warn!(
            status = status,
            duration_ms = duration_ms,
            "Request completed with server error"
        );
    } else if status >= 400 {
        info!(
            status = status,
            duration_ms = duration_ms,
            "Request completed with client error"
        );
    } else {
        info!(
            status = status,
            duration_ms = duration_ms,
            "Request completed"
        );
    }

    response
}

/// Extracts or generates a request ID.
fn extract_or_generate_request_id(req: &Request) -> String {
    req.headers()
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// Request info for structured logging.
#[derive(Debug)]
pub struct RequestInfo {
    /// Request ID.
    pub request_id: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Query string.
    pub query: Option<String>,
    /// User agent.
    pub user_agent: Option<String>,
    /// Client IP.
    pub client_ip: Option<String>,
    /// User ID (if authenticated).
    pub user_id: Option<String>,
    /// Start time.
    pub start_time: Instant,
}

impl RequestInfo {
    /// Creates from a request.
    pub fn from_request(req: &Request) -> Self {
        Self {
            request_id: extract_or_generate_request_id(req),
            method: req.method().to_string(),
            path: req.uri().path().to_string(),
            query: req.uri().query().map(String::from),
            user_agent: req
                .headers()
                .get("User-Agent")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            client_ip: extract_client_ip(req),
            user_id: req
                .extensions()
                .get::<vault_access::TokenClaims>()
                .map(|c| c.sub.clone()),
            start_time: Instant::now(),
        }
    }

    /// Returns the elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

/// Extracts client IP from request headers.
fn extract_client_ip(req: &Request) -> Option<String> {
    // Check X-Forwarded-For
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(ip) = value.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }

    // Check X-Real-IP
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(value) = real_ip.to_str() {
            return Some(value.to_string());
        }
    }

    None
}

/// Log entry for audit logging.
#[derive(Debug, serde::Serialize)]
pub struct AuditLogEntry {
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Request ID.
    pub request_id: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// User ID.
    pub user_id: Option<String>,
    /// Client IP.
    pub client_ip: Option<String>,
    /// Response status.
    pub status: u16,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Resource type.
    pub resource_type: Option<String>,
    /// Resource ID.
    pub resource_id: Option<String>,
    /// Action performed.
    pub action: Option<String>,
}

impl AuditLogEntry {
    /// Creates a new audit log entry.
    pub fn new(info: &RequestInfo, status: u16) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            request_id: info.request_id.clone(),
            method: info.method.clone(),
            path: info.path.clone(),
            user_id: info.user_id.clone(),
            client_ip: info.client_ip.clone(),
            status,
            duration_ms: info.elapsed_ms(),
            resource_type: None,
            resource_id: None,
            action: None,
        }
    }

    /// Sets resource information.
    pub fn with_resource(mut self, resource_type: &str, resource_id: &str) -> Self {
        self.resource_type = Some(resource_type.to_string());
        self.resource_id = Some(resource_id.to_string());
        self
    }

    /// Sets the action.
    pub fn with_action(mut self, action: &str) -> Self {
        self.action = Some(action.to_string());
        self
    }
}
