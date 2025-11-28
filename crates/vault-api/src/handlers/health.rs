//! Health check handlers.

use crate::response::{HealthCheck, HealthResponse, HealthStatus};
use axum::{extract::State, Json};
use std::sync::Arc;
use std::time::Instant;

/// Application start time for uptime calculation.
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Initializes the start time.
pub fn init_start_time() {
    START_TIME.get_or_init(Instant::now);
}

/// Returns the uptime in seconds.
pub fn uptime_seconds() -> u64 {
    START_TIME
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0)
}

/// Health check handler.
pub async fn health_handler() -> Json<HealthResponse> {
    let health = HealthResponse::healthy(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        uptime_seconds(),
    );

    Json(health)
}

/// Liveness probe handler.
pub async fn liveness_handler() -> &'static str {
    "OK"
}

/// Readiness probe handler.
pub async fn readiness_handler() -> Result<&'static str, (axum::http::StatusCode, &'static str)> {
    // In a real implementation, check dependencies here
    Ok("OK")
}

/// Detailed health check handler with component checks.
pub async fn detailed_health_handler() -> Json<HealthResponse> {
    let mut health = HealthResponse::healthy(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        uptime_seconds(),
    );

    // Check storage
    let storage_check = check_storage().await;
    health = health.with_check(storage_check);

    // Check event bus
    let event_check = check_events().await;
    health = health.with_check(event_check);

    Json(health)
}

/// Checks storage health.
async fn check_storage() -> HealthCheck {
    let start = Instant::now();

    // In a real implementation, perform actual storage check
    // For now, return healthy
    HealthCheck {
        name: "storage".to_string(),
        status: HealthStatus::Healthy,
        message: None,
        response_time_ms: Some(start.elapsed().as_millis() as u64),
    }
}

/// Checks event bus health.
async fn check_events() -> HealthCheck {
    let start = Instant::now();

    // In a real implementation, perform actual event bus check
    HealthCheck {
        name: "events".to_string(),
        status: HealthStatus::Healthy,
        message: None,
        response_time_ms: Some(start.elapsed().as_millis() as u64),
    }
}

/// Version information response.
#[derive(Debug, serde::Serialize)]
pub struct VersionInfo {
    /// Package name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Git commit (if available).
    pub git_commit: Option<String>,
    /// Build timestamp.
    pub build_time: Option<String>,
    /// Rust version.
    pub rust_version: String,
}

/// Version handler.
pub async fn version_handler() -> Json<VersionInfo> {
    Json(VersionInfo {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: option_env!("GIT_COMMIT").map(String::from),
        build_time: option_env!("BUILD_TIME").map(String::from),
        rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_handler() {
        init_start_time();
        let response = health_handler().await;
        assert_eq!(response.status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_liveness_handler() {
        let response = liveness_handler().await;
        assert_eq!(response, "OK");
    }

    #[tokio::test]
    async fn test_readiness_handler() {
        let response = readiness_handler().await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_version_handler() {
        let response = version_handler().await;
        assert!(!response.version.is_empty());
    }
}
