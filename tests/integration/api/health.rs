//! Health endpoint integration tests.

use crate::common::{TestClient, TestApp};
use axum::http::StatusCode;
use serde_json::Value;

/// Tests the basic health endpoint.
#[tokio::test]
async fn test_health_endpoint() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    let response = client.get("/health").await;

    response.assert_ok();

    let json: Value = response.json_value();
    assert_eq!(json["status"], "healthy");
    assert!(json["version"].is_string());
}

/// Tests the liveness probe endpoint.
#[tokio::test]
async fn test_liveness_endpoint() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    let response = client.get("/health/live").await;

    response.assert_ok();
    assert_eq!(response.text(), "OK");
}

/// Tests the readiness probe endpoint.
#[tokio::test]
async fn test_readiness_endpoint() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    let response = client.get("/health/ready").await;

    response.assert_ok();
    assert_eq!(response.text(), "OK");
}

/// Tests the detailed health endpoint.
#[tokio::test]
async fn test_detailed_health_endpoint() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    let response = client.get("/health/detailed").await;

    response.assert_ok();

    let json: Value = response.json_value();
    assert_eq!(json["status"], "healthy");
    assert!(json["checks"].is_array());
}

/// Tests the version endpoint.
#[tokio::test]
async fn test_version_endpoint() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    let response = client.get("/health/version").await;

    response.assert_ok();

    let json: Value = response.json_value();
    assert!(json["name"].is_string());
    assert!(json["version"].is_string());
    assert!(json["rust_version"].is_string());
}

/// Tests that health endpoints don't require authentication.
#[tokio::test]
async fn test_health_no_auth_required() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    // All health endpoints should work without auth
    let endpoints = [
        "/health",
        "/health/live",
        "/health/ready",
        "/health/detailed",
        "/health/version",
    ];

    for endpoint in endpoints {
        let response = client.get(endpoint).await;
        assert!(
            response.status.is_success(),
            "Endpoint {} should not require auth, got {}",
            endpoint,
            response.status
        );
    }
}

/// Tests health response format consistency.
#[tokio::test]
async fn test_health_response_format() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    let response = client.get("/health").await;
    response.assert_ok();

    let json: Value = response.json_value();

    // Required fields
    assert!(json.get("status").is_some(), "Missing 'status' field");
    assert!(json.get("service").is_some(), "Missing 'service' field");
    assert!(json.get("version").is_some(), "Missing 'version' field");
    assert!(json.get("uptime_seconds").is_some(), "Missing 'uptime_seconds' field");

    // Status should be a valid value
    let status = json["status"].as_str().unwrap();
    assert!(
        ["healthy", "degraded", "unhealthy"].contains(&status),
        "Invalid status: {}",
        status
    );
}

/// Tests health endpoint under load (basic load test).
#[tokio::test]
async fn test_health_endpoint_under_load() {
    let app = TestApp::new();
    let client = TestClient::new(app.router);

    // Make multiple concurrent requests
    let mut handles = vec![];

    for _ in 0..10 {
        let c = TestClient::new(app.router.clone());
        handles.push(tokio::spawn(async move {
            c.get("/health").await
        }));
    }

    // All requests should succeed
    for handle in handles {
        let response = handle.await.expect("Task panicked");
        response.assert_ok();
    }
}
