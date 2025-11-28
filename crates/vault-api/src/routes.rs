//! API routes.

use crate::{
    handlers::{
        auth, datasets, health, records, webhooks,
    },
    middleware::{cors::cors_layer, logging::logging_layer},
    state::AppState,
};
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::compression::CompressionLayer;

/// Creates the API router.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health endpoints (no auth required)
        .nest("/health", health_routes())
        // API v1
        .nest("/api/v1", api_v1_routes(state.clone()))
        // Add middleware
        .layer(CompressionLayer::new())
        .layer(cors_layer())
        .layer(middleware::from_fn(logging_layer))
        .with_state(state)
}

/// Health routes.
fn health_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(health::health_handler))
        .route("/live", get(health::liveness_handler))
        .route("/ready", get(health::readiness_handler))
        .route("/detailed", get(health::detailed_health_handler))
        .route("/version", get(health::version_handler))
}

/// API v1 routes.
fn api_v1_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        // Auth routes
        .nest("/auth", auth_routes())
        // Dataset routes
        .nest("/datasets", dataset_routes())
        // Webhook routes
        .nest("/webhooks", webhook_routes())
}

/// Authentication routes.
fn auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login", post(auth::login_handler))
        .route("/register", post(auth::register_handler))
        .route("/refresh", post(auth::refresh_token_handler))
        .route("/logout", post(auth::logout_handler))
        .route("/password/change", post(auth::change_password_handler))
        .route("/password/reset", post(auth::request_password_reset_handler))
        .route("/password/reset/confirm", post(auth::confirm_password_reset_handler))
        .route("/me", get(auth::get_current_user_handler))
        .route("/api-keys", get(auth::list_api_keys_handler))
        .route("/api-keys", post(auth::create_api_key_handler))
        .route("/api-keys/:key_id", delete(auth::revoke_api_key_handler))
}

/// Dataset routes.
fn dataset_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Dataset CRUD
        .route("/", get(datasets::list_datasets))
        .route("/", post(datasets::create_dataset))
        .route("/:id", get(datasets::get_dataset))
        .route("/:id", put(datasets::update_dataset))
        .route("/:id", delete(datasets::delete_dataset))
        // Dataset actions
        .route("/:id/archive", post(datasets::archive_dataset))
        .route("/:id/restore", post(datasets::restore_dataset))
        .route("/:id/stats", get(datasets::get_dataset_stats))
        // Record routes nested under datasets
        .route("/:dataset_id/records", get(records::list_records))
        .route("/:dataset_id/records", post(records::create_record))
        .route("/:dataset_id/records/batch", post(records::batch_create_records))
        .route("/:dataset_id/records/batch/delete", post(records::batch_delete_records))
        .route("/:dataset_id/records/:record_id", get(records::get_record))
        .route("/:dataset_id/records/:record_id", put(records::update_record))
        .route("/:dataset_id/records/:record_id", delete(records::delete_record))
        .route("/:dataset_id/records/:record_id/history", get(records::get_record_history))
        .route("/:dataset_id/records/:record_id/versions/:version", get(records::get_record_version))
}

/// Webhook routes.
fn webhook_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(webhooks::list_webhooks))
        .route("/", post(webhooks::create_webhook))
        .route("/:id", get(webhooks::get_webhook))
        .route("/:id", put(webhooks::update_webhook))
        .route("/:id", delete(webhooks::delete_webhook))
        .route("/:id/test", post(webhooks::test_webhook))
        .route("/:id/secret/rotate", post(webhooks::rotate_secret))
        .route("/:webhook_id/deliveries", get(webhooks::list_deliveries))
        .route("/:webhook_id/deliveries/:delivery_id", get(webhooks::get_delivery))
        .route("/:webhook_id/deliveries/:delivery_id/retry", post(webhooks::retry_delivery))
}

/// Creates a minimal router for testing.
pub fn create_test_router() -> Router {
    Router::new()
        .route("/health", get(health::health_handler))
        .route("/health/live", get(health::liveness_handler))
        .route("/health/ready", get(health::readiness_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_test_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_liveness_endpoint() {
        let app = create_test_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readiness_endpoint() {
        let app = create_test_router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
