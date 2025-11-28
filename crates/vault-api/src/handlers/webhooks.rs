//! Webhook handlers.

use crate::{
    error::ApiError,
    pagination::{PagedResponse, Pagination},
    response::{Created, NoContent},
    state::AppState,
    ApiResult,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

/// Webhook response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    /// Webhook ID.
    pub id: String,
    /// Webhook name.
    pub name: String,
    /// URL.
    pub url: String,
    /// Event types.
    pub event_types: Vec<String>,
    /// Status.
    pub status: WebhookStatus,
    /// Created at.
    pub created_at: DateTime<Utc>,
    /// Updated at.
    pub updated_at: DateTime<Utc>,
    /// Statistics.
    pub stats: WebhookStats,
}

/// Webhook status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookStatus {
    /// Active.
    Active,
    /// Paused.
    Paused,
    /// Disabled due to failures.
    Disabled,
}

/// Webhook statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookStats {
    /// Total deliveries.
    pub total_deliveries: u64,
    /// Successful deliveries.
    pub successful_deliveries: u64,
    /// Failed deliveries.
    pub failed_deliveries: u64,
    /// Success rate.
    pub success_rate: f64,
    /// Last delivery at.
    pub last_delivery_at: Option<DateTime<Utc>>,
}

/// Create webhook request.
#[derive(Debug, Deserialize, Validate)]
pub struct CreateWebhookRequest {
    /// Webhook name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    /// URL.
    #[validate(url)]
    pub url: String,
    /// Event types to subscribe to.
    #[validate(length(min = 1))]
    pub event_types: Vec<String>,
    /// Secret (optional, auto-generated if not provided).
    pub secret: Option<String>,
    /// Description.
    pub description: Option<String>,
}

/// Update webhook request.
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateWebhookRequest {
    /// Webhook name.
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    /// URL.
    #[validate(url)]
    pub url: Option<String>,
    /// Event types.
    pub event_types: Option<Vec<String>>,
    /// Status.
    pub status: Option<WebhookStatus>,
    /// Description.
    pub description: Option<String>,
}

/// Webhook query parameters.
#[derive(Debug, Deserialize)]
pub struct WebhookQuery {
    /// Filter by status.
    pub status: Option<WebhookStatus>,
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Pagination.
    #[serde(flatten)]
    pub pagination: Pagination,
}

/// List webhooks handler.
pub async fn list_webhooks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WebhookQuery>,
) -> ApiResult<Json<PagedResponse<WebhookResponse>>> {
    let response = PagedResponse::empty(&query.pagination);
    Ok(Json(response))
}

/// Get webhook handler.
pub async fn get_webhook(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<WebhookResponse>> {
    Err(ApiError::not_found_resource("Webhook", &id))
}

/// Create webhook handler.
pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateWebhookRequest>,
) -> ApiResult<Created<WebhookResponse>> {
    request.validate()?;

    let now = Utc::now();
    let id = Uuid::new_v4().to_string();

    let webhook = WebhookResponse {
        id: id.clone(),
        name: request.name,
        url: request.url,
        event_types: request.event_types,
        status: WebhookStatus::Active,
        created_at: now,
        updated_at: now,
        stats: WebhookStats {
            total_deliveries: 0,
            successful_deliveries: 0,
            failed_deliveries: 0,
            success_rate: 1.0,
            last_delivery_at: None,
        },
    };

    Ok(Created::new(webhook, format!("/api/v1/webhooks/{}", id)))
}

/// Update webhook handler.
pub async fn update_webhook(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(request): Json<UpdateWebhookRequest>,
) -> ApiResult<Json<WebhookResponse>> {
    request.validate()?;
    Err(ApiError::not_found_resource("Webhook", &id))
}

/// Delete webhook handler.
pub async fn delete_webhook(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<NoContent> {
    Err(ApiError::not_found_resource("Webhook", &id))
}

/// Webhook delivery response.
#[derive(Debug, Serialize)]
pub struct DeliveryResponse {
    /// Delivery ID.
    pub id: String,
    /// Event ID.
    pub event_id: String,
    /// Event type.
    pub event_type: String,
    /// Status.
    pub status: DeliveryStatus,
    /// HTTP status code.
    pub http_status: Option<u16>,
    /// Created at.
    pub created_at: DateTime<Utc>,
    /// Attempts.
    pub attempts: u32,
    /// Next retry at.
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Delivery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    /// Pending.
    Pending,
    /// Delivered.
    Delivered,
    /// Failed.
    Failed,
    /// Retrying.
    Retrying,
}

/// List deliveries handler.
pub async fn list_deliveries(
    State(state): State<Arc<AppState>>,
    Path(webhook_id): Path<String>,
    Query(pagination): Query<Pagination>,
) -> ApiResult<Json<PagedResponse<DeliveryResponse>>> {
    let response = PagedResponse::empty(&pagination);
    Ok(Json(response))
}

/// Get delivery handler.
pub async fn get_delivery(
    State(state): State<Arc<AppState>>,
    Path((webhook_id, delivery_id)): Path<(String, String)>,
) -> ApiResult<Json<DeliveryResponse>> {
    Err(ApiError::not_found_resource("Delivery", &delivery_id))
}

/// Retry delivery handler.
pub async fn retry_delivery(
    State(state): State<Arc<AppState>>,
    Path((webhook_id, delivery_id)): Path<(String, String)>,
) -> ApiResult<Json<DeliveryResponse>> {
    Err(ApiError::not_found_resource("Delivery", &delivery_id))
}

/// Test webhook request.
#[derive(Debug, Deserialize)]
pub struct TestWebhookRequest {
    /// Optional custom payload.
    pub payload: Option<serde_json::Value>,
}

/// Test webhook handler.
pub async fn test_webhook(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(request): Json<TestWebhookRequest>,
) -> ApiResult<Json<DeliveryResponse>> {
    // Send a test event to the webhook
    Err(ApiError::not_found_resource("Webhook", &id))
}

/// Rotate webhook secret handler.
pub async fn rotate_secret(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<SecretResponse>> {
    Err(ApiError::not_found_resource("Webhook", &id))
}

/// Secret response.
#[derive(Debug, Serialize)]
pub struct SecretResponse {
    /// Webhook ID.
    pub webhook_id: String,
    /// New secret.
    pub secret: String,
    /// Rotated at.
    pub rotated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_webhook_validation() {
        let request = CreateWebhookRequest {
            name: "test".to_string(),
            url: "https://example.com/webhook".to_string(),
            event_types: vec!["dataset.created".to_string()],
            secret: None,
            description: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_webhook_invalid_url() {
        let request = CreateWebhookRequest {
            name: "test".to_string(),
            url: "not-a-url".to_string(),
            event_types: vec!["dataset.created".to_string()],
            secret: None,
            description: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_webhook_empty_events() {
        let request = CreateWebhookRequest {
            name: "test".to_string(),
            url: "https://example.com/webhook".to_string(),
            event_types: vec![],
            secret: None,
            description: None,
        };

        assert!(request.validate().is_err());
    }
}
