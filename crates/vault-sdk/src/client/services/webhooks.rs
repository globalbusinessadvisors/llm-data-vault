//! Webhooks service.

use std::sync::Arc;

use uuid::Uuid;

use crate::error::Result;
use crate::models::{
    Webhook, WebhookCreate, WebhookUpdate, WebhookList, WebhookEvent,
    WebhookDelivery, RotateSecretResponse, Pagination, PaginatedList,
};

use super::super::http::HttpClient;

/// Service for managing webhooks.
#[derive(Clone)]
pub struct WebhooksService {
    http: Arc<HttpClient>,
}

impl WebhooksService {
    /// Creates a new webhooks service.
    pub(crate) fn new(http: Arc<HttpClient>) -> Self {
        Self { http }
    }

    /// Lists all webhooks.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let webhooks = client.webhooks().list().await?;
    ///
    /// for webhook in webhooks.items {
    ///     println!("{}: {} ({} events)",
    ///         webhook.name, webhook.url, webhook.events.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list(&self) -> Result<WebhookList> {
        self.http.get("/api/v1/webhooks").await
    }

    /// Lists webhooks with pagination.
    pub async fn list_with_pagination(&self, pagination: &Pagination) -> Result<WebhookList> {
        let url = format!(
            "/api/v1/webhooks?limit={}&offset={}",
            pagination.limit.unwrap_or(20),
            pagination.offset.unwrap_or(0)
        );
        self.http.get(&url).await
    }

    /// Gets a webhook by ID.
    pub async fn get(&self, id: impl AsRef<str>) -> Result<Webhook> {
        let url = format!("/api/v1/webhooks/{}", id.as_ref());
        self.http.get(&url).await
    }

    /// Creates a new webhook.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, WebhookCreate, WebhookEvent};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let request = WebhookCreate::new(
    ///     "Record Events",
    ///     "https://api.example.com/webhooks/vault",
    ///     vec![WebhookEvent::RecordCreated, WebhookEvent::RecordUpdated],
    /// ).with_secret("your-webhook-secret");
    ///
    /// let webhook = client.webhooks().create(&request).await?;
    /// println!("Created webhook: {}", webhook.id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(&self, request: &WebhookCreate) -> Result<Webhook> {
        self.http.post("/api/v1/webhooks", request).await
    }

    /// Updates a webhook.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, WebhookUpdate};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let update = WebhookUpdate::new()
    ///     .with_name("Updated Name")
    ///     .with_active(false);
    ///
    /// let webhook = client.webhooks().update("wh_abc123", &update).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update(&self, id: impl AsRef<str>, request: &WebhookUpdate) -> Result<Webhook> {
        let url = format!("/api/v1/webhooks/{}", id.as_ref());
        self.http.patch(&url, request).await
    }

    /// Deletes a webhook.
    pub async fn delete(&self, id: impl AsRef<str>) -> Result<()> {
        let url = format!("/api/v1/webhooks/{}", id.as_ref());
        self.http.delete(&url).await
    }

    /// Enables a webhook.
    pub async fn enable(&self, id: impl AsRef<str>) -> Result<Webhook> {
        let update = WebhookUpdate::new().with_active(true);
        self.update(id, &update).await
    }

    /// Disables a webhook.
    pub async fn disable(&self, id: impl AsRef<str>) -> Result<Webhook> {
        let update = WebhookUpdate::new().with_active(false);
        self.update(id, &update).await
    }

    /// Rotates the webhook secret.
    ///
    /// # Important
    ///
    /// The new secret is only shown once. The old secret remains valid
    /// for a grace period.
    pub async fn rotate_secret(&self, id: impl AsRef<str>) -> Result<RotateSecretResponse> {
        let url = format!("/api/v1/webhooks/{}/secret/rotate", id.as_ref());
        self.http.post(&url, &()).await
    }

    /// Sends a test delivery to the webhook.
    pub async fn test(&self, id: impl AsRef<str>) -> Result<WebhookDelivery> {
        let url = format!("/api/v1/webhooks/{}/test", id.as_ref());
        self.http.post(&url, &()).await
    }

    /// Lists deliveries for a webhook.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let deliveries = client.webhooks().deliveries("wh_abc123").await?;
    ///
    /// for delivery in deliveries.items {
    ///     println!("{}: {} - HTTP {}",
    ///         delivery.id,
    ///         delivery.status,
    ///         delivery.http_status.unwrap_or(0));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn deliveries(&self, id: impl AsRef<str>) -> Result<PaginatedList<WebhookDelivery>> {
        let url = format!("/api/v1/webhooks/{}/deliveries", id.as_ref());
        self.http.get(&url).await
    }

    /// Lists deliveries with pagination.
    pub async fn deliveries_with_pagination(
        &self,
        id: impl AsRef<str>,
        pagination: &Pagination,
    ) -> Result<PaginatedList<WebhookDelivery>> {
        let url = format!(
            "/api/v1/webhooks/{}/deliveries?limit={}&offset={}",
            id.as_ref(),
            pagination.limit.unwrap_or(20),
            pagination.offset.unwrap_or(0)
        );
        self.http.get(&url).await
    }

    /// Gets a specific delivery.
    pub async fn delivery(
        &self,
        webhook_id: impl AsRef<str>,
        delivery_id: impl AsRef<str>,
    ) -> Result<WebhookDelivery> {
        let url = format!(
            "/api/v1/webhooks/{}/deliveries/{}",
            webhook_id.as_ref(),
            delivery_id.as_ref()
        );
        self.http.get(&url).await
    }

    /// Retries a failed delivery.
    pub async fn retry_delivery(
        &self,
        webhook_id: impl AsRef<str>,
        delivery_id: impl AsRef<str>,
    ) -> Result<WebhookDelivery> {
        let url = format!(
            "/api/v1/webhooks/{}/deliveries/{}/retry",
            webhook_id.as_ref(),
            delivery_id.as_ref()
        );
        self.http.post(&url, &()).await
    }

    /// Gets available webhook events.
    pub async fn available_events(&self) -> Result<Vec<WebhookEventInfo>> {
        self.http.get("/api/v1/webhooks/events").await
    }
}

/// Information about a webhook event type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebhookEventInfo {
    /// Event identifier.
    pub event: WebhookEvent,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Example payload.
    pub example_payload: serde_json::Value,
}

impl std::fmt::Debug for WebhooksService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhooksService").finish_non_exhaustive()
    }
}
