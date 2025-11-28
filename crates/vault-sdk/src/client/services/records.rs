//! Records service.

use std::sync::Arc;

use uuid::Uuid;

use crate::error::Result;
use crate::models::{
    Record, RecordCreate, RecordUpdate, RecordList, RecordListParams,
    BulkRecordCreate, BulkResult, PiiDetectionResult,
};

use super::super::http::HttpClient;

/// Service for managing records within a dataset.
#[derive(Clone)]
pub struct RecordsService {
    http: Arc<HttpClient>,
    dataset_id: String,
}

impl RecordsService {
    /// Creates a new records service for a specific dataset.
    pub(crate) fn new(http: Arc<HttpClient>, dataset_id: String) -> Self {
        Self { http, dataset_id }
    }

    /// Returns the dataset ID this service operates on.
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// Lists all records in the dataset.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let records = client.records("ds_abc123").list().await?;
    ///
    /// for record in records.items {
    ///     println!("{}: {} bytes (PII: {})",
    ///         record.id, record.size_bytes, record.pii_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list(&self) -> Result<RecordList> {
        let url = format!("/api/v1/datasets/{}/records", self.dataset_id);
        self.http.get(&url).await
    }

    /// Lists records with filtering and pagination.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, models::RecordListParams, RecordStatus, PiiScanStatus, SortOrder};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let params = RecordListParams::new()
    ///     .with_status(RecordStatus::Active)
    ///     .with_pii_status(PiiScanStatus::Clean)
    ///     .with_sort("created_at", SortOrder::Desc)
    ///     .with_pagination(50, 0);
    ///
    /// let records = client.records("ds_abc123")
    ///     .list_with_params(&params)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_with_params(&self, params: &RecordListParams) -> Result<RecordList> {
        let mut query_parts = Vec::new();

        if let Some(status) = &params.status {
            query_parts.push(format!("status={status}"));
        }
        if let Some(pii_status) = &params.pii_status {
            query_parts.push(format!("pii_status={pii_status}"));
        }
        if let Some(label) = &params.label {
            query_parts.push(format!("label={}", ::urlencoding::encode(label)));
        }
        if let Some(sort_by) = &params.sort_by {
            query_parts.push(format!("sort_by={sort_by}"));
        }
        if let Some(sort_order) = &params.sort_order {
            query_parts.push(format!("sort_order={sort_order}"));
        }
        if let Some(limit) = params.limit {
            query_parts.push(format!("limit={limit}"));
        }
        if let Some(offset) = params.offset {
            query_parts.push(format!("offset={offset}"));
        }

        let url = if query_parts.is_empty() {
            format!("/api/v1/datasets/{}/records", self.dataset_id)
        } else {
            format!(
                "/api/v1/datasets/{}/records?{}",
                self.dataset_id,
                query_parts.join("&")
            )
        };

        self.http.get(&url).await
    }

    /// Gets a record by ID.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let record = client.records("ds_abc123").get("rec_xyz789").await?;
    /// println!("Record content hash: {}", record.content_hash);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get(&self, id: impl AsRef<str>) -> Result<Record> {
        let url = format!("/api/v1/datasets/{}/records/{}", self.dataset_id, id.as_ref());
        self.http.get(&url).await
    }

    /// Creates a new record.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, RecordCreate};
    /// # use serde_json::json;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let content = json!({
    ///     "prompt": "What is machine learning?",
    ///     "response": "Machine learning is a subset of AI..."
    /// });
    ///
    /// let request = RecordCreate::json(content)
    ///     .with_pii_scan(true)
    ///     .with_label("source", "manual");
    ///
    /// let record = client.records("ds_abc123").create(&request).await?;
    /// println!("Created record: {}", record.id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(&self, request: &RecordCreate) -> Result<Record> {
        let url = format!("/api/v1/datasets/{}/records", self.dataset_id);
        self.http.post(&url, request).await
    }

    /// Creates multiple records in bulk.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, RecordCreate, BulkRecordCreate};
    /// # use serde_json::json;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let records = vec![
    ///     RecordCreate::json(json!({"prompt": "Q1", "response": "A1"})),
    ///     RecordCreate::json(json!({"prompt": "Q2", "response": "A2"})),
    ///     RecordCreate::json(json!({"prompt": "Q3", "response": "A3"})),
    /// ];
    ///
    /// let bulk = BulkRecordCreate {
    ///     records,
    ///     continue_on_error: true,
    /// };
    ///
    /// let result = client.records("ds_abc123").create_bulk(&bulk).await?;
    /// println!("Created {} records, {} failed", result.succeeded, result.failed);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_bulk(&self, request: &BulkRecordCreate) -> Result<BulkResult> {
        let url = format!("/api/v1/datasets/{}/records/bulk", self.dataset_id);
        self.http.post(&url, request).await
    }

    /// Updates a record.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, RecordUpdate, RecordStatus};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let update = RecordUpdate::new()
    ///     .with_status(RecordStatus::Archived);
    ///
    /// let record = client.records("ds_abc123")
    ///     .update("rec_xyz789", &update)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update(&self, id: impl AsRef<str>, request: &RecordUpdate) -> Result<Record> {
        let url = format!("/api/v1/datasets/{}/records/{}", self.dataset_id, id.as_ref());
        self.http.patch(&url, request).await
    }

    /// Deletes a record.
    pub async fn delete(&self, id: impl AsRef<str>) -> Result<()> {
        let url = format!("/api/v1/datasets/{}/records/{}", self.dataset_id, id.as_ref());
        self.http.delete(&url).await
    }

    /// Gets PII detection results for a record.
    pub async fn pii_results(&self, id: impl AsRef<str>) -> Result<PiiDetectionResult> {
        let url = format!(
            "/api/v1/datasets/{}/records/{}/pii",
            self.dataset_id,
            id.as_ref()
        );
        self.http.get(&url).await
    }

    /// Triggers a PII scan on a specific record.
    pub async fn scan_pii(&self, id: impl AsRef<str>) -> Result<PiiDetectionResult> {
        let url = format!(
            "/api/v1/datasets/{}/records/{}/scan",
            self.dataset_id,
            id.as_ref()
        );
        self.http.post(&url, &()).await
    }

    /// Gets the anonymized version of a record.
    pub async fn anonymized(&self, id: impl AsRef<str>) -> Result<Record> {
        let url = format!(
            "/api/v1/datasets/{}/records/{}/anonymized",
            self.dataset_id,
            id.as_ref()
        );
        self.http.get(&url).await
    }

    /// Quarantines a record.
    pub async fn quarantine(&self, id: impl AsRef<str>, reason: &str) -> Result<Record> {
        #[derive(serde::Serialize)]
        struct QuarantineRequest<'a> {
            reason: &'a str,
        }

        let url = format!(
            "/api/v1/datasets/{}/records/{}/quarantine",
            self.dataset_id,
            id.as_ref()
        );
        self.http.post(&url, &QuarantineRequest { reason }).await
    }

    /// Releases a record from quarantine.
    pub async fn release(&self, id: impl AsRef<str>) -> Result<Record> {
        let url = format!(
            "/api/v1/datasets/{}/records/{}/release",
            self.dataset_id,
            id.as_ref()
        );
        self.http.post(&url, &()).await
    }

    /// Gets record count.
    pub async fn count(&self) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct CountResponse {
            count: u64,
        }

        let url = format!("/api/v1/datasets/{}/records/count", self.dataset_id);
        let response: CountResponse = self.http.get(&url).await?;
        Ok(response.count)
    }
}

impl std::fmt::Debug for RecordsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordsService")
            .field("dataset_id", &self.dataset_id)
            .finish_non_exhaustive()
    }
}
