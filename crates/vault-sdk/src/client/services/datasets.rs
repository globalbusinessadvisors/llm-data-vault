//! Datasets service.

use std::sync::Arc;

use uuid::Uuid;

use crate::error::Result;
use crate::models::{
    Dataset, DatasetCreate, DatasetUpdate, DatasetList, DatasetListParams, DatasetStats,
};

use super::super::http::HttpClient;

/// Service for managing datasets.
#[derive(Clone)]
pub struct DatasetsService {
    http: Arc<HttpClient>,
}

impl DatasetsService {
    /// Creates a new datasets service.
    pub(crate) fn new(http: Arc<HttpClient>) -> Self {
        Self { http }
    }

    /// Lists all datasets.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let datasets = client.datasets().list().await?;
    ///
    /// for ds in datasets.items {
    ///     println!("{}: {} records ({} bytes)",
    ///         ds.name, ds.record_count, ds.size_bytes);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list(&self) -> Result<DatasetList> {
        self.http.get("/api/v1/datasets").await
    }

    /// Lists datasets with filtering and pagination.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, models::DatasetListParams, DatasetStatus, SortOrder};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let params = DatasetListParams::new()
    ///     .with_status(DatasetStatus::Active)
    ///     .with_search("training")
    ///     .with_sort("created_at", SortOrder::Desc)
    ///     .with_pagination(10, 0);
    ///
    /// let datasets = client.datasets().list_with_params(&params).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_with_params(&self, params: &DatasetListParams) -> Result<DatasetList> {
        let mut query_parts = Vec::new();

        if let Some(status) = &params.status {
            query_parts.push(format!("status={status}"));
        }
        if let Some(format) = &params.format {
            query_parts.push(format!("format={format}"));
        }
        if let Some(search) = &params.search {
            query_parts.push(format!("search={}", ::urlencoding::encode(search)));
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
            "/api/v1/datasets".to_string()
        } else {
            format!("/api/v1/datasets?{}", query_parts.join("&"))
        };

        self.http.get(&url).await
    }

    /// Gets a dataset by ID.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let dataset = client.datasets().get("ds_abc123").await?;
    /// println!("Dataset: {} ({})", dataset.name, dataset.status);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get(&self, id: impl AsRef<str>) -> Result<Dataset> {
        let url = format!("/api/v1/datasets/{}", id.as_ref());
        self.http.get(&url).await
    }

    /// Creates a new dataset.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, DatasetCreate, DatasetFormat};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let request = DatasetCreate::new("Training Data v1")
    ///     .with_description("Fine-tuning dataset for Q4 model")
    ///     .with_format(DatasetFormat::Jsonl)
    ///     .with_label("project", "llm-v2")
    ///     .with_label("environment", "production");
    ///
    /// let dataset = client.datasets().create(&request).await?;
    /// println!("Created dataset: {}", dataset.id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(&self, request: &DatasetCreate) -> Result<Dataset> {
        self.http.post("/api/v1/datasets", request).await
    }

    /// Updates a dataset.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, DatasetUpdate};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let update = DatasetUpdate::new()
    ///     .with_name("Training Data v1.1")
    ///     .with_description("Updated description");
    ///
    /// let dataset = client.datasets().update("ds_abc123", &update).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn update(&self, id: impl AsRef<str>, request: &DatasetUpdate) -> Result<Dataset> {
        let url = format!("/api/v1/datasets/{}", id.as_ref());
        self.http.patch(&url, request).await
    }

    /// Deletes a dataset.
    ///
    /// This also deletes all records in the dataset.
    pub async fn delete(&self, id: impl AsRef<str>) -> Result<()> {
        let url = format!("/api/v1/datasets/{}", id.as_ref());
        self.http.delete(&url).await
    }

    /// Gets dataset statistics.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let stats = client.datasets().stats("ds_abc123").await?;
    ///
    /// println!("Records: {}", stats.record_count);
    /// println!("Size: {} bytes", stats.size_bytes);
    ///
    /// if let Some(pii) = stats.pii_stats {
    ///     println!("PII entities found: {}", pii.total_entities);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stats(&self, id: impl AsRef<str>) -> Result<DatasetStats> {
        let url = format!("/api/v1/datasets/{}/stats", id.as_ref());
        self.http.get(&url).await
    }

    /// Archives a dataset.
    ///
    /// Archived datasets are read-only.
    pub async fn archive(&self, id: impl AsRef<str>) -> Result<Dataset> {
        let url = format!("/api/v1/datasets/{}/archive", id.as_ref());
        self.http.post(&url, &()).await
    }

    /// Unarchives a dataset.
    pub async fn unarchive(&self, id: impl AsRef<str>) -> Result<Dataset> {
        let url = format!("/api/v1/datasets/{}/unarchive", id.as_ref());
        self.http.post(&url, &()).await
    }

    /// Clones a dataset.
    ///
    /// Creates a new dataset with the same schema but no records.
    pub async fn clone(&self, id: impl AsRef<str>, new_name: &str) -> Result<Dataset> {
        #[derive(serde::Serialize)]
        struct CloneRequest<'a> {
            name: &'a str,
        }

        let url = format!("/api/v1/datasets/{}/clone", id.as_ref());
        self.http.post(&url, &CloneRequest { name: new_name }).await
    }

    /// Triggers a PII scan on all records in the dataset.
    pub async fn scan_pii(&self, id: impl AsRef<str>) -> Result<()> {
        let url = format!("/api/v1/datasets/{}/scan", id.as_ref());
        self.http.post::<(), _>(&url, &()).await?;
        Ok(())
    }
}

impl std::fmt::Debug for DatasetsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatasetsService").finish_non_exhaustive()
    }
}
