//! AWS S3 storage backend.

use crate::{StorageError, StorageResult};
use super::{ObjectMetadata, StorageBackend, StorageStats};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;

#[cfg(feature = "aws-s3")]
use aws_sdk_s3::{
    primitives::ByteStream,
    Client,
};

/// S3 storage backend configuration.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name.
    pub bucket: String,
    /// Key prefix.
    pub prefix: Option<String>,
    /// AWS region.
    pub region: Option<String>,
    /// Custom endpoint (for MinIO, LocalStack).
    pub endpoint: Option<String>,
    /// Force path-style URLs.
    pub path_style: bool,
}

impl S3Config {
    /// Creates a new S3 config.
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: None,
            region: None,
            endpoint: None,
            path_style: false,
        }
    }

    /// Sets key prefix.
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Sets region.
    #[must_use]
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Sets custom endpoint.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets path-style URLs.
    #[must_use]
    pub fn with_path_style(mut self, path_style: bool) -> Self {
        self.path_style = path_style;
        self
    }
}

/// S3 storage backend.
#[cfg(feature = "aws-s3")]
pub struct S3Backend {
    client: Client,
    config: S3Config,
}

#[cfg(feature = "aws-s3")]
impl S3Backend {
    /// Creates a new S3 backend.
    pub async fn new(config: S3Config) -> StorageResult<Self> {
        let mut aws_config_builder = aws_config::from_env();

        if let Some(ref region) = config.region {
            aws_config_builder = aws_config_builder.region(
                aws_sdk_s3::config::Region::new(region.clone()),
            );
        }

        let aws_config = aws_config_builder.load().await;

        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config);

        if let Some(ref endpoint) = config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        if config.path_style {
            s3_config_builder = s3_config_builder.force_path_style(true);
        }

        let client = Client::from_conf(s3_config_builder.build());

        Ok(Self { client, config })
    }

    /// Resolves a key with the configured prefix.
    fn full_key(&self, key: &str) -> String {
        match &self.config.prefix {
            Some(prefix) => format!("{}/{}", prefix.trim_end_matches('/'), key),
            None => key.to_string(),
        }
    }

    /// Strips the prefix from a full key.
    fn strip_prefix(&self, full_key: &str) -> String {
        match &self.config.prefix {
            Some(prefix) => {
                let p = format!("{}/", prefix.trim_end_matches('/'));
                full_key.strip_prefix(&p).unwrap_or(full_key).to_string()
            }
            None => full_key.to_string(),
        }
    }
}

#[cfg(feature = "aws-s3")]
#[async_trait]
impl StorageBackend for S3Backend {
    fn name(&self) -> &str {
        "s3"
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        let full_key = self.full_key(key);

        self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&full_key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        let full_key = self.full_key(key);

        let response = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(&full_key)
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("NoSuchKey") || err_str.contains("404") {
                    StorageError::NotFound(key.to_string())
                } else {
                    StorageError::Backend(err_str)
                }
            })?;

        let data = response
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(Bytes::from(data.to_vec()))
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let full_key = self.full_key(key);

        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&full_key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let full_key = self.full_key(key);

        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(&full_key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("404") || err_str.contains("NotFound") {
                    Ok(false)
                } else {
                    Err(StorageError::Backend(err_str))
                }
            }
        }
    }

    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let search_prefix = match (&self.config.prefix, prefix) {
            (Some(base), Some(p)) => format!("{}/{}", base.trim_end_matches('/'), p),
            (Some(base), None) => format!("{}/", base.trim_end_matches('/')),
            (None, Some(p)) => p.to_string(),
            (None, None) => String::new(),
        };

        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.config.bucket)
                .prefix(&search_prefix);

            if let Some(token) = continuation_token.take() {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;

            if let Some(contents) = response.contents {
                for object in contents {
                    if let Some(key) = object.key {
                        keys.push(self.strip_prefix(&key));
                    }
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation_token = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(keys)
    }

    async fn head(&self, key: &str) -> StorageResult<ObjectMetadata> {
        let full_key = self.full_key(key);

        let response = self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(&full_key)
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("404") || err_str.contains("NotFound") {
                    StorageError::NotFound(key.to_string())
                } else {
                    StorageError::Backend(err_str)
                }
            })?;

        let last_modified = response
            .last_modified
            .and_then(|dt| {
                chrono::DateTime::parse_from_rfc3339(&dt.to_string())
                    .ok()
                    .map(|d| d.with_timezone(&chrono::Utc))
            })
            .unwrap_or_else(chrono::Utc::now);

        // Extract custom metadata
        let mut metadata = HashMap::new();
        if let Some(meta) = response.metadata {
            metadata = meta;
        }

        Ok(ObjectMetadata {
            size: response.content_length.unwrap_or(0) as u64,
            content_type: response.content_type,
            last_modified,
            etag: response.e_tag,
            metadata,
        })
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        // S3 doesn't have a direct way to get bucket stats
        // We'd need to list all objects which can be expensive
        let keys = self.list(None).await?;
        let object_count = keys.len() as u64;

        // For total size, we'd need to head each object
        // This is expensive, so we return 0 and let the caller compute if needed

        Ok(StorageStats {
            object_count,
            total_size: 0, // Would need to iterate all objects
            available_space: None,
            custom: {
                let mut m = HashMap::new();
                m.insert(
                    "bucket".to_string(),
                    serde_json::Value::String(self.config.bucket.clone()),
                );
                m
            },
        })
    }
}

/// Stub S3 backend when feature is disabled.
#[cfg(not(feature = "aws-s3"))]
pub struct S3Backend;

#[cfg(not(feature = "aws-s3"))]
impl S3Backend {
    /// Creates a new S3 backend (stub).
    pub async fn new(_config: S3Config) -> StorageResult<Self> {
        Err(StorageError::Configuration(
            "S3 support not enabled. Enable the 'aws-s3' feature.".to_string(),
        ))
    }
}
