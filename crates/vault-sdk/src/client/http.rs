//! HTTP client wrapper with retry and authentication.

use std::time::Duration;

use bytes::Bytes;
use reqwest::{Client, Method, Request, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, warn, instrument};

use crate::auth::Authenticator;
use crate::error::{ApiError, Error, Result};

use super::config::VaultConfig;

/// Internal HTTP client with retry logic.
pub struct HttpClient {
    client: Client,
    config: VaultConfig,
}

impl HttpClient {
    /// Creates a new HTTP client.
    pub fn new(config: &VaultConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .user_agent(&config.user_agent)
            .gzip(true)
            .brotli(true);

        if config.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::limited(config.max_redirects));
        } else {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        if !config.tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| Error::config(format!("Invalid proxy URL: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|e| Error::config(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            config: config.clone(),
        })
    }

    /// Makes a GET request.
    #[instrument(skip(self), fields(url = %url))]
    pub async fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        self.request(Method::GET, url, Option::<&()>::None).await
    }

    /// Makes a POST request.
    #[instrument(skip(self, body), fields(url = %url))]
    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, url: &str, body: &B) -> Result<T> {
        self.request(Method::POST, url, Some(body)).await
    }

    /// Makes a PUT request.
    #[instrument(skip(self, body), fields(url = %url))]
    pub async fn put<T: DeserializeOwned, B: Serialize>(&self, url: &str, body: &B) -> Result<T> {
        self.request(Method::PUT, url, Some(body)).await
    }

    /// Makes a PATCH request.
    #[instrument(skip(self, body), fields(url = %url))]
    pub async fn patch<T: DeserializeOwned, B: Serialize>(&self, url: &str, body: &B) -> Result<T> {
        self.request(Method::PATCH, url, Some(body)).await
    }

    /// Makes a DELETE request.
    #[instrument(skip(self), fields(url = %url))]
    pub async fn delete(&self, url: &str) -> Result<()> {
        self.request_no_content(Method::DELETE, url).await
    }

    /// Makes a request and returns raw bytes.
    #[instrument(skip(self), fields(url = %url))]
    pub async fn get_bytes(&self, url: &str) -> Result<Bytes> {
        let full_url = self.config.url(url);
        let response = self.execute_with_retry(Method::GET, &full_url, Option::<&()>::None).await?;

        response
            .bytes()
            .await
            .map_err(Error::from)
    }

    /// Makes a request with a JSON body and returns a JSON response.
    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let full_url = self.config.url(url);
        let response = self.execute_with_retry(method, &full_url, body).await?;

        let status = response.status();
        let bytes = response.bytes().await?;

        if bytes.is_empty() && std::any::type_name::<T>() == "()" {
            // Return unit type for empty responses
            return Ok(serde_json::from_str("null")?);
        }

        serde_json::from_slice(&bytes).map_err(|e| {
            debug!("Failed to parse response: {}", String::from_utf8_lossy(&bytes));
            Error::Serialization(e)
        })
    }

    /// Makes a request that expects no content.
    async fn request_no_content(&self, method: Method, url: &str) -> Result<()> {
        let full_url = self.config.url(url);
        let _response = self.execute_with_retry(method, &full_url, Option::<&()>::None).await?;
        Ok(())
    }

    /// Executes a request with retry logic.
    async fn execute_with_retry<B: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<Response> {
        let retry = &self.config.retry;
        let mut attempt = 0;

        loop {
            let result = self.execute_once(method.clone(), url, body).await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        return Ok(response);
                    }

                    // Check if we should retry
                    if retry.enabled
                        && attempt < retry.max_retries
                        && retry.should_retry(status.as_u16())
                    {
                        attempt += 1;
                        let backoff = retry.backoff_for_attempt(attempt);
                        warn!(
                            status = %status,
                            attempt = attempt,
                            backoff_ms = backoff.as_millis(),
                            "Request failed, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        continue;
                    }

                    // No retry, convert to error
                    return Err(self.response_to_error(response).await);
                }
                Err(e) => {
                    // Network errors may be retryable
                    if retry.enabled && attempt < retry.max_retries && e.is_retryable() {
                        attempt += 1;
                        let backoff = retry.backoff_for_attempt(attempt);
                        warn!(
                            error = %e,
                            attempt = attempt,
                            backoff_ms = backoff.as_millis(),
                            "Request failed with network error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        continue;
                    }

                    return Err(e);
                }
            }
        }
    }

    /// Executes a single request.
    async fn execute_once<B: Serialize>(
        &self,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<Response> {
        let mut request = self.client.request(method, url);

        // Apply authentication
        request = self.config.auth.authenticate(request).await?;

        // Add body if present
        if let Some(b) = body {
            request = request.json(b);
        }

        request = request.header("Accept", "application/json");

        let response = request.send().await?;
        Ok(response)
    }

    /// Converts an error response to an Error.
    async fn response_to_error(&self, response: Response) -> Error {
        let status = response.status();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Try to parse as API error
        if let Ok(bytes) = response.bytes().await {
            if let Ok(api_error) = serde_json::from_slice::<ApiError>(&bytes) {
                return api_error.into_error();
            }

            // Couldn't parse as API error, create generic error
            let body = String::from_utf8_lossy(&bytes);
            return Self::status_to_error(status, body.to_string(), request_id);
        }

        Self::status_to_error(status, "Unknown error".to_string(), request_id)
    }

    /// Converts a status code to an error.
    fn status_to_error(status: StatusCode, message: String, request_id: Option<String>) -> Error {
        match status {
            StatusCode::BAD_REQUEST => Error::bad_request(message),
            StatusCode::UNAUTHORIZED => Error::unauthorized(message),
            StatusCode::FORBIDDEN => Error::forbidden(message),
            StatusCode::NOT_FOUND => Error::not_found("resource", "unknown"),
            StatusCode::CONFLICT => Error::conflict(message),
            StatusCode::PAYLOAD_TOO_LARGE => Error::PayloadTooLarge { max_size: 0 },
            StatusCode::TOO_MANY_REQUESTS => Error::RateLimited { retry_after_secs: 60 },
            StatusCode::SERVICE_UNAVAILABLE => Error::ServiceUnavailable { message },
            _ => Error::server_error(message, request_id),
        }
    }
}

impl Clone for HttpClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            config: self.config.clone(),
        }
    }
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("base_url", &self.config.base_url)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_client_creation() {
        let config = VaultConfig::new("http://localhost:8080");
        let result = HttpClient::new(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_status_to_error_mapping() {
        assert!(matches!(
            HttpClient::status_to_error(StatusCode::BAD_REQUEST, "test".into(), None),
            Error::BadRequest { .. }
        ));

        assert!(matches!(
            HttpClient::status_to_error(StatusCode::UNAUTHORIZED, "test".into(), None),
            Error::Unauthorized { .. }
        ));

        assert!(matches!(
            HttpClient::status_to_error(StatusCode::FORBIDDEN, "test".into(), None),
            Error::Forbidden { .. }
        ));

        assert!(matches!(
            HttpClient::status_to_error(StatusCode::NOT_FOUND, "test".into(), None),
            Error::NotFound { .. }
        ));

        assert!(matches!(
            HttpClient::status_to_error(StatusCode::TOO_MANY_REQUESTS, "test".into(), None),
            Error::RateLimited { .. }
        ));
    }
}
