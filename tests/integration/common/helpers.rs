//! Test helper functions.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
use tower::ServiceExt;

/// HTTP client wrapper for testing.
pub struct TestClient {
    app: Router,
    auth_token: Option<String>,
}

impl TestClient {
    /// Creates a new test client.
    pub fn new(app: Router) -> Self {
        Self {
            app,
            auth_token: None,
        }
    }

    /// Sets the authentication token.
    pub fn with_auth(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Sets the authentication token (mutable).
    pub fn set_auth(&mut self, token: &str) {
        self.auth_token = Some(token.to_string());
    }

    /// Clears the authentication token.
    pub fn clear_auth(&mut self) {
        self.auth_token = None;
    }

    /// Makes a GET request.
    pub async fn get(&self, uri: &str) -> TestResponse {
        self.request(Method::GET, uri, None::<()>).await
    }

    /// Makes a POST request with JSON body.
    pub async fn post<T: Serialize>(&self, uri: &str, body: T) -> TestResponse {
        self.request(Method::POST, uri, Some(body)).await
    }

    /// Makes a PUT request with JSON body.
    pub async fn put<T: Serialize>(&self, uri: &str, body: T) -> TestResponse {
        self.request(Method::PUT, uri, Some(body)).await
    }

    /// Makes a PATCH request with JSON body.
    pub async fn patch<T: Serialize>(&self, uri: &str, body: T) -> TestResponse {
        self.request(Method::PATCH, uri, Some(body)).await
    }

    /// Makes a DELETE request.
    pub async fn delete(&self, uri: &str) -> TestResponse {
        self.request(Method::DELETE, uri, None::<()>).await
    }

    /// Makes an HTTP request.
    async fn request<T: Serialize>(&self, method: Method, uri: &str, body: Option<T>) -> TestResponse {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");

        if let Some(ref token) = self.auth_token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
        }

        let body = match body {
            Some(b) => Body::from(serde_json::to_vec(&b).expect("Failed to serialize body")),
            None => Body::empty(),
        };

        let request = builder.body(body).expect("Failed to build request");

        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to execute request");

        TestResponse::new(response).await
    }
}

/// Test response wrapper.
#[derive(Debug)]
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: Vec<u8>,
}

impl TestResponse {
    /// Creates a new test response from axum response.
    async fn new(response: Response) -> Self {
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body")
            .to_vec();

        Self {
            status,
            headers,
            body,
        }
    }

    /// Returns the response body as string.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Parses the response body as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).expect("Failed to parse JSON response")
    }

    /// Parses the response body as generic JSON value.
    pub fn json_value(&self) -> Value {
        serde_json::from_slice(&self.body).expect("Failed to parse JSON response")
    }

    /// Asserts the status code.
    pub fn assert_status(&self, expected: StatusCode) -> &Self {
        assert_eq!(
            self.status, expected,
            "Expected status {}, got {}. Body: {}",
            expected,
            self.status,
            self.text()
        );
        self
    }

    /// Asserts the status is 200 OK.
    pub fn assert_ok(&self) -> &Self {
        self.assert_status(StatusCode::OK)
    }

    /// Asserts the status is 201 Created.
    pub fn assert_created(&self) -> &Self {
        self.assert_status(StatusCode::CREATED)
    }

    /// Asserts the status is 204 No Content.
    pub fn assert_no_content(&self) -> &Self {
        self.assert_status(StatusCode::NO_CONTENT)
    }

    /// Asserts the status is 400 Bad Request.
    pub fn assert_bad_request(&self) -> &Self {
        self.assert_status(StatusCode::BAD_REQUEST)
    }

    /// Asserts the status is 401 Unauthorized.
    pub fn assert_unauthorized(&self) -> &Self {
        self.assert_status(StatusCode::UNAUTHORIZED)
    }

    /// Asserts the status is 403 Forbidden.
    pub fn assert_forbidden(&self) -> &Self {
        self.assert_status(StatusCode::FORBIDDEN)
    }

    /// Asserts the status is 404 Not Found.
    pub fn assert_not_found(&self) -> &Self {
        self.assert_status(StatusCode::NOT_FOUND)
    }

    /// Asserts the status is 409 Conflict.
    pub fn assert_conflict(&self) -> &Self {
        self.assert_status(StatusCode::CONFLICT)
    }

    /// Asserts the status is 429 Too Many Requests.
    pub fn assert_rate_limited(&self) -> &Self {
        self.assert_status(StatusCode::TOO_MANY_REQUESTS)
    }

    /// Asserts the status is a success (2xx).
    pub fn assert_success(&self) -> &Self {
        assert!(
            self.status.is_success(),
            "Expected success status, got {}. Body: {}",
            self.status,
            self.text()
        );
        self
    }

    /// Asserts the status is a client error (4xx).
    pub fn assert_client_error(&self) -> &Self {
        assert!(
            self.status.is_client_error(),
            "Expected client error, got {}",
            self.status
        );
        self
    }

    /// Asserts the status is a server error (5xx).
    pub fn assert_server_error(&self) -> &Self {
        assert!(
            self.status.is_server_error(),
            "Expected server error, got {}",
            self.status
        );
        self
    }

    /// Asserts a header exists with expected value.
    pub fn assert_header(&self, name: &str, expected: &str) -> &Self {
        let actual = self
            .headers
            .get(name)
            .map(|v| v.to_str().expect("Invalid header value"))
            .expect(&format!("Header '{}' not found", name));
        assert_eq!(
            actual, expected,
            "Header '{}' expected '{}', got '{}'",
            name, expected, actual
        );
        self
    }

    /// Asserts the response body contains a string.
    pub fn assert_body_contains(&self, expected: &str) -> &Self {
        let body = self.text();
        assert!(
            body.contains(expected),
            "Expected body to contain '{}', body: {}",
            expected,
            body
        );
        self
    }

    /// Asserts a JSON field exists.
    pub fn assert_json_field(&self, path: &str) -> &Self {
        let json: Value = self.json_value();
        let value = json_path(&json, path);
        assert!(
            value.is_some(),
            "JSON field '{}' not found in response: {}",
            path,
            serde_json::to_string_pretty(&json).unwrap()
        );
        self
    }

    /// Asserts a JSON field equals expected value.
    pub fn assert_json_eq(&self, path: &str, expected: &Value) -> &Self {
        let json: Value = self.json_value();
        let value = json_path(&json, path);
        assert!(
            value.is_some(),
            "JSON field '{}' not found",
            path
        );
        assert_eq!(
            value.unwrap(),
            expected,
            "JSON field '{}' mismatch",
            path
        );
        self
    }
}

/// Simple JSON path accessor.
fn json_path<'a>(json: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = json;
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        // Handle array index
        if let Some(index_str) = segment.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Ok(index) = index_str.parse::<usize>() {
                current = current.get(index)?;
                continue;
            }
        }
        current = current.get(segment)?;
    }
    Some(current)
}

/// Generates a random string of specified length.
pub fn random_string(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Generates a random UUID string.
pub fn random_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Waits for a condition with timeout.
pub async fn wait_for<F, Fut>(
    condition: F,
    timeout: Duration,
    check_interval: Duration,
) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if condition().await {
            return true;
        }
        tokio::time::sleep(check_interval).await;
    }
    false
}

/// Retry an operation with backoff.
pub async fn retry<F, Fut, T, E>(
    operation: F,
    max_retries: usize,
    initial_delay: Duration,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut delay = initial_delay;
    let mut last_error = None;

    for _ in 0..max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }

    Err(last_error.expect("No retries performed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_path() {
        let json = serde_json::json!({
            "data": {
                "user": {
                    "name": "Test"
                },
                "items": [1, 2, 3]
            }
        });

        assert_eq!(json_path(&json, "data.user.name"), Some(&serde_json::json!("Test")));
        assert_eq!(json_path(&json, "data.items.[0]"), Some(&serde_json::json!(1)));
        assert_eq!(json_path(&json, "nonexistent"), None);
    }

    #[test]
    fn test_random_string() {
        let s1 = random_string(10);
        let s2 = random_string(10);
        assert_eq!(s1.len(), 10);
        assert_ne!(s1, s2);
    }
}
