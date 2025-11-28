//! Client configuration.

use std::time::Duration;

use crate::auth::AuthProvider;

/// Configuration for the Vault client.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Base URL of the Vault API.
    pub base_url: String,

    /// Authentication provider.
    pub auth: AuthProvider,

    /// Request timeout.
    pub timeout: Duration,

    /// Connection timeout.
    pub connect_timeout: Duration,

    /// Whether to follow redirects.
    pub follow_redirects: bool,

    /// Maximum number of redirects to follow.
    pub max_redirects: usize,

    /// User agent string.
    pub user_agent: String,

    /// Retry configuration.
    pub retry: RetryConfig,

    /// Optional proxy URL.
    pub proxy: Option<String>,

    /// Whether to verify TLS certificates.
    pub tls_verify: bool,
}

impl VaultConfig {
    /// Creates a new configuration with the specified base URL.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth: AuthProvider::default(),
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            follow_redirects: true,
            max_redirects: 10,
            user_agent: crate::USER_AGENT.to_string(),
            retry: RetryConfig::default(),
            proxy: None,
            tls_verify: true,
        }
    }

    /// Sets the authentication provider.
    #[must_use]
    pub fn with_auth(mut self, auth: AuthProvider) -> Self {
        self.auth = auth;
        self
    }

    /// Sets the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the connection timeout.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets whether to follow redirects.
    #[must_use]
    pub fn with_follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Sets the maximum number of redirects.
    #[must_use]
    pub fn with_max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }

    /// Sets the user agent string.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Sets the retry configuration.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    /// Disables retries.
    #[must_use]
    pub fn without_retry(mut self) -> Self {
        self.retry = RetryConfig::disabled();
        self
    }

    /// Sets the proxy URL.
    #[must_use]
    pub fn with_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Sets whether to verify TLS certificates.
    #[must_use]
    pub fn with_tls_verify(mut self, verify: bool) -> Self {
        self.tls_verify = verify;
        self
    }

    /// Builds the full URL for an API path.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self::new("http://localhost:8080")
    }
}

/// Retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,

    /// Initial backoff duration.
    pub initial_backoff: Duration,

    /// Maximum backoff duration.
    pub max_backoff: Duration,

    /// Backoff multiplier.
    pub multiplier: f64,

    /// Whether retries are enabled.
    pub enabled: bool,

    /// HTTP status codes to retry.
    pub retry_status_codes: Vec<u16>,
}

impl RetryConfig {
    /// Creates a new retry configuration.
    #[must_use]
    pub fn new(max_retries: u32) -> Self {
        Self {
            max_retries,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            multiplier: 2.0,
            enabled: true,
            retry_status_codes: vec![429, 500, 502, 503, 504],
        }
    }

    /// Creates a disabled retry configuration.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            multiplier: 1.0,
            enabled: false,
            retry_status_codes: Vec::new(),
        }
    }

    /// Sets the initial backoff.
    #[must_use]
    pub fn with_initial_backoff(mut self, backoff: Duration) -> Self {
        self.initial_backoff = backoff;
        self
    }

    /// Sets the maximum backoff.
    #[must_use]
    pub fn with_max_backoff(mut self, backoff: Duration) -> Self {
        self.max_backoff = backoff;
        self
    }

    /// Sets the multiplier.
    #[must_use]
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Sets the status codes to retry.
    #[must_use]
    pub fn with_retry_status_codes(mut self, codes: Vec<u16>) -> Self {
        self.retry_status_codes = codes;
        self
    }

    /// Checks if a status code should be retried.
    #[must_use]
    pub fn should_retry(&self, status_code: u16) -> bool {
        self.enabled && self.retry_status_codes.contains(&status_code)
    }

    /// Calculates the backoff duration for a given attempt.
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let backoff = self.initial_backoff.as_millis() as f64
            * self.multiplier.powi(attempt.saturating_sub(1) as i32);
        let backoff_ms = backoff.min(self.max_backoff.as_millis() as f64) as u64;
        Duration::from_millis(backoff_ms)
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::new(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_url_building() {
        let config = VaultConfig::new("https://api.example.com");
        assert_eq!(config.url("/api/v1/datasets"), "https://api.example.com/api/v1/datasets");
    }

    #[test]
    fn test_config_strips_trailing_slash() {
        let config = VaultConfig::new("https://api.example.com/");
        assert_eq!(config.base_url, "https://api.example.com");
    }

    #[test]
    fn test_retry_backoff_calculation() {
        let retry = RetryConfig::new(3)
            .with_initial_backoff(Duration::from_millis(100))
            .with_multiplier(2.0);

        assert_eq!(retry.backoff_for_attempt(0), Duration::ZERO);
        assert_eq!(retry.backoff_for_attempt(1), Duration::from_millis(100));
        assert_eq!(retry.backoff_for_attempt(2), Duration::from_millis(200));
        assert_eq!(retry.backoff_for_attempt(3), Duration::from_millis(400));
    }

    #[test]
    fn test_retry_max_backoff() {
        let retry = RetryConfig::new(10)
            .with_initial_backoff(Duration::from_secs(1))
            .with_max_backoff(Duration::from_secs(5))
            .with_multiplier(2.0);

        // 1 * 2^9 = 512 seconds, but max is 5 seconds
        assert_eq!(retry.backoff_for_attempt(10), Duration::from_secs(5));
    }

    #[test]
    fn test_retry_should_retry() {
        let retry = RetryConfig::new(3);
        assert!(retry.should_retry(429));
        assert!(retry.should_retry(503));
        assert!(!retry.should_retry(400));
        assert!(!retry.should_retry(404));

        let disabled = RetryConfig::disabled();
        assert!(!disabled.should_retry(503));
    }
}
