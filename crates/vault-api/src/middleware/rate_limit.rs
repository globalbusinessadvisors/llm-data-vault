//! Rate limiting middleware.

use crate::ApiError;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per second.
    pub requests_per_second: u32,
    /// Burst size.
    pub burst_size: u32,
    /// Window duration.
    pub window: Duration,
    /// Enable per-user limits.
    pub per_user: bool,
    /// Enable per-IP limits.
    pub per_ip: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 200,
            window: Duration::from_secs(1),
            per_user: true,
            per_ip: true,
        }
    }
}

/// Rate limiter using token bucket algorithm.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Buckets by key.
    buckets: Arc<DashMap<String, TokenBucket>>,
}

/// Token bucket for rate limiting.
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;

        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_update = now;
    }

    fn available(&self) -> f64 {
        self.tokens
    }
}

impl RateLimiter {
    /// Creates a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(DashMap::new()),
        }
    }

    /// Checks if a request is allowed.
    pub fn check(&self, key: &str) -> RateLimitResult {
        let capacity = self.config.burst_size as f64;
        let refill_rate = self.config.requests_per_second as f64;

        let mut entry = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));

        if entry.try_consume() {
            RateLimitResult::Allowed {
                remaining: entry.available() as u32,
                reset_after: Duration::from_secs_f64(1.0 / refill_rate),
            }
        } else {
            RateLimitResult::Limited {
                retry_after: Duration::from_secs_f64(1.0 / refill_rate),
            }
        }
    }

    /// Gets the rate limit key for a request.
    pub fn get_key(&self, ip: Option<IpAddr>, user_id: Option<&str>) -> String {
        match (self.config.per_user, self.config.per_ip, user_id, ip) {
            (true, _, Some(user), _) => format!("user:{}", user),
            (_, true, _, Some(ip)) => format!("ip:{}", ip),
            _ => "global".to_string(),
        }
    }

    /// Cleans up expired buckets.
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_update) < max_age
        });
    }
}

/// Rate limit check result.
#[derive(Debug)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed {
        /// Remaining requests in window.
        remaining: u32,
        /// Time until reset.
        reset_after: Duration,
    },
    /// Request is rate limited.
    Limited {
        /// Time until retry is allowed.
        retry_after: Duration,
    },
}

/// Rate limit middleware.
#[derive(Clone)]
pub struct RateLimitMiddleware {
    limiter: RateLimiter,
}

impl RateLimitMiddleware {
    /// Creates a new rate limit middleware.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiter: RateLimiter::new(config),
        }
    }

    /// Creates with default configuration.
    pub fn default_config() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

/// Rate limit layer function.
pub async fn rate_limit_layer(
    limiter: RateLimiter,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract client IP from headers or connection
    let ip = extract_client_ip(&req);

    // Extract user ID from extensions (set by auth middleware)
    let user_id = req
        .extensions()
        .get::<vault_access::TokenClaims>()
        .map(|c| c.sub.as_str());

    let key = limiter.get_key(ip, user_id);

    match limiter.check(&key) {
        RateLimitResult::Allowed { remaining, reset_after } => {
            let mut response = next.run(req).await;

            // Add rate limit headers
            let headers = response.headers_mut();
            headers.insert(
                "X-RateLimit-Remaining",
                remaining.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-RateLimit-Reset",
                reset_after.as_secs().to_string().parse().unwrap(),
            );

            Ok(response)
        }
        RateLimitResult::Limited { retry_after } => {
            warn!(
                key = %key,
                retry_after_secs = retry_after.as_secs(),
                "Rate limit exceeded"
            );

            Err(ApiError::RateLimited(format!(
                "Rate limit exceeded. Retry after {} seconds",
                retry_after.as_secs()
            )))
        }
    }
}

/// Extracts client IP from request.
fn extract_client_ip(req: &Request) -> Option<IpAddr> {
    // Check X-Forwarded-For header
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(ip_str) = value.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.parse() {
                return Some(ip);
            }
        }
    }

    None
}

/// Sliding window rate limiter.
pub struct SlidingWindowLimiter {
    config: RateLimitConfig,
    windows: Arc<DashMap<String, Mutex<VecDeque<Instant>>>>,
}

impl SlidingWindowLimiter {
    /// Creates a new sliding window limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Arc::new(DashMap::new()),
        }
    }

    /// Checks if a request is allowed.
    pub fn check(&self, key: &str) -> RateLimitResult {
        let now = Instant::now();
        let window = self.config.window;
        let limit = self.config.requests_per_second * window.as_secs() as u32;

        let mut entry = self
            .windows
            .entry(key.to_string())
            .or_insert_with(|| Mutex::new(VecDeque::new()));

        let mut timestamps = entry.lock();

        // Remove old timestamps
        while let Some(&oldest) = timestamps.front() {
            if now.duration_since(oldest) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() < limit as usize {
            timestamps.push_back(now);
            RateLimitResult::Allowed {
                remaining: limit - timestamps.len() as u32,
                reset_after: window,
            }
        } else {
            let oldest = timestamps.front().copied().unwrap_or(now);
            let retry_after = window.saturating_sub(now.duration_since(oldest));
            RateLimitResult::Limited { retry_after }
        }
    }

    /// Cleans up old windows.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = self.config.window;

        self.windows.retain(|_, entry| {
            let timestamps = entry.lock();
            timestamps
                .back()
                .map(|&t| now.duration_since(t) < window * 2)
                .unwrap_or(false)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 10,
            burst_size: 10,
            ..Default::default()
        });

        for _ in 0..10 {
            let result = limiter.check("test");
            assert!(matches!(result, RateLimitResult::Allowed { .. }));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 10,
            burst_size: 5,
            ..Default::default()
        });

        // Use up the burst
        for _ in 0..5 {
            limiter.check("test");
        }

        // Should be rate limited
        let result = limiter.check("test");
        assert!(matches!(result, RateLimitResult::Limited { .. }));
    }

    #[test]
    fn test_rate_limiter_key_generation() {
        let limiter = RateLimiter::new(RateLimitConfig {
            per_user: true,
            per_ip: true,
            ..Default::default()
        });

        // With user, should use user key
        let key = limiter.get_key(
            Some("192.168.1.1".parse().unwrap()),
            Some("user-123"),
        );
        assert!(key.starts_with("user:"));

        // Without user, should use IP
        let key = limiter.get_key(
            Some("192.168.1.1".parse().unwrap()),
            None,
        );
        assert!(key.starts_with("ip:"));

        // Without both, should use global
        let key = limiter.get_key(None, None);
        assert_eq!(key, "global");
    }

    #[test]
    fn test_sliding_window_limiter() {
        let limiter = SlidingWindowLimiter::new(RateLimitConfig {
            requests_per_second: 10,
            burst_size: 10,
            window: Duration::from_secs(1),
            ..Default::default()
        });

        // Should allow requests within limit
        for _ in 0..10 {
            let result = limiter.check("test");
            assert!(matches!(result, RateLimitResult::Allowed { .. }));
        }

        // Should block after limit
        let result = limiter.check("test");
        assert!(matches!(result, RateLimitResult::Limited { .. }));
    }
}
