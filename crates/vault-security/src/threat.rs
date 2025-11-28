//! Threat detection and prevention.
//!
//! Provides comprehensive threat detection including:
//! - IP-based rate limiting
//! - IP blocklist/allowlist
//! - Failed login tracking
//! - Brute force protection
//! - Anomaly detection
//! - User agent filtering

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use tracing::{debug, info, warn};

use crate::config::{ThreatConfig, RateLimitConfig};
use crate::error::{SecurityError, Result, ThreatLevel};

/// Threat detector for identifying and blocking malicious activity.
pub struct ThreatDetector {
    config: ThreatConfig,
    rate_limiters: DashMap<String, RateLimiter>,
    failed_logins: DashMap<String, FailedLoginTracker>,
    blocked_ips: RwLock<Vec<IpNetwork>>,
    allowed_ips: RwLock<Vec<IpNetwork>>,
    threat_events: DashMap<String, Vec<ThreatEvent>>,
}

/// A rate limiter using token bucket algorithm.
struct RateLimiter {
    tokens: f64,
    last_update: Instant,
    max_tokens: f64,
    refill_rate: f64,
}

impl RateLimiter {
    fn new(max_tokens: u32, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens as f64,
            last_update: Instant::now(),
            max_tokens: max_tokens as f64,
            refill_rate,
        }
    }

    fn try_acquire(&mut self) -> bool {
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
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;
    }

    fn tokens_remaining(&self) -> u32 {
        self.tokens as u32
    }

    fn time_until_refill(&self) -> Duration {
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            Duration::from_secs_f64(needed / self.refill_rate)
        }
    }
}

/// Tracks failed login attempts.
struct FailedLoginTracker {
    attempts: Vec<Instant>,
    locked_until: Option<Instant>,
}

impl FailedLoginTracker {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            locked_until: None,
        }
    }

    fn record_failure(&mut self, window: Duration) {
        let now = Instant::now();
        let cutoff = now - window;

        // Remove old attempts
        self.attempts.retain(|t| *t > cutoff);
        self.attempts.push(now);
    }

    fn attempt_count(&self, window: Duration) -> usize {
        let cutoff = Instant::now() - window;
        self.attempts.iter().filter(|t| **t > cutoff).count()
    }

    fn lock(&mut self, duration: Duration) {
        self.locked_until = Some(Instant::now() + duration);
    }

    fn is_locked(&self) -> bool {
        self.locked_until.map_or(false, |t| Instant::now() < t)
    }

    fn unlock(&mut self) {
        self.locked_until = None;
        self.attempts.clear();
    }
}

/// A recorded threat event.
#[derive(Debug, Clone)]
pub struct ThreatEvent {
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Threat level.
    pub level: ThreatLevel,
    /// Threat type.
    pub threat_type: String,
    /// Event message.
    pub message: String,
    /// Source IP.
    pub source_ip: Option<IpAddr>,
    /// User ID if authenticated.
    pub user_id: Option<String>,
    /// Request path.
    pub request_path: Option<String>,
    /// Additional context.
    pub context: HashMap<String, String>,
}

impl ThreatEvent {
    /// Creates a new threat event.
    #[must_use]
    pub fn new(level: ThreatLevel, threat_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            threat_type: threat_type.into(),
            message: message.into(),
            source_ip: None,
            user_id: None,
            request_path: None,
            context: HashMap::new(),
        }
    }

    /// Sets the source IP.
    #[must_use]
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Sets the user ID.
    #[must_use]
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Sets the request path.
    #[must_use]
    pub fn with_request_path(mut self, path: impl Into<String>) -> Self {
        self.request_path = Some(path.into());
        self
    }

    /// Adds context.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

/// IP blocklist for threat prevention.
#[derive(Debug, Clone, Default)]
pub struct IpBlocklist {
    networks: Vec<IpNetwork>,
}

impl IpBlocklist {
    /// Creates a new blocklist.
    #[must_use]
    pub fn new() -> Self {
        Self { networks: Vec::new() }
    }

    /// Adds a network to the blocklist.
    ///
    /// # Errors
    ///
    /// Returns an error if the network is invalid.
    pub fn add(&mut self, network: &str) -> Result<()> {
        let net: IpNetwork = network.parse().map_err(|e| {
            SecurityError::configuration_field(format!("Invalid network: {}", e), "ip_blocklist")
        })?;
        self.networks.push(net);
        Ok(())
    }

    /// Checks if an IP is blocked.
    #[must_use]
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(ip))
    }
}

impl ThreatDetector {
    /// Creates a new threat detector with the given configuration.
    #[must_use]
    pub fn new(config: ThreatConfig) -> Self {
        let blocked_ips = config.ip_blocklist
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let allowed_ips = config.ip_allowlist
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        Self {
            config,
            rate_limiters: DashMap::new(),
            failed_logins: DashMap::new(),
            blocked_ips: RwLock::new(blocked_ips),
            allowed_ips: RwLock::new(allowed_ips),
            threat_events: DashMap::new(),
        }
    }

    /// Checks if threat detection is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Checks if an IP is blocked.
    ///
    /// # Errors
    ///
    /// Returns an error if the IP is blocked.
    pub fn check_ip(&self, ip: IpAddr) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check allowlist first
        {
            let allowed = self.allowed_ips.read().map_err(|_| {
                SecurityError::Internal("Failed to acquire allowlist lock".to_string())
            })?;

            if allowed.iter().any(|net| net.contains(ip)) {
                debug!("IP {} is in allowlist", ip);
                return Ok(());
            }
        }

        // Check blocklist
        {
            let blocked = self.blocked_ips.read().map_err(|_| {
                SecurityError::Internal("Failed to acquire blocklist lock".to_string())
            })?;

            if blocked.iter().any(|net| net.contains(ip)) {
                warn!("Blocked IP attempted access: {}", ip);
                return Err(SecurityError::IpBlocked {
                    ip: ip.to_string(),
                    reason: Some("IP is in blocklist".to_string()),
                });
            }
        }

        Ok(())
    }

    /// Checks rate limit for an IP.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limit is exceeded.
    pub fn check_rate_limit_ip(&self, ip: IpAddr) -> Result<RateLimitStatus> {
        if !self.config.enabled {
            return Ok(RateLimitStatus::allowed(u32::MAX));
        }

        // Check if IP is in allowlist (bypass rate limit)
        {
            let allowed = self.allowed_ips.read().map_err(|_| {
                SecurityError::Internal("Failed to acquire allowlist lock".to_string())
            })?;

            if allowed.iter().any(|net| net.contains(ip)) {
                return Ok(RateLimitStatus::allowed(u32::MAX));
            }
        }

        let key = format!("ip:{}", ip);
        self.check_rate_limit(&key, &self.config.rate_limit)
    }

    /// Checks rate limit for a user.
    ///
    /// # Errors
    ///
    /// Returns an error if rate limit is exceeded.
    pub fn check_rate_limit_user(&self, user_id: &str) -> Result<RateLimitStatus> {
        if !self.config.enabled {
            return Ok(RateLimitStatus::allowed(u32::MAX));
        }

        let key = format!("user:{}", user_id);
        let mut config = self.config.rate_limit.clone();
        config.requests_per_second = config.per_user_requests_per_second;

        self.check_rate_limit(&key, &config)
    }

    /// Records a failed login attempt.
    pub fn record_failed_login(&self, identifier: &str, ip: Option<IpAddr>) {
        let key = format!("login:{}", identifier);
        let window = Duration::from_secs(self.config.lockout_duration_secs);

        let mut entry = self.failed_logins.entry(key.clone()).or_insert_with(FailedLoginTracker::new);
        entry.record_failure(window);

        let attempt_count = entry.attempt_count(window);

        if attempt_count >= self.config.max_failed_logins as usize {
            entry.lock(Duration::from_secs(self.config.lockout_duration_secs));

            // Record threat event
            let event = ThreatEvent::new(
                ThreatLevel::High,
                "brute_force",
                format!("Account locked after {} failed login attempts", attempt_count),
            )
            .with_context("identifier", identifier);

            let event = if let Some(ip) = ip {
                event.with_source_ip(ip)
            } else {
                event
            };

            self.record_threat_event(event);

            warn!(
                "Account locked for {}: {} failed attempts",
                identifier, attempt_count
            );
        }
    }

    /// Checks if a login is locked out.
    ///
    /// # Errors
    ///
    /// Returns an error if the account is locked.
    pub fn check_login_lockout(&self, identifier: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let key = format!("login:{}", identifier);

        if let Some(tracker) = self.failed_logins.get(&key) {
            if tracker.is_locked() {
                return Err(SecurityError::threat(
                    "brute_force",
                    ThreatLevel::High,
                    "Account is temporarily locked due to too many failed login attempts",
                ));
            }
        }

        Ok(())
    }

    /// Records a successful login (clears failed attempts).
    pub fn record_successful_login(&self, identifier: &str) {
        let key = format!("login:{}", identifier);

        if let Some(mut tracker) = self.failed_logins.get_mut(&key) {
            tracker.unlock();
        }
    }

    /// Checks user agent for suspicious patterns.
    ///
    /// # Errors
    ///
    /// Returns an error if the user agent is blocked.
    pub fn check_user_agent(&self, user_agent: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let ua_lower = user_agent.to_lowercase();

        for blocked in &self.config.blocked_user_agents {
            if ua_lower.contains(&blocked.to_lowercase()) {
                warn!("Blocked user agent detected: {}", user_agent);
                return Err(SecurityError::threat(
                    "blocked_user_agent",
                    ThreatLevel::Medium,
                    format!("User agent '{}' is blocked", user_agent),
                ));
            }
        }

        Ok(())
    }

    /// Detects potential SQL injection in input.
    ///
    /// # Errors
    ///
    /// Returns an error if SQL injection is detected.
    pub fn detect_sql_injection(&self, input: &str) -> Result<()> {
        if !self.config.enabled || !self.config.detect_sql_injection {
            return Ok(());
        }

        let patterns = [
            r"(?i)\b(union\s+select|select\s+.*\s+from|insert\s+into)",
            r"(?i)\b(drop\s+table|alter\s+table|truncate\s+table)",
            r"(?i)\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
            r"(?i)'\s*(;|--)",
        ];

        for pattern in patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if regex.is_match(input) {
                    return Err(SecurityError::threat(
                        "sql_injection",
                        ThreatLevel::Critical,
                        "Potential SQL injection detected",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Detects potential XSS in input.
    ///
    /// # Errors
    ///
    /// Returns an error if XSS is detected.
    pub fn detect_xss(&self, input: &str) -> Result<()> {
        if !self.config.enabled || !self.config.detect_xss {
            return Ok(());
        }

        let patterns = [
            r"(?i)<script[^>]*>",
            r"(?i)javascript\s*:",
            r"(?i)on\w+\s*=",
            r"(?i)<iframe[^>]*>",
        ];

        for pattern in patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if regex.is_match(input) {
                    return Err(SecurityError::threat(
                        "xss",
                        ThreatLevel::High,
                        "Potential XSS attack detected",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Detects potential path traversal in input.
    ///
    /// # Errors
    ///
    /// Returns an error if path traversal is detected.
    pub fn detect_path_traversal(&self, input: &str) -> Result<()> {
        if !self.config.enabled || !self.config.detect_path_traversal {
            return Ok(());
        }

        let patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[/\\]",
        ];

        for pattern in patterns {
            if let Ok(regex) = regex::Regex::new(&format!("(?i){}", pattern)) {
                if regex.is_match(input) {
                    return Err(SecurityError::threat(
                        "path_traversal",
                        ThreatLevel::High,
                        "Potential path traversal attack detected",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Blocks an IP address.
    pub fn block_ip(&self, ip: IpAddr, reason: Option<&str>) -> Result<()> {
        let network = IpNetwork::from(ip);

        let mut blocked = self.blocked_ips.write().map_err(|_| {
            SecurityError::Internal("Failed to acquire blocklist lock".to_string())
        })?;

        if !blocked.contains(&network) {
            blocked.push(network);

            let event = ThreatEvent::new(
                ThreatLevel::High,
                "ip_blocked",
                format!("IP {} blocked: {}", ip, reason.unwrap_or("manual block")),
            )
            .with_source_ip(ip);

            self.record_threat_event(event);

            info!("IP {} added to blocklist: {}", ip, reason.unwrap_or("no reason"));
        }

        Ok(())
    }

    /// Unblocks an IP address.
    pub fn unblock_ip(&self, ip: IpAddr) -> Result<()> {
        let network = IpNetwork::from(ip);

        let mut blocked = self.blocked_ips.write().map_err(|_| {
            SecurityError::Internal("Failed to acquire blocklist lock".to_string())
        })?;

        blocked.retain(|net| *net != network);
        info!("IP {} removed from blocklist", ip);

        Ok(())
    }

    /// Records a threat event.
    pub fn record_threat_event(&self, event: ThreatEvent) {
        let key = event.source_ip
            .map(|ip| ip.to_string())
            .or_else(|| event.user_id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        self.threat_events.entry(key).or_default().push(event);
    }

    /// Gets recent threat events for an identifier.
    #[must_use]
    pub fn get_threat_events(&self, identifier: &str) -> Vec<ThreatEvent> {
        self.threat_events
            .get(identifier)
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    /// Cleans up old rate limiters and trackers.
    pub fn cleanup(&self) {
        // Clean up rate limiters that haven't been used recently
        self.rate_limiters.retain(|_, limiter| {
            limiter.last_update.elapsed() < Duration::from_secs(3600)
        });

        // Clean up failed login trackers
        let window = Duration::from_secs(self.config.lockout_duration_secs * 2);
        self.failed_logins.retain(|_, tracker| {
            !tracker.attempts.is_empty() &&
            tracker.attempts.last().map_or(false, |t| t.elapsed() < window)
        });

        // Clean up old threat events (keep last 24 hours)
        let cutoff = Utc::now() - chrono::Duration::hours(24);
        self.threat_events.retain(|_, events| {
            events.retain(|e| e.timestamp > cutoff);
            !events.is_empty()
        });
    }

    // Private helper methods

    fn check_rate_limit(&self, key: &str, config: &RateLimitConfig) -> Result<RateLimitStatus> {
        let refill_rate = config.requests_per_second as f64;
        let max_tokens = config.burst_size;

        let mut limiter = self.rate_limiters
            .entry(key.to_string())
            .or_insert_with(|| RateLimiter::new(max_tokens, refill_rate));

        if limiter.try_acquire() {
            Ok(RateLimitStatus::allowed(limiter.tokens_remaining()))
        } else {
            let reset_at = Utc::now() + chrono::Duration::from_std(limiter.time_until_refill()).unwrap_or_default();

            Err(SecurityError::RateLimited {
                limit: config.requests_per_second,
                window_secs: config.window_size_secs,
                reset_at,
            })
        }
    }
}

/// Rate limit status.
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining requests in the current window.
    pub remaining: u32,
    /// When the rate limit resets.
    pub reset_at: Option<DateTime<Utc>>,
}

impl RateLimitStatus {
    /// Creates an allowed status.
    #[must_use]
    pub fn allowed(remaining: u32) -> Self {
        Self {
            allowed: true,
            remaining,
            reset_at: None,
        }
    }

    /// Creates a rate-limited status.
    #[must_use]
    pub fn limited(reset_at: DateTime<Utc>) -> Self {
        Self {
            allowed: false,
            remaining: 0,
            reset_at: Some(reset_at),
        }
    }
}

impl std::fmt::Debug for ThreatDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreatDetector")
            .field("enabled", &self.config.enabled)
            .field("rate_limiters_count", &self.rate_limiters.len())
            .field("failed_logins_count", &self.failed_logins.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ThreatConfig {
        ThreatConfig {
            enabled: true,
            max_failed_logins: 3,
            lockout_duration_secs: 60,
            rate_limit: RateLimitConfig {
                requests_per_second: 10,
                burst_size: 20,
                per_user_requests_per_second: 5,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_rate_limiting() {
        let detector = ThreatDetector::new(test_config());
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow initial requests
        for _ in 0..20 {
            assert!(detector.check_rate_limit_ip(ip).is_ok());
        }

        // Should rate limit after burst
        let result = detector.check_rate_limit_ip(ip);
        assert!(matches!(result, Err(SecurityError::RateLimited { .. })));
    }

    #[test]
    fn test_ip_blocking() {
        let mut config = test_config();
        config.ip_blocklist = vec!["10.0.0.0/8".to_string()];

        let detector = ThreatDetector::new(config);

        // Blocked IP
        let blocked_ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(detector.check_ip(blocked_ip).is_err());

        // Allowed IP
        let allowed_ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(detector.check_ip(allowed_ip).is_ok());
    }

    #[test]
    fn test_failed_login_lockout() {
        let detector = ThreatDetector::new(test_config());
        let identifier = "user@example.com";

        // Record failed attempts
        for _ in 0..3 {
            detector.record_failed_login(identifier, None);
        }

        // Should be locked out
        assert!(detector.check_login_lockout(identifier).is_err());

        // Successful login should unlock
        detector.record_successful_login(identifier);
        assert!(detector.check_login_lockout(identifier).is_ok());
    }

    #[test]
    fn test_sql_injection_detection() {
        let detector = ThreatDetector::new(test_config());

        assert!(detector.detect_sql_injection("'; DROP TABLE users; --").is_err());
        assert!(detector.detect_sql_injection("1 OR 1=1").is_err());
        assert!(detector.detect_sql_injection("normal input").is_ok());
    }

    #[test]
    fn test_xss_detection() {
        let detector = ThreatDetector::new(test_config());

        assert!(detector.detect_xss("<script>alert('xss')</script>").is_err());
        assert!(detector.detect_xss("onclick=alert(1)").is_err());
        assert!(detector.detect_xss("normal text").is_ok());
    }

    #[test]
    fn test_path_traversal_detection() {
        let detector = ThreatDetector::new(test_config());

        assert!(detector.detect_path_traversal("../../../etc/passwd").is_err());
        assert!(detector.detect_path_traversal("..\\windows\\system32").is_err());
        assert!(detector.detect_path_traversal("normal/path/file.txt").is_ok());
    }

    #[test]
    fn test_user_agent_blocking() {
        let mut config = test_config();
        config.blocked_user_agents = vec!["sqlmap".to_string()];

        let detector = ThreatDetector::new(config);

        assert!(detector.check_user_agent("sqlmap/1.0").is_err());
        assert!(detector.check_user_agent("Mozilla/5.0 Chrome").is_ok());
    }

    #[test]
    fn test_dynamic_ip_blocking() {
        let detector = ThreatDetector::new(test_config());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Initially allowed
        assert!(detector.check_ip(ip).is_ok());

        // Block the IP
        detector.block_ip(ip, Some("suspicious activity")).unwrap();

        // Now blocked
        assert!(detector.check_ip(ip).is_err());

        // Unblock
        detector.unblock_ip(ip).unwrap();

        // Allowed again
        assert!(detector.check_ip(ip).is_ok());
    }
}
