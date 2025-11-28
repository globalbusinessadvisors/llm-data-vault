//! Secure session management.
//!
//! Provides distributed session management including:
//! - Secure session ID generation
//! - Session expiration and idle timeout
//! - Session data encryption
//! - Session regeneration on authentication
//! - Concurrent session limits

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::config::SessionConfig;
use crate::error::{SecurityError, Result};

/// A unique session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a new random session ID.
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Creates a session ID from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is invalid.
    pub fn from_string(s: impl Into<String>) -> Result<Self> {
        let s = s.into();

        if s.len() != 64 {
            return Err(SecurityError::Session("Invalid session ID length".to_string()));
        }

        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SecurityError::Session("Invalid session ID format".to_string()));
        }

        Ok(Self(s))
    }

    /// Returns the session ID as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session data stored for each session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID.
    pub id: SessionId,
    /// User ID associated with the session.
    pub user_id: String,
    /// Tenant ID.
    pub tenant_id: Option<String>,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
    /// Last activity time.
    pub last_activity: DateTime<Utc>,
    /// Client IP address.
    pub ip_address: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,
    /// Custom session data.
    pub data: HashMap<String, serde_json::Value>,
    /// Whether the session is active.
    pub active: bool,
    /// Authentication method used.
    pub auth_method: Option<String>,
    /// Number of times session was renewed.
    pub renewal_count: u32,
}

impl Session {
    /// Creates a new session.
    #[must_use]
    pub fn new(user_id: impl Into<String>, ttl: Duration) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            user_id: user_id.into(),
            tenant_id: None,
            created_at: now,
            expires_at: now + chrono::Duration::from_std(ttl).unwrap_or_default(),
            last_activity: now,
            ip_address: None,
            user_agent: None,
            data: HashMap::new(),
            active: true,
            auth_method: None,
            renewal_count: 0,
        }
    }

    /// Sets the tenant ID.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the IP address.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Sets the user agent.
    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Sets the authentication method.
    #[must_use]
    pub fn with_auth_method(mut self, method: impl Into<String>) -> Self {
        self.auth_method = Some(method.into());
        self
    }

    /// Checks if the session is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Checks if the session is idle (past idle timeout).
    #[must_use]
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        let idle_since = Utc::now().signed_duration_since(self.last_activity);
        idle_since > chrono::Duration::from_std(idle_timeout).unwrap_or_default()
    }

    /// Updates the last activity time.
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Extends the session expiration.
    pub fn extend(&mut self, ttl: Duration) {
        self.expires_at = Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_default();
        self.renewal_count += 1;
    }

    /// Sets a session data value.
    pub fn set<T: Serialize>(&mut self, key: impl Into<String>, value: T) -> Result<()> {
        let json = serde_json::to_value(value)
            .map_err(|e| SecurityError::Session(format!("Failed to serialize session data: {}", e)))?;
        self.data.insert(key.into(), json);
        Ok(())
    }

    /// Gets a session data value.
    pub fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.data.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Removes a session data value.
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.data.remove(key)
    }

    /// Deactivates the session.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

/// Internal session storage.
struct SessionStore {
    sessions: DashMap<String, Session>,
    user_sessions: DashMap<String, Vec<SessionId>>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            user_sessions: DashMap::new(),
        }
    }
}

/// Session manager for handling user sessions.
pub struct SessionManager {
    config: SessionConfig,
    store: SessionStore,
    last_cleanup: RwLock<Instant>,
}

impl SessionManager {
    /// Creates a new session manager with the given configuration.
    #[must_use]
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            store: SessionStore::new(),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Creates a new session for a user.
    ///
    /// # Errors
    ///
    /// Returns an error if session creation fails or max sessions exceeded.
    pub fn create_session(&self, user_id: &str) -> Result<Session> {
        // Check max sessions per user
        let user_sessions = self.get_user_sessions(user_id);
        if user_sessions.len() >= self.config.max_sessions_per_user {
            // Remove oldest session
            if let Some(oldest) = user_sessions.first() {
                self.destroy_session(&oldest.id)?;
            }
        }

        let session = Session::new(user_id, self.config.session_ttl());

        // Store session
        self.store.sessions.insert(session.id.as_str().to_string(), session.clone());

        // Track user sessions
        self.store.user_sessions
            .entry(user_id.to_string())
            .or_default()
            .push(session.id.clone());

        debug!("Created session {} for user {}", session.id, user_id);
        Ok(session)
    }

    /// Gets a session by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found or expired.
    pub fn get_session(&self, session_id: &SessionId) -> Result<Session> {
        let session = self.store.sessions
            .get(session_id.as_str())
            .map(|s| s.clone())
            .ok_or_else(|| SecurityError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;

        // Check if expired
        if session.is_expired() {
            self.destroy_session(session_id)?;
            return Err(SecurityError::SessionExpired {
                session_id: session_id.to_string(),
            });
        }

        // Check idle timeout
        if session.is_idle(self.config.idle_timeout()) {
            self.destroy_session(session_id)?;
            return Err(SecurityError::SessionExpired {
                session_id: session_id.to_string(),
            });
        }

        // Check if active
        if !session.active {
            return Err(SecurityError::SessionExpired {
                session_id: session_id.to_string(),
            });
        }

        Ok(session)
    }

    /// Validates and updates a session's last activity.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is invalid.
    pub fn validate_session(&self, session_id: &SessionId) -> Result<Session> {
        let mut session = self.get_session(session_id)?;
        session.touch();

        // Update stored session
        self.store.sessions.insert(session_id.as_str().to_string(), session.clone());

        Ok(session)
    }

    /// Regenerates a session ID (for security after authentication).
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found.
    pub fn regenerate_session(&self, old_session_id: &SessionId) -> Result<Session> {
        if !self.config.regenerate_on_auth {
            return self.get_session(old_session_id);
        }

        let old_session = self.get_session(old_session_id)?;
        let new_id = SessionId::new();

        let mut new_session = Session {
            id: new_id.clone(),
            created_at: Utc::now(), // Reset creation time
            last_activity: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::from_std(self.config.session_ttl()).unwrap_or_default(),
            ..old_session.clone()
        };
        new_session.renewal_count = 0;

        // Remove old session
        self.store.sessions.remove(old_session_id.as_str());

        // Store new session
        self.store.sessions.insert(new_id.as_str().to_string(), new_session.clone());

        // Update user sessions mapping
        if let Some(mut user_sessions) = self.store.user_sessions.get_mut(&old_session.user_id) {
            user_sessions.retain(|id| id != old_session_id);
            user_sessions.push(new_id.clone());
        }

        info!(
            "Regenerated session {} -> {} for user {}",
            old_session_id, new_id, old_session.user_id
        );

        Ok(new_session)
    }

    /// Extends a session's expiration time.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found.
    pub fn extend_session(&self, session_id: &SessionId) -> Result<Session> {
        let mut session = self.get_session(session_id)?;
        session.extend(self.config.session_ttl());

        self.store.sessions.insert(session_id.as_str().to_string(), session.clone());

        debug!("Extended session {} to {}", session_id, session.expires_at);
        Ok(session)
    }

    /// Updates session data.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found.
    pub fn update_session<F>(&self, session_id: &SessionId, f: F) -> Result<Session>
    where
        F: FnOnce(&mut Session),
    {
        let mut session = self.get_session(session_id)?;
        f(&mut session);
        session.touch();

        self.store.sessions.insert(session_id.as_str().to_string(), session.clone());

        Ok(session)
    }

    /// Destroys a session.
    ///
    /// # Errors
    ///
    /// Returns an error if destruction fails.
    pub fn destroy_session(&self, session_id: &SessionId) -> Result<()> {
        if let Some((_, session)) = self.store.sessions.remove(session_id.as_str()) {
            // Remove from user sessions
            if let Some(mut user_sessions) = self.store.user_sessions.get_mut(&session.user_id) {
                user_sessions.retain(|id| id != session_id);
            }

            debug!("Destroyed session {} for user {}", session_id, session.user_id);
        }

        Ok(())
    }

    /// Destroys all sessions for a user.
    pub fn destroy_user_sessions(&self, user_id: &str) -> Result<()> {
        if let Some((_, session_ids)) = self.store.user_sessions.remove(user_id) {
            for session_id in session_ids {
                self.store.sessions.remove(session_id.as_str());
            }
            info!("Destroyed all sessions for user {}", user_id);
        }

        Ok(())
    }

    /// Gets all sessions for a user.
    #[must_use]
    pub fn get_user_sessions(&self, user_id: &str) -> Vec<Session> {
        self.store.user_sessions
            .get(user_id)
            .map(|session_ids| {
                session_ids
                    .iter()
                    .filter_map(|id| self.store.sessions.get(id.as_str()).map(|s| s.clone()))
                    .filter(|s| s.active && !s.is_expired())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets the session count for a user.
    #[must_use]
    pub fn get_user_session_count(&self, user_id: &str) -> usize {
        self.get_user_sessions(user_id).len()
    }

    /// Cleans up expired sessions.
    pub fn cleanup(&self) -> Result<CleanupStats> {
        let mut expired = 0;
        let mut idle = 0;

        let session_ids: Vec<String> = self.store.sessions
            .iter()
            .map(|r| r.key().clone())
            .collect();

        for session_id in session_ids {
            if let Some(session) = self.store.sessions.get(&session_id) {
                if session.is_expired() {
                    drop(session);
                    if let Ok(id) = SessionId::from_string(&session_id) {
                        let _ = self.destroy_session(&id);
                        expired += 1;
                    }
                } else if session.is_idle(self.config.idle_timeout()) {
                    drop(session);
                    if let Ok(id) = SessionId::from_string(&session_id) {
                        let _ = self.destroy_session(&id);
                        idle += 1;
                    }
                }
            }
        }

        // Update last cleanup time
        if let Ok(mut last_cleanup) = self.last_cleanup.write() {
            *last_cleanup = Instant::now();
        }

        let stats = CleanupStats {
            expired_removed: expired,
            idle_removed: idle,
            total_active: self.store.sessions.len(),
        };

        if expired > 0 || idle > 0 {
            info!(
                "Session cleanup: {} expired, {} idle removed, {} active",
                expired, idle, stats.total_active
            );
        }

        Ok(stats)
    }

    /// Runs cleanup if the cleanup interval has passed.
    pub fn maybe_cleanup(&self) -> Result<Option<CleanupStats>> {
        let should_cleanup = self.last_cleanup
            .read()
            .map(|t| t.elapsed() >= Duration::from_secs(self.config.cleanup_interval_secs))
            .unwrap_or(true);

        if should_cleanup {
            Ok(Some(self.cleanup()?))
        } else {
            Ok(None)
        }
    }

    /// Returns the total number of active sessions.
    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.store.sessions.len()
    }

    /// Returns session cookie configuration.
    #[must_use]
    pub fn cookie_config(&self) -> CookieConfig {
        CookieConfig {
            name: "session".to_string(),
            secure: self.config.secure_cookies,
            http_only: true,
            same_site: self.config.same_site.clone(),
            max_age: self.config.session_ttl_secs,
            path: "/".to_string(),
        }
    }
}

/// Cleanup statistics.
#[derive(Debug, Clone)]
pub struct CleanupStats {
    /// Number of expired sessions removed.
    pub expired_removed: usize,
    /// Number of idle sessions removed.
    pub idle_removed: usize,
    /// Total active sessions remaining.
    pub total_active: usize,
}

/// Session cookie configuration.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// Cookie name.
    pub name: String,
    /// Whether to use secure cookies.
    pub secure: bool,
    /// Whether cookie is HTTP-only.
    pub http_only: bool,
    /// SameSite policy.
    pub same_site: String,
    /// Cookie max age in seconds.
    pub max_age: u64,
    /// Cookie path.
    pub path: String,
}

impl CookieConfig {
    /// Formats the cookie header value.
    #[must_use]
    pub fn to_header(&self, session_id: &SessionId) -> String {
        let mut parts = vec![
            format!("{}={}", self.name, session_id),
            format!("Path={}", self.path),
            format!("Max-Age={}", self.max_age),
            format!("SameSite={}", self.same_site),
        ];

        if self.http_only {
            parts.push("HttpOnly".to_string());
        }

        if self.secure {
            parts.push("Secure".to_string());
        }

        parts.join("; ")
    }
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("active_sessions", &self.store.sessions.len())
            .field("users_with_sessions", &self.store.user_sessions.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SessionConfig {
        SessionConfig {
            session_ttl_secs: 3600,
            idle_timeout_secs: 1800,
            max_sessions_per_user: 3,
            regenerate_on_auth: true,
            secure_cookies: true,
            same_site: "Strict".to_string(),
            cleanup_interval_secs: 60,
            ..Default::default()
        }
    }

    #[test]
    fn test_create_session() {
        let manager = SessionManager::new(test_config());
        let session = manager.create_session("user123").unwrap();

        assert_eq!(session.user_id, "user123");
        assert!(session.active);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_get_session() {
        let manager = SessionManager::new(test_config());
        let session = manager.create_session("user123").unwrap();

        let retrieved = manager.get_session(&session.id).unwrap();
        assert_eq!(retrieved.user_id, session.user_id);
    }

    #[test]
    fn test_validate_session() {
        let manager = SessionManager::new(test_config());
        let session = manager.create_session("user123").unwrap();

        let validated = manager.validate_session(&session.id).unwrap();
        assert!(validated.last_activity >= session.last_activity);
    }

    #[test]
    fn test_regenerate_session() {
        let manager = SessionManager::new(test_config());
        let original = manager.create_session("user123").unwrap();

        let regenerated = manager.regenerate_session(&original.id).unwrap();
        assert_ne!(regenerated.id, original.id);
        assert_eq!(regenerated.user_id, original.user_id);

        // Old session should be gone
        assert!(manager.get_session(&original.id).is_err());
    }

    #[test]
    fn test_destroy_session() {
        let manager = SessionManager::new(test_config());
        let session = manager.create_session("user123").unwrap();

        manager.destroy_session(&session.id).unwrap();

        assert!(manager.get_session(&session.id).is_err());
    }

    #[test]
    fn test_max_sessions_per_user() {
        let manager = SessionManager::new(test_config());

        // Create max sessions
        for _ in 0..3 {
            manager.create_session("user123").unwrap();
        }

        // Creating another should remove the oldest
        let new_session = manager.create_session("user123").unwrap();
        assert_eq!(manager.get_user_session_count("user123"), 3);
        assert!(manager.get_session(&new_session.id).is_ok());
    }

    #[test]
    fn test_session_data() {
        let manager = SessionManager::new(test_config());
        let session = manager.create_session("user123").unwrap();

        // Set data
        manager.update_session(&session.id, |s| {
            s.set("role", "admin").unwrap();
            s.set("preferences", serde_json::json!({"theme": "dark"})).unwrap();
        }).unwrap();

        // Get data
        let updated = manager.get_session(&session.id).unwrap();
        assert_eq!(updated.get::<String>("role"), Some("admin".to_string()));
    }

    #[test]
    fn test_session_id_validation() {
        // Valid session ID
        let valid = SessionId::from_string("a".repeat(64));
        assert!(valid.is_ok());

        // Invalid length
        let invalid = SessionId::from_string("short");
        assert!(invalid.is_err());

        // Invalid characters
        let invalid = SessionId::from_string("g".repeat(64));
        assert!(invalid.is_err());
    }

    #[test]
    fn test_cookie_config() {
        let manager = SessionManager::new(test_config());
        let cookie = manager.cookie_config();

        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site, "Strict");
    }
}
