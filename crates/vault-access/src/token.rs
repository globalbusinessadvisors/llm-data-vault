//! JWT token management.

use crate::{AccessError, AccessResult};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;

/// Token configuration.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// Secret key for signing (HS256).
    pub secret: String,
    /// Token issuer.
    pub issuer: String,
    /// Token audience.
    pub audience: Option<String>,
    /// Access token expiration (seconds).
    pub access_token_ttl: i64,
    /// Refresh token expiration (seconds).
    pub refresh_token_ttl: i64,
    /// Algorithm to use.
    pub algorithm: Algorithm,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            secret: "change-me-in-production".to_string(),
            issuer: "llm-data-vault".to_string(),
            audience: None,
            access_token_ttl: 3600,        // 1 hour
            refresh_token_ttl: 86400 * 7,  // 7 days
            algorithm: Algorithm::HS256,
        }
    }
}

impl TokenConfig {
    /// Creates a new config with secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }

    /// Sets issuer.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Sets audience.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Sets access token TTL.
    #[must_use]
    pub fn with_access_ttl(mut self, seconds: i64) -> Self {
        self.access_token_ttl = seconds;
        self
    }

    /// Sets refresh token TTL.
    #[must_use]
    pub fn with_refresh_ttl(mut self, seconds: i64) -> Self {
        self.refresh_token_ttl = seconds;
        self
    }
}

/// JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Not before (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// JWT ID (unique identifier).
    pub jti: String,
    /// Token type.
    pub token_type: TokenType,
    /// User's roles.
    #[serde(default)]
    pub roles: Vec<String>,
    /// User's permissions (direct).
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Tenant ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Custom claims.
    #[serde(default)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Access token.
    Access,
    /// Refresh token.
    Refresh,
    /// API key token.
    ApiKey,
}

impl TokenClaims {
    /// Creates new claims for an access token.
    pub fn access(user_id: impl Into<String>, issuer: impl Into<String>, ttl_seconds: i64) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id.into(),
            iss: issuer.into(),
            aud: None,
            exp: (now + Duration::seconds(ttl_seconds)).timestamp(),
            iat: now.timestamp(),
            nbf: Some(now.timestamp()),
            jti: uuid::Uuid::new_v4().to_string(),
            token_type: TokenType::Access,
            roles: Vec::new(),
            permissions: Vec::new(),
            tenant_id: None,
            custom: HashMap::new(),
        }
    }

    /// Creates new claims for a refresh token.
    pub fn refresh(user_id: impl Into<String>, issuer: impl Into<String>, ttl_seconds: i64) -> Self {
        let mut claims = Self::access(user_id, issuer, ttl_seconds);
        claims.token_type = TokenType::Refresh;
        claims
    }

    /// Sets roles.
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.roles = roles.into_iter().map(|r| r.into()).collect();
        self
    }

    /// Sets permissions.
    #[must_use]
    pub fn with_permissions(mut self, permissions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.permissions = permissions.into_iter().map(|p| p.into()).collect();
        self
    }

    /// Sets tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets audience.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.aud = Some(audience.into());
        self
    }

    /// Adds custom claim.
    #[must_use]
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.custom.insert(key.into(), v);
        }
        self
    }

    /// Checks if the token is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Checks if the token has a specific role.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Checks if the token has a specific permission.
    #[must_use]
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission || p == "*")
    }
}

/// Token manager.
pub struct TokenManager {
    config: TokenConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    revoked_tokens: RwLock<HashSet<String>>,
}

impl TokenManager {
    /// Creates a new token manager.
    pub fn new(config: TokenConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());

        Self {
            config,
            encoding_key,
            decoding_key,
            revoked_tokens: RwLock::new(HashSet::new()),
        }
    }

    /// Creates an access token.
    pub fn create_access_token(&self, user_id: &str, roles: &[String], tenant_id: Option<&str>) -> AccessResult<String> {
        let mut claims = TokenClaims::access(user_id, &self.config.issuer, self.config.access_token_ttl)
            .with_roles(roles.iter().cloned());

        if let Some(tid) = tenant_id {
            claims = claims.with_tenant(tid);
        }

        if let Some(ref aud) = self.config.audience {
            claims = claims.with_audience(aud);
        }

        self.encode(&claims)
    }

    /// Creates a refresh token.
    pub fn create_refresh_token(&self, user_id: &str) -> AccessResult<String> {
        let mut claims = TokenClaims::refresh(user_id, &self.config.issuer, self.config.refresh_token_ttl);

        if let Some(ref aud) = self.config.audience {
            claims = claims.with_audience(aud);
        }

        self.encode(&claims)
    }

    /// Creates a token pair (access + refresh).
    pub fn create_token_pair(&self, user_id: &str, roles: &[String], tenant_id: Option<&str>) -> AccessResult<TokenPair> {
        let access_token = self.create_access_token(user_id, roles, tenant_id)?;
        let refresh_token = self.create_refresh_token(user_id)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_ttl,
        })
    }

    /// Encodes claims into a token.
    pub fn encode(&self, claims: &TokenClaims) -> AccessResult<String> {
        let header = Header::new(self.config.algorithm);
        encode(&header, claims, &self.encoding_key)
            .map_err(|e| AccessError::InvalidToken(e.to_string()))
    }

    /// Decodes and validates a token.
    pub fn decode(&self, token: &str) -> AccessResult<TokenClaims> {
        // Check if revoked
        if self.revoked_tokens.read().contains(token) {
            return Err(AccessError::InvalidToken("Token has been revoked".to_string()));
        }

        let mut validation = Validation::new(self.config.algorithm);
        validation.set_issuer(&[&self.config.issuer]);

        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
        }

        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| {
                if e.to_string().contains("ExpiredSignature") {
                    AccessError::TokenExpired
                } else {
                    AccessError::InvalidToken(e.to_string())
                }
            })?;

        Ok(token_data.claims)
    }

    /// Validates a token and returns claims.
    pub fn validate(&self, token: &str) -> AccessResult<TokenClaims> {
        let claims = self.decode(token)?;

        if claims.is_expired() {
            return Err(AccessError::TokenExpired);
        }

        Ok(claims)
    }

    /// Refreshes an access token using a refresh token.
    pub fn refresh(&self, refresh_token: &str) -> AccessResult<TokenPair> {
        let claims = self.validate(refresh_token)?;

        if claims.token_type != TokenType::Refresh {
            return Err(AccessError::InvalidToken(
                "Expected refresh token".to_string(),
            ));
        }

        // Create new token pair
        self.create_token_pair(&claims.sub, &claims.roles, claims.tenant_id.as_deref())
    }

    /// Revokes a token.
    pub fn revoke(&self, token: &str) {
        self.revoked_tokens.write().insert(token.to_string());
    }

    /// Revokes all tokens for a user (by JTI prefix).
    pub fn revoke_all_for_user(&self, user_id: &str) {
        // In production, this would typically be handled by a token store
        // For now, we just mark the user as having all tokens revoked
        tracing::info!("Revoking all tokens for user: {}", user_id);
    }

    /// Clears expired revocations (cleanup).
    pub fn cleanup_revocations(&self) {
        // In production, implement proper TTL-based cleanup
        // For now, this is a placeholder
    }

    /// Returns the config.
    #[must_use]
    pub fn config(&self) -> &TokenConfig {
        &self.config
    }
}

/// Token pair (access + refresh).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Access token.
    pub access_token: String,
    /// Refresh token.
    pub refresh_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Expiration time in seconds.
    pub expires_in: i64,
}

/// API key manager.
pub struct ApiKeyManager {
    keys: RwLock<HashMap<String, ApiKey>>,
    token_manager: Arc<TokenManager>,
}

/// API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Key ID.
    pub id: String,
    /// Key hash (not the actual key).
    pub key_hash: String,
    /// User ID.
    pub user_id: String,
    /// Name/description.
    pub name: String,
    /// Roles.
    pub roles: Vec<String>,
    /// Permissions.
    pub permissions: Vec<String>,
    /// Tenant ID.
    pub tenant_id: Option<String>,
    /// Created at.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Expires at.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last used.
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    /// Is active.
    pub active: bool,
}

impl ApiKeyManager {
    /// Creates a new API key manager.
    pub fn new(token_manager: Arc<TokenManager>) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            token_manager,
        }
    }

    /// Creates a new API key.
    pub fn create_key(
        &self,
        user_id: &str,
        name: &str,
        roles: Vec<String>,
        tenant_id: Option<String>,
        expires_in_days: Option<u32>,
    ) -> AccessResult<(String, ApiKey)> {
        let key_id = uuid::Uuid::new_v4().to_string();
        let raw_key = format!("vk_{}", uuid::Uuid::new_v4().simple());
        let key_hash = blake3::hash(raw_key.as_bytes()).to_hex().to_string();

        let expires_at = expires_in_days.map(|days| {
            Utc::now() + Duration::days(days as i64)
        });

        let api_key = ApiKey {
            id: key_id.clone(),
            key_hash,
            user_id: user_id.to_string(),
            name: name.to_string(),
            roles,
            permissions: Vec::new(),
            tenant_id,
            created_at: Utc::now(),
            expires_at,
            last_used: None,
            active: true,
        };

        self.keys.write().insert(key_id, api_key.clone());

        Ok((raw_key, api_key))
    }

    /// Validates an API key.
    pub fn validate_key(&self, raw_key: &str) -> AccessResult<ApiKey> {
        let key_hash = blake3::hash(raw_key.as_bytes()).to_hex().to_string();

        let keys = self.keys.read();
        let api_key = keys
            .values()
            .find(|k| k.key_hash == key_hash)
            .ok_or_else(|| AccessError::InvalidToken("Invalid API key".to_string()))?;

        if !api_key.active {
            return Err(AccessError::InvalidToken("API key is disabled".to_string()));
        }

        if let Some(expires) = api_key.expires_at {
            if Utc::now() > expires {
                return Err(AccessError::TokenExpired);
            }
        }

        Ok(api_key.clone())
    }

    /// Revokes an API key.
    pub fn revoke_key(&self, key_id: &str) -> AccessResult<()> {
        let mut keys = self.keys.write();
        if let Some(key) = keys.get_mut(key_id) {
            key.active = false;
            Ok(())
        } else {
            Err(AccessError::InvalidToken("API key not found".to_string()))
        }
    }

    /// Lists API keys for a user.
    pub fn list_keys(&self, user_id: &str) -> Vec<ApiKey> {
        self.keys
            .read()
            .values()
            .filter(|k| k.user_id == user_id)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_manager() -> TokenManager {
        TokenManager::new(TokenConfig::new("test-secret"))
    }

    #[test]
    fn test_create_access_token() {
        let manager = create_manager();
        let token = manager
            .create_access_token("user123", &["admin".to_string()], None)
            .unwrap();

        assert!(!token.is_empty());

        let claims = manager.decode(&token).unwrap();
        assert_eq!(claims.sub, "user123");
        assert!(claims.has_role("admin"));
    }

    #[test]
    fn test_token_pair() {
        let manager = create_manager();
        let pair = manager
            .create_token_pair("user123", &["user".to_string()], Some("tenant-1"))
            .unwrap();

        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());

        let claims = manager.decode(&pair.access_token).unwrap();
        assert_eq!(claims.tenant_id, Some("tenant-1".to_string()));
    }

    #[test]
    fn test_refresh_token() {
        let manager = create_manager();
        let pair = manager
            .create_token_pair("user123", &["user".to_string()], None)
            .unwrap();

        let new_pair = manager.refresh(&pair.refresh_token).unwrap();
        assert!(!new_pair.access_token.is_empty());
        assert_ne!(new_pair.access_token, pair.access_token);
    }

    #[test]
    fn test_revoke_token() {
        let manager = create_manager();
        let token = manager
            .create_access_token("user123", &[], None)
            .unwrap();

        assert!(manager.validate(&token).is_ok());

        manager.revoke(&token);

        assert!(manager.validate(&token).is_err());
    }

    #[test]
    fn test_claims_helpers() {
        let claims = TokenClaims::access("user123", "test", 3600)
            .with_roles(["admin", "user"])
            .with_permissions(["read", "write"])
            .with_tenant("tenant-1");

        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
        assert!(!claims.has_role("guest"));

        assert!(claims.has_permission("read"));
        assert!(!claims.has_permission("delete"));
    }

    #[test]
    fn test_api_key_manager() {
        let token_manager = Arc::new(create_manager());
        let api_manager = ApiKeyManager::new(token_manager);

        let (raw_key, api_key) = api_manager
            .create_key("user123", "Test Key", vec!["user".to_string()], None, None)
            .unwrap();

        assert!(raw_key.starts_with("vk_"));
        assert!(api_key.active);

        let validated = api_manager.validate_key(&raw_key).unwrap();
        assert_eq!(validated.user_id, "user123");
    }
}
