//! Security configuration with validation.
//!
//! Provides comprehensive security configuration management with:
//! - Environment-aware defaults (development vs production)
//! - Configuration validation to prevent insecure setups
//! - Builder pattern for flexible configuration
//! - Secure defaults for all settings

use std::collections::HashSet;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{SecurityError, Result};

/// Environment type for security configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Development environment - relaxed security.
    #[default]
    Development,
    /// Staging environment - production-like security.
    Staging,
    /// Production environment - maximum security.
    Production,
}

impl Environment {
    /// Parses environment from string.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "production" | "prod" => Self::Production,
            "staging" | "stage" => Self::Staging,
            _ => Self::Development,
        }
    }

    /// Returns true if this is a production environment.
    #[must_use]
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Main security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Environment type.
    #[serde(default)]
    pub environment: Environment,

    /// TLS configuration.
    #[serde(default)]
    pub tls: TlsConfig,

    /// CORS security configuration.
    #[serde(default)]
    pub cors: CorsSecurityConfig,

    /// Security headers configuration.
    #[serde(default)]
    pub headers: HeadersConfig,

    /// Secrets management configuration.
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// Session management configuration.
    #[serde(default)]
    pub session: SessionConfig,

    /// Request signing configuration.
    #[serde(default)]
    pub signing: SigningConfig,

    /// Input validation configuration.
    #[serde(default)]
    pub input: InputConfig,

    /// Threat detection configuration.
    #[serde(default)]
    pub threat: ThreatConfig,

    /// Audit configuration.
    #[serde(default)]
    pub audit: AuditConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            environment: Environment::Development,
            tls: TlsConfig::default(),
            cors: CorsSecurityConfig::default(),
            headers: HeadersConfig::default(),
            secrets: SecretsConfig::default(),
            session: SessionConfig::default(),
            signing: SigningConfig::default(),
            input: InputConfig::default(),
            threat: ThreatConfig::default(),
            audit: AuditConfig::default(),
        }
    }
}

impl SecurityConfig {
    /// Creates a new security configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if required environment variables are missing or invalid.
    pub fn from_env() -> Result<Self> {
        let environment = std::env::var("VAULT_ENV")
            .or_else(|_| std::env::var("ENVIRONMENT"))
            .map(|s| Environment::from_str(&s))
            .unwrap_or_default();

        let mut config = Self {
            environment,
            ..Default::default()
        };

        // Override from environment variables
        if let Ok(secret) = std::env::var("VAULT_MASTER_KEY") {
            config.secrets.master_key = Some(secret);
        }

        if let Ok(origins) = std::env::var("VAULT_CORS_ORIGINS") {
            config.cors.allowed_origins = origins.split(',').map(String::from).collect();
        }

        if std::env::var("VAULT_REQUIRE_TLS").is_ok() {
            config.tls.require_tls = true;
        }

        if let Ok(session_ttl) = std::env::var("VAULT_SESSION_TTL_SECS") {
            if let Ok(secs) = session_ttl.parse() {
                config.session.session_ttl_secs = secs;
            }
        }

        Ok(config)
    }

    /// Creates a builder for security configuration.
    #[must_use]
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }

    /// Validates the security configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or insecure for the environment.
    pub fn validate(&self) -> Result<()> {
        // Validate based on environment
        if self.environment.is_production() {
            self.validate_production()?;
        }

        // Validate individual components
        self.tls.validate(self.environment)?;
        self.cors.validate(self.environment)?;
        self.secrets.validate(self.environment)?;
        self.session.validate(self.environment)?;
        self.signing.validate(self.environment)?;
        self.input.validate()?;
        self.threat.validate()?;
        self.audit.validate()?;

        Ok(())
    }

    /// Validates production-specific requirements.
    fn validate_production(&self) -> Result<()> {
        // TLS must be required in production
        if !self.tls.require_tls {
            return Err(SecurityError::configuration_field(
                "TLS must be required in production",
                "tls.require_tls",
            ));
        }

        // Master key must be set in production
        if self.secrets.master_key.is_none() {
            return Err(SecurityError::configuration_field(
                "Master key must be set in production",
                "secrets.master_key",
            ));
        }

        // CORS must not allow all origins in production
        if self.cors.allowed_origins.iter().any(|o| o == "*") {
            return Err(SecurityError::configuration_field(
                "CORS must not allow all origins in production",
                "cors.allowed_origins",
            ));
        }

        // Session secret must be set
        if self.session.secret.is_none() {
            return Err(SecurityError::configuration_field(
                "Session secret must be set in production",
                "session.secret",
            ));
        }

        Ok(())
    }

    /// Returns secure defaults for production.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            environment: Environment::Production,
            tls: TlsConfig::production_defaults(),
            cors: CorsSecurityConfig::production_defaults(),
            headers: HeadersConfig::production_defaults(),
            secrets: SecretsConfig::default(),
            session: SessionConfig::production_defaults(),
            signing: SigningConfig::production_defaults(),
            input: InputConfig::strict(),
            threat: ThreatConfig::production_defaults(),
            audit: AuditConfig::production_defaults(),
        }
    }
}

/// Builder for security configuration.
#[derive(Debug, Default)]
pub struct SecurityConfigBuilder {
    config: SecurityConfig,
}

impl SecurityConfigBuilder {
    /// Sets the environment.
    #[must_use]
    pub fn environment(mut self, environment: Environment) -> Self {
        self.config.environment = environment;
        self
    }

    /// Sets the TLS configuration.
    #[must_use]
    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.config.tls = tls;
        self
    }

    /// Sets the CORS configuration.
    #[must_use]
    pub fn cors(mut self, cors: CorsSecurityConfig) -> Self {
        self.config.cors = cors;
        self
    }

    /// Sets the headers configuration.
    #[must_use]
    pub fn headers(mut self, headers: HeadersConfig) -> Self {
        self.config.headers = headers;
        self
    }

    /// Sets the secrets configuration.
    #[must_use]
    pub fn secrets(mut self, secrets: SecretsConfig) -> Self {
        self.config.secrets = secrets;
        self
    }

    /// Sets the session configuration.
    #[must_use]
    pub fn session(mut self, session: SessionConfig) -> Self {
        self.config.session = session;
        self
    }

    /// Sets the signing configuration.
    #[must_use]
    pub fn signing(mut self, signing: SigningConfig) -> Self {
        self.config.signing = signing;
        self
    }

    /// Sets the input configuration.
    #[must_use]
    pub fn input(mut self, input: InputConfig) -> Self {
        self.config.input = input;
        self
    }

    /// Sets the threat configuration.
    #[must_use]
    pub fn threat(mut self, threat: ThreatConfig) -> Self {
        self.config.threat = threat;
        self
    }

    /// Sets the audit configuration.
    #[must_use]
    pub fn audit(mut self, audit: AuditConfig) -> Self {
        self.config.audit = audit;
        self
    }

    /// Builds and validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn build(self) -> Result<SecurityConfig> {
        self.config.validate()?;
        Ok(self.config)
    }

    /// Builds the configuration without validation.
    #[must_use]
    pub fn build_unchecked(self) -> SecurityConfig {
        self.config
    }
}

/// TLS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Whether TLS is required.
    #[serde(default)]
    pub require_tls: bool,

    /// Minimum TLS version.
    #[serde(default = "TlsConfig::default_min_version")]
    pub min_version: String,

    /// Certificate path.
    pub cert_path: Option<String>,

    /// Key path.
    pub key_path: Option<String>,

    /// CA certificate path for client verification.
    pub ca_cert_path: Option<String>,

    /// Whether to verify client certificates.
    #[serde(default)]
    pub verify_client: bool,

    /// HSTS max age in seconds.
    #[serde(default = "TlsConfig::default_hsts_max_age")]
    pub hsts_max_age_secs: u64,

    /// Whether HSTS includes subdomains.
    #[serde(default = "TlsConfig::default_hsts_include_subdomains")]
    pub hsts_include_subdomains: bool,

    /// Whether HSTS preload is enabled.
    #[serde(default)]
    pub hsts_preload: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            require_tls: false,
            min_version: Self::default_min_version(),
            cert_path: None,
            key_path: None,
            ca_cert_path: None,
            verify_client: false,
            hsts_max_age_secs: Self::default_hsts_max_age(),
            hsts_include_subdomains: Self::default_hsts_include_subdomains(),
            hsts_preload: false,
        }
    }
}

impl TlsConfig {
    fn default_min_version() -> String {
        "1.2".to_string()
    }

    fn default_hsts_max_age() -> u64 {
        31_536_000 // 1 year
    }

    fn default_hsts_include_subdomains() -> bool {
        true
    }

    /// Returns production defaults.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            require_tls: true,
            min_version: "1.3".to_string(),
            hsts_max_age_secs: 63_072_000, // 2 years
            hsts_include_subdomains: true,
            hsts_preload: true,
            ..Default::default()
        }
    }

    /// Validates the TLS configuration.
    fn validate(&self, env: Environment) -> Result<()> {
        if env.is_production() && !self.require_tls {
            warn!("TLS is not required in production - this is a security risk");
        }

        if self.require_tls && (self.cert_path.is_none() || self.key_path.is_none()) {
            // Allow if using a reverse proxy
            warn!("TLS required but cert/key not configured - ensure TLS termination at load balancer");
        }

        Ok(())
    }
}

/// CORS security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsSecurityConfig {
    /// Allowed origins.
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Allowed methods.
    #[serde(default = "CorsSecurityConfig::default_methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed headers.
    #[serde(default = "CorsSecurityConfig::default_headers")]
    pub allowed_headers: Vec<String>,

    /// Exposed headers.
    #[serde(default)]
    pub exposed_headers: Vec<String>,

    /// Whether credentials are allowed.
    #[serde(default)]
    pub allow_credentials: bool,

    /// Max age for preflight cache.
    #[serde(default = "CorsSecurityConfig::default_max_age")]
    pub max_age_secs: u64,
}

impl Default for CorsSecurityConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: Self::default_methods(),
            allowed_headers: Self::default_headers(),
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_secs: Self::default_max_age(),
        }
    }
}

impl CorsSecurityConfig {
    fn default_methods() -> Vec<String> {
        vec![
            "GET".to_string(),
            "POST".to_string(),
            "PUT".to_string(),
            "PATCH".to_string(),
            "DELETE".to_string(),
            "OPTIONS".to_string(),
        ]
    }

    fn default_headers() -> Vec<String> {
        vec![
            "Authorization".to_string(),
            "Content-Type".to_string(),
            "X-Request-ID".to_string(),
            "X-API-Key".to_string(),
        ]
    }

    fn default_max_age() -> u64 {
        3600
    }

    /// Returns production defaults.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            allowed_origins: vec![], // Must be explicitly configured
            allow_credentials: true,
            max_age_secs: 7200,
            ..Default::default()
        }
    }

    /// Validates the CORS configuration.
    fn validate(&self, env: Environment) -> Result<()> {
        if env.is_production() {
            if self.allowed_origins.is_empty() {
                return Err(SecurityError::configuration_field(
                    "CORS origins must be configured in production",
                    "cors.allowed_origins",
                ));
            }

            if self.allowed_origins.iter().any(|o| o == "*") {
                return Err(SecurityError::configuration_field(
                    "Wildcard CORS origin not allowed in production",
                    "cors.allowed_origins",
                ));
            }

            if self.allow_credentials && self.allowed_origins.iter().any(|o| o == "*") {
                return Err(SecurityError::configuration_field(
                    "Cannot allow credentials with wildcard origin",
                    "cors.allow_credentials",
                ));
            }
        }

        Ok(())
    }
}

/// Security headers configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersConfig {
    /// Content Security Policy.
    pub content_security_policy: Option<String>,

    /// X-Frame-Options header value.
    #[serde(default = "HeadersConfig::default_frame_options")]
    pub frame_options: String,

    /// X-Content-Type-Options.
    #[serde(default = "HeadersConfig::default_content_type_options")]
    pub content_type_options: String,

    /// Referrer-Policy.
    #[serde(default = "HeadersConfig::default_referrer_policy")]
    pub referrer_policy: String,

    /// Permissions-Policy.
    pub permissions_policy: Option<String>,

    /// Whether to add X-XSS-Protection header.
    #[serde(default = "HeadersConfig::default_xss_protection")]
    pub xss_protection: bool,

    /// Cross-Origin-Opener-Policy.
    #[serde(default = "HeadersConfig::default_coop")]
    pub cross_origin_opener_policy: String,

    /// Cross-Origin-Resource-Policy.
    #[serde(default = "HeadersConfig::default_corp")]
    pub cross_origin_resource_policy: String,

    /// Cross-Origin-Embedder-Policy.
    pub cross_origin_embedder_policy: Option<String>,
}

impl Default for HeadersConfig {
    fn default() -> Self {
        Self {
            content_security_policy: None,
            frame_options: Self::default_frame_options(),
            content_type_options: Self::default_content_type_options(),
            referrer_policy: Self::default_referrer_policy(),
            permissions_policy: None,
            xss_protection: Self::default_xss_protection(),
            cross_origin_opener_policy: Self::default_coop(),
            cross_origin_resource_policy: Self::default_corp(),
            cross_origin_embedder_policy: None,
        }
    }
}

impl HeadersConfig {
    fn default_frame_options() -> String {
        "DENY".to_string()
    }

    fn default_content_type_options() -> String {
        "nosniff".to_string()
    }

    fn default_referrer_policy() -> String {
        "strict-origin-when-cross-origin".to_string()
    }

    fn default_xss_protection() -> bool {
        true
    }

    fn default_coop() -> String {
        "same-origin".to_string()
    }

    fn default_corp() -> String {
        "same-origin".to_string()
    }

    /// Returns production defaults with strict CSP.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            content_security_policy: Some(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; font-src 'self'; connect-src 'self'; \
                 frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                    .to_string(),
            ),
            permissions_policy: Some(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), \
                 magnetometer=(), microphone=(), payment=(), usb=()"
                    .to_string(),
            ),
            cross_origin_embedder_policy: Some("require-corp".to_string()),
            ..Default::default()
        }
    }
}

/// Secrets management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Master encryption key (from environment).
    #[serde(skip_serializing)]
    pub master_key: Option<String>,

    /// Key derivation iterations.
    #[serde(default = "SecretsConfig::default_kdf_iterations")]
    pub kdf_iterations: u32,

    /// Secret rotation interval in seconds.
    #[serde(default = "SecretsConfig::default_rotation_interval")]
    pub rotation_interval_secs: u64,

    /// Whether to encrypt secrets at rest.
    #[serde(default = "SecretsConfig::default_encrypt_at_rest")]
    pub encrypt_at_rest: bool,

    /// Secret cache TTL in seconds.
    #[serde(default = "SecretsConfig::default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            master_key: None,
            kdf_iterations: Self::default_kdf_iterations(),
            rotation_interval_secs: Self::default_rotation_interval(),
            encrypt_at_rest: Self::default_encrypt_at_rest(),
            cache_ttl_secs: Self::default_cache_ttl(),
        }
    }
}

impl SecretsConfig {
    fn default_kdf_iterations() -> u32 {
        100_000
    }

    fn default_rotation_interval() -> u64 {
        86400 * 90 // 90 days
    }

    fn default_encrypt_at_rest() -> bool {
        true
    }

    fn default_cache_ttl() -> u64 {
        3600 // 1 hour
    }

    /// Validates the secrets configuration.
    fn validate(&self, env: Environment) -> Result<()> {
        if env.is_production() && self.master_key.is_none() {
            return Err(SecurityError::configuration_field(
                "Master key must be set in production",
                "secrets.master_key",
            ));
        }

        if self.kdf_iterations < 10_000 {
            return Err(SecurityError::configuration_field(
                "KDF iterations must be at least 10,000",
                "secrets.kdf_iterations",
            ));
        }

        Ok(())
    }
}

/// Session management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session secret for signing.
    #[serde(skip_serializing)]
    pub secret: Option<String>,

    /// Session TTL in seconds.
    #[serde(default = "SessionConfig::default_session_ttl")]
    pub session_ttl_secs: u64,

    /// Idle timeout in seconds.
    #[serde(default = "SessionConfig::default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Maximum sessions per user.
    #[serde(default = "SessionConfig::default_max_sessions")]
    pub max_sessions_per_user: usize,

    /// Whether to regenerate session ID on authentication.
    #[serde(default = "SessionConfig::default_regenerate_on_auth")]
    pub regenerate_on_auth: bool,

    /// Whether to use secure cookies.
    #[serde(default = "SessionConfig::default_secure_cookies")]
    pub secure_cookies: bool,

    /// Cookie same-site policy.
    #[serde(default = "SessionConfig::default_same_site")]
    pub same_site: String,

    /// Session cleanup interval in seconds.
    #[serde(default = "SessionConfig::default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            secret: None,
            session_ttl_secs: Self::default_session_ttl(),
            idle_timeout_secs: Self::default_idle_timeout(),
            max_sessions_per_user: Self::default_max_sessions(),
            regenerate_on_auth: Self::default_regenerate_on_auth(),
            secure_cookies: Self::default_secure_cookies(),
            same_site: Self::default_same_site(),
            cleanup_interval_secs: Self::default_cleanup_interval(),
        }
    }
}

impl SessionConfig {
    fn default_session_ttl() -> u64 {
        86400 // 24 hours
    }

    fn default_idle_timeout() -> u64 {
        3600 // 1 hour
    }

    fn default_max_sessions() -> usize {
        5
    }

    fn default_regenerate_on_auth() -> bool {
        true
    }

    fn default_secure_cookies() -> bool {
        false // Changed to true in production
    }

    fn default_same_site() -> String {
        "Lax".to_string()
    }

    fn default_cleanup_interval() -> u64 {
        300 // 5 minutes
    }

    /// Returns production defaults.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            secure_cookies: true,
            same_site: "Strict".to_string(),
            session_ttl_secs: 28800, // 8 hours
            idle_timeout_secs: 1800, // 30 minutes
            max_sessions_per_user: 3,
            ..Default::default()
        }
    }

    /// Validates the session configuration.
    fn validate(&self, env: Environment) -> Result<()> {
        if env.is_production() {
            if self.secret.is_none() {
                return Err(SecurityError::configuration_field(
                    "Session secret must be set in production",
                    "session.secret",
                ));
            }

            if !self.secure_cookies {
                warn!("Secure cookies disabled in production - this is a security risk");
            }

            if self.same_site != "Strict" && self.same_site != "Lax" {
                return Err(SecurityError::configuration_field(
                    "SameSite must be Strict or Lax in production",
                    "session.same_site",
                ));
            }
        }

        if self.session_ttl_secs == 0 {
            return Err(SecurityError::configuration_field(
                "Session TTL must be greater than 0",
                "session.session_ttl_secs",
            ));
        }

        Ok(())
    }

    /// Returns the session TTL as a Duration.
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.session_ttl_secs)
    }

    /// Returns the idle timeout as a Duration.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

/// Request signing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Whether request signing is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Signing algorithm.
    #[serde(default = "SigningConfig::default_algorithm")]
    pub algorithm: String,

    /// Signing key (from environment).
    #[serde(skip_serializing)]
    pub signing_key: Option<String>,

    /// Signature validity in seconds.
    #[serde(default = "SigningConfig::default_validity")]
    pub validity_secs: u64,

    /// Nonce cache size.
    #[serde(default = "SigningConfig::default_nonce_cache_size")]
    pub nonce_cache_size: usize,

    /// Headers to include in signature.
    #[serde(default = "SigningConfig::default_signed_headers")]
    pub signed_headers: Vec<String>,
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: Self::default_algorithm(),
            signing_key: None,
            validity_secs: Self::default_validity(),
            nonce_cache_size: Self::default_nonce_cache_size(),
            signed_headers: Self::default_signed_headers(),
        }
    }
}

impl SigningConfig {
    fn default_algorithm() -> String {
        "HMAC-SHA256".to_string()
    }

    fn default_validity() -> u64 {
        300 // 5 minutes
    }

    fn default_nonce_cache_size() -> usize {
        100_000
    }

    fn default_signed_headers() -> Vec<String> {
        vec![
            "host".to_string(),
            "content-type".to_string(),
            "x-request-id".to_string(),
        ]
    }

    /// Returns production defaults.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            enabled: true,
            validity_secs: 60, // 1 minute
            ..Default::default()
        }
    }

    /// Validates the signing configuration.
    fn validate(&self, _env: Environment) -> Result<()> {
        if self.enabled && self.signing_key.is_none() {
            return Err(SecurityError::configuration_field(
                "Signing key must be set when signing is enabled",
                "signing.signing_key",
            ));
        }

        if self.validity_secs == 0 {
            return Err(SecurityError::configuration_field(
                "Signature validity must be greater than 0",
                "signing.validity_secs",
            ));
        }

        Ok(())
    }
}

/// Input validation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConfig {
    /// Maximum request body size in bytes.
    #[serde(default = "InputConfig::default_max_body_size")]
    pub max_body_size: usize,

    /// Maximum string length.
    #[serde(default = "InputConfig::default_max_string_length")]
    pub max_string_length: usize,

    /// Maximum array length.
    #[serde(default = "InputConfig::default_max_array_length")]
    pub max_array_length: usize,

    /// Maximum JSON depth.
    #[serde(default = "InputConfig::default_max_json_depth")]
    pub max_json_depth: usize,

    /// Allowed content types.
    #[serde(default = "InputConfig::default_allowed_content_types")]
    pub allowed_content_types: Vec<String>,

    /// Blocked patterns (regex).
    #[serde(default)]
    pub blocked_patterns: Vec<String>,

    /// Whether to sanitize HTML.
    #[serde(default = "InputConfig::default_sanitize_html")]
    pub sanitize_html: bool,

    /// Whether to validate UTF-8.
    #[serde(default = "InputConfig::default_validate_utf8")]
    pub validate_utf8: bool,

    /// Whether to strip null bytes.
    #[serde(default = "InputConfig::default_strip_null_bytes")]
    pub strip_null_bytes: bool,
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            max_body_size: Self::default_max_body_size(),
            max_string_length: Self::default_max_string_length(),
            max_array_length: Self::default_max_array_length(),
            max_json_depth: Self::default_max_json_depth(),
            allowed_content_types: Self::default_allowed_content_types(),
            blocked_patterns: vec![],
            sanitize_html: Self::default_sanitize_html(),
            validate_utf8: Self::default_validate_utf8(),
            strip_null_bytes: Self::default_strip_null_bytes(),
        }
    }
}

impl InputConfig {
    fn default_max_body_size() -> usize {
        10 * 1024 * 1024 // 10 MB
    }

    fn default_max_string_length() -> usize {
        1_000_000 // 1 MB
    }

    fn default_max_array_length() -> usize {
        10_000
    }

    fn default_max_json_depth() -> usize {
        32
    }

    fn default_allowed_content_types() -> Vec<String> {
        vec![
            "application/json".to_string(),
            "application/x-www-form-urlencoded".to_string(),
            "multipart/form-data".to_string(),
            "text/plain".to_string(),
        ]
    }

    fn default_sanitize_html() -> bool {
        true
    }

    fn default_validate_utf8() -> bool {
        true
    }

    fn default_strip_null_bytes() -> bool {
        true
    }

    /// Returns strict input validation.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_body_size: 1024 * 1024, // 1 MB
            max_string_length: 100_000,
            max_array_length: 1000,
            max_json_depth: 16,
            blocked_patterns: vec![
                r"<script".to_string(),
                r"javascript:".to_string(),
                r"on\w+=".to_string(),
            ],
            ..Default::default()
        }
    }

    /// Validates the input configuration.
    fn validate(&self) -> Result<()> {
        if self.max_body_size == 0 {
            return Err(SecurityError::configuration_field(
                "Max body size must be greater than 0",
                "input.max_body_size",
            ));
        }

        if self.max_json_depth == 0 {
            return Err(SecurityError::configuration_field(
                "Max JSON depth must be greater than 0",
                "input.max_json_depth",
            ));
        }

        // Validate regex patterns
        for pattern in &self.blocked_patterns {
            regex::Regex::new(pattern).map_err(|e| {
                SecurityError::configuration_field(
                    format!("Invalid blocked pattern: {e}"),
                    "input.blocked_patterns",
                )
            })?;
        }

        Ok(())
    }
}

/// Threat detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatConfig {
    /// Whether threat detection is enabled.
    #[serde(default = "ThreatConfig::default_enabled")]
    pub enabled: bool,

    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// IP blocklist.
    #[serde(default)]
    pub ip_blocklist: Vec<String>,

    /// IP allowlist (bypass rate limits).
    #[serde(default)]
    pub ip_allowlist: Vec<String>,

    /// Maximum failed login attempts.
    #[serde(default = "ThreatConfig::default_max_failed_logins")]
    pub max_failed_logins: u32,

    /// Lockout duration in seconds.
    #[serde(default = "ThreatConfig::default_lockout_duration")]
    pub lockout_duration_secs: u64,

    /// Whether to detect SQL injection.
    #[serde(default = "ThreatConfig::default_detect_sql_injection")]
    pub detect_sql_injection: bool,

    /// Whether to detect XSS.
    #[serde(default = "ThreatConfig::default_detect_xss")]
    pub detect_xss: bool,

    /// Whether to detect path traversal.
    #[serde(default = "ThreatConfig::default_detect_path_traversal")]
    pub detect_path_traversal: bool,

    /// Suspicious user agents to block.
    #[serde(default)]
    pub blocked_user_agents: Vec<String>,
}

impl Default for ThreatConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            rate_limit: RateLimitConfig::default(),
            ip_blocklist: vec![],
            ip_allowlist: vec![],
            max_failed_logins: Self::default_max_failed_logins(),
            lockout_duration_secs: Self::default_lockout_duration(),
            detect_sql_injection: Self::default_detect_sql_injection(),
            detect_xss: Self::default_detect_xss(),
            detect_path_traversal: Self::default_detect_path_traversal(),
            blocked_user_agents: vec![],
        }
    }
}

impl ThreatConfig {
    fn default_enabled() -> bool {
        true
    }

    fn default_max_failed_logins() -> u32 {
        5
    }

    fn default_lockout_duration() -> u64 {
        900 // 15 minutes
    }

    fn default_detect_sql_injection() -> bool {
        true
    }

    fn default_detect_xss() -> bool {
        true
    }

    fn default_detect_path_traversal() -> bool {
        true
    }

    /// Returns production defaults.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            rate_limit: RateLimitConfig::strict(),
            max_failed_logins: 3,
            lockout_duration_secs: 1800, // 30 minutes
            blocked_user_agents: vec![
                "sqlmap".to_string(),
                "nikto".to_string(),
                "nessus".to_string(),
            ],
            ..Default::default()
        }
    }

    /// Validates the threat configuration.
    fn validate(&self) -> Result<()> {
        self.rate_limit.validate()?;

        for ip in &self.ip_blocklist {
            ip.parse::<ipnetwork::IpNetwork>().map_err(|e| {
                SecurityError::configuration_field(
                    format!("Invalid IP in blocklist: {e}"),
                    "threat.ip_blocklist",
                )
            })?;
        }

        for ip in &self.ip_allowlist {
            ip.parse::<ipnetwork::IpNetwork>().map_err(|e| {
                SecurityError::configuration_field(
                    format!("Invalid IP in allowlist: {e}"),
                    "threat.ip_allowlist",
                )
            })?;
        }

        Ok(())
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per second.
    #[serde(default = "RateLimitConfig::default_requests_per_second")]
    pub requests_per_second: u32,

    /// Burst size.
    #[serde(default = "RateLimitConfig::default_burst_size")]
    pub burst_size: u32,

    /// Per-user rate limit.
    #[serde(default = "RateLimitConfig::default_per_user_limit")]
    pub per_user_requests_per_second: u32,

    /// Per-IP rate limit.
    #[serde(default = "RateLimitConfig::default_per_ip_limit")]
    pub per_ip_requests_per_second: u32,

    /// Window size in seconds.
    #[serde(default = "RateLimitConfig::default_window_size")]
    pub window_size_secs: u64,

    /// Whether to use sliding window.
    #[serde(default = "RateLimitConfig::default_sliding_window")]
    pub sliding_window: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: Self::default_requests_per_second(),
            burst_size: Self::default_burst_size(),
            per_user_requests_per_second: Self::default_per_user_limit(),
            per_ip_requests_per_second: Self::default_per_ip_limit(),
            window_size_secs: Self::default_window_size(),
            sliding_window: Self::default_sliding_window(),
        }
    }
}

impl RateLimitConfig {
    fn default_requests_per_second() -> u32 {
        100
    }

    fn default_burst_size() -> u32 {
        200
    }

    fn default_per_user_limit() -> u32 {
        50
    }

    fn default_per_ip_limit() -> u32 {
        100
    }

    fn default_window_size() -> u64 {
        60
    }

    fn default_sliding_window() -> bool {
        true
    }

    /// Returns strict rate limiting.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            requests_per_second: 50,
            burst_size: 100,
            per_user_requests_per_second: 20,
            per_ip_requests_per_second: 50,
            ..Default::default()
        }
    }

    /// Validates the rate limit configuration.
    fn validate(&self) -> Result<()> {
        if self.requests_per_second == 0 {
            return Err(SecurityError::configuration_field(
                "Requests per second must be greater than 0",
                "rate_limit.requests_per_second",
            ));
        }

        if self.burst_size < self.requests_per_second {
            return Err(SecurityError::configuration_field(
                "Burst size must be >= requests per second",
                "rate_limit.burst_size",
            ));
        }

        Ok(())
    }
}

/// Audit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    #[serde(default = "AuditConfig::default_enabled")]
    pub enabled: bool,

    /// Whether to use immutable storage.
    #[serde(default = "AuditConfig::default_immutable")]
    pub immutable: bool,

    /// Whether to include integrity hashes.
    #[serde(default = "AuditConfig::default_include_integrity")]
    pub include_integrity: bool,

    /// Audit log retention in days.
    #[serde(default = "AuditConfig::default_retention_days")]
    pub retention_days: u32,

    /// Maximum entries to keep in memory.
    #[serde(default = "AuditConfig::default_max_memory_entries")]
    pub max_memory_entries: usize,

    /// Events to audit.
    #[serde(default = "AuditConfig::default_audited_events")]
    pub audited_events: HashSet<String>,

    /// Whether to redact sensitive data.
    #[serde(default = "AuditConfig::default_redact_sensitive")]
    pub redact_sensitive: bool,

    /// Fields to redact.
    #[serde(default = "AuditConfig::default_redacted_fields")]
    pub redacted_fields: HashSet<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            immutable: Self::default_immutable(),
            include_integrity: Self::default_include_integrity(),
            retention_days: Self::default_retention_days(),
            max_memory_entries: Self::default_max_memory_entries(),
            audited_events: Self::default_audited_events(),
            redact_sensitive: Self::default_redact_sensitive(),
            redacted_fields: Self::default_redacted_fields(),
        }
    }
}

impl AuditConfig {
    fn default_enabled() -> bool {
        true
    }

    fn default_immutable() -> bool {
        false
    }

    fn default_include_integrity() -> bool {
        true
    }

    fn default_retention_days() -> u32 {
        365
    }

    fn default_max_memory_entries() -> usize {
        10_000
    }

    fn default_audited_events() -> HashSet<String> {
        [
            "authentication",
            "authorization",
            "data_access",
            "data_modification",
            "configuration_change",
            "security_event",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn default_redact_sensitive() -> bool {
        true
    }

    fn default_redacted_fields() -> HashSet<String> {
        [
            "password",
            "token",
            "secret",
            "api_key",
            "authorization",
            "credit_card",
            "ssn",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    /// Returns production defaults.
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            immutable: true,
            include_integrity: true,
            retention_days: 730, // 2 years
            max_memory_entries: 100_000,
            ..Default::default()
        }
    }

    /// Validates the audit configuration.
    fn validate(&self) -> Result<()> {
        if self.enabled && self.retention_days == 0 {
            return Err(SecurityError::configuration_field(
                "Audit retention must be greater than 0 when enabled",
                "audit.retention_days",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert_eq!(config.environment, Environment::Development);
        assert!(!config.tls.require_tls);
    }

    #[test]
    fn test_production_validation() {
        let config = SecurityConfig {
            environment: Environment::Production,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_production_defaults() {
        let config = SecurityConfig::production_defaults();
        assert!(config.tls.require_tls);
        assert!(config.cors.allowed_origins.is_empty());
    }

    #[test]
    fn test_builder() {
        let config = SecurityConfig::builder()
            .environment(Environment::Development)
            .build_unchecked();

        assert_eq!(config.environment, Environment::Development);
    }

    #[test]
    fn test_rate_limit_validation() {
        let config = RateLimitConfig {
            requests_per_second: 100,
            burst_size: 50, // Invalid: less than requests_per_second
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }
}
