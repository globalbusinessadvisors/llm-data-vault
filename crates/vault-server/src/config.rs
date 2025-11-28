//! Server configuration.

use anyhow::Result;
use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};

/// Server configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Service name.
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Server host.
    #[serde(default = "default_host")]
    pub host: String,

    /// Server port.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Debug mode.
    #[serde(default)]
    pub debug: bool,

    /// JWT secret.
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,

    /// JWT issuer.
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,

    /// JWT audience.
    #[serde(default = "default_jwt_audience")]
    pub jwt_audience: String,

    /// Token expiry in hours.
    #[serde(default = "default_token_expiry")]
    pub token_expiry_hours: u64,

    /// Maximum request body size.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Request timeout in seconds.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,

    /// Rate limit requests per second.
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u32,

    /// Rate limit burst size.
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,

    /// CORS allowed origins.
    #[serde(default = "default_cors_origins")]
    pub cors_origins: Vec<String>,

    /// Storage configuration.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Database configuration.
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Telemetry configuration.
    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// Encryption configuration.
    #[serde(default)]
    pub encryption: EncryptionConfig,
}

/// Storage configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Storage backend type (memory, filesystem, s3).
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// Filesystem storage path.
    pub path: Option<String>,

    /// S3 bucket name.
    pub s3_bucket: Option<String>,

    /// S3 region.
    pub s3_region: Option<String>,

    /// S3 endpoint (for S3-compatible services).
    pub s3_endpoint: Option<String>,
}

/// Database configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// Database URL.
    pub url: Option<String>,

    /// Maximum connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Minimum connections.
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,

    /// Connection timeout in seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
}

/// Telemetry configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// Enable metrics.
    #[serde(default = "default_true")]
    pub enable_metrics: bool,

    /// Enable tracing.
    #[serde(default = "default_true")]
    pub enable_tracing: bool,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log format (json, pretty).
    #[serde(default = "default_log_format")]
    pub log_format: String,

    /// OTLP endpoint for tracing.
    pub otlp_endpoint: Option<String>,

    /// Metrics port.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            enable_tracing: true,
            log_level: "info".to_string(),
            log_format: "pretty".to_string(),
            otlp_endpoint: None,
            metrics_port: 9090,
        }
    }
}

/// Encryption configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EncryptionConfig {
    /// KMS provider (aws, local).
    #[serde(default = "default_kms_provider")]
    pub kms_provider: String,

    /// AWS KMS key ID.
    pub aws_kms_key_id: Option<String>,

    /// AWS region.
    pub aws_region: Option<String>,

    /// Local master key (base64 encoded, for development only).
    pub local_master_key: Option<String>,
}

// Default value functions
fn default_service_name() -> String {
    "llm-data-vault".to_string()
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_jwt_secret() -> String {
    "change-me-in-production".to_string()
}

fn default_jwt_issuer() -> String {
    "llm-data-vault".to_string()
}

fn default_jwt_audience() -> String {
    "llm-data-vault".to_string()
}

fn default_token_expiry() -> u64 {
    24 // hours
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_request_timeout() -> u64 {
    30 // seconds
}

fn default_rate_limit_rps() -> u32 {
    100
}

fn default_rate_limit_burst() -> u32 {
    200
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_storage_backend() -> String {
    "memory".to_string()
}

fn default_max_connections() -> u32 {
    10
}

fn default_min_connections() -> u32 {
    1
}

fn default_connect_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_kms_provider() -> String {
    "local".to_string()
}

impl ServerConfig {
    /// Loads configuration from files and environment.
    pub fn load() -> Result<Self> {
        let config = Config::builder()
            // Start with defaults
            .set_default("service_name", default_service_name())?
            .set_default("host", default_host())?
            .set_default("port", default_port())?
            // Load from config files
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name("config/local").required(false))
            // Override with environment variables
            .add_source(
                Environment::with_prefix("VAULT")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        let server_config: ServerConfig = config.try_deserialize()?;

        // Validate configuration
        server_config.validate()?;

        Ok(server_config)
    }

    /// Validates the configuration.
    fn validate(&self) -> Result<()> {
        // Check JWT secret in production
        if !self.debug && self.jwt_secret == "change-me-in-production" {
            tracing::warn!("Using default JWT secret in non-debug mode!");
        }

        // Validate port
        if self.port == 0 {
            anyhow::bail!("Invalid port: 0");
        }

        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            host: default_host(),
            port: default_port(),
            debug: false,
            jwt_secret: default_jwt_secret(),
            jwt_issuer: default_jwt_issuer(),
            jwt_audience: default_jwt_audience(),
            token_expiry_hours: default_token_expiry(),
            max_body_size: default_max_body_size(),
            request_timeout_seconds: default_request_timeout(),
            rate_limit_rps: default_rate_limit_rps(),
            rate_limit_burst: default_rate_limit_burst(),
            cors_origins: default_cors_origins(),
            storage: StorageConfig::default(),
            database: DatabaseConfig::default(),
            telemetry: TelemetryConfig::default(),
            encryption: EncryptionConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();

        assert_eq!(config.port, 8080);
        assert_eq!(config.host, "0.0.0.0");
        assert!(!config.debug);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ServerConfig::default();
        config.port = 8080;

        assert!(config.validate().is_ok());

        config.port = 0;
        assert!(config.validate().is_err());
    }
}
