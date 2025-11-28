# Configuration Management

## 1. Configuration Hierarchy

Configuration is loaded in the following order (later sources override earlier ones):

1. **Defaults** - Hardcoded in Rust structs
2. **Config File** - `vault.toml` (TOML format)
3. **Environment Variables** - Prefixed with `VAULT_`
4. **CLI Arguments** - Command-line flags

## 2. Complete Configuration Schema

### 2.1 Root Configuration

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub encryption: EncryptionConfig,
    pub auth: AuthConfig,
    pub anonymization: AnonymizationConfig,
    pub observability: ObservabilityConfig,
    pub rate_limiting: RateLimitConfig,
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.validate()?;
        self.database.validate()?;
        self.storage.validate()?;
        self.encryption.validate()?;
        self.auth.validate()?;
        self.anonymization.validate()?;
        self.observability.validate()?;
        self.rate_limiting.validate()?;
        Ok(())
    }
}
```

### 2.2 Server Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_workers")]
    pub workers: usize,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,

    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,

    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 8080 }
fn default_workers() -> usize { num_cpus::get() }
fn default_max_connections() -> usize { 1000 }
fn default_request_timeout() -> u64 { 30 }
fn default_shutdown_timeout() -> u64 { 10 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
}

impl ServerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::Invalid("port must be non-zero".into()));
        }
        if self.workers == 0 {
            return Err(ConfigError::Invalid("workers must be non-zero".into()));
        }
        if let Some(tls) = &self.tls {
            if !tls.cert_path.exists() {
                return Err(ConfigError::Invalid("TLS cert file not found".into()));
            }
            if !tls.key_path.exists() {
                return Err(ConfigError::Invalid("TLS key file not found".into()));
            }
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_SERVER_HOST`
- `VAULT_SERVER_PORT`
- `VAULT_SERVER_WORKERS`
- `VAULT_SERVER_MAX_CONNECTIONS`
- `VAULT_SERVER_REQUEST_TIMEOUT_SECS`
- `VAULT_SERVER_TLS_CERT_PATH`
- `VAULT_SERVER_TLS_KEY_PATH`

### 2.3 Database Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_url")]
    pub url: String,

    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    #[serde(default = "default_pool_timeout")]
    pub pool_timeout_secs: u64,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    #[serde(default = "default_max_lifetime")]
    pub max_lifetime_secs: u64,

    #[serde(default = "default_auto_migrate")]
    pub auto_migrate: bool,
}

fn default_url() -> String { "postgresql://localhost/vault".to_string() }
fn default_pool_size() -> u32 { 10 }
fn default_pool_timeout() -> u64 { 30 }
fn default_connection_timeout() -> u64 { 10 }
fn default_idle_timeout() -> u64 { 600 }
fn default_max_lifetime() -> u64 { 1800 }
fn default_auto_migrate() -> bool { false }

impl DatabaseConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.url.is_empty() {
            return Err(ConfigError::Invalid("database URL required".into()));
        }
        if self.pool_size == 0 {
            return Err(ConfigError::Invalid("pool_size must be non-zero".into()));
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_DATABASE_URL` (Required in production)
- `VAULT_DATABASE_POOL_SIZE`
- `VAULT_DATABASE_POOL_TIMEOUT_SECS`
- `VAULT_DATABASE_CONNECTION_TIMEOUT_SECS`

### 2.4 Storage Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    #[serde(default = "default_backend")]
    pub backend: StorageBackend,

    #[serde(default)]
    pub local: Option<LocalStorageConfig>,

    #[serde(default)]
    pub s3: Option<S3StorageConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    Local,
    S3,
}

fn default_backend() -> StorageBackend { StorageBackend::Local }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalStorageConfig {
    pub data_dir: PathBuf,
    #[serde(default = "default_max_file_size")]
    pub max_file_size_mb: u64,
}

fn default_max_file_size() -> u64 { 100 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3StorageConfig {
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default = "default_s3_prefix")]
    pub prefix: String,
}

fn default_s3_prefix() -> String { "vault/".to_string() }

impl StorageConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self.backend {
            StorageBackend::Local => {
                if self.local.is_none() {
                    return Err(ConfigError::Invalid("local storage config required".into()));
                }
            }
            StorageBackend::S3 => {
                if self.s3.is_none() {
                    return Err(ConfigError::Invalid("S3 storage config required".into()));
                }
                let s3 = self.s3.as_ref().unwrap();
                if s3.bucket.is_empty() {
                    return Err(ConfigError::Invalid("S3 bucket required".into()));
                }
            }
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_STORAGE_BACKEND`
- `VAULT_STORAGE_LOCAL_DATA_DIR`
- `VAULT_STORAGE_S3_BUCKET`
- `VAULT_STORAGE_S3_REGION`
- `VAULT_STORAGE_S3_ENDPOINT`
- `VAULT_STORAGE_S3_ACCESS_KEY_ID` (Secret)
- `VAULT_STORAGE_S3_SECRET_ACCESS_KEY` (Secret)

### 2.5 Encryption Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptionConfig {
    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    #[serde(skip_serializing)]
    pub master_key: Option<String>,

    #[serde(default)]
    pub key_rotation_days: Option<u64>,

    #[serde(default = "default_kms_backend")]
    pub kms_backend: KmsBackend,

    #[serde(default)]
    pub aws_kms: Option<AwsKmsConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KmsBackend {
    Local,
    AwsKms,
}

fn default_algorithm() -> String { "AES-256-GCM".to_string() }
fn default_kms_backend() -> KmsBackend { KmsBackend::Local }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwsKmsConfig {
    pub key_id: String,
    pub region: String,
}

impl EncryptionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        match self.kms_backend {
            KmsBackend::Local => {
                if self.master_key.is_none() {
                    return Err(ConfigError::Invalid("master_key required for local KMS".into()));
                }
            }
            KmsBackend::AwsKms => {
                if self.aws_kms.is_none() {
                    return Err(ConfigError::Invalid("aws_kms config required".into()));
                }
            }
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_ENCRYPTION_MASTER_KEY` (Secret, Required)
- `VAULT_ENCRYPTION_ALGORITHM`
- `VAULT_ENCRYPTION_KMS_BACKEND`
- `VAULT_ENCRYPTION_AWS_KMS_KEY_ID`
- `VAULT_ENCRYPTION_AWS_KMS_REGION`

### 2.6 Authentication Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,

    #[serde(default = "default_jwt_expiry")]
    pub jwt_expiry_secs: u64,

    #[serde(default = "default_refresh_expiry")]
    pub refresh_token_expiry_secs: u64,

    #[serde(default = "default_bcrypt_cost")]
    pub bcrypt_cost: u32,

    #[serde(default)]
    pub api_key_enabled: bool,
}

fn default_jwt_secret() -> String { String::new() }
fn default_jwt_expiry() -> u64 { 3600 }
fn default_refresh_expiry() -> u64 { 2592000 }
fn default_bcrypt_cost() -> u32 { 12 }

impl AuthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.jwt_secret.is_empty() {
            return Err(ConfigError::Invalid("jwt_secret required".into()));
        }
        if self.jwt_secret.len() < 32 {
            return Err(ConfigError::Invalid("jwt_secret must be at least 32 characters".into()));
        }
        if self.bcrypt_cost < 10 || self.bcrypt_cost > 31 {
            return Err(ConfigError::Invalid("bcrypt_cost must be between 10 and 31".into()));
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_AUTH_JWT_SECRET` (Secret, Required)
- `VAULT_AUTH_JWT_EXPIRY_SECS`
- `VAULT_AUTH_REFRESH_TOKEN_EXPIRY_SECS`
- `VAULT_AUTH_BCRYPT_COST`
- `VAULT_AUTH_API_KEY_ENABLED`

### 2.7 Anonymization Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnonymizationConfig {
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,

    #[serde(skip_serializing)]
    pub hash_salt: Option<String>,

    #[serde(default = "default_faker_locale")]
    pub faker_locale: String,

    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

fn default_hash_algorithm() -> String { "SHA-256".to_string() }
fn default_faker_locale() -> String { "en_US".to_string() }
fn default_cache_size() -> usize { 10000 }

impl AnonymizationConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.hash_salt.is_none() {
            return Err(ConfigError::Invalid("hash_salt required".into()));
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_ANONYMIZATION_HASH_SALT` (Secret, Required)
- `VAULT_ANONYMIZATION_HASH_ALGORITHM`
- `VAULT_ANONYMIZATION_FAKER_LOCALE`

### 2.8 Observability Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservabilityConfig {
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub tracing: TracingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default = "default_log_format")]
    pub format: LogFormat,

    #[serde(default)]
    pub file_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> LogFormat { LogFormat::Json }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,

    #[serde(default = "default_metrics_port")]
    pub port: u16,

    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_enabled() -> bool { true }
fn default_metrics_port() -> u16 { 9090 }
fn default_metrics_path() -> String { "/metrics".to_string() }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub otlp_endpoint: Option<String>,

    #[serde(default = "default_service_name")]
    pub service_name: String,
}

fn default_service_name() -> String { "llm-data-vault".to_string() }

impl ObservabilityConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.tracing.enabled && self.tracing.otlp_endpoint.is_none() {
            return Err(ConfigError::Invalid("otlp_endpoint required when tracing enabled".into()));
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_LOGGING_LEVEL`
- `VAULT_LOGGING_FORMAT`
- `VAULT_LOGGING_FILE_PATH`
- `VAULT_METRICS_ENABLED`
- `VAULT_METRICS_PORT`
- `VAULT_TRACING_ENABLED`
- `VAULT_TRACING_OTLP_ENDPOINT`

### 2.9 Rate Limiting Configuration

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,

    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,

    #[serde(default = "default_burst_size")]
    pub burst_size: u32,

    #[serde(default = "default_storage_backend")]
    pub storage: RateLimitStorage,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitStorage {
    InMemory,
    Redis,
}

fn default_rate_limit_enabled() -> bool { true }
fn default_requests_per_minute() -> u32 { 60 }
fn default_burst_size() -> u32 { 10 }
fn default_storage_backend() -> RateLimitStorage { RateLimitStorage::InMemory }

impl RateLimitConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.requests_per_minute == 0 {
            return Err(ConfigError::Invalid("requests_per_minute must be non-zero".into()));
        }
        Ok(())
    }
}
```

**Environment Variables:**
- `VAULT_RATE_LIMITING_ENABLED`
- `VAULT_RATE_LIMITING_REQUESTS_PER_MINUTE`
- `VAULT_RATE_LIMITING_BURST_SIZE`

## 3. Environment Variable Reference

| Variable | Config Path | Type | Default | Required |
|----------|-------------|------|---------|----------|
| `VAULT_SERVER_HOST` | server.host | string | 0.0.0.0 | No |
| `VAULT_SERVER_PORT` | server.port | u16 | 8080 | No |
| `VAULT_SERVER_WORKERS` | server.workers | usize | num_cpus | No |
| `VAULT_SERVER_MAX_CONNECTIONS` | server.max_connections | usize | 1000 | No |
| `VAULT_SERVER_REQUEST_TIMEOUT_SECS` | server.request_timeout_secs | u64 | 30 | No |
| `VAULT_SERVER_TLS_CERT_PATH` | server.tls.cert_path | path | - | No |
| `VAULT_SERVER_TLS_KEY_PATH` | server.tls.key_path | path | - | No |
| `VAULT_DATABASE_URL` | database.url | string | - | **Yes** |
| `VAULT_DATABASE_POOL_SIZE` | database.pool_size | u32 | 10 | No |
| `VAULT_DATABASE_POOL_TIMEOUT_SECS` | database.pool_timeout_secs | u64 | 30 | No |
| `VAULT_STORAGE_BACKEND` | storage.backend | enum | local | No |
| `VAULT_STORAGE_LOCAL_DATA_DIR` | storage.local.data_dir | path | - | If local |
| `VAULT_STORAGE_S3_BUCKET` | storage.s3.bucket | string | - | If S3 |
| `VAULT_STORAGE_S3_REGION` | storage.s3.region | string | - | If S3 |
| `VAULT_STORAGE_S3_ACCESS_KEY_ID` | storage.s3.access_key_id | string | - | No (IAM) |
| `VAULT_STORAGE_S3_SECRET_ACCESS_KEY` | storage.s3.secret_access_key | string | - | No (IAM) |
| `VAULT_ENCRYPTION_MASTER_KEY` | encryption.master_key | string | - | **Yes** |
| `VAULT_ENCRYPTION_ALGORITHM` | encryption.algorithm | string | AES-256-GCM | No |
| `VAULT_ENCRYPTION_KMS_BACKEND` | encryption.kms_backend | enum | local | No |
| `VAULT_ENCRYPTION_AWS_KMS_KEY_ID` | encryption.aws_kms.key_id | string | - | If AWS KMS |
| `VAULT_AUTH_JWT_SECRET` | auth.jwt_secret | string | - | **Yes** |
| `VAULT_AUTH_JWT_EXPIRY_SECS` | auth.jwt_expiry_secs | u64 | 3600 | No |
| `VAULT_AUTH_BCRYPT_COST` | auth.bcrypt_cost | u32 | 12 | No |
| `VAULT_ANONYMIZATION_HASH_SALT` | anonymization.hash_salt | string | - | **Yes** |
| `VAULT_LOGGING_LEVEL` | observability.logging.level | string | info | No |
| `VAULT_LOGGING_FORMAT` | observability.logging.format | enum | json | No |
| `VAULT_METRICS_ENABLED` | observability.metrics.enabled | bool | true | No |
| `VAULT_METRICS_PORT` | observability.metrics.port | u16 | 9090 | No |
| `VAULT_TRACING_ENABLED` | observability.tracing.enabled | bool | false | No |
| `VAULT_TRACING_OTLP_ENDPOINT` | observability.tracing.otlp_endpoint | string | - | If tracing |
| `VAULT_RATE_LIMITING_ENABLED` | rate_limiting.enabled | bool | true | No |
| `VAULT_RATE_LIMITING_REQUESTS_PER_MINUTE` | rate_limiting.requests_per_minute | u32 | 60 | No |

## 4. Example vault.toml

```toml
# LLM Data Vault Configuration

[server]
host = "0.0.0.0"
port = 8080
workers = 4
max_connections = 1000
request_timeout_secs = 30
shutdown_timeout_secs = 10

[server.tls]
# cert_path = "/etc/vault/certs/server.crt"
# key_path = "/etc/vault/certs/server.key"
# client_ca_path = "/etc/vault/certs/ca.crt"

[database]
url = "postgresql://vault:password@localhost:5432/vault"
pool_size = 10
pool_timeout_secs = 30
connection_timeout_secs = 10
idle_timeout_secs = 600
max_lifetime_secs = 1800
auto_migrate = false

[storage]
backend = "local"

[storage.local]
data_dir = "/var/lib/vault/data"
max_file_size_mb = 100

# [storage.s3]
# bucket = "llm-vault-prod"
# region = "us-east-1"
# prefix = "vault/"
# endpoint = ""  # Optional: for S3-compatible storage

[encryption]
algorithm = "AES-256-GCM"
# master_key set via VAULT_ENCRYPTION_MASTER_KEY
kms_backend = "local"

# [encryption.aws_kms]
# key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
# region = "us-east-1"

[auth]
# jwt_secret set via VAULT_AUTH_JWT_SECRET
jwt_expiry_secs = 3600
refresh_token_expiry_secs = 2592000
bcrypt_cost = 12
api_key_enabled = true

[anonymization]
hash_algorithm = "SHA-256"
# hash_salt set via VAULT_ANONYMIZATION_HASH_SALT
faker_locale = "en_US"
cache_size = 10000

[observability.logging]
level = "info"
format = "json"
# file_path = "/var/log/vault/app.log"

[observability.metrics]
enabled = true
port = 9090
path = "/metrics"

[observability.tracing]
enabled = false
# otlp_endpoint = "http://jaeger:4317"
service_name = "llm-data-vault"

[rate_limiting]
enabled = true
requests_per_minute = 60
burst_size = 10
storage = "inmemory"
```

## 5. Secrets Management

### 5.1 Never Store in Config Files

The following MUST be provided via environment variables or external secrets management:

- `VAULT_ENCRYPTION_MASTER_KEY`
- `VAULT_AUTH_JWT_SECRET`
- `VAULT_ANONYMIZATION_HASH_SALT`
- `VAULT_DATABASE_URL` (contains password)
- `VAULT_STORAGE_S3_ACCESS_KEY_ID`
- `VAULT_STORAGE_S3_SECRET_ACCESS_KEY`

### 5.2 Development (Environment Variables)

```bash
export VAULT_ENCRYPTION_MASTER_KEY="dev-key-change-in-production-min-32-chars"
export VAULT_AUTH_JWT_SECRET="dev-jwt-secret-change-in-production-min-32-chars"
export VAULT_ANONYMIZATION_HASH_SALT="dev-salt-change-in-production"
export VAULT_DATABASE_URL="postgresql://vault:dev@localhost:5432/vault"
```

### 5.3 Production (AWS Secrets Manager)

```rust
use aws_sdk_secretsmanager::Client;

async fn load_secrets(config: &mut Config) -> Result<()> {
    let client = Client::new(&aws_config::load_from_env().await);

    // Load encryption master key
    let master_key = client
        .get_secret_value()
        .secret_id("vault/encryption/master-key")
        .send()
        .await?;
    config.encryption.master_key = Some(master_key.secret_string().unwrap().to_string());

    // Load JWT secret
    let jwt_secret = client
        .get_secret_value()
        .secret_id("vault/auth/jwt-secret")
        .send()
        .await?;
    config.auth.jwt_secret = jwt_secret.secret_string().unwrap().to_string();

    // Load database credentials
    let db_secret = client
        .get_secret_value()
        .secret_id("vault/database/credentials")
        .send()
        .await?;
    let db_creds: DbCredentials = serde_json::from_str(db_secret.secret_string().unwrap())?;
    config.database.url = format!(
        "postgresql://{}:{}@{}/{}",
        db_creds.username, db_creds.password, db_creds.host, db_creds.database
    );

    Ok(())
}
```

### 5.4 Production (HashiCorp Vault)

```rust
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

async fn load_from_vault(config: &mut Config) -> Result<()> {
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address("https://vault.example.com")
            .token(std::env::var("VAULT_TOKEN")?)
            .build()?
    )?;

    let secrets: std::collections::HashMap<String, String> =
        kv2::read(&client, "secret", "vault/config").await?;

    config.encryption.master_key = secrets.get("master_key").cloned();
    config.auth.jwt_secret = secrets.get("jwt_secret").unwrap().clone();
    config.anonymization.hash_salt = secrets.get("hash_salt").cloned();

    Ok(())
}
```

## 6. Environment-Specific Configurations

### 6.1 Development (vault.dev.toml)

```toml
[server]
host = "127.0.0.1"
port = 8080
workers = 2

[database]
url = "postgresql://vault:dev@localhost:5432/vault_dev"
pool_size = 5
auto_migrate = true

[storage]
backend = "local"

[storage.local]
data_dir = "./data"

[encryption]
kms_backend = "local"

[observability.logging]
level = "debug"
format = "text"

[rate_limiting]
enabled = false
```

### 6.2 Staging (vault.staging.toml)

```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
pool_size = 10
auto_migrate = false

[storage]
backend = "s3"

[storage.s3]
bucket = "llm-vault-staging"
region = "us-east-1"

[encryption]
kms_backend = "aws_kms"

[observability.logging]
level = "info"
format = "json"

[observability.tracing]
enabled = true
otlp_endpoint = "http://jaeger:4317"

[rate_limiting]
enabled = true
requests_per_minute = 100
```

### 6.3 Production (vault.prod.toml)

```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 8
max_connections = 2000

[server.tls]
cert_path = "/etc/vault/certs/server.crt"
key_path = "/etc/vault/certs/server.key"

[database]
pool_size = 20
auto_migrate = false

[storage]
backend = "s3"

[storage.s3]
bucket = "llm-vault-production"
region = "us-east-1"

[encryption]
kms_backend = "aws_kms"
key_rotation_days = 90

[observability.logging]
level = "info"
format = "json"
file_path = "/var/log/vault/app.log"

[observability.tracing]
enabled = true
otlp_endpoint = "http://tempo:4317"

[rate_limiting]
enabled = true
requests_per_minute = 60
burst_size = 10
storage = "redis"
```

## 7. Validation Requirements

### 7.1 Startup Validation

```rust
impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Required secrets
        if self.encryption.master_key.is_none() {
            return Err(ConfigError::MissingRequired("VAULT_ENCRYPTION_MASTER_KEY"));
        }

        if self.auth.jwt_secret.is_empty() {
            return Err(ConfigError::MissingRequired("VAULT_AUTH_JWT_SECRET"));
        }

        if self.anonymization.hash_salt.is_none() {
            return Err(ConfigError::MissingRequired("VAULT_ANONYMIZATION_HASH_SALT"));
        }

        // Database URL required in production
        if std::env::var("VAULT_ENV").unwrap_or_default() == "production" {
            if self.database.url.is_empty() || self.database.url.contains("localhost") {
                return Err(ConfigError::Invalid("Production database URL required"));
            }
        }

        // TLS required in production
        if std::env::var("VAULT_ENV").unwrap_or_default() == "production" {
            if self.server.tls.is_none() {
                return Err(ConfigError::Invalid("TLS required in production"));
            }
        }

        // Validate each subsection
        self.server.validate()?;
        self.database.validate()?;
        self.storage.validate()?;
        self.encryption.validate()?;
        self.auth.validate()?;
        self.anonymization.validate()?;
        self.observability.validate()?;
        self.rate_limiting.validate()?;

        Ok(())
    }
}
```

### 7.2 Required vs Optional Fields

**Always Required:**
- `encryption.master_key`
- `auth.jwt_secret`
- `anonymization.hash_salt`

**Required in Production:**
- `database.url` (not localhost)
- `server.tls.*`

**Conditionally Required:**
- `storage.local.*` (if backend = local)
- `storage.s3.*` (if backend = s3)
- `encryption.aws_kms.*` (if kms_backend = aws_kms)
- `observability.tracing.otlp_endpoint` (if tracing enabled)

## 8. Kubernetes Integration

### 8.1 ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-config
  namespace: vault
data:
  vault.toml: |
    [server]
    host = "0.0.0.0"
    port = 8080
    workers = 8
    max_connections = 2000
    request_timeout_secs = 30

    [server.tls]
    cert_path = "/etc/vault/certs/tls.crt"
    key_path = "/etc/vault/certs/tls.key"

    [database]
    pool_size = 20
    pool_timeout_secs = 30
    connection_timeout_secs = 10
    auto_migrate = false

    [storage]
    backend = "s3"

    [storage.s3]
    bucket = "llm-vault-production"
    region = "us-east-1"

    [encryption]
    algorithm = "AES-256-GCM"
    kms_backend = "aws_kms"

    [encryption.aws_kms]
    key_id = "arn:aws:kms:us-east-1:123456789012:key/vault-master-key"
    region = "us-east-1"

    [auth]
    jwt_expiry_secs = 3600
    refresh_token_expiry_secs = 2592000
    bcrypt_cost = 12
    api_key_enabled = true

    [anonymization]
    hash_algorithm = "SHA-256"
    faker_locale = "en_US"
    cache_size = 10000

    [observability.logging]
    level = "info"
    format = "json"

    [observability.metrics]
    enabled = true
    port = 9090
    path = "/metrics"

    [observability.tracing]
    enabled = true
    otlp_endpoint = "http://tempo.observability:4317"
    service_name = "llm-data-vault"

    [rate_limiting]
    enabled = true
    requests_per_minute = 60
    burst_size = 10
    storage = "inmemory"
```

### 8.2 Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-secrets
  namespace: vault
type: Opaque
stringData:
  database-url: "postgresql://vault:CHANGEME@postgres.database:5432/vault"
  encryption-master-key: "CHANGEME-32-char-minimum-encryption-key"
  jwt-secret: "CHANGEME-32-char-minimum-jwt-secret-key"
  hash-salt: "CHANGEME-hash-salt-for-anonymization"
```

### 8.3 Deployment (mounting configs)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
  namespace: vault
spec:
  template:
    spec:
      containers:
      - name: vault
        image: llm-data-vault:latest
        env:
        - name: VAULT_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: vault-secrets
              key: database-url
        - name: VAULT_ENCRYPTION_MASTER_KEY
          valueFrom:
            secretKeyRef:
              name: vault-secrets
              key: encryption-master-key
        - name: VAULT_AUTH_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: vault-secrets
              key: jwt-secret
        - name: VAULT_ANONYMIZATION_HASH_SALT
          valueFrom:
            secretKeyRef:
              name: vault-secrets
              key: hash-salt
        volumeMounts:
        - name: config
          mountPath: /etc/vault
          readOnly: true
        - name: tls-certs
          mountPath: /etc/vault/certs
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: vault-config
      - name: tls-certs
        secret:
          secretName: vault-tls
```

### 8.4 External Secrets Operator Integration

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-secrets
  namespace: vault
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: vault-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-url
    remoteRef:
      key: vault/production/database
      property: url
  - secretKey: encryption-master-key
    remoteRef:
      key: vault/production/encryption
      property: master_key
  - secretKey: jwt-secret
    remoteRef:
      key: vault/production/auth
      property: jwt_secret
  - secretKey: hash-salt
    remoteRef:
      key: vault/production/anonymization
      property: hash_salt
```
