# Configuration Reference

Complete reference for all LLM Data Vault configuration options.

## Configuration Sources

Configuration is loaded in the following order (later sources override earlier):

1. Default values (built-in)
2. Configuration file (`config/default.toml`)
3. Environment-specific file (`config/{environment}.toml`)
4. Environment variables (prefix: `VAULT__`)
5. Command-line arguments

## Environment Variables

All configuration options can be set via environment variables using the `VAULT__` prefix with double underscores for nested values.

**Examples:**
- `VAULT__PORT=8080`
- `VAULT__DATABASE__URL=postgres://...`
- `VAULT__STORAGE__S3__BUCKET=my-bucket`

---

## Server Configuration

### Basic Settings

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `host` | `VAULT__HOST` | string | `0.0.0.0` | Bind address |
| `port` | `VAULT__PORT` | integer | `8080` | HTTP port |
| `service_name` | `VAULT__SERVICE_NAME` | string | `llm-data-vault` | Service identifier |
| `debug` | `VAULT__DEBUG` | boolean | `false` | Enable debug mode |

```toml
# config/default.toml
host = "0.0.0.0"
port = 8080
service_name = "llm-data-vault"
debug = false
```

### Request Handling

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `max_body_size` | `VAULT__MAX_BODY_SIZE` | integer | `10485760` | Max request body (bytes) |
| `request_timeout_seconds` | `VAULT__REQUEST_TIMEOUT_SECONDS` | integer | `30` | Request timeout |

```toml
max_body_size = 10485760  # 10MB
request_timeout_seconds = 30
```

---

## Authentication

### JWT Configuration

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `jwt_secret` | `VAULT__JWT_SECRET` | string | **required** | JWT signing secret (min 32 chars) |
| `jwt_issuer` | `VAULT__JWT_ISSUER` | string | `llm-data-vault` | JWT issuer claim |
| `jwt_audience` | `VAULT__JWT_AUDIENCE` | string | `llm-data-vault` | JWT audience claim |
| `token_expiry_hours` | `VAULT__TOKEN_EXPIRY_HOURS` | integer | `24` | Access token lifetime (hours) |
| `refresh_token_days` | `VAULT__REFRESH_TOKEN_DAYS` | integer | `7` | Refresh token lifetime (days) |

```toml
jwt_secret = "your-secure-secret-at-least-32-characters-long"
jwt_issuer = "llm-data-vault"
jwt_audience = "llm-data-vault"
token_expiry_hours = 24
refresh_token_days = 7
```

**Security Notes:**
- `jwt_secret` must be at least 32 characters
- Use a cryptographically secure random value
- Rotate secrets periodically
- Never commit secrets to version control

### API Keys

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `api_key_prefix` | `VAULT__API_KEY_PREFIX` | string | `vault_` | Prefix for generated API keys |
| `api_key_hash_algorithm` | `VAULT__API_KEY_HASH_ALGORITHM` | string | `blake3` | Hash algorithm for storage |

```toml
api_key_prefix = "vault_"
api_key_hash_algorithm = "blake3"
```

---

## Database

### PostgreSQL Connection

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `database.url` | `VAULT__DATABASE__URL` | string | - | PostgreSQL connection URL |
| `database.max_connections` | `VAULT__DATABASE__MAX_CONNECTIONS` | integer | `10` | Max pool size |
| `database.min_connections` | `VAULT__DATABASE__MIN_CONNECTIONS` | integer | `1` | Min pool size |
| `database.connect_timeout_seconds` | `VAULT__DATABASE__CONNECT_TIMEOUT_SECONDS` | integer | `30` | Connection timeout |
| `database.idle_timeout_seconds` | `VAULT__DATABASE__IDLE_TIMEOUT_SECONDS` | integer | `600` | Idle connection timeout |

```toml
[database]
url = "postgres://user:password@localhost:5432/vault?sslmode=prefer"
max_connections = 10
min_connections = 1
connect_timeout_seconds = 30
idle_timeout_seconds = 600
```

**Connection URL Format:**
```
postgres://[user[:password]@][host][:port][/database][?param=value]
```

**SSL Modes:**
- `disable` - No SSL
- `prefer` - Try SSL, fall back to non-SSL
- `require` - Require SSL
- `verify-ca` - Verify server certificate
- `verify-full` - Verify server certificate and hostname

---

## Storage

### Backend Selection

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `storage.backend` | `VAULT__STORAGE__BACKEND` | string | `memory` | Backend type |

Available backends: `memory`, `filesystem`, `s3`

### In-Memory Backend

For development and testing only.

```toml
[storage]
backend = "memory"
```

### Filesystem Backend

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `storage.filesystem.path` | `VAULT__STORAGE__FILESYSTEM__PATH` | string | `./data` | Storage directory |
| `storage.filesystem.create_if_missing` | `VAULT__STORAGE__FILESYSTEM__CREATE_IF_MISSING` | boolean | `true` | Create directory |

```toml
[storage]
backend = "filesystem"

[storage.filesystem]
path = "/var/lib/vault/data"
create_if_missing = true
```

### S3 Backend

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `storage.s3.bucket` | `VAULT__STORAGE__S3__BUCKET` | string | **required** | S3 bucket name |
| `storage.s3.region` | `VAULT__STORAGE__S3__REGION` | string | `us-east-1` | AWS region |
| `storage.s3.prefix` | `VAULT__STORAGE__S3__PREFIX` | string | `` | Key prefix |
| `storage.s3.endpoint` | `VAULT__STORAGE__S3__ENDPOINT` | string | - | Custom endpoint (for S3-compatible) |

```toml
[storage]
backend = "s3"

[storage.s3]
bucket = "llm-data-vault-production"
region = "us-east-1"
prefix = "data/"
# endpoint = "https://s3.custom-endpoint.com"  # For S3-compatible storage
```

**AWS Credentials:**

Credentials are loaded from the standard AWS credential chain:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. IAM instance profile (EC2/ECS/EKS)
4. IAM role (for EKS with IRSA)

### Storage Options

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `storage.max_object_size` | `VAULT__STORAGE__MAX_OBJECT_SIZE` | integer | `104857600` | Max object size (100MB) |
| `storage.chunk_size` | `VAULT__STORAGE__CHUNK_SIZE` | integer | `4194304` | Chunk size for large objects (4MB) |
| `storage.compression` | `VAULT__STORAGE__COMPRESSION` | boolean | `true` | Enable compression |
| `storage.encryption` | `VAULT__STORAGE__ENCRYPTION` | boolean | `true` | Enable encryption at rest |

```toml
[storage]
max_object_size = 104857600  # 100MB
chunk_size = 4194304         # 4MB
compression = true
encryption = true
```

---

## Encryption

### KMS Provider

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `encryption.kms_provider` | `VAULT__ENCRYPTION__KMS_PROVIDER` | string | `local` | KMS provider |
| `encryption.master_key` | `VAULT__ENCRYPTION__MASTER_KEY` | string | - | Master key (local provider) |

Available providers: `local`, `aws`

### Local Provider

```toml
[encryption]
kms_provider = "local"
master_key = "your-32-byte-master-key-here"  # Base64 encoded
```

### AWS KMS Provider

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `encryption.aws.key_id` | `VAULT__ENCRYPTION__AWS__KEY_ID` | string | **required** | KMS key ID or ARN |
| `encryption.aws.region` | `VAULT__ENCRYPTION__AWS__REGION` | string | `us-east-1` | AWS region |

```toml
[encryption]
kms_provider = "aws"

[encryption.aws]
key_id = "arn:aws:kms:us-east-1:123456789:key/abcd-1234"
region = "us-east-1"
```

### Data Key Caching

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `encryption.cache_size` | `VAULT__ENCRYPTION__CACHE_SIZE` | integer | `1000` | Max cached keys |
| `encryption.cache_ttl_seconds` | `VAULT__ENCRYPTION__CACHE_TTL_SECONDS` | integer | `300` | Cache TTL |

```toml
[encryption]
cache_size = 1000
cache_ttl_seconds = 300
```

---

## Rate Limiting

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `rate_limit_rps` | `VAULT__RATE_LIMIT_RPS` | integer | `100` | Requests per second |
| `rate_limit_burst` | `VAULT__RATE_LIMIT_BURST` | integer | `200` | Burst size |

```toml
rate_limit_rps = 100
rate_limit_burst = 200
```

---

## CORS

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `cors_origins` | `VAULT__CORS_ORIGINS` | array | `["*"]` | Allowed origins |
| `cors_max_age` | `VAULT__CORS_MAX_AGE` | integer | `3600` | Preflight cache (seconds) |

```toml
cors_origins = ["https://app.example.com", "https://admin.example.com"]
cors_max_age = 3600
```

**For production, always specify explicit origins instead of `*`.**

---

## Telemetry

### Logging

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `telemetry.log_level` | `VAULT__TELEMETRY__LOG_LEVEL` | string | `info` | Log level |
| `telemetry.log_format` | `VAULT__TELEMETRY__LOG_FORMAT` | string | `json` | Log format |

Log levels: `trace`, `debug`, `info`, `warn`, `error`
Log formats: `json`, `pretty`

```toml
[telemetry]
log_level = "info"
log_format = "json"
```

### Metrics

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `telemetry.enable_metrics` | `VAULT__TELEMETRY__ENABLE_METRICS` | boolean | `true` | Enable Prometheus metrics |
| `telemetry.metrics_port` | `VAULT__TELEMETRY__METRICS_PORT` | integer | `9090` | Metrics port |

```toml
[telemetry]
enable_metrics = true
metrics_port = 9090
```

### Tracing

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `telemetry.enable_tracing` | `VAULT__TELEMETRY__ENABLE_TRACING` | boolean | `true` | Enable tracing |
| `telemetry.otlp_endpoint` | `VAULT__TELEMETRY__OTLP_ENDPOINT` | string | - | OTLP collector endpoint |
| `telemetry.service_name` | `VAULT__TELEMETRY__SERVICE_NAME` | string | `llm-data-vault` | Service name for traces |

```toml
[telemetry]
enable_tracing = true
otlp_endpoint = "http://otel-collector:4317"
service_name = "llm-data-vault"
```

---

## PII Detection

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `pii.min_confidence` | `VAULT__PII__MIN_CONFIDENCE` | float | `0.5` | Minimum confidence threshold |
| `pii.context_analysis` | `VAULT__PII__CONTEXT_ANALYSIS` | boolean | `true` | Enable context analysis |
| `pii.context_window` | `VAULT__PII__CONTEXT_WINDOW` | integer | `100` | Context window (chars) |

```toml
[pii]
min_confidence = 0.5
context_analysis = true
context_window = 100
```

### Compliance Framework

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `pii.compliance_framework` | `VAULT__PII__COMPLIANCE_FRAMEWORK` | string | `gdpr` | Active framework |

Available: `gdpr`, `ccpa`, `hipaa`, `pci_dss`, `soc2`

```toml
[pii]
compliance_framework = "gdpr"
```

---

## Webhooks

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `webhooks.max_retries` | `VAULT__WEBHOOKS__MAX_RETRIES` | integer | `3` | Max delivery retries |
| `webhooks.retry_backoff_seconds` | `VAULT__WEBHOOKS__RETRY_BACKOFF_SECONDS` | integer | `60` | Base backoff |
| `webhooks.timeout_seconds` | `VAULT__WEBHOOKS__TIMEOUT_SECONDS` | integer | `30` | Request timeout |

```toml
[webhooks]
max_retries = 3
retry_backoff_seconds = 60
timeout_seconds = 30
```

---

## Redis (Optional)

For distributed rate limiting and caching:

| Option | Env Variable | Type | Default | Description |
|--------|--------------|------|---------|-------------|
| `redis.url` | `VAULT__REDIS__URL` | string | - | Redis connection URL |
| `redis.pool_size` | `VAULT__REDIS__POOL_SIZE` | integer | `10` | Connection pool size |

```toml
[redis]
url = "redis://localhost:6379"
pool_size = 10
```

---

## Complete Example

```toml
# config/production.toml

# Server
host = "0.0.0.0"
port = 8080
service_name = "llm-data-vault"
debug = false
max_body_size = 10485760
request_timeout_seconds = 30

# Authentication
jwt_secret = "${VAULT__JWT_SECRET}"  # From environment
jwt_issuer = "llm-data-vault"
jwt_audience = "llm-data-vault"
token_expiry_hours = 24
refresh_token_days = 7

# Rate Limiting
rate_limit_rps = 100
rate_limit_burst = 200

# CORS
cors_origins = ["https://app.example.com"]

# Database
[database]
url = "${VAULT__DATABASE__URL}"
max_connections = 20
min_connections = 5

# Storage
[storage]
backend = "s3"
max_object_size = 104857600
compression = true
encryption = true

[storage.s3]
bucket = "llm-data-vault-prod"
region = "us-east-1"
prefix = "data/"

# Encryption
[encryption]
kms_provider = "aws"

[encryption.aws]
key_id = "${VAULT__ENCRYPTION__AWS__KEY_ID}"
region = "us-east-1"

# Telemetry
[telemetry]
log_level = "info"
log_format = "json"
enable_metrics = true
metrics_port = 9090
enable_tracing = true
otlp_endpoint = "http://otel-collector:4317"

# PII Detection
[pii]
min_confidence = 0.5
context_analysis = true
compliance_framework = "gdpr"

# Webhooks
[webhooks]
max_retries = 3
retry_backoff_seconds = 60
timeout_seconds = 30

# Redis
[redis]
url = "${VAULT__REDIS__URL}"
pool_size = 10
```

---

## Environment-Specific Overrides

Create environment-specific files:

- `config/development.toml`
- `config/staging.toml`
- `config/production.toml`

Set the environment:

```bash
export VAULT__ENV=production
```

---

## Validation

The server validates configuration on startup and will fail with a clear error message if:

- Required values are missing
- Values are invalid (wrong type, out of range)
- JWT secret is too short
- Database URL is malformed
- S3 bucket doesn't exist (with S3 backend)

---

## See Also

- [Deployment Guide](KUBERNETES.md)
- [Security Hardening](../security/HARDENING.md)
- [Operations Runbook](../operations/RUNBOOK.md)
