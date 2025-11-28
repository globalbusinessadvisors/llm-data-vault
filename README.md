# LLM Data Vault

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

**Enterprise-grade secure storage and anonymization for LLM training data.**

LLM Data Vault provides a comprehensive solution for organizations to securely store, manage, and anonymize sensitive data used in Large Language Model training and inference workflows. It enables compliance with data protection regulations while maintaining data utility for AI/ML pipelines.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Reference](#cli-reference)
- [SDK Usage](#sdk-usage)
- [Security](#security)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Capabilities

- **Secure Data Storage** - AES-256-GCM encrypted storage with envelope encryption and KMS integration
- **PII Detection** - Automatic detection of 20+ PII types including emails, SSNs, credit cards, names, addresses
- **Data Anonymization** - Multiple strategies: redaction, masking, replacement, pseudonymization, generalization
- **Access Control** - Fine-grained RBAC/ABAC with JWT authentication and API key management
- **Audit Logging** - Tamper-evident audit trails with cryptographic integrity verification
- **Data Lineage** - Track data provenance and transformations across the pipeline
- **Version Control** - Full versioning of datasets and records with diff capabilities

### Security Hardening

- **Request Signing** - HMAC-SHA256 request signatures with replay protection
- **Threat Detection** - Rate limiting, IP blocking, SQL injection and XSS detection
- **Session Management** - Secure distributed sessions with regeneration and idle timeouts
- **Security Headers** - CSP, HSTS, X-Frame-Options, and CORS configuration
- **Input Validation** - Comprehensive sanitization and validation of all inputs
- **Secrets Management** - Encrypted secrets storage with key derivation and rotation

### DevOps Integration

- **CLI Tool** - Full-featured command-line interface for automation and scripting
- **CI/CD Support** - Exit codes and JSON output for pipeline integration
- **Multiple Output Formats** - Table, JSON, YAML, CSV for various use cases
- **Shell Completions** - Auto-completion for Bash, Zsh, Fish, PowerShell

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LLM Data Vault                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │   CLI    │  │   SDK    │  │  REST    │  │      gRPC        │ │
│  │  (vault) │  │  (Rust)  │  │   API    │  │      API         │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
│       │             │             │                  │           │
│  ┌────┴─────────────┴─────────────┴──────────────────┴─────────┐ │
│  │                     API Gateway (Axum)                       │ │
│  │  • Authentication  • Rate Limiting  • Request Validation    │ │
│  └──────────────────────────────┬──────────────────────────────┘ │
│                                 │                                 │
│  ┌──────────────────────────────┴──────────────────────────────┐ │
│  │                      Core Services                           │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │ │
│  │  │  Datasets   │  │   Records   │  │   PII Detection     │  │ │
│  │  │  Service    │  │   Service   │  │   & Anonymization   │  │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │ │
│  │  │   Access    │  │   Audit     │  │      Version        │  │ │
│  │  │   Control   │  │   Logging   │  │      Control        │  │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │ │
│  └──────────────────────────────┬──────────────────────────────┘ │
│                                 │                                 │
│  ┌──────────────────────────────┴──────────────────────────────┐ │
│  │                    Security Layer                            │ │
│  │  • Encryption (AES-256-GCM)  • Key Management (KMS)         │ │
│  │  • Threat Detection          • Session Management           │ │
│  └──────────────────────────────┬──────────────────────────────┘ │
│                                 │                                 │
│  ┌──────────────────────────────┴──────────────────────────────┐ │
│  │                    Storage Layer                             │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │ │
│  │  │  PostgreSQL │  │    Redis    │  │    Object Store     │  │ │
│  │  │  (metadata) │  │   (cache)   │  │   (S3/GCS/Azure)    │  │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Crate Structure

| Crate | Description |
|-------|-------------|
| `vault-core` | Core domain types, traits, and error handling |
| `vault-crypto` | Cryptographic primitives, encryption, and KMS integration |
| `vault-storage` | Storage backends (PostgreSQL, Redis, S3) |
| `vault-anonymize` | PII detection and anonymization engine |
| `vault-access` | Authentication, authorization, RBAC/ABAC |
| `vault-version` | Dataset and record versioning |
| `vault-integration` | External system integrations |
| `vault-api` | REST API handlers and middleware |
| `vault-server` | HTTP/gRPC server implementation |
| `vault-sdk` | Official Rust SDK for API clients |
| `vault-cli` | Command-line interface |
| `vault-migrations` | Database schema migrations |
| `vault-security` | Security hardening and threat detection |

---

## Quick Start

### Using Docker

```bash
# Start the vault server
docker run -d \
  -p 8080:8080 \
  -e VAULT_DATABASE_URL=postgres://... \
  -e VAULT_REDIS_URL=redis://... \
  ghcr.io/llm-data-vault/vault-server:latest

# Use the CLI
docker run --rm -it \
  -e VAULT_URL=http://localhost:8080 \
  -e VAULT_API_KEY=your-api-key \
  ghcr.io/llm-data-vault/vault-cli:latest \
  vault status
```

### Using Cargo

```bash
# Install the CLI
cargo install vault-cli

# Configure
export VAULT_URL=https://vault.example.com
export VAULT_API_KEY=your-api-key

# Check status
vault status

# Scan a file for PII
vault scan ./data/training.jsonl

# Anonymize a file
vault anonymize ./data/training.jsonl --output ./data/training.anonymized.jsonl
```

---

## Installation

### Prerequisites

- Rust 1.75 or later
- PostgreSQL 14+
- Redis 7+
- (Optional) AWS/GCP/Azure credentials for cloud storage

### Building from Source

```bash
# Clone the repository
git clone https://github.com/llm-data-vault/llm-data-vault.git
cd llm-data-vault

# Build all crates
cargo build --release

# Run tests
cargo test --workspace

# Install the CLI
cargo install --path crates/vault-cli
```

### Installing the CLI

```bash
# From crates.io (when published)
cargo install vault-cli

# Or download pre-built binaries from GitHub Releases
curl -sSL https://github.com/llm-data-vault/llm-data-vault/releases/latest/download/vault-linux-amd64 -o vault
chmod +x vault
sudo mv vault /usr/local/bin/
```

---

## CLI Reference

The `vault` CLI provides comprehensive commands for managing datasets, detecting PII, and integrating with DevOps workflows.

### Global Options

```
Options:
  --url <URL>           Vault API base URL [env: VAULT_URL]
  --api-key <KEY>       API key for authentication [env: VAULT_API_KEY]
  --token <TOKEN>       Bearer token for authentication [env: VAULT_TOKEN]
  -f, --format <FMT>    Output format: table, json, json-compact, yaml, plain [default: table]
  -P, --profile <NAME>  Configuration profile [default: default]
  --no-color            Disable colored output
  -v, --verbose         Enable verbose output
  -q, --quiet           Suppress all output except errors
```

### DevOps Commands

#### `vault status`

Check vault service status and connectivity.

```bash
# Basic status check
vault status

# Detailed component status
vault status --detailed

# JSON output for CI/CD
vault status --json
```

#### `vault scan <path>`

Scan files or directories for PII.

```bash
# Scan a single file
vault scan ./data/training.jsonl

# Scan directory recursively
vault scan ./data/ --recursive

# CI/CD mode - fail if PII detected
vault scan ./data/ --fail-on-detection

# Generate JSON report
vault scan ./data/ --report-format json --output report.json

# Filter by file patterns
vault scan ./data/ --include "*.json,*.txt" --exclude "*.log"

# Set confidence threshold
vault scan ./data/ --min-confidence 0.9
```

#### `vault anonymize <file>`

Anonymize a file by replacing PII with safe values.

```bash
# Anonymize to new file
vault anonymize ./data/training.jsonl --output ./data/training.safe.jsonl

# Anonymize in place (with backup)
vault anonymize ./data/training.jsonl --in-place --backup

# Choose anonymization strategy
vault anonymize ./data/training.jsonl --strategy mask    # j***@***.com
vault anonymize ./data/training.jsonl --strategy redact  # [EMAIL]
vault anonymize ./data/training.jsonl --strategy replace # fake data
```

#### `vault encrypt <file>`

Encrypt a file using vault encryption.

```bash
# Encrypt with key
vault encrypt ./sensitive.json --key $ENCRYPTION_KEY

# Encrypt with KMS key ID
vault encrypt ./sensitive.json --key-id arn:aws:kms:...

# Delete original after encryption
vault encrypt ./sensitive.json --key $KEY --delete-original
```

#### `vault decrypt <file>`

Decrypt a file encrypted with vault.

```bash
# Decrypt
vault decrypt ./sensitive.json.enc --key $ENCRYPTION_KEY

# Specify output file
vault decrypt ./sensitive.json.enc --output ./decrypted.json
```

#### `vault lineage inspect <dataset>`

Inspect data lineage for a dataset.

```bash
# Show all lineage
vault lineage inspect ds_abc123

# Show upstream sources
vault lineage inspect ds_abc123 --upstream

# Show downstream dependents
vault lineage inspect ds_abc123 --downstream

# Export as DOT graph
vault lineage inspect ds_abc123 --graph > lineage.dot
```

#### `vault audit-log`

View and query audit logs.

```bash
# View recent entries
vault audit-log

# Filter by actor
vault audit-log --actor user@example.com

# Filter by action
vault audit-log --action dataset.create

# Filter by time range
vault audit-log --from 2024-01-01T00:00:00Z --to 2024-01-31T23:59:59Z

# Follow mode (stream new entries)
vault audit-log --follow

# Export as JSON
vault audit-log --output-format json
```

### Data Management Commands

#### `vault datasets`

Manage datasets.

```bash
# List all datasets
vault datasets list

# Create a dataset
vault datasets create --name "Training Data v1" --format jsonl

# Get dataset details
vault datasets get ds_abc123

# Update dataset
vault datasets update ds_abc123 --description "Updated description"

# Delete dataset
vault datasets delete ds_abc123

# Get statistics
vault datasets stats ds_abc123

# Archive/unarchive
vault datasets archive ds_abc123
vault datasets unarchive ds_abc123
```

#### `vault records`

Manage records within datasets.

```bash
# List records
vault records list --dataset ds_abc123

# Create a record
vault records create --dataset ds_abc123 --json '{"text": "Hello world"}'

# Import from file
vault records import --dataset ds_abc123 --file ./data.jsonl

# Get record
vault records get --dataset ds_abc123 rec_xyz789

# Update record
vault records update --dataset ds_abc123 rec_xyz789 --status archived
```

#### `vault pii`

PII detection and anonymization.

```bash
# Detect PII in text
vault pii detect --text "Contact john@example.com or call 555-1234"

# Detect from file
vault pii detect --file ./message.txt

# Anonymize text
vault pii anonymize --text "My SSN is 123-45-6789" --strategy redact
```

### Authentication Commands

```bash
# Login with credentials
vault auth login --username admin --password ***

# Show current user
vault auth whoami

# Verify token
vault auth verify

# Logout
vault auth logout
```

### Configuration Commands

```bash
# Show configuration
vault config show

# Set configuration value
vault config set url https://vault.example.com

# Initialize new profile
vault config init --profile production

# List profiles
vault config profiles
```

---

## SDK Usage

The official Rust SDK provides a type-safe, async-first client for the Vault API.

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
vault-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Basic Usage

```rust
use vault_sdk::{VaultClient, DatasetCreate, RecordCreate, DatasetFormat};

#[tokio::main]
async fn main() -> Result<(), vault_sdk::Error> {
    // Create client with API key
    let client = VaultClient::builder()
        .base_url("https://vault.example.com")
        .api_key("vk_live_xxxxx")
        .build()?;

    // Create a dataset
    let dataset = client.datasets()
        .create(DatasetCreate::new("Training Data")
            .with_description("GPT fine-tuning dataset")
            .with_format(DatasetFormat::Jsonl))
        .await?;

    println!("Created dataset: {}", dataset.id);

    // Add records
    let record = client.records()
        .create(&dataset.id.to_string(), RecordCreate::json(serde_json::json!({
            "prompt": "What is the capital of France?",
            "completion": "Paris"
        })))
        .await?;

    // Check for PII
    let pii_result = client.pii()
        .detect("Contact john@example.com for more info")
        .await?;

    for entity in pii_result.entities {
        println!("Found {} at position {}-{}",
            entity.pii_type, entity.start, entity.end);
    }

    Ok(())
}
```

### Authentication Methods

```rust
use vault_sdk::VaultClient;
use std::time::Duration;

// API Key authentication
let client = VaultClient::builder()
    .base_url("https://vault.example.com")
    .api_key("vk_live_xxxxx")
    .build()?;

// Bearer token authentication
let client = VaultClient::builder()
    .base_url("https://vault.example.com")
    .bearer_token("eyJ...")
    .build()?;

// With custom timeout
let client = VaultClient::builder()
    .base_url("https://vault.example.com")
    .api_key("vk_live_xxxxx")
    .timeout(Duration::from_secs(30))
    .build()?;
```

### Error Handling

```rust
use vault_sdk::Error;

match client.datasets().get("ds_invalid").await {
    Ok(dataset) => println!("Found: {}", dataset.name),
    Err(Error::NotFound { resource, id }) => {
        println!("{} not found: {}", resource, id);
    }
    Err(Error::Unauthorized { message }) => {
        println!("Auth failed: {}", message);
    }
    Err(Error::RateLimited { retry_after }) => {
        println!("Rate limited, retry after {:?}", retry_after);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

### Retry Configuration

```rust
use std::time::Duration;

let client = VaultClient::builder()
    .base_url("https://vault.example.com")
    .api_key("vk_live_xxxxx")
    .max_retries(3)
    .initial_backoff(Duration::from_millis(100))
    .max_backoff(Duration::from_secs(10))
    .build()?;
```

### PII Detection and Anonymization

```rust
use vault_sdk::{PiiDetectionRequest, AnonymizationRequest, AnonymizationStrategy, PiiType};

// Detect PII with options
let result = client.pii()
    .detect_with_options(&PiiDetectionRequest::new(text)
        .with_min_confidence(0.9)
        .with_types(vec![PiiType::Email, PiiType::Phone])
        .with_context())
    .await?;

// Anonymize with custom strategy
let result = client.pii()
    .anonymize_with_options(&AnonymizationRequest::new(text)
        .with_strategy(AnonymizationStrategy::Mask)
        .with_type_strategy(PiiType::Email, AnonymizationStrategy::Replace))
    .await?;

println!("Anonymized: {}", result.anonymized_text);
```

### Available SDK Services

| Service | Methods |
|---------|---------|
| `client.datasets()` | `list`, `get`, `create`, `update`, `delete`, `stats` |
| `client.records()` | `list`, `get`, `create`, `create_bulk`, `update`, `delete` |
| `client.pii()` | `detect`, `detect_with_options`, `anonymize`, `anonymize_with_options`, `is_clean` |
| `client.webhooks()` | `list`, `get`, `create`, `update`, `delete`, `deliveries` |
| `client.api_keys()` | `list`, `get`, `create`, `revoke` |
| `client.auth()` | `login`, `refresh`, `me` |
| `client.health()` | `check` |

---

## Security

### Encryption

- **At Rest**: AES-256-GCM encryption for all stored data
- **In Transit**: TLS 1.3 for all network communication
- **Key Management**: Integration with AWS KMS, GCP KMS, Azure Key Vault, or HashiCorp Vault

### Authentication

- **API Keys**: Scoped API keys with rate limiting and IP restrictions
- **JWT Tokens**: Short-lived access tokens with refresh capability
- **OAuth 2.0**: Integration with identity providers (Okta, Auth0, etc.)

### Authorization

- **RBAC**: Role-based access control with predefined roles
- **ABAC**: Attribute-based policies for fine-grained control
- **Resource Policies**: Per-dataset and per-record access policies

### Threat Protection

- **Rate Limiting**: Token bucket algorithm with configurable limits
- **IP Blocking**: Automatic and manual IP blocklist management
- **Input Validation**: SQL injection, XSS, and path traversal detection
- **Request Signing**: HMAC-SHA256 signatures with replay protection

### Security Hardening Module (`vault-security`)

The `vault-security` crate provides comprehensive security capabilities:

| Component | Description |
|-----------|-------------|
| `SecurityConfig` | Environment-aware configuration with production validation |
| `SecretStore` | Encrypted secrets management with key derivation |
| `RequestSigner` | HMAC-SHA256 request signing with replay protection |
| `InputValidator` | SQL injection, XSS, path traversal detection |
| `SecurityHeaders` | CSP, HSTS, X-Frame-Options middleware |
| `ThreatDetector` | Rate limiting, IP blocking, attack detection |
| `SessionManager` | Secure distributed session management |
| `SecureAuditLog` | Tamper-evident audit logging with chain integrity |

### Audit & Compliance

- **Immutable Audit Logs**: Cryptographically linked audit entries
- **Data Lineage**: Track all data transformations and access
- **Compliance Reports**: GDPR, HIPAA, SOC 2 compliance support

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_URL` | API base URL | `http://localhost:8080` |
| `VAULT_API_KEY` | API key for authentication | - |
| `VAULT_TOKEN` | Bearer token for authentication | - |
| `VAULT_DATABASE_URL` | PostgreSQL connection string | - |
| `VAULT_REDIS_URL` | Redis connection string | - |
| `VAULT_LOG_LEVEL` | Logging level (trace, debug, info, warn, error) | `info` |
| `VAULT_ENCRYPTION_KEY` | Master encryption key | - |
| `VAULT_KMS_KEY_ID` | KMS key ID for envelope encryption | - |

### Configuration File

The CLI uses TOML configuration files stored in `~/.config/llm-data-vault/`:

```toml
# ~/.config/llm-data-vault/vault-cli/config.toml

url = "https://vault.example.com"
default_format = "table"
timeout_secs = 30
color = true
default_dataset = "ds_abc123"

# API key stored separately for security
# Use: vault config set api_key "vk_live_xxxxx"
```

### Server Configuration

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  workers: 4

database:
  url: "postgres://user:pass@localhost/vault"
  max_connections: 20
  min_connections: 5

redis:
  url: "redis://localhost:6379"
  pool_size: 10

security:
  encryption_key: "${VAULT_ENCRYPTION_KEY}"
  jwt_secret: "${VAULT_JWT_SECRET}"
  jwt_expiry_secs: 3600

  rate_limit:
    requests_per_second: 100
    burst_size: 200

  cors:
    allowed_origins: ["https://app.example.com"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE"]

storage:
  type: "s3"
  bucket: "vault-data"
  region: "us-east-1"

observability:
  otlp_endpoint: "http://otel-collector:4317"
  metrics_port: 9090
```

---

## API Reference

### REST API

Base URL: `https://vault.example.com/api/v1`

#### Datasets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/datasets` | List datasets |
| POST | `/datasets` | Create dataset |
| GET | `/datasets/{id}` | Get dataset |
| PATCH | `/datasets/{id}` | Update dataset |
| DELETE | `/datasets/{id}` | Delete dataset |
| GET | `/datasets/{id}/stats` | Get statistics |

#### Records

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/datasets/{id}/records` | List records |
| POST | `/datasets/{id}/records` | Create record |
| POST | `/datasets/{id}/records/bulk` | Bulk create |
| GET | `/datasets/{id}/records/{rid}` | Get record |
| PATCH | `/datasets/{id}/records/{rid}` | Update record |
| DELETE | `/datasets/{id}/records/{rid}` | Delete record |

#### PII

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/pii/detect` | Detect PII in text |
| POST | `/pii/anonymize` | Anonymize text |

#### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Login with credentials |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout |
| GET | `/auth/me` | Get current user |

### Example Requests

```bash
# Create a dataset
curl -X POST https://vault.example.com/api/v1/datasets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Training Data",
    "format": "jsonl",
    "description": "GPT fine-tuning dataset"
  }'

# Detect PII
curl -X POST https://vault.example.com/api/v1/pii/detect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact john@example.com or call 555-123-4567",
    "min_confidence": 0.8
  }'
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/llm-data-vault/llm-data-vault.git
cd llm-data-vault

# Install development dependencies
cargo install cargo-watch cargo-nextest

# Run tests
cargo nextest run

# Run with hot reload
cargo watch -x run

# Format and lint
cargo fmt
cargo clippy --all-targets
```

### Running Tests

```bash
# Unit tests
cargo test --workspace

# Integration tests (requires Docker)
cargo test --features integration

# With coverage
cargo llvm-cov --workspace
```

---

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

---

## Support

- **Documentation**: [https://docs.llm-data-vault.dev](https://docs.llm-data-vault.dev)
- **Issues**: [GitHub Issues](https://github.com/llm-data-vault/llm-data-vault/issues)
- **Discussions**: [GitHub Discussions](https://github.com/llm-data-vault/llm-data-vault/discussions)
- **Security**: security@llm-data-vault.dev

---

Built with Rust for performance, safety, and reliability.
