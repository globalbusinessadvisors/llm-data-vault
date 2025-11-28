# LLM Data Vault - Missing Components Implementation Guide

This document details all missing components identified in the production readiness assessment, with implementation guidance.

---

## 1. Documentation (CRITICAL)

### 1.1 OpenAPI Specification

**Location:** `docs/api/openapi.yaml`

**Template:**
```yaml
openapi: 3.0.3
info:
  title: LLM Data Vault API
  description: Secure LLM training data management API
  version: 1.0.0
  contact:
    name: API Support
    email: support@example.com
  license:
    name: LLMDevOps-PSACL v1.0

servers:
  - url: https://api.example.com/api/v1
    description: Production
  - url: https://staging-api.example.com/api/v1
    description: Staging

security:
  - bearerAuth: []
  - apiKeyAuth: []

paths:
  /health:
    get:
      summary: Health check
      tags: [Health]
      security: []
      responses:
        '200':
          description: Service is healthy

  /auth/login:
    post:
      summary: Authenticate user
      tags: [Authentication]
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Authentication successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'

  /datasets:
    get:
      summary: List datasets
      tags: [Datasets]
      parameters:
        - $ref: '#/components/parameters/PageSize'
        - $ref: '#/components/parameters/Cursor'
      responses:
        '200':
          description: List of datasets

    post:
      summary: Create dataset
      tags: [Datasets]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateDatasetRequest'
      responses:
        '201':
          description: Dataset created

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

  schemas:
    LoginRequest:
      type: object
      required: [email, password]
      properties:
        email:
          type: string
          format: email
        password:
          type: string
          format: password

    LoginResponse:
      type: object
      properties:
        access_token:
          type: string
        refresh_token:
          type: string
        expires_in:
          type: integer

    # Add all schemas...

  parameters:
    PageSize:
      name: limit
      in: query
      schema:
        type: integer
        default: 20
        maximum: 100
    Cursor:
      name: cursor
      in: query
      schema:
        type: string
```

### 1.2 README.md Enhancement

**Location:** `README.md`

```markdown
# LLM Data Vault

Secure, compliant data management for LLM training pipelines.

## Features

- **Encryption**: AES-256-GCM encryption with AWS KMS integration
- **PII Detection**: Automatic detection of 10+ PII types
- **Anonymization**: K-anonymity, differential privacy, tokenization
- **Access Control**: Fine-grained RBAC and ABAC
- **Versioning**: Git-like versioning with data lineage
- **Compliance**: GDPR, CCPA, HIPAA, PCI-DSS, SOC 2

## Quick Start

### Prerequisites
- Rust 1.75+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Development Setup

\`\`\`bash
# Clone repository
git clone https://github.com/your-org/llm-data-vault.git
cd llm-data-vault

# Start dependencies
docker-compose up -d postgres redis

# Build and run
cargo build --release
./target/release/vault-server
\`\`\`

### Docker

\`\`\`bash
docker pull your-registry/llm-data-vault:latest
docker run -p 8080:8080 -e VAULT__JWT_SECRET=your-secret your-registry/llm-data-vault:latest
\`\`\`

### Kubernetes

\`\`\`bash
kubectl apply -f deploy/kubernetes/
\`\`\`

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT__PORT` | Server port | 8080 |
| `VAULT__JWT_SECRET` | JWT signing secret | (required) |
| `VAULT__DATABASE__URL` | PostgreSQL URL | (required) |
| `VAULT__STORAGE__BACKEND` | Storage backend | memory |

See [Configuration Reference](docs/deployment/CONFIGURATION.md) for all options.

## API Documentation

- [OpenAPI Spec](docs/api/openapi.yaml)
- [Interactive Docs](https://api.example.com/docs)

## Architecture

\`\`\`
┌─────────────────────────────────────────────────────┐
│                   REST/gRPC API                      │
├─────────────────────────────────────────────────────┤
│  Auth │ Rate Limit │ Logging │ Metrics │ CORS      │
├───────┴────────────┴─────────┴─────────┴───────────┤
│           Handlers (Datasets, Records, Auth)        │
├─────────────────────────────────────────────────────┤
│  Access Control  │  PII Detection  │  Encryption   │
├──────────────────┴─────────────────┴───────────────┤
│     Versioning    │    Storage     │   Events      │
└─────────────────────────────────────────────────────┘
\`\`\`

## Documentation

- [Deployment Guide](docs/deployment/KUBERNETES.md)
- [Operations Runbook](docs/operations/RUNBOOK.md)
- [Security Hardening](docs/security/HARDENING.md)
- [API Reference](docs/api/openapi.yaml)

## License

LLMDevOps-PSACL v1.0 - See [LICENSE.md](LICENSE.md)
```

---

## 2. Integration Tests (CRITICAL)

### 2.1 Test Structure

**Location:** `tests/integration/`

```rust
// tests/integration/api_auth_test.rs
use axum::http::StatusCode;
use llm_data_vault_test_utils::TestServer;

#[tokio::test]
async fn test_login_success() {
    let server = TestServer::new().await;

    let response = server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "email": "test@example.com",
            "password": "password123"
        }))
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await;
    assert!(body.get("access_token").is_some());
    assert!(body.get("refresh_token").is_some());
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let server = TestServer::new().await;

    let response = server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({
            "email": "test@example.com",
            "password": "wrong"
        }))
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_endpoint_requires_auth() {
    let server = TestServer::new().await;

    let response = server
        .get("/api/v1/datasets")
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_endpoint_with_valid_token() {
    let server = TestServer::new().await;
    let token = server.login_as_admin().await;

    let response = server
        .get("/api/v1/datasets")
        .bearer_auth(&token)
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}
```

```rust
// tests/integration/api_datasets_test.rs
use axum::http::StatusCode;
use llm_data_vault_test_utils::TestServer;

#[tokio::test]
async fn test_create_dataset() {
    let server = TestServer::new().await;
    let token = server.login_as_admin().await;

    let response = server
        .post("/api/v1/datasets")
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "Test Dataset",
            "description": "Test description"
        }))
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let body: serde_json::Value = response.json().await;
    assert!(body.get("id").is_some());
}

#[tokio::test]
async fn test_list_datasets_pagination() {
    let server = TestServer::new().await;
    let token = server.login_as_admin().await;

    // Create 25 datasets
    for i in 0..25 {
        server.create_dataset(&token, &format!("Dataset {}", i)).await;
    }

    // Get first page
    let response = server
        .get("/api/v1/datasets?limit=10")
        .bearer_auth(&token)
        .send()
        .await;

    let body: serde_json::Value = response.json().await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 10);
    assert!(body.get("next_cursor").is_some());
}
```

```rust
// tests/integration/pii_detection_test.rs
use llm_data_vault_test_utils::TestServer;

#[tokio::test]
async fn test_pii_detection_email() {
    let server = TestServer::new().await;
    let token = server.login_as_admin().await;

    let dataset_id = server.create_dataset(&token, "PII Test").await;

    let response = server
        .post(&format!("/api/v1/datasets/{}/records", dataset_id))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "data": {
                "text": "Contact me at john.doe@example.com"
            }
        }))
        .send()
        .await;

    let body: serde_json::Value = response.json().await;
    let detections = body["pii_detections"].as_array().unwrap();

    assert!(!detections.is_empty());
    assert_eq!(detections[0]["type"], "email");
}

#[tokio::test]
async fn test_anonymization_redact() {
    let server = TestServer::new().await;
    let token = server.login_as_admin().await;

    let response = server
        .post("/api/v1/anonymize")
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "text": "My SSN is 123-45-6789",
            "strategy": "redact"
        }))
        .send()
        .await;

    let body: serde_json::Value = response.json().await;
    assert_eq!(body["result"], "My SSN is [REDACTED]");
}
```

### 2.2 Test Utilities

```rust
// tests/common/mod.rs
use std::sync::Arc;
use reqwest::Client;

pub struct TestServer {
    pub base_url: String,
    pub client: Client,
}

impl TestServer {
    pub async fn new() -> Self {
        // Start test server or use test instance
        let base_url = std::env::var("TEST_SERVER_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        Self {
            base_url,
            client: Client::new(),
        }
    }

    pub async fn login_as_admin(&self) -> String {
        let response = self
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({
                "email": "admin@example.com",
                "password": "admin123"
            }))
            .send()
            .await
            .expect("Login failed");

        let body: serde_json::Value = response.json().await.unwrap();
        body["access_token"].as_str().unwrap().to_string()
    }

    pub async fn create_dataset(&self, token: &str, name: &str) -> String {
        let response = self
            .post("/api/v1/datasets")
            .bearer_auth(token)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await
            .expect("Create dataset failed");

        let body: serde_json::Value = response.json().await.unwrap();
        body["id"].as_str().unwrap().to_string()
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client.get(format!("{}{}", self.base_url, path))
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.client.post(format!("{}{}", self.base_url, path))
    }
}
```

---

## 3. Database Migrations (HIGH)

### 3.1 Migration Files

**Location:** `migrations/`

```sql
-- migrations/20240101000000_initial_schema.sql
-- Initial schema setup

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(63) NOT NULL UNIQUE,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    roles TEXT[] DEFAULT '{}',
    permissions TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
```

```sql
-- migrations/20240101000001_create_datasets.sql

CREATE TABLE datasets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    schema_id UUID,
    settings JSONB DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    is_deleted BOOLEAN DEFAULT false,
    deleted_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_datasets_tenant ON datasets(tenant_id);
CREATE INDEX idx_datasets_created ON datasets(created_at);
CREATE INDEX idx_datasets_tags ON datasets USING gin(tags);
```

```sql
-- migrations/20240101000002_create_records.sql

CREATE TABLE records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_id UUID NOT NULL REFERENCES datasets(id),
    content_address VARCHAR(128) NOT NULL,
    content_hash VARCHAR(128) NOT NULL,
    size_bytes BIGINT NOT NULL,
    mime_type VARCHAR(127),
    metadata JSONB DEFAULT '{}',
    pii_detections JSONB DEFAULT '[]',
    is_anonymized BOOLEAN DEFAULT false,
    anonymization_strategy VARCHAR(63),
    version INTEGER NOT NULL DEFAULT 1,
    is_deleted BOOLEAN DEFAULT false,
    deleted_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_records_dataset ON records(dataset_id);
CREATE INDEX idx_records_content_address ON records(content_address);
CREATE INDEX idx_records_content_hash ON records(content_hash);
CREATE INDEX idx_records_created ON records(created_at);
```

```sql
-- migrations/20240101000003_create_versions.sql

CREATE TABLE commits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_id UUID NOT NULL REFERENCES datasets(id),
    parent_id UUID REFERENCES commits(id),
    tree_hash VARCHAR(128) NOT NULL,
    message TEXT,
    author_id UUID REFERENCES users(id),
    author_name VARCHAR(255),
    author_email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE branches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_id UUID NOT NULL REFERENCES datasets(id),
    name VARCHAR(255) NOT NULL,
    commit_id UUID REFERENCES commits(id),
    is_default BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(dataset_id, name)
);

CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_id UUID NOT NULL REFERENCES datasets(id),
    name VARCHAR(255) NOT NULL,
    commit_id UUID NOT NULL REFERENCES commits(id),
    message TEXT,
    tagger_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(dataset_id, name)
);

CREATE INDEX idx_commits_dataset ON commits(dataset_id);
CREATE INDEX idx_commits_parent ON commits(parent_id);
CREATE INDEX idx_branches_dataset ON branches(dataset_id);
```

```sql
-- migrations/20240101000004_create_audit_logs.sql

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(63) NOT NULL,
    resource_type VARCHAR(63) NOT NULL,
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    request_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at);

-- Partition by month for scalability
-- CREATE TABLE audit_logs_2024_01 PARTITION OF audit_logs
--     FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

```sql
-- migrations/20240101000005_create_access_control.sql

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id),
    name VARCHAR(63) NOT NULL,
    description TEXT,
    permissions TEXT[] DEFAULT '{}',
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    statements JSONB NOT NULL DEFAULT '[]',
    is_enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(8) NOT NULL,
    permissions TEXT[] DEFAULT '{}',
    rate_limit INTEGER,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
```

```sql
-- migrations/20240101000006_create_webhooks.sql

CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret_hash VARCHAR(255),
    events TEXT[] NOT NULL,
    is_active BOOLEAN DEFAULT true,
    retry_config JSONB DEFAULT '{"max_retries": 3, "backoff_seconds": 60}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_id UUID NOT NULL REFERENCES webhooks(id),
    event_type VARCHAR(63) NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    attempt_count INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    status VARCHAR(31) DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX idx_deliveries_status ON webhook_deliveries(status);
CREATE INDEX idx_deliveries_next_retry ON webhook_deliveries(next_retry_at) WHERE status = 'pending';
```

---

## 4. Monitoring Configuration (HIGH)

### 4.1 Prometheus Alerting Rules

**Location:** `monitoring/alerts/rules.yaml`

```yaml
groups:
  - name: llm-data-vault
    rules:
      # Availability
      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_total{status=~"5.."}[5m]))
          / sum(rate(http_requests_total[5m])) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: High error rate detected
          description: Error rate is {{ $value | humanizePercentage }}

      - alert: ServiceDown
        expr: up{job="vault-server"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: Vault server is down
          description: Instance {{ $labels.instance }} is unreachable

      # Latency
      - alert: HighLatencyP99
        expr: |
          histogram_quantile(0.99,
            sum(rate(http_request_duration_seconds_bucket[5m])) by (le)
          ) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: High API latency
          description: P99 latency is {{ $value | humanizeDuration }}

      - alert: HighLatencyP95
        expr: |
          histogram_quantile(0.95,
            sum(rate(http_request_duration_seconds_bucket[5m])) by (le)
          ) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: Elevated API latency
          description: P95 latency is {{ $value | humanizeDuration }}

      # Security
      - alert: HighAuthFailureRate
        expr: |
          sum(rate(auth_failures_total[5m])) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High authentication failure rate
          description: {{ $value }} auth failures per second

      - alert: RateLimitExceeded
        expr: |
          sum(rate(rate_limit_exceeded_total[5m])) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High rate limit exceeded events
          description: {{ $value }} rate limit events per second

      # Resources
      - alert: HighMemoryUsage
        expr: |
          container_memory_usage_bytes{container="vault-server"}
          / container_spec_memory_limit_bytes > 0.85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: High memory usage
          description: Memory usage is {{ $value | humanizePercentage }}

      - alert: HighCPUUsage
        expr: |
          rate(container_cpu_usage_seconds_total{container="vault-server"}[5m]) > 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: High CPU usage
          description: CPU usage is {{ $value | humanizePercentage }}

      # Storage
      - alert: StorageHighUtilization
        expr: storage_used_bytes / storage_total_bytes > 0.85
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: Storage utilization high
          description: Storage is {{ $value | humanizePercentage }} full

      # Business
      - alert: PIIDetectionSpike
        expr: |
          sum(rate(pii_detections_total[5m]))
          > 3 * sum(rate(pii_detections_total[1h] offset 1d))
        for: 15m
        labels:
          severity: info
        annotations:
          summary: Unusual PII detection activity
          description: PII detections are 3x higher than yesterday
```

### 4.2 Grafana Dashboard

**Location:** `monitoring/dashboards/overview.json`

```json
{
  "dashboard": {
    "title": "LLM Data Vault - Overview",
    "tags": ["llm-data-vault"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "targets": [
          {
            "expr": "sum(rate(http_requests_total[5m]))",
            "legendFormat": "Total RPS"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{status=~\"5..\"}[5m])) / sum(rate(http_requests_total[5m])) * 100",
            "legendFormat": "Error %"
          }
        ]
      },
      {
        "title": "Latency Percentiles",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
        "targets": [
          {
            "expr": "histogram_quantile(0.50, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
            "legendFormat": "p50"
          },
          {
            "expr": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
            "legendFormat": "p95"
          },
          {
            "expr": "histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))",
            "legendFormat": "p99"
          }
        ]
      },
      {
        "title": "Active Requests",
        "type": "stat",
        "gridPos": {"h": 4, "w": 6, "x": 12, "y": 8},
        "targets": [
          {
            "expr": "sum(http_requests_active)",
            "legendFormat": "Active"
          }
        ]
      }
    ]
  }
}
```

---

## 5. Security Middleware (HIGH)

### 5.1 Security Headers

**Location:** `crates/vault-api/src/middleware/security.rs`

```rust
//! Security headers middleware.

use axum::{
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

/// Adds security headers to all responses.
pub async fn security_headers<B>(req: Request<B>, next: Next<B>) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // Prevent MIME type sniffing
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );

    // XSS protection (legacy browsers)
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer policy
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Content Security Policy
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
    );

    // HSTS (only if TLS)
    // headers.insert(
    //     header::STRICT_TRANSPORT_SECURITY,
    //     HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    // );

    // Permissions policy
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    response
}
```

---

## 6. Terraform Modules (HIGH)

### 6.1 AWS EKS Module

**Location:** `terraform/modules/aws/eks/main.tf`

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "cluster_name" {
  type        = string
  description = "Name of the EKS cluster"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the cluster"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for the cluster"
}

variable "node_instance_types" {
  type        = list(string)
  default     = ["t3.medium"]
  description = "Instance types for node group"
}

variable "node_desired_size" {
  type        = number
  default     = 3
  description = "Desired number of nodes"
}

resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = "1.28"

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
  ]
}

resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-nodes"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  instance_types  = var.node_instance_types

  scaling_config {
    desired_size = var.node_desired_size
    max_size     = var.node_desired_size * 2
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_policy,
    aws_iam_role_policy_attachment.cni_policy,
    aws_iam_role_policy_attachment.ecr_policy,
  ]
}

resource "aws_kms_key" "eks" {
  description             = "EKS secret encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# IAM roles and policies...
resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role" "node" {
  name = "${var.cluster_name}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node.name
}

resource "aws_iam_role_policy_attachment" "ecr_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "cluster_ca_certificate" {
  value = aws_eks_cluster.main.certificate_authority[0].data
}

output "cluster_name" {
  value = aws_eks_cluster.main.name
}
```

---

## 7. Operations Runbook Template

**Location:** `docs/operations/RUNBOOK.md`

```markdown
# LLM Data Vault Operations Runbook

## Service Overview

- **Service:** LLM Data Vault
- **Port:** 8080 (API), 9090 (Metrics)
- **Health Endpoint:** /health/ready

## Startup Procedure

1. Verify dependencies are running:
   \`\`\`bash
   kubectl get pods -l app=postgres
   kubectl get pods -l app=redis
   \`\`\`

2. Deploy the service:
   \`\`\`bash
   kubectl apply -f deploy/kubernetes/
   \`\`\`

3. Verify deployment:
   \`\`\`bash
   kubectl rollout status deployment/vault-server
   kubectl get pods -l app=vault-server
   \`\`\`

4. Check health:
   \`\`\`bash
   kubectl port-forward svc/vault-server 8080:8080
   curl http://localhost:8080/health/ready
   \`\`\`

## Shutdown Procedure

1. Graceful shutdown:
   \`\`\`bash
   kubectl scale deployment vault-server --replicas=0
   \`\`\`

2. Wait for connections to drain (60s timeout)

3. Verify shutdown:
   \`\`\`bash
   kubectl get pods -l app=vault-server
   \`\`\`

## Common Issues

### Issue: High Error Rate

**Symptoms:** Error rate > 1% for 5+ minutes

**Investigation:**
1. Check logs: \`kubectl logs -l app=vault-server --tail=100\`
2. Check metrics: Error rate by endpoint
3. Check dependencies: Database, Redis, S3

**Resolution:**
- If database issue: Check connection pool, restart if needed
- If memory issue: Scale up or restart pods
- If external service: Check AWS status, failover if needed

### Issue: High Latency

**Symptoms:** P99 > 1s for 10+ minutes

**Investigation:**
1. Check active requests: \`curl /health/detailed\`
2. Check database query times
3. Check network latency

**Resolution:**
- Scale horizontally: \`kubectl scale deployment vault-server --replicas=5\`
- Check slow queries in database
- Enable caching if not active

### Issue: Authentication Failures

**Symptoms:** > 10 auth failures/second

**Investigation:**
1. Check for brute force: \`grep "auth failure" logs\`
2. Check JWT secret validity
3. Check token expiration settings

**Resolution:**
- If brute force: Block IP range
- If config issue: Verify JWT_SECRET environment variable
- If expired tokens: Check clock sync between services

## Rollback Procedure

1. Get previous revision:
   \`\`\`bash
   kubectl rollout history deployment/vault-server
   \`\`\`

2. Rollback:
   \`\`\`bash
   kubectl rollout undo deployment/vault-server
   \`\`\`

3. Verify:
   \`\`\`bash
   kubectl rollout status deployment/vault-server
   \`\`\`

## Contact

- **On-Call:** [PagerDuty/Slack link]
- **Escalation:** [Team lead contact]
- **Documentation:** [Link to wiki]
```

---

## Summary

This document provides implementation templates for all critical missing components. Priority order:

1. **Week 1:** API Documentation, README, Security hardening
2. **Week 2:** Integration tests, Operations runbook
3. **Month 1:** Database migrations, Terraform modules, Monitoring
4. **Quarter 1:** E2E tests, Performance benchmarks, DR procedures

Estimated total effort: 4-6 weeks for production readiness.
