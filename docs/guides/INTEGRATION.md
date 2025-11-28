# API Integration Guide

This guide provides comprehensive instructions for integrating with LLM Data Vault's REST API.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication](#authentication)
3. [Working with Datasets](#working-with-datasets)
4. [Managing Records](#managing-records)
5. [PII Detection & Anonymization](#pii-detection--anonymization)
6. [Webhooks](#webhooks)
7. [Error Handling](#error-handling)
8. [Rate Limiting](#rate-limiting)
9. [Best Practices](#best-practices)
10. [SDK Examples](#sdk-examples)

---

## Getting Started

### Base URL

```
Production:  https://api.yourdomain.com/api/v1
Staging:     https://staging-api.yourdomain.com/api/v1
Development: http://localhost:8080/api/v1
```

### Request Format

All requests must:
- Use `Content-Type: application/json` for request bodies
- Include `Authorization: Bearer <token>` header for authenticated endpoints
- Use UTF-8 encoding

### Response Format

All responses return JSON with this structure:

**Success Response**:
```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "request_id": "req_abc123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

**Error Response**:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input",
    "details": [
      { "field": "email", "message": "Invalid email format" }
    ]
  },
  "meta": {
    "request_id": "req_abc123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

## Authentication

### Login

Obtain an access token with user credentials:

```bash
curl -X POST https://api.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your-password"
  }'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
}
```

### Using the Token

Include the access token in all subsequent requests:

```bash
curl https://api.yourdomain.com/api/v1/datasets \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Refreshing Tokens

Before the access token expires, refresh it:

```bash
curl -X POST https://api.yourdomain.com/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

### API Keys

For service-to-service authentication, use API keys:

```bash
# Create an API key (requires admin privileges)
curl -X POST https://api.yourdomain.com/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ML Pipeline",
    "scopes": ["dataset:read", "record:read", "record:create"],
    "expires_at": "2025-01-01T00:00:00Z"
  }'
```

Use the API key:
```bash
curl https://api.yourdomain.com/api/v1/datasets \
  -H "Authorization: ApiKey vault_sk_abc123..."
```

---

## Working with Datasets

### Create a Dataset

```bash
curl -X POST https://api.yourdomain.com/api/v1/datasets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Customer Support Conversations",
    "description": "Training data for support chatbot",
    "tags": ["support", "chatbot", "v1"],
    "schema": {
      "type": "object",
      "properties": {
        "text": { "type": "string" },
        "category": { "type": "string" },
        "sentiment": { "type": "string", "enum": ["positive", "negative", "neutral"] }
      },
      "required": ["text"]
    }
  }'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "id": "ds_abc123",
    "name": "Customer Support Conversations",
    "description": "Training data for support chatbot",
    "tags": ["support", "chatbot", "v1"],
    "schema": { ... },
    "record_count": 0,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
}
```

### List Datasets

```bash
# Basic listing
curl https://api.yourdomain.com/api/v1/datasets \
  -H "Authorization: Bearer $TOKEN"

# With pagination and filtering
curl "https://api.yourdomain.com/api/v1/datasets?limit=20&offset=0&tags=support" \
  -H "Authorization: Bearer $TOKEN"
```

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Max results (default: 20, max: 100) |
| `offset` | integer | Pagination offset |
| `tags` | string | Filter by tag (comma-separated) |
| `search` | string | Search in name/description |
| `sort` | string | Sort field (created_at, updated_at, name) |
| `order` | string | Sort order (asc, desc) |

### Get Dataset Details

```bash
curl https://api.yourdomain.com/api/v1/datasets/ds_abc123 \
  -H "Authorization: Bearer $TOKEN"
```

### Update Dataset

```bash
curl -X PATCH https://api.yourdomain.com/api/v1/datasets/ds_abc123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "tags": ["support", "chatbot", "v2"]
  }'
```

### Delete Dataset

```bash
curl -X DELETE https://api.yourdomain.com/api/v1/datasets/ds_abc123 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Managing Records

### Add a Single Record

```bash
curl -X POST https://api.yourdomain.com/api/v1/datasets/ds_abc123/records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "text": "Hello, how can I assist you today?",
      "category": "greeting",
      "sentiment": "positive"
    },
    "metadata": {
      "source": "web_chat",
      "session_id": "sess_xyz789"
    }
  }'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "id": "rec_def456",
    "dataset_id": "ds_abc123",
    "data": {
      "text": "Hello, how can I assist you today?",
      "category": "greeting",
      "sentiment": "positive"
    },
    "metadata": {
      "source": "web_chat",
      "session_id": "sess_xyz789"
    },
    "content_hash": "3b45c8a9f2e1d...",
    "pii_detected": false,
    "version": 1,
    "created_at": "2024-01-15T10:35:00Z"
  }
}
```

### Bulk Insert Records

```bash
curl -X POST https://api.yourdomain.com/api/v1/datasets/ds_abc123/records/bulk \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "records": [
      {
        "data": { "text": "First message", "category": "greeting" }
      },
      {
        "data": { "text": "Second message", "category": "question" }
      },
      {
        "data": { "text": "Third message", "category": "answer" }
      }
    ]
  }'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "inserted": 3,
    "failed": 0,
    "records": [
      { "id": "rec_001", "status": "created" },
      { "id": "rec_002", "status": "created" },
      { "id": "rec_003", "status": "created" }
    ]
  }
}
```

### Query Records

```bash
# List all records
curl "https://api.yourdomain.com/api/v1/datasets/ds_abc123/records?limit=50" \
  -H "Authorization: Bearer $TOKEN"

# Filter by metadata
curl "https://api.yourdomain.com/api/v1/datasets/ds_abc123/records?filter=category:greeting" \
  -H "Authorization: Bearer $TOKEN"

# Search in content
curl "https://api.yourdomain.com/api/v1/datasets/ds_abc123/records?search=hello" \
  -H "Authorization: Bearer $TOKEN"
```

### Get Record by ID

```bash
curl https://api.yourdomain.com/api/v1/datasets/ds_abc123/records/rec_def456 \
  -H "Authorization: Bearer $TOKEN"
```

### Update Record

```bash
curl -X PUT https://api.yourdomain.com/api/v1/datasets/ds_abc123/records/rec_def456 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "text": "Updated message content",
      "category": "greeting",
      "sentiment": "positive"
    }
  }'
```

### Delete Record

```bash
curl -X DELETE https://api.yourdomain.com/api/v1/datasets/ds_abc123/records/rec_def456 \
  -H "Authorization: Bearer $TOKEN"
```

---

## PII Detection & Anonymization

### Detect PII in Text

```bash
curl -X POST https://api.yourdomain.com/api/v1/pii/detect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact John Smith at john.smith@email.com or call 555-123-4567. His SSN is 123-45-6789."
  }'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "detections": [
      {
        "type": "person_name",
        "value": "John Smith",
        "start": 8,
        "end": 18,
        "confidence": 0.85
      },
      {
        "type": "email",
        "value": "john.smith@email.com",
        "start": 22,
        "end": 42,
        "confidence": 0.99
      },
      {
        "type": "phone",
        "value": "555-123-4567",
        "start": 51,
        "end": 63,
        "confidence": 0.95
      },
      {
        "type": "ssn",
        "value": "123-45-6789",
        "start": 77,
        "end": 88,
        "confidence": 0.98
      }
    ],
    "pii_found": true,
    "risk_level": "high"
  }
}
```

### Anonymize Text

```bash
curl -X POST https://api.yourdomain.com/api/v1/pii/anonymize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact John Smith at john.smith@email.com or call 555-123-4567.",
    "strategy": "redact",
    "pii_types": ["email", "phone"]
  }'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "original": "Contact John Smith at john.smith@email.com or call 555-123-4567.",
    "anonymized": "Contact John Smith at [EMAIL REDACTED] or call [PHONE REDACTED].",
    "detections_processed": 2,
    "strategy_applied": "redact"
  }
}
```

### Anonymization Strategies

| Strategy | Description | Example |
|----------|-------------|---------|
| `redact` | Replace with type label | `[EMAIL REDACTED]` |
| `mask` | Partial masking | `j***@e***.com` |
| `tokenize` | Replace with token | `<TOKEN_abc123>` |
| `generalize` | Generalize value | `example.com` → `[DOMAIN]` |

### Batch PII Processing

```bash
curl -X POST https://api.yourdomain.com/api/v1/pii/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "texts": [
      "Email: user1@example.com",
      "Phone: 555-111-2222",
      "No PII here"
    ],
    "strategy": "redact"
  }'
```

---

## Webhooks

### Create a Webhook

```bash
curl -X POST https://api.yourdomain.com/api/v1/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Data Pipeline Notifier",
    "url": "https://your-service.com/webhooks/vault",
    "events": ["record.created", "record.updated", "pii.detected"],
    "secret": "whsec_your-webhook-secret"
  }'
```

**Response**:
```json
{
  "success": true,
  "data": {
    "id": "wh_abc123",
    "name": "Data Pipeline Notifier",
    "url": "https://your-service.com/webhooks/vault",
    "events": ["record.created", "record.updated", "pii.detected"],
    "active": true,
    "created_at": "2024-01-15T10:40:00Z"
  }
}
```

### Webhook Events

| Event | Description |
|-------|-------------|
| `dataset.created` | New dataset created |
| `dataset.updated` | Dataset metadata updated |
| `dataset.deleted` | Dataset deleted |
| `record.created` | New record added |
| `record.updated` | Record updated |
| `record.deleted` | Record deleted |
| `pii.detected` | PII found in record |

### Webhook Payload

```json
{
  "id": "evt_xyz789",
  "type": "record.created",
  "created_at": "2024-01-15T10:45:00Z",
  "data": {
    "record_id": "rec_def456",
    "dataset_id": "ds_abc123",
    "pii_detected": false
  }
}
```

### Verifying Webhook Signatures

```python
import hmac
import hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

# Usage
is_valid = verify_webhook(
    request.body,
    request.headers['X-Vault-Signature'],
    'whsec_your-webhook-secret'
)
```

### List Webhooks

```bash
curl https://api.yourdomain.com/api/v1/webhooks \
  -H "Authorization: Bearer $TOKEN"
```

### Update Webhook

```bash
curl -X PATCH https://api.yourdomain.com/api/v1/webhooks/wh_abc123 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "active": false
  }'
```

### Delete Webhook

```bash
curl -X DELETE https://api.yourdomain.com/api/v1/webhooks/wh_abc123 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Error Handling

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTHENTICATION_REQUIRED` | 401 | Missing or invalid token |
| `INVALID_TOKEN` | 401 | Token expired or malformed |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource doesn't exist |
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

### Handling Errors

```python
import requests

def make_request(url, token):
    response = requests.get(url, headers={"Authorization": f"Bearer {token}"})

    if response.status_code == 401:
        # Token expired - refresh and retry
        new_token = refresh_token()
        return make_request(url, new_token)

    elif response.status_code == 429:
        # Rate limited - wait and retry
        retry_after = int(response.headers.get('Retry-After', 60))
        time.sleep(retry_after)
        return make_request(url, token)

    elif response.status_code >= 500:
        # Server error - retry with backoff
        raise ServerError(response.json())

    elif response.status_code >= 400:
        # Client error - don't retry
        error = response.json()['error']
        raise ClientError(error['code'], error['message'])

    return response.json()['data']
```

---

## Rate Limiting

### Rate Limit Headers

Every response includes rate limit information:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705318200
```

### Default Limits

| Endpoint | Limit |
|----------|-------|
| Authentication | 10 req/min |
| Read operations | 100 req/min |
| Write operations | 50 req/min |
| Bulk operations | 10 req/min |
| PII detection | 30 req/min |

### Handling Rate Limits

```python
def handle_rate_limit(response):
    if response.status_code == 429:
        retry_after = int(response.headers.get('Retry-After', 60))
        reset_time = int(response.headers.get('X-RateLimit-Reset', 0))

        # Option 1: Wait for retry-after
        time.sleep(retry_after)

        # Option 2: Wait until reset time
        wait_time = reset_time - time.time()
        if wait_time > 0:
            time.sleep(wait_time)
```

---

## Best Practices

### 1. Use Bulk Operations

Instead of individual requests:
```bash
# Bad: 100 individual requests
for record in records:
    POST /datasets/{id}/records
```

Use bulk endpoints:
```bash
# Good: 1 bulk request
POST /datasets/{id}/records/bulk
{
  "records": [... 100 records ...]
}
```

### 2. Implement Retry Logic

```python
import time
from functools import wraps

def retry_with_backoff(max_retries=3, base_delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (ConnectionError, TimeoutError) as e:
                    if attempt == max_retries - 1:
                        raise
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
        return wrapper
    return decorator

@retry_with_backoff(max_retries=3)
def create_record(dataset_id, data):
    return client.post(f"/datasets/{dataset_id}/records", json=data)
```

### 3. Cache Authentication Tokens

```python
class TokenManager:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0

    def get_token(self):
        if time.time() >= self.expires_at - 60:  # Refresh 1 min early
            self._refresh()
        return self.access_token

    def _refresh(self):
        response = requests.post(
            f"{BASE_URL}/auth/refresh",
            json={"refresh_token": self.refresh_token}
        )
        data = response.json()['data']
        self.access_token = data['access_token']
        self.expires_at = time.time() + data['expires_in']
```

### 4. Use Idempotency Keys

For critical operations, include idempotency keys:

```bash
curl -X POST https://api.yourdomain.com/api/v1/datasets/ds_abc123/records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: unique-request-id-12345" \
  -H "Content-Type: application/json" \
  -d '{ "data": { "text": "..." } }'
```

### 5. Validate Before Submission

```python
from jsonschema import validate

# Get dataset schema
dataset = client.get(f"/datasets/{dataset_id}")
schema = dataset['schema']

# Validate locally before submitting
for record in records:
    validate(instance=record['data'], schema=schema)

# Then submit
client.post(f"/datasets/{dataset_id}/records/bulk", json={"records": records})
```

---

## SDK Examples

### Python

```python
from vault_client import VaultClient

# Initialize client
client = VaultClient(
    base_url="https://api.yourdomain.com",
    api_key="vault_sk_abc123..."
)

# Create dataset
dataset = client.datasets.create(
    name="Training Data",
    description="ML training dataset",
    tags=["ml", "training"]
)

# Add records
records = [
    {"text": "Example 1", "label": "positive"},
    {"text": "Example 2", "label": "negative"},
]
client.records.bulk_create(dataset.id, records)

# Query with PII detection
results = client.records.list(
    dataset_id=dataset.id,
    pii_detected=False,
    limit=100
)

# Anonymize text
anonymized = client.pii.anonymize(
    text="Contact user@email.com",
    strategy="redact"
)
```

### JavaScript/TypeScript

```typescript
import { VaultClient } from '@vault/sdk';

const client = new VaultClient({
  baseUrl: 'https://api.yourdomain.com',
  apiKey: 'vault_sk_abc123...',
});

// Create dataset
const dataset = await client.datasets.create({
  name: 'Training Data',
  description: 'ML training dataset',
  tags: ['ml', 'training'],
});

// Add records
await client.records.bulkCreate(dataset.id, [
  { text: 'Example 1', label: 'positive' },
  { text: 'Example 2', label: 'negative' },
]);

// Stream records
for await (const record of client.records.stream(dataset.id)) {
  console.log(record);
}

// PII detection
const result = await client.pii.detect('Contact user@email.com');
console.log(result.detections);
```

### Go

```go
package main

import (
    "context"
    vault "github.com/your-org/vault-sdk-go"
)

func main() {
    client := vault.NewClient(
        vault.WithBaseURL("https://api.yourdomain.com"),
        vault.WithAPIKey("vault_sk_abc123..."),
    )

    ctx := context.Background()

    // Create dataset
    dataset, err := client.Datasets.Create(ctx, &vault.CreateDatasetRequest{
        Name:        "Training Data",
        Description: "ML training dataset",
        Tags:        []string{"ml", "training"},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Add records
    _, err = client.Records.BulkCreate(ctx, dataset.ID, []vault.RecordData{
        {Text: "Example 1", Label: "positive"},
        {Text: "Example 2", Label: "negative"},
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

---

## Health Checks

### Check API Status

```bash
# Basic health
curl https://api.yourdomain.com/health

# Readiness (for load balancers)
curl https://api.yourdomain.com/health/ready

# Detailed status
curl https://api.yourdomain.com/health/detailed \
  -H "Authorization: Bearer $TOKEN"
```

---

## See Also

- [API Reference (OpenAPI)](../api/openapi.yaml)
- [Authentication Guide](../security/HARDENING.md#authentication--authorization)
- [Rate Limiting Details](../deployment/CONFIGURATION.md#rate-limiting)
- [Webhook Security](../security/HARDENING.md#webhook-security)
