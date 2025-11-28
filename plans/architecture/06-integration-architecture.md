# Integration Architecture

## Document Control
- **Version**: 1.0
- **Last Updated**: 2025-11-27
- **Status**: Draft
- **Owner**: Architecture Team

## 1. Integration Overview

### 1.1 Integration Strategy

LLM-Data-Vault follows an **API-first, event-driven** integration architecture:

- **API-First Design**: All functionality exposed through well-defined APIs before implementation
- **Event-Driven Communication**: Asynchronous events for state changes and cross-service coordination
- **Multiple Protocol Support**: REST, gRPC, and event streams for different use cases
- **SDK-Enabled**: Official SDKs reduce integration complexity
- **Standards-Based**: CloudEvents, OpenAPI, Protocol Buffers

### 1.2 Integration Patterns

```
┌─────────────────────────────────────────────────────────────────┐
│                     Integration Layers                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   REST API   │  │   gRPC API   │  │  Event Bus   │         │
│  │  (Sync I/O)  │  │ (Streaming)  │  │  (Async)     │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                 │                  │                  │
│  ┌──────┴─────────────────┴──────────────────┴───────┐         │
│  │              API Gateway Layer                     │         │
│  │  - Rate Limiting  - Auth  - Validation  - Caching │         │
│  └────────────────────────────────────────────────────┘         │
│         │                                                        │
│  ┌──────┴─────────────────────────────────────────────┐         │
│  │           Core Business Services                   │         │
│  │  - Dataset  - Version  - Record  - Anonymization  │         │
│  └────────────────────────────────────────────────────┘         │
│         │                                                        │
│  ┌──────┴─────────────────────────────────────────────┐         │
│  │          External Integrations                     │         │
│  │  - LLM DevOps  - Storage  - KMS  - Identity       │         │
│  └────────────────────────────────────────────────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 2. REST API Architecture

### 2.1 Design Principles

- **Resource-Oriented**: URLs represent resources, HTTP verbs represent actions
- **Stateless**: Each request contains all information needed
- **HATEOAS**: Hypermedia links guide API navigation
- **Idempotent Operations**: Safe retry of PUT, DELETE, and idempotency keys for POST
- **Consistent Error Handling**: RFC 7807 Problem Details format
- **Pagination**: Cursor-based for scalability
- **Filtering & Sorting**: Query parameters with standardized syntax

### 2.2 Versioning Strategy

```
URL Path Versioning: /api/v1/datasets
- Major version in URL path
- Backward compatibility within major version
- Deprecation warnings in headers: Sunset, Deprecation
- Version lifecycle: Preview -> Stable -> Deprecated -> Removed
```

**Version Support Policy**:
- N (current): Full support
- N-1: Security fixes only
- N-2: Deprecated, removal notice
- Minimum 12 months support per major version

### 2.3 Endpoint Catalog

#### 2.3.1 Dataset Operations

```
POST   /api/v1/datasets                    # Create dataset
GET    /api/v1/datasets                    # List datasets
GET    /api/v1/datasets/{id}              # Get dataset details
PATCH  /api/v1/datasets/{id}              # Update dataset
DELETE /api/v1/datasets/{id}              # Delete dataset
POST   /api/v1/datasets/{id}/archive      # Archive dataset
GET    /api/v1/datasets/{id}/stats        # Dataset statistics
GET    /api/v1/datasets/{id}/lineage      # Data lineage
```

#### 2.3.2 Version Operations

```
POST   /api/v1/datasets/{id}/versions           # Create version
GET    /api/v1/datasets/{id}/versions           # List versions
GET    /api/v1/datasets/{id}/versions/{vid}     # Get version
PATCH  /api/v1/datasets/{id}/versions/{vid}     # Update version
DELETE /api/v1/datasets/{id}/versions/{vid}     # Delete version
POST   /api/v1/datasets/{id}/versions/{vid}/finalize  # Finalize version
GET    /api/v1/datasets/{id}/versions/{vid}/diff/{vid2}  # Compare versions
```

#### 2.3.3 Record Operations

```
POST   /api/v1/datasets/{id}/records         # Bulk insert records
GET    /api/v1/datasets/{id}/records         # Query records
GET    /api/v1/datasets/{id}/records/{rid}   # Get record
PATCH  /api/v1/datasets/{id}/records/{rid}   # Update record
DELETE /api/v1/datasets/{id}/records/{rid}   # Delete record
POST   /api/v1/datasets/{id}/records/export  # Export records
POST   /api/v1/datasets/{id}/records/import  # Import records
```

#### 2.3.4 Anonymization Operations

```
POST   /api/v1/anonymization/analyze         # Analyze PII
POST   /api/v1/anonymization/anonymize       # Anonymize data
POST   /api/v1/anonymization/validate        # Validate anonymization
GET    /api/v1/anonymization/techniques      # List techniques
GET    /api/v1/anonymization/metrics         # Anonymization metrics
```

#### 2.3.5 Admin Operations

```
GET    /api/v1/admin/health                  # Health check
GET    /api/v1/admin/metrics                 # Prometheus metrics
GET    /api/v1/admin/audit-logs              # Audit trail
POST   /api/v1/admin/policies                # Create policy
GET    /api/v1/admin/policies                # List policies
PATCH  /api/v1/admin/policies/{id}           # Update policy
DELETE /api/v1/admin/policies/{id}           # Delete policy
```

### 2.4 Request/Response Formats

#### 2.4.1 Standard Request Format

```json
{
  "request_id": "req_abc123",
  "timestamp": "2025-11-27T10:00:00Z",
  "data": {
    // Resource-specific payload
  },
  "options": {
    "idempotency_key": "idem_xyz789",
    "async": false,
    "timeout_ms": 30000
  }
}
```

#### 2.4.2 Standard Response Format

```json
{
  "request_id": "req_abc123",
  "timestamp": "2025-11-27T10:00:00Z",
  "status": "success",
  "data": {
    // Resource data
  },
  "metadata": {
    "version": "v1",
    "resource_version": "1.2.3"
  },
  "links": {
    "self": "/api/v1/datasets/ds_123",
    "versions": "/api/v1/datasets/ds_123/versions"
  }
}
```

#### 2.4.3 Error Response Format (RFC 7807)

```json
{
  "type": "https://api.llm-data-vault.io/errors/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "The 'schema' field is required",
  "instance": "/api/v1/datasets/ds_123",
  "request_id": "req_abc123",
  "timestamp": "2025-11-27T10:00:00Z",
  "errors": [
    {
      "field": "schema",
      "code": "required_field_missing",
      "message": "Schema field is required for dataset creation"
    }
  ]
}
```

#### 2.4.4 Pagination Format

```json
{
  "data": [ /* results */ ],
  "pagination": {
    "cursor": "eyJpZCI6MTIzfQ==",
    "has_more": true,
    "total_count": 1500,
    "page_size": 100
  },
  "links": {
    "self": "/api/v1/datasets?cursor=eyJpZCI6MTIzfQ==",
    "next": "/api/v1/datasets?cursor=eyJpZCI6MjIzfQ==",
    "prev": "/api/v1/datasets?cursor=eyJpZCI6MjN9"
  }
}
```

## 3. gRPC API Architecture

### 3.1 Service Definitions

```protobuf
// dataset_service.proto
syntax = "proto3";

package llm_data_vault.v1;

service DatasetService {
  // Unary operations
  rpc CreateDataset(CreateDatasetRequest) returns (Dataset);
  rpc GetDataset(GetDatasetRequest) returns (Dataset);
  rpc UpdateDataset(UpdateDatasetRequest) returns (Dataset);
  rpc DeleteDataset(DeleteDatasetRequest) returns (Empty);

  // Server streaming
  rpc ListDatasets(ListDatasetsRequest) returns (stream Dataset);
  rpc StreamRecords(StreamRecordsRequest) returns (stream Record);

  // Client streaming
  rpc BulkInsertRecords(stream Record) returns (BulkInsertResponse);

  // Bidirectional streaming
  rpc ProcessRecords(stream Record) returns (stream ProcessedRecord);
}

message Dataset {
  string id = 1;
  string name = 2;
  Schema schema = 3;
  map<string, string> metadata = 4;
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp updated_at = 6;
}

message Record {
  string id = 1;
  string dataset_id = 2;
  bytes data = 3;
  map<string, string> attributes = 4;
}
```

### 3.2 Streaming Patterns

#### 3.2.1 Server Streaming (Large Result Sets)

```
Client                          Server
  │                               │
  ├──── ListDatasetsRequest ─────>│
  │                               │
  │<──── Dataset 1 ───────────────┤
  │<──── Dataset 2 ───────────────┤
  │<──── Dataset 3 ───────────────┤
  │<──── ... ─────────────────────┤
  │<──── Dataset N ───────────────┤
  │<──── EOF ─────────────────────┤
```

**Use Cases**: Large dataset exports, record streaming, log tailing

#### 3.2.2 Client Streaming (Bulk Uploads)

```
Client                          Server
  │                               │
  ├──── Record 1 ───────────────>│
  ├──── Record 2 ───────────────>│
  ├──── Record 3 ───────────────>│
  ├──── ... ────────────────────>│
  ├──── Record N ───────────────>│
  ├──── EOF ────────────────────>│
  │                               │
  │<──── BulkInsertResponse ──────┤
```

**Use Cases**: Bulk record insertion, batch imports

#### 3.2.3 Bidirectional Streaming (Real-time Processing)

```
Client                          Server
  │                               │
  ├──── Record 1 ───────────────>│
  │<──── ProcessedRecord 1 ───────┤
  ├──── Record 2 ───────────────>│
  │<──── ProcessedRecord 2 ───────┤
  ├──── Record 3 ───────────────>│
  │<──── ProcessedRecord 3 ───────┤
```

**Use Cases**: Real-time anonymization, streaming validation

### 3.3 Performance Considerations

- **Connection Pooling**: Reuse HTTP/2 connections
- **Compression**: Enable gzip for large messages
- **Deadline Propagation**: Set and propagate request deadlines
- **Backpressure**: Flow control for streaming
- **Metadata**: Pass tracing and auth context

## 4. Event Architecture

### 4.1 Event Catalog

#### 4.1.1 Dataset Events

```
dataset.created              # New dataset created
dataset.updated              # Dataset metadata updated
dataset.deleted              # Dataset deleted
dataset.archived             # Dataset archived
dataset.schema_changed       # Schema modified
dataset.access_granted       # Access permission granted
dataset.access_revoked       # Access permission revoked
```

#### 4.1.2 Version Events

```
version.created              # New version created
version.finalized            # Version marked as final
version.deprecated           # Version deprecated
version.deleted              # Version deleted
version.records_added        # Records added to version
version.records_updated      # Records updated in version
```

#### 4.1.3 Record Events

```
record.created               # Record created
record.updated               # Record updated
record.deleted               # Record deleted
record.anonymized            # Record anonymized
record.validated             # Record validation completed
record.exported              # Record exported
```

#### 4.1.4 Access Events

```
access.read                  # Record/dataset read
access.write                 # Record/dataset write
access.denied                # Access denied
access.policy_evaluated      # Policy evaluation performed
```

### 4.2 CloudEvents Format

```json
{
  "specversion": "1.0",
  "type": "io.llm-data-vault.dataset.created",
  "source": "/datasets/ds_123",
  "id": "evt_abc123",
  "time": "2025-11-27T10:00:00Z",
  "datacontenttype": "application/json",
  "dataschema": "https://api.llm-data-vault.io/schemas/dataset-created/v1",
  "subject": "ds_123",
  "data": {
    "dataset_id": "ds_123",
    "name": "training-conversations",
    "created_by": "user_xyz",
    "schema_version": "1.0.0",
    "metadata": {
      "purpose": "llm_training",
      "classification": "internal"
    }
  },
  "extensions": {
    "traceparent": "00-abc123-def456-01",
    "tenant_id": "tenant_org1",
    "correlation_id": "corr_xyz789"
  }
}
```

### 4.3 Kafka Delivery Patterns

#### 4.3.1 Topic Organization

```
Topic Naming: <domain>.<entity>.<event>
Examples:
  - llm-data-vault.dataset.created
  - llm-data-vault.record.anonymized
  - llm-data-vault.access.denied

Partitioning Strategy:
  - Key: dataset_id for ordering guarantees
  - Partitions: Based on throughput (start with 10-20)

Retention:
  - Default: 7 days
  - Audit events: 365 days
  - Compacted topics for state: infinite
```

#### 4.3.2 Producer Patterns

```yaml
Producer Configuration:
  acks: all                    # Wait for all replicas
  retries: 10                  # Retry failed sends
  max.in.flight: 5             # Pipeline requests
  compression.type: lz4        # Compress messages
  idempotence: true            # Exactly-once semantics

Batching:
  linger.ms: 10                # Wait 10ms for batching
  batch.size: 16384            # 16KB batches
```

#### 4.3.3 Consumer Patterns

```yaml
Consumer Configuration:
  enable.auto.commit: false    # Manual offset commits
  isolation.level: read_committed  # Transactional reads
  max.poll.records: 500        # Limit batch size

Consumer Groups:
  - llm-analytics-hub          # Metrics aggregation
  - llm-governance-dashboard   # Audit visualization
  - webhook-dispatcher         # Webhook delivery
  - search-indexer             # Search index updates
```

#### 4.3.4 Error Handling

```
Event Processing Flow:
┌──────────────┐
│ Kafka Topic  │
└──────┬───────┘
       │
       v
┌──────────────┐     Success     ┌──────────────┐
│  Consumer    │ ───────────────>│ Process OK   │
└──────┬───────┘                 └──────────────┘
       │
       │ Transient Error
       v
┌──────────────┐
│ Retry Topic  │ (exponential backoff)
└──────┬───────┘
       │
       │ Permanent Error
       v
┌──────────────┐
│  DLQ Topic   │ (manual intervention)
└──────────────┘
```

## 5. LLM DevOps Module Integration

### 5.1 Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM-Data-Vault                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Dataset    │  │   Version    │  │   Record     │     │
│  │   Service    │  │   Service    │  │   Service    │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                  │              │
└─────────┼─────────────────┼──────────────────┼──────────────┘
          │                 │                  │
          │ Events          │ Events           │ Events
          │ API Calls       │ API Calls        │ API Calls
          │                 │                  │
┌─────────┴─────────────────┴──────────────────┴──────────────┐
│              LLM DevOps Integration Layer                    │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │LLM-Registry │  │LLM-Policy   │  │LLM-Analytics│         │
│  │             │  │Engine       │  │Hub          │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  ┌─────────────────────────────────────────────────┐        │
│  │       LLM-Governance-Dashboard                  │        │
│  └─────────────────────────────────────────────────┘        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 LLM-Registry Integration

**Purpose**: Dataset registration and discovery

**Integration Points**:

```yaml
1. Dataset Registration:
   Event: dataset.created
   Action: Register dataset in LLM-Registry
   API: POST /registry/v1/datasets
   Payload:
     - dataset_id
     - name
     - schema
     - metadata
     - access_url

2. Version Catalog:
   Event: version.finalized
   Action: Publish version to registry
   API: POST /registry/v1/datasets/{id}/versions
   Payload:
     - version_id
     - schema_version
     - record_count
     - checksum

3. Dataset Discovery:
   Trigger: User search
   API: GET /registry/v1/datasets?query={search}
   Response: Dataset catalog with access URLs
```

**Data Flow**:

```
Dataset Created → Event Published → Registry Service
                                   ↓
                         Register in Catalog
                                   ↓
                         Return Registry Entry
                                   ↓
                         Update Dataset Metadata
```

### 5.3 LLM-Policy-Engine Integration

**Purpose**: Policy-based access control and data governance

**Integration Points**:

```yaml
1. Policy Evaluation:
   Trigger: Dataset/record access request
   API: POST /policy/v1/evaluate
   Request:
     subject: user_id
     resource: dataset_id
     action: read/write/delete
     context: { role, department, classification }
   Response:
     decision: allow/deny
     obligations: [ log_access, anonymize_fields ]

2. Policy Sync:
   Event: policy.updated (from Policy Engine)
   Action: Update local policy cache
   TTL: 5 minutes

3. Anonymization Policies:
   Trigger: record.created
   API: POST /policy/v1/anonymization-requirements
   Request:
     dataset_id: ds_123
     record_schema: { ... }
   Response:
     required_techniques: [ k_anonymity, l_diversity ]
     pii_fields: [ email, ssn ]
```

**Policy Decision Flow**:

```
Access Request
     │
     v
┌─────────────┐
│Check Local  │  Cache Hit
│Policy Cache ├─────────────> Allow/Deny
└──────┬──────┘
       │ Cache Miss
       v
┌─────────────┐
│Call Policy  │
│Engine API   │
└──────┬──────┘
       │
       v
┌─────────────┐
│Update Cache │
└──────┬──────┘
       │
       v
   Allow/Deny
```

### 5.4 LLM-Analytics-Hub Integration

**Purpose**: Metrics, monitoring, and usage analytics

**Integration Points**:

```yaml
1. Usage Metrics:
   Method: Event streaming
   Events:
     - access.read (with count, size, latency)
     - access.write (with count, size)
     - record.anonymized (with technique, duration)
   Destination: Kafka topic → Analytics Hub

2. Performance Metrics:
   Method: Prometheus metrics endpoint
   Endpoint: GET /admin/metrics
   Metrics:
     - dataset_operation_duration_seconds
     - record_anonymization_duration_seconds
     - api_request_count
     - storage_bytes_used

3. Custom Analytics:
   Method: REST API
   API: POST /analytics/v1/events
   Use Case: Dataset quality scores, lineage tracking
```

**Metrics Pipeline**:

```
LLM-Data-Vault Metrics
         │
         ├─> Prometheus (pull)
         │   └─> Grafana Dashboards
         │
         └─> Kafka Events (push)
             └─> Analytics Hub
                 ├─> Time-series DB
                 ├─> Data Warehouse
                 └─> ML Analysis
```

### 5.5 LLM-Governance-Dashboard Integration

**Purpose**: Audit, compliance, and governance visualization

**Integration Points**:

```yaml
1. Audit Events:
   Method: Event streaming
   Events: All access.* events
   Format: CloudEvents with audit context
   Destination: governance.audit topic

2. Compliance Reports:
   API: GET /governance/v1/compliance-report
   Query Parameters:
     - dataset_id
     - start_date
     - end_date
     - report_type (GDPR, HIPAA, SOC2)
   Response: Compliance status, violations, remediation

3. Data Lineage:
   API: GET /datasets/{id}/lineage
   Response: Full lineage graph
   Integration: Dashboard renders lineage visualization
```

**Audit Data Flow**:

```
┌──────────────────┐
│ LLM-Data-Vault   │
│ (All Operations) │
└────────┬─────────┘
         │
         │ Audit Events
         v
┌──────────────────┐
│  Kafka Topics    │
│ - access.read    │
│ - access.write   │
│ - access.denied  │
└────────┬─────────┘
         │
         v
┌──────────────────┐
│ Governance       │
│ Dashboard        │
│ - Audit Log      │
│ - Compliance     │
│ - Lineage        │
└──────────────────┘
```

## 6. External System Integration

### 6.1 Identity Provider Integration (OAuth 2.0 / OIDC)

```yaml
Supported Providers:
  - Okta
  - Auth0
  - Azure AD
  - Google Workspace
  - Generic OIDC

Configuration:
  issuer: https://idp.example.com
  client_id: llm-data-vault
  client_secret: <secret>
  scopes: [ openid, profile, email, groups ]

Token Validation:
  - Signature verification (JWKS)
  - Issuer validation
  - Audience validation
  - Expiration check
  - Scope validation

Claims Mapping:
  sub → user_id
  email → user_email
  groups → user_roles
  custom:department → department
```

**Authentication Flow**:

```
Client → OAuth Provider → LLM-Data-Vault
  │            │               │
  │ Auth Req   │               │
  ├───────────>│               │
  │            │               │
  │ Login      │               │
  │<───────────┤               │
  │            │               │
  │ Token      │               │
  │<───────────┤               │
  │            │               │
  │ API Call + Token           │
  ├───────────────────────────>│
  │            │               │
  │            │  Validate     │
  │            │<──────────────┤
  │            │               │
  │            │  User Info    │
  │            │──────────────>│
  │            │               │
  │         API Response       │
  │<───────────────────────────┤
```

### 6.2 Key Management Service (KMS) Integration

```yaml
Supported KMS:
  - AWS KMS
  - Google Cloud KMS
  - Azure Key Vault
  - HashiCorp Vault

Use Cases:
  - Dataset encryption keys (DEK)
  - Field-level encryption keys
  - API credentials encryption
  - Certificate management

Key Hierarchy:
  Master Key (KMS) → Data Encryption Key (DEK) → Field Encryption

Operations:
  - Encrypt: POST /kms/v1/encrypt
  - Decrypt: POST /kms/v1/decrypt
  - GenerateDataKey: POST /kms/v1/generate-data-key
  - RotateKey: POST /kms/v1/rotate-key
```

**Envelope Encryption**:

```
┌─────────────────────────────────────────┐
│         Master Key (in KMS)             │
│         (never leaves KMS)              │
└────────────────┬────────────────────────┘
                 │
                 │ Encrypts/Decrypts
                 v
┌─────────────────────────────────────────┐
│    Data Encryption Key (DEK)            │
│    (encrypted form stored with data)    │
└────────────────┬────────────────────────┘
                 │
                 │ Encrypts/Decrypts
                 v
┌─────────────────────────────────────────┐
│         Actual Dataset Records          │
└─────────────────────────────────────────┘
```

### 6.3 Storage Backend Integration

#### 6.3.1 Object Storage (S3-Compatible)

```yaml
Supported Backends:
  - AWS S3
  - Google Cloud Storage
  - Azure Blob Storage
  - MinIO
  - Ceph

Configuration:
  endpoint: https://s3.amazonaws.com
  bucket: llm-data-vault-prod
  region: us-east-1
  credentials:
    access_key_id: <key>
    secret_access_key: <secret>

Operations:
  - PutObject: Upload records/versions
  - GetObject: Retrieve records/versions
  - DeleteObject: Remove records/versions
  - ListObjects: Enumerate datasets

Optimization:
  - Multipart upload for large datasets
  - Presigned URLs for direct client access
  - S3 Select for filtered queries
  - Lifecycle policies for archival
```

#### 6.3.2 Database Integration

```yaml
Supported Databases:
  - PostgreSQL (metadata, relational)
  - MongoDB (document records)
  - Cassandra (time-series, audit logs)
  - Redis (cache, session)

Connection Pooling:
  max_connections: 100
  idle_timeout: 300s
  connection_lifetime: 3600s

Migrations:
  Tool: Liquibase / Flyway
  Versioning: Sequential
  Rollback: Supported
```

### 6.4 Observability Integration

```yaml
Distributed Tracing (OpenTelemetry):
  Exporter: Jaeger / Zipkin / Tempo
  Sampling: 1% (production), 100% (dev)
  Propagation: W3C Trace Context

Metrics (Prometheus):
  Endpoint: /metrics
  Format: OpenMetrics
  Scrape Interval: 15s

Logging (Structured):
  Format: JSON
  Level: INFO (production), DEBUG (dev)
  Destination: stdout → Fluentd → Elasticsearch
  Fields: timestamp, level, message, trace_id, user_id
```

## 7. Webhook Architecture

### 7.1 Webhook Registration

```yaml
Registration API:
  POST /api/v1/webhooks

Request:
  url: https://customer.example.com/webhooks/llm-vault
  events: [ dataset.created, record.anonymized ]
  secret: <webhook_secret>
  active: true
  metadata:
    description: "Production data pipeline"
    owner: "data-team@example.com"

Response:
  id: wh_abc123
  url: https://customer.example.com/webhooks/llm-vault
  events: [ dataset.created, record.anonymized ]
  secret_hash: <bcrypt_hash>
  created_at: 2025-11-27T10:00:00Z
  active: true
```

### 7.2 Webhook Delivery

#### 7.2.1 Delivery Flow

```
┌────────────────┐
│ Event Occurs   │
└───────┬────────┘
        │
        v
┌────────────────┐
│ Event Published│
│ to Kafka       │
└───────┬────────┘
        │
        v
┌────────────────┐
│ Webhook        │
│ Dispatcher     │
│ (Consumer)     │
└───────┬────────┘
        │
        │ Match event to subscriptions
        v
┌────────────────┐
│ Queue Delivery │
│ (per webhook)  │
└───────┬────────┘
        │
        │ Retry with backoff
        v
┌────────────────┐
│ HTTP POST to   │
│ Customer URL   │
└───────┬────────┘
        │
        v
┌────────────────┐
│ Log Result     │
│ (success/fail) │
└────────────────┘
```

#### 7.2.2 Webhook Payload

```json
POST https://customer.example.com/webhooks/llm-vault
Headers:
  Content-Type: application/json
  X-LLM-Vault-Signature: sha256=abc123...
  X-LLM-Vault-Event: dataset.created
  X-LLM-Vault-Delivery: delivery_xyz789
  X-LLM-Vault-Timestamp: 2025-11-27T10:00:00Z

Body:
{
  "event": {
    "type": "dataset.created",
    "id": "evt_abc123",
    "timestamp": "2025-11-27T10:00:00Z"
  },
  "data": {
    "dataset_id": "ds_123",
    "name": "training-conversations",
    "created_by": "user_xyz"
  },
  "webhook": {
    "id": "wh_abc123",
    "delivery_id": "delivery_xyz789"
  }
}
```

### 7.3 Webhook Security

```yaml
Signature Verification:
  Algorithm: HMAC-SHA256
  Secret: Shared webhook secret
  Header: X-LLM-Vault-Signature
  Format: sha256=<hex_digest>

Verification Steps:
  1. Extract timestamp from X-LLM-Vault-Timestamp
  2. Reject if timestamp > 5 minutes old
  3. Compute HMAC-SHA256(secret, timestamp + body)
  4. Compare with X-LLM-Vault-Signature
  5. Accept if match

IP Allowlist (Optional):
  Allow delivery only from known IP ranges

HTTPS Required:
  All webhook URLs must use HTTPS
```

### 7.4 Retry Policy

```yaml
Retry Configuration:
  Max Attempts: 5
  Backoff: Exponential
  Initial Delay: 1s
  Max Delay: 3600s
  Multiplier: 2

Retry Schedule:
  Attempt 1: Immediate
  Attempt 2: 1s later
  Attempt 3: 2s later (1 * 2^1)
  Attempt 4: 4s later (1 * 2^2)
  Attempt 5: 8s later (1 * 2^3)

Failure Handling:
  - After max attempts: Mark as failed
  - Store failed deliveries for manual retry
  - Alert webhook owner
  - Automatic disable after 100 consecutive failures
```

## 8. SDK Architecture

### 8.1 SDK Design Principles

- **Consistent Interface**: Same methods across all languages
- **Idiomatic Code**: Follow language conventions and best practices
- **Type Safety**: Leverage type systems (TypeScript, Rust)
- **Error Handling**: Clear, actionable error messages
- **Async Support**: Non-blocking operations where appropriate
- **Retry Logic**: Built-in exponential backoff
- **Pagination**: Automatic handling of large result sets
- **Documentation**: Inline docs, examples, tutorials

### 8.2 Python SDK

```python
# Installation
# pip install llm-data-vault

from llm_data_vault import Client, Dataset, AnonymizationTechnique

# Initialize client
client = Client(
    api_key="ldv_key_abc123",
    base_url="https://api.llm-data-vault.io",
    timeout=30.0
)

# Create dataset
dataset = client.datasets.create(
    name="training-conversations",
    schema={
        "fields": [
            {"name": "prompt", "type": "string"},
            {"name": "response", "type": "string"}
        ]
    },
    metadata={"purpose": "llm_training"}
)

# Insert records
records = [
    {"prompt": "Hello", "response": "Hi there!"},
    {"prompt": "How are you?", "response": "I'm doing well!"}
]
dataset.records.insert_many(records)

# Query with filtering
results = dataset.records.query(
    filter={"prompt": {"$contains": "Hello"}},
    limit=100
)

# Anonymize records
anonymized = client.anonymization.anonymize(
    data=records,
    techniques=[
        AnonymizationTechnique.K_ANONYMITY,
        AnonymizationTechnique.MASKING
    ]
)

# Async support
import asyncio

async def main():
    async with Client(api_key="...") as client:
        dataset = await client.datasets.create_async(...)
        await dataset.records.insert_many_async(records)

asyncio.run(main())
```

### 8.3 Rust SDK

```rust
// Installation
// cargo add llm-data-vault

use llm_data_vault::{Client, Dataset, Record, Error};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize client
    let client = Client::new("ldv_key_abc123")
        .base_url("https://api.llm-data-vault.io")
        .timeout(Duration::from_secs(30))
        .build()?;

    // Create dataset
    let dataset = client
        .datasets()
        .create("training-conversations")
        .schema(json!({
            "fields": [
                {"name": "prompt", "type": "string"},
                {"name": "response", "type": "string"}
            ]
        }))
        .metadata(json!({"purpose": "llm_training"}))
        .send()
        .await?;

    // Insert records
    let records = vec![
        json!({"prompt": "Hello", "response": "Hi there!"}),
        json!({"prompt": "How are you?", "response": "I'm doing well!"})
    ];

    dataset.records().insert_many(&records).await?;

    // Query with filtering
    let results = dataset
        .records()
        .query()
        .filter(json!({"prompt": {"$contains": "Hello"}}))
        .limit(100)
        .send()
        .await?;

    // Stream large result sets
    let mut stream = dataset.records().stream().await?;
    while let Some(record) = stream.next().await {
        println!("{:?}", record?);
    }

    Ok(())
}
```

### 8.4 Go SDK

```go
// Installation
// go get github.com/llm-devops/llm-data-vault-go

package main

import (
    "context"
    "log"
    "time"

    ldv "github.com/llm-devops/llm-data-vault-go"
)

func main() {
    // Initialize client
    client := ldv.NewClient(
        ldv.WithAPIKey("ldv_key_abc123"),
        ldv.WithBaseURL("https://api.llm-data-vault.io"),
        ldv.WithTimeout(30 * time.Second),
    )

    ctx := context.Background()

    // Create dataset
    dataset, err := client.Datasets.Create(ctx, &ldv.CreateDatasetRequest{
        Name: "training-conversations",
        Schema: map[string]interface{}{
            "fields": []map[string]string{
                {"name": "prompt", "type": "string"},
                {"name": "response", "type": "string"},
            },
        },
        Metadata: map[string]string{
            "purpose": "llm_training",
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // Insert records
    records := []map[string]string{
        {"prompt": "Hello", "response": "Hi there!"},
        {"prompt": "How are you?", "response": "I'm doing well!"},
    }

    _, err = dataset.Records.InsertMany(ctx, records)
    if err != nil {
        log.Fatal(err)
    }

    // Query with pagination
    iter := dataset.Records.Query(ctx, &ldv.QueryRequest{
        Filter: map[string]interface{}{
            "prompt": map[string]string{"$contains": "Hello"},
        },
        PageSize: 100,
    })

    for iter.Next() {
        record := iter.Record()
        log.Printf("Record: %+v\n", record)
    }

    if err := iter.Err(); err != nil {
        log.Fatal(err)
    }
}
```

### 8.5 TypeScript SDK

```typescript
// Installation
// npm install @llm-devops/llm-data-vault

import { Client, Dataset, Record, AnonymizationTechnique } from '@llm-devops/llm-data-vault';

// Initialize client
const client = new Client({
  apiKey: 'ldv_key_abc123',
  baseURL: 'https://api.llm-data-vault.io',
  timeout: 30000,
});

// Create dataset
const dataset: Dataset = await client.datasets.create({
  name: 'training-conversations',
  schema: {
    fields: [
      { name: 'prompt', type: 'string' },
      { name: 'response', type: 'string' },
    ],
  },
  metadata: { purpose: 'llm_training' },
});

// Insert records
const records: Record[] = [
  { prompt: 'Hello', response: 'Hi there!' },
  { prompt: 'How are you?', response: "I'm doing well!" },
];

await dataset.records.insertMany(records);

// Query with filtering
const results = await dataset.records.query({
  filter: { prompt: { $contains: 'Hello' } },
  limit: 100,
});

// Anonymize records
const anonymized = await client.anonymization.anonymize({
  data: records,
  techniques: [
    AnonymizationTechnique.K_ANONYMITY,
    AnonymizationTechnique.MASKING,
  ],
});

// Stream large datasets
const stream = dataset.records.stream();
for await (const record of stream) {
  console.log(record);
}

// Error handling with typed errors
try {
  await dataset.records.insert(record);
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('Validation failed:', error.fields);
  } else if (error instanceof AuthenticationError) {
    console.error('Authentication failed:', error.message);
  } else {
    throw error;
  }
}
```

## 9. API Gateway Patterns

### 9.1 Rate Limiting

#### 9.1.1 Rate Limit Strategy

```yaml
Tier-Based Limits:
  Free Tier:
    requests_per_minute: 60
    requests_per_day: 10000
    burst: 10

  Professional Tier:
    requests_per_minute: 600
    requests_per_day: 100000
    burst: 50

  Enterprise Tier:
    requests_per_minute: 6000
    requests_per_day: unlimited
    burst: 200

Algorithm: Token Bucket
  - Tokens added at constant rate
  - Each request consumes 1 token
  - Burst allows temporary spike
  - Reject when bucket empty
```

#### 9.1.2 Rate Limit Headers

```
Response Headers:
  X-RateLimit-Limit: 600          # Requests per window
  X-RateLimit-Remaining: 542      # Requests remaining
  X-RateLimit-Reset: 1701072000   # Unix timestamp of reset
  X-RateLimit-Window: 60          # Window size in seconds

429 Too Many Requests Response:
  Status: 429
  Retry-After: 45                 # Seconds to wait
  Body:
    {
      "type": "rate_limit_exceeded",
      "title": "Rate Limit Exceeded",
      "status": 429,
      "detail": "Rate limit of 600 requests per minute exceeded",
      "retry_after": 45
    }
```

### 9.2 Request Validation

```yaml
Validation Layers:
  1. Schema Validation:
     - JSON Schema validation
     - Required fields check
     - Type validation
     - Format validation (email, UUID, etc.)

  2. Business Rule Validation:
     - Field value constraints
     - Cross-field dependencies
     - Reference integrity

  3. Security Validation:
     - SQL injection patterns
     - XSS patterns
     - Path traversal
     - Excessive payload size

Validation Flow:
  Request → Schema Validation → Business Rules → Security Check → Process
            ↓ Fail              ↓ Fail           ↓ Fail
         400 Error          400 Error        400 Error
```

### 9.3 Response Caching

#### 9.3.1 Cache Strategy

```yaml
Cache Layers:
  1. CDN Cache (CloudFront/CloudFlare):
     - Static content
     - Public dataset metadata
     - TTL: 1 hour

  2. API Gateway Cache:
     - GET /datasets (list)
     - GET /datasets/{id} (details)
     - TTL: 5 minutes

  3. Application Cache (Redis):
     - Policy decisions
     - User permissions
     - Schema metadata
     - TTL: 1-15 minutes

Cache Keys:
  Format: {resource_type}:{id}:{version}:{user_context}
  Example: dataset:ds_123:v1.2.3:user_xyz
```

#### 9.3.2 Cache Headers

```
Response Headers:
  Cache-Control: public, max-age=300       # 5 minute cache
  ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
  Last-Modified: Wed, 27 Nov 2025 10:00:00 GMT
  Vary: Accept-Encoding, Authorization      # Cache key variations

Conditional Requests:
  Request:
    If-None-Match: "33a64df551425fcc55e4d42a148795d9f25f89d4"
    If-Modified-Since: Wed, 27 Nov 2025 10:00:00 GMT

  Response (Cache Hit):
    Status: 304 Not Modified
    (No body)
```

#### 9.3.3 Cache Invalidation

```yaml
Invalidation Strategies:
  1. Event-Based:
     - Listen to dataset.updated, version.finalized events
     - Purge specific cache entries

  2. Time-Based:
     - TTL expiration
     - Stale-while-revalidate pattern

  3. Manual:
     - Admin API: DELETE /admin/cache/{key}
     - Purge by pattern: dataset:*

Cache Invalidation Flow:
  Dataset Updated → Event Published → Cache Service
                                    ↓
                           Identify Cache Keys
                                    ↓
                           Purge Cache Entries
                                    ↓
                           Next Request: Cache Miss
```

### 9.4 API Gateway Configuration

```yaml
Gateway: Kong / AWS API Gateway / Nginx

Configuration:
  upstream:
    service: llm-data-vault
    load_balancing: round_robin
    health_check:
      interval: 10s
      timeout: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3

  plugins:
    - name: rate-limiting
      config:
        minute: 600
        policy: redis

    - name: request-validation
      config:
        body_schema: openapi-schema.json

    - name: response-cache
      config:
        strategy: memory
        ttl: 300

    - name: cors
      config:
        origins: ["*"]
        methods: [GET, POST, PUT, PATCH, DELETE, OPTIONS]
        headers: [Authorization, Content-Type]

    - name: jwt
      config:
        key_claim_name: kid
        secret_is_base64: true

    - name: request-transformer
      config:
        add:
          headers: ["X-Gateway-Version:1.0"]
```

### 9.5 API Documentation (OpenAPI)

```yaml
openapi: 3.0.0
info:
  title: LLM-Data-Vault API
  version: 1.0.0
  description: Privacy-first dataset management for LLM workflows

servers:
  - url: https://api.llm-data-vault.io/v1
    description: Production
  - url: https://api-staging.llm-data-vault.io/v1
    description: Staging

security:
  - BearerAuth: []
  - ApiKeyAuth: []

paths:
  /datasets:
    get:
      summary: List datasets
      operationId: listDatasets
      tags: [Datasets]
      parameters:
        - name: page
          in: query
          schema:
            type: string
          description: Cursor for pagination
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 20
      responses:
        '200':
          description: List of datasets
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DatasetList'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'

components:
  schemas:
    Dataset:
      type: object
      required: [id, name, schema]
      properties:
        id:
          type: string
          example: ds_abc123
        name:
          type: string
          example: training-conversations
        schema:
          $ref: '#/components/schemas/DatasetSchema'

  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
```

## 10. Integration Security

### 10.1 API Authentication

```yaml
Supported Methods:
  1. API Key:
     - Header: X-API-Key
     - Format: ldv_key_{random}
     - Rotation: Every 90 days

  2. JWT (OAuth 2.0):
     - Header: Authorization: Bearer {token}
     - Validation: JWKS endpoint
     - Expiration: 1 hour

  3. mTLS:
     - Client certificate validation
     - Certificate pinning
     - Use case: Service-to-service
```

### 10.2 Authorization Model

```yaml
RBAC (Role-Based Access Control):
  Roles:
    - admin: Full access
    - data_engineer: Create/update datasets
    - data_scientist: Read datasets, query records
    - auditor: Read-only audit logs

ABAC (Attribute-Based Access Control):
  Attributes:
    - user.department
    - dataset.classification
    - record.pii_level
    - context.time_of_day

  Policy Example:
    Allow read if:
      - user.department == dataset.department
      - dataset.classification <= user.clearance_level
      - record.pii_level == "anonymized"
```

### 10.3 Data Encryption

```yaml
In-Transit:
  - TLS 1.3
  - Perfect Forward Secrecy (PFS)
  - Certificate pinning for SDKs

At-Rest:
  - AES-256-GCM
  - Envelope encryption (KMS)
  - Field-level encryption for PII

Key Management:
  - Master keys in KMS
  - Data keys rotated every 90 days
  - Audit all key operations
```

## 11. Integration Monitoring

### 11.1 Key Metrics

```yaml
API Metrics:
  - Request rate (req/s)
  - Error rate (%)
  - Latency (p50, p95, p99)
  - Success rate (%)

Integration Metrics:
  - External API call duration
  - Event processing lag
  - Webhook delivery success rate
  - SDK usage by version

Resource Metrics:
  - Connection pool utilization
  - Cache hit rate
  - Queue depth
  - Circuit breaker state
```

### 11.2 SLIs / SLOs

```yaml
Service Level Indicators (SLIs):
  - Availability: % of successful requests
  - Latency: % of requests < 200ms
  - Throughput: Requests per second
  - Error Rate: % of failed requests

Service Level Objectives (SLOs):
  - 99.9% availability (43 min downtime/month)
  - 95% of requests < 200ms
  - 99% of requests < 1000ms
  - Error rate < 0.1%

Error Budget:
  - Monthly budget: 0.1% (43 minutes)
  - Alert when 50% consumed
  - Freeze deployments when exhausted
```

---

**Document Status**: Draft for Review
**Next Review Date**: 2025-12-27
**Related Documents**:
- 01-system-overview.md
- 03-data-architecture.md
- 07-reliability-architecture.md
