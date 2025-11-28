# LLM-Data-Vault: System Overview Architecture

**Document:** Architecture Phase - System Overview
**Version:** 1.0.0
**Status:** Draft
**Phase:** SPARC - Architecture
**Last Updated:** 2025-11-27
**Parent Platform:** LLM DevOps Platform

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Context Diagram](#2-system-context-diagram)
3. [Container Diagram (C4 Model Level 2)](#3-container-diagram-c4-model-level-2)
4. [Key Quality Attributes](#4-key-quality-attributes)
5. [Technology Stack](#5-technology-stack)
6. [Deployment Model](#6-deployment-model)
7. [Cross-Cutting Concerns](#7-cross-cutting-concerns)
8. [Architectural Decision Records](#8-architectural-decision-records)

---

## 1. Executive Summary

### 1.1 System Purpose and Value Proposition

LLM-Data-Vault is an enterprise-grade, cryptographically secure data management platform designed specifically for Large Language Model (LLM) operations. It serves as the foundational data layer within the LLM DevOps ecosystem, providing:

**Core Value Proposition:**
- **Privacy-Preserving Data Management**: Transform sensitive LLM data (prompts, responses, training datasets, evaluation corpora) from compliance liabilities into strategic assets through intelligent anonymization
- **Enterprise Security**: Zero-trust architecture with envelope encryption, granular access controls, and comprehensive audit trails meeting GDPR, HIPAA, CCPA, and SOC 2 requirements
- **Operational Excellence**: Git-like versioning for reproducible experiments, content-addressable storage for deduplication, and sub-100ms API latency at petabyte scale

**Business Impact:**
- Enable safe dataset sharing across organizational boundaries while maintaining regulatory compliance
- Reduce storage costs by 40% through content-addressable deduplication
- Accelerate model development cycles through versioned, reproducible datasets
- Minimize security incident risk through defense-in-depth and automated PII detection (99.5%+ accuracy)

### 1.2 Key Architectural Decisions and Rationale

| Decision | Rationale | Trade-offs |
|----------|-----------|------------|
| **Rust + Tokio for runtime** | Memory safety eliminates entire classes of vulnerabilities; async runtime provides 10,000+ req/s throughput with minimal resource overhead | Longer compilation times; steeper learning curve vs. Go/Python |
| **Envelope encryption pattern** | Two-tier key hierarchy (KEK via KMS + DEK for data) enables key rotation without data re-encryption; supports multiple KMS providers | Additional network hop for key operations; increased complexity |
| **Content-addressable storage** | BLAKE3 hashing provides 40% deduplication efficiency; cryptographic integrity verification prevents silent corruption | Requires additional metadata layer; cannot modify objects in-place |
| **Pluggable backend abstraction** | Trait-based storage/encryption/auth interfaces prevent vendor lock-in; enables hybrid cloud and air-gapped deployments | Performance overhead from abstraction layer; increased testing matrix |
| **Event-driven integration** | Kafka/RabbitMQ pub/sub decouples vault from consumers; enables eventual consistency and horizontal scaling | Operational complexity; eventual consistency requires idempotent consumers |
| **gRPC for high-throughput paths** | HTTP/2 multiplexing + Protobuf encoding provides 10x throughput vs REST for bulk operations | Binary protocol complicates debugging; requires code generation |
| **PostgreSQL for metadata** | ACID guarantees for critical metadata; rich query capabilities for lineage tracking; mature ecosystem | Vertical scaling limits; requires careful schema design for performance |
| **Redis for caching** | Sub-millisecond policy decision caching; reduces KMS load by 90% for DEK retrieval | Cache invalidation complexity; additional infrastructure dependency |

### 1.3 System Boundaries and Scope

**In Scope:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    LLM-Data-Vault Core                          │
├─────────────────────────────────────────────────────────────────┤
│ ✓ Encrypted storage (at-rest AES-256-GCM, in-transit TLS 1.3)  │
│ ✓ PII detection & anonymization (k-anonymity, diff privacy)     │
│ ✓ Git-like versioning & content-addressable storage            │
│ ✓ RBAC/ABAC access control with policy engine integration      │
│ ✓ Complete audit trail with cryptographic integrity            │
│ ✓ Multi-backend support (S3, Azure Blob, GCS, on-prem)         │
│ ✓ Dataset lineage tracking & impact analysis                   │
│ ✓ Compliance automation (retention, RTBF, geo-residency)       │
│ ✓ REST & gRPC APIs with SDK libraries (Python, JS, Go, Rust)   │
└─────────────────────────────────────────────────────────────────┘
```

**Out of Scope:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    External Concerns                            │
├─────────────────────────────────────────────────────────────────┤
│ ✗ Model training execution (handled by training orchestrators)  │
│ ✗ Real-time inference serving (handled by inference modules)    │
│ ✗ Prompt engineering tools (handled by prompt optimization)     │
│ ✗ Data labeling interfaces (handled by annotation tools)        │
│ ✗ Model performance monitoring (handled by observability)       │
│ ✗ Synthetic data generation (handled by data augmentation)      │
└─────────────────────────────────────────────────────────────────┘
```

**Integration Boundaries:**
- **Upstream**: Receives data from LLM-Monitor (prompts/responses), training pipelines (datasets), evaluation frameworks (corpora)
- **Downstream**: Serves data to LLM-Analytics-Hub (anonymized analytics), training systems (versioned datasets), LLM-Registry (metadata sync)
- **Lateral**: Enforces policies via LLM-Policy-Engine; reports audit events to LLM-Governance-Dashboard

---

## 2. System Context Diagram

### 2.1 High-Level Context

```
                        ┌─────────────────────────────────────────────────────────────┐
                        │              LLM DevOps Ecosystem                           │
                        └─────────────────────────────────────────────────────────────┘
                                                    │
        ┌──────────────────────────────────────────┼────────────────────────────────────────┐
        │                                          │                                        │
        ▼                                          ▼                                        ▼
┌───────────────┐                        ┌─────────────────┐                    ┌──────────────────┐
│ LLM-Registry  │◄──────────────────────►│  LLM-Policy     │◄──────────────────►│ LLM-Governance   │
│               │  Metadata Sync         │    Engine       │  Policy Eval       │   Dashboard      │
│ - Model Links │  (REST/Events)         │                 │  (gRPC)            │                  │
│ - Catalog     │                        │ - RBAC/ABAC     │                    │ - Audit Trails   │
│ - Versioning  │                        │ - Compliance    │                    │ - Compliance     │
└───────┬───────┘                        └────────┬────────┘                    └────────▲─────────┘
        │                                         │                                      │
        │                                         │                                      │
        │            ┌────────────────────────────┼──────────────────────────────────────┤
        │            │                            │                                      │
        │            │                            │                                      │
        ▼            ▼                            ▼                                      │
┌────────────────────────────────────────────────────────────────────────────────────────┴──────┐
│                                   LLM-Data-Vault                                              │
│                         (Core Secure Storage & Anonymization)                                 │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐ │
│  │   REST API     │  │   gRPC API     │  │  Event Bus     │  │   SDK Libraries           │ │
│  │   (Axum)       │  │   (Tonic)      │  │  (Kafka)       │  │   (Python/JS/Go/Rust)     │ │
│  └────────────────┘  └────────────────┘  └────────────────┘  └────────────────────────────┘ │
│                                                                                               │
│  ┌────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                         Core Services                                                  │  │
│  │  • Encryption Engine  • Anonymization Engine  • Access Control  • Audit Logger        │  │
│  │  • Versioning System  • Lineage Tracker       • Storage Manager • Policy Enforcer     │  │
│  └────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                               │
└───────┬───────────────────────────────┬───────────────────────────────┬───────────────────────┘
        │                               │                               │
        ▼                               ▼                               ▼
┌────────────────┐            ┌──────────────────┐          ┌──────────────────────┐
│LLM-Analytics   │            │  Training/Eval   │          │   Application        │
│     Hub        │            │    Systems       │          │    Services          │
│                │            │                  │          │                      │
│ - Anonymized   │            │ - Dataset Access │          │ - Prompt Libraries   │
│   Exports      │            │ - Versioned Data │          │ - Conversation Logs  │
│ - Aggregates   │            │ - Lineage Track  │          │ - Custom Datasets    │
└────────────────┘            └──────────────────┘          └──────────────────────┘

        ┌───────────────────────────────────────────────────────────────────┐
        │                   External Dependencies                           │
        ├───────────────────────────────────────────────────────────────────┤
        │                                                                   │
        │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
        │  │    KMS       │  │   Storage    │  │  Identity Providers  │   │
        │  │              │  │   Backends   │  │                      │   │
        │  │ • AWS KMS    │  │ • AWS S3     │  │ • OIDC (Okta/Auth0) │   │
        │  │ • Azure KV   │  │ • Azure Blob │  │ • SAML (Enterprise) │   │
        │  │ • GCP KMS    │  │ • GCS        │  │ • LDAP (AD)         │   │
        │  │ • Vault      │  │ • MinIO      │  │ • mTLS (Services)   │   │
        │  └──────────────┘  └──────────────┘  └──────────────────────┘   │
        │                                                                   │
        └───────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────┐
│                              User Actors                                   │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │    Data      │  │     ML       │  │   Security   │  │  Compliance  │  │
│  │  Scientists  │  │  Engineers   │  │  Engineers   │  │   Officers   │  │
│  │              │  │              │  │              │  │              │  │
│  │ • Upload     │  │ • API Access │  │ • Configure  │  │ • Audit Logs │  │
│  │ • Query      │  │ • Pipelines  │  │   Policies   │  │ • Reports    │  │
│  │ • Anonymize  │  │ • Automation │  │ • Monitor    │  │ • Validation │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Communication Protocols

| Integration Point | Protocol | Direction | Data Flow | SLA |
|-------------------|----------|-----------|-----------|-----|
| **LLM-Registry** | REST + Events (Kafka) | Bidirectional | Metadata sync, dataset registration | p99 < 100ms (REST), at-least-once (Events) |
| **LLM-Policy-Engine** | gRPC (mTLS) | Vault → Policy | Authorization requests, policy evaluation | p99 < 50ms (cached), < 200ms (fresh) |
| **LLM-Analytics-Hub** | Events (Kafka) | Vault → Analytics | Anonymized data exports, usage metrics | Batch (hourly), eventual consistency |
| **LLM-Governance** | Events (Kafka) | Vault → Dashboard | Audit events, compliance reports | Real-time streaming, no backpressure |
| **Training Systems** | gRPC (streaming) | Vault → Training | Versioned datasets, large file transfer | Throughput > 1GB/s per stream |
| **Application APIs** | REST (HTTPS) | Bidirectional | CRUD operations, queries | p99 < 100ms, 10k req/s sustained |
| **KMS Providers** | SDK (HTTPS) | Vault → KMS | Key operations (encrypt/decrypt DEK) | p99 < 100ms (critical path) |
| **Storage Backends** | S3 API / SDK | Vault → Storage | Object storage (encrypted payloads) | p99 < 500ms (upload), < 200ms (download) |
| **Identity Providers** | OIDC/SAML/LDAP | Vault ← IdP | User authentication, token validation | p99 < 300ms (with caching) |

---

## 3. Container Diagram (C4 Model Level 2)

### 3.1 Container Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                              LLM-Data-Vault System Boundary                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

                                    ┌─────────────────────┐
                                    │     API Gateway     │
                                    │     (Axum/Tonic)    │
                                    │                     │
                                    │ • TLS Termination   │
                                    │ • Load Balancing    │
                                    │ • Rate Limiting     │
                                    │ • Request Routing   │
                                    └──────────┬──────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
        ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
        │  REST API Service │      │  gRPC API Service │      │  Event Publisher  │
        │      (Axum)       │      │     (Tonic)       │      │     (Kafka)       │
        │                   │      │                   │      │                   │
        │ • CRUD Endpoints  │      │ • Stream Records  │      │ • Audit Events    │
        │ • HATEOAS Links   │      │ • Bulk Ingest     │      │ • Data Changes    │
        │ • Pagination      │      │ • Bidirectional   │      │ • Lineage Events  │
        └─────────┬─────────┘      └─────────┬─────────┘      └─────────┬─────────┘
                  │                          │                          │
                  └──────────────────────────┼──────────────────────────┘
                                             │
                            ┌────────────────▼────────────────┐
                            │   Access Control Service        │
                            │                                 │
                            │ • Authentication (JWT/mTLS)     │
                            │ • RBAC/ABAC Engine              │
                            │ • Policy Integration (gRPC)     │
                            │ • Session Management            │
                            └────────────┬────────────────────┘
                                         │
                ┌────────────────────────┼────────────────────────┐
                │                        │                        │
                ▼                        ▼                        ▼
    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
    │ Core Vault       │    │ Anonymization    │    │  Versioning      │
    │   Service        │    │    Service       │    │   Service        │
    │                  │    │                  │    │                  │
    │ • Dataset CRUD   │    │ • PII Detection  │    │ • Git-like OPS   │
    │ • Record Mgmt    │    │ • Strategies     │    │ • Commit/Branch  │
    │ • Metadata Ops   │    │ • Token Vault    │    │ • Lineage Track  │
    │ • Lineage Link   │    │ • Policy Apply   │    │ • Diff/Merge     │
    └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
             │                       │                       │
             └───────────────────────┼───────────────────────┘
                                     │
                ┌────────────────────┼────────────────────────┐
                │                    │                        │
                ▼                    ▼                        ▼
    ┌──────────────────┐  ┌──────────────────┐   ┌──────────────────┐
    │  Encryption      │  │  Storage         │   │   Audit          │
    │   Service        │  │  Service         │   │  Service         │
    │                  │  │                  │   │                  │
    │ • Envelope Enc   │  │ • Backend Abstr  │   │ • Immutable Log  │
    │ • KMS Integ      │  │ • S3/Blob/GCS    │   │ • Crypto Chain   │
    │ • Key Rotation   │  │ • Content-Addr   │   │ • Event Emit     │
    │ • DEK Caching    │  │ • Deduplication  │   │ • Compliance     │
    └────────┬─────────┘  └────────┬─────────┘   └────────┬─────────┘
             │                     │                      │
             └─────────────────────┼──────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│  PostgreSQL  │          │    Redis     │          │    Kafka     │
│   Metadata   │          │    Cache     │          │  Event Bus   │
│              │          │              │          │              │
│ • Datasets   │          │ • Policy     │          │ • Audit Log  │
│ • Versions   │          │ • DEK Cache  │          │ • Data Sync  │
│ • Lineage    │          │ • Session    │          │ • Integration│
│ • Audit Idx  │          │ • Rate Limit │          │ • Dead Letter│
└──────────────┘          └──────────────┘          └──────────────┘

        ┌───────────────────────────────────────────────────┐
        │          External Systems (Out of Process)        │
        ├───────────────────────────────────────────────────┤
        │                                                   │
        │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
        │  │   KMS    │  │ Storage  │  │   Identity   │   │
        │  │ (Vault/  │  │ Backend  │  │   Provider   │   │
        │  │AWS/Azure)│  │ (S3/Blob)│  │ (OIDC/SAML)  │   │
        │  └──────────┘  └──────────┘  └──────────────┘   │
        │                                                   │
        └───────────────────────────────────────────────────┘
```

### 3.2 Inter-Container Communication Patterns

#### 3.2.1 Request Flow: User Uploads Dataset

```
User → API Gateway → REST API Service → Access Control Service
                                               ↓
                                    [Policy Engine: gRPC call]
                                               ↓
                                         ALLOW decision
                                               ↓
Core Vault Service → Anonymization Service (if policy requires)
        ↓                       ↓
        ├──→ Encryption Service (encrypt records)
        │           ↓
        │    Storage Service (persist to S3)
        │           ↓
        │    PostgreSQL (metadata)
        │
        ├──→ Versioning Service (create commit)
        │           ↓
        │    PostgreSQL (commit metadata)
        │
        └──→ Audit Service (log event)
                    ↓
             Kafka (publish event)
                    ↓
         [LLM-Registry, LLM-Governance consume]
```

#### 3.2.2 Request Flow: Analytics Export (Anonymized)

```
Analytics Hub → gRPC API Service → Access Control Service
                                          ↓
                                  [Policy: requires anonymization]
                                          ↓
Core Vault Service → Storage Service (retrieve records)
        ↓
Anonymization Service (apply k-anonymity)
        ↓
Encryption Service (re-encrypt with analytics key)
        ↓
Storage Service (write to export staging)
        ↓
Event Publisher → Kafka (export.completed event)
        ↓
Analytics Hub (download anonymized data)
```

#### 3.2.3 Key Rotation Flow

```
Encryption Service (scheduled job)
        ↓
KMS Provider (generate new KEK version)
        ↓
Storage Service (list all encrypted objects)
        ↓
For each object:
    Storage Service (retrieve encrypted DEK + ciphertext)
        ↓
    KMS Provider (decrypt DEK with old KEK)
        ↓
    KMS Provider (encrypt DEK with new KEK)
        ↓
    Storage Service (update encrypted DEK, keep ciphertext)
        ↓
    PostgreSQL (update key_version metadata)
        ↓
    Audit Service (log rotation event)
        ↓
    Kafka (key.rotated event)
```

---

## 4. Key Quality Attributes

### 4.1 Scalability

**Requirements:**
- Support 10TB+ individual datasets through chunking and streaming
- Handle 10,000+ concurrent API requests per second
- Maintain linear scaling to 100+ nodes in Kubernetes cluster
- Manage petabyte-scale total storage across all datasets

**Approach:**
```
Horizontal Scaling Strategy:
┌─────────────────────────────────────────────────────────────┐
│  Component         │ Scaling Strategy                       │
├────────────────────┼────────────────────────────────────────┤
│ API Gateway        │ Stateless: Scale to N pods behind LB   │
│ REST/gRPC Services │ Stateless: Auto-scale on CPU/memory    │
│ Core Vault Service │ Stateless: Partition by dataset_id     │
│ Encryption Service │ Stateless: DEK caching in Redis        │
│ Storage Service    │ Stateless: S3 scales independently     │
│ PostgreSQL         │ Read replicas (5+), sharding by hash   │
│ Redis              │ Cluster mode: 3 masters, 3 replicas    │
│ Kafka              │ 10+ brokers, partition by dataset_id   │
└────────────────────┴────────────────────────────────────────┘

Data Partitioning:
• Metadata: Hash partitioning on dataset_id (PostgreSQL)
• Objects: Prefix-based partitioning in S3 (dataset_id/version_id/)
• Events: Kafka topic partitioning by dataset_id
• Cache: Consistent hashing across Redis cluster
```

**Performance Targets:**
| Metric | Target | Measurement |
|--------|--------|-------------|
| API Latency (p50) | < 50ms | Single-record GET operations |
| API Latency (p99) | < 100ms | Excluding bulk operations |
| Bulk Ingest Throughput | > 1GB/s | gRPC streaming ingest |
| Query Throughput | 10,000 req/s | Sustained load with caching |
| Storage Deduplication | 40% reduction | Content-addressable storage |
| Horizontal Scaling | Linear to 100 nodes | No coordination bottlenecks |

### 4.2 Availability

**Target:** 99.9% uptime (8.76 hours downtime/year)

**Approach:**
```
High Availability Architecture:
┌────────────────────────────────────────────────────────────────┐
│  Layer              │ HA Strategy                              │
├─────────────────────┼──────────────────────────────────────────┤
│ API Gateway         │ Multi-AZ load balancer (3+ zones)       │
│ Service Pods        │ Min 3 replicas per service, anti-affinity│
│ PostgreSQL          │ Primary + 2 sync replicas (Patroni)     │
│ Redis               │ Sentinel mode (1 master, 2 replicas)    │
│ Kafka               │ Replication factor 3, min.insync 2      │
│ Storage (S3)        │ Cross-region replication (async)        │
│ KMS                 │ Multi-region keys (AWS KMS)             │
└─────────────────────┴──────────────────────────────────────────┘

Failure Handling:
• Circuit Breakers: Prevent cascading failures (5 errors/10s)
• Retry Logic: Exponential backoff (1s → 32s max)
• Graceful Degradation: Read-only mode if storage unavailable
• Health Checks: Liveness (process alive) + Readiness (deps ok)
• Auto-Healing: Kubernetes liveness probe restarts unhealthy pods
```

**Disaster Recovery:**
- **RTO (Recovery Time Objective):** < 4 hours
- **RPO (Recovery Point Objective):** < 1 hour
- **Backup Strategy:** Continuous replication to secondary region + daily snapshots
- **Failover:** Automated DNS failover to standby region (Route 53 health checks)

### 4.3 Performance

**Latency Requirements:**
```
Operation Type              │ p50    │ p99    │ p99.9  │
────────────────────────────┼────────┼────────┼────────┤
Metadata Query (cached)     │ 10ms   │ 20ms   │ 50ms   │
Metadata Query (uncached)   │ 30ms   │ 80ms   │ 150ms  │
Single Record Retrieval     │ 40ms   │ 90ms   │ 200ms  │
Batch Query (100 records)   │ 200ms  │ 500ms  │ 1s     │
Record Ingestion (sync)     │ 50ms   │ 150ms  │ 300ms  │
Anonymization (single)      │ 100ms  │ 300ms  │ 800ms  │
Policy Evaluation (cached)  │ 5ms    │ 15ms   │ 30ms   │
Policy Evaluation (fresh)   │ 80ms   │ 200ms  │ 400ms  │
```

**Throughput Requirements:**
```
API Endpoint               │ Target Throughput  │ Concurrency │
───────────────────────────┼────────────────────┼─────────────┤
GET /datasets              │ 5,000 req/s        │ 500         │
GET /datasets/:id/records  │ 3,000 req/s        │ 300         │
POST /datasets/:id/records │ 1,000 req/s        │ 100         │
gRPC StreamRecords         │ 1GB/s per stream   │ 100 streams │
gRPC BulkIngest            │ 500MB/s per stream │ 50 streams  │
```

**Optimization Techniques:**
1. **Caching Layers:**
   - L1: In-memory LRU cache (per service instance)
   - L2: Redis cluster (shared across instances)
   - L3: CDN for static metadata (CloudFront/Fastly)

2. **Database Optimization:**
   - Connection pooling (100 connections per service)
   - Prepared statement caching
   - Index optimization (B-tree for lookups, GIN for JSONB)
   - Query result caching (Redis)

3. **Network Optimization:**
   - HTTP/2 multiplexing (gRPC)
   - Compression (gzip for REST, Protobuf for gRPC)
   - Keep-alive connections
   - Regional edge deployments

### 4.4 Security Posture

**Security Controls:**
```
Defense-in-Depth Layers:
┌──────────────────────────────────────────────────────────────┐
│ Layer 1: Network Security                                    │
│ • VPC isolation, private subnets                             │
│ • Security groups (least privilege)                          │
│ • WAF rules (OWASP Top 10 protection)                        │
│ • DDoS protection (rate limiting, CloudFlare)                │
└──────────────────────────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ Layer 2: Application Security                                │
│ • TLS 1.3 for all connections (no TLS 1.0/1.1)               │
│ • mTLS for service-to-service communication                  │
│ • Input validation (JSON schema, Protobuf)                   │
│ • CSRF protection, SQL injection prevention                  │
└──────────────────────────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ Layer 3: Authentication & Authorization                      │
│ • JWT with short TTL (15 min), refresh rotation              │
│ • RBAC + ABAC policy evaluation                              │
│ • MFA enforcement for sensitive operations                   │
│ • Service account key rotation (90 days)                     │
└──────────────────────────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ Layer 4: Data Security                                       │
│ • Envelope encryption (AES-256-GCM)                          │
│ • Field-level encryption for high-sensitivity data           │
│ • Automatic PII detection (99.5%+ accuracy)                  │
│ • Secure memory handling (zeroize on drop)                   │
└──────────────────────────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ Layer 5: Audit & Monitoring                                  │
│ • Immutable audit logs (write-once storage)                  │
│ • Real-time anomaly detection (failed auth, unusual access)  │
│ • SIEM integration (Splunk, Datadog)                         │
│ • Quarterly penetration testing                              │
└──────────────────────────────────────────────────────────────┘
```

**Compliance Mappings:**
| Framework | Controls Implemented |
|-----------|---------------------|
| **GDPR** | Article 5 (data minimization), Article 17 (RTBF), Article 30 (records of processing), Article 32 (security measures) |
| **HIPAA** | 164.308(a)(4) (access controls), 164.312(a)(2)(iv) (encryption), 164.312(b) (audit controls) |
| **SOC 2** | CC6.1 (logical access), CC6.6 (encryption), CC7.2 (system monitoring) |
| **PCI-DSS** | 3.4 (encrypted storage), 8.2 (MFA), 10.1 (audit trails) |

### 4.5 Maintainability

**Code Quality:**
- **Test Coverage:** > 90% for critical paths (encryption, access control, anonymization)
- **Static Analysis:** Clippy (Rust linter), cargo-audit (dependency vulnerabilities)
- **Documentation:** Every public API documented with examples (rustdoc)
- **Code Reviews:** Required for all changes, 2+ approvals for security-critical code

**Operational Excellence:**
```
Observability Stack:
┌──────────────────────────────────────────────────────────────┐
│ Metrics (Prometheus)                                         │
│ • Request rate, error rate, latency (RED method)             │
│ • Resource utilization (CPU, memory, disk, network)          │
│ • Business metrics (datasets created, anonymizations, etc.)  │
└──────────────────────────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ Tracing (OpenTelemetry → Jaeger)                             │
│ • Distributed traces across services                         │
│ • Span annotations for slow operations                       │
│ • Trace sampling (10% in prod, 100% in staging)              │
└──────────────────────────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ Logging (Structured JSON → ELK/Loki)                         │
│ • Correlation IDs for request tracking                       │
│ • Log levels: ERROR, WARN, INFO, DEBUG, TRACE                │
│ • Retention: 90 days hot, 1 year archive                     │
└──────────────────────────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────┐
│ Alerting (Prometheus Alertmanager)                           │
│ • P0: API down, data corruption detected                     │
│ • P1: High error rate (>1%), storage nearly full             │
│ • P2: Performance degradation, failed backups                │
└──────────────────────────────────────────────────────────────┘
```

**Deployment Automation:**
- **CI/CD:** GitHub Actions → build → test → scan → deploy to staging → approval → deploy to prod
- **Infrastructure as Code:** Terraform for cloud resources, Helm for Kubernetes
- **GitOps:** ArgoCD for declarative deployment, automatic drift detection
- **Rollback:** Automated rollback on health check failures (< 5 min)

---

## 5. Technology Stack

### 5.1 Runtime and Core Libraries

```rust
// Cargo.toml (simplified)
[dependencies]
# Async Runtime
tokio = { version = "1.35", features = ["full"] }
async-trait = "0.1"

# Web Framework
axum = { version = "0.7", features = ["macros", "multipart"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "compression", "trace"] }

# gRPC
tonic = { version = "0.11", features = ["tls", "compression"] }
prost = "0.12"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Database
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-native-tls", "uuid", "chrono"] }
redis = { version = "0.24", features = ["tokio-comp", "cluster"] }

# Cryptography
ring = "0.17"  # AES-GCM encryption
blake3 = "1.5"  # Content hashing
sodiumoxide = "0.2"  # Additional crypto primitives

# Observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
opentelemetry = { version = "0.21", features = ["rt-tokio"] }
opentelemetry-jaeger = "0.20"
prometheus = "0.13"

# Error Handling
thiserror = "1.0"
anyhow = "1.0"

# Validation
validator = { version = "0.16", features = ["derive"] }

# UUID and Time
uuid = { version = "1.6", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }

# Configuration
config = "0.13"
figment = { version = "0.10", features = ["toml", "env"] }

# Security
jsonwebtoken = "9.2"
argon2 = "0.5"
zeroize = "1.7"
```

### 5.2 Storage and Data Layer

**Primary Database:** PostgreSQL 15+
```sql
-- Core tables (simplified schema)
CREATE TABLE datasets (
    id UUID PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    workspace_id UUID NOT NULL,
    current_version_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    created_by UUID NOT NULL,
    metadata JSONB,
    CONSTRAINT unique_name_workspace UNIQUE(name, workspace_id)
);

CREATE INDEX idx_datasets_workspace ON datasets(workspace_id);
CREATE INDEX idx_datasets_metadata ON datasets USING GIN(metadata);

CREATE TABLE dataset_versions (
    id UUID PRIMARY KEY,
    dataset_id UUID NOT NULL REFERENCES datasets(id),
    version_number INTEGER NOT NULL,
    commit_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    record_count BIGINT,
    size_bytes BIGINT,
    CONSTRAINT unique_dataset_version UNIQUE(dataset_id, version_number)
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID UNIQUE NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    actor_id UUID NOT NULL,
    resource_type VARCHAR(64),
    resource_id UUID,
    action VARCHAR(64),
    result VARCHAR(32),
    metadata JSONB,
    signature VARCHAR(256)  -- Cryptographic signature for tamper detection
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_actor ON audit_log(actor_id);
```

**Cache Layer:** Redis 7+ (Cluster Mode)
```
Cache Hierarchy:
┌─────────────────────────────────────────┐
│ Key Pattern          │ TTL    │ Purpose │
├──────────────────────┼────────┼─────────┤
│ policy:decision:{id} │ 5 min  │ Policy  │
│ dek:cache:{key_id}   │ 1 hour │ DEK     │
│ session:{token}      │ 15 min │ Session │
│ ratelimit:{key}      │ 1 min  │ Limit   │
│ metadata:{ds_id}     │ 10 min │ Dataset │
└──────────────────────┴────────┴─────────┘
```

**Object Storage:** S3-Compatible (AWS S3, MinIO, etc.)
```
Bucket Structure:
vault-prod/
├── datasets/
│   └── {dataset_id}/
│       └── {version_id}/
│           ├── records/
│           │   └── {chunk_hash}  # Content-addressable
│           └── metadata.json.enc
├── audit/
│   └── {year}/{month}/{day}/
│       └── {hour}.jsonl.enc
└── exports/
    └── {export_id}/
        └── anonymized_data.parquet.enc
```

**Message Queue:** Apache Kafka 3.6+
```
Topic Configuration:
┌─────────────────────────┬────────────┬──────────┬───────────┐
│ Topic                   │ Partitions │ Replicas │ Retention │
├─────────────────────────┼────────────┼──────────┼───────────┤
│ vault.events.lifecycle  │ 10         │ 3        │ 7 days    │
│ vault.events.access     │ 20         │ 3        │ 30 days   │
│ vault.events.audit      │ 10         │ 3        │ 90 days   │
│ vault.tasks.export      │ 5          │ 3        │ 1 day     │
│ vault.tasks.encryption  │ 10         │ 3        │ 1 day     │
└─────────────────────────┴────────────┴──────────┴───────────┘
```

### 5.3 Observability Stack

**Metrics:** Prometheus + Grafana
```yaml
# Prometheus scrape config (simplified)
scrape_configs:
  - job_name: 'vault-api'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        regex: llm-data-vault
        action: keep
    metrics_path: /metrics
    scrape_interval: 15s
```

**Tracing:** OpenTelemetry → Jaeger
```rust
// Tracer initialization
use opentelemetry::global;
use opentelemetry_jaeger::new_agent_pipeline;

pub fn init_tracer() -> Result<()> {
    global::set_text_map_propagator(opentelemetry_jaeger::Propagator::new());

    let tracer = new_agent_pipeline()
        .with_service_name("llm-data-vault")
        .with_endpoint("jaeger-agent:6831")
        .install_batch(opentelemetry::runtime::Tokio)?;

    tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    Ok(())
}
```

**Logging:** Structured JSON → ELK Stack / Loki
```rust
// Structured logging example
use tracing::{info, error, instrument};

#[instrument(skip(request), fields(request_id = %request.id))]
async fn handle_request(request: Request) -> Result<Response> {
    info!(
        dataset_id = %request.dataset_id,
        operation = "create",
        "Processing dataset creation"
    );

    match create_dataset(&request).await {
        Ok(dataset) => {
            info!(
                dataset_id = %dataset.id,
                duration_ms = %start.elapsed().as_millis(),
                "Dataset created successfully"
            );
            Ok(Response::success(dataset))
        }
        Err(e) => {
            error!(
                error = %e,
                request_id = %request.id,
                "Failed to create dataset"
            );
            Err(e)
        }
    }
}
```

---

## 6. Deployment Model

### 6.1 Kubernetes-Native Design

**Deployment Architecture:**
```yaml
# Simplified Kubernetes deployment structure
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-data-vault-api
  namespace: llm-platform
spec:
  replicas: 3  # Minimum for HA
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0  # Zero-downtime deployments
  template:
    spec:
      affinity:
        podAntiAffinity:  # Spread across nodes
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: llm-data-vault-api
              topologyKey: kubernetes.io/hostname
      containers:
      - name: api
        image: llm-data-vault:v1.0.0
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 4Gi
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: vault-secrets
              key: database-url
        - name: RUST_LOG
          value: "info,llm_data_vault=debug"
```

**Service Mesh Integration (Istio):**
```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: vault-api
spec:
  hosts:
  - vault-api.llm-platform.svc.cluster.local
  http:
  - match:
    - uri:
        prefix: /api/v1
    route:
    - destination:
        host: vault-api
        subset: v1
      weight: 90  # Canary deployment: 90% v1, 10% v2
    - destination:
        host: vault-api
        subset: v2
      weight: 10
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
      retryOn: 5xx,reset,connect-failure
```

### 6.2 Multi-Region Deployment

```
Global Deployment Topology:
┌───────────────────────────────────────────────────────────────────┐
│                      Global Load Balancer                         │
│                    (Route 53 / Cloud DNS)                         │
└───────────┬───────────────────────────────────┬───────────────────┘
            │                                   │
            ▼                                   ▼
┌─────────────────────────┐       ┌─────────────────────────┐
│   Region: us-east-1     │       │   Region: eu-west-1     │
│   (Primary)             │◄─────►│   (Secondary)           │
├─────────────────────────┤       ├─────────────────────────┤
│ • 3 AZs                 │       │ • 3 AZs                 │
│ • Active/Active API     │       │ • Active/Active API     │
│ • PostgreSQL Primary    │       │ • PostgreSQL Replica    │
│ • S3 Primary            │       │ • S3 Replica (CRR)      │
│ • Kafka Primary         │       │ • Kafka Mirror          │
└─────────────────────────┘       └─────────────────────────┘
            │                                   │
            └───────────────┬───────────────────┘
                            ▼
                ┌─────────────────────────┐
                │   Region: ap-southeast-1│
                │   (DR / Read Replica)   │
                ├─────────────────────────┤
                │ • 3 AZs                 │
                │ • Read-only API         │
                │ • PostgreSQL Replica    │
                │ • S3 Replica (CRR)      │
                └─────────────────────────┘

Traffic Routing Strategy:
• Latency-based routing (Route 53) for optimal user experience
• Health check failover (30s interval, 3 consecutive failures)
• Manual regional failover for disaster recovery
• Cross-region replication lag target: < 5 seconds
```

### 6.3 Scaling Strategies

**Horizontal Scaling (Kubernetes HPA):**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vault-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: llm-data-vault-api
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Pods
        value: 1
        periodSeconds: 60
```

**Vertical Scaling (Database):**
```
PostgreSQL Vertical Scaling Plan:
┌─────────────────────┬──────────────┬─────────┬──────────┐
│ Workload Tier       │ Instance     │ vCPU    │ Memory   │
├─────────────────────┼──────────────┼─────────┼──────────┤
│ Development         │ db.t3.medium │ 2       │ 4 GB     │
│ Staging             │ db.r6g.large │ 2       │ 16 GB    │
│ Production (small)  │ db.r6g.xlarge│ 4       │ 32 GB    │
│ Production (medium) │ db.r6g.2xl   │ 8       │ 64 GB    │
│ Production (large)  │ db.r6g.4xl   │ 16      │ 128 GB   │
│ Production (xlarge) │ db.r6g.8xl   │ 32      │ 256 GB   │
└─────────────────────┴──────────────┴─────────┴──────────┘

Scaling Triggers:
• CPU > 75% for 10 minutes → Scale up
• Connection saturation (> 80% of max_connections) → Scale up
• Disk IOPS saturation → Migrate to Provisioned IOPS
• Read replica lag > 10 seconds → Add read replica
```

**Data Partitioning (Sharding):**
```
Sharding Strategy (when single DB insufficient):
┌────────────────────────────────────────────────────────────┐
│ Shard Key: HASH(dataset_id) % num_shards                  │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Shard 0        Shard 1        Shard 2        Shard 3     │
│  ┌──────┐      ┌──────┐      ┌──────┐      ┌──────┐      │
│  │ DB 0 │      │ DB 1 │      │ DB 2 │      │ DB 3 │      │
│  └──────┘      └──────┘      └──────┘      └──────┘      │
│  datasets      datasets      datasets      datasets      │
│  00-25%        26-50%        51-75%        76-100%       │
│                                                            │
│  Each shard: Primary + 2 replicas                         │
│  Cross-shard queries: Application-level joins              │
│  Shard count: Start with 4, expand to 16 as needed        │
└────────────────────────────────────────────────────────────┘
```

---

## 7. Cross-Cutting Concerns

### 7.1 Configuration Management

**Hierarchical Configuration (using Figment):**
```rust
// Configuration precedence: CLI args > Env vars > Config file > Defaults
use figment::{Figment, providers::{Env, Format, Toml}};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub encryption: EncryptionConfig,
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,          // Default: "0.0.0.0"
    pub port: u16,             // Default: 8080
    pub grpc_port: u16,        // Default: 9090
    pub workers: usize,        // Default: num_cpus
    pub request_timeout: u64,  // Default: 30 (seconds)
}

impl Config {
    pub fn load() -> Result<Self> {
        Figment::new()
            .merge(Toml::file("config/default.toml"))
            .merge(Toml::file(format!("config/{}.toml", env())))
            .merge(Env::prefixed("VAULT_").split("__"))
            .extract()
            .context("Failed to load configuration")
    }
}

// Example: Override via environment variable
// VAULT_DATABASE__MAX_CONNECTIONS=50
```

**Environment-Specific Configs:**
```toml
# config/production.toml
[server]
host = "0.0.0.0"
port = 8080
workers = 16
request_timeout = 60

[database]
url = "${DATABASE_URL}"  # Injected from Kubernetes secret
max_connections = 100
min_connections = 10
connect_timeout = 5
statement_cache_size = 1000

[storage]
backend = "s3"
bucket = "llm-vault-prod-us-east-1"
region = "us-east-1"
endpoint = ""  # Use AWS default

[encryption]
kms_provider = "aws"
kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc-def-ghi"
dek_cache_ttl = 3600  # 1 hour

[observability]
metrics_enabled = true
metrics_port = 9091
tracing_enabled = true
tracing_endpoint = "http://jaeger-collector:14268/api/traces"
log_level = "info"
log_format = "json"
```

### 7.2 Secret Management

**Integration with External Secret Stores:**
```rust
// src/secrets/mod.rs

#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn get_secret(&self, key: &str) -> Result<String>;
    async fn set_secret(&self, key: &str, value: &str) -> Result<()>;
    async fn delete_secret(&self, key: &str) -> Result<()>;
}

// Vault implementation
pub struct VaultSecretProvider {
    client: VaultClient,
    mount_path: String,
}

impl VaultSecretProvider {
    pub async fn new(config: VaultConfig) -> Result<Self> {
        let client = VaultClient::new(config.address.clone())
            .with_auth(config.auth_method.clone())
            .build()?;

        Ok(Self {
            client,
            mount_path: config.mount_path,
        })
    }
}

#[async_trait]
impl SecretProvider for VaultSecretProvider {
    async fn get_secret(&self, key: &str) -> Result<String> {
        let path = format!("{}/{}", self.mount_path, key);
        let secret = self.client.read_secret(&path).await?;

        secret.data.get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Secret not found: {}", key))
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let path = format!("{}/{}", self.mount_path, key);
        let data = json!({ "value": value });
        self.client.write_secret(&path, data).await?;
        Ok(())
    }
}

// Usage
let secrets = VaultSecretProvider::new(vault_config).await?;
let db_password = secrets.get_secret("database/password").await?;
```

**Kubernetes Secret Integration:**
```yaml
# External Secrets Operator configuration
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: llm-platform
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "llm-data-vault"
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-secrets
  namespace: llm-platform
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: vault-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-url
    remoteRef:
      key: llm-platform/database
      property: url
  - secretKey: kms-key-id
    remoteRef:
      key: llm-platform/encryption
      property: kms_key_id
```

### 7.3 Logging and Tracing Correlation

**Correlation ID Propagation:**
```rust
// src/observability/correlation.rs

use tracing::Span;
use uuid::Uuid;

pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_header(header: &str) -> Result<Self> {
        Ok(Self(Uuid::parse_str(header)?))
    }
}

// Middleware to inject correlation ID
pub async fn correlation_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    let correlation_id = request
        .headers()
        .get("X-Correlation-ID")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| Uuid::new_v4());

    // Attach to current span
    Span::current().record("correlation_id", correlation_id.to_string());

    // Store in request extensions
    request.extensions_mut().insert(CorrelationId(correlation_id));

    // Add to response headers
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-Correlation-ID",
        HeaderValue::from_str(&correlation_id.to_string()).unwrap(),
    );

    response
}

// Usage in service layer
#[instrument(skip(self), fields(correlation_id = %correlation_id.0))]
pub async fn create_dataset(
    &self,
    correlation_id: &CorrelationId,
    command: CreateDatasetCommand,
) -> Result<Dataset> {
    info!("Creating dataset: {}", command.name);

    // Propagate to downstream services
    let mut context = HashMap::new();
    context.insert("correlation_id", correlation_id.0.to_string());

    let result = self.storage
        .store_with_context(&data, context)
        .await?;

    Ok(result)
}
```

**Distributed Tracing Example:**
```rust
// Trace propagation across service boundaries
use opentelemetry::global;
use opentelemetry::propagation::Injector;

pub async fn call_policy_engine(
    &self,
    request: PolicyRequest,
) -> Result<PolicyDecision> {
    let mut metadata = tonic::metadata::MetadataMap::new();

    // Inject trace context into gRPC metadata
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(
            &tracing::Span::current().context(),
            &mut MetadataInjector(&mut metadata),
        );
    });

    let response = self.policy_client
        .evaluate(tonic::Request::from_parts(metadata, request))
        .await?;

    Ok(response.into_inner())
}

struct MetadataInjector<'a>(&'a mut tonic::metadata::MetadataMap);

impl<'a> Injector for MetadataInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(key) = tonic::metadata::MetadataKey::from_bytes(key.as_bytes()) {
            if let Ok(val) = tonic::metadata::MetadataValue::try_from(&value) {
                self.0.insert(key, val);
            }
        }
    }
}
```

### 7.4 Health Checking and Readiness

**Health Check Implementation:**
```rust
// src/health/mod.rs

#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub checks: Vec<ComponentHealth>,
    pub timestamp: DateTime<Utc>,
    pub version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Serialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthState,
    pub latency_ms: u64,
    pub message: Option<String>,
}

pub struct HealthChecker {
    db_pool: PgPool,
    redis_client: redis::Client,
    storage: Arc<dyn StorageBackend>,
    kms: Arc<dyn KmsProvider>,
}

impl HealthChecker {
    // Liveness: Is the process alive?
    pub async fn liveness(&self) -> HealthStatus {
        HealthStatus {
            status: HealthState::Healthy,
            checks: vec![],
            timestamp: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    // Readiness: Can the service handle requests?
    pub async fn readiness(&self) -> HealthStatus {
        let checks = tokio::join!(
            self.check_database(),
            self.check_redis(),
            self.check_storage(),
            self.check_kms(),
        );

        let all_checks = vec![checks.0, checks.1, checks.2, checks.3];

        let status = if all_checks.iter().all(|c| matches!(c.status, HealthState::Healthy)) {
            HealthState::Healthy
        } else if all_checks.iter().any(|c| matches!(c.status, HealthState::Unhealthy)) {
            HealthState::Unhealthy
        } else {
            HealthState::Degraded
        };

        HealthStatus {
            status,
            checks: all_checks,
            timestamp: Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    async fn check_database(&self) -> ComponentHealth {
        let start = Instant::now();
        let result = sqlx::query("SELECT 1").execute(&self.db_pool).await;

        ComponentHealth {
            name: "database".to_string(),
            status: if result.is_ok() {
                HealthState::Healthy
            } else {
                HealthState::Unhealthy
            },
            latency_ms: start.elapsed().as_millis() as u64,
            message: result.err().map(|e| e.to_string()),
        }
    }

    async fn check_redis(&self) -> ComponentHealth {
        let start = Instant::now();
        let mut conn = self.redis_client.get_async_connection().await;
        let result = if let Ok(mut conn) = conn.as_mut() {
            redis::cmd("PING").query_async::<_, String>(&mut conn).await
        } else {
            Err(conn.unwrap_err())
        };

        ComponentHealth {
            name: "redis".to_string(),
            status: if result.is_ok() {
                HealthState::Healthy
            } else {
                HealthState::Unhealthy
            },
            latency_ms: start.elapsed().as_millis() as u64,
            message: result.err().map(|e| e.to_string()),
        }
    }

    async fn check_storage(&self) -> ComponentHealth {
        let start = Instant::now();
        let result = self.storage.health_check().await;

        ComponentHealth {
            name: "storage".to_string(),
            status: match result {
                Ok(_) => HealthState::Healthy,
                Err(_) => HealthState::Degraded,  // Degraded, not unhealthy (can retry)
            },
            latency_ms: start.elapsed().as_millis() as u64,
            message: result.err().map(|e| e.to_string()),
        }
    }

    async fn check_kms(&self) -> ComponentHealth {
        let start = Instant::now();
        let result = self.kms.health_check().await;

        ComponentHealth {
            name: "kms".to_string(),
            status: match result {
                Ok(_) => HealthState::Healthy,
                Err(_) => HealthState::Degraded,  // Can operate with cached DEKs temporarily
            },
            latency_ms: start.elapsed().as_millis() as u64,
            message: result.err().map(|e| e.to_string()),
        }
    }
}
```

---

## 8. Architectural Decision Records

### ADR-001: Rust as Implementation Language

**Status:** Accepted

**Context:**
Need to select primary implementation language for LLM-Data-Vault that balances performance, security, and developer productivity.

**Decision:**
Use Rust with Tokio async runtime.

**Rationale:**
- **Memory Safety:** Eliminates buffer overflows, use-after-free, data races at compile time
- **Performance:** Zero-cost abstractions, no GC pauses, comparable to C/C++
- **Async Runtime:** Tokio provides 10k+ concurrent connections with minimal overhead
- **Ecosystem:** Mature libraries for crypto (ring), serialization (serde), database (sqlx)
- **Security:** Type system prevents entire classes of vulnerabilities

**Consequences:**
- **Positive:** Reduced security vulnerabilities, excellent performance, low resource usage
- **Negative:** Longer compilation times, steeper learning curve, smaller talent pool
- **Mitigation:** Invest in developer training, use CI caching for builds

---

### ADR-002: Envelope Encryption Pattern

**Status:** Accepted

**Context:**
Need encryption strategy that supports key rotation without re-encrypting all data, works with multiple KMS providers, and maintains high performance.

**Decision:**
Implement envelope encryption with two-tier key hierarchy:
- **KEK (Key Encryption Key):** Managed by external KMS, rotates every 90 days
- **DEK (Data Encryption Key):** Generated per-dataset, encrypted by KEK

**Rationale:**
- **Key Rotation:** Can rotate KEK by re-encrypting DEKs only (metadata), not all data
- **Performance:** DEK cached in Redis (1 hour TTL) reduces KMS calls by 90%
- **Portability:** Abstraction allows switching KMS providers (AWS KMS, Vault, etc.)
- **Security:** Defense in depth - KMS compromise requires additional DEK access

**Consequences:**
- **Positive:** Fast key rotation, KMS-agnostic, efficient caching
- **Negative:** Additional network hop for initial DEK retrieval, complexity in key management
- **Mitigation:** Redis cluster for DEK caching, robust retry logic for KMS calls

---

### ADR-003: Content-Addressable Storage

**Status:** Accepted

**Context:**
Need storage strategy for large datasets that provides deduplication, integrity verification, and efficient versioning.

**Decision:**
Use content-addressable storage with BLAKE3 hashing for all record storage.

**Rationale:**
- **Deduplication:** Identical records stored once, saving 40% storage in typical LLM datasets
- **Integrity:** Hash verifies data integrity on every read, detects silent corruption
- **Versioning:** Git-like semantics with immutable objects enable efficient branching
- **Concurrency:** Multiple writes of same content are idempotent, no conflicts

**Consequences:**
- **Positive:** Significant storage savings, built-in integrity checks, git-like workflows
- **Negative:** Cannot modify objects in-place (must write new version), hash computation overhead
- **Mitigation:** BLAKE3 is 10x faster than SHA-256, use streaming hashing for large objects

---

### ADR-004: PostgreSQL for Metadata

**Status:** Accepted

**Context:**
Need database for metadata (dataset info, versions, lineage, audit logs) with ACID guarantees, rich query capabilities, and proven scalability.

**Decision:**
Use PostgreSQL 15+ with JSONB for flexible metadata and read replicas for scaling.

**Rationale:**
- **ACID:** Critical for audit logs and lineage tracking (must be consistent)
- **JSONB:** Schema flexibility for evolving metadata without migrations
- **Ecosystem:** Mature tooling (Patroni for HA, pgBackRest for backups)
- **Performance:** Excellent for transactional workloads, supports 10k+ TPS
- **Compliance:** Widely accepted in regulated industries

**Consequences:**
- **Positive:** Strong consistency, rich queries (lineage traversal), proven reliability
- **Negative:** Vertical scaling limits (eventual need for sharding)
- **Mitigation:** Read replicas for scaling reads, sharding by dataset_id for writes

---

### ADR-005: gRPC for High-Throughput Operations

**Status:** Accepted

**Context:**
Need API protocol for bulk operations (dataset ingestion, streaming queries) that provides high throughput and low latency.

**Decision:**
Provide both REST (Axum) for CRUD and gRPC (Tonic) for streaming/bulk operations.

**Rationale:**
- **Performance:** HTTP/2 multiplexing + Protobuf binary encoding = 10x throughput vs REST
- **Streaming:** Bidirectional streaming for large dataset transfers (GB+ files)
- **Type Safety:** Protobuf schema provides compile-time type checking
- **Ecosystem:** Wide language support (Python, Go, Java, etc.)

**Consequences:**
- **Positive:** Excellent performance for bulk ops, streaming support, type-safe APIs
- **Negative:** Binary protocol harder to debug, requires code generation
- **Mitigation:** Provide REST for most ops (80%), gRPC for performance-critical paths (20%)

---

### ADR-006: Event-Driven Integration

**Status:** Accepted

**Context:**
Need integration pattern with other LLM DevOps modules that scales, decouples services, and supports eventual consistency.

**Decision:**
Use Kafka for event-driven integration with at-least-once delivery semantics.

**Rationale:**
- **Decoupling:** Vault publishes events, consumers subscribe independently
- **Scalability:** Kafka handles millions of events/second, partitioned by dataset_id
- **Durability:** Events persisted to disk, replayable for recovery
- **Ecosystem:** Mature tooling (Kafka Connect, Streams, Schema Registry)

**Consequences:**
- **Positive:** Loose coupling, high throughput, event replay for debugging
- **Negative:** Operational complexity, eventual consistency requires idempotent consumers
- **Mitigation:** Managed Kafka (MSK, Confluent Cloud), consumer idempotency patterns

---

## Conclusion

This System Overview Architecture establishes the foundational design for LLM-Data-Vault as an enterprise-grade, secure, and scalable data management platform. The architecture prioritizes:

1. **Security First:** Zero-trust architecture with defense-in-depth and comprehensive audit trails
2. **Performance at Scale:** Sub-100ms latency at 10k+ req/s with horizontal scaling to petabytes
3. **Operational Excellence:** Kubernetes-native deployment with comprehensive observability
4. **Flexibility:** Pluggable backends (storage, KMS, auth) prevent vendor lock-in

**Next Steps in SPARC Methodology:**
- **Component Diagrams:** Detailed internal architecture for each container (encryption service, anonymization engine, etc.)
- **Sequence Diagrams:** Request flows for critical operations (ingestion, anonymization, key rotation)
- **Data Flow Diagrams:** End-to-end data movement with encryption boundaries
- **Deployment Diagrams:** Infrastructure-as-code for multi-region deployment
- **Security Architecture:** Threat model and security controls mapping

---

**Document Metadata:**
- **Authors:** LLM DevOps Architecture Team
- **Reviewers:** Security Team, Platform Team, Compliance Team
- **Approval:** Pending architectural review board
- **Related Documents:**
  - [LLM-Data-Vault Specification](../LLM-Data-Vault-Specification.md)
  - [Pseudocode Index](../pseudocode/00-index.md)
  - [Design Principles](../../DESIGN_PRINCIPLES.md)
  - [Dependencies & Integration Points](../DEPENDENCIES_AND_INTEGRATION_POINTS.md)

---

*This document is part of the SPARC (Specification, Pseudocode, Architecture, Refinement, Completion) methodology for LLM-Data-Vault.*
