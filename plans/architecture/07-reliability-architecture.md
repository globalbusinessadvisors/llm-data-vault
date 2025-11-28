# Reliability Architecture

**Document Version:** 1.0
**Last Updated:** 2025-11-27
**Status:** Draft
**Owner:** Platform Engineering Team

---

## Table of Contents

1. [Reliability Overview](#1-reliability-overview)
2. [Error Handling Architecture](#2-error-handling-architecture)
3. [Resilience Patterns](#3-resilience-patterns)
4. [Health Checking](#4-health-checking)
5. [Graceful Shutdown](#5-graceful-shutdown)
6. [Observability](#6-observability)
7. [Capacity Planning](#7-capacity-planning)
8. [Chaos Engineering](#8-chaos-engineering)
9. [Incident Management](#9-incident-management)
10. [Testing Strategy](#10-testing-strategy)
11. [SLI/SLO Definition](#11-slislo-definition)

---

## 1. Reliability Overview

### 1.1 Mission Statement

LLM-Data-Vault is designed to be a highly reliable, production-grade system that enterprises can depend on for handling sensitive data with 99.9% availability. This document defines the architectural patterns, practices, and mechanisms that enable this level of reliability.

### 1.2 SLA Targets

```
┌─────────────────────────────────────────────────────────┐
│                   SLA COMMITMENT                         │
├─────────────────────────────────────────────────────────┤
│ Availability:         99.9% (43.8 min downtime/month)   │
│ Latency (p99):        < 200ms                           │
│ Error Rate:           < 0.1%                            │
│ Throughput:           10,000 req/s                      │
│ Data Durability:      99.999999999% (11 nines)         │
│ Recovery Time (RTO):  < 5 minutes                       │
│ Recovery Point (RPO): < 1 minute                        │
└─────────────────────────────────────────────────────────┘
```

### 1.3 Error Budget Concept

Error budgets provide a quantitative measure of acceptable unreliability, enabling data-driven decisions about feature velocity versus stability.

```
Monthly Error Budget Calculation:
─────────────────────────────────
Total minutes in month:     43,800
Availability target:        99.9%
Allowed downtime:           43.8 minutes
Error budget remaining:     Updated real-time

Budget Consumption:
┌──────────────────────────────────────────┐
│  Week 1: [████████░░░░░░░░░░] 20%       │
│  Week 2: [████████████░░░░░░] 30%       │
│  Week 3: [████████████████░░] 40%       │
│  Week 4: [░░░░░░░░░░░░░░░░░░] Remaining │
└──────────────────────────────────────────┘

Actions Based on Budget:
- < 25% consumed: Normal velocity
- 25-50% consumed: Cautious deployment
- 50-75% consumed: Freeze non-critical changes
- > 75% consumed: Emergency freeze, focus on reliability
```

### 1.4 Reliability Principles

#### Defense in Depth
Multiple layers of protection ensure that no single failure can compromise the system:
- Application-level error handling
- Circuit breakers for external dependencies
- Request timeouts and retry policies
- Infrastructure redundancy
- Data replication and backup

#### Fail Fast and Loud
Failures should be detected immediately and reported clearly:
- Explicit error types with context
- Comprehensive logging and tracing
- Real-time alerting
- No silent failures

#### Graceful Degradation
System continues operating with reduced functionality when components fail:
- Core operations remain available
- Non-essential features disabled
- Clear communication of degraded state
- Automatic recovery when possible

#### Observable and Debuggable
Every operation produces telemetry for diagnosis:
- Structured logging with correlation IDs
- Distributed tracing across services
- Metrics for all critical paths
- Runtime profiling capabilities

#### Design for Failure
Assume everything will fail and plan accordingly:
- No single points of failure
- Automatic failover mechanisms
- Self-healing capabilities
- Regular chaos engineering

---

## 2. Error Handling Architecture

### 2.1 Error Taxonomy

```
VaultError (Base Error)
│
├── ClientError (4xx) - User/Client mistakes
│   │
│   ├── ValidationError (400)
│   │   ├── SchemaValidationError
│   │   ├── ConstraintViolationError
│   │   └── InvalidParameterError
│   │
│   ├── AuthenticationError (401)
│   │   ├── InvalidCredentialsError
│   │   ├── TokenExpiredError
│   │   └── MissingAuthenticationError
│   │
│   ├── AuthorizationError (403)
│   │   ├── InsufficientPermissionsError
│   │   ├── ResourceAccessDeniedError
│   │   └── TenantIsolationViolationError
│   │
│   ├── NotFoundError (404)
│   │   ├── DatasetNotFoundError
│   │   ├── RecordNotFoundError
│   │   └── VersionNotFoundError
│   │
│   ├── ConflictError (409)
│   │   ├── DuplicateResourceError
│   │   ├── ConcurrentModificationError
│   │   └── StateConflictError
│   │
│   ├── InvalidRequestError (422)
│   │   ├── UnsupportedOperationError
│   │   ├── InvalidStateTransitionError
│   │   └── BusinessRuleViolationError
│   │
│   └── RateLimitError (429)
│       ├── TenantRateLimitError
│       └── GlobalRateLimitError
│
├── ServerError (5xx) - System failures
│   │
│   ├── InternalError (500)
│   │   ├── UnexpectedError
│   │   ├── ConfigurationError
│   │   └── InvariantViolationError
│   │
│   ├── StorageError (500)
│   │   ├── StorageConnectionError
│   │   ├── StorageReadError
│   │   ├── StorageWriteError
│   │   └── StorageCapacityError
│   │
│   ├── EncryptionError (500)
│   │   ├── KeyRetrievalError
│   │   ├── EncryptionOperationError
│   │   └── DecryptionOperationError
│   │
│   ├── DependencyError (502)
│   │   ├── DownstreamServiceError
│   │   ├── DatabaseError
│   │   └── MessageQueueError
│   │
│   └── ServiceUnavailableError (503)
│       ├── MaintenanceModeError
│       ├── OverloadedError
│       └── StartupError
│
└── TransientError - Retry-able failures
    │
    ├── TimeoutError (504)
    │   ├── ConnectionTimeoutError
    │   ├── RequestTimeoutError
    │   └── OperationTimeoutError
    │
    ├── NetworkError
    │   ├── ConnectionResetError
    │   ├── DNSResolutionError
    │   └── NetworkPartitionError
    │
    └── TemporaryResourceError
        ├── TemporaryLockError
        └── TemporaryUnavailableError
```

### 2.2 Error Response Format

All errors follow a consistent JSON structure for easy parsing and handling:

```json
{
  "error": {
    "code": "VAULT_ERR_001",
    "type": "DatasetNotFoundError",
    "message": "Dataset not found",
    "details": {
      "dataset_id": "ds_abc123xyz",
      "tenant_id": "tenant_456",
      "requested_at": "2025-01-01T00:00:00Z"
    },
    "trace_id": "abc123def456",
    "span_id": "span789",
    "timestamp": "2025-01-01T00:00:00.123Z",
    "retry_after": null,
    "documentation_url": "https://docs.llm-data-vault.com/errors/VAULT_ERR_001"
  }
}
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `code` | string | Machine-readable error code (VAULT_ERR_XXX) |
| `type` | string | Error class name |
| `message` | string | Human-readable error description |
| `details` | object | Context-specific error information |
| `trace_id` | string | Distributed trace ID for correlation |
| `span_id` | string | Current operation span ID |
| `timestamp` | string | ISO 8601 timestamp |
| `retry_after` | int | Seconds to wait before retry (for rate limits) |
| `documentation_url` | string | Link to error documentation |

### 2.3 Error Code Ranges

```
VAULT_ERR_0001-0999:   Client errors (validation, auth)
VAULT_ERR_1000-1999:   Server errors (internal, storage)
VAULT_ERR_2000-2999:   Dependency errors (external services)
VAULT_ERR_3000-3999:   Transient errors (timeouts, network)
VAULT_ERR_4000-4999:   Business logic errors
VAULT_ERR_5000-5999:   Security errors (encryption, KMS)
VAULT_ERR_9000-9999:   Unknown/unclassified errors
```

### 2.4 Error Handling Patterns

#### 2.4.1 Error Wrapping and Context

Errors are wrapped with context as they propagate up the stack:

```go
// Go example
func (s *DatasetService) GetDataset(ctx context.Context, id string) (*Dataset, error) {
    dataset, err := s.repo.FindByID(ctx, id)
    if err != nil {
        return nil, errors.Wrap(err,
            errors.WithCode("VAULT_ERR_001"),
            errors.WithContext("dataset_id", id),
            errors.WithOperation("GetDataset"),
        )
    }
    return dataset, nil
}

// Error chain:
// DatasetNotFoundError
//   -> Repository.FindByID failed
//     -> Database query returned no rows
//       -> SQL: SELECT * FROM datasets WHERE id = ?
```

#### 2.4.2 Panic Recovery

All HTTP handlers and background workers have panic recovery:

```go
func RecoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                // Log panic with stack trace
                logger.Error("panic recovered",
                    "error", err,
                    "stack", debug.Stack(),
                    "trace_id", getTraceID(r.Context()),
                )

                // Return 500 response
                writeError(w, &InternalError{
                    Code: "VAULT_ERR_9999",
                    Message: "Internal server error",
                    TraceID: getTraceID(r.Context()),
                })

                // Emit metric
                metrics.PanicsTotal.Inc()
            }
        }()

        next.ServeHTTP(w, r)
    })
}
```

#### 2.4.3 Graceful Degradation

When optional dependencies fail, core functionality remains available:

```
Request Flow with Degradation:
┌──────────┐
│  Client  │
└────┬─────┘
     │
     v
┌─────────────────┐
│  API Gateway    │
└────┬────────────┘
     │
     v
┌─────────────────┐     ┌──────────────┐
│  Core Service   │────>│   Redis      │ (Cache Layer)
└────┬────────────┘     └──────┬───────┘
     │                         X (Failed)
     v                         │
┌─────────────────┐           │
│   PostgreSQL    │<──────────┘ (Fallback to DB)
└─────────────────┘

Degradation Scenarios:
1. Redis fails -> Bypass cache, query DB directly
2. Metrics collector fails -> Buffer metrics, continue serving
3. Tracing fails -> Log without traces, continue serving
4. Non-critical features -> Return 503 for feature, keep core up
```

---

## 3. Resilience Patterns

### 3.1 Circuit Breaker Pattern

Circuit breakers prevent cascading failures by failing fast when a dependency is unhealthy.

```
Circuit Breaker State Machine:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│    CLOSED                 OPEN               HALF-OPEN  │
│   (Normal)            (Failing Fast)        (Testing)   │
│       │                    │                    │       │
│       │                    │                    │       │
│   [Success]            [Timer]            [Success]     │
│       │                    │                    │       │
│       v                    v                    v       │
│   ┌───────┐           ┌────────┐          ┌────────┐   │
│   │       │  Failure  │        │  Timeout │        │   │
│   │Closed │─────────>│  Open  │────────>│ Half-  │   │
│   │       │<─────────│        │<────────│  Open  │   │
│   └───────┘  Success └────────┘  Failure└────────┘   │
│       ^                                      │         │
│       │                                      │         │
│       └──────────────────────────────────────┘         │
│                    Success                             │
└─────────────────────────────────────────────────────────┘

State Behaviors:
- CLOSED:    All requests pass through, failures counted
- OPEN:      All requests fail immediately (fail fast)
- HALF-OPEN: Limited requests allowed to test recovery
```

#### Configuration

```yaml
circuit_breaker:
  # Failure threshold to open circuit
  failure_threshold: 5
  failure_window: 60s

  # Open state duration
  open_duration: 30s

  # Half-open state configuration
  half_open_requests: 3
  half_open_success_threshold: 2

  # Error classification
  count_as_failure:
    - ServerError
    - TimeoutError
    - DependencyError

  ignore_errors:
    - ClientError  # Don't count user errors
```

#### Implementation Example

```go
type CircuitBreaker struct {
    state            State
    failureCount     int
    successCount     int
    lastFailureTime  time.Time
    config           Config
    mutex            sync.RWMutex
}

func (cb *CircuitBreaker) Execute(fn func() error) error {
    if !cb.allowRequest() {
        return ErrCircuitOpen
    }

    err := fn()
    cb.recordResult(err)
    return err
}

func (cb *CircuitBreaker) allowRequest() bool {
    cb.mutex.RLock()
    defer cb.mutex.RUnlock()

    switch cb.state {
    case StateClosed:
        return true
    case StateOpen:
        if time.Since(cb.lastFailureTime) > cb.config.OpenDuration {
            cb.transitionToHalfOpen()
            return true
        }
        return false
    case StateHalfOpen:
        return cb.successCount < cb.config.HalfOpenRequests
    }
    return false
}
```

### 3.2 Retry Pattern

Automatic retries for transient failures with exponential backoff and jitter.

```
Retry Timeline:
┌────────────────────────────────────────────────────────┐
│ Attempt 1: Failed (TimeoutError)                      │
│     │                                                  │
│     └──> Wait: 100ms + jitter(0-50ms)                │
│                                                        │
│ Attempt 2: Failed (ConnectionError)                   │
│     │                                                  │
│     └──> Wait: 200ms + jitter(0-100ms)               │
│                                                        │
│ Attempt 3: Success                                    │
│     └──> Return result                                │
└────────────────────────────────────────────────────────┘

Backoff Formula:
delay = min(initial_delay * (2 ^ attempt), max_delay) + random(0, jitter)
```

#### Retry Policy Configuration

```yaml
retry_policy:
  # Maximum retry attempts
  max_attempts: 3

  # Backoff configuration
  initial_delay: 100ms
  max_delay: 5s
  backoff_multiplier: 2.0
  jitter: 0.5  # 50% jitter

  # Retryable conditions
  retry_on:
    - TimeoutError
    - ConnectionError
    - ServiceUnavailableError
    - RateLimitError  # with exponential backoff

  # Non-retryable conditions
  do_not_retry:
    - ValidationError
    - AuthenticationError
    - NotFoundError
    - ConflictError

  # Per-operation overrides
  operations:
    idempotent_writes:
      max_attempts: 5
    non_idempotent_writes:
      max_attempts: 1
```

#### Implementation Example

```go
func RetryWithBackoff(ctx context.Context, fn func() error, policy RetryPolicy) error {
    var lastErr error

    for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
        // Execute operation
        err := fn()

        // Success
        if err == nil {
            if attempt > 0 {
                metrics.RetrySuccessTotal.Inc()
            }
            return nil
        }

        lastErr = err

        // Check if retryable
        if !isRetryable(err, policy) {
            return err
        }

        // Last attempt exhausted
        if attempt == policy.MaxAttempts-1 {
            break
        }

        // Calculate backoff
        delay := calculateBackoff(attempt, policy)

        // Wait with context cancellation support
        select {
        case <-time.After(delay):
            continue
        case <-ctx.Done():
            return ctx.Err()
        }
    }

    metrics.RetryExhaustedTotal.Inc()
    return fmt.Errorf("max retries exceeded: %w", lastErr)
}

func calculateBackoff(attempt int, policy RetryPolicy) time.Duration {
    // Exponential backoff
    delay := policy.InitialDelay * time.Duration(math.Pow(2, float64(attempt)))

    // Cap at max delay
    if delay > policy.MaxDelay {
        delay = policy.MaxDelay
    }

    // Add jitter
    jitter := time.Duration(rand.Float64() * float64(delay) * policy.Jitter)

    return delay + jitter
}
```

### 3.3 Bulkhead Pattern

Resource isolation prevents resource exhaustion in one component from affecting others.

```
Bulkhead Isolation:
┌─────────────────────────────────────────────────────────┐
│                    Thread Pools                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   API Pool   │  │Storage Pool  │  │  KMS Pool    │  │
│  │  (200 max)   │  │  (50 max)    │  │  (20 max)    │  │
│  │              │  │              │  │              │  │
│  │ [##########] │  │ [#####     ] │  │ [##        ] │  │
│  │  50% used    │  │  50% used    │  │  20% used    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Cache Pool  │  │Analytics Pool│  │  Async Pool  │  │
│  │  (30 max)    │  │  (100 max)   │  │  (50 max)    │  │
│  │              │  │              │  │              │  │
│  │ [##########] │  │ [#######    ] │  │ [####      ] │  │
│  │  80% used    │  │  70% used    │  │  40% used    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘

If Storage Pool saturates -> Only storage operations blocked
                          -> API continues serving cached data
```

#### Configuration

```yaml
bulkheads:
  api_requests:
    max_concurrent: 200
    queue_size: 500
    timeout: 30s

  storage_operations:
    max_concurrent: 50
    queue_size: 100
    timeout: 10s

  kms_operations:
    max_concurrent: 20
    queue_size: 50
    timeout: 5s

  cache_operations:
    max_concurrent: 30
    queue_size: 0  # No queuing, fail fast
    timeout: 1s

  analytics_jobs:
    max_concurrent: 100
    queue_size: 1000
    timeout: 300s

  async_workers:
    max_concurrent: 50
    queue_size: 10000
    timeout: 60s
```

### 3.4 Timeout Pattern

Comprehensive timeout configuration prevents hanging operations.

```
Timeout Hierarchy:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  Client Request (60s total timeout)                    │
│  │                                                      │
│  ├──> Connection Timeout (5s)                          │
│  │    └──> DNS Resolution (2s)                         │
│  │    └──> TCP Handshake (3s)                          │
│  │                                                      │
│  ├──> Request Timeout (30s)                            │
│  │    ├──> Authentication (2s)                         │
│  │    ├──> Authorization (1s)                          │
│  │    ├──> Validation (500ms)                          │
│  │    └──> Business Logic (26.5s)                      │
│  │         ├──> Database Query (10s)                   │
│  │         ├──> KMS Operation (5s)                     │
│  │         └──> Storage Operation (10s)                │
│  │                                                      │
│  └──> Streaming Operations (5m)                        │
│       └──> Large file upload/download                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### Timeout Configuration

```yaml
timeouts:
  # Connection establishment
  connection:
    dial_timeout: 5s
    tls_handshake_timeout: 10s
    dns_resolution_timeout: 2s

  # Request processing
  request:
    read_timeout: 30s
    write_timeout: 30s
    idle_timeout: 120s
    header_timeout: 5s

  # Database operations
  database:
    connection_timeout: 5s
    query_timeout: 10s
    transaction_timeout: 30s

  # External services
  kms:
    operation_timeout: 5s

  storage:
    read_timeout: 10s
    write_timeout: 30s
    metadata_timeout: 5s

  cache:
    operation_timeout: 1s

  # Long-running operations
  streaming:
    upload_timeout: 300s  # 5 minutes
    download_timeout: 300s
    chunk_timeout: 30s

  # Background jobs
  jobs:
    worker_timeout: 600s  # 10 minutes
    shutdown_timeout: 30s
```

---

## 4. Health Checking

### 4.1 Health Check Architecture

```
Health Check System:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  ┌──────────────┐      ┌──────────────┐               │
│  │   Liveness   │      │  Readiness   │               │
│  │    Probe     │      │    Probe     │               │
│  │              │      │              │               │
│  │  Process OK? │      │ Dependencies │               │
│  │  Basic check │      │   Healthy?   │               │
│  └──────┬───────┘      └──────┬───────┘               │
│         │                     │                        │
│         v                     v                        │
│  ┌─────────────────────────────────────┐               │
│  │        Health Registry              │               │
│  │  ┌───────────────────────────────┐  │               │
│  │  │ - Database: Healthy           │  │               │
│  │  │ - Redis: Healthy              │  │               │
│  │  │ - KMS: Healthy                │  │               │
│  │  │ - Storage: Degraded           │  │               │
│  │  │ - MessageQueue: Healthy       │  │               │
│  │  └───────────────────────────────┘  │               │
│  └─────────────────────────────────────┘               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Liveness Probe

Indicates if the application process is running and not deadlocked.

```http
GET /health/live HTTP/1.1
Host: api.llm-data-vault.com

Response (200 OK):
{
  "status": "alive",
  "timestamp": "2025-01-01T00:00:00Z"
}
```

#### Configuration

```yaml
liveness:
  endpoint: /health/live
  port: 8080

  # Kubernetes probe settings
  kubernetes:
    initial_delay_seconds: 30
    period_seconds: 10
    timeout_seconds: 5
    success_threshold: 1
    failure_threshold: 3

  # Checks performed
  checks:
    - process_running: true
    - goroutine_threshold: 10000  # Alert if exceeded
    - memory_threshold: 2GB       # Alert if exceeded
```

#### Implementation

```go
func LivenessHandler(w http.ResponseWriter, r *http.Request) {
    // Simple check - is the process responding?
    response := map[string]interface{}{
        "status": "alive",
        "timestamp": time.Now().UTC(),
    }

    // Optional: Check for resource leaks
    if runtime.NumGoroutine() > 10000 {
        logger.Warn("high goroutine count", "count", runtime.NumGoroutine())
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}
```

### 4.3 Readiness Probe

Indicates if the application can serve traffic (dependencies are healthy).

```http
GET /health/ready HTTP/1.1
Host: api.llm-data-vault.com

Response (200 OK):
{
  "status": "ready",
  "timestamp": "2025-01-01T00:00:00Z",
  "checks": {
    "database": {
      "status": "healthy",
      "latency_ms": 5,
      "message": "connection pool: 10/100 active"
    },
    "redis": {
      "status": "healthy",
      "latency_ms": 2,
      "message": "connected"
    },
    "kms": {
      "status": "healthy",
      "latency_ms": 45,
      "message": "accessible"
    },
    "storage": {
      "status": "degraded",
      "latency_ms": 150,
      "message": "slow response times"
    }
  },
  "overall_status": "degraded"
}
```

#### Configuration

```yaml
readiness:
  endpoint: /health/ready
  port: 8080

  # Kubernetes probe settings
  kubernetes:
    initial_delay_seconds: 10
    period_seconds: 5
    timeout_seconds: 3
    success_threshold: 1
    failure_threshold: 2

  # Dependency checks
  checks:
    database:
      enabled: true
      timeout: 2s
      query: "SELECT 1"
      critical: true

    redis:
      enabled: true
      timeout: 1s
      operation: "PING"
      critical: false  # Can operate without cache

    kms:
      enabled: true
      timeout: 3s
      operation: "list_keys"
      critical: true

    storage:
      enabled: true
      timeout: 2s
      operation: "head_bucket"
      critical: true

    message_queue:
      enabled: true
      timeout: 2s
      operation: "ping"
      critical: false
```

#### Implementation

```go
type HealthChecker struct {
    checks map[string]HealthCheck
}

type HealthCheck interface {
    Name() string
    Check(ctx context.Context) HealthStatus
    IsCritical() bool
}

type HealthStatus struct {
    Status    string        // "healthy", "degraded", "unhealthy"
    LatencyMs int64
    Message   string
    Error     error
}

func (hc *HealthChecker) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
    defer cancel()

    results := make(map[string]HealthStatus)
    overallHealthy := true
    overallCritical := false

    // Execute all checks in parallel
    var wg sync.WaitGroup
    var mu sync.Mutex

    for name, check := range hc.checks {
        wg.Add(1)
        go func(name string, check HealthCheck) {
            defer wg.Done()

            start := time.Now()
            status := check.Check(ctx)
            status.LatencyMs = time.Since(start).Milliseconds()

            mu.Lock()
            results[name] = status

            if status.Status != "healthy" {
                overallHealthy = false
                if check.IsCritical() {
                    overallCritical = true
                }
            }
            mu.Unlock()
        }(name, check)
    }

    wg.Wait()

    // Determine overall status
    overallStatus := "ready"
    statusCode := http.StatusOK

    if overallCritical {
        overallStatus = "not_ready"
        statusCode = http.StatusServiceUnavailable
    } else if !overallHealthy {
        overallStatus = "degraded"
        statusCode = http.StatusOK  // Still serve traffic
    }

    response := map[string]interface{}{
        "status":         overallStatus,
        "timestamp":      time.Now().UTC(),
        "checks":         results,
        "overall_status": overallStatus,
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(response)
}
```

### 4.4 Startup Probe

Indicates if the application has completed initialization (for slow-starting apps).

```http
GET /health/startup HTTP/1.1
Host: api.llm-data-vault.com

Response (200 OK):
{
  "status": "started",
  "timestamp": "2025-01-01T00:00:00Z",
  "startup_duration_ms": 15420,
  "components": {
    "config_loaded": true,
    "database_migrated": true,
    "cache_warmed": true,
    "workers_started": true
  }
}
```

#### Configuration

```yaml
startup:
  endpoint: /health/startup
  port: 8080

  # Kubernetes probe settings
  kubernetes:
    initial_delay_seconds: 0
    period_seconds: 5
    timeout_seconds: 5
    success_threshold: 1
    failure_threshold: 12  # 60 seconds max startup time

  # Initialization steps
  required_steps:
    - load_configuration
    - connect_database
    - run_migrations
    - connect_cache
    - initialize_kms
    - warm_cache
    - start_workers
```

### 4.5 Dependency Health Checks

Individual dependency health checks with specific criteria:

#### Database Health

```go
func (c *DatabaseHealthCheck) Check(ctx context.Context) HealthStatus {
    start := time.Now()

    // Execute simple query
    var result int
    err := c.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
    latency := time.Since(start)

    if err != nil {
        return HealthStatus{
            Status:  "unhealthy",
            Message: fmt.Sprintf("query failed: %v", err),
            Error:   err,
        }
    }

    // Check connection pool stats
    stats := c.db.Stats()
    poolUsage := float64(stats.InUse) / float64(stats.MaxOpenConnections)

    status := "healthy"
    message := fmt.Sprintf("connection pool: %d/%d active",
        stats.InUse, stats.MaxOpenConnections)

    if poolUsage > 0.9 {
        status = "degraded"
        message += " (high utilization)"
    }

    if latency > 100*time.Millisecond {
        status = "degraded"
        message += " (slow response)"
    }

    return HealthStatus{
        Status:  status,
        Message: message,
    }
}
```

#### KMS Health

```go
func (c *KMSHealthCheck) Check(ctx context.Context) HealthStatus {
    start := time.Now()

    // Try to list keys (lightweight operation)
    _, err := c.kmsClient.ListKeys(ctx, &kms.ListKeysInput{
        Limit: aws.Int32(1),
    })
    latency := time.Since(start)

    if err != nil {
        return HealthStatus{
            Status:  "unhealthy",
            Message: fmt.Sprintf("KMS not accessible: %v", err),
            Error:   err,
        }
    }

    status := "healthy"
    message := "accessible"

    if latency > 200*time.Millisecond {
        status = "degraded"
        message = "slow response times"
    }

    return HealthStatus{
        Status:  status,
        Message: message,
    }
}
```

---

## 5. Graceful Shutdown

### 5.1 Shutdown Sequence

```
Graceful Shutdown Flow:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  1. Receive SIGTERM                                     │
│     │                                                   │
│     v                                                   │
│  2. Stop accepting new requests                        │
│     ├──> Return 503 to health checks                   │
│     └──> Load balancer removes from pool               │
│                                                         │
│  3. Wait for in-flight requests (max 30s)              │
│     ├──> Request 1: [##########] Completed             │
│     ├──> Request 2: [#######   ] Processing            │
│     └──> Request 3: [####      ] Processing            │
│                                                         │
│  4. Stop background workers                            │
│     ├──> Signal workers to stop                        │
│     ├──> Complete current jobs                         │
│     └──> Persist incomplete work                       │
│                                                         │
│  5. Flush buffers                                      │
│     ├──> Flush metrics to Prometheus                   │
│     ├──> Flush logs to aggregator                      │
│     └──> Flush traces to collector                     │
│                                                         │
│  6. Close connections                                  │
│     ├──> Close database connections                    │
│     ├──> Close cache connections                       │
│     └──> Close message queue connections               │
│                                                         │
│  7. Exit process                                       │
│     └──> Return exit code 0                            │
│                                                         │
└─────────────────────────────────────────────────────────┘

Timeline:
T+0s:    SIGTERM received
T+0s:    Stop accepting requests
T+0-30s: Drain in-flight requests
T+30s:   Stop workers
T+31s:   Flush buffers
T+32s:   Close connections
T+33s:   Exit
```

### 5.2 Implementation

```go
type GracefulShutdown struct {
    server          *http.Server
    workers         []Worker
    db              *sql.DB
    cache           *redis.Client
    metricsExporter MetricsExporter
    logger          Logger
    shutdownTimeout time.Duration
}

func (gs *GracefulShutdown) Shutdown(ctx context.Context) error {
    logger.Info("initiating graceful shutdown")

    // Create shutdown context with timeout
    shutdownCtx, cancel := context.WithTimeout(ctx, gs.shutdownTimeout)
    defer cancel()

    // 1. Stop accepting new requests
    logger.Info("stopping HTTP server")
    if err := gs.server.Shutdown(shutdownCtx); err != nil {
        logger.Error("HTTP server shutdown failed", "error", err)
    }

    // 2. Stop background workers
    logger.Info("stopping background workers")
    gs.stopWorkers(shutdownCtx)

    // 3. Flush metrics and logs
    logger.Info("flushing metrics and logs")
    gs.flushMetrics(shutdownCtx)
    gs.flushLogs(shutdownCtx)

    // 4. Close database connections
    logger.Info("closing database connections")
    if err := gs.db.Close(); err != nil {
        logger.Error("database close failed", "error", err)
    }

    // 5. Close cache connections
    logger.Info("closing cache connections")
    if err := gs.cache.Close(); err != nil {
        logger.Error("cache close failed", "error", err)
    }

    logger.Info("graceful shutdown complete")
    return nil
}

func (gs *GracefulShutdown) stopWorkers(ctx context.Context) {
    var wg sync.WaitGroup

    for _, worker := range gs.workers {
        wg.Add(1)
        go func(w Worker) {
            defer wg.Done()

            logger.Info("stopping worker", "name", w.Name())
            if err := w.Shutdown(ctx); err != nil {
                logger.Error("worker shutdown failed",
                    "name", w.Name(),
                    "error", err)
            }
        }(worker)
    }

    // Wait for all workers to stop
    done := make(chan struct{})
    go func() {
        wg.Wait()
        close(done)
    }()

    select {
    case <-done:
        logger.Info("all workers stopped")
    case <-ctx.Done():
        logger.Warn("worker shutdown timeout exceeded")
    }
}
```

### 5.3 Kubernetes Integration

#### PreStop Hook

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-data-vault
spec:
  template:
    spec:
      containers:
      - name: vault
        image: llm-data-vault:latest
        lifecycle:
          preStop:
            exec:
              command: ["/bin/sh", "-c", "sleep 5"]
        ports:
        - containerPort: 8080
          name: http
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2

      # Graceful termination period
      terminationGracePeriodSeconds: 60
```

#### Pod Disruption Budget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: llm-data-vault-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: llm-data-vault

  # Prevent more than 1 pod from being disrupted at a time
  maxUnavailable: 1
```

### 5.4 Signal Handling

```go
func main() {
    // Setup application
    app := setupApplication()

    // Start server in background
    go func() {
        logger.Info("starting HTTP server", "port", 8080)
        if err := app.server.ListenAndServe(); err != http.ErrServerClosed {
            logger.Fatal("server failed", "error", err)
        }
    }()

    // Wait for shutdown signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

    sig := <-quit
    logger.Info("shutdown signal received", "signal", sig)

    // Initiate graceful shutdown
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    if err := app.Shutdown(ctx); err != nil {
        logger.Error("shutdown failed", "error", err)
        os.Exit(1)
    }

    logger.Info("server stopped successfully")
}
```

---

## 6. Observability

### 6.1 Metrics Architecture

```
Metrics Collection & Export:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│                  Application                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │                                                 │   │
│  │  metrics.RequestsTotal.Inc()                    │   │
│  │  metrics.RequestDuration.Observe(duration)      │   │
│  │  metrics.ActiveConnections.Set(count)           │   │
│  │                                                 │   │
│  └──────────────────┬──────────────────────────────┘   │
│                     │                                   │
│                     v                                   │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Prometheus Client Library                │  │
│  │  ┌────────────────────────────────────────────┐  │  │
│  │  │ - Counters    (monotonic increase)         │  │  │
│  │  │ - Gauges      (current value)              │  │  │
│  │  │ - Histograms  (distributions)              │  │  │
│  │  │ - Summaries   (quantiles)                  │  │  │
│  │  └────────────────────────────────────────────┘  │  │
│  └──────────────────┬───────────────────────────────┘  │
│                     │                                   │
└─────────────────────┼───────────────────────────────────┘
                      │
                      │ HTTP /metrics endpoint
                      │
                      v
         ┌────────────────────────┐
         │   Prometheus Server    │
         │  ┌──────────────────┐  │
         │  │  Time Series DB  │  │
         │  └──────────────────┘  │
         └────────┬───────────────┘
                  │
                  v
         ┌────────────────────────┐
         │      Grafana           │
         │  ┌──────────────────┐  │
         │  │   Dashboards     │  │
         │  │   Alerting       │  │
         │  └──────────────────┘  │
         └────────────────────────┘
```

### 6.2 Core Metrics

#### Request Metrics

```promql
# Total requests by method, endpoint, and status
vault_requests_total{method="GET", endpoint="/api/v1/datasets", status="200"}

# Request duration histogram
vault_request_duration_seconds_bucket{
  method="POST",
  endpoint="/api/v1/datasets",
  le="0.1"
} 1234

# Request size histogram
vault_request_size_bytes_bucket{
  method="POST",
  endpoint="/api/v1/datasets",
  le="1024"
} 567

# Active requests gauge
vault_active_requests{method="GET", endpoint="/api/v1/datasets"} 42
```

#### Storage Metrics

```promql
# Storage operations
vault_storage_operations_total{
  operation="read",
  backend="s3",
  status="success"
}

# Storage operation duration
vault_storage_operation_duration_seconds{
  operation="write",
  backend="s3"
}

# Storage bytes transferred
vault_storage_bytes_total{
  operation="write",
  backend="s3"
}

# Storage errors
vault_storage_errors_total{
  operation="read",
  backend="s3",
  error_type="timeout"
}
```

#### Encryption Metrics

```promql
# Encryption operations
vault_encryption_operations_total{
  operation="encrypt",
  algorithm="aes256",
  status="success"
}

# Encryption duration
vault_encryption_duration_seconds{
  operation="decrypt",
  algorithm="aes256"
}

# KMS operations
vault_kms_operations_total{
  operation="generate_data_key",
  status="success"
}
```

#### Anonymization Metrics

```promql
# Anonymization operations
vault_anonymization_operations_total{
  strategy="hash",
  field_type="email",
  status="success"
}

# Anonymization duration
vault_anonymization_duration_seconds{
  strategy="tokenize"
}

# Privacy violations detected
vault_privacy_violations_total{
  type="pii_detected",
  severity="high"
}
```

#### System Metrics

```promql
# Active connections
vault_active_connections{type="database"} 45
vault_active_connections{type="cache"} 12

# Circuit breaker state
vault_circuit_breaker_state{
  dependency="database",
  state="closed"
} 1

# Error budget remaining (percentage)
vault_error_budget_remaining{slo="availability"} 0.85

# Goroutines
vault_goroutines_count 234

# Memory usage
vault_memory_bytes{type="heap"} 524288000
vault_memory_bytes{type="stack"} 32768000
```

### 6.3 Distributed Tracing

```
Trace Example: POST /api/v1/datasets
┌─────────────────────────────────────────────────────────┐
│ Trace ID: abc123def456                                  │
│ Duration: 145ms                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ [HTTP POST /api/v1/datasets]                 145ms     │
│  │                                                      │
│  ├─[Authenticate]                            12ms      │
│  │  └─[JWT Verification]                     10ms      │
│  │                                                      │
│  ├─[Authorize]                               5ms       │
│  │                                                      │
│  ├─[Validate Request]                        8ms       │
│  │  ├─[Schema Validation]                    6ms       │
│  │  └─[Business Rules]                       2ms       │
│  │                                                      │
│  ├─[Create Dataset]                          115ms     │
│  │  │                                                   │
│  │  ├─[Generate DEK]                         45ms      │
│  │  │  └─[KMS.GenerateDataKey]               43ms      │
│  │  │                                                   │
│  │  ├─[Insert Database]                      35ms      │
│  │  │  └─[PostgreSQL INSERT]                 33ms      │
│  │  │                                                   │
│  │  ├─[Store Metadata]                       25ms      │
│  │  │  └─[S3.PutObject]                      23ms      │
│  │  │                                                   │
│  │  └─[Publish Event]                        10ms      │
│  │     └─[Kafka.Produce]                     8ms       │
│  │                                                      │
│  └─[Format Response]                         5ms       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### Trace Context Propagation

```go
type TraceContext struct {
    TraceID  string                 // Unique trace identifier
    SpanID   string                 // Current span identifier
    ParentID string                 // Parent span identifier
    Baggage  map[string]string      // Cross-cutting concerns
    Sampled  bool                   // Should this trace be sampled?
}

// HTTP header propagation (W3C Trace Context)
traceparent: 00-abc123def456-span789-01
tracestate: tenant=acme,user=user123

// Span creation
func (s *Service) CreateDataset(ctx context.Context, req *CreateDatasetRequest) (*Dataset, error) {
    span, ctx := tracer.StartSpan(ctx, "CreateDataset")
    defer span.Finish()

    span.SetTag("dataset.name", req.Name)
    span.SetTag("tenant.id", req.TenantID)

    // Propagate context to child operations
    dataset, err := s.repo.Insert(ctx, req)
    if err != nil {
        span.SetTag("error", true)
        span.LogKV("error.message", err.Error())
        return nil, err
    }

    span.SetTag("dataset.id", dataset.ID)
    return dataset, nil
}
```

#### Sampling Strategy

```yaml
tracing:
  # Sampling configuration
  sampling:
    # Default sampling rate (1% of traces)
    default_rate: 0.01

    # Always sample errors
    sample_errors: true

    # Always sample slow requests (> 1s)
    sample_slow_requests: true
    slow_threshold: 1s

    # Per-endpoint sampling rules
    rules:
      - endpoint: /api/v1/health/*
        rate: 0.001  # Health checks rarely sampled

      - endpoint: /api/v1/datasets
        rate: 0.05   # Dataset operations 5% sampled

      - endpoint: /api/v1/admin/*
        rate: 1.0    # Admin operations always sampled

  # Trace exporters
  exporters:
    - type: jaeger
      endpoint: http://jaeger:14268/api/traces

    - type: zipkin
      endpoint: http://zipkin:9411/api/v2/spans
```

### 6.4 Structured Logging

#### Log Format

```json
{
  "timestamp": "2025-01-01T12:34:56.789Z",
  "level": "INFO",
  "logger": "dataset.service",
  "message": "Dataset created successfully",
  "trace_id": "abc123def456",
  "span_id": "span789",
  "user_id": "user-123",
  "tenant_id": "tenant-456",
  "dataset_id": "ds-789",
  "duration_ms": 145,
  "fields": {
    "dataset_name": "customer_data",
    "record_count": 10000,
    "size_bytes": 5242880
  }
}
```

#### Log Levels

```
TRACE:  Very detailed diagnostic information
DEBUG:  Detailed information for debugging
INFO:   General informational messages
WARN:   Warning messages for potentially harmful situations
ERROR:  Error events that might still allow the app to continue
FATAL:  Severe errors that cause the application to abort
```

#### Logging Best Practices

```go
// ✅ Good: Structured logging with context
logger.Info("dataset created",
    "dataset_id", dataset.ID,
    "tenant_id", dataset.TenantID,
    "size_bytes", dataset.Size,
    "duration_ms", duration.Milliseconds(),
)

// ❌ Bad: Unstructured string formatting
logger.Info(fmt.Sprintf("Dataset %s created for tenant %s", dataset.ID, dataset.TenantID))

// ✅ Good: Include error context
logger.Error("failed to create dataset",
    "error", err,
    "dataset_name", req.Name,
    "tenant_id", req.TenantID,
    "retry_attempt", attempt,
)

// ❌ Bad: Log error without context
logger.Error("error: " + err.Error())

// ✅ Good: Log levels appropriately
logger.Debug("entering function", "params", params)  // Development only
logger.Info("operation completed", "result", result)  // Normal operations
logger.Warn("slow query detected", "duration", dur)   // Potential issues
logger.Error("operation failed", "error", err)        // Errors

// ❌ Bad: Everything is INFO or ERROR
logger.Info("debug info...")  // Should be DEBUG
logger.Error("warning...")    // Should be WARN
```

#### Log Aggregation

```
Log Pipeline:
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│ Application │─────>│ Fluentd/     │─────>│ Elasticsearch│
│ (JSON logs) │      │ Filebeat     │      │ / Loki      │
└─────────────┘      └──────────────┘      └──────┬──────┘
                                                   │
                                                   v
                                            ┌─────────────┐
                                            │   Kibana/   │
                                            │   Grafana   │
                                            └─────────────┘
```

### 6.5 Alerting Rules

#### High Error Rate Alert

```yaml
groups:
  - name: vault_reliability
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: |
          (
            sum(rate(vault_requests_total{status=~"5.."}[5m]))
            /
            sum(rate(vault_requests_total[5m]))
          ) > 0.01
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "High error rate detected"
          description: |
            Error rate is {{ $value | humanizePercentage }}
            (threshold: 1%)
            Current SLO: 99.9% availability
          runbook_url: https://wiki.company.com/runbooks/high-error-rate
```

#### High Latency Alert

```yaml
      - alert: HighLatency
        expr: |
          histogram_quantile(0.99,
            rate(vault_request_duration_seconds_bucket[5m])
          ) > 0.2
        for: 5m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "High latency detected"
          description: |
            P99 latency is {{ $value }}s (threshold: 200ms)
            Endpoint: {{ $labels.endpoint }}
          runbook_url: https://wiki.company.com/runbooks/high-latency
```

#### Error Budget Burn Rate Alert

```yaml
      - alert: ErrorBudgetBurnRateTooFast
        expr: |
          (
            1 - (
              sum(rate(vault_requests_total{status!~"5.."}[1h]))
              /
              sum(rate(vault_requests_total[1h]))
            )
          ) > (1 - 0.999) * 14.4  # 14.4x burn rate = budget consumed in 2 days
        for: 15m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Error budget burning too fast"
          description: |
            At current error rate, monthly error budget will be
            exhausted in < 2 days.
            Consider freezing non-critical deployments.
          runbook_url: https://wiki.company.com/runbooks/error-budget
```

#### Service Degradation Alert

```yaml
      - alert: ServiceDegraded
        expr: vault_circuit_breaker_state{state="open"} == 1
        for: 2m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "Service dependency degraded"
          description: |
            Circuit breaker for {{ $labels.dependency }} is OPEN.
            Service is operating in degraded mode.
          runbook_url: https://wiki.company.com/runbooks/circuit-breaker
```

#### Resource Exhaustion Alert

```yaml
      - alert: DatabaseConnectionPoolExhausted
        expr: |
          vault_active_connections{type="database"}
          /
          vault_max_connections{type="database"}
          > 0.9
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Database connection pool near exhaustion"
          description: |
            Connection pool is {{ $value | humanizePercentage }} full.
            May need to scale up connection limits or investigate leaks.
          runbook_url: https://wiki.company.com/runbooks/connection-pool
```

---

## 7. Capacity Planning

### 7.1 Load Estimation

#### Target Capacity

```
Production Load Profile:
┌─────────────────────────────────────────────────────────┐
│ Requests per second:          10,000 req/s             │
│ Peak requests per second:     25,000 req/s (2.5x)      │
│ Concurrent users:             1,000                     │
│ Active datasets:              100,000                   │
│ Total data volume:            10 TB                     │
│ Data growth rate:             2 TB/month                │
│ Average request latency:      50ms (p50)                │
│ P99 request latency:          200ms                     │
└─────────────────────────────────────────────────────────┘
```

#### Request Distribution

```
Request Mix:
┌──────────────────────────────────────────┐
│ Operation          % of Traffic  RPS     │
├──────────────────────────────────────────┤
│ Read Datasets      40%           4,000   │
│ Query Data         30%           3,000   │
│ Write Data         20%           2,000   │
│ Create Dataset     5%            500     │
│ Delete/Update      3%            300     │
│ Admin Operations   2%            200     │
└──────────────────────────────────────────┘

Request Pattern:
Peak Hours: 9am-5pm weekdays (2.5x average)
Off-Peak: Nights and weekends (0.3x average)

     ^
RPS  │     ┌───┐
     │    ┌┘   └┐     ┌───┐
     │   ┌┘     └┐   ┌┘   └┐
     │  ┌┘       └┐ ┌┘     └┐
     │ ┌┘         └─┘       └┐
     └─┴──────────────────────┴─────>
       6am    12pm    6pm    12am   Time
```

### 7.2 Resource Requirements

#### Compute Requirements

```
Per-Instance Resource Calculation:
┌─────────────────────────────────────────────────────────┐
│ CPU:                                                    │
│   Base load: 2 vCPU                                     │
│   Per 1,000 req/s: +1 vCPU                             │
│   Target instance: 4 vCPU for 2,000 req/s             │
│                                                         │
│ Memory:                                                 │
│   Base: 2 GB                                            │
│   Connection pools: 512 MB                              │
│   Caching: 2 GB                                         │
│   Application heap: 1.5 GB                              │
│   Buffer: 1 GB                                          │
│   Target instance: 8 GB RAM                             │
│                                                         │
│ Network:                                                │
│   Average request size: 10 KB                           │
│   Average response size: 50 KB                          │
│   Per 1,000 req/s: 60 MB/s bandwidth                   │
│   Target instance: 120 MB/s (1 Gbps)                   │
└─────────────────────────────────────────────────────────┘

Cluster Sizing:
- Target: 10,000 req/s
- Per instance: 2,000 req/s
- Required instances: 5 minimum
- With redundancy (N+2): 7 instances
- With headroom (20%): 9 instances
```

#### Database Requirements

```
PostgreSQL Sizing:
┌─────────────────────────────────────────────────────────┐
│ Connection Pool:                                        │
│   Max connections per app instance: 20                  │
│   Total app instances: 9                                │
│   Required: 180 connections                             │
│   Database max_connections: 300 (with buffer)           │
│                                                         │
│ Storage:                                                │
│   Metadata per dataset: 5 KB                            │
│   100,000 datasets: 500 MB                              │
│   Indexes: 200 MB                                       │
│   Transaction logs: 50 GB                               │
│   Total: 60 GB minimum                                  │
│   With growth (2 years): 200 GB                         │
│                                                         │
│ IOPS:                                                   │
│   Write operations: 2,000/s                             │
│   Read operations: 7,000/s                              │
│   Required IOPS: 10,000 (provisioned)                   │
│                                                         │
│ Instance Size:                                          │
│   db.r5.xlarge (4 vCPU, 32 GB RAM)                     │
│   With read replica for scaling                         │
└─────────────────────────────────────────────────────────┘
```

#### Cache Requirements

```
Redis Sizing:
┌─────────────────────────────────────────────────────────┐
│ Cache Size:                                             │
│   Dataset metadata: 500 MB                              │
│   Session data: 100 MB                                  │
│   Rate limiting counters: 50 MB                         │
│   Hot data cache: 5 GB                                  │
│   Total: 6 GB                                           │
│   With overhead (30%): 8 GB                             │
│                                                         │
│ Operations:                                             │
│   Cache hit rate target: 80%                            │
│   Cache operations: 8,000/s                             │
│                                                         │
│ Instance Size:                                          │
│   cache.r5.large (2 vCPU, 13.07 GB RAM)                │
│   With read replicas for HA                             │
└─────────────────────────────────────────────────────────┘
```

#### Object Storage Requirements

```
S3 Sizing:
┌─────────────────────────────────────────────────────────┐
│ Storage:                                                │
│   Current: 10 TB                                        │
│   Growth: 2 TB/month                                    │
│   2-year projection: 58 TB                              │
│                                                         │
│ Requests:                                               │
│   PUT requests: 2,000/s                                 │
│   GET requests: 7,000/s                                 │
│   Total: 9,000/s                                        │
│                                                         │
│ Data Transfer:                                          │
│   Upload: 200 MB/s                                      │
│   Download: 700 MB/s                                    │
│   Total: 900 MB/s (7.2 Gbps)                           │
└─────────────────────────────────────────────────────────┘
```

### 7.3 Scaling Triggers

#### Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: llm-data-vault-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: llm-data-vault

  minReplicas: 5
  maxReplicas: 50

  metrics:
    # Scale based on CPU
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70

    # Scale based on memory
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80

    # Scale based on request rate
    - type: Pods
      pods:
        metric:
          name: vault_requests_per_second
        target:
          type: AverageValue
          averageValue: "2000"

  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
        - type: Pods
          value: 2
          periodSeconds: 60
      selectPolicy: Min

    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 30
        - type: Pods
          value: 4
          periodSeconds: 30
      selectPolicy: Max
```

#### Database Scaling

```yaml
# Read replica autoscaling
database_scaling:
  # Scale up triggers
  scale_up:
    - metric: cpu_utilization
      threshold: 70%
      duration: 5m

    - metric: connection_pool_utilization
      threshold: 80%
      duration: 3m

    - metric: replication_lag
      threshold: 5s
      duration: 2m

  # Scale down triggers
  scale_down:
    - metric: cpu_utilization
      threshold: 30%
      duration: 30m

    - metric: connection_pool_utilization
      threshold: 40%
      duration: 30m

  # Scaling parameters
  min_replicas: 1
  max_replicas: 5
  cooldown_period: 600s
```

### 7.4 Cost Optimization

```
Cost Breakdown (Monthly):
┌─────────────────────────────────────────────────────────┐
│ Compute (9 instances):           $1,800                 │
│ Database (with replicas):        $1,200                 │
│ Cache (with replicas):           $300                   │
│ Object Storage (10TB):           $230                   │
│ Data Transfer:                   $450                   │
│ Load Balancer:                   $180                   │
│ Monitoring:                      $150                   │
│ ───────────────────────────────────────                 │
│ Total:                           $4,310/month            │
│                                                         │
│ Cost per 1M requests:            $1.25                  │
│ Cost per GB stored:              $0.023                 │
└─────────────────────────────────────────────────────────┘

Optimization Strategies:
1. Use spot instances for non-critical workloads (30% savings)
2. Enable S3 Intelligent-Tiering (15% savings)
3. Optimize data transfer with CloudFront (20% savings)
4. Right-size instances based on actual usage (25% savings)
5. Use reserved instances for baseline capacity (40% savings)

Potential savings: $1,500/month (35%)
```

---

## 8. Chaos Engineering

### 8.1 Chaos Engineering Philosophy

Chaos engineering is the discipline of experimenting on a system to build confidence in its capability to withstand turbulent conditions in production.

```
Chaos Engineering Cycle:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  1. Define Steady State                                │
│     └─> Normal metrics and behavior                    │
│                                                         │
│  2. Hypothesize                                        │
│     └─> "System will remain available if..."          │
│                                                         │
│  3. Introduce Variables                                │
│     └─> Inject failures                                │
│                                                         │
│  4. Observe Results                                    │
│     └─> Compare to steady state                        │
│                                                         │
│  5. Learn and Improve                                  │
│     └─> Fix weaknesses, update runbooks               │
│                                                         │
│  ──────> Repeat ──────────────────────────────>        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 8.2 Failure Injection Scenarios

#### Pod Termination

```yaml
# LitmusChaos experiment: Random pod deletion
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: pod-delete-chaos
spec:
  engineState: 'active'
  appinfo:
    appns: 'default'
    applabel: 'app=llm-data-vault'
    appkind: 'deployment'

  chaosServiceAccount: litmus-admin

  experiments:
    - name: pod-delete
      spec:
        components:
          env:
            # Number of pods to delete
            - name: TOTAL_CHAOS_DURATION
              value: '60'

            # Interval between deletions
            - name: CHAOS_INTERVAL
              value: '10'

            # Number of pods to delete per interval
            - name: PODS_AFFECTED_PERC
              value: '20'

            # Force deletion
            - name: FORCE
              value: 'true'

# Expected outcomes:
# - Remaining pods handle increased load
# - New pods start successfully
# - No request failures (with retry)
# - Circuit breakers do not open
```

#### Network Latency Injection

```yaml
# LitmusChaos experiment: Network latency
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: network-latency-chaos
spec:
  engineState: 'active'
  appinfo:
    appns: 'default'
    applabel: 'app=llm-data-vault'
    appkind: 'deployment'

  chaosServiceAccount: litmus-admin

  experiments:
    - name: pod-network-latency
      spec:
        components:
          env:
            # Latency to inject (ms)
            - name: NETWORK_LATENCY
              value: '2000'

            # Duration
            - name: TOTAL_CHAOS_DURATION
              value: '120'

            # Target containers
            - name: TARGET_CONTAINER
              value: 'vault'

            # Jitter
            - name: JITTER
              value: '500'

# Expected outcomes:
# - Requests timeout and retry
# - Circuit breakers may open temporarily
# - Graceful degradation to cached data
# - Alerts fire for high latency
```

#### Dependency Failure

```yaml
# LitmusChaos experiment: Database failure
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: database-failure-chaos
spec:
  engineState: 'active'
  appinfo:
    appns: 'database'
    applabel: 'app=postgresql'
    appkind: 'statefulset'

  chaosServiceAccount: litmus-admin

  experiments:
    - name: pod-delete
      spec:
        components:
          env:
            - name: TOTAL_CHAOS_DURATION
              value: '300'

            - name: PODS_AFFECTED_PERC
              value: '100'

# Expected outcomes:
# - Application fails to connect to database
# - Circuit breaker opens for database
# - Read-only mode activated (cache-only)
# - Graceful error messages to users
# - Automatic recovery when database returns
```

#### Resource Exhaustion

```yaml
# LitmusChaos experiment: CPU stress
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: cpu-stress-chaos
spec:
  engineState: 'active'
  appinfo:
    appns: 'default'
    applabel: 'app=llm-data-vault'
    appkind: 'deployment'

  chaosServiceAccount: litmus-admin

  experiments:
    - name: pod-cpu-hog
      spec:
        components:
          env:
            # CPU cores to stress
            - name: CPU_CORES
              value: '2'

            # Duration
            - name: TOTAL_CHAOS_DURATION
              value: '180'

            # CPU load percentage
            - name: CPU_LOAD
              value: '100'

# Expected outcomes:
# - HPA scales up new pods
# - Requests handled by healthy pods
# - Some request latency increase
# - Load balancer redistributes traffic
```

### 8.3 Game Day Scenarios

#### Scenario 1: Database Failover

```
Game Day: Database Primary Failure
─────────────────────────────────────
Objective: Validate automatic failover to database replica

Timeline:
T+0:00  Inject failure - Terminate database primary
T+0:05  Monitor application behavior
T+0:10  Validate automatic failover
T+0:15  Verify data consistency
T+0:20  End experiment, debrief

Success Criteria:
✓ Failover completes within 30 seconds
✓ Zero data loss (RPO = 0)
✓ Application recovery without manual intervention
✓ All monitoring alerts fire correctly

Validation Steps:
1. Monitor error rate during failover
2. Check circuit breaker state
3. Verify write operations resume
4. Confirm replication lag returns to normal
5. Review logs for any unexpected errors
```

#### Scenario 2: Regional Outage

```
Game Day: Complete AZ Failure
─────────────────────────────────────
Objective: Validate multi-AZ resilience

Timeline:
T+0:00  Simulate AZ failure (network partition)
T+0:05  Monitor cross-AZ traffic
T+0:10  Validate service continuity
T+0:15  Check data replication
T+0:30  Restore AZ connectivity
T+0:35  Verify re-convergence
T+0:40  End experiment, debrief

Success Criteria:
✓ Service remains available in other AZs
✓ No customer-facing errors
✓ Data remains consistent across AZs
✓ Automatic recovery when AZ returns

Validation Steps:
1. Verify load balancer health checks
2. Monitor pod distribution across AZs
3. Check database replica status
4. Validate object storage access
5. Review cost impact of cross-AZ traffic
```

#### Scenario 3: Cascading Failure

```
Game Day: Cascading Service Degradation
─────────────────────────────────────
Objective: Test circuit breakers and bulkheads

Timeline:
T+0:00  Inject latency in KMS service (2s delay)
T+0:05  Monitor encryption operation timeouts
T+0:10  Increase KMS latency (5s delay)
T+0:15  Observe circuit breaker behavior
T+0:20  Inject cache failure
T+0:25  Monitor cascading effects
T+0:30  Restore services
T+0:35  End experiment, debrief

Success Criteria:
✓ Circuit breakers prevent cascading failures
✓ Core read operations remain available
✓ Graceful degradation for write operations
✓ Clear error messages to users

Validation Steps:
1. Monitor circuit breaker state changes
2. Verify bulkhead isolation
3. Check retry behavior
4. Validate graceful degradation
5. Review user-facing error messages
```

### 8.4 Chaos Testing in CI/CD

```yaml
# GitLab CI chaos testing stage
chaos_testing:
  stage: chaos
  image: litmuschaos/litmus-operator:latest

  only:
    - main
    - /^release\/.*$/

  when: manual  # Require manual trigger

  script:
    # Deploy to chaos testing environment
    - kubectl apply -f k8s/chaos-environment/

    # Wait for steady state
    - ./scripts/wait-for-steady-state.sh

    # Run chaos experiments
    - kubectl apply -f chaos/experiments/pod-delete.yaml
    - ./scripts/validate-experiment.sh pod-delete

    - kubectl apply -f chaos/experiments/network-latency.yaml
    - ./scripts/validate-experiment.sh network-latency

    - kubectl apply -f chaos/experiments/resource-stress.yaml
    - ./scripts/validate-experiment.sh resource-stress

    # Generate report
    - ./scripts/generate-chaos-report.sh

  artifacts:
    reports:
      junit: chaos-results.xml
    paths:
      - chaos-report.html
    expire_in: 30 days

  environment:
    name: chaos-testing
    on_stop: cleanup_chaos
```

---

## 9. Incident Management

### 9.1 Incident Severity Levels

| Level | Description | Impact | Response Time | Example |
|-------|-------------|--------|---------------|---------|
| **P1** | Critical | Service completely down or major security breach | 15 minutes | API unavailable, data breach |
| **P2** | High | Significant degradation affecting many users | 1 hour | High latency, partial outage |
| **P3** | Medium | Minor degradation or single feature broken | 4 hours | Non-critical feature broken |
| **P4** | Low | Cosmetic issues or minor bugs | 24 hours | UI glitch, documentation error |

### 9.2 Incident Response Process

```
Incident Response Workflow:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  1. Detection                                           │
│     ├─> Automated alerts                                │
│     ├─> User reports                                    │
│     └─> Monitoring dashboards                           │
│                                                         │
│  2. Initial Response (< 15 min)                        │
│     ├─> Acknowledge alert                               │
│     ├─> Assess severity                                 │
│     ├─> Create incident ticket                          │
│     └─> Page on-call engineer                           │
│                                                         │
│  3. Investigation (< 30 min)                           │
│     ├─> Review metrics and logs                         │
│     ├─> Identify affected components                    │
│     ├─> Determine root cause                            │
│     └─> Establish incident channel                      │
│                                                         │
│  4. Mitigation (< 1 hour)                              │
│     ├─> Implement immediate fix or rollback             │
│     ├─> Verify mitigation effectiveness                 │
│     ├─> Monitor for stability                           │
│     └─> Update stakeholders                             │
│                                                         │
│  5. Resolution                                         │
│     ├─> Confirm service restored                        │
│     ├─> Document timeline                               │
│     ├─> Close incident ticket                           │
│     └─> Schedule post-incident review                   │
│                                                         │
│  6. Post-Incident Review (< 5 days)                   │
│     ├─> Blameless postmortem                           │
│     ├─> Root cause analysis                             │
│     ├─> Action items                                    │
│     └─> Process improvements                            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 9.3 Runbooks

#### Runbook: API High Error Rate

```markdown
# Runbook: API High Error Rate

## Trigger
- Alert: HighErrorRate fires
- Condition: Error rate > 1% for 5 minutes

## Initial Assessment (5 minutes)

1. **Check Grafana Dashboard**
   - URL: https://grafana.company.com/d/vault-overview
   - Review error rate graph
   - Identify affected endpoints
   - Check error types (4xx vs 5xx)

2. **Query Recent Errors**
   ```bash
   # Get error breakdown
   kubectl logs -l app=llm-data-vault --tail=1000 | \
     grep '"level":"ERROR"' | \
     jq -r '.error.type' | sort | uniq -c | sort -rn
   ```

3. **Check Service Health**
   ```bash
   # Check readiness status
   kubectl get pods -l app=llm-data-vault
   kubectl exec -it llm-data-vault-xxxx -- \
     curl http://localhost:8080/health/ready
   ```

## Common Causes and Fixes

### Cause 1: Database Connection Pool Exhausted

**Symptoms:**
- Errors: "connection pool timeout"
- High database connection count

**Fix:**
```bash
# Increase connection pool size
kubectl set env deployment/llm-data-vault \
  DB_MAX_CONNECTIONS=50

# Or restart pods to reset connections
kubectl rollout restart deployment/llm-data-vault
```

### Cause 2: Downstream Service Failure

**Symptoms:**
- Errors: "DependencyError", "TimeoutError"
- Circuit breakers opening

**Fix:**
```bash
# Check circuit breaker status
curl http://localhost:8080/metrics | \
  grep vault_circuit_breaker_state

# If KMS is down, enable degraded mode (read-only)
kubectl set env deployment/llm-data-vault \
  DEGRADED_MODE=true
```

### Cause 3: Resource Exhaustion

**Symptoms:**
- High CPU or memory usage
- OOMKilled pods
- Slow response times

**Fix:**
```bash
# Scale up immediately
kubectl scale deployment/llm-data-vault --replicas=15

# Or increase resource limits
kubectl set resources deployment/llm-data-vault \
  --limits=cpu=2,memory=4Gi
```

### Cause 4: Bad Deployment

**Symptoms:**
- Errors started after recent deployment
- New error types appearing

**Fix:**
```bash
# Rollback to previous version
kubectl rollout undo deployment/llm-data-vault

# Verify rollback
kubectl rollout status deployment/llm-data-vault
```

## Escalation

- After 30 minutes: Escalate to senior engineer
- After 1 hour: Page engineering manager
- If security related: Page security team immediately

## Communication

- Update status page: https://status.company.com
- Post in #incidents Slack channel
- Email enterprise customers if SLA impacted

## Post-Incident

- Schedule postmortem within 5 days
- Update this runbook with lessons learned
```

#### Runbook: Database Connection Failure

```markdown
# Runbook: Database Connection Failure

## Trigger
- Alert: DatabaseHealthCheckFailed
- Application logs: "connection refused", "timeout"

## Initial Assessment (3 minutes)

1. **Check Database Status**
   ```bash
   # Check database pods
   kubectl get pods -n database -l app=postgresql

   # Check database logs
   kubectl logs -n database postgresql-0 --tail=100

   # Check database metrics
   psql -h db.example.com -U admin -c "SELECT 1;"
   ```

2. **Check Network Connectivity**
   ```bash
   # From application pod
   kubectl exec -it llm-data-vault-xxxx -- \
     nc -zv postgresql.database.svc.cluster.local 5432
   ```

## Common Causes and Fixes

### Cause 1: Database Pod Crashed

**Fix:**
```bash
# Check pod status
kubectl describe pod -n database postgresql-0

# If CrashLoopBackOff, check recent changes
kubectl logs -n database postgresql-0 --previous

# Restart pod
kubectl delete pod -n database postgresql-0
```

### Cause 2: Connection Pool Exhausted

**Fix:**
```bash
# Check active connections
psql -h db.example.com -U admin -c \
  "SELECT count(*) FROM pg_stat_activity;"

# Kill idle connections
psql -h db.example.com -U admin -c \
  "SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE state = 'idle'
   AND query_start < now() - interval '5 minutes';"
```

### Cause 3: Failover in Progress

**Fix:**
```bash
# Check replication status
psql -h db.example.com -U admin -c \
  "SELECT * FROM pg_stat_replication;"

# If manual failover needed
# 1. Promote replica
kubectl exec -n database postgresql-1 -- \
  pg_ctlcluster promote

# 2. Update application connection string
kubectl set env deployment/llm-data-vault \
  DB_HOST=postgresql-1.database.svc.cluster.local
```

## Temporary Mitigation

If database is unavailable, enable read-only mode:
```bash
kubectl set env deployment/llm-data-vault \
  READ_ONLY_MODE=true
```

This allows:
- ✓ Read operations from cache
- ✗ Write operations (return 503)
```

### 9.4 Post-Incident Review Template

```markdown
# Post-Incident Review: [Incident Title]

**Date:** 2025-01-01
**Duration:** 2 hours 15 minutes
**Severity:** P1
**Author:** [Name]
**Attendees:** [List]

---

## Executive Summary

Brief description of what happened and the impact.

---

## Impact

- **Users affected:** 1,250 (5% of active users)
- **Requests failed:** 45,000
- **Revenue impact:** $5,000 estimated
- **SLA breach:** Yes, consumed 15% of monthly error budget

---

## Timeline (all times UTC)

| Time | Event |
|------|-------|
| 14:32 | Deployment v1.2.3 started |
| 14:35 | First error alerts fire |
| 14:37 | On-call engineer paged |
| 14:40 | Incident declared (P1) |
| 14:45 | Root cause identified (bad config) |
| 14:50 | Rollback initiated |
| 14:55 | Service restored |
| 15:00 | Monitoring confirmed stability |
| 15:30 | Incident closed |

---

## Root Cause

The incident was caused by a configuration error in deployment v1.2.3
that set the database connection pool size to 0 instead of 50. This
caused all database operations to fail immediately.

---

## Detection

- Automated alert fired at 14:35 (3 minutes after deployment)
- Multiple user reports via support ticket system
- StatusPage updated at 14:42 (10 minutes after start)

---

## Response

**What went well:**
- Alert fired quickly after deployment
- Team responded within SLA (< 15 minutes)
- Clear rollback process was followed
- Communication was timely and clear

**What could be improved:**
- Pre-deployment validation missed the config error
- Rollback took longer than expected (15 minutes)
- Some customer notifications were delayed

---

## Action Items

| Action | Owner | Due Date | Priority |
|--------|-------|----------|----------|
| Add config validation to CI/CD | @alice | 2025-01-08 | P0 |
| Improve rollback automation | @bob | 2025-01-15 | P0 |
| Update deployment checklist | @charlie | 2025-01-10 | P1 |
| Add canary deployment stage | @alice | 2025-01-20 | P1 |
| Review alert thresholds | @bob | 2025-01-12 | P2 |

---

## Lessons Learned

1. **Validation matters:** Pre-deployment validation should catch config errors
2. **Canary deployments:** Gradual rollout would have limited impact
3. **Documentation works:** Following the runbook led to quick resolution
4. **Communication is key:** Regular updates kept stakeholders informed

---

## Supporting Data

- Grafana dashboard: [link]
- Incident ticket: INC-12345
- Deployment logs: [link]
- Error samples: [link]
```

---

## 10. Testing Strategy

### 10.1 Testing Pyramid

```
Testing Pyramid:
                    ┌────────────┐
                    │  Manual    │  <- 5%
                    │  Testing   │
                ┌───┴────────────┴───┐
                │   E2E Tests        │  <- 10%
                │  (Integration)     │
            ┌───┴────────────────────┴───┐
            │  Integration Tests         │  <- 25%
            │  (Contract, API)           │
        ┌───┴────────────────────────────┴───┐
        │     Unit Tests                     │  <- 60%
        │  (Fast, Isolated)                  │
        └────────────────────────────────────┘

Target Coverage:
- Unit tests: 90%+ code coverage
- Integration tests: All API endpoints
- E2E tests: Critical user journeys
- Manual tests: Edge cases, UX validation
```

### 10.2 Unit Testing

```go
// Example: Dataset service unit test
func TestCreateDataset(t *testing.T) {
    tests := []struct {
        name    string
        request *CreateDatasetRequest
        setup   func(*mocks.Repository, *mocks.KMSClient)
        want    *Dataset
        wantErr bool
    }{
        {
            name: "successful creation",
            request: &CreateDatasetRequest{
                Name:     "test-dataset",
                TenantID: "tenant-1",
                Schema:   schema,
            },
            setup: func(repo *mocks.Repository, kms *mocks.KMSClient) {
                kms.On("GenerateDataKey", mock.Anything, mock.Anything).
                    Return(&DataKey{ID: "key-1"}, nil)
                repo.On("Insert", mock.Anything, mock.Anything).
                    Return(&Dataset{ID: "ds-1"}, nil)
            },
            want: &Dataset{
                ID:       "ds-1",
                Name:     "test-dataset",
                TenantID: "tenant-1",
            },
            wantErr: false,
        },
        {
            name: "KMS failure",
            request: &CreateDatasetRequest{
                Name:     "test-dataset",
                TenantID: "tenant-1",
            },
            setup: func(repo *mocks.Repository, kms *mocks.KMSClient) {
                kms.On("GenerateDataKey", mock.Anything, mock.Anything).
                    Return(nil, errors.New("KMS unavailable"))
            },
            want:    nil,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup mocks
            repo := new(mocks.Repository)
            kms := new(mocks.KMSClient)
            tt.setup(repo, kms)

            // Create service
            svc := NewDatasetService(repo, kms)

            // Execute
            got, err := svc.CreateDataset(context.Background(), tt.request)

            // Assert
            if tt.wantErr {
                assert.Error(t, err)
                return
            }

            assert.NoError(t, err)
            assert.Equal(t, tt.want.ID, got.ID)
            assert.Equal(t, tt.want.Name, got.Name)

            // Verify mock expectations
            repo.AssertExpectations(t)
            kms.AssertExpectations(t)
        })
    }
}
```

#### Property-Based Testing

```go
// Example: Property-based testing for encryption
func TestEncryptionProperties(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        // Generate random plaintext
        plaintext := rapid.SliceOfN(rapid.Byte(), 1, 1024).Draw(t, "plaintext")

        // Create encryptor
        key := make([]byte, 32)
        rand.Read(key)
        enc := NewEncryptor(key)

        // Property 1: Encrypt then decrypt returns original
        ciphertext, err := enc.Encrypt(plaintext)
        require.NoError(t, err)

        decrypted, err := enc.Decrypt(ciphertext)
        require.NoError(t, err)
        assert.Equal(t, plaintext, decrypted)

        // Property 2: Same plaintext produces different ciphertext (IV)
        ciphertext2, err := enc.Encrypt(plaintext)
        require.NoError(t, err)
        assert.NotEqual(t, ciphertext, ciphertext2)

        // Property 3: Ciphertext is longer than plaintext (IV + padding)
        assert.Greater(t, len(ciphertext), len(plaintext))
    })
}
```

### 10.3 Integration Testing

```go
// Example: Integration test with test containers
func TestDatasetAPI_Integration(t *testing.T) {
    // Start dependencies with testcontainers
    ctx := context.Background()

    // PostgreSQL
    postgresContainer, err := postgres.RunContainer(ctx,
        testcontainers.WithImage("postgres:15"),
        postgres.WithDatabase("testdb"),
        postgres.WithUsername("test"),
        postgres.WithPassword("test"),
    )
    require.NoError(t, err)
    defer postgresContainer.Terminate(ctx)

    // Redis
    redisContainer, err := redis.RunContainer(ctx,
        testcontainers.WithImage("redis:7"),
    )
    require.NoError(t, err)
    defer redisContainer.Terminate(ctx)

    // Get connection strings
    dbURL, _ := postgresContainer.ConnectionString(ctx)
    redisURL, _ := redisContainer.ConnectionString(ctx)

    // Setup application
    app := setupTestApp(t, dbURL, redisURL)
    defer app.Shutdown(ctx)

    // Test: Create dataset
    req := httptest.NewRequest("POST", "/api/v1/datasets", strings.NewReader(`{
        "name": "test-dataset",
        "schema": {...}
    }`))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+testToken)

    resp := httptest.NewRecorder()
    app.ServeHTTP(resp, req)

    assert.Equal(t, http.StatusCreated, resp.Code)

    var dataset Dataset
    json.Unmarshal(resp.Body.Bytes(), &dataset)
    assert.NotEmpty(t, dataset.ID)

    // Test: Read dataset
    req = httptest.NewRequest("GET", "/api/v1/datasets/"+dataset.ID, nil)
    req.Header.Set("Authorization", "Bearer "+testToken)

    resp = httptest.NewRecorder()
    app.ServeHTTP(resp, req)

    assert.Equal(t, http.StatusOK, resp.Code)
}
```

#### Contract Testing

```go
// Example: Consumer contract test (Pact)
func TestDatasetAPIContract(t *testing.T) {
    pact := &dsl.Pact{
        Consumer: "mobile-app",
        Provider: "llm-data-vault",
    }
    defer pact.Teardown()

    // Define interaction
    pact.
        AddInteraction().
        Given("dataset ds-123 exists").
        UponReceiving("a request to get dataset").
        WithRequest(dsl.Request{
            Method: "GET",
            Path:   dsl.String("/api/v1/datasets/ds-123"),
            Headers: dsl.MapMatcher{
                "Authorization": dsl.String("Bearer token"),
            },
        }).
        WillRespondWith(dsl.Response{
            Status: 200,
            Headers: dsl.MapMatcher{
                "Content-Type": dsl.String("application/json"),
            },
            Body: dsl.Match(Dataset{
                ID:        "ds-123",
                Name:      "customer-data",
                CreatedAt: "2025-01-01T00:00:00Z",
            }),
        })

    // Verify interaction
    test := func() error {
        client := NewClient(fmt.Sprintf("http://localhost:%d", pact.Server.Port))
        dataset, err := client.GetDataset("ds-123")
        if err != nil {
            return err
        }
        assert.Equal(t, "ds-123", dataset.ID)
        return nil
    }

    err := pact.Verify(test)
    assert.NoError(t, err)
}
```

### 10.4 Performance Testing

```javascript
// Example: Load test with k6
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
    stages: [
        { duration: '2m', target: 100 },   // Ramp up to 100 users
        { duration: '5m', target: 100 },   // Stay at 100 users
        { duration: '2m', target: 200 },   // Ramp up to 200 users
        { duration: '5m', target: 200 },   // Stay at 200 users
        { duration: '2m', target: 0 },     // Ramp down
    ],
    thresholds: {
        'http_req_duration': ['p(95)<200', 'p(99)<500'],
        'http_req_failed': ['rate<0.01'],
        'errors': ['rate<0.01'],
    },
};

export default function() {
    // Create dataset
    let createResp = http.post(
        'https://api.llm-data-vault.com/api/v1/datasets',
        JSON.stringify({
            name: `dataset-${__VU}-${__ITER}`,
            schema: {...},
        }),
        {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${__ENV.API_TOKEN}`,
            },
        }
    );

    let success = check(createResp, {
        'status is 201': (r) => r.status === 201,
        'response time < 500ms': (r) => r.timings.duration < 500,
    });

    errorRate.add(!success);

    if (!success) {
        console.error(`Failed: ${createResp.status} ${createResp.body}`);
        return;
    }

    let dataset = JSON.parse(createResp.body);

    // Read dataset
    let getResp = http.get(
        `https://api.llm-data-vault.com/api/v1/datasets/${dataset.id}`,
        {
            headers: {
                'Authorization': `Bearer ${__ENV.API_TOKEN}`,
            },
        }
    );

    check(getResp, {
        'status is 200': (r) => r.status === 200,
        'response time < 100ms': (r) => r.timings.duration < 100,
    });

    sleep(1);
}
```

### 10.5 Chaos Testing

```yaml
# Example: Automated chaos test in CI/CD
apiVersion: v1
kind: ConfigMap
metadata:
  name: chaos-test-suite
data:
  test.sh: |
    #!/bin/bash
    set -e

    echo "Starting chaos test suite..."

    # Test 1: Pod deletion
    echo "Test 1: Random pod deletion"
    kubectl apply -f chaos/pod-delete.yaml
    sleep 60

    # Verify service availability
    curl -f https://api.llm-data-vault.com/health || exit 1

    # Check error rate
    ERROR_RATE=$(curl -s http://prometheus:9090/api/v1/query \
      --data-urlencode 'query=rate(vault_requests_total{status=~"5.."}[5m])' | \
      jq -r '.data.result[0].value[1]')

    if (( $(echo "$ERROR_RATE > 0.01" | bc -l) )); then
        echo "ERROR: Error rate too high: $ERROR_RATE"
        exit 1
    fi

    # Test 2: Network latency
    echo "Test 2: Network latency injection"
    kubectl apply -f chaos/network-latency.yaml
    sleep 120

    # Verify circuit breakers
    CB_STATE=$(curl -s http://prometheus:9090/api/v1/query \
      --data-urlencode 'query=vault_circuit_breaker_state{state="open"}' | \
      jq -r '.data.result | length')

    if [ "$CB_STATE" -gt 0 ]; then
        echo "WARNING: Circuit breakers opened (expected for latency test)"
    fi

    echo "All chaos tests passed!"
```

---

## 11. SLI/SLO Definition

### 11.1 Service Level Indicators (SLIs)

```
SLI Measurement Framework:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  Availability SLI                                       │
│  ────────────────────────────────────────               │
│  Definition: Percentage of successful requests          │
│  Formula:                                               │
│      successful_requests                                │
│      ──────────────────── × 100                        │
│      total_requests                                     │
│                                                         │
│  Measurement:                                           │
│      sum(vault_requests_total{status!~"5.."})          │
│      ───────────────────────────────────────           │
│      sum(vault_requests_total)                         │
│                                                         │
│  Target: 99.9%                                          │
│  ────────────────────────────────────────               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### SLI Definitions Table

| SLI | Measurement | Target | Query |
|-----|-------------|--------|-------|
| **Availability** | Successful requests / Total requests | 99.9% | `sum(rate(vault_requests_total{status!~"5.."}[30d])) / sum(rate(vault_requests_total[30d]))` |
| **Latency (p50)** | 50th percentile response time | < 50ms | `histogram_quantile(0.50, rate(vault_request_duration_seconds_bucket[5m]))` |
| **Latency (p95)** | 95th percentile response time | < 100ms | `histogram_quantile(0.95, rate(vault_request_duration_seconds_bucket[5m]))` |
| **Latency (p99)** | 99th percentile response time | < 200ms | `histogram_quantile(0.99, rate(vault_request_duration_seconds_bucket[5m]))` |
| **Error Rate** | 5xx responses / Total responses | < 0.1% | `sum(rate(vault_requests_total{status=~"5.."}[5m])) / sum(rate(vault_requests_total[5m]))` |
| **Throughput** | Requests processed per second | 10,000 | `sum(rate(vault_requests_total[5m]))` |
| **Data Durability** | Data not lost / Total data | 99.999999999% | Measured via storage backend SLA |

### 11.2 Service Level Objectives (SLOs)

```
SLO Compliance Window: 30 days rolling
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  Availability SLO: 99.9% over 30 days                  │
│  ────────────────────────────────────────               │
│  Error budget:     0.1% = 43.8 minutes/month           │
│  Current status:   99.94% (25.9 min downtime)          │
│  Budget remaining: 17.9 minutes (40.9%)                │
│                                                         │
│  Progress: [████████████████░░░░] 59.1% consumed       │
│                                                         │
│  Burn rate: 0.8x (on track)                            │
│  └─> If burn rate > 1.0x, budget will be exhausted     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### SLO Compliance Matrix

| SLO | Period | Target | Current | Status | Budget Remaining |
|-----|--------|--------|---------|--------|------------------|
| Availability | 30d | 99.9% | 99.94% | ✓ | 40.9% |
| Latency (p99) | 30d | < 200ms | 145ms | ✓ | N/A |
| Error Rate | 30d | < 0.1% | 0.06% | ✓ | 40% |
| Throughput | 5m | 10,000 req/s | 8,500 req/s | ✓ | N/A |

### 11.3 Error Budget Policy

```yaml
error_budget_policy:
  # When error budget is healthy
  budget_remaining_75_100:
    velocity: normal
    deployment_frequency: continuous
    change_approval: automated
    testing_requirements: standard

  # When error budget is being consumed
  budget_remaining_50_75:
    velocity: cautious
    deployment_frequency: daily
    change_approval: peer_review
    testing_requirements: enhanced
    actions:
      - Increase monitoring
      - Review recent changes
      - Hold architecture review

  # When error budget is low
  budget_remaining_25_50:
    velocity: slow
    deployment_frequency: weekly
    change_approval: senior_engineer
    testing_requirements: comprehensive
    actions:
      - Freeze non-critical features
      - Focus on reliability improvements
      - Increase chaos testing
      - Review and update runbooks

  # When error budget is exhausted
  budget_remaining_0_25:
    velocity: emergency_only
    deployment_frequency: freeze
    change_approval: engineering_manager
    testing_requirements: exhaustive
    actions:
      - Complete deployment freeze
      - All hands on reliability
      - Daily incident reviews
      - Executive escalation
      - Customer communication plan
```

### 11.4 Burn Rate Alerting

```yaml
# Multi-window burn rate alerts
groups:
  - name: slo_burn_rate
    interval: 30s
    rules:
      # Fast burn (budget exhausted in < 1 hour)
      - alert: ErrorBudgetFastBurn
        expr: |
          (
            1 - (
              sum(rate(vault_requests_total{status!~"5.."}[5m]))
              /
              sum(rate(vault_requests_total[5m]))
            )
          ) > (1 - 0.999) * 720  # 720x burn rate
        for: 2m
        labels:
          severity: critical
          slo: availability
        annotations:
          summary: "Error budget burning extremely fast"
          description: |
            At current rate, monthly error budget will be exhausted in < 1 hour.
            Immediate action required.

      # Medium burn (budget exhausted in < 6 hours)
      - alert: ErrorBudgetMediumBurn
        expr: |
          (
            1 - (
              sum(rate(vault_requests_total{status!~"5.."}[30m]))
              /
              sum(rate(vault_requests_total[30m]))
            )
          ) > (1 - 0.999) * 120  # 120x burn rate
        for: 15m
        labels:
          severity: warning
          slo: availability
        annotations:
          summary: "Error budget burning fast"
          description: |
            At current rate, monthly error budget will be exhausted in < 6 hours.

      # Slow burn (budget exhausted in < 3 days)
      - alert: ErrorBudgetSlowBurn
        expr: |
          (
            1 - (
              sum(rate(vault_requests_total{status!~"5.."}[6h]))
              /
              sum(rate(vault_requests_total[6h]))
            )
          ) > (1 - 0.999) * 10  # 10x burn rate
        for: 1h
        labels:
          severity: warning
          slo: availability
        annotations:
          summary: "Error budget burning steadily"
          description: |
            At current rate, monthly error budget will be exhausted in < 3 days.
            Review recent changes and consider slowing deployment velocity.
```

### 11.5 SLO Reporting Dashboard

```
Grafana Dashboard: SLO Overview
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  ┌────────────────────────────────────────────────┐    │
│  │ Availability                                    │    │
│  │ Current: 99.94%  Target: 99.9%  ✓              │    │
│  │ [████████████████████████░░░░]                 │    │
│  └────────────────────────────────────────────────┘    │
│                                                         │
│  ┌────────────────────────────────────────────────┐    │
│  │ Latency (p99)                                   │    │
│  │ Current: 145ms   Target: <200ms  ✓             │    │
│  │ [██████████████████░░░░░░░░░░░]                │    │
│  └────────────────────────────────────────────────┘    │
│                                                         │
│  ┌────────────────────────────────────────────────┐    │
│  │ Error Rate                                      │    │
│  │ Current: 0.06%   Target: <0.1%   ✓             │    │
│  │ [████████████░░░░░░░░░░░░░░░░░░]               │    │
│  └────────────────────────────────────────────────┘    │
│                                                         │
│  ┌────────────────────────────────────────────────┐    │
│  │ Error Budget Remaining                          │    │
│  │ 40.9% (17.9 minutes)                            │    │
│  │                                                 │    │
│  │     [████████████████░░░░░░░░░] 59.1% used     │    │
│  │                                                 │    │
│  │ Burn rate: 0.8x (On track)                     │    │
│  └────────────────────────────────────────────────┘    │
│                                                         │
│  ┌────────────────────────────────────────────────┐    │
│  │ 30-Day Availability Trend                       │    │
│  │                                                 │    │
│  │ 100% ┤                      ╭─────────────     │    │
│  │ 99.9%┤────────╮╭────────────╯                  │    │
│  │ 99.8%┤        ╰╯                               │    │
│  │      └───────────────────────────────────────> │    │
│  │      Day 1                           Day 30    │    │
│  └────────────────────────────────────────────────┘    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 12. Summary

### 12.1 Reliability Checklist

```
Production Readiness Checklist:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│ Error Handling                                          │
│   [✓] Error taxonomy implemented                        │
│   [✓] Consistent error response format                  │
│   [✓] Panic recovery in all handlers                    │
│   [✓] Graceful degradation strategies                   │
│                                                         │
│ Resilience Patterns                                     │
│   [✓] Circuit breakers configured                       │
│   [✓] Retry policies with backoff                       │
│   [✓] Bulkheads for resource isolation                  │
│   [✓] Timeouts for all operations                       │
│                                                         │
│ Health Checking                                         │
│   [✓] Liveness probe implemented                        │
│   [✓] Readiness probe with dependencies                 │
│   [✓] Startup probe for slow starts                     │
│   [✓] Pod disruption budget configured                  │
│                                                         │
│ Observability                                           │
│   [✓] Prometheus metrics exported                       │
│   [✓] Distributed tracing configured                    │
│   [✓] Structured logging implemented                    │
│   [✓] Alerting rules defined                            │
│                                                         │
│ Testing                                                 │
│   [✓] 90%+ unit test coverage                           │
│   [✓] Integration tests with testcontainers            │
│   [✓] Performance tests (load, stress)                  │
│   [✓] Chaos tests automated                             │
│                                                         │
│ Operations                                              │
│   [✓] Runbooks for common failures                      │
│   [✓] SLIs/SLOs defined and monitored                   │
│   [✓] Error budget tracking                             │
│   [✓] Incident response process                         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 12.2 Key Metrics to Monitor

```
Golden Signals:
1. Latency:     How long does it take to serve requests?
2. Traffic:     How much demand is placed on the system?
3. Errors:      What is the rate of failing requests?
4. Saturation:  How full is the system?

RED Metrics (for user-facing services):
1. Rate:        Requests per second
2. Errors:      Error rate
3. Duration:    Request duration

USE Metrics (for resources):
1. Utilization: % time resource is busy
2. Saturation:  Amount of queued work
3. Errors:      Error count
```

### 12.3 Next Steps

1. **Implement** error taxonomy and response format
2. **Deploy** circuit breakers for critical dependencies
3. **Configure** health checks and probes
4. **Setup** observability stack (Prometheus, Grafana, Jaeger)
5. **Write** runbooks for common failure scenarios
6. **Define** SLIs/SLOs and error budgets
7. **Automate** chaos engineering tests
8. **Establish** incident response procedures
9. **Schedule** regular game days
10. **Monitor** and iterate on reliability improvements

---

## Appendices

### Appendix A: Error Code Reference

See `/docs/error-codes.md` for complete error code catalog.

### Appendix B: Runbook Index

| Scenario | Runbook | Owner |
|----------|---------|-------|
| High error rate | `/runbooks/high-error-rate.md` | Platform |
| Database failure | `/runbooks/database-failure.md` | Platform |
| KMS unavailable | `/runbooks/kms-unavailable.md` | Security |
| Storage failure | `/runbooks/storage-failure.md` | Platform |
| Memory leak | `/runbooks/memory-leak.md` | Platform |

### Appendix C: Grafana Dashboards

- SLO Overview: `/dashboards/slo-overview.json`
- Service Health: `/dashboards/service-health.json`
- Error Analysis: `/dashboards/error-analysis.json`
- Performance: `/dashboards/performance.json`

### Appendix D: Alert Contact Matrix

| Severity | Contact | Method | Response Time |
|----------|---------|--------|---------------|
| P1 | On-call engineer | PagerDuty | 15 min |
| P1 | Engineering manager | PagerDuty + Phone | 30 min |
| P2 | On-call engineer | PagerDuty | 1 hour |
| P3 | Team lead | Slack | 4 hours |
| P4 | Assigned engineer | Jira | 24 hours |

---

**Document Status:** This document should be reviewed quarterly and updated based on operational learnings and evolving requirements.

**Related Documents:**
- [06-security-architecture.md](/workspaces/llm-data-vault/plans/architecture/06-security-architecture.md)
- [05-scalability-architecture.md](/workspaces/llm-data-vault/plans/architecture/05-scalability-architecture.md)
- [04-data-architecture.md](/workspaces/llm-data-vault/plans/architecture/04-data-architecture.md)
