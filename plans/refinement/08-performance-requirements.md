# Performance Requirements

## Document Control

| Version | Date       | Author | Changes                    |
|---------|------------|--------|----------------------------|
| 0.1     | 2025-11-27 | Team   | Initial draft              |

## 1. Performance Targets

### 1.1 Latency Requirements

All latency measurements are for single-node operations under normal load conditions (70% capacity).

| Operation | p50 | p95 | p99 | p99.9 | Notes |
|-----------|-----|-----|-----|-------|-------|
| GET /datasets/{id} | 10ms | 30ms | 50ms | 100ms | Cached metadata |
| POST /datasets | 20ms | 50ms | 100ms | 200ms | Excludes data upload |
| PUT /datasets/{id} | 25ms | 60ms | 120ms | 250ms | Metadata update only |
| DELETE /datasets/{id} | 30ms | 70ms | 150ms | 300ms | Soft delete |
| GET /records (batch) | 50ms | 100ms | 200ms | 500ms | Up to 1000 records |
| POST /records | 15ms | 40ms | 80ms | 150ms | Single record |
| POST /anonymize | 30ms | 80ms | 150ms | 300ms | Per record |
| POST /encrypt | 25ms | 60ms | 120ms | 250ms | 100KB payload |
| POST /decrypt | 20ms | 50ms | 100ms | 200ms | 100KB payload |
| GET /search | 100ms | 250ms | 500ms | 1000ms | Full-text search |
| POST /validate | 15ms | 35ms | 70ms | 140ms | Schema validation |
| GET /audit/logs | 80ms | 200ms | 400ms | 800ms | Paginated query |

### 1.2 Operation-Specific Latency (Internal)

| Internal Operation | p50 | p95 | p99 | Target |
|-------------------|-----|-----|-----|--------|
| Encryption (1KB) | 1ms | 3ms | 5ms | <10ms |
| Encryption (100KB) | 5ms | 10ms | 20ms | <50ms |
| Encryption (1MB) | 40ms | 80ms | 150ms | <200ms |
| Encryption (10MB) | 400ms | 800ms | 1500ms | <2000ms |
| PII detection (1KB) | 10ms | 25ms | 50ms | <100ms |
| PII detection (10KB) | 50ms | 120ms | 250ms | <500ms |
| PII detection (100KB) | 200ms | 500ms | 1000ms | <2000ms |
| Hash computation (1MB) | 2ms | 5ms | 10ms | <20ms |
| Serialization (1MB) | 3ms | 8ms | 15ms | <30ms |
| Deserialization (1MB) | 4ms | 10ms | 20ms | <40ms |
| Database query (simple) | 2ms | 5ms | 10ms | <20ms |
| Database query (complex) | 15ms | 40ms | 80ms | <150ms |
| Cache lookup | 0.5ms | 1ms | 2ms | <5ms |
| S3 PUT (1MB) | 100ms | 250ms | 500ms | <1000ms |
| S3 GET (1MB) | 50ms | 120ms | 250ms | <500ms |

### 1.3 Throughput Requirements

| Component | Target | Maximum | Conditions |
|-----------|--------|---------|------------|
| API (read) | 10,000 req/s | 15,000 req/s | Per node, mixed endpoints |
| API (write) | 2,000 req/s | 3,000 req/s | Per node, mixed endpoints |
| API (metadata) | 20,000 req/s | 30,000 req/s | Per node, GET only |
| Storage (read) | 1 GB/s | 1.5 GB/s | Aggregate across cluster |
| Storage (write) | 500 MB/s | 750 MB/s | Aggregate across cluster |
| Anonymization | 10,000 records/s | 15,000 records/s | Per worker pod |
| Encryption | 100 MB/s | 150 MB/s | Per worker pod |
| PII detection | 5,000 records/s | 8,000 records/s | Per worker pod |
| Validation | 20,000 records/s | 30,000 records/s | Per worker pod |
| Audit logging | 50,000 events/s | 75,000 events/s | Aggregate |

### 1.4 Resource Limits

| Component | CPU | Memory | Disk I/O | Network | Connections |
|-----------|-----|--------|----------|---------|-------------|
| API pod (min) | 1 core | 1 GB | - | - | 500 |
| API pod (max) | 2 cores | 2 GB | - | 1 Gbps | 1000 |
| Worker pod (min) | 2 cores | 2 GB | 100 MB/s | - | 50 |
| Worker pod (max) | 4 cores | 4 GB | 500 MB/s | 1 Gbps | 100 |
| Database (min) | 4 cores | 16 GB | 1 GB/s | 1 Gbps | 200 |
| Database (max) | 8 cores | 32 GB | 2 GB/s | 10 Gbps | 500 |
| Redis cache | 2 cores | 8 GB | - | 1 Gbps | 10,000 |
| Message queue | 2 cores | 4 GB | 200 MB/s | 1 Gbps | 1,000 |

### 1.5 Scalability Requirements

| Metric | Minimum | Target | Maximum |
|--------|---------|--------|---------|
| Concurrent users | 1,000 | 10,000 | 100,000 |
| Datasets | 100 | 10,000 | 1,000,000 |
| Records per dataset | 1,000 | 1,000,000 | 100,000,000 |
| Total storage | 100 GB | 10 TB | 1 PB |
| Audit log retention | 30 days | 365 days | 3 years |
| API nodes | 2 | 10 | 100 |
| Worker nodes | 2 | 20 | 200 |

### 1.6 Availability and Reliability

| SLA Metric | Target | Measurement Period |
|------------|--------|-------------------|
| Uptime | 99.9% | Monthly |
| API availability | 99.95% | Monthly |
| Data durability | 99.999999999% | Annually |
| RTO (Recovery Time) | 15 minutes | Per incident |
| RPO (Recovery Point) | 5 minutes | Per incident |
| Mean Time to Recovery | 30 minutes | Per incident |
| Error rate | <0.1% | Per hour |

## 2. Benchmark Suite

### 2.1 Criterion Benchmarks (Rust)

```rust
// benches/crypto_benchmarks.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use llm_data_vault::crypto::{EncryptionService, KeyManager};

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");
    let key_manager = KeyManager::new().unwrap();
    let encryption_service = EncryptionService::new(key_manager);

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                let data = vec![0u8; size];
                b.iter(|| {
                    encryption_service.encrypt(black_box(&data)).unwrap()
                });
            },
        );
    }
    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("decryption");
    let key_manager = KeyManager::new().unwrap();
    let encryption_service = EncryptionService::new(key_manager);

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        let data = vec![0u8; *size];
        let encrypted = encryption_service.encrypt(&data).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &encrypted,
            |b, encrypted| {
                b.iter(|| {
                    encryption_service.decrypt(black_box(encrypted)).unwrap()
                });
            },
        );
    }
    group.finish();
}

// benches/pii_benchmarks.rs
use llm_data_vault::pii::{PIIDetector, PIIDetectorConfig};

fn bench_pii_detection_regex(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii_detection_regex");
    let detector = PIIDetector::new(PIIDetectorConfig::default());

    let test_cases = vec![
        ("small", "John Doe, SSN: 123-45-6789, Email: john@example.com"),
        ("medium", include_str!("../test_data/medium_text.txt")),
        ("large", include_str!("../test_data/large_text.txt")),
    ];

    for (name, text) in test_cases {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &text,
            |b, text| {
                b.iter(|| {
                    detector.detect_regex(black_box(text))
                });
            },
        );
    }
    group.finish();
}

fn bench_pii_detection_ner(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii_detection_ner");
    let detector = PIIDetector::with_ner_model().unwrap();

    for (name, text) in [
        ("small", "John Doe lives in San Francisco."),
        ("medium", include_str!("../test_data/medium_text.txt")),
    ] {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &text,
            |b, text| {
                b.iter(|| {
                    detector.detect_ner(black_box(text))
                });
            },
        );
    }
    group.finish();
}

// benches/storage_benchmarks.rs
use llm_data_vault::storage::{StorageBackend, S3Backend};

fn bench_storage_put(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_put");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let storage = runtime.block_on(async {
        S3Backend::new("test-bucket").await.unwrap()
    });

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &data,
            |b, data| {
                b.to_async(&runtime).iter(|| async {
                    storage.put(black_box("test-key"), black_box(data)).await.unwrap()
                });
            },
        );
    }
    group.finish();
}

fn bench_storage_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_get");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let storage = runtime.block_on(async {
        let s3 = S3Backend::new("test-bucket").await.unwrap();
        // Prepopulate test data
        for size in [1024, 10_240, 102_400, 1_048_576].iter() {
            let data = vec![0u8; *size];
            s3.put(&format!("bench-{}", size), &data).await.unwrap();
        }
        s3
    });

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, size| {
                b.to_async(&runtime).iter(|| async {
                    storage.get(black_box(&format!("bench-{}", size))).await.unwrap()
                });
            },
        );
    }
    group.finish();
}

// benches/serialization_benchmarks.rs
use llm_data_vault::models::Dataset;

fn bench_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_serialization");
    let dataset = Dataset::example_large(); // Contains 10k records

    group.bench_function("serialize", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&dataset)).unwrap()
        });
    });

    let json = serde_json::to_string(&dataset).unwrap();
    group.throughput(Throughput::Bytes(json.len() as u64));
    group.bench_function("deserialize", |b| {
        b.iter(|| {
            serde_json::from_str::<Dataset>(black_box(&json)).unwrap()
        });
    });

    group.finish();
}

fn bench_bincode_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("bincode_serialization");
    let dataset = Dataset::example_large();

    group.bench_function("serialize", |b| {
        b.iter(|| {
            bincode::serialize(black_box(&dataset)).unwrap()
        });
    });

    let bytes = bincode::serialize(&dataset).unwrap();
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("deserialize", |b| {
        b.iter(|| {
            bincode::deserialize::<Dataset>(black_box(&bytes)).unwrap()
        });
    });

    group.finish();
}

// benches/hashing_benchmarks.rs
use llm_data_vault::integrity::HashService;

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    let hash_service = HashService::new();

    for size in [1024, 10_240, 102_400, 1_048_576, 10_485_760].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &data,
            |b, data| {
                b.iter(|| {
                    hash_service.hash(black_box(data))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_encryption,
    bench_decryption,
    bench_pii_detection_regex,
    bench_pii_detection_ner,
    bench_storage_put,
    bench_storage_get,
    bench_json_serialization,
    bench_bincode_serialization,
    bench_hashing,
);
criterion_main!(benches);
```

### 2.2 Load Test Scenarios (k6)

```javascript
// tests/load/baseline.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');
const API_BASE = __ENV.API_BASE || 'http://localhost:8080';

export const options = {
    stages: [
        { duration: '2m', target: 50 },   // Ramp up
        { duration: '10m', target: 100 }, // Stay at baseline
        { duration: '2m', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<100', 'p(99)<200'],
        http_req_failed: ['rate<0.01'],
        errors: ['rate<0.01'],
    },
};

export default function() {
    // Create dataset
    let createRes = http.post(`${API_BASE}/api/v1/datasets`, JSON.stringify({
        name: `test-dataset-${__VU}-${__ITER}`,
        description: 'Load test dataset',
        schema: {
            type: 'object',
            properties: {
                name: { type: 'string' },
                email: { type: 'string' },
            },
        },
    }), {
        headers: { 'Content-Type': 'application/json' },
    });

    check(createRes, {
        'dataset created': (r) => r.status === 201,
    }) || errorRate.add(1);

    const datasetId = createRes.json('id');

    // Get dataset
    let getRes = http.get(`${API_BASE}/api/v1/datasets/${datasetId}`);
    check(getRes, {
        'dataset retrieved': (r) => r.status === 200,
    }) || errorRate.add(1);

    // Add records
    let recordRes = http.post(`${API_BASE}/api/v1/datasets/${datasetId}/records`, JSON.stringify({
        data: {
            name: 'John Doe',
            email: 'john@example.com',
        },
    }), {
        headers: { 'Content-Type': 'application/json' },
    });

    check(recordRes, {
        'record added': (r) => r.status === 201,
    }) || errorRate.add(1);

    sleep(1);
}

// tests/load/normal.js
export const options = {
    stages: [
        { duration: '5m', target: 500 },   // Ramp up
        { duration: '30m', target: 1000 }, // Normal load
        { duration: '5m', target: 0 },     // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<150', 'p(99)<300'],
        http_req_failed: ['rate<0.01'],
    },
};

// tests/load/peak.js
export const options = {
    stages: [
        { duration: '2m', target: 2000 },  // Fast ramp up
        { duration: '10m', target: 5000 }, // Peak load
        { duration: '2m', target: 0 },     // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<300', 'p(99)<500'],
        http_req_failed: ['rate<0.05'],
    },
};

// tests/load/stress.js
export const options = {
    stages: [
        { duration: '5m', target: 5000 },   // Ramp to expected max
        { duration: '5m', target: 10000 },  // Push to limits
        { duration: '5m', target: 15000 },  // Keep increasing
        { duration: '5m', target: 20000 },  // Until failure
    ],
    thresholds: {
        http_req_duration: ['p(95)<1000'],
    },
};

// tests/load/soak.js
export const options = {
    stages: [
        { duration: '5m', target: 500 },   // Ramp up
        { duration: '24h', target: 500 },  // Sustained load
        { duration: '5m', target: 0 },     // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<150', 'p(99)<300'],
        http_req_failed: ['rate<0.01'],
    },
};

// tests/load/scenarios/mixed_workload.js
export const options = {
    scenarios: {
        read_heavy: {
            executor: 'constant-vus',
            vus: 100,
            duration: '10m',
            exec: 'readWorkload',
        },
        write_heavy: {
            executor: 'constant-vus',
            vus: 20,
            duration: '10m',
            exec: 'writeWorkload',
        },
        anonymization: {
            executor: 'constant-arrival-rate',
            rate: 50,
            timeUnit: '1s',
            duration: '10m',
            preAllocatedVUs: 10,
            exec: 'anonymizeWorkload',
        },
    },
};

export function readWorkload() {
    const datasetId = 'test-dataset-1';
    http.get(`${API_BASE}/api/v1/datasets/${datasetId}`);
    http.get(`${API_BASE}/api/v1/datasets/${datasetId}/records?limit=100`);
    sleep(0.5);
}

export function writeWorkload() {
    // Create and update operations
    let res = http.post(`${API_BASE}/api/v1/datasets`, JSON.stringify({
        name: `dataset-${Date.now()}`,
    }), { headers: { 'Content-Type': 'application/json' } });

    const id = res.json('id');
    http.post(`${API_BASE}/api/v1/datasets/${id}/records`, JSON.stringify({
        data: { field: 'value' },
    }), { headers: { 'Content-Type': 'application/json' } });

    sleep(1);
}

export function anonymizeWorkload() {
    http.post(`${API_BASE}/api/v1/anonymize`, JSON.stringify({
        data: {
            name: 'John Doe',
            ssn: '123-45-6789',
            email: 'john@example.com',
        },
    }), { headers: { 'Content-Type': 'application/json' } });

    sleep(0.1);
}
```

## 3. Optimization Guidelines

### 3.1 Database Optimization

#### Connection Pooling
```rust
// Database pool configuration
DatabaseConfig {
    min_connections: 10,
    max_connections: 100,
    connection_timeout: Duration::from_secs(30),
    idle_timeout: Some(Duration::from_secs(600)),
    max_lifetime: Some(Duration::from_secs(1800)),
}
```

**Guidelines:**
- Min connections: 10-20% of max
- Max connections: Based on `(core_count * 2) + effective_spindle_count`
- Monitor connection pool exhaustion
- Use prepared statements for repeated queries
- Implement connection retry with exponential backoff

#### Query Optimization Patterns
- Use indexes on foreign keys and frequently queried columns
- Avoid SELECT *; specify only needed columns
- Use EXPLAIN ANALYZE for slow queries (>50ms)
- Implement pagination with cursor-based approach for large result sets
- Batch INSERT/UPDATE operations when possible
- Use database-level constraints instead of application validation

#### Index Usage Monitoring
```sql
-- Monitor index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
WHERE idx_scan < 50
ORDER BY idx_scan ASC;

-- Find missing indexes
SELECT schemaname, tablename, seq_scan, seq_tup_read,
       idx_scan, seq_tup_read / seq_scan AS avg
FROM pg_stat_user_tables
WHERE seq_scan > 0
ORDER BY seq_tup_read DESC
LIMIT 20;
```

#### Vacuum Scheduling
- Auto-vacuum enabled with aggressive settings
- Manual VACUUM ANALYZE weekly during low-traffic windows
- Monitor table bloat and dead tuples
- VACUUM FULL quarterly for large tables

### 3.2 Caching Strategy

#### Cache Hit Ratio Target
- Overall cache hit ratio: 90%+
- Metadata cache: 95%+
- Query result cache: 85%+
- Static content: 99%+

#### TTL Tuning
```rust
CacheConfig {
    metadata_ttl: Duration::from_secs(300),      // 5 minutes
    query_result_ttl: Duration::from_secs(60),   // 1 minute
    user_session_ttl: Duration::from_secs(3600), // 1 hour
    static_content_ttl: Duration::from_secs(86400), // 24 hours
}
```

#### Cache Warming
- Pre-populate frequently accessed datasets on startup
- Warm cache after deployment using background jobs
- Implement cache-aside pattern for most queries
- Use write-through for critical metadata

#### Eviction Policies
- LRU (Least Recently Used) for query results
- LFU (Least Frequently Used) for metadata
- TTL-based expiration for time-sensitive data
- Manual invalidation for updates

### 3.3 Memory Management

#### Buffer Sizing
```rust
const READ_BUFFER_SIZE: usize = 8 * 1024;        // 8KB
const WRITE_BUFFER_SIZE: usize = 64 * 1024;      // 64KB
const NETWORK_BUFFER_SIZE: usize = 32 * 1024;    // 32KB
const CRYPTO_BUFFER_SIZE: usize = 1024 * 1024;   // 1MB
```

#### Arena Allocators
- Use `bumpalo` for temporary allocations in hot paths
- Pool allocations for fixed-size objects
- Consider `mimalloc` or `jemalloc` as global allocator

```rust
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
```

#### Memory Pooling
- Object pools for frequently allocated types
- Reuse buffers for encryption/decryption
- Implement drop guards for automatic cleanup

### 3.4 Async Runtime Optimization

#### Tokio Tuning
```rust
tokio::runtime::Builder::new_multi_thread()
    .worker_threads(num_cpus::get())
    .thread_name("llm-vault-worker")
    .thread_stack_size(3 * 1024 * 1024)
    .event_interval(61)
    .global_queue_interval(31)
    .max_blocking_threads(512)
    .build()
    .unwrap()
```

#### Worker Thread Count
- CPU-bound tasks: `num_cpus::get()`
- I/O-bound tasks: `2 * num_cpus::get()`
- Mixed workload: `1.5 * num_cpus::get()`

#### Queue Depths
```rust
const TASK_QUEUE_DEPTH: usize = 10000;
const CHANNEL_BUFFER_SIZE: usize = 1000;
const MPSC_BUFFER_SIZE: usize = 100;
```

**Guidelines:**
- Use bounded channels to prevent memory exhaustion
- Monitor queue depth and apply backpressure
- Separate queues for different priority levels

## 4. Profiling Tools

### 4.1 Async Profiling (tokio-console)

```bash
# Enable tokio-console in development
RUSTFLAGS="--cfg tokio_unstable" cargo run

# Connect to running application
tokio-console http://localhost:6669
```

**Metrics to monitor:**
- Task spawn rate and count
- Task poll times
- Async lock contention
- Resource utilization per task

### 4.2 CPU Profiling (perf)

```bash
# Record CPU profile
perf record -F 99 -g ./target/release/llm-data-vault

# Generate report
perf report

# Export for flamegraph
perf script | stackcollapse-perf.pl | flamegraph.pl > cpu-flamegraph.svg
```

### 4.3 Memory Profiling (heaptrack)

```bash
# Record heap allocations
heaptrack ./target/release/llm-data-vault

# Analyze results
heaptrack_gui heaptrack.llm-data-vault.*.gz
```

**Focus areas:**
- Total allocations
- Peak memory usage
- Allocation hotspots
- Memory leaks

### 4.4 Flamegraph Generation

```rust
// Add to Cargo.toml for profiling
[profile.release]
debug = true
```

```bash
# Using cargo-flamegraph
cargo flamegraph --bin llm-data-vault

# Using perf + flamegraph scripts
perf record -F 99 -g ./target/release/llm-data-vault
perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg
```

## 5. Performance Testing in CI

### 5.1 Benchmark Regression Detection

```yaml
# .github/workflows/benchmark.yml
name: Benchmark

on:
  pull_request:
  push:
    branches: [main]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run benchmarks
        run: cargo bench --bench crypto_benchmarks -- --save-baseline pr-${{ github.event.number }}

      - name: Compare with main
        run: |
          cargo bench --bench crypto_benchmarks -- --baseline main --save-baseline pr-${{ github.event.number }}

      - name: Check for regressions
        run: |
          # Fail if performance degrades by >10%
          critcmp main pr-${{ github.event.number }} --threshold 10
```

**Regression Thresholds:**
- Critical path: 5% degradation fails PR
- Standard operations: 10% degradation fails PR
- Background tasks: 20% degradation warning only

### 5.2 Automated Load Tests

```yaml
# .github/workflows/load-test.yml
name: Load Test

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  load-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Start services
        run: docker-compose up -d

      - name: Wait for healthy
        run: ./scripts/wait-for-healthy.sh

      - name: Run baseline load test
        run: k6 run tests/load/baseline.js

      - name: Run normal load test
        run: k6 run tests/load/normal.js

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: load-test-results
          path: results/
```

### 5.3 Performance Gates

```yaml
# Performance gates in CI
gates:
  api_latency_p95: 100ms
  api_latency_p99: 200ms
  error_rate: 0.1%
  throughput_min: 1000 req/s
  memory_max: 2GB
  cpu_max: 80%
```

## 6. Capacity Planning

### 6.1 Users per Node

**API Node Capacity:**
- Light users (1 req/min): 10,000 users/node
- Medium users (10 req/min): 1,000 users/node
- Heavy users (100 req/min): 100 users/node
- Mixed workload estimate: 2,000 concurrent users/node

**Worker Node Capacity:**
- Anonymization jobs: 100 concurrent/node
- Encryption jobs: 200 concurrent/node
- PII detection jobs: 150 concurrent/node

### 6.2 Storage Growth Projections

| Time Period | Active Users | Datasets | Avg Dataset Size | Total Storage | Growth Rate |
|-------------|--------------|----------|------------------|---------------|-------------|
| Month 1 | 100 | 500 | 100 MB | 50 GB | - |
| Month 3 | 500 | 2,500 | 100 MB | 250 GB | 5x |
| Month 6 | 2,000 | 10,000 | 120 MB | 1.2 TB | 24x |
| Year 1 | 10,000 | 50,000 | 150 MB | 7.5 TB | 150x |
| Year 2 | 50,000 | 250,000 | 200 MB | 50 TB | 1000x |

**Storage Overhead:**
- Encryption overhead: +5%
- Audit logs: +10%
- Metadata and indexes: +3%
- Total overhead: ~20%

### 6.3 Scaling Triggers

**Horizontal Scaling (Add Nodes):**
- CPU utilization >70% for 5 minutes
- Memory utilization >80% for 5 minutes
- Request queue depth >1000 for 1 minute
- API latency p95 >150ms for 5 minutes

**Vertical Scaling (Upgrade Nodes):**
- Consistent CPU >80% despite horizontal scaling
- Memory pressure causing OOM events
- Database connection pool exhaustion

**Database Scaling:**
- Connection pool utilization >80%
- Query latency p95 >50ms
- Storage >80% capacity
- Read replicas: read latency >30ms

## 7. Performance Monitoring

### 7.1 Key Metrics to Track

**Application Metrics:**
```rust
// Prometheus metrics
lazy_static! {
    static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "endpoint", "status"]
    ).unwrap();

    static ref ENCRYPTION_DURATION: Histogram = register_histogram!(
        "encryption_duration_seconds",
        "Encryption operation duration"
    ).unwrap();

    static ref PII_DETECTION_DURATION: Histogram = register_histogram!(
        "pii_detection_duration_seconds",
        "PII detection duration"
    ).unwrap();

    static ref ACTIVE_REQUESTS: IntGauge = register_int_gauge!(
        "active_requests",
        "Number of active HTTP requests"
    ).unwrap();

    static ref CACHE_HIT_RATE: Counter = register_counter!(
        "cache_hits_total",
        "Total cache hits"
    ).unwrap();
}
```

### 7.2 Alerting Thresholds

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| API latency p95 | >150ms | >300ms | Scale API nodes |
| API latency p99 | >300ms | >500ms | Investigate slow queries |
| Error rate | >0.5% | >1% | Check logs, rollback if needed |
| CPU utilization | >70% | >85% | Scale horizontally |
| Memory utilization | >75% | >90% | Check for leaks, scale |
| Disk utilization | >80% | >90% | Expand storage |
| Cache hit rate | <85% | <75% | Review cache config |
| Database connections | >80% pool | >95% pool | Increase pool size |
| Queue depth | >5000 | >10000 | Apply backpressure |

### 7.3 Dashboard Requirements

**API Performance Dashboard:**
- Request rate (req/s)
- Latency percentiles (p50, p95, p99)
- Error rate and error types
- Active connections
- Response size distribution

**Resource Utilization Dashboard:**
- CPU usage per node
- Memory usage per node
- Disk I/O per node
- Network throughput
- Container/pod health

**Business Metrics Dashboard:**
- Active users
- Datasets created/updated
- Records processed
- Anonymization jobs completed
- Storage consumption

## 8. Optimization Backlog

### 8.1 Known Optimization Opportunities

#### High Priority (P0)
1. **Database Query Optimization**
   - Add composite indexes on (dataset_id, created_at)
   - Implement query result caching for list endpoints
   - Expected impact: 30% latency reduction

2. **Connection Pooling Tuning**
   - Increase max connections from 100 to 200
   - Implement connection warming on startup
   - Expected impact: Eliminate connection timeout errors

3. **Async I/O Improvements**
   - Use `tokio::fs` instead of `std::fs`
   - Batch S3 operations using multipart API
   - Expected impact: 40% improvement in file operations

#### Medium Priority (P1)
4. **Serialization Optimization**
   - Switch from JSON to bincode for internal APIs
   - Implement zero-copy deserialization where possible
   - Expected impact: 20% reduction in serialization overhead

5. **Memory Pool Implementation**
   - Create buffer pools for encryption operations
   - Reuse allocations for frequently created objects
   - Expected impact: 15% reduction in allocation overhead

6. **Cache Optimization**
   - Implement distributed caching with Redis
   - Add cache warming for popular datasets
   - Expected impact: Increase cache hit rate from 85% to 95%

#### Low Priority (P2)
7. **Compile-Time Optimizations**
   - Enable LTO (Link-Time Optimization)
   - Profile-guided optimization (PGO)
   - Expected impact: 5-10% overall performance improvement

8. **Algorithm Improvements**
   - Replace regex-based PII detection with Aho-Corasick
   - Parallelize bulk operations with rayon
   - Expected impact: 50% faster PII detection

9. **Network Optimization**
   - Implement HTTP/2 server push for related resources
   - Add response compression (gzip/brotli)
   - Expected impact: 30% reduction in response size

### 8.2 Priority Ranking Criteria

**Impact Score (1-10):**
- Performance improvement magnitude
- Number of users affected
- Frequency of operation

**Effort Score (1-10):**
- Implementation complexity
- Testing requirements
- Risk of regression

**Priority = Impact / Effort**

### 8.3 Experimental Optimizations

- **SIMD acceleration** for encryption operations
- **io_uring** for Linux I/O operations
- **Custom allocator** tuned for workload
- **Ahead-of-time compilation** for hot paths
- **GPU acceleration** for ML-based PII detection

---

## Appendix A: Benchmark Results Template

```markdown
## Benchmark Results - [Date]

### Environment
- Hardware: [specs]
- OS: [version]
- Rust version: [version]
- Commit: [hash]

### Results

#### Encryption Performance
| Size | Throughput | Latency (avg) | Latency (p95) |
|------|------------|---------------|---------------|
| 1KB  | X MB/s     | X ms          | X ms          |
| 100KB| X MB/s     | X ms          | X ms          |
| 1MB  | X MB/s     | X ms          | X ms          |

#### Comparison with Baseline
- Encryption (1MB): +5% faster
- PII detection: +10% faster
- Storage operations: No change

### Regressions
- None detected

### Notes
[Any relevant observations]
```

## Appendix B: Load Test Results Template

```markdown
## Load Test Results - [Date]

### Scenario: [baseline/normal/peak/stress/soak]

### Configuration
- Duration: [time]
- VUs: [min-max]
- Target RPS: [value]

### Results
| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Requests/s | X | >1000 | PASS |
| Latency p95 | Xms | <150ms | PASS |
| Latency p99 | Xms | <300ms | PASS |
| Error rate | X% | <0.1% | PASS |

### Resource Utilization
- CPU: X% avg, X% max
- Memory: X GB avg, X GB max
- Network: X Mbps avg

### Issues
[Any issues encountered]

### Recommendations
[Scaling or optimization recommendations]
```
