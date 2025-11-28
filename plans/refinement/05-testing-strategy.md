# Testing Strategy

**Version:** 1.0
**Last Updated:** 2025-11-27
**Status:** Draft

## Overview

This document defines comprehensive testing requirements for bug-free implementation of LLM-Data-Vault. Our testing strategy follows the testing pyramid principle with emphasis on automated testing, continuous integration, and high code coverage.

## 1. Testing Pyramid

Our testing distribution follows industry best practices:

- **Unit Tests: 70%** - Fast, isolated tests of individual components
- **Integration Tests: 20%** - Tests of component interactions and external dependencies
- **E2E Tests: 10%** - Full system tests simulating real user workflows

### Rationale
- Unit tests provide fast feedback and enable confident refactoring
- Integration tests validate component interactions
- E2E tests ensure system-level correctness
- Pyramid shape optimizes for speed and reliability

## 2. Unit Testing Standards

### Coverage Requirements

| Category | Minimum Coverage | Target Coverage |
|----------|-----------------|-----------------|
| Overall Codebase | 85% | 90%+ |
| Critical Paths | 100% | 100% |
| Error Handling | 100% | 100% |
| Business Logic | 95% | 100% |
| Infrastructure | 70% | 80% |

**Critical Paths Include:**
- Dataset creation and management
- Encryption/decryption operations
- Authentication and authorization
- Data ingestion pipelines
- Query processing

### Test Organization

```rust
// src/domain/dataset.rs
pub struct Dataset {
    pub id: DatasetId,
    pub name: String,
    pub schema: Schema,
}

impl Dataset {
    pub fn new(name: String, schema: Schema) -> Result<Self, DatasetError> {
        // Implementation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod dataset_creation {
        use super::*;

        #[test]
        fn test_new_valid_input_returns_ok() {
            let schema = Schema::default();
            let result = Dataset::new("test_dataset".to_string(), schema);
            assert!(result.is_ok());
        }

        #[test]
        fn test_new_empty_name_returns_error() {
            let schema = Schema::default();
            let result = Dataset::new("".to_string(), schema);
            assert!(matches!(result, Err(DatasetError::InvalidName(_))));
        }

        #[test]
        fn test_new_name_too_long_returns_error() {
            let schema = Schema::default();
            let long_name = "a".repeat(256);
            let result = Dataset::new(long_name, schema);
            assert!(matches!(result, Err(DatasetError::InvalidName(_))));
        }
    }

    mod dataset_validation {
        use super::*;

        #[test]
        fn test_validate_schema_compatibility_compatible_returns_ok() {
            // Test implementation
        }

        #[test]
        fn test_validate_schema_compatibility_incompatible_returns_error() {
            // Test implementation
        }
    }
}
```

### Naming Convention

**Pattern:** `test_{function}_{scenario}_{expected}`

**Examples:**
```rust
#[test]
fn test_create_dataset_valid_input_returns_ok() { }

#[test]
fn test_create_dataset_duplicate_name_returns_error() { }

#[test]
fn test_encrypt_data_empty_input_returns_error() { }

#[test]
fn test_query_execution_timeout_returns_error() { }

#[test]
fn test_user_authentication_invalid_token_returns_unauthorized() { }
```

### Mocking Strategy

#### Using mockall for Trait Mocking

```rust
// src/infrastructure/repository.rs
use mockall::automock;

#[automock]
pub trait DatasetRepository: Send + Sync {
    async fn create(&self, dataset: Dataset) -> Result<Dataset, RepositoryError>;
    async fn find_by_id(&self, id: &DatasetId) -> Result<Option<Dataset>, RepositoryError>;
    async fn update(&self, dataset: Dataset) -> Result<Dataset, RepositoryError>;
    async fn delete(&self, id: &DatasetId) -> Result<(), RepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_service_create_dataset_calls_repository() {
        let mut mock_repo = MockDatasetRepository::new();

        mock_repo
            .expect_create()
            .times(1)
            .with(eq(expected_dataset))
            .returning(|ds| Ok(ds));

        let service = DatasetService::new(mock_repo);
        let result = service.create_dataset(request).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_service_create_dataset_repository_error_propagates() {
        let mut mock_repo = MockDatasetRepository::new();

        mock_repo
            .expect_create()
            .times(1)
            .returning(|_| Err(RepositoryError::ConnectionFailed));

        let service = DatasetService::new(mock_repo);
        let result = service.create_dataset(request).await;

        assert!(matches!(result, Err(ServiceError::RepositoryError(_))));
    }
}
```

#### Mock External Dependencies

```rust
// tests/mocks/s3_client.rs
use async_trait::async_trait;
use mockall::mock;

mock! {
    pub S3Client {
        async fn upload(&self, key: &str, data: Vec<u8>) -> Result<(), S3Error>;
        async fn download(&self, key: &str) -> Result<Vec<u8>, S3Error>;
        async fn delete(&self, key: &str) -> Result<(), S3Error>;
    }
}

// tests/mocks/encryption_service.rs
mock! {
    pub EncryptionService {
        fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, EncryptionError>;
        fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, EncryptionError>;
    }
}
```

## 3. Integration Testing

### Test Containers Setup

```rust
// tests/integration/setup.rs
use testcontainers::*;
use testcontainers::images::postgres::Postgres;

pub struct TestEnvironment {
    postgres: Container<Postgres>,
    redis: Container<Redis>,
    localstack: Container<LocalStack>,
    pub db_url: String,
    pub redis_url: String,
    pub s3_endpoint: String,
}

impl TestEnvironment {
    pub async fn new() -> Self {
        let docker = clients::Cli::default();

        // PostgreSQL
        let postgres = docker.run(Postgres::default());
        let db_port = postgres.get_host_port_ipv4(5432);
        let db_url = format!("postgres://postgres:postgres@localhost:{}/test", db_port);

        // Redis
        let redis = docker.run(images::redis::Redis::default());
        let redis_port = redis.get_host_port_ipv4(6379);
        let redis_url = format!("redis://localhost:{}", redis_port);

        // LocalStack (S3)
        let localstack = docker.run(images::generic::GenericImage::new("localstack/localstack", "latest")
            .with_env_var("SERVICES", "s3"));
        let s3_port = localstack.get_host_port_ipv4(4566);
        let s3_endpoint = format!("http://localhost:{}", s3_port);

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&sqlx::PgPool::connect(&db_url).await.unwrap())
            .await
            .unwrap();

        Self {
            postgres,
            redis,
            localstack,
            db_url,
            redis_url,
            s3_endpoint,
        }
    }

    pub async fn cleanup(&self) {
        // Cleanup logic
    }
}

// Setup/teardown pattern
#[tokio::test]
async fn test_with_environment() {
    let env = TestEnvironment::new().await;

    // Test logic using env.db_url, env.redis_url, etc.

    env.cleanup().await;
}
```

### API Testing

```rust
// tests/integration/api/dataset_api_test.rs
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn test_create_dataset_valid_request_returns_created() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    let request_body = json!({
        "name": "test_dataset",
        "schema": {
            "fields": [
                {"name": "id", "type": "integer"},
                {"name": "text", "type": "string"}
            ]
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/datasets")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer valid_token")
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let dataset: Dataset = serde_json::from_slice(&body).unwrap();
    assert_eq!(dataset.name, "test_dataset");
}

#[tokio::test]
async fn test_create_dataset_unauthorized_returns_401() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/datasets")
                .header("Content-Type", "application/json")
                // No Authorization header
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_dataset_invalid_schema_returns_400() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    let request_body = json!({
        "name": "test_dataset",
        "schema": {
            "fields": [] // Invalid: empty fields
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/datasets")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer valid_token")
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
```

### Database Testing

```rust
// tests/integration/database/migration_test.rs
#[tokio::test]
async fn test_migrations_apply_cleanly() {
    let env = TestEnvironment::new().await;
    let pool = PgPool::connect(&env.db_url).await.unwrap();

    // Migrations already ran in setup, verify tables exist
    let result = sqlx::query("SELECT COUNT(*) FROM datasets")
        .fetch_one(&pool)
        .await;

    assert!(result.is_ok());
}

// tests/integration/database/transaction_test.rs
#[tokio::test]
async fn test_transaction_rollback_on_error() {
    let env = TestEnvironment::new().await;
    let pool = PgPool::connect(&env.db_url).await.unwrap();

    let result = async {
        let mut tx = pool.begin().await?;

        // Insert dataset
        sqlx::query("INSERT INTO datasets (name) VALUES ($1)")
            .bind("test")
            .execute(&mut *tx)
            .await?;

        // Force error
        sqlx::query("INSERT INTO datasets (name) VALUES ($1)")
            .bind("test") // Duplicate name
            .execute(&mut *tx)
            .await?;

        tx.commit().await
    }.await;

    assert!(result.is_err());

    // Verify rollback
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM datasets")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(count.0, 0);
}

// tests/integration/database/constraint_test.rs
#[tokio::test]
async fn test_unique_constraint_enforced() {
    let env = TestEnvironment::new().await;
    let repo = PostgresDatasetRepository::new(&env.db_url).await;

    let dataset1 = Dataset::new("test".to_string(), Schema::default()).unwrap();
    let dataset2 = Dataset::new("test".to_string(), Schema::default()).unwrap();

    let result1 = repo.create(dataset1).await;
    assert!(result1.is_ok());

    let result2 = repo.create(dataset2).await;
    assert!(matches!(result2, Err(RepositoryError::UniqueViolation(_))));
}
```

## 4. Property-Based Testing

### Proptest Setup

```rust
// tests/property/dataset_test.rs
use proptest::prelude::*;

// Arbitrary implementations for domain types
impl Arbitrary for DatasetName {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        "[a-z][a-z0-9_]{2,63}"
            .prop_map(|s| DatasetName::new(s).unwrap())
            .boxed()
    }
}

impl Arbitrary for Schema {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop::collection::vec(any::<Field>(), 1..20)
            .prop_map(|fields| Schema { fields })
            .boxed()
    }
}

// Serialization roundtrip tests
proptest! {
    #[test]
    fn test_dataset_json_roundtrip(dataset in any::<Dataset>()) {
        let json = serde_json::to_string(&dataset).unwrap();
        let deserialized: Dataset = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(dataset, deserialized);
    }

    #[test]
    fn test_dataset_bincode_roundtrip(dataset in any::<Dataset>()) {
        let encoded = bincode::serialize(&dataset).unwrap();
        let decoded: Dataset = bincode::deserialize(&encoded).unwrap();
        prop_assert_eq!(dataset, decoded);
    }
}

// Invariant testing
proptest! {
    #[test]
    fn test_dataset_name_always_valid(name in "[a-z][a-z0-9_]{2,63}") {
        let result = DatasetName::new(name);
        prop_assert!(result.is_ok());
    }

    #[test]
    fn test_dataset_name_invalid_chars_rejected(
        name in "[^a-z0-9_]+"
    ) {
        let result = DatasetName::new(name);
        prop_assert!(result.is_err());
    }

    #[test]
    fn test_encryption_decryption_identity(
        data in prop::collection::vec(any::<u8>(), 0..1000),
        key in prop::collection::vec(any::<u8>(), 32)
    ) {
        let encrypted = encrypt(&data, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        prop_assert_eq!(data, decrypted);
    }
}
```

## 5. Security Testing

### Fuzzing with cargo-fuzz

```rust
// fuzz/fuzz_targets/parse_query.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use llm_data_vault::query::parse_query;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_query(s);
    }
});

// fuzz/fuzz_targets/decrypt_data.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use llm_data_vault::crypto::decrypt;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let (key, ciphertext) = data.split_at(32);
        let _ = decrypt(ciphertext, key);
    }
});

// fuzz/fuzz_targets/validate_schema.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use llm_data_vault::domain::Schema;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Schema>(s);
    }
});
```

**Running Fuzz Tests:**
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run specific fuzz target
cargo fuzz run parse_query

# Run with corpus
cargo fuzz run decrypt_data -- -max_total_time=300

# Generate coverage report
cargo fuzz coverage parse_query
```

### Penetration Testing

```rust
// tests/security/owasp_test.rs

#[tokio::test]
async fn test_sql_injection_protection() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    let malicious_inputs = vec![
        "'; DROP TABLE datasets; --",
        "1' OR '1'='1",
        "'; UPDATE users SET admin=true; --",
    ];

    for input in malicious_inputs {
        let response = app.clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/datasets?name={}", input))
                    .header("Authorization", "Bearer valid_token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should not execute malicious SQL
        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[tokio::test]
async fn test_authentication_bypass_attempts() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    let bypass_attempts = vec![
        None, // No token
        Some("invalid_token"),
        Some("Bearer "),
        Some(""),
        Some("null"),
    ];

    for token in bypass_attempts {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/api/v1/datasets");

        if let Some(t) = token {
            builder = builder.header("Authorization", t);
        }

        let response = app.clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_authorization_boundary_enforcement() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    // User A creates dataset
    let dataset_id = create_dataset_as_user(&app, "user_a_token").await;

    // User B attempts to access User A's dataset
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/datasets/{}", dataset_id))
                .header("Authorization", "Bearer user_b_token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_xss_prevention() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    let xss_payload = "<script>alert('XSS')</script>";

    let request_body = json!({
        "name": xss_payload,
        "schema": {"fields": []}
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/datasets")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer valid_token")
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    // Response should escape or sanitize
    assert!(!body_str.contains("<script>"));
}
```

## 6. Performance Testing

### Criterion Benchmarks

```rust
// benches/dataset_benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_dataset_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dataset_creation");

    for size in [10, 100, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let schema = create_schema_with_fields(size);
                Dataset::new(black_box("test".to_string()), black_box(schema))
            });
        });
    }

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");

    let key = [0u8; 32];

    for size in [1024, 10_240, 102_400, 1_024_000].iter() {
        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| encrypt(black_box(data), black_box(&key)));
        });
    }

    group.finish();
}

fn bench_query_parsing(c: &mut Criterion) {
    c.bench_function("parse_simple_query", |b| {
        b.iter(|| {
            parse_query(black_box("SELECT * FROM datasets WHERE id = 1"))
        });
    });

    c.bench_function("parse_complex_query", |b| {
        let complex_query = "SELECT d.id, d.name, COUNT(r.id) FROM datasets d \
                            LEFT JOIN records r ON d.id = r.dataset_id \
                            WHERE d.created_at > '2024-01-01' \
                            GROUP BY d.id, d.name \
                            HAVING COUNT(r.id) > 100 \
                            ORDER BY d.created_at DESC \
                            LIMIT 10";

        b.iter(|| parse_query(black_box(complex_query)));
    });
}

criterion_group!(benches, bench_dataset_creation, bench_encryption, bench_query_parsing);
criterion_main!(benches);
```

### Load Testing with k6

```javascript
// tests/load/scenarios/normal_load.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export const options = {
    scenarios: {
        normal_load: {
            executor: 'constant-vus',
            vus: 50,
            duration: '5m',
        },
    },
    thresholds: {
        http_req_duration: ['p(95)<500', 'p(99)<1000'],
        errors: ['rate<0.01'],
    },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export default function() {
    // Create dataset
    const createPayload = JSON.stringify({
        name: `dataset_${Date.now()}_${__VU}`,
        schema: {
            fields: [
                { name: 'id', type: 'integer' },
                { name: 'text', type: 'string' },
            ],
        },
    });

    const createRes = http.post(`${BASE_URL}/api/v1/datasets`, createPayload, {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${getToken()}`,
        },
    });

    check(createRes, {
        'dataset created': (r) => r.status === 201,
    }) || errorRate.add(1);

    if (createRes.status === 201) {
        const dataset = JSON.parse(createRes.body);

        // List datasets
        const listRes = http.get(`${BASE_URL}/api/v1/datasets`, {
            headers: { 'Authorization': `Bearer ${getToken()}` },
        });

        check(listRes, {
            'datasets listed': (r) => r.status === 200,
        }) || errorRate.add(1);

        // Get specific dataset
        const getRes = http.get(`${BASE_URL}/api/v1/datasets/${dataset.id}`, {
            headers: { 'Authorization': `Bearer ${getToken()}` },
        });

        check(getRes, {
            'dataset retrieved': (r) => r.status === 200,
        }) || errorRate.add(1);
    }

    sleep(1);
}

function getToken() {
    // Token generation logic
    return 'valid_token';
}
```

```javascript
// tests/load/scenarios/peak_load.js
export const options = {
    scenarios: {
        peak_load: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2m', target: 100 },
                { duration: '5m', target: 100 },
                { duration: '2m', target: 200 },
                { duration: '5m', target: 200 },
                { duration: '2m', target: 0 },
            ],
        },
    },
    thresholds: {
        http_req_duration: ['p(95)<1000', 'p(99)<2000'],
        errors: ['rate<0.05'],
    },
};
```

```javascript
// tests/load/scenarios/stress_test.js
export const options = {
    scenarios: {
        stress_test: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2m', target: 100 },
                { duration: '5m', target: 200 },
                { duration: '5m', target: 300 },
                { duration: '5m', target: 400 },
                { duration: '10m', target: 0 },
            ],
        },
    },
};
```

## 7. Chaos Testing

```rust
// tests/chaos/failure_injection.rs
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_database_connection_failure_recovery() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    // Normal operation
    let response = create_dataset(&app).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Simulate database failure
    env.stop_postgres().await;

    let response = create_dataset(&app).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Restore database
    env.start_postgres().await;
    sleep(Duration::from_secs(5)).await;

    // Should recover
    let response = create_dataset(&app).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_network_partition_handling() {
    // Simulate network partition between services
    let env = TestEnvironment::new().await;

    // Block network traffic to S3
    env.block_s3_traffic().await;

    // Upload should fail gracefully
    let result = upload_to_s3(&env, "test_key", vec![1, 2, 3]).await;
    assert!(result.is_err());

    // Should not affect other services
    let response = create_dataset(&app).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Restore network
    env.restore_s3_traffic().await;

    // Upload should work again
    let result = upload_to_s3(&env, "test_key", vec![1, 2, 3]).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_resource_exhaustion() {
    let env = TestEnvironment::new().await;
    let app = create_app(&env).await;

    // Fill up disk space
    env.fill_disk(95).await; // 95% full

    // Should handle gracefully
    let response = create_large_dataset(&app).await;
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);

    // Cleanup and verify recovery
    env.cleanup_disk().await;

    let response = create_large_dataset(&app).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}
```

## 8. CI/CD Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  CARGO_TERM_COLOR: always

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rust: [stable, nightly]

    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: ${{ matrix.rust }}
          override: true
          components: rustfmt, clippy

      - name: Cache cargo registry
        uses: actions/cache@v3
        with:
          path: ~/.cargo/registry
          key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}

      - name: Run unit tests
        run: cargo test --lib --bins --tests

      - name: Run doctests
        run: cargo test --doc

  integration-tests:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      redis:
        image: redis:7
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true

      - name: Run integration tests
        run: cargo test --test '*' -- --test-threads=1
        env:
          DATABASE_URL: postgres://postgres:postgres@localhost:5432/test
          REDIS_URL: redis://localhost:6379

  coverage:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true

      - name: Install tarpaulin
        run: cargo install cargo-tarpaulin

      - name: Generate coverage
        run: cargo tarpaulin --out Xml --output-dir ./coverage

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/cobertura.xml
          fail_ci_if_error: true

      - name: Check coverage threshold
        run: |
          coverage=$(grep -oP 'line-rate="\K[^"]+' coverage/cobertura.xml | head -1)
          threshold=0.90
          if (( $(echo "$coverage < $threshold" | bc -l) )); then
            echo "Coverage $coverage is below threshold $threshold"
            exit 1
          fi

  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run cargo audit
        uses: actions-rs/audit-check@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Run cargo deny
        run: |
          cargo install cargo-deny
          cargo deny check

  lint:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true
          components: rustfmt, clippy

      - name: Check formatting
        run: cargo fmt -- --check

      - name: Run clippy
        run: cargo clippy -- -D warnings
```

## 9. Test Data Management

### Fixtures

```rust
// tests/fixtures/mod.rs
pub struct Fixtures;

impl Fixtures {
    pub fn dataset() -> Dataset {
        Dataset {
            id: DatasetId::new(),
            name: "test_dataset".to_string(),
            schema: Self::schema(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn schema() -> Schema {
        Schema {
            fields: vec![
                Field {
                    name: "id".to_string(),
                    field_type: FieldType::Integer,
                    nullable: false,
                },
                Field {
                    name: "text".to_string(),
                    field_type: FieldType::String,
                    nullable: true,
                },
            ],
        }
    }

    pub fn user() -> User {
        User {
            id: UserId::new(),
            email: "test@example.com".to_string(),
            created_at: Utc::now(),
        }
    }
}
```

### Factories

```rust
// tests/factories/dataset_factory.rs
use fake::{Fake, Faker};

pub struct DatasetFactory;

impl DatasetFactory {
    pub fn build() -> DatasetBuilder {
        DatasetBuilder::default()
    }
}

#[derive(Default)]
pub struct DatasetBuilder {
    name: Option<String>,
    schema: Option<Schema>,
}

impl DatasetBuilder {
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_schema(mut self, schema: Schema) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn build(self) -> Dataset {
        Dataset {
            id: DatasetId::new(),
            name: self.name.unwrap_or_else(|| Faker.fake()),
            schema: self.schema.unwrap_or_else(|| SchemaFactory::build().build()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

// Usage:
let dataset = DatasetFactory::build()
    .with_name("custom_name")
    .build();
```

### Seed Data

```rust
// tests/seeds/mod.rs
pub async fn seed_database(pool: &PgPool) {
    // Seed users
    sqlx::query(
        "INSERT INTO users (id, email) VALUES
         ('550e8400-e29b-41d4-a716-446655440000', 'user1@example.com'),
         ('550e8400-e29b-41d4-a716-446655440001', 'user2@example.com')"
    )
    .execute(pool)
    .await
    .unwrap();

    // Seed datasets
    sqlx::query(
        "INSERT INTO datasets (id, name, schema, user_id) VALUES
         ('650e8400-e29b-41d4-a716-446655440000', 'dataset1', '{}', '550e8400-e29b-41d4-a716-446655440000'),
         ('650e8400-e29b-41d4-a716-446655440001', 'dataset2', '{}', '550e8400-e29b-41d4-a716-446655440001')"
    )
    .execute(pool)
    .await
    .unwrap();
}
```

## 10. Test Documentation

### Test Plan Template

```markdown
# Test Plan: [Feature Name]

## Overview
Brief description of the feature being tested.

## Scope

### In Scope
- Specific functionalities to test
- Components involved
- Integration points

### Out of Scope
- What is not being tested
- Deferred testing

## Test Strategy

### Unit Tests
- [ ] Component A functionality
- [ ] Component B functionality
- [ ] Error handling
- [ ] Edge cases

### Integration Tests
- [ ] API endpoints
- [ ] Database interactions
- [ ] External service interactions

### E2E Tests
- [ ] User workflow 1
- [ ] User workflow 2

## Test Data Requirements
- Required test data
- Data setup procedures

## Success Criteria
- All tests pass
- Coverage meets requirements (90%+)
- No critical bugs

## Risks and Mitigations
| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Example | Medium | High | Mitigation strategy |

## Timeline
- Development: [dates]
- Testing: [dates]
- Review: [dates]
```

### Bug Report Template

```markdown
# Bug Report

## Summary
Brief description of the bug.

## Environment
- Version:
- OS:
- Rust version:

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Test Case
```rust
#[test]
fn test_reproduces_bug() {
    // Minimal reproducible test case
}
```

## Logs/Screenshots
Include relevant logs or screenshots.

## Severity
- [ ] Critical - System crash, data loss
- [ ] High - Major functionality broken
- [ ] Medium - Feature impaired
- [ ] Low - Minor issue

## Additional Context
Any other relevant information.
```

## Summary

This testing strategy provides comprehensive coverage across all testing levels:

1. **Unit Tests (70%)** - Fast, isolated component tests with high coverage requirements
2. **Integration Tests (20%)** - Database, API, and service integration validation
3. **E2E Tests (10%)** - Full system workflows and user scenarios
4. **Property-Based Testing** - Automated invariant and roundtrip validation
5. **Security Testing** - Fuzzing, penetration testing, OWASP coverage
6. **Performance Testing** - Benchmarks and load testing at scale
7. **Chaos Testing** - Failure injection and resilience validation
8. **CI/CD Integration** - Automated testing in GitHub Actions
9. **Test Data Management** - Fixtures, factories, and seed data
10. **Documentation** - Templates for test plans and bug reports

By following this strategy, LLM-Data-Vault will achieve high-quality, bug-free implementation with confidence in correctness, security, and performance.
