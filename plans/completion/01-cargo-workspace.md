# Cargo Workspace Configuration for LLM-Data-Vault

**Document Version:** 1.0.0
**Last Updated:** 2025-11-27
**Purpose:** Complete Cargo workspace and crate configurations for the Rust-based LLM-Data-Vault system

---

## Table of Contents

1. [Root Workspace Cargo.toml](#1-root-workspace-cargotoml)
2. [Individual Crate Configurations](#2-individual-crate-configurations)
3. [Rust Toolchain Configuration](#3-rust-toolchain-configuration)
4. [Cargo Build Configuration](#4-cargo-build-configuration)
5. [Clippy Linting Configuration](#5-clippy-linting-configuration)
6. [Rustfmt Code Formatting](#6-rustfmt-code-formatting)

---

## 1. Root Workspace Cargo.toml

**Location:** `/workspaces/llm-data-vault/Cargo.toml`

```toml
[workspace]
members = [
    "crates/vault-core",
    "crates/vault-storage",
    "crates/vault-crypto",
    "crates/vault-anonymize",
    "crates/vault-access",
    "crates/vault-api",
    "crates/vault-version",
    "crates/vault-integration",
    "crates/vault-server",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["LLM-Data-Vault Team"]
license = "Apache-2.0"
repository = "https://github.com/your-org/llm-data-vault"
homepage = "https://github.com/your-org/llm-data-vault"
rust-version = "1.75"

[workspace.dependencies]
# Internal crates
vault-core = { path = "crates/vault-core", version = "0.1.0" }
vault-storage = { path = "crates/vault-storage", version = "0.1.0" }
vault-crypto = { path = "crates/vault-crypto", version = "0.1.0" }
vault-anonymize = { path = "crates/vault-anonymize", version = "0.1.0" }
vault-access = { path = "crates/vault-access", version = "0.1.0" }
vault-api = { path = "crates/vault-api", version = "0.1.0" }
vault-version = { path = "crates/vault-version", version = "0.1.0" }
vault-integration = { path = "crates/vault-integration", version = "0.1.0" }

# Async runtime
tokio = { version = "1.35", features = ["full"] }
tokio-util = { version = "0.7", features = ["io", "codec"] }
async-trait = "0.1"
futures = "0.3"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
toml = "0.8"
bincode = "1.3"

# Error handling
thiserror = "1.0"
anyhow = "1.0"
color-eyre = "0.6"

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-appender = "0.2"
tracing-opentelemetry = "0.22"
opentelemetry = { version = "0.21", features = ["trace", "metrics"] }
opentelemetry-otlp = { version = "0.14", features = ["grpc-tonic"] }

# Web frameworks
axum = { version = "0.7", features = ["macros", "multipart", "ws"] }
axum-extra = { version = "0.9", features = ["typed-header"] }
tower = { version = "0.4", features = ["full"] }
tower-http = { version = "0.5", features = ["trace", "cors", "compression-full"] }
hyper = { version = "1.1", features = ["full"] }

# gRPC
tonic = { version = "0.11", features = ["tls", "gzip"] }
tonic-build = "0.11"
tonic-reflection = "0.11"
prost = "0.12"
prost-types = "0.12"

# Cryptography
ring = "0.17"
blake3 = "1.5"
sha2 = "0.10"
argon2 = "0.5"
zeroize = { version = "1.7", features = ["derive"] }
rand = "0.8"
rand_core = { version = "0.6", features = ["std"] }

# AWS SDK
aws-config = "1.1"
aws-sdk-s3 = "1.14"
aws-sdk-kms = "1.13"
aws-types = "1.1"

# Cloud storage (multi-cloud)
azure_storage = "0.19"
azure_storage_blobs = "0.19"
google-cloud-storage = "0.16"
google-cloud-auth = "0.13"

# Database
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "sqlite", "uuid", "chrono", "json"] }
sea-orm = { version = "0.12", features = ["sqlx-postgres", "runtime-tokio-native-tls", "macros"] }

# Authentication & authorization
jsonwebtoken = "9.2"
oauth2 = "4.4"
openidconnect = "3.4"

# Time handling
chrono = { version = "0.4", features = ["serde"] }
time = { version = "0.3", features = ["serde", "formatting", "parsing"] }

# UUID generation
uuid = { version = "1.6", features = ["v4", "v7", "serde"] }

# Regular expressions
regex = "1.10"
fancy-regex = "0.13"

# Text processing
unicode-segmentation = "1.11"
unicode-normalization = "0.1"

# Machine learning (ONNX for PII detection)
ort = { version = "2.0.0-rc.0", default-features = false, features = ["load-dynamic"] }
ndarray = "0.15"

# HTTP client
reqwest = { version = "0.11", features = ["json", "rustls-tls", "stream"] }

# Kafka integration
rdkafka = { version = "0.36", features = ["cmake-build", "ssl", "sasl"] }

# Configuration management
config = "0.14"
figment = { version = "0.10", features = ["toml", "json", "yaml", "env"] }

# CLI
clap = { version = "4.4", features = ["derive", "env", "cargo"] }
clap_complete = "4.4"

# Bytes manipulation
bytes = "1.5"

# URL parsing
url = { version = "2.5", features = ["serde"] }

# Metrics
prometheus = { version = "0.13", features = ["process"] }
metrics = "0.22"
metrics-exporter-prometheus = "0.13"

# Testing utilities
mockall = "0.12"
wiremock = "0.6"
rstest = "0.18"
proptest = "1.4"
criterion = { version = "0.5", features = ["html_reports", "async_tokio"] }

# Memory management
parking_lot = "0.12"
once_cell = "1.19"

# Validation
validator = { version = "0.17", features = ["derive"] }

# Compression
flate2 = "1.0"
zstd = "0.13"

# Base64 encoding
base64 = "0.21"

# Semantic versioning
semver = "1.0"

# Data structures
dashmap = "5.5"
indexmap = { version = "2.1", features = ["serde"] }

# Derive helpers
derive_more = "0.99"
strum = { version = "0.26", features = ["derive"] }
strum_macros = "0.26"

# Object storage abstraction
object_store = { version = "0.9", features = ["aws", "azure", "gcp"] }

# Content addressing
multihash = "0.19"
cid = "0.11"

# Policy engine
opa-wasm = "0.2"

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"
missing_debug_implementations = "warn"
rust_2018_idioms = "warn"
unreachable_pub = "warn"
unused_import_braces = "warn"
unused_lifetimes = "warn"
unused_qualifications = "warn"

[workspace.lints.clippy]
# Pedantic lints
all = "warn"
pedantic = "warn"
nursery = "warn"

# Restriction lints for security
as_conversions = "warn"
clone_on_ref_ptr = "warn"
create_dir = "warn"
dbg_macro = "warn"
decimal_literal_representation = "warn"
exit = "warn"
filetype_is_file = "warn"
float_cmp_const = "warn"
get_unwrap = "warn"
let_underscore_must_use = "warn"
mem_forget = "warn"
missing_docs_in_private_items = "allow"
multiple_inherent_impl = "warn"
panic = "warn"
panic_in_result_fn = "warn"
print_stdout = "warn"
print_stderr = "warn"
todo = "warn"
unimplemented = "warn"
unreachable = "warn"
unwrap_used = "warn"
expect_used = "warn"

# Allowed pedantic lints
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"

[profile.dev]
opt-level = 0
debug = true
debug-assertions = true
overflow-checks = true
lto = false
panic = 'unwind'
incremental = true
codegen-units = 256
rpath = false

[profile.release]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = "thin"
panic = 'abort'
incremental = false
codegen-units = 16
rpath = false
strip = true

[profile.bench]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = "thin"
panic = 'abort'
incremental = false
codegen-units = 16
rpath = false

[profile.test]
opt-level = 1
debug = true
debug-assertions = true
overflow-checks = true
lto = false
panic = 'unwind'
incremental = true
codegen-units = 256
rpath = false

# Profile for production builds with maximum optimization
[profile.production]
inherits = "release"
opt-level = 3
lto = "fat"
codegen-units = 1
panic = 'abort'
strip = true
```

---

## 2. Individual Crate Configurations

### 2.1 vault-core

**Location:** `/workspaces/llm-data-vault/crates/vault-core/Cargo.toml`

```toml
[package]
name = "vault-core"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "Core types, traits, and error definitions for LLM-Data-Vault"

[dependencies]
# Async
async-trait = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging
tracing = { workspace = true }

# Time
chrono = { workspace = true }
time = { workspace = true }

# UUID
uuid = { workspace = true }

# Validation
validator = { workspace = true }

# Derive utilities
derive_more = { workspace = true }
strum = { workspace = true }
strum_macros = { workspace = true }

# Memory safety
zeroize = { workspace = true }

# Bytes
bytes = { workspace = true }

# URL parsing
url = { workspace = true }

# Data structures
indexmap = { workspace = true }

# Semantic versioning
semver = { workspace = true }

# Content addressing
multihash = { workspace = true }
cid = { workspace = true }

# Cryptographic hashing
blake3 = { workspace = true }
sha2 = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
rstest = { workspace = true }
proptest = { workspace = true }
serde_json = { workspace = true }

[lints]
workspace = true

[lib]
doctest = true
```

### 2.2 vault-storage

**Location:** `/workspaces/llm-data-vault/crates/vault-storage/Cargo.toml`

```toml
[package]
name = "vault-storage"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "Storage backend abstractions and implementations for LLM-Data-Vault"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }

# Async runtime
tokio = { workspace = true }
tokio-util = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }

# AWS S3
aws-config = { workspace = true }
aws-sdk-s3 = { workspace = true }
aws-types = { workspace = true }

# Azure Blob Storage
azure_storage = { workspace = true, optional = true }
azure_storage_blobs = { workspace = true, optional = true }

# Google Cloud Storage
google-cloud-storage = { workspace = true, optional = true }
google-cloud-auth = { workspace = true, optional = true }

# Object store abstraction
object_store = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }
bincode = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging
tracing = { workspace = true }

# Bytes
bytes = { workspace = true }

# Cryptographic hashing
blake3 = { workspace = true }
sha2 = { workspace = true }

# Compression
flate2 = { workspace = true }
zstd = { workspace = true }

# URL parsing
url = { workspace = true }

# UUID
uuid = { workspace = true }

# Concurrency
parking_lot = { workspace = true }
dashmap = { workspace = true }

# Base64
base64 = { workspace = true }

# Content addressing
multihash = { workspace = true }
cid = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
tempfile = "3.9"
mockall = { workspace = true }
wiremock = { workspace = true }
rstest = { workspace = true }
criterion = { workspace = true }

[features]
default = ["s3"]
s3 = []
azure = ["azure_storage", "azure_storage_blobs"]
gcp = ["google-cloud-storage", "google-cloud-auth"]
local = []
all-backends = ["s3", "azure", "gcp", "local"]

[lints]
workspace = true

[[bench]]
name = "storage_benchmarks"
harness = false
```

### 2.3 vault-crypto

**Location:** `/workspaces/llm-data-vault/crates/vault-crypto/Cargo.toml`

```toml
[package]
name = "vault-crypto"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "Encryption services and key management for LLM-Data-Vault"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }

# Async
tokio = { workspace = true }
async-trait = { workspace = true }

# Cryptography
ring = { workspace = true }
blake3 = { workspace = true }
sha2 = { workspace = true }
argon2 = { workspace = true }
zeroize = { workspace = true }
rand = { workspace = true }
rand_core = { workspace = true }

# AWS KMS
aws-config = { workspace = true, optional = true }
aws-sdk-kms = { workspace = true, optional = true }

# Azure Key Vault
azure_security_keyvault = { version = "0.19", optional = true }
azure_identity = { version = "0.19", optional = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }
bincode = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging
tracing = { workspace = true }

# Bytes
bytes = { workspace = true }

# Base64
base64 = { workspace = true }

# UUID
uuid = { workspace = true }

# Time
chrono = { workspace = true }

# Derive utilities
derive_more = { workspace = true }

# Concurrency
parking_lot = { workspace = true }
once_cell = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
hex = "0.4"
rstest = { workspace = true }
proptest = { workspace = true }
criterion = { workspace = true }

[features]
default = ["local"]
local = []
aws-kms = ["aws-config", "aws-sdk-kms"]
azure-kv = ["azure_security_keyvault", "azure_identity"]
all-providers = ["local", "aws-kms", "azure-kv"]

[lints]
workspace = true

[[bench]]
name = "crypto_benchmarks"
harness = false
```

### 2.4 vault-anonymize

**Location:** `/workspaces/llm-data-vault/crates/vault-anonymize/Cargo.toml`

```toml
[package]
name = "vault-anonymize"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "PII detection and anonymization engine for LLM-Data-Vault"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }
vault-crypto = { workspace = true }

# Async
tokio = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }

# Regular expressions
regex = { workspace = true }
fancy-regex = { workspace = true }

# Text processing
unicode-segmentation = { workspace = true }
unicode-normalization = { workspace = true }

# Machine learning (ONNX Runtime for NER models)
ort = { workspace = true, optional = true }
ndarray = { workspace = true, optional = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging
tracing = { workspace = true }

# Cryptographic operations
blake3 = { workspace = true }
sha2 = { workspace = true }

# UUID
uuid = { workspace = true }

# Time
chrono = { workspace = true }

# Concurrency
parking_lot = { workspace = true }
dashmap = { workspace = true }
once_cell = { workspace = true }

# Base64
base64 = { workspace = true }

# Data structures
indexmap = { workspace = true }

# Derive utilities
derive_more = { workspace = true }
strum = { workspace = true }
strum_macros = { workspace = true }

# Bytes
bytes = { workspace = true }

# Phone number parsing
phonenumber = { version = "0.3", optional = true }

# Email validation
email_address = { version = "0.2", optional = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
rstest = { workspace = true }
proptest = { workspace = true }
criterion = { workspace = true }
insta = "1.34"

[features]
default = ["regex-patterns", "ml-models"]
regex-patterns = []
ml-models = ["ort", "ndarray"]
phone-validation = ["phonenumber"]
email-validation = ["email_address"]
full = ["regex-patterns", "ml-models", "phone-validation", "email-validation"]

[lints]
workspace = true

[[bench]]
name = "anonymization_benchmarks"
harness = false
```

### 2.5 vault-access

**Location:** `/workspaces/llm-data-vault/crates/vault-access/Cargo.toml`

```toml
[package]
name = "vault-access"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "RBAC/ABAC access control and authentication for LLM-Data-Vault"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }

# Async
tokio = { workspace = true }
async-trait = { workspace = true }

# Authentication
jsonwebtoken = { workspace = true }
oauth2 = { workspace = true }
openidconnect = { workspace = true, optional = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging
tracing = { workspace = true }

# Cryptography
ring = { workspace = true }
sha2 = { workspace = true }
base64 = { workspace = true }

# Time
chrono = { workspace = true }
time = { workspace = true }

# UUID
uuid = { workspace = true }

# Database
sqlx = { workspace = true, optional = true }
sea-orm = { workspace = true, optional = true }

# HTTP client
reqwest = { workspace = true, optional = true }

# Validation
validator = { workspace = true }

# Concurrency
parking_lot = { workspace = true }
dashmap = { workspace = true }

# Data structures
indexmap = { workspace = true }

# Derive utilities
derive_more = { workspace = true }
strum = { workspace = true }
strum_macros = { workspace = true }

# Policy engine (OPA WebAssembly)
opa-wasm = { workspace = true, optional = true }

# URL parsing
url = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
mockall = { workspace = true }
rstest = { workspace = true }
wiremock = { workspace = true }

[features]
default = ["jwt"]
jwt = []
oauth = ["reqwest"]
oidc = ["openidconnect", "reqwest"]
database = ["sqlx", "sea-orm"]
policy-engine = ["opa-wasm"]
full = ["jwt", "oauth", "oidc", "database", "policy-engine"]

[lints]
workspace = true
```

### 2.6 vault-api

**Location:** `/workspaces/llm-data-vault/crates/vault-api/Cargo.toml`

```toml
[package]
name = "vault-api"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "REST and gRPC API implementations for LLM-Data-Vault"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }
vault-storage = { workspace = true }
vault-crypto = { workspace = true }
vault-anonymize = { workspace = true }
vault-access = { workspace = true }
vault-version = { workspace = true }

# Async runtime
tokio = { workspace = true }
tokio-util = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }

# Web framework (REST)
axum = { workspace = true }
axum-extra = { workspace = true }
tower = { workspace = true }
tower-http = { workspace = true }
hyper = { workspace = true }

# gRPC
tonic = { workspace = true }
tonic-reflection = { workspace = true }
prost = { workspace = true }
prost-types = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging and tracing
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
tracing-opentelemetry = { workspace = true }
opentelemetry = { workspace = true }
opentelemetry-otlp = { workspace = true }

# Validation
validator = { workspace = true }

# UUID
uuid = { workspace = true }

# Time
chrono = { workspace = true }

# Bytes
bytes = { workspace = true }

# URL parsing
url = { workspace = true }

# Metrics
prometheus = { workspace = true }
metrics = { workspace = true }
metrics-exporter-prometheus = { workspace = true }

# Concurrency
parking_lot = { workspace = true }

# Data structures
indexmap = { workspace = true }

# Base64
base64 = { workspace = true }

# Derive utilities
derive_more = { workspace = true }

[build-dependencies]
tonic-build = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
tower = { workspace = true, features = ["util"] }
mockall = { workspace = true }
rstest = { workspace = true }
wiremock = { workspace = true }
http-body-util = "0.1"

[features]
default = ["rest", "grpc"]
rest = []
grpc = []
openapi = []
metrics = []
full = ["rest", "grpc", "openapi", "metrics"]

[lints]
workspace = true
```

### 2.7 vault-version

**Location:** `/workspaces/llm-data-vault/crates/vault-version/Cargo.toml`

```toml
[package]
name = "vault-version"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "Version control and lineage tracking for LLM-Data-Vault datasets"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }
vault-storage = { workspace = true }
vault-crypto = { workspace = true }

# Async
tokio = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }
bincode = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging
tracing = { workspace = true }

# Cryptographic operations
blake3 = { workspace = true }
sha2 = { workspace = true }

# Content addressing
multihash = { workspace = true }
cid = { workspace = true }

# UUID
uuid = { workspace = true }

# Time
chrono = { workspace = true }

# Bytes
bytes = { workspace = true }

# Database
sqlx = { workspace = true, optional = true }

# Concurrency
parking_lot = { workspace = true }
dashmap = { workspace = true }

# Data structures
indexmap = { workspace = true }

# Derive utilities
derive_more = { workspace = true }
strum = { workspace = true }
strum_macros = { workspace = true }

# Semantic versioning
semver = { workspace = true }

# Compression for diffs
flate2 = { workspace = true }

# Base64
base64 = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
tempfile = "3.9"
rstest = { workspace = true }
proptest = { workspace = true }
criterion = { workspace = true }

[features]
default = []
database = ["sqlx"]
full = ["database"]

[lints]
workspace = true

[[bench]]
name = "version_benchmarks"
harness = false
```

### 2.8 vault-integration

**Location:** `/workspaces/llm-data-vault/crates/vault-integration/Cargo.toml`

```toml
[package]
name = "vault-integration"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "Event streaming, webhooks, and external integrations for LLM-Data-Vault"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }

# Async runtime
tokio = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }

# Kafka
rdkafka = { workspace = true, optional = true }

# HTTP client
reqwest = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }

# Logging
tracing = { workspace = true }

# UUID
uuid = { workspace = true }

# Time
chrono = { workspace = true }

# Bytes
bytes = { workspace = true }

# URL parsing
url = { workspace = true }

# Validation
validator = { workspace = true }

# Concurrency
parking_lot = { workspace = true }
dashmap = { workspace = true }

# Retry logic
backoff = { version = "0.4", features = ["tokio"] }

# Cryptographic signatures
ring = { workspace = true }
sha2 = { workspace = true }
base64 = { workspace = true }

# Data structures
indexmap = { workspace = true }

# Derive utilities
derive_more = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
mockall = { workspace = true }
wiremock = { workspace = true }
rstest = { workspace = true }

[features]
default = ["webhooks"]
webhooks = []
kafka = ["rdkafka"]
kinesis = []
full = ["webhooks", "kafka", "kinesis"]

[lints]
workspace = true
```

### 2.9 vault-server (Binary)

**Location:** `/workspaces/llm-data-vault/crates/vault-server/Cargo.toml`

```toml
[package]
name = "vault-server"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
description = "Main server application for LLM-Data-Vault"

[dependencies]
# Internal dependencies
vault-core = { workspace = true }
vault-storage = { workspace = true, features = ["all-backends"] }
vault-crypto = { workspace = true, features = ["all-providers"] }
vault-anonymize = { workspace = true, features = ["full"] }
vault-access = { workspace = true, features = ["full"] }
vault-api = { workspace = true, features = ["full"] }
vault-version = { workspace = true, features = ["full"] }
vault-integration = { workspace = true, features = ["full"] }

# Async runtime
tokio = { workspace = true }
tokio-util = { workspace = true }
futures = { workspace = true }

# CLI
clap = { workspace = true }
clap_complete = { workspace = true }

# Configuration
config = { workspace = true }
figment = { workspace = true }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }
serde_yaml = { workspace = true }
toml = { workspace = true }

# Error handling
thiserror = { workspace = true }
anyhow = { workspace = true }
color-eyre = { workspace = true }

# Logging and tracing
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
tracing-appender = { workspace = true }
tracing-opentelemetry = { workspace = true }
opentelemetry = { workspace = true }
opentelemetry-otlp = { workspace = true }

# Web framework
axum = { workspace = true }
tower = { workspace = true }
tower-http = { workspace = true }

# gRPC
tonic = { workspace = true }

# Database
sqlx = { workspace = true }
sea-orm = { workspace = true }

# Metrics
prometheus = { workspace = true }
metrics = { workspace = true }
metrics-exporter-prometheus = { workspace = true }

# Signal handling
signal-hook = "0.3"
signal-hook-tokio = { version = "0.3", features = ["futures-v0_3"] }

# Shutdown coordination
tokio-graceful-shutdown = "0.14"

# System info
sysinfo = "0.30"

# Concurrency
parking_lot = { workspace = true }
once_cell = { workspace = true }

# Time
chrono = { workspace = true }

# UUID
uuid = { workspace = true }

# Validation
validator = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
tempfile = "3.9"
rstest = { workspace = true }

[features]
default = ["full"]
full = []
minimal = []

[lints]
workspace = true

[[bin]]
name = "vault-server"
path = "src/main.rs"
```

---

## 3. Rust Toolchain Configuration

**Location:** `/workspaces/llm-data-vault/rust-toolchain.toml`

```toml
[toolchain]
channel = "1.75"
components = [
    "rustfmt",
    "clippy",
    "rust-src",
    "rust-analyzer",
    "llvm-tools-preview"
]
targets = [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin"
]
profile = "default"
```

---

## 4. Cargo Build Configuration

**Location:** `/workspaces/llm-data-vault/.cargo/config.toml`

```toml
[build]
# Use all available CPU cores for parallel compilation
jobs = -1

# Incremental compilation for faster rebuilds in development
incremental = true

# Default target for building
# target = "x86_64-unknown-linux-gnu"

[target.x86_64-unknown-linux-gnu]
# Use mold linker for faster linking (if available)
# linker = "clang"
# rustflags = ["-C", "link-arg=-fuse-ld=mold"]

[target.x86_64-unknown-linux-musl]
# Static linking for musl targets
rustflags = ["-C", "target-feature=+crt-static"]

[target.x86_64-apple-darwin]
# macOS specific settings
rustflags = ["-C", "link-arg=-Wl,-undefined,dynamic_lookup"]

[target.aarch64-apple-darwin]
# Apple Silicon specific settings
rustflags = ["-C", "link-arg=-Wl,-undefined,dynamic_lookup"]

# Cargo registry configuration
[registry]
default = "crates-io"

[net]
# Retry configuration for network operations
retry = 3
git-fetch-with-cli = false

# Source replacement for faster builds (optional - uncomment if using)
# [source.crates-io]
# replace-with = "vendored-sources"
#
# [source.vendored-sources]
# directory = "vendor"

# Environment variables
[env]
# Ensure ONNX Runtime can find its libraries
# ORT_DYLIB_PATH = { value = "", relative = true }

# Alias commands for convenience
[alias]
# Run all tests with output
test-all = "test --workspace --all-features -- --nocapture"

# Check all crates
check-all = "check --workspace --all-features"

# Build with all features
build-all = "build --workspace --all-features"

# Run clippy on all crates
lint = "clippy --workspace --all-features -- -D warnings"

# Format all code
fmt-all = "fmt --all"

# Build documentation
doc-all = "doc --workspace --all-features --no-deps"

# Run benchmarks
bench-all = "bench --workspace --all-features"

# Clean everything including build artifacts
clean-all = "clean"

# Security audit
audit = "audit --deny warnings"

# Update dependencies
update-deps = "update"

# Build optimized release binary
release = "build --release --all-features"

# Build production binary with maximum optimization
production = "build --profile production --all-features"

# Run integration tests
test-integration = "test --workspace --all-features --test '*'"

# Run unit tests only
test-unit = "test --workspace --all-features --lib"

# Generate coverage report
coverage = "tarpaulin --workspace --all-features --out Html --output-dir coverage"

[term]
# Better terminal output
verbose = false
color = 'auto'
progress.when = 'auto'
progress.width = 80
```

---

## 5. Clippy Linting Configuration

**Location:** `/workspaces/llm-data-vault/clippy.toml`

```toml
# Clippy configuration for LLM-Data-Vault
# This file customizes Clippy lint behavior beyond workspace-level settings

# Allow type complexity in specific cases where it's justified
type-complexity-threshold = 500

# Cognitive complexity threshold
cognitive-complexity-threshold = 50

# Maximum number of single char bindings
single-char-binding-names-threshold = 4

# Maximum allowed size for a type
type-size-threshold = 200

# Maximum number of lines for a function
too-many-lines-threshold = 150

# Maximum number of arguments for a function
too-many-arguments-threshold = 8

# Maximum number of struct fields
struct-excessive-bools-threshold = 3

# Allow certain functions without documentation
missing-docs-in-private-items = false

# Vector initialization with constant size
vec-box-size-threshold = 4096

# Allow certain patterns
allow-mixed-uninlined-format-args = true

# Literal representation
literal-representation-threshold = 65536

# Array size threshold for stack allocation warnings
array-size-threshold = 524288

# Enable all lints in tests
enable-raw-pointer-heuristic-for-send = false

# Suppress false positives
suppress-restriction-lint-in-const = true

# Allow expect/unwrap in tests
allow-expect-in-tests = true
allow-unwrap-in-tests = true

# Allow print statements in binaries
allow-print-in-cli-programs = true

# Allow dbg! macro in development
allow-dbg-in-tests = true

# Blacklisted names to avoid
blacklisted-names = ["foo", "bar", "baz", "quux", "test", "tmp"]

# Standard library functions that should have alternatives
disallowed-methods = [
    # Use tracing instead
    { path = "std::println", reason = "use tracing macros" },
    { path = "std::eprintln", reason = "use tracing macros" },
    { path = "std::dbg", reason = "use tracing macros" },

    # Unsafe operations
    { path = "std::env::set_var", reason = "prefer configuration management" },
]

# Types that should not be used
disallowed-types = [
    { path = "std::collections::HashMap", reason = "use indexmap::IndexMap for deterministic iteration" },
]
```

---

## 6. Rustfmt Code Formatting

**Location:** `/workspaces/llm-data-vault/rustfmt.toml`

```toml
# Rustfmt configuration for LLM-Data-Vault
# Enforces consistent code style across the workspace

# Rust edition
edition = "2021"

# Maximum line width
max_width = 100

# Hard tabs or spaces
hard_tabs = false
tab_spaces = 4

# Function definitions
fn_args_layout = "Tall"
fn_single_line = false

# Where clause formatting
where_single_line = false
where_pred_indent = "Visual"

# Generics
generics_indent = "Block"

# Struct formatting
struct_field_align_threshold = 20
struct_lit_single_line = false
struct_lit_width = 40
struct_variant_width = 50

# Array formatting
array_width = 80

# Chain formatting
chain_width = 60
single_line_if_else_max_width = 50

# Import formatting
imports_indent = "Block"
imports_layout = "Mixed"
imports_granularity = "Crate"
group_imports = "StdExternalCrate"
reorder_imports = true
reorder_modules = true

# Control flow
control_brace_style = "AlwaysSameLine"
brace_style = "SameLineWhere"
indent_style = "Block"

# Match expressions
match_arm_blocks = true
match_arm_leading_pipes = "Never"
match_block_trailing_comma = false

# Comments and documentation
wrap_comments = true
comment_width = 100
normalize_comments = true
normalize_doc_attributes = true
format_code_in_doc_comments = true
doc_comment_code_block_width = 100

# String literals
format_strings = true
format_macro_matchers = true
format_macro_bodies = true

# Overflow
overflow_delimited_expr = true
enum_discrim_align_threshold = 20

# Blank lines
blank_lines_upper_bound = 2
blank_lines_lower_bound = 0

# Use field init shorthand
use_field_init_shorthand = true

# Use try shorthand
use_try_shorthand = true

# Newlines
newline_style = "Unix"

# Trailing comma
trailing_comma = "Vertical"
trailing_semicolon = true

# Spacing
space_after_colon = true
space_before_colon = false
spaces_around_ranges = false

# Hexadecimal literals
hex_literal_case = "Lower"

# Attributes
inline_attribute_width = 80

# Else formatting
empty_item_single_line = true
force_explicit_abi = true
force_multiline_blocks = false

# Version
version = "Two"

# Unstable features (requires nightly for some)
# Uncomment when using nightly Rust
# unstable_features = true
# condense_wildcard_suffixes = true
# indent_arrays = true
# overflow_delimited_expr = true
# format_code_in_doc_comments = true

# Ordering
reorder_impl_items = true

# Error handling
error_on_line_overflow = false
error_on_unformatted = false

# Edition idioms
edition_2021_semantic = true

# License template (optional - add license header to files)
# license_template_path = "LICENSE_HEADER"

# File specific ignoring
# ignore = []

# Required version (ensures consistent formatting)
required_version = "1.7.0"
```

---

## Summary

This comprehensive Cargo workspace configuration provides:

1. **Root Workspace**: Centralized dependency management, linting rules, and build profiles for all 9 crates
2. **Individual Crates**: Complete `Cargo.toml` files with appropriate dependencies:
   - **vault-core**: Lightweight core types (~15 dependencies)
   - **vault-storage**: Multi-cloud storage backends with optional features
   - **vault-crypto**: Encryption with pluggable key management providers
   - **vault-anonymize**: PII detection with ML/regex options
   - **vault-access**: Authentication and authorization with RBAC/ABAC
   - **vault-api**: REST and gRPC APIs with observability
   - **vault-version**: Git-like version control for datasets
   - **vault-integration**: Event streaming and webhooks
   - **vault-server**: Full-featured binary with all integrations

3. **Toolchain**: Rust 1.75+ with required components and multi-platform targets
4. **Build Config**: Optimized compiler settings, linker configuration, and helpful aliases
5. **Clippy**: Strict security-focused lints with practical thresholds
6. **Rustfmt**: Consistent code style with comprehensive formatting rules

**Total Configuration Lines:** ~875 lines of production-ready TOML

The configuration follows LLM-Data-Vault's design principles:
- **Security**: Forbids `unsafe` code, enables security-focused lints
- **Modularity**: Features flags enable pluggable backends/providers
- **Interoperability**: Multi-cloud support, standard serialization
- **Observability**: OpenTelemetry, structured logging, Prometheus metrics
