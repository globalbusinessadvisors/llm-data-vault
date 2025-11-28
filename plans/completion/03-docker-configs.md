# Docker Configurations for LLM-Data-Vault

Complete Docker setup for development, testing, and production environments.

---

## 1. Production Dockerfile

Multi-stage build optimized for security and size.

**File: `Dockerfile`**

```dockerfile
# =============================================================================
# Stage 1: Chef - Setup cargo-chef for dependency caching
# =============================================================================
FROM rust:1.75-slim as chef

WORKDIR /app

# Install cargo-chef for caching Rust dependencies
RUN cargo install cargo-chef --locked

# =============================================================================
# Stage 2: Planner - Generate recipe.json for dependencies
# =============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo chef prepare --recipe-path recipe.json

# =============================================================================
# Stage 3: Builder - Build the application
# =============================================================================
FROM chef AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy recipe and build dependencies (cached layer)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source code and build application
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build with optimizations
RUN cargo build --release --bin vault-server && \
    strip /app/target/release/vault-server

# =============================================================================
# Stage 4: Runtime - Minimal production image
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r vault && \
    useradd -r -g vault -u 1000 -m -s /bin/bash vault

# Create application directories
RUN mkdir -p /app/config /app/data /app/logs && \
    chown -R vault:vault /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=vault:vault /app/target/release/vault-server /app/vault-server

# Copy default configuration
COPY --chown=vault:vault config/default.toml /app/config/

# Switch to non-root user
USER vault

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/vault-server", "health-check"] || exit 1

# Set environment variables
ENV RUST_LOG=info \
    VAULT_CONFIG_PATH=/app/config/default.toml \
    VAULT_DATA_DIR=/app/data \
    VAULT_LOG_DIR=/app/logs

# Run the application
ENTRYPOINT ["/app/vault-server"]
CMD ["serve"]
```

---

## 2. Development Dockerfile

Full toolchain with development tools and hot-reload support.

**File: `Dockerfile.dev`**

```dockerfile
FROM rust:1.75-slim

WORKDIR /app

# Install development dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    ca-certificates \
    curl \
    git \
    build-essential \
    postgresql-client \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

# Install development tools
RUN cargo install cargo-watch cargo-edit cargo-audit cargo-outdated

# Install AWS CLI for LocalStack testing
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf aws awscliv2.zip

# Create non-root user for development
RUN groupadd -r devuser && \
    useradd -r -g devuser -u 1000 -m -s /bin/bash devuser && \
    chown -R devuser:devuser /app

USER devuser

# Pre-download dependencies (optional, for faster rebuilds)
COPY --chown=devuser:devuser Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && \
    cargo build && \
    rm -rf src

# Expose ports
EXPOSE 8080 9090

# Health check for development
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command: watch for changes and rebuild
CMD ["cargo", "watch", "-x", "run"]
```

---

## 3. docker-compose.yml

Complete development environment with all dependencies.

**File: `docker-compose.yml`**

```yaml
version: '3.8'

services:
  # =============================================================================
  # Vault Server
  # =============================================================================
  vault-server:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: llm-vault-server
    ports:
      - "8080:8080"  # API server
      - "9090:9090"  # Metrics endpoint
    volumes:
      - ./:/app:cached
      - cargo-cache:/usr/local/cargo/registry
      - target-cache:/app/target
    environment:
      RUST_LOG: debug
      RUST_BACKTRACE: 1
      DATABASE_URL: postgres://vault:vault_password@postgres:5432/llm_vault
      REDIS_URL: redis://redis:6379
      AWS_ACCESS_KEY_ID: test
      AWS_SECRET_ACCESS_KEY: test
      AWS_REGION: us-east-1
      AWS_ENDPOINT_URL: http://localstack:4566
      KAFKA_BROKERS: kafka:9092
      JAEGER_AGENT_HOST: jaeger
      JAEGER_AGENT_PORT: 6831
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      localstack:
        condition: service_healthy
      kafka:
        condition: service_healthy
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # PostgreSQL Database
  # =============================================================================
  postgres:
    image: postgres:16-alpine
    container_name: llm-vault-postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: vault_password
      POSTGRES_DB: llm_vault
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vault -d llm_vault"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # Redis Cache
  # =============================================================================
  redis:
    image: redis:7-alpine
    container_name: llm-vault-redis
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes --requirepass redis_password
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # LocalStack (AWS Services)
  # =============================================================================
  localstack:
    image: localstack/localstack:3.0
    container_name: llm-vault-localstack
    ports:
      - "4566:4566"  # LocalStack gateway
      - "4510-4559:4510-4559"  # External services
    environment:
      SERVICES: s3,kms,secretsmanager,sts
      DEBUG: 1
      DATA_DIR: /tmp/localstack/data
      DOCKER_HOST: unix:///var/run/docker.sock
      AWS_ACCESS_KEY_ID: test
      AWS_SECRET_ACCESS_KEY: test
      AWS_DEFAULT_REGION: us-east-1
    volumes:
      - localstack-data:/tmp/localstack
      - /var/run/docker.sock:/var/run/docker.sock
      - ./scripts/localstack-init.sh:/etc/localstack/init/ready.d/init.sh:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4566/_localstack/health"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # Zookeeper (for Kafka)
  # =============================================================================
  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    container_name: llm-vault-zookeeper
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    volumes:
      - zookeeper-data:/var/lib/zookeeper/data
      - zookeeper-logs:/var/lib/zookeeper/log
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "2181"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # Kafka Message Broker
  # =============================================================================
  kafka:
    image: confluentinc/cp-kafka:7.5.0
    container_name: llm-vault-kafka
    ports:
      - "9092:9092"
      - "29092:29092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:29092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
    volumes:
      - kafka-data:/var/lib/kafka/data
    depends_on:
      zookeeper:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "kafka-broker-api-versions", "--bootstrap-server", "localhost:9092"]
      interval: 10s
      timeout: 10s
      retries: 5
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # Jaeger (Distributed Tracing)
  # =============================================================================
  jaeger:
    image: jaegertracing/all-in-one:1.51
    container_name: llm-vault-jaeger
    ports:
      - "5775:5775/udp"  # Zipkin compact
      - "6831:6831/udp"  # Jaeger compact
      - "6832:6832/udp"  # Jaeger binary
      - "5778:5778"      # Config endpoint
      - "16686:16686"    # Web UI
      - "14268:14268"    # Jaeger collector
      - "14250:14250"    # gRPC
      - "9411:9411"      # Zipkin
    environment:
      COLLECTOR_ZIPKIN_HOST_PORT: ":9411"
      COLLECTOR_OTLP_ENABLED: "true"
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # Prometheus (Metrics Collection)
  # =============================================================================
  prometheus:
    image: prom/prometheus:v2.48.0
    container_name: llm-vault-prometheus
    ports:
      - "9091:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    networks:
      - vault-network
    restart: unless-stopped

  # =============================================================================
  # Grafana (Metrics Visualization)
  # =============================================================================
  grafana:
    image: grafana/grafana:10.2.2
    container_name: llm-vault-grafana
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_INSTALL_PLUGINS: grafana-clock-panel
    volumes:
      - grafana-data:/var/lib/grafana
      - ./config/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./config/grafana/dashboards:/var/lib/grafana/dashboards:ro
    depends_on:
      - prometheus
    networks:
      - vault-network
    restart: unless-stopped

# =============================================================================
# Networks
# =============================================================================
networks:
  vault-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

# =============================================================================
# Volumes
# =============================================================================
volumes:
  postgres-data:
    driver: local
  redis-data:
    driver: local
  localstack-data:
    driver: local
  kafka-data:
    driver: local
  zookeeper-data:
    driver: local
  zookeeper-logs:
    driver: local
  prometheus-data:
    driver: local
  grafana-data:
    driver: local
  cargo-cache:
    driver: local
  target-cache:
    driver: local
```

---

## 4. docker-compose.test.yml

Isolated testing environment with cleanup capabilities.

**File: `docker-compose.test.yml`**

```yaml
version: '3.8'

services:
  # =============================================================================
  # Test Runner
  # =============================================================================
  test-runner:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: llm-vault-test-runner
    command: cargo test --all-features -- --test-threads=1
    environment:
      RUST_LOG: debug
      RUST_BACKTRACE: full
      DATABASE_URL: postgres://vault_test:test_password@postgres-test:5432/llm_vault_test
      REDIS_URL: redis://redis-test:6379
      AWS_ACCESS_KEY_ID: test
      AWS_SECRET_ACCESS_KEY: test
      AWS_REGION: us-east-1
      AWS_ENDPOINT_URL: http://localstack-test:4566
      KAFKA_BROKERS: kafka-test:9092
      TEST_MODE: "true"
    volumes:
      - ./:/app:cached
      - test-cargo-cache:/usr/local/cargo/registry
      - test-target-cache:/app/target
    depends_on:
      postgres-test:
        condition: service_healthy
      redis-test:
        condition: service_healthy
      localstack-test:
        condition: service_healthy
    networks:
      - test-network

  # =============================================================================
  # Test PostgreSQL
  # =============================================================================
  postgres-test:
    image: postgres:16-alpine
    container_name: llm-vault-postgres-test
    environment:
      POSTGRES_USER: vault_test
      POSTGRES_PASSWORD: test_password
      POSTGRES_DB: llm_vault_test
    tmpfs:
      - /var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vault_test -d llm_vault_test"]
      interval: 5s
      timeout: 3s
      retries: 3
    networks:
      - test-network

  # =============================================================================
  # Test Redis
  # =============================================================================
  redis-test:
    image: redis:7-alpine
    container_name: llm-vault-redis-test
    command: redis-server --save ""
    tmpfs:
      - /data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3
    networks:
      - test-network

  # =============================================================================
  # Test LocalStack
  # =============================================================================
  localstack-test:
    image: localstack/localstack:3.0
    container_name: llm-vault-localstack-test
    environment:
      SERVICES: s3,kms,secretsmanager
      DEBUG: 0
      DATA_DIR: /tmp/localstack/data
    tmpfs:
      - /tmp/localstack
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4566/_localstack/health"]
      interval: 5s
      timeout: 3s
      retries: 3
    networks:
      - test-network

  # =============================================================================
  # Test Kafka & Zookeeper (Lightweight)
  # =============================================================================
  zookeeper-test:
    image: confluentinc/cp-zookeeper:7.5.0
    container_name: llm-vault-zookeeper-test
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    tmpfs:
      - /var/lib/zookeeper/data
      - /var/lib/zookeeper/log
    networks:
      - test-network

  kafka-test:
    image: confluentinc/cp-kafka:7.5.0
    container_name: llm-vault-kafka-test
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper-test:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka-test:9092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT
      KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
    tmpfs:
      - /var/lib/kafka/data
    depends_on:
      - zookeeper-test
    healthcheck:
      test: ["CMD", "kafka-broker-api-versions", "--bootstrap-server", "localhost:9092"]
      interval: 5s
      timeout: 5s
      retries: 3
    networks:
      - test-network

networks:
  test-network:
    driver: bridge

volumes:
  test-cargo-cache:
    driver: local
  test-target-cache:
    driver: local
```

---

## 5. .dockerignore

Optimize build context by excluding unnecessary files.

**File: `.dockerignore`**

```
# Git
.git/
.gitignore
.gitattributes

# Build artifacts
target/
**/target/
**/*.rs.bk
*.pdb

# IDE
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Documentation
*.md
docs/
plans/
LICENSE*
CHANGELOG*

# CI/CD
.github/
.gitlab-ci.yml
.travis.yml

# Docker
Dockerfile*
docker-compose*.yml
.dockerignore

# Dependencies
node_modules/
vendor/

# Environment
.env
.env.*
*.local

# Logs
logs/
*.log
npm-debug.log*
yarn-debug.log*

# Data
data/
*.db
*.sqlite

# Tests
tests/fixtures/
coverage/
*.profraw

# Temporary files
tmp/
temp/
*.tmp
*.cache

# OS
Thumbs.db
.DS_Store

# Misc
scripts/
examples/
benchmarks/
```

---

## 6. Container Security

### 6.1 Trivy Scanning Configuration

**File: `.trivyignore`**

```
# Ignore specific CVEs with justification

# Example: CVE-2023-xxxxx - False positive for development dependencies
# CVE-2023-xxxxx

# Add CVEs to ignore with comments explaining why
```

**File: `scripts/security-scan.sh`**

```bash
#!/bin/bash
set -e

echo "Running Trivy security scan..."

# Scan filesystem for vulnerabilities
trivy fs --severity HIGH,CRITICAL --exit-code 1 .

# Scan Docker image
docker build -t llm-vault:scan-test .
trivy image --severity HIGH,CRITICAL --exit-code 1 llm-vault:scan-test

# Scan for misconfigurations
trivy config --severity HIGH,CRITICAL --exit-code 1 .

# Generate SBOM (Software Bill of Materials)
trivy image --format cyclonedx --output sbom.json llm-vault:scan-test

echo "Security scan completed successfully!"
```

### 6.2 Security Best Practices Checklist

```markdown
## Container Security Checklist

### Build Time
- [ ] Use minimal base images (distroless/alpine)
- [ ] Multi-stage builds to reduce attack surface
- [ ] Run as non-root user (UID/GID specified)
- [ ] No secrets in image layers
- [ ] Scan images with Trivy/Snyk
- [ ] Pin all dependencies to specific versions
- [ ] Use .dockerignore to exclude sensitive files
- [ ] Verify base image signatures

### Runtime
- [ ] Read-only root filesystem where possible
- [ ] Drop unnecessary Linux capabilities
- [ ] Resource limits (CPU, memory) defined
- [ ] Network policies configured
- [ ] Secrets via environment/volume, not baked in
- [ ] Health checks implemented
- [ ] Logging to stdout/stderr
- [ ] TLS/HTTPS for all external communication

### Image Management
- [ ] Images signed with Docker Content Trust
- [ ] Registry access via authentication
- [ ] Regular image updates (base + dependencies)
- [ ] Automated vulnerability scanning in CI/CD
- [ ] Image retention policy defined
- [ ] SBOM generated and stored

### Kubernetes Security (if applicable)
- [ ] Pod Security Standards enforced
- [ ] Network policies configured
- [ ] RBAC properly configured
- [ ] Service accounts with minimal permissions
- [ ] Secrets management (sealed secrets/external)
- [ ] Pod security contexts defined
```

---

## 7. Image Tagging Strategy

### 7.1 Semantic Versioning

```bash
# Version format: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]

# Production releases
llm-vault:1.0.0
llm-vault:1.0.1
llm-vault:1.1.0

# Pre-releases
llm-vault:2.0.0-alpha.1
llm-vault:2.0.0-beta.1
llm-vault:2.0.0-rc.1

# Development builds
llm-vault:1.0.0-dev.20231127
```

### 7.2 Git SHA Tags

```bash
# Full SHA
llm-vault:sha-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0

# Short SHA (7 chars)
llm-vault:sha-a1b2c3d

# Branch-based
llm-vault:main-a1b2c3d
llm-vault:feature-auth-a1b2c3d
```

### 7.3 Latest Tag Policy

```bash
# Tags to maintain:
llm-vault:latest              # Latest stable release
llm-vault:latest-dev          # Latest development build
llm-vault:1.x                 # Latest 1.x minor version
llm-vault:1.2.x               # Latest 1.2.x patch version
```

### 7.4 Tagging Script

**File: `scripts/docker-tag.sh`**

```bash
#!/bin/bash
set -e

VERSION=${1:-}
GIT_SHA=$(git rev-parse --short HEAD)
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
REGISTRY=${REGISTRY:-ghcr.io/your-org}
IMAGE_NAME=${IMAGE_NAME:-llm-vault}

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

# Validate semantic version
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo "Error: Invalid semantic version format"
    exit 1
fi

echo "Building and tagging image..."
echo "Version: $VERSION"
echo "Git SHA: $GIT_SHA"
echo "Branch: $GIT_BRANCH"

# Build image
docker build -t ${IMAGE_NAME}:build .

# Apply tags
docker tag ${IMAGE_NAME}:build ${REGISTRY}/${IMAGE_NAME}:${VERSION}
docker tag ${IMAGE_NAME}:build ${REGISTRY}/${IMAGE_NAME}:sha-${GIT_SHA}

# Extract major.minor.patch
MAJOR=$(echo $VERSION | cut -d. -f1)
MINOR=$(echo $VERSION | cut -d. -f2)
PATCH=$(echo $VERSION | cut -d. -f3 | cut -d- -f1)

# Apply progressive tags for stable releases
if [[ ! $VERSION =~ - ]]; then
    docker tag ${IMAGE_NAME}:build ${REGISTRY}/${IMAGE_NAME}:${MAJOR}
    docker tag ${IMAGE_NAME}:build ${REGISTRY}/${IMAGE_NAME}:${MAJOR}.${MINOR}
    docker tag ${IMAGE_NAME}:build ${REGISTRY}/${IMAGE_NAME}:latest
    echo "Applied stable release tags"
fi

# Push all tags
echo "Pushing images..."
docker push ${REGISTRY}/${IMAGE_NAME}:${VERSION}
docker push ${REGISTRY}/${IMAGE_NAME}:sha-${GIT_SHA}

if [[ ! $VERSION =~ - ]]; then
    docker push ${REGISTRY}/${IMAGE_NAME}:${MAJOR}
    docker push ${REGISTRY}/${IMAGE_NAME}:${MAJOR}.${MINOR}
    docker push ${REGISTRY}/${IMAGE_NAME}:latest
fi

echo "Successfully built and pushed ${VERSION}"
```

---

## 8. Helper Scripts

### 8.1 LocalStack Initialization

**File: `scripts/localstack-init.sh`**

```bash
#!/bin/bash
set -e

echo "Initializing LocalStack resources..."

# Wait for LocalStack to be ready
while ! curl -f http://localhost:4566/_localstack/health > /dev/null 2>&1; do
    echo "Waiting for LocalStack..."
    sleep 2
done

# Create S3 bucket
aws --endpoint-url=http://localhost:4566 s3 mb s3://llm-vault-data || true

# Create KMS key
KEY_ID=$(aws --endpoint-url=http://localhost:4566 kms create-key \
    --description "LLM Vault Master Key" \
    --query 'KeyMetadata.KeyId' \
    --output text)

echo "Created KMS key: $KEY_ID"

# Create alias
aws --endpoint-url=http://localhost:4566 kms create-alias \
    --alias-name alias/llm-vault-master \
    --target-key-id $KEY_ID || true

echo "LocalStack initialization complete!"
```

### 8.2 Database Initialization

**File: `scripts/init-db.sql`**

```sql
-- Initialize database with extensions and schemas

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS vault;
CREATE SCHEMA IF NOT EXISTS audit;

-- Grant permissions
GRANT ALL ON SCHEMA vault TO vault;
GRANT ALL ON SCHEMA audit TO vault;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.access_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    metadata JSONB,
    INDEX idx_timestamp (timestamp),
    INDEX idx_user_id (user_id)
);
```

---

## 9. Makefile Targets

Add these Docker-related targets to your Makefile:

```makefile
# Docker targets
.PHONY: docker-build docker-build-dev docker-up docker-down docker-test

docker-build:
	docker build -t llm-vault:latest .

docker-build-dev:
	docker build -f Dockerfile.dev -t llm-vault:dev .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down -v

docker-test:
	docker-compose -f docker-compose.test.yml up --abort-on-container-exit --exit-code-from test-runner

docker-logs:
	docker-compose logs -f vault-server

docker-clean:
	docker-compose down -v --remove-orphans
	docker system prune -f

docker-scan:
	./scripts/security-scan.sh
```

---

## Summary

This document provides complete Docker configurations including:

1. **Production Dockerfile**: Multi-stage build with cargo-chef caching, non-root user, and minimal runtime image
2. **Development Dockerfile**: Full toolchain with development tools and hot-reload support
3. **docker-compose.yml**: Complete development environment with PostgreSQL, Redis, LocalStack, Kafka, Jaeger, Prometheus, and Grafana
4. **docker-compose.test.yml**: Isolated testing environment with cleanup and tmpfs for speed
5. **.dockerignore**: Optimized build context exclusions
6. **Container Security**: Trivy scanning configuration and security checklist
7. **Image Tagging Strategy**: Semantic versioning, Git SHA tags, and automated tagging scripts

All configurations follow security best practices with non-root users, health checks, minimal attack surfaces, and comprehensive monitoring capabilities.
