# Development Environment Setup

**Document:** 07-dev-environment.md
**Version:** 1.0.0
**Phase:** SPARC - Completion
**Last Updated:** 2025-11-27
**Status:** Ready for Implementation

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start Guide](#2-quick-start-guide)
3. [Makefile](#3-makefile)
4. [VS Code Configuration](#4-vs-code-configuration)
5. [Environment Files](#5-environment-files)
6. [Database Setup](#6-database-setup)
7. [Local Testing](#7-local-testing)
8. [Debugging](#8-debugging)
9. [Git Hooks](#9-git-hooks)
10. [Troubleshooting](#10-troubleshooting)
11. [Contributing Guide](#11-contributing-guide)

---

## 1. Prerequisites

### 1.1 Rust Toolchain

**Required Version:** Rust 1.75.0 or later

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Update to latest stable
rustup update stable

# Set default toolchain
rustup default stable

# Verify installation
rustc --version
cargo --version
```

**Required Components:**
```bash
# Install Rust components
rustup component add rustfmt clippy rust-analyzer

# Install nightly for advanced features (optional)
rustup toolchain install nightly
```

### 1.2 Docker and Docker Compose

**Required Versions:**
- Docker Engine 24.0+
- Docker Compose 2.20+

```bash
# Verify Docker installation
docker --version
docker compose version

# Test Docker
docker run hello-world
```

**macOS:**
```bash
brew install --cask docker
```

**Linux:**
```bash
# Docker Engine
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Docker Compose (included with Docker Desktop)
sudo usermod -aG docker $USER
newgrp docker
```

**Windows:**
- Install Docker Desktop from https://www.docker.com/products/docker-desktop

### 1.3 Required CLI Tools

**Essential Tools:**

```bash
# sqlx-cli - Database migrations and type checking
cargo install sqlx-cli --no-default-features --features postgres,sqlite

# cargo-watch - Auto-reload development server
cargo install cargo-watch

# cargo-nextest - Faster test runner
cargo install cargo-nextest

# cargo-tarpaulin - Code coverage (Linux only)
cargo install cargo-tarpaulin

# cargo-audit - Security vulnerability scanner
cargo install cargo-audit

# cargo-deny - Dependency license and advisory checker
cargo install cargo-deny

# cargo-outdated - Check for outdated dependencies
cargo install cargo-outdated
```

**Optional Development Tools:**

```bash
# cargo-expand - Expand macros for debugging
cargo install cargo-expand

# cargo-flamegraph - Performance profiling
cargo install flamegraph

# cargo-bloat - Find what takes space in binary
cargo install cargo-bloat

# cargo-udeps - Find unused dependencies (requires nightly)
cargo install cargo-udeps --locked
```

**Database Tools:**

```bash
# PostgreSQL client
# macOS
brew install postgresql@15

# Linux (Ubuntu/Debian)
sudo apt-get install postgresql-client-15

# Verify
psql --version
```

**Additional Utilities:**

```bash
# jq - JSON processing
# macOS
brew install jq

# Linux
sudo apt-get install jq

# httpie - API testing
pip install httpie

# grpcurl - gRPC testing
brew install grpcurl  # macOS
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest  # Other
```

### 1.4 IDE Recommendations

#### VS Code (Recommended)

**Installation:**
```bash
# macOS
brew install --cask visual-studio-code

# Linux
sudo snap install code --classic
```

**Essential Extensions:**
- `rust-lang.rust-analyzer` - Rust language support
- `vadimcn.vscode-lldb` - Debugging support
- `tamasfe.even-better-toml` - TOML syntax highlighting
- `serayuzgur.crates` - Manage Cargo.toml dependencies
- `mutantdino.resourcemonitor` - System resource monitoring

**Recommended Extensions:**
- `usernamehw.errorlens` - Inline error messages
- `github.copilot` - AI pair programming
- `ms-azuretools.vscode-docker` - Docker support
- `eamodio.gitlens` - Enhanced Git integration
- `streetsidesoftware.code-spell-checker` - Spell checking

#### RustRover (JetBrains)

**Installation:**
- Download from https://www.jetbrains.com/rust/
- Professional IDE with advanced Rust support
- Built-in database tools, debugger, and profiler

**Key Features:**
- Advanced code completion
- Integrated test runner
- Database tools
- Built-in HTTP client
- Profiling and memory analysis

#### Other Options

**Vim/Neovim:**
```vim
" Install rust-analyzer via coc.nvim or native LSP
" Add to your config:
Plug 'neovim/nvim-lspconfig'
Plug 'simrat39/rust-tools.nvim'
```

**Emacs:**
```elisp
;; Install rust-mode and lsp-mode
(use-package rust-mode
  :hook (rust-mode . lsp))
```

---

## 2. Quick Start Guide

### 2.1 Clone Repository

```bash
# Clone via HTTPS
git clone https://github.com/your-org/llm-data-vault.git
cd llm-data-vault

# Or via SSH
git clone git@github.com:your-org/llm-data-vault.git
cd llm-data-vault

# Verify branch
git branch
```

### 2.2 Install Dependencies

```bash
# Install all required tools
make setup

# Or manually:
cargo install sqlx-cli --no-default-features --features postgres
cargo install cargo-watch cargo-nextest
```

### 2.3 Start Infrastructure

```bash
# Start PostgreSQL, Redis, and other services
docker compose up -d

# Verify services are running
docker compose ps

# View logs
docker compose logs -f

# Expected output:
# postgres_1    | database system is ready to accept connections
# redis_1       | Ready to accept connections
```

### 2.4 Configure Environment

```bash
# Copy environment template
cp .env.example .env.development

# Edit configuration
vim .env.development

# Source environment
export $(cat .env.development | xargs)
```

### 2.5 Run Migrations

```bash
# Apply all migrations
make migrate

# Or manually:
sqlx migrate run --database-url $DATABASE_URL

# Verify migrations
psql $DATABASE_URL -c "\dt"
```

### 2.6 Seed Database (Optional)

```bash
# Load seed data
make seed

# Or manually:
cargo run --bin seed-db
```

### 2.7 Start Development Server

```bash
# Start with auto-reload
make dev

# Or manually:
cargo watch -x 'run --bin vault-api'

# Server should start on http://localhost:8080
```

### 2.8 Run Tests

```bash
# Run all tests
make test

# Or manually:
cargo nextest run

# Expected output:
# Running 127 tests across 8 binaries
# PASS [   0.234s] vault-core tests::test_dataset_creation
# ...
```

### 2.9 Verify Installation

```bash
# Health check
curl http://localhost:8080/health

# Expected response:
# {"status":"healthy","version":"0.1.0","timestamp":"2025-11-27T12:00:00Z"}

# API documentation
open http://localhost:8080/docs
```

---

## 3. Makefile

Complete Makefile for common development tasks.

**File:** `Makefile`

```makefile
.PHONY: help setup dev test lint fmt build docker-build migrate seed clean

# Default target
.DEFAULT_GOAL := help

# Environment variables
DATABASE_URL ?= postgres://vault:vault_dev_pass@localhost:5432/vault_dev
RUST_LOG ?= info,vault=debug

##@ General

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Setup

setup: ## Install all required tools and dependencies
	@echo "Installing Rust toolchain components..."
	rustup component add rustfmt clippy rust-analyzer
	@echo "Installing development tools..."
	cargo install sqlx-cli --no-default-features --features postgres --quiet
	cargo install cargo-watch --quiet
	cargo install cargo-nextest --quiet
	cargo install cargo-audit --quiet
	@echo "Copying environment files..."
	cp -n .env.example .env.development || true
	@echo "Setup complete! Run 'make dev' to start development."

install-hooks: ## Install git hooks
	@echo "Installing git hooks..."
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	cp scripts/commit-msg .git/hooks/commit-msg
	chmod +x .git/hooks/commit-msg
	@echo "Git hooks installed."

##@ Development

dev: ## Start development server with auto-reload
	@echo "Starting development server..."
	export DATABASE_URL=$(DATABASE_URL) && \
	export RUST_LOG=$(RUST_LOG) && \
	cargo watch -x 'run --bin vault-api' -w crates

dev-all: ## Start all services (infrastructure + server)
	@echo "Starting infrastructure..."
	docker compose up -d
	@echo "Waiting for database..."
	@sleep 3
	@echo "Running migrations..."
	$(MAKE) migrate
	@echo "Starting development server..."
	$(MAKE) dev

stop: ## Stop all services
	docker compose down

restart: stop dev-all ## Restart all services

logs: ## View application logs
	docker compose logs -f

##@ Building

build: ## Build all crates in release mode
	cargo build --release --all-features

build-dev: ## Build all crates in debug mode
	cargo build --all-features

check: ## Run cargo check
	cargo check --all-features --all-targets

##@ Testing

test: ## Run all tests
	cargo nextest run --all-features

test-unit: ## Run unit tests only
	cargo nextest run --all-features --lib

test-integration: ## Run integration tests only
	cargo nextest run --all-features --test '*'

test-watch: ## Run tests in watch mode
	cargo watch -x 'nextest run'

test-coverage: ## Generate test coverage report
	cargo tarpaulin --out Html --output-dir coverage --all-features

##@ Quality

lint: ## Run clippy linter
	cargo clippy --all-features --all-targets -- -D warnings

lint-fix: ## Fix linting issues automatically
	cargo clippy --all-features --all-targets --fix --allow-dirty

fmt: ## Format code with rustfmt
	cargo fmt --all

fmt-check: ## Check code formatting
	cargo fmt --all -- --check

audit: ## Check for security vulnerabilities
	cargo audit

deny: ## Check dependencies for issues
	cargo deny check

outdated: ## Check for outdated dependencies
	cargo outdated

##@ Database

migrate: ## Run database migrations
	sqlx migrate run --database-url $(DATABASE_URL)

migrate-revert: ## Revert last migration
	sqlx migrate revert --database-url $(DATABASE_URL)

migrate-add: ## Create new migration (use: make migrate-add NAME=migration_name)
	@if [ -z "$(NAME)" ]; then \
		echo "Error: NAME is required. Usage: make migrate-add NAME=migration_name"; \
		exit 1; \
	fi
	sqlx migrate add -r $(NAME)

db-reset: ## Reset database (drop + migrate)
	@echo "Dropping database..."
	docker compose exec postgres psql -U vault -c "DROP DATABASE IF EXISTS vault_dev;"
	docker compose exec postgres psql -U vault -c "CREATE DATABASE vault_dev;"
	@echo "Running migrations..."
	$(MAKE) migrate
	@echo "Seeding database..."
	$(MAKE) seed

seed: ## Seed database with test data
	cargo run --bin seed-db -- --env development

db-shell: ## Open PostgreSQL shell
	docker compose exec postgres psql -U vault -d vault_dev

##@ Docker

docker-build: ## Build Docker image
	docker build -t llm-data-vault:latest .

docker-run: ## Run Docker container
	docker run -p 8080:8080 --env-file .env.development llm-data-vault:latest

docker-push: ## Push Docker image to registry
	docker tag llm-data-vault:latest ghcr.io/your-org/llm-data-vault:latest
	docker push ghcr.io/your-org/llm-data-vault:latest

compose-up: ## Start all Docker Compose services
	docker compose up -d

compose-down: ## Stop all Docker Compose services
	docker compose down -v

compose-logs: ## View Docker Compose logs
	docker compose logs -f

##@ Documentation

docs: ## Generate and open documentation
	cargo doc --no-deps --open --all-features

docs-private: ## Generate documentation including private items
	cargo doc --no-deps --document-private-items --open --all-features

##@ Cleaning

clean: ## Clean build artifacts
	cargo clean
	rm -rf target/
	rm -rf coverage/

clean-docker: ## Clean Docker resources
	docker compose down -v --remove-orphans
	docker system prune -f

clean-all: clean clean-docker ## Clean everything

##@ Release

pre-release: lint fmt-check test audit ## Run all checks before release
	@echo "All pre-release checks passed!"

release-patch: ## Create patch release (0.0.X)
	cargo release patch --execute

release-minor: ## Create minor release (0.X.0)
	cargo release minor --execute

release-major: ## Create major release (X.0.0)
	cargo release major --execute
```

---

## 4. VS Code Configuration

### 4.1 Settings (.vscode/settings.json)

```json
{
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "rust-lang.rust-analyzer",
  "editor.rulers": [100],
  "editor.tabSize": 4,
  "editor.insertSpaces": true,
  "files.trimTrailingWhitespace": true,
  "files.insertFinalNewline": true,

  "[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer",
    "editor.formatOnSave": true
  },

  "[toml]": {
    "editor.defaultFormatter": "tamasfe.even-better-toml",
    "editor.formatOnSave": true
  },

  "[json]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode",
    "editor.formatOnSave": true
  },

  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.checkOnSave.allTargets": true,
  "rust-analyzer.checkOnSave.extraArgs": ["--all-features"],
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.inlayHints.enable": true,
  "rust-analyzer.inlayHints.parameterHints": true,
  "rust-analyzer.inlayHints.typeHints": true,
  "rust-analyzer.lens.enable": true,
  "rust-analyzer.lens.run": true,
  "rust-analyzer.lens.debug": true,
  "rust-analyzer.procMacro.enable": true,

  "files.watcherExclude": {
    "**/target/**": true,
    "**/node_modules/**": true
  },

  "search.exclude": {
    "**/target": true,
    "**/node_modules": true,
    "**/.git": true
  },

  "sqltools.connections": [
    {
      "name": "LLM-Data-Vault Dev",
      "driver": "PostgreSQL",
      "server": "localhost",
      "port": 5432,
      "database": "vault_dev",
      "username": "vault",
      "password": "vault_dev_pass"
    }
  ],

  "evenBetterToml.formatter.alignEntries": true,
  "evenBetterToml.formatter.indentTables": true,

  "errorLens.enabledDiagnosticLevels": [
    "error",
    "warning",
    "info"
  ],

  "terminal.integrated.env.osx": {
    "DATABASE_URL": "postgres://vault:vault_dev_pass@localhost:5432/vault_dev"
  },
  "terminal.integrated.env.linux": {
    "DATABASE_URL": "postgres://vault:vault_dev_pass@localhost:5432/vault_dev"
  }
}
```

### 4.2 Extensions (.vscode/extensions.json)

```json
{
  "recommendations": [
    "rust-lang.rust-analyzer",
    "vadimcn.vscode-lldb",
    "tamasfe.even-better-toml",
    "serayuzgur.crates",
    "usernamehw.errorlens",
    "ms-azuretools.vscode-docker",
    "eamodio.gitlens",
    "streetsidesoftware.code-spell-checker",
    "mtxr.sqltools",
    "mtxr.sqltools-driver-pg"
  ],
  "unwantedRecommendations": []
}
```

### 4.3 Launch Configuration (.vscode/launch.json)

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug API Server",
      "cargo": {
        "args": [
          "build",
          "--bin=vault-api",
          "--package=vault-api"
        ],
        "filter": {
          "name": "vault-api",
          "kind": "bin"
        }
      },
      "args": [],
      "cwd": "${workspaceFolder}",
      "env": {
        "RUST_LOG": "debug,vault=trace",
        "DATABASE_URL": "postgres://vault:vault_dev_pass@localhost:5432/vault_dev"
      }
    },
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug Tests",
      "cargo": {
        "args": [
          "test",
          "--no-run",
          "--all-features",
          "--lib"
        ]
      },
      "args": [],
      "cwd": "${workspaceFolder}",
      "env": {
        "RUST_LOG": "debug",
        "DATABASE_URL": "postgres://vault:vault_dev_pass@localhost:5432/vault_test"
      }
    },
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug Current Test",
      "cargo": {
        "args": [
          "test",
          "--no-run",
          "--all-features",
          "${input:testName}"
        ]
      },
      "args": [],
      "cwd": "${workspaceFolder}"
    },
    {
      "type": "lldb",
      "request": "attach",
      "name": "Attach to Process",
      "pid": "${command:pickMyProcess}"
    }
  ],
  "inputs": [
    {
      "id": "testName",
      "type": "promptString",
      "description": "Test name to debug",
      "default": ""
    }
  ]
}
```

### 4.4 Tasks (.vscode/tasks.json)

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "cargo build",
      "type": "cargo",
      "command": "build",
      "args": ["--all-features"],
      "problemMatcher": ["$rustc"],
      "group": "build"
    },
    {
      "label": "cargo test",
      "type": "cargo",
      "command": "test",
      "args": ["--all-features"],
      "problemMatcher": ["$rustc"],
      "group": "test"
    },
    {
      "label": "cargo clippy",
      "type": "cargo",
      "command": "clippy",
      "args": ["--all-features", "--", "-D", "warnings"],
      "problemMatcher": ["$rustc"],
      "group": "build"
    },
    {
      "label": "cargo run",
      "type": "cargo",
      "command": "run",
      "args": ["--bin", "vault-api"],
      "problemMatcher": ["$rustc"],
      "group": "none",
      "options": {
        "env": {
          "RUST_LOG": "debug,vault=trace",
          "DATABASE_URL": "postgres://vault:vault_dev_pass@localhost:5432/vault_dev"
        }
      }
    },
    {
      "label": "docker compose up",
      "type": "shell",
      "command": "docker compose up -d",
      "problemMatcher": [],
      "group": "none"
    },
    {
      "label": "docker compose down",
      "type": "shell",
      "command": "docker compose down",
      "problemMatcher": [],
      "group": "none"
    },
    {
      "label": "run migrations",
      "type": "shell",
      "command": "sqlx migrate run",
      "problemMatcher": [],
      "group": "none"
    }
  ]
}
```

---

## 5. Environment Files

### 5.1 Environment Template (.env.example)

```bash
# Application Configuration
APP_NAME=LLM-Data-Vault
APP_ENV=development
APP_VERSION=0.1.0
LOG_LEVEL=info

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
SERVER_WORKERS=4

# Database Configuration
DATABASE_URL=postgres://vault:vault_dev_pass@localhost:5432/vault_dev
DATABASE_MAX_CONNECTIONS=10
DATABASE_MIN_CONNECTIONS=2
DATABASE_CONNECT_TIMEOUT=30
DATABASE_IDLE_TIMEOUT=600

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_POOL_SIZE=10

# Authentication
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRATION_HOURS=24
SESSION_TIMEOUT_MINUTES=30

# Encryption
MASTER_KEY_ID=dev-master-key-001
ENCRYPTION_ALGORITHM=AES-256-GCM

# Storage
S3_BUCKET=llm-data-vault-dev
S3_REGION=us-east-1
S3_ENDPOINT=http://localhost:9000  # MinIO for local dev
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=minioadmin

# Observability
OTLP_ENDPOINT=http://localhost:4317
METRICS_ENABLED=true
TRACING_ENABLED=true

# Feature Flags
ENABLE_ANONYMIZATION=true
ENABLE_VERSIONING=true
ENABLE_WEBHOOKS=false

# Development
RUST_BACKTRACE=1
RUST_LOG=info,vault=debug,sqlx=warn
```

### 5.2 Development Environment (.env.development)

```bash
# Development-specific overrides
APP_ENV=development
LOG_LEVEL=debug
RUST_LOG=debug,vault=trace,sqlx=debug

# Database (local Docker)
DATABASE_URL=postgres://vault:vault_dev_pass@localhost:5432/vault_dev

# Development tools
ENABLE_API_DOCS=true
ENABLE_PLAYGROUND=true
CORS_ALLOW_ALL=true
```

### 5.3 Test Environment (.env.test)

```bash
# Test-specific configuration
APP_ENV=test
LOG_LEVEL=warn
RUST_LOG=warn,vault=info

# Test Database
DATABASE_URL=postgres://vault:vault_test_pass@localhost:5432/vault_test
DATABASE_MAX_CONNECTIONS=5

# Disable external services
ENABLE_WEBHOOKS=false
METRICS_ENABLED=false
TRACING_ENABLED=false

# Fast test execution
DATABASE_CONNECT_TIMEOUT=5
```

---

## 6. Database Setup

### 6.1 Docker Compose (docker-compose.yml)

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: vault-postgres
    environment:
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: vault_dev_pass
      POSTGRES_DB: vault_dev
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vault"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: vault-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  minio:
    image: minio/minio:latest
    container_name: vault-minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 20s
      retries: 3

volumes:
  postgres_data:
  redis_data:
  minio_data:
```

### 6.2 Database Initialization (scripts/init-db.sql)

```sql
-- Create test database
CREATE DATABASE vault_test;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE vault_dev TO vault;
GRANT ALL PRIVILEGES ON DATABASE vault_test TO vault;

-- Enable extensions
\c vault_dev;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

\c vault_test;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
```

### 6.3 Migration Commands

```bash
# Apply all pending migrations
sqlx migrate run

# Check migration status
sqlx migrate info

# Revert last migration
sqlx migrate revert

# Create new migration
sqlx migrate add -r create_users_table

# Generate sqlx-data.json for offline mode
cargo sqlx prepare

# Force re-run migration (dev only)
sqlx database drop && sqlx database create && sqlx migrate run
```

### 6.4 Seed Script (bin/seed-db.rs)

```rust
// Example seed script structure
use sqlx::PgPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPool::connect(&database_url).await?;

    println!("Seeding database...");

    // Insert test tenant
    sqlx::query!(
        "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)
         ON CONFLICT (slug) DO NOTHING",
        uuid::Uuid::new_v4(),
        "Test Tenant",
        "test-tenant"
    )
    .execute(&pool)
    .await?;

    println!("Database seeded successfully!");
    Ok(())
}
```

### 6.5 Reset Script

```bash
#!/bin/bash
# scripts/reset-db.sh

set -e

echo "Resetting database..."

# Drop and recreate
docker compose exec postgres psql -U vault -c "DROP DATABASE IF EXISTS vault_dev;"
docker compose exec postgres psql -U vault -c "CREATE DATABASE vault_dev;"

# Run migrations
sqlx migrate run

# Seed data
cargo run --bin seed-db

echo "Database reset complete!"
```

---

## 7. Local Testing

### 7.1 Running Unit Tests

```bash
# Run all unit tests
cargo nextest run --lib

# Run specific crate tests
cargo nextest run -p vault-core

# Run with logging
RUST_LOG=debug cargo nextest run

# Run single test
cargo nextest run test_dataset_creation
```

### 7.2 Running Integration Tests

```bash
# All integration tests
cargo nextest run --test '*'

# Specific integration test file
cargo nextest run --test storage_tests

# With database cleanup
TEST_DATABASE_URL=postgres://vault:vault_test_pass@localhost:5432/vault_test \
  cargo nextest run --test '*'
```

### 7.3 Test Organization

```rust
// Unit tests (in same file as code)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_creation() {
        // Test implementation
    }
}

// Integration tests (tests/ directory)
// tests/storage_tests.rs
#[tokio::test]
async fn test_postgres_storage() {
    // Integration test
}
```

### 7.4 Coverage Generation

```bash
# Generate HTML coverage report
cargo tarpaulin --out Html --output-dir coverage

# Open coverage report
open coverage/index.html

# Generate lcov format for CI
cargo tarpaulin --out Lcov

# Exclude test modules
cargo tarpaulin --exclude-files 'tests/*' --out Html
```

### 7.5 Benchmarking

```bash
# Run benchmarks
cargo bench

# Specific benchmark
cargo bench --bench storage_bench

# With profiling
cargo bench -- --profile-time=5
```

---

## 8. Debugging

### 8.1 VS Code Debugging

**Steps:**
1. Set breakpoint in code (click left margin)
2. Press F5 or select "Debug API Server"
3. Use debug controls:
   - F5: Continue
   - F10: Step over
   - F11: Step into
   - Shift+F11: Step out
   - Ctrl+Shift+F5: Restart
   - Shift+F5: Stop

### 8.2 Logging Setup

```rust
// Initialize tracing
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_logging() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,vault=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

// Usage in code
tracing::info!("Server starting on port {}", port);
tracing::debug!(user_id = ?user_id, "Processing request");
tracing::error!(error = ?e, "Failed to connect to database");
```

### 8.3 Environment Variables for Debugging

```bash
# Enable backtraces
export RUST_BACKTRACE=1       # Simple backtrace
export RUST_BACKTRACE=full    # Full backtrace

# Detailed logging
export RUST_LOG=trace

# SQL query logging
export RUST_LOG=sqlx=debug

# Specific module logging
export RUST_LOG=vault_core=trace,vault_storage=debug
```

### 8.4 Debug Tools

```bash
# Print macro expansions
cargo expand

# Analyze binary size
cargo bloat --release

# Profile performance
cargo flamegraph

# Check for undefined behavior (requires nightly)
cargo +nightly miri test
```

---

## 9. Git Hooks

### 9.1 Pre-commit Hook (scripts/pre-commit)

```bash
#!/bin/bash
# .git/hooks/pre-commit

set -e

echo "Running pre-commit checks..."

# Format check
echo "Checking code formatting..."
if ! cargo fmt -- --check; then
    echo "Error: Code is not formatted. Run 'cargo fmt' to fix."
    exit 1
fi

# Linting
echo "Running clippy..."
if ! cargo clippy --all-features --all-targets -- -D warnings; then
    echo "Error: Clippy found issues. Fix them before committing."
    exit 1
fi

# Tests
echo "Running tests..."
if ! cargo nextest run; then
    echo "Error: Tests failed. Fix them before committing."
    exit 1
fi

echo "Pre-commit checks passed!"
```

### 9.2 Commit Message Hook (scripts/commit-msg)

```bash
#!/bin/bash
# .git/hooks/commit-msg

commit_msg_file=$1
commit_msg=$(cat "$commit_msg_file")

# Check commit message format
# Format: type(scope): subject
pattern="^(feat|fix|docs|style|refactor|perf|test|chore|ci)(\(.+\))?: .{1,72}"

if ! echo "$commit_msg" | grep -Eq "$pattern"; then
    echo "Error: Commit message must follow conventional commits format:"
    echo "  type(scope): subject"
    echo ""
    echo "Types: feat, fix, docs, style, refactor, perf, test, chore, ci"
    echo ""
    echo "Example: feat(api): add dataset creation endpoint"
    exit 1
fi
```

### 9.3 Installation

```bash
# Install hooks
make install-hooks

# Or manually:
chmod +x scripts/pre-commit scripts/commit-msg
cp scripts/pre-commit .git/hooks/
cp scripts/commit-msg .git/hooks/
```

---

## 10. Troubleshooting

### 10.1 Common Issues

**Issue: sqlx compile-time verification fails**

```bash
# Solution: Generate offline metadata
cargo sqlx prepare

# Or disable compile-time checks temporarily
export SQLX_OFFLINE=true
```

**Issue: Port already in use**

```bash
# Find and kill process using port 8080
lsof -ti:8080 | xargs kill -9

# Or change port in .env
SERVER_PORT=8081
```

**Issue: Database connection refused**

```bash
# Check if PostgreSQL is running
docker compose ps

# Restart services
docker compose restart postgres

# Check logs
docker compose logs postgres
```

**Issue: Permission denied on Docker socket**

```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

**Issue: Slow compilation**

```bash
# Enable sccache for caching
cargo install sccache
export RUSTC_WRAPPER=sccache

# Use mold linker (Linux)
cargo install mold
```

### 10.2 FAQ

**Q: How do I reset my development environment?**

```bash
make clean-all
make setup
make dev-all
```

**Q: How do I update dependencies?**

```bash
# Check for updates
cargo outdated

# Update Cargo.lock
cargo update

# Update to latest compatible versions
cargo upgrade  # requires cargo-edit
```

**Q: How do I run tests in parallel?**

```bash
# nextest runs tests in parallel by default
cargo nextest run

# Control parallelism
cargo nextest run --test-threads 4
```

**Q: How do I profile my application?**

```bash
# CPU profiling
cargo flamegraph --bin vault-api

# Memory profiling (requires valgrind)
valgrind --tool=massif target/release/vault-api
```

---

## 11. Contributing Guide

### 11.1 Code Style

**Follow Rust conventions:**
- Use `rustfmt` for formatting
- Follow clippy recommendations
- Write comprehensive documentation
- Add tests for new features

**Example:**

```rust
/// Creates a new dataset with the given name and description.
///
/// # Arguments
///
/// * `name` - The name of the dataset
/// * `description` - Optional description
///
/// # Returns
///
/// Returns `Ok(Dataset)` on success, or `Error` on failure.
///
/// # Examples
///
/// ```
/// let dataset = create_dataset("My Dataset", Some("Description"))?;
/// ```
pub fn create_dataset(
    name: &str,
    description: Option<&str>,
) -> Result<Dataset, Error> {
    // Implementation
}
```

### 11.2 Pull Request Process

1. **Create feature branch:**
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make changes and commit:**
   ```bash
   git add .
   git commit -m "feat(api): add dataset creation endpoint"
   ```

3. **Push and create PR:**
   ```bash
   git push origin feat/my-feature
   # Open PR on GitHub
   ```

4. **PR checklist:**
   - [ ] Tests added/updated
   - [ ] Documentation updated
   - [ ] Changelog entry added
   - [ ] All CI checks pass
   - [ ] Code reviewed

### 11.3 Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Add/update tests
- `chore`: Maintenance
- `ci`: CI/CD changes

**Examples:**

```
feat(storage): add PostgreSQL storage backend

Implements PostgreSQL storage adapter with connection pooling
and automatic reconnection.

Closes #123
```

```
fix(api): handle null values in dataset metadata

Previously, null metadata values caused panics. Now they are
properly handled and returned as None.
```

### 11.4 Testing Requirements

**All PRs must include:**
- Unit tests for new functions
- Integration tests for new features
- Updated documentation
- No clippy warnings
- Code coverage maintained or improved

**Example test:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_dataset_success() {
        let storage = InMemoryStorage::new();
        let dataset = create_dataset(&storage, "Test", None).await;
        assert!(dataset.is_ok());
    }

    #[tokio::test]
    async fn test_create_dataset_duplicate_name() {
        let storage = InMemoryStorage::new();
        create_dataset(&storage, "Test", None).await.unwrap();
        let result = create_dataset(&storage, "Test", None).await;
        assert!(matches!(result, Err(Error::AlreadyExists)));
    }
}
```

### 11.5 Issue Templates

**Bug Report:**
- Description
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (OS, Rust version)
- Logs/screenshots

**Feature Request:**
- Problem description
- Proposed solution
- Alternatives considered
- Additional context

---

## Quick Reference

**Essential Commands:**

```bash
# Setup
make setup                    # Install tools and dependencies
make install-hooks            # Install git hooks

# Development
make dev                      # Start dev server
make dev-all                  # Start everything (infra + server)

# Testing
make test                     # Run all tests
make test-coverage            # Generate coverage report

# Quality
make lint                     # Run clippy
make fmt                      # Format code
make audit                    # Security audit

# Database
make migrate                  # Run migrations
make seed                     # Seed database
make db-reset                 # Reset database

# Docker
make docker-build             # Build Docker image
make compose-up               # Start services
make compose-down             # Stop services

# Cleaning
make clean                    # Clean build artifacts
make clean-all                # Clean everything
```

**Environment Variables:**

```bash
DATABASE_URL                  # PostgreSQL connection string
RUST_LOG                      # Logging level
RUST_BACKTRACE               # Enable backtraces
```

---

**End of Document**
