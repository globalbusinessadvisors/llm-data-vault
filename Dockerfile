# LLM Data Vault - Multi-stage Dockerfile
# Build stage
FROM rust:1.75-bookworm as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build dependencies first (for caching)
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --package vault-server || true

# Build the actual application
RUN rm -rf src
COPY . .
RUN cargo build --release --package vault-server

# Runtime stage
FROM debian:bookworm-slim as runtime

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r vault && useradd -r -g vault vault

# Copy binary from builder
COPY --from=builder /app/target/release/vault-server /app/vault-server

# Copy config files
COPY config/ /app/config/

# Set ownership
RUN chown -R vault:vault /app

# Switch to non-root user
USER vault

# Environment variables
ENV RUST_LOG=info
ENV VAULT__HOST=0.0.0.0
ENV VAULT__PORT=8080

# Expose ports
EXPOSE 8080
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health/ready || exit 1

# Run the server
ENTRYPOINT ["/app/vault-server"]
