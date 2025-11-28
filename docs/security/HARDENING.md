# Security Hardening Guide

This guide provides comprehensive security hardening recommendations for LLM Data Vault in production environments.

## Table of Contents

1. [Security Principles](#security-principles)
2. [Network Security](#network-security)
3. [Authentication & Authorization](#authentication--authorization)
4. [Encryption](#encryption)
5. [Container Security](#container-security)
6. [Kubernetes Security](#kubernetes-security)
7. [Database Security](#database-security)
8. [Secrets Management](#secrets-management)
9. [Logging & Monitoring](#logging--monitoring)
10. [Compliance](#compliance)
11. [Security Checklist](#security-checklist)

---

## Security Principles

### Defense in Depth

LLM Data Vault implements multiple security layers:

```
┌─────────────────────────────────────────────────────────────┐
│                     Network Layer                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  TLS Termination                       │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │               Authentication                     │  │  │
│  │  │  ┌───────────────────────────────────────────┐  │  │  │
│  │  │  │             Authorization                  │  │  │  │
│  │  │  │  ┌─────────────────────────────────────┐  │  │  │  │
│  │  │  │  │         Input Validation            │  │  │  │  │
│  │  │  │  │  ┌───────────────────────────────┐  │  │  │  │  │
│  │  │  │  │  │      Encryption at Rest       │  │  │  │  │  │
│  │  │  │  │  │  ┌─────────────────────────┐  │  │  │  │  │  │
│  │  │  │  │  │  │      Your Data          │  │  │  │  │  │  │
│  │  │  │  │  │  └─────────────────────────┘  │  │  │  │  │  │
│  │  │  │  │  └───────────────────────────────┘  │  │  │  │  │
│  │  │  │  └─────────────────────────────────────┘  │  │  │  │
│  │  │  └───────────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Zero Trust Model

- **Never trust, always verify** - Every request must be authenticated
- **Least privilege** - Grant minimum required permissions
- **Assume breach** - Design for compromise scenarios

---

## Network Security

### TLS Configuration

**Required Settings**:
- TLS 1.2 minimum (TLS 1.3 recommended)
- Strong cipher suites only
- Valid certificates from trusted CA

**Ingress TLS Configuration**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vault-server
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
spec:
  tls:
    - hosts:
        - api.yourdomain.com
      secretName: vault-tls
```

### Network Policies

**Restrict ingress to application**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-server-ingress
  namespace: llm-data-vault
spec:
  podSelector:
    matchLabels:
      app: vault-server
  policyTypes:
    - Ingress
  ingress:
    # Only allow from ingress controller
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - port: 8080
          protocol: TCP
    # Allow Prometheus scraping
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - port: 9090
          protocol: TCP
```

**Restrict egress**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-server-egress
  namespace: llm-data-vault
spec:
  podSelector:
    matchLabels:
      app: vault-server
  policyTypes:
    - Egress
  egress:
    # Database
    - to:
        - namespaceSelector:
            matchLabels:
              name: database
      ports:
        - port: 5432
          protocol: TCP
    # Redis
    - to:
        - namespaceSelector:
            matchLabels:
              name: cache
      ports:
        - port: 6379
          protocol: TCP
    # AWS services (S3, KMS)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 443
          protocol: TCP
    # DNS
    - to: []
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

### Web Application Firewall (WAF)

Configure AWS WAF or similar:
```json
{
  "Name": "vault-waf-rules",
  "Rules": [
    {
      "Name": "RateLimit",
      "Priority": 1,
      "Action": { "Block": {} },
      "Statement": {
        "RateBasedStatement": {
          "Limit": 2000,
          "AggregateKeyType": "IP"
        }
      }
    },
    {
      "Name": "SQLInjection",
      "Priority": 2,
      "Action": { "Block": {} },
      "Statement": {
        "SqliMatchStatement": {
          "FieldToMatch": { "Body": {} },
          "TextTransformations": [
            { "Priority": 0, "Type": "URL_DECODE" }
          ]
        }
      }
    },
    {
      "Name": "XSS",
      "Priority": 3,
      "Action": { "Block": {} },
      "Statement": {
        "XssMatchStatement": {
          "FieldToMatch": { "Body": {} },
          "TextTransformations": [
            { "Priority": 0, "Type": "HTML_ENTITY_DECODE" }
          ]
        }
      }
    }
  ]
}
```

---

## Authentication & Authorization

### JWT Security

**Configuration Requirements**:
```toml
# config/production.toml
jwt_secret = "${VAULT__JWT_SECRET}"  # Min 32 chars, use 64+ for production
jwt_issuer = "llm-data-vault"
jwt_audience = "llm-data-vault"
token_expiry_hours = 1              # Short-lived tokens (1 hour max)
refresh_token_days = 7              # Refresh tokens for longer sessions
```

**Best Practices**:
1. Use cryptographically secure random secrets (256+ bits)
2. Rotate JWT secrets periodically (quarterly minimum)
3. Keep access tokens short-lived (1 hour maximum)
4. Implement token revocation for logout
5. Validate all JWT claims (iss, aud, exp, nbf)

**Generate Secure Secret**:
```bash
# Generate 64-character secret
openssl rand -base64 48

# Or using /dev/urandom
head -c 64 /dev/urandom | base64 | tr -d '\n'
```

### API Key Security

```toml
api_key_prefix = "vault_"
api_key_hash_algorithm = "blake3"  # Fast, secure hash
```

**Best Practices**:
1. Hash API keys before storage (never store plaintext)
2. Implement API key rotation
3. Scope API keys to specific operations
4. Set expiration dates on API keys
5. Log all API key usage

### Password Policy

Enforce strong passwords:
```rust
// Minimum requirements (implement in application)
const MIN_PASSWORD_LENGTH: usize = 12;
const REQUIRE_UPPERCASE: bool = true;
const REQUIRE_LOWERCASE: bool = true;
const REQUIRE_DIGIT: bool = true;
const REQUIRE_SPECIAL: bool = true;
const MAX_PASSWORD_AGE_DAYS: u32 = 90;
```

### RBAC Configuration

**Principle of Least Privilege**:
```yaml
# Define roles with minimum required permissions
roles:
  reader:
    permissions:
      - dataset:read
      - record:read

  writer:
    permissions:
      - dataset:read
      - dataset:create
      - record:read
      - record:create
      - record:update

  admin:
    permissions:
      - "*"  # Full access (limit to few users)
```

**Regular Access Reviews**:
- Review user permissions quarterly
- Remove unused accounts
- Audit admin access monthly

---

## Encryption

### Encryption at Rest

**AES-256-GCM Configuration**:
```toml
[encryption]
kms_provider = "aws"  # Use AWS KMS for production
cache_size = 1000     # Cache data keys for performance
cache_ttl_seconds = 300

[encryption.aws]
key_id = "arn:aws:kms:us-east-1:123456789:key/your-key-id"
region = "us-east-1"
```

**AWS KMS Key Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowVaultAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789:role/vault-server-role"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:EncryptionContext:service": "llm-data-vault"
        }
      }
    }
  ]
}
```

### Key Management

1. **Key Rotation**: Enable automatic annual rotation for KMS keys
2. **Key Hierarchy**: Use envelope encryption (master key encrypts data keys)
3. **Key Access**: Audit all key usage via CloudTrail
4. **Backup**: KMS keys are automatically backed up by AWS

### Data in Transit

All connections must use TLS:
- API endpoints: HTTPS only
- Database: SSL/TLS mode `verify-full`
- Redis: TLS enabled
- S3: HTTPS endpoints

```toml
[database]
url = "postgres://user:pass@host:5432/vault?sslmode=verify-full"

[redis]
url = "rediss://redis:6379"  # 'rediss' for TLS
```

---

## Container Security

### Image Security

**Dockerfile Best Practices**:
```dockerfile
# Use minimal base image
FROM gcr.io/distroless/cc-debian12:nonroot

# Don't run as root
USER nonroot:nonroot

# Copy only necessary files
COPY --from=builder /app/target/release/vault-server /vault-server

# No shell, no package manager
ENTRYPOINT ["/vault-server"]
```

**Image Scanning**:
```bash
# Scan with Trivy
trivy image ghcr.io/your-org/llm-data-vault:latest

# Scan with Grype
grype ghcr.io/your-org/llm-data-vault:latest
```

### Runtime Security

**Security Context**:
```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: vault-server
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
```

### Resource Limits

Always set resource limits to prevent DoS:
```yaml
resources:
  requests:
    cpu: "100m"
    memory: "256Mi"
  limits:
    cpu: "1000m"
    memory: "1Gi"
```

---

## Kubernetes Security

### Pod Security Standards

Apply restricted policy:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: llm-data-vault
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### RBAC for Service Accounts

**Minimal Service Account**:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-server
  namespace: llm-data-vault
automountServiceAccountToken: false  # Disable if not needed
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-server
  namespace: llm-data-vault
rules:
  # Only what's absolutely necessary
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-server
  namespace: llm-data-vault
subjects:
  - kind: ServiceAccount
    name: vault-server
roleRef:
  kind: Role
  name: vault-server
  apiGroup: rbac.authorization.k8s.io
```

### Admission Controllers

Enable these admission controllers:
- `PodSecurityAdmission` - Enforce pod security standards
- `ValidatingAdmissionWebhook` - Custom validation
- `MutatingAdmissionWebhook` - Inject sidecars, labels

**OPA Gatekeeper Policy Example**:
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-team-label
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["llm-data-vault"]
  parameters:
    labels: ["team", "environment"]
```

---

## Database Security

### PostgreSQL Hardening

**Connection Security**:
```ini
# postgresql.conf
ssl = on
ssl_cert_file = '/certs/server.crt'
ssl_key_file = '/certs/server.key'
ssl_ca_file = '/certs/ca.crt'
ssl_min_protocol_version = 'TLSv1.2'

# Restrict connections
listen_addresses = '10.0.0.0/8'  # Internal network only
```

**pg_hba.conf**:
```
# TYPE  DATABASE  USER      ADDRESS         METHOD
hostssl vault     vault     10.0.0.0/8      scram-sha-256
hostssl all       all       0.0.0.0/0       reject
```

**User Privileges**:
```sql
-- Application user with minimal privileges
CREATE USER vault WITH PASSWORD 'secure-password';
GRANT CONNECT ON DATABASE vault TO vault;
GRANT USAGE ON SCHEMA public TO vault;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vault;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO vault;

-- No superuser, createdb, or createrole
ALTER USER vault NOSUPERUSER NOCREATEDB NOCREATEROLE;
```

### Connection Pool Security

```toml
[database]
max_connections = 20      # Limit pool size
connect_timeout_seconds = 5
idle_timeout_seconds = 300
```

---

## Secrets Management

### Kubernetes Secrets

**External Secrets Operator** (recommended):
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-secrets
  namespace: llm-data-vault
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: aws-secrets-manager
  target:
    name: vault-secrets
    creationPolicy: Owner
  data:
    - secretKey: jwt-secret
      remoteRef:
        key: llm-data-vault/jwt-secret
    - secretKey: database-url
      remoteRef:
        key: llm-data-vault/database-url
```

### AWS Secrets Manager

```bash
# Store secrets
aws secretsmanager create-secret \
  --name llm-data-vault/jwt-secret \
  --secret-string "$(openssl rand -base64 48)"

# Enable rotation
aws secretsmanager rotate-secret \
  --secret-id llm-data-vault/jwt-secret \
  --rotation-rules AutomaticallyAfterDays=90
```

### Secret Hygiene

1. **Never commit secrets** to version control
2. **Rotate secrets** on schedule and after incidents
3. **Audit secret access** via CloudTrail or equivalent
4. **Use separate secrets** per environment
5. **Encrypt secrets** at rest in secret store

---

## Logging & Monitoring

### Security Logging

**Required Log Events**:
```rust
// Authentication events
log::info!(target: "audit", event = "login_success", user_id = %user_id);
log::warn!(target: "audit", event = "login_failed", email = %email, reason = %reason);

// Authorization events
log::warn!(target: "audit", event = "access_denied", user_id = %user_id, resource = %resource);

// Data access
log::info!(target: "audit", event = "data_read", user_id = %user_id, dataset_id = %id);
log::info!(target: "audit", event = "data_write", user_id = %user_id, dataset_id = %id);

// Administrative actions
log::info!(target: "audit", event = "user_created", admin_id = %admin, new_user_id = %user);
log::info!(target: "audit", event = "role_assigned", admin_id = %admin, user_id = %user, role = %role);
```

**Log Retention**:
- Security logs: 1 year minimum (compliance requirement)
- Application logs: 90 days
- Access logs: 1 year

### Security Monitoring

**Prometheus Alerts**:
```yaml
groups:
  - name: security
    rules:
      - alert: HighAuthenticationFailureRate
        expr: |
          sum(rate(auth_failures_total[5m])) /
          sum(rate(auth_attempts_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High authentication failure rate
          description: >
            Authentication failure rate is {{ $value | humanizePercentage }}

      - alert: UnauthorizedAccessAttempts
        expr: sum(rate(authorization_denied_total[5m])) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High rate of unauthorized access attempts

      - alert: SuspiciousIPActivity
        expr: |
          count by (client_ip) (rate(http_requests_total[5m])) > 1000
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: Suspicious activity from IP {{ $labels.client_ip }}
```

### SIEM Integration

Export logs to SIEM (Splunk, Elastic, etc.):
```yaml
# Fluent Bit configuration
[OUTPUT]
    Name        splunk
    Match       audit.*
    Host        splunk.example.com
    Port        8088
    TLS         On
    Splunk_Token ${SPLUNK_TOKEN}
```

---

## Compliance

### GDPR Requirements

| Requirement | Implementation |
|-------------|----------------|
| Data minimization | Only collect necessary PII |
| Purpose limitation | Document data usage purposes |
| Storage limitation | Implement data retention policies |
| Integrity & confidentiality | AES-256 encryption |
| Right to erasure | Implement DELETE /users/{id}/data |
| Data portability | Export API endpoint |
| Breach notification | Alerting + incident response |

### HIPAA Requirements

| Requirement | Implementation |
|-------------|----------------|
| Access controls | RBAC + ABAC |
| Audit controls | Comprehensive logging |
| Integrity controls | Content hashing |
| Transmission security | TLS 1.2+ everywhere |
| Encryption | AES-256-GCM |

### SOC 2 Controls

| Control | Implementation |
|---------|----------------|
| CC6.1 Logical access | JWT authentication, RBAC |
| CC6.2 Auth mechanisms | Strong passwords, MFA-ready |
| CC6.3 Role-based access | RBAC system |
| CC6.6 Output protection | Encryption at rest |
| CC6.7 Data transmission | TLS encryption |
| CC7.2 Monitoring | Prometheus + alerting |

---

## Security Checklist

### Pre-Deployment

- [ ] TLS certificates installed and valid
- [ ] JWT secret is cryptographically secure (64+ characters)
- [ ] Database credentials rotated from defaults
- [ ] API keys hashed before storage
- [ ] Network policies applied
- [ ] Pod security standards enforced
- [ ] Resource limits configured
- [ ] Security context with non-root user
- [ ] Read-only root filesystem
- [ ] Image vulnerability scan passed

### Post-Deployment

- [ ] Health endpoints accessible (not publicly)
- [ ] Metrics endpoint secured
- [ ] Audit logging enabled
- [ ] Security alerts configured
- [ ] Penetration test scheduled
- [ ] Incident response plan documented
- [ ] Backup encryption verified
- [ ] Secret rotation scheduled

### Ongoing

- [ ] Weekly vulnerability scans
- [ ] Monthly access reviews
- [ ] Quarterly secret rotation
- [ ] Annual penetration test
- [ ] Annual compliance audit

---

## Incident Response

### Security Incident Procedure

1. **Detect**: Monitor alerts, logs, user reports
2. **Contain**: Isolate affected systems
3. **Eradicate**: Remove threat
4. **Recover**: Restore services
5. **Learn**: Post-incident review

### Emergency Contacts

| Role | Contact | Response Time |
|------|---------|---------------|
| Security Team | security@example.com | 1 hour |
| On-Call Engineer | PagerDuty | 15 minutes |
| CISO | ciso@example.com | 4 hours |
| Legal | legal@example.com | 24 hours |

### Breach Notification

Per GDPR Article 33: Notify supervisory authority within 72 hours of breach discovery.

---

## See Also

- [Configuration Reference](../deployment/CONFIGURATION.md)
- [Operations Runbook](../operations/RUNBOOK.md)
- [Kubernetes Deployment](../deployment/KUBERNETES.md)
