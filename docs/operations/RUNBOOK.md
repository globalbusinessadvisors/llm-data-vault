# Operations Runbook

This runbook provides operational procedures for LLM Data Vault in production environments.

## Table of Contents

1. [System Overview](#system-overview)
2. [Startup and Shutdown](#startup-and-shutdown)
3. [Health Monitoring](#health-monitoring)
4. [Common Operations](#common-operations)
5. [Incident Response](#incident-response)
6. [Troubleshooting](#troubleshooting)
7. [Backup and Recovery](#backup-and-recovery)
8. [Scaling](#scaling)
9. [Security Operations](#security-operations)
10. [Maintenance Windows](#maintenance-windows)

---

## System Overview

### Components

| Component | Purpose | Port | Health Endpoint |
|-----------|---------|------|-----------------|
| Vault Server | Main API service | 8080 | `/health` |
| Metrics Server | Prometheus metrics | 9090 | `/metrics` |
| PostgreSQL | Metadata storage | 5432 | pg_isready |
| Redis | Caching & rate limiting | 6379 | PING |
| S3 | Content storage | 443 | AWS health |

### Dependencies

```
┌─────────────────┐
│  Vault Server   │
└────────┬────────┘
         │
    ┌────┴────┬──────────┐
    ▼         ▼          ▼
┌───────┐ ┌───────┐ ┌─────────┐
│Postgres│ │ Redis │ │   S3    │
└───────┘ └───────┘ └─────────┘
```

### Critical Paths

1. **Authentication**: Vault Server → PostgreSQL (user lookup) → JWT signing
2. **Data Storage**: Vault Server → Encryption → S3
3. **PII Detection**: Vault Server → In-process regex engine
4. **Rate Limiting**: Vault Server → Redis

---

## Startup and Shutdown

### Startup Sequence

```bash
# 1. Verify dependencies are healthy
kubectl get pods -n database
kubectl get pods -n cache

# 2. Check secrets exist
kubectl get secret vault-secrets -n llm-data-vault

# 3. Scale up deployment
kubectl scale deployment vault-server --replicas=3 -n llm-data-vault

# 4. Monitor rollout
kubectl rollout status deployment/vault-server -n llm-data-vault

# 5. Verify health
for pod in $(kubectl get pods -l app=vault-server -n llm-data-vault -o name); do
  kubectl exec $pod -n llm-data-vault -- curl -s http://localhost:8080/health/ready
done
```

### Graceful Shutdown

```bash
# 1. Scale down gradually
kubectl scale deployment vault-server --replicas=1 -n llm-data-vault

# 2. Wait for connections to drain (terminationGracePeriodSeconds)
kubectl rollout status deployment/vault-server -n llm-data-vault

# 3. Scale to zero
kubectl scale deployment vault-server --replicas=0 -n llm-data-vault
```

### Emergency Shutdown

```bash
# Immediate shutdown (may drop in-flight requests)
kubectl delete deployment vault-server -n llm-data-vault
```

---

## Health Monitoring

### Health Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `GET /health` | Basic liveness | `{"status": "healthy"}` |
| `GET /health/live` | Kubernetes liveness probe | `{"status": "ok"}` |
| `GET /health/ready` | Kubernetes readiness probe | `{"status": "ready"}` |
| `GET /health/detailed` | Component status | Full component health |

### Manual Health Check

```bash
# Basic health
curl -s http://vault-server:8080/health | jq

# Detailed health
curl -s http://vault-server:8080/health/detailed | jq

# Example response
{
  "status": "healthy",
  "version": "1.0.0",
  "components": {
    "database": {"status": "healthy", "latency_ms": 2},
    "redis": {"status": "healthy", "latency_ms": 1},
    "storage": {"status": "healthy"}
  }
}
```

### Key Metrics to Monitor

```promql
# Request rate
sum(rate(http_requests_total[5m])) by (method, path)

# Error rate
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))

# Latency (p99)
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))

# Active connections
http_requests_active

# Database pool
db_connections_active
db_connections_idle

# Memory usage
process_resident_memory_bytes
```

### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Error rate | > 1% | > 5% |
| P99 latency | > 500ms | > 2s |
| CPU usage | > 70% | > 90% |
| Memory usage | > 80% | > 95% |
| DB connections | > 80% pool | > 95% pool |

---

## Common Operations

### Viewing Logs

```bash
# All pods
kubectl logs -l app=vault-server -n llm-data-vault --tail=100

# Specific pod
kubectl logs vault-server-abc123 -n llm-data-vault

# Follow logs
kubectl logs -f -l app=vault-server -n llm-data-vault

# Previous container (after crash)
kubectl logs vault-server-abc123 -n llm-data-vault --previous

# Filter by level (if using structured logging)
kubectl logs -l app=vault-server -n llm-data-vault | jq 'select(.level == "error")'
```

### Checking Resource Usage

```bash
# Pod resources
kubectl top pods -n llm-data-vault

# Node resources
kubectl top nodes

# Detailed pod info
kubectl describe pod -l app=vault-server -n llm-data-vault
```

### Restarting Services

```bash
# Rolling restart (zero-downtime)
kubectl rollout restart deployment/vault-server -n llm-data-vault

# Force restart specific pod
kubectl delete pod vault-server-abc123 -n llm-data-vault

# Restart with new config
kubectl apply -f deploy/kubernetes/configmap.yaml -n llm-data-vault
kubectl rollout restart deployment/vault-server -n llm-data-vault
```

### Updating Configuration

```bash
# 1. Update ConfigMap
kubectl edit configmap vault-config -n llm-data-vault

# Or apply from file
kubectl apply -f deploy/kubernetes/configmap.yaml -n llm-data-vault

# 2. Restart to pick up changes
kubectl rollout restart deployment/vault-server -n llm-data-vault

# 3. Verify new config
kubectl exec -it deployment/vault-server -n llm-data-vault -- \
  env | grep VAULT__
```

### Rotating Secrets

```bash
# 1. Generate new JWT secret
NEW_SECRET=$(openssl rand -base64 32)

# 2. Update secret
kubectl create secret generic vault-secrets \
  --namespace llm-data-vault \
  --from-literal=jwt-secret="$NEW_SECRET" \
  --from-literal=database-url="$(kubectl get secret vault-secrets -n llm-data-vault -o jsonpath='{.data.database-url}' | base64 -d)" \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Rolling restart
kubectl rollout restart deployment/vault-server -n llm-data-vault

# NOTE: Existing JWTs will become invalid after rotation
```

---

## Incident Response

### Severity Levels

| Level | Description | Response Time | Escalation |
|-------|-------------|---------------|------------|
| SEV1 | Complete outage | 15 min | Immediate page |
| SEV2 | Partial outage | 30 min | Page on-call |
| SEV3 | Degraded service | 2 hours | Slack alert |
| SEV4 | Minor issue | Next business day | Ticket |

### SEV1: Complete Outage

**Symptoms**: All health checks failing, no successful requests

**Immediate Actions**:
```bash
# 1. Check pod status
kubectl get pods -n llm-data-vault

# 2. Check events
kubectl get events -n llm-data-vault --sort-by=.lastTimestamp

# 3. Check logs
kubectl logs -l app=vault-server -n llm-data-vault --tail=500

# 4. Check dependencies
kubectl exec -it deployment/vault-server -n llm-data-vault -- \
  curl -s http://postgres:5432 || echo "DB unreachable"

# 5. If pods crashing, check resource limits
kubectl describe pod -l app=vault-server -n llm-data-vault | grep -A5 "Last State"
```

**Common Causes**:
- Database unreachable → Check PostgreSQL status
- Invalid configuration → Check recent config changes
- Resource exhaustion → Increase limits or scale
- Certificate expiration → Renew TLS certificates

### SEV2: High Error Rate

**Symptoms**: Error rate > 5%, some requests succeeding

**Immediate Actions**:
```bash
# 1. Check error distribution
kubectl logs -l app=vault-server -n llm-data-vault | \
  jq 'select(.level == "error")' | head -50

# 2. Check specific error types
kubectl logs -l app=vault-server -n llm-data-vault | \
  jq 'select(.level == "error") | .error' | sort | uniq -c

# 3. Check if specific endpoints affected
# (via Prometheus or logs)

# 4. Check rate limiting
kubectl exec -it deployment/vault-server -n llm-data-vault -- \
  redis-cli -h redis GET rate_limit_status
```

### SEV3: High Latency

**Symptoms**: P99 > 2s, but requests succeeding

**Immediate Actions**:
```bash
# 1. Check database latency
kubectl exec -it deployment/vault-server -n llm-data-vault -- \
  curl -s http://localhost:8080/health/detailed | jq '.components.database'

# 2. Check connection pool saturation
# (via metrics)

# 3. Check for slow queries
kubectl exec -it postgres-0 -n database -- \
  psql -U vault -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"

# 4. Consider scaling
kubectl scale deployment vault-server --replicas=5 -n llm-data-vault
```

### Post-Incident

1. **Document timeline** of events and actions taken
2. **Root cause analysis** within 48 hours
3. **Action items** to prevent recurrence
4. **Update runbook** with new procedures if needed

---

## Troubleshooting

### Pod Won't Start

```bash
# Check events
kubectl describe pod <pod-name> -n llm-data-vault

# Common issues:
# - ImagePullBackOff: Check image name and registry credentials
# - CrashLoopBackOff: Check logs with --previous flag
# - Pending: Check resource availability and node selectors
```

### Database Connection Failures

```bash
# Test connectivity
kubectl run -it --rm debug --image=postgres:15 -n llm-data-vault -- \
  psql "$DATABASE_URL"

# Check connection count
kubectl exec -it postgres-0 -n database -- \
  psql -U vault -c "SELECT count(*) FROM pg_stat_activity;"

# Check for locks
kubectl exec -it postgres-0 -n database -- \
  psql -U vault -c "SELECT * FROM pg_locks WHERE NOT granted;"
```

### Memory Issues

```bash
# Check current usage
kubectl top pod -l app=vault-server -n llm-data-vault

# Check for OOMKilled
kubectl describe pod -l app=vault-server -n llm-data-vault | grep -i oom

# Increase limits if needed
kubectl patch deployment vault-server -n llm-data-vault \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"vault-server","resources":{"limits":{"memory":"2Gi"}}}]}}}}'
```

### Authentication Failures

```bash
# Check JWT secret is set
kubectl get secret vault-secrets -n llm-data-vault -o jsonpath='{.data.jwt-secret}' | base64 -d | wc -c
# Should be >= 32 characters

# Test token generation (if API accessible)
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test"}'

# Check clock skew (JWT validation is time-sensitive)
kubectl exec -it deployment/vault-server -n llm-data-vault -- date
```

### S3 Access Issues

```bash
# Check AWS credentials
kubectl exec -it deployment/vault-server -n llm-data-vault -- \
  env | grep AWS

# Test S3 connectivity
kubectl run -it --rm aws-cli --image=amazon/aws-cli -n llm-data-vault -- \
  s3 ls s3://your-bucket/

# Check IAM role (if using IRSA)
kubectl describe serviceaccount vault-server -n llm-data-vault
```

---

## Backup and Recovery

### Database Backup

**Automated Backup** (recommended):
```bash
# Create CronJob for daily backups
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: database
spec:
  schedule: "0 2 * * *"  # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15
            command:
            - /bin/sh
            - -c
            - |
              pg_dump -h postgres -U vault vault | \
              gzip | \
              aws s3 cp - s3://backups/postgres/vault-\$(date +%Y%m%d).sql.gz
          restartPolicy: OnFailure
EOF
```

**Manual Backup**:
```bash
# Create backup
kubectl exec -it postgres-0 -n database -- \
  pg_dump -U vault vault > backup-$(date +%Y%m%d).sql

# Copy to local machine
kubectl cp database/postgres-0:backup-20240101.sql ./backup-20240101.sql
```

### Database Recovery

```bash
# 1. Stop application
kubectl scale deployment vault-server --replicas=0 -n llm-data-vault

# 2. Restore database
kubectl exec -i postgres-0 -n database -- \
  psql -U vault vault < backup-20240101.sql

# 3. Restart application
kubectl scale deployment vault-server --replicas=3 -n llm-data-vault

# 4. Verify data
curl http://localhost:8080/api/v1/datasets \
  -H "Authorization: Bearer $TOKEN"
```

### S3 Data Recovery

```bash
# List available versions (if versioning enabled)
aws s3api list-object-versions --bucket your-bucket --prefix data/

# Restore specific version
aws s3api get-object --bucket your-bucket --key data/object-id \
  --version-id "version-id" restored-object

# Cross-region recovery (if replication configured)
aws s3 sync s3://backup-bucket-us-west-2/ s3://primary-bucket-us-east-1/
```

### Disaster Recovery Procedure

1. **Assess damage** - Determine what's affected
2. **Activate DR site** (if multi-region)
3. **Restore database** from latest backup
4. **Verify S3 data** accessibility
5. **Update DNS** to point to DR site
6. **Verify functionality** with smoke tests
7. **Notify stakeholders**

---

## Scaling

### Horizontal Scaling

```bash
# Manual scaling
kubectl scale deployment vault-server --replicas=5 -n llm-data-vault

# Verify HPA is working
kubectl get hpa -n llm-data-vault

# Check current scale
kubectl get deployment vault-server -n llm-data-vault
```

### Vertical Scaling

```bash
# Update resource limits
kubectl patch deployment vault-server -n llm-data-vault -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "vault-server",
          "resources": {
            "requests": {"cpu": "500m", "memory": "512Mi"},
            "limits": {"cpu": "2000m", "memory": "2Gi"}
          }
        }]
      }
    }
  }
}'
```

### Database Scaling

```bash
# Increase connection pool (application side)
kubectl edit configmap vault-config -n llm-data-vault
# Set VAULT__DATABASE__MAX_CONNECTIONS=30

# Scale database (if using managed service)
# - AWS RDS: Modify instance class
# - In-cluster: Add read replicas
```

### Scaling Checklist

- [ ] Check current resource utilization
- [ ] Verify database can handle additional connections
- [ ] Ensure Redis can handle increased rate limiting load
- [ ] Update HPA limits if scaling beyond current max
- [ ] Monitor after scaling for 30 minutes
- [ ] Update capacity planning documents

---

## Security Operations

### Audit Log Review

```bash
# View authentication events
kubectl logs -l app=vault-server -n llm-data-vault | \
  jq 'select(.event_type == "authentication")'

# View authorization failures
kubectl logs -l app=vault-server -n llm-data-vault | \
  jq 'select(.event_type == "authorization" and .result == "denied")'

# Export audit logs to S3
kubectl logs -l app=vault-server -n llm-data-vault | \
  gzip | aws s3 cp - s3://audit-logs/$(date +%Y%m%d).json.gz
```

### Security Incident Response

1. **Contain**: Revoke compromised credentials immediately
   ```bash
   # Rotate JWT secret (invalidates all tokens)
   kubectl create secret generic vault-secrets \
     --from-literal=jwt-secret="$(openssl rand -base64 32)" \
     --dry-run=client -o yaml | kubectl apply -f -
   kubectl rollout restart deployment/vault-server -n llm-data-vault
   ```

2. **Investigate**: Review audit logs for unauthorized access
   ```bash
   # Export logs for analysis
   kubectl logs -l app=vault-server -n llm-data-vault --since=24h > incident-logs.json
   ```

3. **Remediate**: Fix vulnerability and update security controls

4. **Report**: Document incident and notify affected parties

### Certificate Rotation

```bash
# Check certificate expiration
kubectl get secret vault-tls -n llm-data-vault -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -noout -enddate

# Renew with cert-manager (automatic)
kubectl delete certificate vault-server -n llm-data-vault
# cert-manager will automatically create new certificate

# Manual renewal
kubectl create secret tls vault-tls \
  --cert=new-cert.pem \
  --key=new-key.pem \
  -n llm-data-vault \
  --dry-run=client -o yaml | kubectl apply -f -
```

---

## Maintenance Windows

### Pre-Maintenance Checklist

- [ ] Notify stakeholders 24 hours in advance
- [ ] Create database backup
- [ ] Document current state (versions, replica count)
- [ ] Prepare rollback plan
- [ ] Schedule maintenance in low-traffic period

### During Maintenance

```bash
# 1. Enable maintenance mode (if applicable)
kubectl annotate deployment vault-server maintenance=true -n llm-data-vault

# 2. Perform maintenance tasks
# ...

# 3. Verify system health
kubectl rollout status deployment/vault-server -n llm-data-vault
curl http://localhost:8080/health/detailed

# 4. Disable maintenance mode
kubectl annotate deployment vault-server maintenance- -n llm-data-vault
```

### Post-Maintenance

- [ ] Verify all health checks pass
- [ ] Run smoke tests
- [ ] Check error rates in monitoring
- [ ] Send completion notification
- [ ] Document any issues encountered

### Version Upgrades

```bash
# 1. Review release notes and breaking changes

# 2. Test in staging environment first

# 3. Create backup
kubectl exec -it postgres-0 -n database -- pg_dump -U vault vault > pre-upgrade-backup.sql

# 4. Update image
kubectl set image deployment/vault-server \
  vault-server=ghcr.io/your-org/llm-data-vault:v1.2.0 \
  -n llm-data-vault

# 5. Monitor rollout
kubectl rollout status deployment/vault-server -n llm-data-vault

# 6. Run database migrations (if needed)
kubectl exec -it deployment/vault-server -n llm-data-vault -- \
  vault-server migrate

# 7. Verify functionality
./scripts/smoke-test.sh
```

---

## Appendix

### Useful Commands Quick Reference

```bash
# Pod status
kubectl get pods -n llm-data-vault

# Logs
kubectl logs -l app=vault-server -n llm-data-vault --tail=100

# Restart
kubectl rollout restart deployment/vault-server -n llm-data-vault

# Scale
kubectl scale deployment vault-server --replicas=5 -n llm-data-vault

# Health check
curl http://localhost:8080/health/detailed

# Port forward
kubectl port-forward svc/vault-server 8080:8080 -n llm-data-vault
```

### Contact Information

| Role | Contact | Escalation |
|------|---------|------------|
| On-Call Engineer | PagerDuty | Automatic |
| Platform Team | #platform-team | Slack |
| Security Team | security@example.com | Email/Slack |
| Database Admin | #database-team | Slack |

### Related Documentation

- [Configuration Reference](../deployment/CONFIGURATION.md)
- [Kubernetes Deployment](../deployment/KUBERNETES.md)
- [Security Hardening](../security/HARDENING.md)
- [Architecture Overview](../architecture/OVERVIEW.md)
