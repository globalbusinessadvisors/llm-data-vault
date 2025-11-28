# Kubernetes Deployment Guide

This guide covers deploying LLM Data Vault to Kubernetes in production.

## Prerequisites

- Kubernetes cluster 1.25+
- kubectl configured
- Helm 3.x (optional)
- PostgreSQL 15+
- Redis 7+
- AWS credentials (for S3/KMS)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Ingress Controller                │   │
│  │                  (TLS Termination)                   │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                   │
│  ┌───────────────────────┼─────────────────────────────┐   │
│  │                 Service (ClusterIP)                  │   │
│  └───────────────────────┬─────────────────────────────┘   │
│                          │                                   │
│  ┌───────────────────────┼─────────────────────────────┐   │
│  │              Deployment (3+ replicas)                │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐               │   │
│  │  │  Pod 1  │ │  Pod 2  │ │  Pod 3  │    ...        │   │
│  │  └─────────┘ └─────────┘ └─────────┘               │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                   │
│         ┌────────────────┼────────────────┐                 │
│         ▼                ▼                ▼                 │
│  ┌───────────┐    ┌───────────┐    ┌───────────┐          │
│  │ PostgreSQL│    │   Redis   │    │    S3     │          │
│  │ (Metadata)│    │  (Cache)  │    │ (Content) │          │
│  └───────────┘    └───────────┘    └───────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Create Namespace

```bash
kubectl create namespace llm-data-vault
```

### 2. Create Secrets

```bash
# Generate a secure JWT secret
JWT_SECRET=$(openssl rand -base64 32)

# Create secrets
kubectl create secret generic vault-secrets \
  --namespace llm-data-vault \
  --from-literal=jwt-secret="$JWT_SECRET" \
  --from-literal=database-url="postgres://user:password@postgres:5432/vault" \
  --from-literal=redis-url="redis://redis:6379" \
  --from-literal=aws-access-key-id="YOUR_ACCESS_KEY" \
  --from-literal=aws-secret-access-key="YOUR_SECRET_KEY"
```

### 3. Deploy

```bash
kubectl apply -f deploy/kubernetes/ -n llm-data-vault
```

### 4. Verify Deployment

```bash
# Check pods
kubectl get pods -n llm-data-vault

# Check deployment status
kubectl rollout status deployment/vault-server -n llm-data-vault

# Check logs
kubectl logs -l app=vault-server -n llm-data-vault --tail=100

# Test health endpoint
kubectl port-forward svc/vault-server 8080:8080 -n llm-data-vault
curl http://localhost:8080/health/ready
```

## Production Configuration

### Resource Allocation

The default configuration provides:

| Resource | Request | Limit |
|----------|---------|-------|
| CPU | 100m | 1000m |
| Memory | 256Mi | 1Gi |

Adjust based on your workload:

```yaml
# deploy/kubernetes/deployment.yaml
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2000m"
    memory: "2Gi"
```

### Replica Count

**Minimum Production**: 3 replicas
**Recommended**: Scale based on traffic

```yaml
spec:
  replicas: 3
```

### Horizontal Pod Autoscaler

The HPA is configured to scale between 3-20 pods:

```yaml
# deploy/kubernetes/hpa.yaml
spec:
  minReplicas: 3
  maxReplicas: 20
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
```

### Pod Disruption Budget

Ensures minimum availability during updates:

```yaml
# deploy/kubernetes/pdb.yaml
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: vault-server
```

## Environment Configuration

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-config
  namespace: llm-data-vault
data:
  VAULT__HOST: "0.0.0.0"
  VAULT__PORT: "8080"
  VAULT__LOG_LEVEL: "info"
  VAULT__STORAGE__BACKEND: "s3"
  VAULT__STORAGE__S3__REGION: "us-east-1"
  VAULT__STORAGE__S3__BUCKET: "llm-data-vault-prod"
  VAULT__TELEMETRY__ENABLE_METRICS: "true"
  VAULT__TELEMETRY__ENABLE_TRACING: "true"
  VAULT__TELEMETRY__METRICS_PORT: "9090"
  VAULT__RATE_LIMIT_RPS: "100"
  VAULT__RATE_LIMIT_BURST: "200"
```

### Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-secrets
  namespace: llm-data-vault
type: Opaque
stringData:
  jwt-secret: "your-secure-jwt-secret-min-32-characters"
  database-url: "postgres://user:password@postgres.db.svc:5432/vault"
  redis-url: "redis://redis.cache.svc:6379"
  aws-access-key-id: "AKIAXXXXXXXXXXXXXXXX"
  aws-secret-access-key: "your-secret-key"
```

## Storage Configuration

### PostgreSQL

For metadata storage, use a managed PostgreSQL service or deploy in-cluster:

```yaml
# Example: AWS RDS
VAULT__DATABASE__URL: "postgres://user:pass@rds-endpoint.region.rds.amazonaws.com:5432/vault?sslmode=require"
VAULT__DATABASE__MAX_CONNECTIONS: "20"
VAULT__DATABASE__MIN_CONNECTIONS: "5"
```

### Redis

For caching and rate limiting:

```yaml
# Example: AWS ElastiCache
VAULT__REDIS__URL: "redis://elasticache-endpoint.cache.amazonaws.com:6379"
```

### S3

For content storage:

```yaml
VAULT__STORAGE__BACKEND: "s3"
VAULT__STORAGE__S3__BUCKET: "llm-data-vault-production"
VAULT__STORAGE__S3__REGION: "us-east-1"
VAULT__STORAGE__S3__PREFIX: "data/"
```

## Networking

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: vault-server
  namespace: llm-data-vault
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
    prometheus.io/path: "/metrics"
spec:
  type: ClusterIP
  ports:
    - name: http
      port: 8080
      targetPort: 8080
    - name: metrics
      port: 9090
      targetPort: 9090
  selector:
    app: vault-server
```

### Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vault-server
  namespace: llm-data-vault
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
spec:
  tls:
    - hosts:
        - api.yourdomain.com
      secretName: vault-tls
  rules:
    - host: api.yourdomain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: vault-server
                port:
                  number: 8080
```

### Network Policies

Restrict traffic to essential connections:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-server
  namespace: llm-data-vault
spec:
  podSelector:
    matchLabels:
      app: vault-server
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - port: 8080
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - port: 9090
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: database
      ports:
        - port: 5432
    - to:
        - namespaceSelector:
            matchLabels:
              name: cache
      ports:
        - port: 6379
    - to:  # AWS services
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - port: 443
```

## Security

### Security Context

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
        - name: vault-server
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

### Pod Security Standards

Apply restricted policy:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: llm-data-vault
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-server
  namespace: llm-data-vault
  annotations:
    # For AWS IRSA
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/vault-server-role
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-server
  namespace: llm-data-vault
rules:
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

## Health Checks

### Probes Configuration

```yaml
spec:
  containers:
    - name: vault-server
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
        failureThreshold: 3
      startupProbe:
        httpGet:
          path: /health/live
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 5
        failureThreshold: 30
```

## Monitoring

### Prometheus ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vault-server
  namespace: llm-data-vault
spec:
  selector:
    matchLabels:
      app: vault-server
  endpoints:
    - port: metrics
      interval: 15s
      path: /metrics
```

### Grafana Dashboard

Import the dashboard from `monitoring/dashboards/overview.json`.

## Updates and Rollbacks

### Rolling Update Strategy

```yaml
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
```

### Performing Updates

```bash
# Update image
kubectl set image deployment/vault-server \
  vault-server=ghcr.io/your-org/llm-data-vault:v1.1.0 \
  -n llm-data-vault

# Watch rollout
kubectl rollout status deployment/vault-server -n llm-data-vault

# Rollback if needed
kubectl rollout undo deployment/vault-server -n llm-data-vault
```

### Blue-Green Deployment

For zero-downtime deployments:

```bash
# Deploy new version
kubectl apply -f deploy/kubernetes/deployment-v2.yaml -n llm-data-vault

# Verify health
kubectl rollout status deployment/vault-server-v2 -n llm-data-vault

# Switch traffic
kubectl patch service vault-server -p '{"spec":{"selector":{"version":"v2"}}}' -n llm-data-vault

# Remove old version
kubectl delete deployment vault-server-v1 -n llm-data-vault
```

## Troubleshooting

### Common Issues

**Pods not starting:**
```bash
kubectl describe pod -l app=vault-server -n llm-data-vault
kubectl logs -l app=vault-server -n llm-data-vault --previous
```

**Database connection issues:**
```bash
# Check database connectivity
kubectl run -it --rm debug --image=postgres:15 -n llm-data-vault -- \
  psql "postgres://user:pass@postgres:5432/vault"
```

**Memory issues:**
```bash
# Check resource usage
kubectl top pods -n llm-data-vault
```

**Health check failures:**
```bash
# Check health endpoints
kubectl exec -it deployment/vault-server -n llm-data-vault -- \
  curl -s http://localhost:8080/health/detailed | jq
```

### Debug Mode

Enable debug logging:

```yaml
env:
  - name: VAULT__LOG_LEVEL
    value: "debug"
  - name: RUST_BACKTRACE
    value: "1"
```

## Backup and Recovery

### Database Backup

```bash
# Create backup
kubectl exec -it postgres-0 -n database -- \
  pg_dump -U user vault > backup.sql

# Restore
kubectl exec -i postgres-0 -n database -- \
  psql -U user vault < backup.sql
```

### S3 Data Backup

Enable S3 versioning and cross-region replication for data durability.

## Multi-Region Deployment

For high availability across regions:

1. Deploy to multiple clusters
2. Use Global Accelerator or CloudFront for routing
3. Configure cross-region database replication
4. Use S3 Cross-Region Replication

## Cost Optimization

### Right-sizing

Monitor actual usage and adjust resources:

```bash
# View resource recommendations
kubectl top pods -n llm-data-vault
```

### Spot Instances

Use spot/preemptible nodes for non-critical workloads:

```yaml
spec:
  template:
    spec:
      nodeSelector:
        node-type: spot
      tolerations:
        - key: "spot"
          operator: "Equal"
          value: "true"
          effect: "NoSchedule"
```

## Next Steps

1. [Configure monitoring and alerting](../operations/MONITORING.md)
2. [Set up CI/CD pipeline](../operations/CICD.md)
3. [Review security hardening](../security/HARDENING.md)
