# Helm Chart - Complete Deployment Package

**Document:** 06-helm-chart.md
**Version:** 1.0.0
**Phase:** SPARC - Completion
**Last Updated:** 2025-11-27
**Status:** Ready for Implementation

---

## Table of Contents

1. [Chart Structure](#1-chart-structure)
2. [Chart.yaml](#2-chartyaml)
3. [values.yaml](#3-valuesyaml)
4. [_helpers.tpl](#4-_helperstpl)
5. [Template Files](#5-template-files)
6. [Environment Overrides](#6-environment-overrides)
7. [Test Templates](#7-test-templates)
8. [Installation Guide](#8-installation-guide)

---

## 1. Chart Structure

### 1.1 Directory Layout

```
charts/llm-data-vault/
├── Chart.yaml                      # Chart metadata and dependencies
├── values.yaml                     # Default configuration values
├── values-dev.yaml                 # Development environment overrides
├── values-staging.yaml             # Staging environment overrides
├── values-prod.yaml                # Production environment overrides
├── README.md                       # Chart documentation
├── .helmignore                     # Files to ignore during packaging
├── templates/
│   ├── NOTES.txt                   # Post-install instructions
│   ├── _helpers.tpl                # Template helper functions
│   ├── serviceaccount.yaml         # Service account for pods
│   ├── configmap.yaml              # Application configuration
│   ├── secret.yaml                 # Sensitive configuration
│   ├── deployment.yaml             # Main application deployment
│   ├── service.yaml                # Service for API access
│   ├── ingress.yaml                # Ingress/route configuration
│   ├── hpa.yaml                    # Horizontal Pod Autoscaler
│   ├── pdb.yaml                    # Pod Disruption Budget
│   ├── networkpolicy.yaml          # Network isolation rules
│   ├── servicemonitor.yaml         # Prometheus monitoring
│   ├── cronjob-backup.yaml         # Backup jobs
│   ├── cronjob-compliance.yaml     # Compliance reporting jobs
│   └── tests/
│       ├── test-connection.yaml    # Helm test for connectivity
│       └── test-healthcheck.yaml   # Helm test for health endpoints
└── crds/                           # Custom Resource Definitions (if any)
```

---

## 2. Chart.yaml

### 2.1 Chart Metadata

```yaml
# charts/llm-data-vault/Chart.yaml
apiVersion: v2
name: llm-data-vault
description: Secure, enterprise-grade storage and anonymization layer for LLM data management
type: application
version: 1.0.0
appVersion: "1.0.0"

keywords:
  - llm
  - data-vault
  - privacy
  - anonymization
  - pii-detection
  - encryption
  - compliance

home: https://github.com/your-org/llm-data-vault
sources:
  - https://github.com/your-org/llm-data-vault

maintainers:
  - name: LLM DevOps Team
    email: devops@example.com
    url: https://example.com

icon: https://example.com/llm-data-vault-icon.png

# Dependencies - sub-charts for data layer
dependencies:
  - name: postgresql
    version: "12.12.10"
    repository: https://charts.bitnami.com/bitnami
    condition: postgresql.enabled
    tags:
      - database

  - name: redis
    version: "18.6.1"
    repository: https://charts.bitnami.com/bitnami
    condition: redis.enabled
    tags:
      - cache

  - name: minio
    version: "5.0.15"
    repository: https://charts.min.io/
    condition: minio.enabled
    tags:
      - storage

# Annotations for Artifact Hub
annotations:
  artifacthub.io/category: ai-ml
  artifacthub.io/license: MIT
  artifacthub.io/links: |
    - name: Documentation
      url: https://docs.example.com/llm-data-vault
    - name: Support
      url: https://github.com/your-org/llm-data-vault/issues
  artifacthub.io/changes: |
    - kind: added
      description: Initial release with core anonymization features
    - kind: added
      description: RBAC and ABAC access control
    - kind: added
      description: Dataset versioning and lineage tracking
  artifacthub.io/containsSecurityUpdates: "false"
  artifacthub.io/prerelease: "false"
  artifacthub.io/recommendations: |
    - url: https://artifacthub.io/packages/helm/prometheus-community/kube-prometheus-stack
    - url: https://artifacthub.io/packages/helm/istio/istiod
  artifacthub.io/screenshots: |
    - title: Dashboard Overview
      url: https://example.com/screenshots/dashboard.png
```

---

## 3. values.yaml

### 3.1 Complete Default Values

```yaml
# charts/llm-data-vault/values.yaml

# Global configuration shared across all sub-charts
global:
  # Kubernetes cluster domain
  clusterDomain: cluster.local

  # Image pull secrets for private registries
  imagePullSecrets: []
  # - name: regcred

  # Storage class for persistent volumes
  storageClass: ""

  # Time zone for all containers
  timezone: "UTC"

# Application image configuration
image:
  registry: ghcr.io
  repository: your-org/llm-data-vault
  tag: "1.0.0"
  pullPolicy: IfNotPresent
  # Override image pull secrets specifically for this image
  pullSecrets: []

# Deployment strategy
replicaCount: 3

# Update strategy
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 1
    maxUnavailable: 0

# Pod deployment configuration
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"
  prometheus.io/path: "/metrics"

podLabels:
  app.kubernetes.io/component: api-server
  app.kubernetes.io/part-of: llm-devops-platform

# Security context for pods
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault

# Security context for containers
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
  capabilities:
    drop:
      - ALL

# Service account configuration
serviceAccount:
  create: true
  annotations:
    # AWS IAM role annotation for IRSA
    # eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/llm-vault-role
  name: ""
  automountServiceAccountToken: true

# Service configuration
service:
  type: ClusterIP
  port: 8080
  targetPort: 8080
  protocol: TCP
  annotations: {}
  # For AWS NLB
  # service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
  sessionAffinity: None

# Ingress configuration
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "100"
    # Request size limits
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
    # Timeouts
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"

  hosts:
    - host: vault.example.com
      paths:
        - path: /
          pathType: Prefix

  tls:
    - secretName: llm-vault-tls
      hosts:
        - vault.example.com

# Resource limits and requests
resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 1000m
    memory: 2Gi

# Horizontal Pod Autoscaler
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 30
        - type: Pods
          value: 2
          periodSeconds: 60
      selectPolicy: Max

# Pod Disruption Budget
podDisruptionBudget:
  enabled: true
  minAvailable: 2
  # maxUnavailable: 1

# Liveness probe configuration
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
    scheme: HTTP
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  successThreshold: 1
  failureThreshold: 3

# Readiness probe configuration
readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
    scheme: HTTP
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  successThreshold: 1
  failureThreshold: 3

# Startup probe (for slow-starting containers)
startupProbe:
  httpGet:
    path: /health/startup
    port: 8080
    scheme: HTTP
  initialDelaySeconds: 0
  periodSeconds: 5
  timeoutSeconds: 3
  successThreshold: 1
  failureThreshold: 30

# Node selection
nodeSelector: {}
# Example: node.kubernetes.io/instance-type: c5.2xlarge

# Tolerations
tolerations: []
# - key: "workload"
#   operator: "Equal"
#   value: "data-processing"
#   effect: "NoSchedule"

# Affinity rules
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                  - llm-data-vault
          topologyKey: kubernetes.io/hostname
      - weight: 50
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                  - llm-data-vault
          topologyKey: topology.kubernetes.io/zone

# Priority class for pod scheduling
priorityClassName: ""

# Environment variables
env:
  # Server configuration
  - name: SERVER_PORT
    value: "8080"
  - name: SERVER_HOST
    value: "0.0.0.0"
  - name: LOG_LEVEL
    value: "info"
  - name: LOG_FORMAT
    value: "json"

  # Database configuration
  - name: DB_HOST
    value: "llm-data-vault-postgresql"
  - name: DB_PORT
    value: "5432"
  - name: DB_NAME
    value: "llm_vault"
  - name: DB_USER
    value: "vault_user"
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: llm-vault-secrets
        key: database-password
  - name: DB_SSL_MODE
    value: "require"
  - name: DB_MAX_CONNECTIONS
    value: "100"

  # Redis configuration
  - name: REDIS_HOST
    value: "llm-data-vault-redis-master"
  - name: REDIS_PORT
    value: "6379"
  - name: REDIS_PASSWORD
    valueFrom:
      secretKeyRef:
        name: llm-vault-secrets
        key: redis-password
  - name: REDIS_DB
    value: "0"

  # Object storage configuration
  - name: S3_ENDPOINT
    value: "https://s3.amazonaws.com"
  - name: S3_REGION
    value: "us-east-1"
  - name: S3_BUCKET
    value: "llm-vault-storage"
  - name: S3_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: llm-vault-secrets
        key: s3-access-key-id
  - name: S3_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: llm-vault-secrets
        key: s3-secret-access-key

  # Encryption configuration
  - name: ENCRYPTION_KEY_ID
    value: "primary-key-v1"
  - name: ENCRYPTION_ALGORITHM
    value: "AES-256-GCM"
  - name: KMS_PROVIDER
    value: "aws-kms"

  # Feature flags
  - name: ENABLE_PII_DETECTION
    value: "true"
  - name: ENABLE_AUTO_ANONYMIZATION
    value: "true"
  - name: ENABLE_METRICS
    value: "true"
  - name: ENABLE_TRACING
    value: "true"

# Environment variables from ConfigMap
envFrom:
  - configMapRef:
      name: llm-vault-config

# Extra volumes
extraVolumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir:
      sizeLimit: 1Gi

# Extra volume mounts
extraVolumeMounts:
  - name: tmp
    mountPath: /tmp
  - name: cache
    mountPath: /app/cache

# ConfigMap data
configMap:
  data:
    # Application configuration file
    config.yaml: |
      server:
        host: 0.0.0.0
        port: 8080
        read_timeout: 30s
        write_timeout: 30s
        max_header_bytes: 1048576

      database:
        pool:
          max_size: 100
          min_size: 10
          connection_timeout: 30s
          idle_timeout: 600s

      storage:
        backend: s3
        chunk_size: 5242880  # 5MB
        multipart_threshold: 104857600  # 100MB
        retry:
          max_attempts: 3
          backoff: exponential

      anonymization:
        engines:
          - name: email
            pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            replacement: '[EMAIL]'
          - name: phone
            pattern: '\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
            replacement: '[PHONE]'
          - name: ssn
            pattern: '\b\d{3}-\d{2}-\d{4}\b'
            replacement: '[SSN]'
          - name: credit_card
            pattern: '\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
            replacement: '[CARD]'

        confidence_threshold: 0.85
        preserve_format: true

      access_control:
        rbac:
          enabled: true
          default_role: viewer
        abac:
          enabled: true
          policy_engine: opa

      compliance:
        retention:
          default_days: 90
          max_days: 2555  # 7 years
        audit:
          enabled: true
          log_all_access: true

      monitoring:
        metrics:
          enabled: true
          port: 9090
          path: /metrics
        tracing:
          enabled: true
          sampler: probabilistic
          sampling_rate: 0.1
        logging:
          level: info
          format: json
          output: stdout

# Secrets (base64 encoded in production, use external-secrets or sealed-secrets)
secrets:
  # Database password (changeme in production)
  database-password: "changeme123"
  # Redis password
  redis-password: "redis-changeme123"
  # S3/MinIO credentials
  s3-access-key-id: "AKIAIOSFODNN7EXAMPLE"
  s3-secret-access-key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  # Encryption master key (should be from KMS in production)
  encryption-master-key: "32-byte-hex-encoded-key-here-changeme"
  # JWT secret for API authentication
  jwt-secret: "jwt-signing-secret-changeme"

# Network Policy
networkPolicy:
  enabled: true
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
      ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 9090
  egress:
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Allow PostgreSQL
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: postgresql
      ports:
        - protocol: TCP
          port: 5432
    # Allow Redis
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: redis
      ports:
        - protocol: TCP
          port: 6379
    # Allow external HTTPS (for S3, KMS, etc.)
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443

# ServiceMonitor for Prometheus Operator
serviceMonitor:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
  labels:
    prometheus: kube-prometheus
  relabelings: []
  metricRelabelings: []

# CronJob for backups
cronJobBackup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  suspend: false
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  concurrencyPolicy: Forbid
  resources:
    limits:
      cpu: 500m
      memory: 1Gi
    requests:
      cpu: 250m
      memory: 512Mi

# CronJob for compliance reporting
cronJobCompliance:
  enabled: true
  schedule: "0 3 * * 0"  # Weekly on Sunday at 3 AM
  suspend: false
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  concurrencyPolicy: Forbid
  resources:
    limits:
      cpu: 500m
      memory: 1Gi
    requests:
      cpu: 250m
      memory: 512Mi

# PostgreSQL sub-chart configuration
postgresql:
  enabled: true
  auth:
    username: vault_user
    password: changeme123
    database: llm_vault
  architecture: replication
  replication:
    enabled: true
    readReplicas: 2
  primary:
    persistence:
      enabled: true
      size: 100Gi
      storageClass: ""
    resources:
      limits:
        cpu: 4000m
        memory: 8Gi
      requests:
        cpu: 2000m
        memory: 4Gi
  readReplicas:
    persistence:
      enabled: true
      size: 100Gi
    resources:
      limits:
        cpu: 2000m
        memory: 4Gi
      requests:
        cpu: 1000m
        memory: 2Gi
  metrics:
    enabled: true
    serviceMonitor:
      enabled: true

# Redis sub-chart configuration
redis:
  enabled: true
  architecture: replication
  auth:
    enabled: true
    password: redis-changeme123
  master:
    persistence:
      enabled: true
      size: 20Gi
    resources:
      limits:
        cpu: 2000m
        memory: 4Gi
      requests:
        cpu: 1000m
        memory: 2Gi
  replica:
    replicaCount: 2
    persistence:
      enabled: true
      size: 20Gi
    resources:
      limits:
        cpu: 1000m
        memory: 2Gi
      requests:
        cpu: 500m
        memory: 1Gi
  metrics:
    enabled: true
    serviceMonitor:
      enabled: true

# MinIO sub-chart (optional, for on-premises S3-compatible storage)
minio:
  enabled: false
  mode: distributed
  replicas: 4
  auth:
    rootUser: minioadmin
    rootPassword: minioadmin123
  persistence:
    enabled: true
    size: 500Gi
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
  metrics:
    serviceMonitor:
      enabled: true
```

---

## 4. _helpers.tpl

### 4.1 Template Helper Functions

```yaml
{{/*
charts/llm-data-vault/templates/_helpers.tpl

Expand the name of the chart.
*/}}
{{- define "llm-data-vault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "llm-data-vault.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "llm-data-vault.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "llm-data-vault.labels" -}}
helm.sh/chart: {{ include "llm-data-vault.chart" . }}
{{ include "llm-data-vault.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: llm-devops-platform
{{- with .Values.podLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "llm-data-vault.selectorLabels" -}}
app.kubernetes.io/name: {{ include "llm-data-vault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "llm-data-vault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "llm-data-vault.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create image pull secret name
*/}}
{{- define "llm-data-vault.imagePullSecrets" -}}
{{- if .Values.image.pullSecrets }}
{{- toYaml .Values.image.pullSecrets }}
{{- else if .Values.global.imagePullSecrets }}
{{- toYaml .Values.global.imagePullSecrets }}
{{- end }}
{{- end }}

{{/*
Database connection string
*/}}
{{- define "llm-data-vault.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "llm-data-vault.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql://%s:%s@%s:%s/%s" (index .Values.env "DB_USER") (index .Values.env "DB_PASSWORD") (index .Values.env "DB_HOST") (index .Values.env "DB_PORT") (index .Values.env "DB_NAME") }}
{{- end }}
{{- end }}

{{/*
Redis connection string
*/}}
{{- define "llm-data-vault.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://:%s@%s-redis-master:6379/0" .Values.redis.auth.password (include "llm-data-vault.fullname" .) }}
{{- else }}
{{- printf "redis://:%s@%s:%s/%s" (index .Values.env "REDIS_PASSWORD") (index .Values.env "REDIS_HOST") (index .Values.env "REDIS_PORT") (index .Values.env "REDIS_DB") }}
{{- end }}
{{- end }}

{{/*
Generate container image name
*/}}
{{- define "llm-data-vault.image" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Return the proper Storage Class
*/}}
{{- define "llm-data-vault.storageClass" -}}
{{- if .Values.global.storageClass }}
{{- printf "storageClassName: %s" .Values.global.storageClass }}
{{- else if .Values.persistence.storageClass }}
{{- printf "storageClassName: %s" .Values.persistence.storageClass }}
{{- end }}
{{- end }}
```

---

## 5. Template Files

### 5.1 ServiceAccount

```yaml
# charts/llm-data-vault/templates/serviceaccount.yaml
{{- if .Values.serviceAccount.create -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "llm-data-vault.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
automountServiceAccountToken: {{ .Values.serviceAccount.automountServiceAccountToken }}
{{- end }}
```

### 5.2 ConfigMap

```yaml
# charts/llm-data-vault/templates/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "llm-data-vault.fullname" . }}-config
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
data:
  {{- with .Values.configMap.data }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
```

### 5.3 Secret

```yaml
# charts/llm-data-vault/templates/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "llm-data-vault.fullname" . }}-secrets
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
type: Opaque
stringData:
  {{- range $key, $value := .Values.secrets }}
  {{ $key }}: {{ $value | quote }}
  {{- end }}
```

### 5.4 Deployment

```yaml
# charts/llm-data-vault/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "llm-data-vault.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
spec:
  {{- if not .Values.autoscaling.enabled }}
  replicas: {{ .Values.replicaCount }}
  {{- end }}
  {{- with .Values.updateStrategy }}
  strategy:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "llm-data-vault.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      annotations:
        checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
        checksum/secret: {{ include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
        {{- with .Values.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      labels:
        {{- include "llm-data-vault.selectorLabels" . | nindent 8 }}
        {{- with .Values.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      {{- if or .Values.image.pullSecrets .Values.global.imagePullSecrets }}
      imagePullSecrets:
        {{- include "llm-data-vault.imagePullSecrets" . | nindent 8 }}
      {{- end }}
      serviceAccountName: {{ include "llm-data-vault.serviceAccountName" . }}
      {{- with .Values.podSecurityContext }}
      securityContext:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.priorityClassName }}
      priorityClassName: {{ . }}
      {{- end }}
      containers:
        - name: {{ .Chart.Name }}
          image: {{ include "llm-data-vault.image" . }}
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          {{- with .Values.securityContext }}
          securityContext:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          ports:
            - name: http
              containerPort: {{ .Values.service.targetPort }}
              protocol: TCP
            - name: metrics
              containerPort: 9090
              protocol: TCP
          {{- with .Values.livenessProbe }}
          livenessProbe:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with .Values.readinessProbe }}
          readinessProbe:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with .Values.startupProbe }}
          startupProbe:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with .Values.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          env:
            {{- range .Values.env }}
            - name: {{ .name }}
              {{- if .value }}
              value: {{ .value | quote }}
              {{- else if .valueFrom }}
              valueFrom:
                {{- toYaml .valueFrom | nindent 16 }}
              {{- end }}
            {{- end }}
          {{- with .Values.envFrom }}
          envFrom:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          volumeMounts:
            - name: config
              mountPath: /app/config
              readOnly: true
            {{- with .Values.extraVolumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
      volumes:
        - name: config
          configMap:
            name: {{ include "llm-data-vault.fullname" . }}-config
        {{- with .Values.extraVolumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
```

### 5.5 Service

```yaml
# charts/llm-data-vault/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "llm-data-vault.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
  {{- with .Values.service.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  type: {{ .Values.service.type }}
  {{- with .Values.service.sessionAffinity }}
  sessionAffinity: {{ . }}
  {{- end }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: {{ .Values.service.targetPort }}
      protocol: {{ .Values.service.protocol }}
      name: http
  selector:
    {{- include "llm-data-vault.selectorLabels" . | nindent 4 }}
```

### 5.6 Ingress

```yaml
# charts/llm-data-vault/templates/ingress.yaml
{{- if .Values.ingress.enabled -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "llm-data-vault.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- if .Values.ingress.className }}
  ingressClassName: {{ .Values.ingress.className }}
  {{- end }}
  {{- if .Values.ingress.tls }}
  tls:
    {{- range .Values.ingress.tls }}
    - hosts:
        {{- range .hosts }}
        - {{ . | quote }}
        {{- end }}
      secretName: {{ .secretName }}
    {{- end }}
  {{- end }}
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host | quote }}
      http:
        paths:
          {{- range .paths }}
          - path: {{ .path }}
            pathType: {{ .pathType }}
            backend:
              service:
                name: {{ include "llm-data-vault.fullname" $ }}
                port:
                  number: {{ $.Values.service.port }}
          {{- end }}
    {{- end }}
{{- end }}
```

### 5.7 HorizontalPodAutoscaler

```yaml
# charts/llm-data-vault/templates/hpa.yaml
{{- if .Values.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "llm-data-vault.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "llm-data-vault.fullname" . }}
  minReplicas: {{ .Values.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.autoscaling.maxReplicas }}
  metrics:
    {{- if .Values.autoscaling.targetCPUUtilizationPercentage }}
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .Values.autoscaling.targetCPUUtilizationPercentage }}
    {{- end }}
    {{- if .Values.autoscaling.targetMemoryUtilizationPercentage }}
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: {{ .Values.autoscaling.targetMemoryUtilizationPercentage }}
    {{- end }}
  {{- with .Values.autoscaling.behavior }}
  behavior:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
```

### 5.8 PodDisruptionBudget

```yaml
# charts/llm-data-vault/templates/pdb.yaml
{{- if .Values.podDisruptionBudget.enabled }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "llm-data-vault.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
spec:
  {{- if .Values.podDisruptionBudget.minAvailable }}
  minAvailable: {{ .Values.podDisruptionBudget.minAvailable }}
  {{- end }}
  {{- if .Values.podDisruptionBudget.maxUnavailable }}
  maxUnavailable: {{ .Values.podDisruptionBudget.maxUnavailable }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "llm-data-vault.selectorLabels" . | nindent 6 }}
{{- end }}
```

### 5.9 NetworkPolicy

```yaml
# charts/llm-data-vault/templates/networkpolicy.yaml
{{- if .Values.networkPolicy.enabled }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "llm-data-vault.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "llm-data-vault.selectorLabels" . | nindent 6 }}
  policyTypes:
    {{- toYaml .Values.networkPolicy.policyTypes | nindent 4 }}
  {{- with .Values.networkPolicy.ingress }}
  ingress:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.networkPolicy.egress }}
  egress:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
```

### 5.10 ServiceMonitor

```yaml
# charts/llm-data-vault/templates/servicemonitor.yaml
{{- if .Values.serviceMonitor.enabled }}
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ include "llm-data-vault.fullname" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
    {{- with .Values.serviceMonitor.labels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  selector:
    matchLabels:
      {{- include "llm-data-vault.selectorLabels" . | nindent 6 }}
  endpoints:
    - port: metrics
      path: /metrics
      interval: {{ .Values.serviceMonitor.interval }}
      scrapeTimeout: {{ .Values.serviceMonitor.scrapeTimeout }}
      {{- with .Values.serviceMonitor.relabelings }}
      relabelings:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.serviceMonitor.metricRelabelings }}
      metricRelabelings:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end }}
```

### 5.11 CronJob - Backup

```yaml
# charts/llm-data-vault/templates/cronjob-backup.yaml
{{- if .Values.cronJobBackup.enabled }}
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ include "llm-data-vault.fullname" . }}-backup
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
    app.kubernetes.io/component: backup
spec:
  schedule: {{ .Values.cronJobBackup.schedule | quote }}
  suspend: {{ .Values.cronJobBackup.suspend }}
  successfulJobsHistoryLimit: {{ .Values.cronJobBackup.successfulJobsHistoryLimit }}
  failedJobsHistoryLimit: {{ .Values.cronJobBackup.failedJobsHistoryLimit }}
  concurrencyPolicy: {{ .Values.cronJobBackup.concurrencyPolicy }}
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            {{- include "llm-data-vault.selectorLabels" . | nindent 12 }}
            app.kubernetes.io/component: backup
        spec:
          restartPolicy: OnFailure
          serviceAccountName: {{ include "llm-data-vault.serviceAccountName" . }}
          containers:
            - name: backup
              image: {{ include "llm-data-vault.image" . }}
              imagePullPolicy: {{ .Values.image.pullPolicy }}
              command:
                - /app/backup
                - --type=full
                - --retention=30d
              env:
                {{- range .Values.env }}
                - name: {{ .name }}
                  {{- if .value }}
                  value: {{ .value | quote }}
                  {{- else if .valueFrom }}
                  valueFrom:
                    {{- toYaml .valueFrom | nindent 20 }}
                  {{- end }}
                {{- end }}
              resources:
                {{- toYaml .Values.cronJobBackup.resources | nindent 16 }}
{{- end }}
```

### 5.12 CronJob - Compliance

```yaml
# charts/llm-data-vault/templates/cronjob-compliance.yaml
{{- if .Values.cronJobCompliance.enabled }}
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {{ include "llm-data-vault.fullname" . }}-compliance
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
    app.kubernetes.io/component: compliance
spec:
  schedule: {{ .Values.cronJobCompliance.schedule | quote }}
  suspend: {{ .Values.cronJobCompliance.suspend }}
  successfulJobsHistoryLimit: {{ .Values.cronJobCompliance.successfulJobsHistoryLimit }}
  failedJobsHistoryLimit: {{ .Values.cronJobCompliance.failedJobsHistoryLimit }}
  concurrencyPolicy: {{ .Values.cronJobCompliance.concurrencyPolicy }}
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            {{- include "llm-data-vault.selectorLabels" . | nindent 12 }}
            app.kubernetes.io/component: compliance
        spec:
          restartPolicy: OnFailure
          serviceAccountName: {{ include "llm-data-vault.serviceAccountName" . }}
          containers:
            - name: compliance-report
              image: {{ include "llm-data-vault.image" . }}
              imagePullPolicy: {{ .Values.image.pullPolicy }}
              command:
                - /app/compliance-report
                - --format=pdf
                - --output=s3
              env:
                {{- range .Values.env }}
                - name: {{ .name }}
                  {{- if .value }}
                  value: {{ .value | quote }}
                  {{- else if .valueFrom }}
                  valueFrom:
                    {{- toYaml .valueFrom | nindent 20 }}
                  {{- end }}
                {{- end }}
              resources:
                {{- toYaml .Values.cronJobCompliance.resources | nindent 16 }}
{{- end }}
```

### 5.13 NOTES.txt

```yaml
# charts/llm-data-vault/templates/NOTES.txt
Thank you for installing {{ .Chart.Name }}!

Your release is named {{ .Release.Name }}.

To learn more about the release, try:

  $ helm status {{ .Release.Name }} -n {{ .Release.Namespace }}
  $ helm get all {{ .Release.Name }} -n {{ .Release.Namespace }}

1. Get the application URL:
{{- if .Values.ingress.enabled }}
{{- range $host := .Values.ingress.hosts }}
  {{- range .paths }}
  http{{ if $.Values.ingress.tls }}s{{ end }}://{{ $host.host }}{{ .path }}
  {{- end }}
{{- end }}
{{- else if contains "NodePort" .Values.service.type }}
  export NODE_PORT=$(kubectl get --namespace {{ .Release.Namespace }} -o jsonpath="{.spec.ports[0].nodePort}" services {{ include "llm-data-vault.fullname" . }})
  export NODE_IP=$(kubectl get nodes --namespace {{ .Release.Namespace }} -o jsonpath="{.items[0].status.addresses[0].address}")
  echo http://$NODE_IP:$NODE_PORT
{{- else if contains "LoadBalancer" .Values.service.type }}
     NOTE: It may take a few minutes for the LoadBalancer IP to be available.
           You can watch the status of by running 'kubectl get --namespace {{ .Release.Namespace }} svc -w {{ include "llm-data-vault.fullname" . }}'
  export SERVICE_IP=$(kubectl get svc --namespace {{ .Release.Namespace }} {{ include "llm-data-vault.fullname" . }} --template "{{"{{ range (index .status.loadBalancer.ingress 0) }}{{.}}{{ end }}"}}")
  echo http://$SERVICE_IP:{{ .Values.service.port }}
{{- else if contains "ClusterIP" .Values.service.type }}
  export POD_NAME=$(kubectl get pods --namespace {{ .Release.Namespace }} -l "app.kubernetes.io/name={{ include "llm-data-vault.name" . }},app.kubernetes.io/instance={{ .Release.Name }}" -o jsonpath="{.items[0].metadata.name}")
  export CONTAINER_PORT=$(kubectl get pod --namespace {{ .Release.Namespace }} $POD_NAME -o jsonpath="{.spec.containers[0].ports[0].containerPort}")
  echo "Visit http://127.0.0.1:8080 to use your application"
  kubectl --namespace {{ .Release.Namespace }} port-forward $POD_NAME 8080:$CONTAINER_PORT
{{- end }}

2. Check application health:
  curl http{{ if .Values.ingress.enabled }}{{ if .Values.ingress.tls }}s{{ end }}{{ end }}://{{ (index .Values.ingress.hosts 0).host }}/health/ready

3. View logs:
  kubectl logs -f deployment/{{ include "llm-data-vault.fullname" . }} -n {{ .Release.Namespace }}

4. Run tests:
  helm test {{ .Release.Name }} -n {{ .Release.Namespace }}

For more information on using LLM-Data-Vault, visit:
  https://docs.example.com/llm-data-vault
```

---

## 6. Environment Overrides

### 6.1 Development Environment

```yaml
# charts/llm-data-vault/values-dev.yaml

# Development-specific overrides
replicaCount: 1

image:
  tag: "dev-latest"
  pullPolicy: Always

resources:
  limits:
    cpu: 500m
    memory: 1Gi
  requests:
    cpu: 250m
    memory: 512Mi

autoscaling:
  enabled: false

podDisruptionBudget:
  enabled: false

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-staging
  hosts:
    - host: vault-dev.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: llm-vault-dev-tls
      hosts:
        - vault-dev.example.com

env:
  - name: LOG_LEVEL
    value: "debug"
  - name: ENABLE_DEBUG_ENDPOINTS
    value: "true"
  - name: ENABLE_SWAGGER_UI
    value: "true"

postgresql:
  enabled: true
  architecture: standalone
  auth:
    password: dev-password123
  primary:
    persistence:
      size: 10Gi
    resources:
      limits:
        cpu: 1000m
        memory: 2Gi
      requests:
        cpu: 500m
        memory: 1Gi

redis:
  enabled: true
  architecture: standalone
  auth:
    password: dev-redis123
  master:
    persistence:
      size: 5Gi
    resources:
      limits:
        cpu: 500m
        memory: 1Gi
      requests:
        cpu: 250m
        memory: 512Mi

minio:
  enabled: true
  mode: standalone
  replicas: 1
  persistence:
    size: 50Gi
```

### 6.2 Staging Environment

```yaml
# charts/llm-data-vault/values-staging.yaml

# Staging-specific overrides
replicaCount: 2

image:
  tag: "staging-latest"
  pullPolicy: Always

resources:
  limits:
    cpu: 1000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 5

podDisruptionBudget:
  enabled: true
  minAvailable: 1

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/limit-rps: "50"
  hosts:
    - host: vault-staging.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: llm-vault-staging-tls
      hosts:
        - vault-staging.example.com

env:
  - name: LOG_LEVEL
    value: "info"
  - name: ENABLE_TRACING
    value: "true"

postgresql:
  enabled: true
  architecture: replication
  replication:
    readReplicas: 1
  primary:
    persistence:
      size: 50Gi
    resources:
      limits:
        cpu: 2000m
        memory: 4Gi
      requests:
        cpu: 1000m
        memory: 2Gi

redis:
  enabled: true
  architecture: replication
  replica:
    replicaCount: 1
  master:
    persistence:
      size: 10Gi
```

### 6.3 Production Environment

```yaml
# charts/llm-data-vault/values-prod.yaml

# Production-specific overrides
replicaCount: 5

image:
  registry: ghcr.io
  repository: your-org/llm-data-vault
  tag: "1.0.0"
  pullPolicy: IfNotPresent

resources:
  limits:
    cpu: 4000m
    memory: 8Gi
  requests:
    cpu: 2000m
    memory: 4Gi

autoscaling:
  enabled: true
  minReplicas: 5
  maxReplicas: 50
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 3

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/limit-rps: "200"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs: "true"
  hosts:
    - host: vault.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: llm-vault-prod-tls
      hosts:
        - vault.example.com

env:
  - name: LOG_LEVEL
    value: "warn"
  - name: ENABLE_METRICS
    value: "true"
  - name: ENABLE_TRACING
    value: "true"
  - name: DB_MAX_CONNECTIONS
    value: "200"

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: app.kubernetes.io/name
              operator: In
              values:
                - llm-data-vault
        topologyKey: kubernetes.io/hostname
      - labelSelector:
          matchExpressions:
            - key: app.kubernetes.io/name
              operator: In
              values:
                - llm-data-vault
        topologyKey: topology.kubernetes.io/zone

priorityClassName: high-priority

postgresql:
  enabled: true
  architecture: replication
  replication:
    readReplicas: 3
  primary:
    persistence:
      enabled: true
      size: 500Gi
      storageClass: fast-ssd
    resources:
      limits:
        cpu: 8000m
        memory: 16Gi
      requests:
        cpu: 4000m
        memory: 8Gi
  readReplicas:
    persistence:
      size: 500Gi
      storageClass: fast-ssd
    resources:
      limits:
        cpu: 4000m
        memory: 8Gi
      requests:
        cpu: 2000m
        memory: 4Gi

redis:
  enabled: true
  architecture: replication
  replica:
    replicaCount: 3
  master:
    persistence:
      enabled: true
      size: 100Gi
      storageClass: fast-ssd
    resources:
      limits:
        cpu: 4000m
        memory: 8Gi
      requests:
        cpu: 2000m
        memory: 4Gi

minio:
  enabled: false  # Use external S3 in production

# External secrets operator integration
secrets:
  external:
    enabled: true
    backend: aws-secrets-manager
    refreshInterval: 1h
```

---

## 7. Test Templates

### 7.1 Connection Test

```yaml
# charts/llm-data-vault/templates/tests/test-connection.yaml
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "llm-data-vault.fullname" . }}-test-connection"
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
  annotations:
    "helm.sh/hook": test
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  restartPolicy: Never
  containers:
    - name: wget
      image: busybox:1.36
      command: ['wget']
      args:
        - '--spider'
        - '--timeout=10'
        - 'http://{{ include "llm-data-vault.fullname" . }}:{{ .Values.service.port }}/health/ready'
```

### 7.2 Health Check Test

```yaml
# charts/llm-data-vault/templates/tests/test-healthcheck.yaml
apiVersion: v1
kind: Pod
metadata:
  name: "{{ include "llm-data-vault.fullname" . }}-test-healthcheck"
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-data-vault.labels" . | nindent 4 }}
  annotations:
    "helm.sh/hook": test
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  restartPolicy: Never
  containers:
    - name: curl
      image: curlimages/curl:8.5.0
      command: ['curl']
      args:
        - '--fail'
        - '--silent'
        - '--show-error'
        - '--max-time'
        - '10'
        - 'http://{{ include "llm-data-vault.fullname" . }}:{{ .Values.service.port }}/health/live'
```

---

## 8. Installation Guide

### 8.1 Prerequisites

Before installing the Helm chart, ensure you have:

```bash
# Required tools
- Kubernetes cluster (v1.28+)
- Helm 3.12+
- kubectl configured with cluster access
- cert-manager (for TLS certificates)
- Prometheus Operator (for monitoring)

# Add required Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add minio https://charts.min.io/
helm repo update
```

### 8.2 Installation Commands

#### Development Installation

```bash
# Create namespace
kubectl create namespace llm-vault-dev

# Install with development values
helm install llm-vault ./charts/llm-data-vault \
  --namespace llm-vault-dev \
  --values ./charts/llm-data-vault/values-dev.yaml \
  --set image.tag=dev-$(git rev-parse --short HEAD) \
  --wait \
  --timeout 10m

# Verify installation
helm status llm-vault -n llm-vault-dev
kubectl get pods -n llm-vault-dev
```

#### Staging Installation

```bash
# Create namespace
kubectl create namespace llm-vault-staging

# Create secrets (use external-secrets in production)
kubectl create secret generic llm-vault-secrets \
  --namespace llm-vault-staging \
  --from-literal=database-password='staging-db-pass' \
  --from-literal=redis-password='staging-redis-pass' \
  --from-literal=s3-access-key-id='AKIAIOSFODNN7EXAMPLE' \
  --from-literal=s3-secret-access-key='secret-key-here'

# Install with staging values
helm install llm-vault ./charts/llm-data-vault \
  --namespace llm-vault-staging \
  --values ./charts/llm-data-vault/values-staging.yaml \
  --set image.tag=v1.0.0-rc1 \
  --wait \
  --timeout 15m

# Run tests
helm test llm-vault -n llm-vault-staging
```

#### Production Installation

```bash
# Create namespace
kubectl create namespace llm-vault-prod

# Label namespace for monitoring
kubectl label namespace llm-vault-prod monitoring=enabled

# Install using GitOps (ArgoCD example)
cat <<EOF | kubectl apply -f -
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: llm-data-vault
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/llm-data-vault
    targetRevision: main
    path: charts/llm-data-vault
    helm:
      valueFiles:
        - values-prod.yaml
      parameters:
        - name: image.tag
          value: "1.0.0"
  destination:
    server: https://kubernetes.default.svc
    namespace: llm-vault-prod
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
EOF

# Or manual installation
helm install llm-vault ./charts/llm-data-vault \
  --namespace llm-vault-prod \
  --values ./charts/llm-data-vault/values-prod.yaml \
  --set image.tag=1.0.0 \
  --wait \
  --timeout 20m
```

### 8.3 Upgrade Commands

```bash
# Dry run upgrade to preview changes
helm upgrade llm-vault ./charts/llm-data-vault \
  --namespace llm-vault-prod \
  --values ./charts/llm-data-vault/values-prod.yaml \
  --set image.tag=1.1.0 \
  --dry-run \
  --debug

# Perform upgrade
helm upgrade llm-vault ./charts/llm-data-vault \
  --namespace llm-vault-prod \
  --values ./charts/llm-data-vault/values-prod.yaml \
  --set image.tag=1.1.0 \
  --wait \
  --timeout 15m \
  --atomic \
  --cleanup-on-fail

# Verify upgrade
helm list -n llm-vault-prod
kubectl rollout status deployment/llm-vault -n llm-vault-prod
```

### 8.4 Rollback Commands

```bash
# List release history
helm history llm-vault -n llm-vault-prod

# Rollback to previous version
helm rollback llm-vault -n llm-vault-prod

# Rollback to specific revision
helm rollback llm-vault 3 -n llm-vault-prod --wait
```

### 8.5 Uninstall Commands

```bash
# Uninstall release (keeps namespace)
helm uninstall llm-vault -n llm-vault-dev

# Delete namespace and all resources
kubectl delete namespace llm-vault-dev

# Uninstall with cleanup hooks
helm uninstall llm-vault \
  --namespace llm-vault-dev \
  --wait \
  --timeout 5m
```

### 8.6 Customization Examples

#### Custom Image Registry

```bash
helm install llm-vault ./charts/llm-data-vault \
  --set image.registry=my-registry.example.com \
  --set image.repository=llm-platform/data-vault \
  --set image.tag=custom-v1.0.0 \
  --set image.pullSecrets[0].name=my-registry-secret
```

#### External Database

```bash
helm install llm-vault ./charts/llm-data-vault \
  --set postgresql.enabled=false \
  --set env[0].name=DB_HOST \
  --set env[0].value=external-postgres.example.com \
  --set env[1].name=DB_PORT \
  --set env[1].value=5432
```

#### Custom Resource Limits

```bash
helm install llm-vault ./charts/llm-data-vault \
  --set resources.requests.cpu=4000m \
  --set resources.requests.memory=8Gi \
  --set resources.limits.cpu=8000m \
  --set resources.limits.memory=16Gi
```

### 8.7 Debugging Tips

```bash
# View rendered templates
helm template llm-vault ./charts/llm-data-vault \
  --values ./charts/llm-data-vault/values-dev.yaml \
  --debug

# Get all values
helm get values llm-vault -n llm-vault-dev

# Get manifest
helm get manifest llm-vault -n llm-vault-dev

# View logs
kubectl logs -f deployment/llm-vault -n llm-vault-dev

# Describe pod for events
kubectl describe pod -l app.kubernetes.io/name=llm-data-vault -n llm-vault-dev

# Check ConfigMap
kubectl get configmap llm-vault-config -n llm-vault-dev -o yaml

# Port forward for local testing
kubectl port-forward svc/llm-vault 8080:8080 -n llm-vault-dev
```

### 8.8 Chart Packaging and Publishing

```bash
# Lint the chart
helm lint ./charts/llm-data-vault

# Package the chart
helm package ./charts/llm-data-vault

# Generate index
helm repo index .

# Push to ChartMuseum
curl --data-binary "@llm-data-vault-1.0.0.tgz" \
  http://chartmuseum.example.com/api/charts

# Push to OCI registry (Harbor, ACR, ECR)
helm package ./charts/llm-data-vault
helm push llm-data-vault-1.0.0.tgz oci://registry.example.com/helm-charts
```

---

## Summary

This comprehensive Helm chart provides:

1. **Complete Chart Structure** with all necessary templates and configurations
2. **Flexible Values** supporting development, staging, and production environments
3. **Security Best Practices** including pod security contexts, network policies, and secret management
4. **High Availability** with HPA, PDB, and pod anti-affinity rules
5. **Observability** with Prometheus metrics, health checks, and structured logging
6. **Sub-chart Dependencies** for PostgreSQL, Redis, and MinIO
7. **Automated Jobs** for backups and compliance reporting
8. **Complete Testing** with Helm test hooks
9. **Production-Ready** configurations with resource limits, autoscaling, and monitoring

The chart is designed to be cloud-agnostic and can be deployed on AWS (EKS), Azure (AKS), GCP (GKE), or on-premises Kubernetes clusters with minimal modifications.

Total lines: ~780 lines of YAML configuration and documentation.
