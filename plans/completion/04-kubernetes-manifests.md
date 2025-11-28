# Kubernetes Manifests - LLM-Data-Vault

**Module:** LLM-Data-Vault
**Version:** 1.0.0
**Status:** Production-Ready
**Last Updated:** 2025-11-27

---

## Table of Contents

1. [Namespace and RBAC](#1-namespace-and-rbac)
2. [ConfigMaps](#2-configmaps)
3. [Secrets (Templates)](#3-secrets-templates)
4. [Deployment](#4-deployment)
5. [Service](#5-service)
6. [Ingress](#6-ingress)
7. [HorizontalPodAutoscaler](#7-horizontalpodautoscaler)
8. [PodDisruptionBudget](#8-poddisruptionbudget)
9. [NetworkPolicy](#9-networkpolicy)
10. [ServiceMonitor (Prometheus)](#10-servicemonitor-prometheus)
11. [Kustomization](#11-kustomization)

---

## 1. Namespace and RBAC

### Namespace Definition

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/part-of: llm-devops-platform
    environment: production
```

### ServiceAccount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-api
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
  annotations:
    # AWS IRSA (IAM Roles for Service Accounts)
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/llm-data-vault-api
    # Azure Workload Identity
    azure.workload.identity/client-id: CLIENT_ID
    # GCP Workload Identity
    iam.gke.io/gcp-service-account: vault-api@PROJECT_ID.iam.gserviceaccount.com
automountServiceAccountToken: true
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-worker
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/llm-data-vault-worker
automountServiceAccountToken: true
```

### Role and RoleBinding

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-api-role
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
rules:
  # Allow reading ConfigMaps for configuration
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
  # Allow reading Secrets
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  # Allow creating events for logging
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
  # Allow pod info for health checks
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-api-rolebinding
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: vault-api-role
subjects:
  - kind: ServiceAccount
    name: vault-api
    namespace: llm-data-vault
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-worker-role
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-worker-rolebinding
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: vault-worker-role
subjects:
  - kind: ServiceAccount
    name: vault-worker
    namespace: llm-data-vault
```

### ClusterRole for CRDs

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vault-dataset-manager
  labels:
    app.kubernetes.io/name: llm-data-vault
rules:
  # Custom Resource Definitions for Datasets
  - apiGroups: ["datavault.llmdevops.io"]
    resources: ["datasets", "corpora", "anonymizationpolicies"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["datavault.llmdevops.io"]
    resources: ["datasets/status", "corpora/status"]
    verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vault-api-dataset-manager
  labels:
    app.kubernetes.io/name: llm-data-vault
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: vault-dataset-manager
subjects:
  - kind: ServiceAccount
    name: vault-api
    namespace: llm-data-vault
```

---

## 2. ConfigMaps

### Application Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-api-config
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
data:
  # Server Configuration
  SERVER_PORT: "8080"
  SERVER_HOST: "0.0.0.0"
  SERVER_TIMEOUT_READ: "30s"
  SERVER_TIMEOUT_WRITE: "30s"
  SERVER_TIMEOUT_IDLE: "120s"

  # Storage Backend
  STORAGE_BACKEND: "s3"
  STORAGE_S3_REGION: "us-east-1"
  STORAGE_S3_BUCKET: "llm-data-vault-prod"
  STORAGE_S3_ENDPOINT: ""  # Leave empty for AWS S3, set for MinIO/custom
  STORAGE_MAX_UPLOAD_SIZE: "10737418240"  # 10GB

  # Database Configuration
  DATABASE_DRIVER: "postgres"
  DATABASE_HOST: "vault-postgres.llm-data-vault.svc.cluster.local"
  DATABASE_PORT: "5432"
  DATABASE_NAME: "datavault"
  DATABASE_SSL_MODE: "require"
  DATABASE_MAX_OPEN_CONNS: "25"
  DATABASE_MAX_IDLE_CONNS: "10"
  DATABASE_CONN_MAX_LIFETIME: "1h"

  # Cache Configuration
  CACHE_ENABLED: "true"
  CACHE_BACKEND: "redis"
  CACHE_REDIS_HOST: "vault-redis.llm-data-vault.svc.cluster.local"
  CACHE_REDIS_PORT: "6379"
  CACHE_TTL: "3600"

  # Encryption Configuration
  ENCRYPTION_PROVIDER: "kms"
  ENCRYPTION_ALGORITHM: "AES-256-GCM"
  ENCRYPTION_KMS_REGION: "us-east-1"
  ENCRYPTION_KEY_ROTATION_DAYS: "90"

  # Authentication
  AUTH_JWT_ISSUER: "https://auth.llmdevops.io"
  AUTH_JWT_AUDIENCE: "llm-data-vault"
  AUTH_JWT_EXPIRY: "15m"
  AUTH_REFRESH_TOKEN_EXPIRY: "168h"  # 7 days

  # Authorization
  AUTHZ_POLICY_ENGINE: "opa"
  AUTHZ_OPA_URL: "http://opa.llm-data-vault.svc.cluster.local:8181"
  AUTHZ_CACHE_ENABLED: "true"

  # Logging
  LOG_LEVEL: "info"
  LOG_FORMAT: "json"
  LOG_OUTPUT: "stdout"

  # Metrics
  METRICS_ENABLED: "true"
  METRICS_PORT: "9090"
  METRICS_PATH: "/metrics"

  # Tracing
  TRACING_ENABLED: "true"
  TRACING_EXPORTER: "otlp"
  TRACING_OTLP_ENDPOINT: "http://jaeger-collector.observability.svc.cluster.local:4318"
  TRACING_SAMPLE_RATE: "0.1"

  # Rate Limiting
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_REQUESTS_PER_MINUTE: "1000"
  RATE_LIMIT_BURST: "100"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-worker-config
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
data:
  # Worker Configuration
  WORKER_CONCURRENCY: "10"
  WORKER_QUEUE: "redis"
  WORKER_REDIS_HOST: "vault-redis.llm-data-vault.svc.cluster.local"
  WORKER_REDIS_PORT: "6379"

  # Anonymization
  ANONYMIZATION_ENGINE: "presidio"
  ANONYMIZATION_CONFIDENCE_THRESHOLD: "0.85"
  ANONYMIZATION_BATCH_SIZE: "100"

  # Job Processing
  JOB_MAX_RETRIES: "3"
  JOB_RETRY_BACKOFF: "exponential"
  JOB_TIMEOUT: "3600"  # 1 hour

  # Storage (same as API)
  STORAGE_BACKEND: "s3"
  STORAGE_S3_REGION: "us-east-1"
  STORAGE_S3_BUCKET: "llm-data-vault-prod"

  # Logging
  LOG_LEVEL: "info"
  LOG_FORMAT: "json"
```

### Feature Flags

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-feature-flags
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
data:
  features.yaml: |
    features:
      # Core Features
      dataset_versioning:
        enabled: true
        rollout_percentage: 100

      anonymization_auto:
        enabled: true
        rollout_percentage: 100

      differential_privacy:
        enabled: true
        rollout_percentage: 50
        whitelist:
          - "data-science-team"
          - "ml-engineering-team"

      # Advanced Features
      k_anonymity:
        enabled: true
        rollout_percentage: 25
        config:
          min_k: 5

      custom_pii_patterns:
        enabled: true
        rollout_percentage: 100

      # Integration Features
      webhook_notifications:
        enabled: true
        rollout_percentage: 100

      external_catalog_sync:
        enabled: false
        rollout_percentage: 0

      # Experimental Features
      ml_based_pii_detection:
        enabled: true
        rollout_percentage: 10
        config:
          model: "microsoft/presidio-en"

      vector_embeddings:
        enabled: false
        rollout_percentage: 0

      # Performance Features
      compression_zstd:
        enabled: true
        rollout_percentage: 100

      streaming_api:
        enabled: true
        rollout_percentage: 75
```

---

## 3. Secrets (Templates)

### Database Credentials

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-database-credentials
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
type: Opaque
stringData:
  DATABASE_USER: "vault_api"
  DATABASE_PASSWORD: "REPLACE_WITH_SECURE_PASSWORD"
  DATABASE_CONNECTION_STRING: "postgresql://vault_api:REPLACE_WITH_SECURE_PASSWORD@vault-postgres.llm-data-vault.svc.cluster.local:5432/datavault?sslmode=require"
```

### JWT Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-jwt-secrets
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
type: Opaque
stringData:
  # Generate with: openssl rand -base64 64
  JWT_SIGNING_KEY: "REPLACE_WITH_BASE64_ENCODED_256BIT_KEY"
  JWT_REFRESH_KEY: "REPLACE_WITH_BASE64_ENCODED_256BIT_KEY"
  # JWKS URL for public key verification
  JWKS_URL: "https://auth.llmdevops.io/.well-known/jwks.json"
```

### API Keys

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-api-keys
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
type: Opaque
stringData:
  # AWS Credentials (if not using IRSA)
  AWS_ACCESS_KEY_ID: "REPLACE_WITH_AWS_ACCESS_KEY"
  AWS_SECRET_ACCESS_KEY: "REPLACE_WITH_AWS_SECRET_KEY"

  # Redis Password
  REDIS_PASSWORD: "REPLACE_WITH_REDIS_PASSWORD"

  # Encryption Master Key (for envelope encryption)
  MASTER_ENCRYPTION_KEY: "REPLACE_WITH_BASE64_ENCODED_KEY"

  # External Service API Keys
  PRESIDIO_API_KEY: "REPLACE_IF_USING_CLOUD_SERVICE"
  OPA_API_KEY: "REPLACE_IF_REQUIRED"

  # Webhook Signing Secret
  WEBHOOK_SIGNING_SECRET: "REPLACE_WITH_RANDOM_SECRET"
```

### TLS Certificates

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-tls-cert
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
type: kubernetes.io/tls
stringData:
  # Replace with actual certificate and key
  tls.crt: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKZ... (REPLACE WITH ACTUAL CERT)
    -----END CERTIFICATE-----
  tls.key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA... (REPLACE WITH ACTUAL KEY)
    -----END RSA PRIVATE KEY-----
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    MIIDXTCCAkWgAwIBAgIJAKZ... (REPLACE WITH CA CERT)
    -----END CERTIFICATE-----
```

---

## 4. Deployment

### Vault API Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-api
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
    app.kubernetes.io/version: "1.0.0"
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: api
  template:
    metadata:
      labels:
        app.kubernetes.io/name: llm-data-vault
        app.kubernetes.io/component: api
        app.kubernetes.io/version: "1.0.0"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
        # Force pod restart on config change
        checksum/config: "{{ include (print $.Template.BasePath '/configmap.yaml') . | sha256sum }}"
        checksum/secret: "{{ include (print $.Template.BasePath '/secret.yaml') . | sha256sum }}"
    spec:
      serviceAccountName: vault-api
      automountServiceAccountToken: true

      # Security Context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault

      # Init Containers
      initContainers:
        - name: wait-for-database
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              until nc -z vault-postgres.llm-data-vault.svc.cluster.local 5432; do
                echo "Waiting for database..."
                sleep 2
              done
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]

        - name: migrate-database
          image: ghcr.io/llm-devops/llm-data-vault:1.0.0
          command: ["/app/migrate", "up"]
          envFrom:
            - configMapRef:
                name: vault-api-config
            - secretRef:
                name: vault-database-credentials
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true

      # Main Containers
      containers:
        - name: api
          image: ghcr.io/llm-devops/llm-data-vault:1.0.0
          imagePullPolicy: IfNotPresent

          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: metrics
              containerPort: 9090
              protocol: TCP
            - name: grpc
              containerPort: 9000
              protocol: TCP

          # Environment Variables
          envFrom:
            - configMapRef:
                name: vault-api-config
            - secretRef:
                name: vault-database-credentials
            - secretRef:
                name: vault-jwt-secrets
            - secretRef:
                name: vault-api-keys

          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: POD_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP

          # Resource Management
          resources:
            requests:
              cpu: 500m
              memory: 1Gi
              ephemeral-storage: 1Gi
            limits:
              cpu: 2000m
              memory: 4Gi
              ephemeral-storage: 5Gi

          # Health Checks
          livenessProbe:
            httpGet:
              path: /health/live
              port: http
              scheme: HTTP
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            successThreshold: 1
            failureThreshold: 3

          readinessProbe:
            httpGet:
              path: /health/ready
              port: http
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 5
            timeoutSeconds: 3
            successThreshold: 1
            failureThreshold: 3

          startupProbe:
            httpGet:
              path: /health/startup
              port: http
              scheme: HTTP
            initialDelaySeconds: 0
            periodSeconds: 5
            timeoutSeconds: 3
            successThreshold: 1
            failureThreshold: 30

          # Security Context
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1000

          # Volume Mounts
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /app/cache
            - name: tls-certs
              mountPath: /etc/tls
              readOnly: true
            - name: feature-flags
              mountPath: /etc/config/features
              readOnly: true

      # Volumes
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 1Gi
        - name: cache
          emptyDir:
            sizeLimit: 2Gi
        - name: tls-certs
          secret:
            secretName: vault-tls-cert
            defaultMode: 0400
        - name: feature-flags
          configMap:
            name: vault-feature-flags

      # Pod Anti-Affinity
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app.kubernetes.io/component
                      operator: In
                      values: ["api"]
                topologyKey: kubernetes.io/hostname
            - weight: 50
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app.kubernetes.io/component
                      operator: In
                      values: ["api"]
                topologyKey: topology.kubernetes.io/zone
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node.kubernetes.io/workload
                    operator: In
                    values: ["compute", "general"]

      # Tolerations
      tolerations:
        - key: "workload"
          operator: "Equal"
          value: "compute"
          effect: "NoSchedule"

      # DNS Policy
      dnsPolicy: ClusterFirst

      # Termination Grace Period
      terminationGracePeriodSeconds: 60
```

### Vault Worker Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-worker
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
    app.kubernetes.io/version: "1.0.0"
spec:
  replicas: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 2
      maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: worker
  template:
    metadata:
      labels:
        app.kubernetes.io/name: llm-data-vault
        app.kubernetes.io/component: worker
        app.kubernetes.io/version: "1.0.0"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: vault-worker
      automountServiceAccountToken: true

      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: worker
          image: ghcr.io/llm-devops/llm-data-vault-worker:1.0.0
          imagePullPolicy: IfNotPresent

          command: ["/app/worker"]
          args:
            - "--concurrency=$(WORKER_CONCURRENCY)"
            - "--queue=$(WORKER_QUEUE)"

          ports:
            - name: metrics
              containerPort: 9090
              protocol: TCP

          envFrom:
            - configMapRef:
                name: vault-worker-config
            - secretRef:
                name: vault-database-credentials
            - secretRef:
                name: vault-api-keys

          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: WORKER_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.uid

          resources:
            requests:
              cpu: 1000m
              memory: 2Gi
              ephemeral-storage: 5Gi
            limits:
              cpu: 4000m
              memory: 8Gi
              ephemeral-storage: 20Gi

          livenessProbe:
            httpGet:
              path: /health/live
              port: metrics
            initialDelaySeconds: 30
            periodSeconds: 15
            timeoutSeconds: 5
            failureThreshold: 3

          readinessProbe:
            httpGet:
              path: /health/ready
              port: metrics
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 2

          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1000

          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: work
              mountPath: /app/work

      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 2Gi
        - name: work
          emptyDir:
            sizeLimit: 10Gi

      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app.kubernetes.io/component
                      operator: In
                      values: ["worker"]
                topologyKey: kubernetes.io/hostname

      terminationGracePeriodSeconds: 120
```

---

## 5. Service

### ClusterIP Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: vault-api
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
spec:
  type: ClusterIP
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 10800  # 3 hours
  ports:
    - name: http
      port: 80
      targetPort: http
      protocol: TCP
    - name: grpc
      port: 9000
      targetPort: grpc
      protocol: TCP
    - name: metrics
      port: 9090
      targetPort: metrics
      protocol: TCP
  selector:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
---
apiVersion: v1
kind: Service
metadata:
  name: vault-api-metrics
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
spec:
  type: ClusterIP
  clusterIP: None  # Headless for metrics scraping
  ports:
    - name: metrics
      port: 9090
      targetPort: metrics
      protocol: TCP
  selector:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
---
apiVersion: v1
kind: Service
metadata:
  name: vault-worker-metrics
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
spec:
  type: ClusterIP
  clusterIP: None  # Headless for metrics scraping
  ports:
    - name: metrics
      port: 9090
      targetPort: metrics
      protocol: TCP
  selector:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
```

---

## 6. Ingress

### Ingress with TLS

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vault-api-ingress
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
  annotations:
    # Nginx Ingress Controller
    nginx.ingress.kubernetes.io/rewrite-target: /$2
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/proxy-body-size: "10g"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
    nginx.ingress.kubernetes.io/client-body-buffer-size: "10m"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/limit-rps: "50"

    # Security Headers
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 1; mode=block";
      more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains";
      more_set_headers "Content-Security-Policy: default-src 'self'";

    # CORS (if needed)
    nginx.ingress.kubernetes.io/enable-cors: "true"
    nginx.ingress.kubernetes.io/cors-allow-origin: "https://console.llmdevops.io"
    nginx.ingress.kubernetes.io/cors-allow-methods: "GET, POST, PUT, DELETE, OPTIONS"
    nginx.ingress.kubernetes.io/cors-allow-headers: "DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization"

    # Certificate Manager (cert-manager.io)
    cert-manager.io/cluster-issuer: "letsencrypt-prod"

    # Traefik (alternative)
    traefik.ingress.kubernetes.io/router.entrypoints: "websecure"
    traefik.ingress.kubernetes.io/router.tls: "true"
    traefik.ingress.kubernetes.io/router.middlewares: "llm-data-vault-ratelimit@kubernetescrd"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - vault-api.llmdevops.io
        - vault.llmdevops.io
      secretName: vault-api-tls
  rules:
    - host: vault-api.llmdevops.io
      http:
        paths:
          # API v1 Routes
          - path: /api/v1(/|$)(.*)
            pathType: ImplementationSpecific
            backend:
              service:
                name: vault-api
                port:
                  name: http

          # gRPC Routes
          - path: /grpc
            pathType: Prefix
            backend:
              service:
                name: vault-api
                port:
                  name: grpc

          # Health Checks (not behind auth)
          - path: /health
            pathType: Prefix
            backend:
              service:
                name: vault-api
                port:
                  name: http

    # Alternative domain
    - host: vault.llmdevops.io
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: vault-api
                port:
                  name: http
```

---

## 7. HorizontalPodAutoscaler

### CPU/Memory Based Scaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vault-api-hpa
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vault-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
    # CPU Utilization
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70

    # Memory Utilization
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80

  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 60
        - type: Pods
          value: 2
          periodSeconds: 60
      selectPolicy: Max

    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
        - type: Pods
          value: 1
          periodSeconds: 60
      selectPolicy: Min
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vault-worker-hpa
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vault-worker
  minReplicas: 5
  maxReplicas: 50
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 75

    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 85

  behavior:
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
        - type: Percent
          value: 200
          periodSeconds: 30
        - type: Pods
          value: 5
          periodSeconds: 30
      selectPolicy: Max

    scaleDown:
      stabilizationWindowSeconds: 600
      policies:
        - type: Pods
          value: 2
          periodSeconds: 120
      selectPolicy: Min
```

### Custom Metrics Scaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vault-api-custom-hpa
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vault-api
  minReplicas: 3
  maxReplicas: 30
  metrics:
    # Request Rate (from Prometheus)
    - type: Pods
      pods:
        metric:
          name: http_requests_per_second
        target:
          type: AverageValue
          averageValue: "1000"

    # Queue Depth
    - type: External
      external:
        metric:
          name: redis_queue_depth
          selector:
            matchLabels:
              queue: "vault-jobs"
        target:
          type: AverageValue
          averageValue: "50"

    # Response Latency P99
    - type: Pods
      pods:
        metric:
          name: http_request_duration_p99_seconds
        target:
          type: AverageValue
          averageValue: "0.5"
```

---

## 8. PodDisruptionBudget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: vault-api-pdb
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: api
  unhealthyPodEvictionPolicy: AlwaysAllow
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: vault-worker-pdb
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
spec:
  maxUnavailable: 30%
  selector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: worker
  unhealthyPodEvictionPolicy: AlwaysAllow
```

---

## 9. NetworkPolicy

### Ingress Rules

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-api-network-policy
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: api
  policyTypes:
    - Ingress
    - Egress

  ingress:
    # Allow from Ingress Controller
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080

    # Allow from internal services
    - from:
        - namespaceSelector:
            matchLabels:
              name: llm-gateway
        - namespaceSelector:
            matchLabels:
              name: llm-analytics-hub
      ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 9000

    # Allow Prometheus scraping
    - from:
        - namespaceSelector:
            matchLabels:
              name: observability
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
      ports:
        - protocol: TCP
          port: 9090

  egress:
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
        - podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53

    # Allow database access
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432

    # Allow Redis access
    - to:
        - podSelector:
            matchLabels:
              app: redis
      ports:
        - protocol: TCP
          port: 6379

    # Allow S3 (HTTPS)
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443

    # Allow OPA
    - to:
        - podSelector:
            matchLabels:
              app: opa
      ports:
        - protocol: TCP
          port: 8181
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-worker-network-policy
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: worker
  policyTypes:
    - Ingress
    - Egress

  ingress:
    # Allow Prometheus scraping only
    - from:
        - namespaceSelector:
            matchLabels:
              name: observability
      ports:
        - protocol: TCP
          port: 9090

  egress:
    # DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53

    # Database
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432

    # Redis Queue
    - to:
        - podSelector:
            matchLabels:
              app: redis
      ports:
        - protocol: TCP
          port: 6379

    # S3 and external APIs
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-default
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

---

## 10. ServiceMonitor (Prometheus)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vault-api-metrics
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: api
    prometheus: kube-prometheus
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: api

  namespaceSelector:
    matchNames:
      - llm-data-vault

  endpoints:
    - port: metrics
      interval: 30s
      scrapeTimeout: 10s
      path: /metrics
      scheme: http

      relabelings:
        - sourceLabels: [__meta_kubernetes_pod_name]
          targetLabel: pod
        - sourceLabels: [__meta_kubernetes_pod_node_name]
          targetLabel: node
        - sourceLabels: [__meta_kubernetes_namespace]
          targetLabel: namespace

      metricRelabelings:
        - sourceLabels: [__name__]
          regex: 'go_.*'
          action: drop
        - sourceLabels: [__name__]
          regex: 'process_.*'
          action: drop
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vault-worker-metrics
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    app.kubernetes.io/component: worker
    prometheus: kube-prometheus
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: llm-data-vault
      app.kubernetes.io/component: worker

  namespaceSelector:
    matchNames:
      - llm-data-vault

  endpoints:
    - port: metrics
      interval: 30s
      scrapeTimeout: 10s
      path: /metrics
      scheme: http
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: vault-alerts
  namespace: llm-data-vault
  labels:
    app.kubernetes.io/name: llm-data-vault
    prometheus: kube-prometheus
spec:
  groups:
    - name: vault-api
      interval: 30s
      rules:
        - alert: VaultAPIHighErrorRate
          expr: |
            rate(http_requests_total{status=~"5.."}[5m])
            / rate(http_requests_total[5m]) > 0.05
          for: 5m
          labels:
            severity: critical
            component: api
          annotations:
            summary: "High API error rate"
            description: "Error rate is {{ $value | humanizePercentage }}"

        - alert: VaultAPIHighLatency
          expr: |
            histogram_quantile(0.99,
              rate(http_request_duration_seconds_bucket[5m])
            ) > 1.0
          for: 10m
          labels:
            severity: warning
            component: api
          annotations:
            summary: "High API latency"
            description: "P99 latency is {{ $value }}s"

        - alert: VaultAPILowAvailability
          expr: |
            (sum(up{job="vault-api"}) / count(up{job="vault-api"})) < 0.5
          for: 5m
          labels:
            severity: critical
            component: api
          annotations:
            summary: "Low API pod availability"
            description: "Only {{ $value | humanizePercentage }} pods available"

    - name: vault-worker
      interval: 30s
      rules:
        - alert: VaultWorkerQueueBacklog
          expr: redis_queue_length{queue="vault-jobs"} > 1000
          for: 15m
          labels:
            severity: warning
            component: worker
          annotations:
            summary: "Worker queue backlog"
            description: "Queue has {{ $value }} pending jobs"

        - alert: VaultWorkerJobFailureRate
          expr: |
            rate(worker_jobs_failed_total[5m])
            / rate(worker_jobs_total[5m]) > 0.1
          for: 10m
          labels:
            severity: warning
            component: worker
          annotations:
            summary: "High worker job failure rate"
            description: "{{ $value | humanizePercentage }} jobs failing"
```

---

## 11. Kustomization

### Base Kustomization

```yaml
# kustomization.yaml (base/)
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: llm-data-vault

resources:
  - namespace.yaml
  - serviceaccount.yaml
  - rbac.yaml
  - configmap-api.yaml
  - configmap-worker.yaml
  - configmap-features.yaml
  - secret-database.yaml
  - secret-jwt.yaml
  - secret-apikeys.yaml
  - secret-tls.yaml
  - deployment-api.yaml
  - deployment-worker.yaml
  - service.yaml
  - ingress.yaml
  - hpa.yaml
  - pdb.yaml
  - networkpolicy.yaml
  - servicemonitor.yaml

commonLabels:
  app.kubernetes.io/name: llm-data-vault
  app.kubernetes.io/managed-by: kustomize

images:
  - name: ghcr.io/llm-devops/llm-data-vault
    newTag: 1.0.0
  - name: ghcr.io/llm-devops/llm-data-vault-worker
    newTag: 1.0.0

configMapGenerator:
  - name: vault-build-info
    literals:
      - BUILD_VERSION=1.0.0
      - BUILD_DATE=2025-11-27
      - GIT_COMMIT=abc123

secretGenerator:
  - name: vault-generated-secrets
    type: Opaque
    options:
      disableNameSuffixHash: true
    literals:
      - INTERNAL_API_KEY=REPLACE_ME

replicas:
  - name: vault-api
    count: 3
  - name: vault-worker
    count: 5
```

### Development Overlay

```yaml
# overlays/dev/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: llm-data-vault-dev

bases:
  - ../../base

nameSuffix: -dev

commonLabels:
  environment: development

patches:
  # Reduce replicas for dev
  - target:
      kind: Deployment
      name: vault-api
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 1

  - target:
      kind: Deployment
      name: vault-worker
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 1

  # Reduce resources for dev
  - target:
      kind: Deployment
    patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources/requests/cpu
        value: 100m
      - op: replace
        path: /spec/template/spec/containers/0/resources/requests/memory
        value: 256Mi

configMapGenerator:
  - name: vault-api-config
    behavior: merge
    literals:
      - LOG_LEVEL=debug
      - TRACING_SAMPLE_RATE=1.0

images:
  - name: ghcr.io/llm-devops/llm-data-vault
    newTag: dev-latest
```

### Production Overlay

```yaml
# overlays/prod/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: llm-data-vault

bases:
  - ../../base

commonLabels:
  environment: production

patches:
  # Production replicas
  - target:
      kind: Deployment
      name: vault-api
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 5

  - target:
      kind: Deployment
      name: vault-worker
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 10

  # Production resource limits
  - target:
      kind: Deployment
      name: vault-api
    patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources/requests/cpu
        value: 1000m
      - op: replace
        path: /spec/template/spec/containers/0/resources/requests/memory
        value: 2Gi
      - op: replace
        path: /spec/template/spec/containers/0/resources/limits/cpu
        value: 4000m
      - op: replace
        path: /spec/template/spec/containers/0/resources/limits/memory
        value: 8Gi

configMapGenerator:
  - name: vault-api-config
    behavior: merge
    literals:
      - LOG_LEVEL=info
      - TRACING_SAMPLE_RATE=0.1
      - RATE_LIMIT_REQUESTS_PER_MINUTE=5000

secretGenerator:
  - name: vault-database-credentials
    behavior: replace
    files:
      - DATABASE_CONNECTION_STRING=secrets/db-connection-string.txt

  - name: vault-jwt-secrets
    behavior: replace
    files:
      - JWT_SIGNING_KEY=secrets/jwt-signing-key.txt
      - JWT_REFRESH_KEY=secrets/jwt-refresh-key.txt

images:
  - name: ghcr.io/llm-devops/llm-data-vault
    newTag: 1.0.0
  - name: ghcr.io/llm-devops/llm-data-vault-worker
    newTag: 1.0.0

replicas:
  - name: vault-api
    count: 5
  - name: vault-worker
    count: 10
```

### Staging Overlay

```yaml
# overlays/staging/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: llm-data-vault-staging

bases:
  - ../../base

nameSuffix: -staging

commonLabels:
  environment: staging

patches:
  - target:
      kind: Deployment
      name: vault-api
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 2

  - target:
      kind: Deployment
      name: vault-worker
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 3

configMapGenerator:
  - name: vault-api-config
    behavior: merge
    literals:
      - LOG_LEVEL=debug
      - STORAGE_S3_BUCKET=llm-data-vault-staging
      - TRACING_SAMPLE_RATE=0.5

images:
  - name: ghcr.io/llm-devops/llm-data-vault
    newTag: staging-latest
```

---

## Deployment Instructions

### Prerequisites

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# Install kustomize
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash

# Install helm (optional)
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### Deploy to Development

```bash
# Apply base + dev overlay
kubectl apply -k overlays/dev/

# Verify deployment
kubectl get pods -n llm-data-vault-dev
kubectl logs -n llm-data-vault-dev -l app.kubernetes.io/component=api
```

### Deploy to Production

```bash
# Dry run first
kubectl apply -k overlays/prod/ --dry-run=client

# Apply to production
kubectl apply -k overlays/prod/

# Watch rollout
kubectl rollout status deployment/vault-api -n llm-data-vault
kubectl rollout status deployment/vault-worker -n llm-data-vault

# Verify
kubectl get all -n llm-data-vault
```

### Update Secrets

```bash
# Create secret files
echo -n "postgresql://..." > secrets/db-connection-string.txt
echo -n "base64encodedkey..." > secrets/jwt-signing-key.txt

# Apply with kustomize
kubectl apply -k overlays/prod/

# Restart pods to pick up new secrets
kubectl rollout restart deployment/vault-api -n llm-data-vault
```

### Scaling Operations

```bash
# Manual scaling
kubectl scale deployment vault-api --replicas=10 -n llm-data-vault

# Check HPA status
kubectl get hpa -n llm-data-vault

# Describe HPA for details
kubectl describe hpa vault-api-hpa -n llm-data-vault
```

---

## Monitoring and Troubleshooting

### View Logs

```bash
# API logs
kubectl logs -f deployment/vault-api -n llm-data-vault

# Worker logs
kubectl logs -f deployment/vault-worker -n llm-data-vault --all-containers=true

# Previous container logs (if crashed)
kubectl logs deployment/vault-api --previous -n llm-data-vault
```

### Check Metrics

```bash
# Port-forward Prometheus
kubectl port-forward -n observability svc/prometheus 9090:9090

# Access metrics directly
kubectl port-forward -n llm-data-vault svc/vault-api 9090:9090
curl http://localhost:9090/metrics
```

### Debug Network Issues

```bash
# Test DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup vault-api.llm-data-vault.svc.cluster.local

# Test connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- curl http://vault-api.llm-data-vault.svc.cluster.local/health
```

---

**Total Lines:** ~780

This comprehensive Kubernetes manifest provides production-ready deployment configurations for LLM-Data-Vault with complete RBAC, security policies, autoscaling, monitoring, and multi-environment support using Kustomize.

