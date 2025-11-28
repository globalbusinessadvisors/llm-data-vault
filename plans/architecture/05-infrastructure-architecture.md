# LLM-Data-Vault: Infrastructure Architecture

**Document:** Architecture Phase - Infrastructure Architecture
**Version:** 1.0.0
**Status:** Draft
**Phase:** SPARC - Architecture
**Last Updated:** 2025-11-27
**Parent Platform:** LLM DevOps Platform

---

## Table of Contents

1. [Infrastructure Overview](#1-infrastructure-overview)
2. [Kubernetes Architecture](#2-kubernetes-architecture)
3. [Compute Resources](#3-compute-resources)
4. [Storage Infrastructure](#4-storage-infrastructure)
5. [Networking](#5-networking)
6. [Scaling Architecture](#6-scaling-architecture)
7. [High Availability](#7-high-availability)
8. [Disaster Recovery](#8-disaster-recovery)
9. [Infrastructure as Code](#9-infrastructure-as-code)
10. [Cost Optimization](#10-cost-optimization)

---

## 1. Infrastructure Overview

### 1.1 Design Principles

**Cloud-Agnostic Foundation:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    Infrastructure Philosophy                     │
├─────────────────────────────────────────────────────────────────┤
│ • Cloud-Native, Not Cloud-Locked                                │
│   └─ Kubernetes as universal control plane                      │
│   └─ Standard interfaces (CSI, CNI, Service Mesh)               │
│   └─ Vendor-neutral abstractions                                │
│                                                                  │
│ • Infrastructure as Code (IaC) Everything                       │
│   └─ Terraform for cloud resources                              │
│   └─ Helm for Kubernetes workloads                              │
│   └─ GitOps for continuous deployment                           │
│                                                                  │
│ • Defense in Depth                                              │
│   └─ Network policies + Service mesh mTLS                       │
│   └─ Pod security standards (restricted)                        │
│   └─ Secrets management via external providers                  │
│                                                                  │
│ • Observability by Design                                       │
│   └─ Prometheus metrics + OpenTelemetry tracing                 │
│   └─ Structured logging with correlation IDs                    │
│   └─ Resource quotas and budget alerts                          │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Supported Deployment Targets

| Environment | Kubernetes Distribution | Storage Backend | Network Configuration |
|-------------|------------------------|-----------------|----------------------|
| **AWS** | EKS 1.28+ | S3 (Standard/IA), EBS CSI, EFS | VPC CNI, AWS Load Balancer Controller |
| **Azure** | AKS 1.28+ | Blob Storage (Hot/Cool), Azure Disk CSI | Azure CNI, Application Gateway |
| **GCP** | GKE 1.28+ | Cloud Storage, Persistent Disk CSI | GKE CNI, Cloud Load Balancing |
| **On-Premises** | K3s/RKE2/OpenShift | MinIO/Ceph, Rook-Ceph CSI | Calico/Cilium, MetalLB |
| **Hybrid** | Rancher Multi-Cluster | Cross-cloud abstraction layer | Service mesh federation (Istio) |

### 1.3 Infrastructure Stack

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Observability Layer                            │
│  Prometheus | Grafana | Loki | Tempo | Alertmanager | PagerDuty        │
└────────────────────────────────────────────────────────────────────────┘
                                    ▲
┌────────────────────────────────────────────────────────────────────────┐
│                        Application Layer (Pods)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │
│  │  API Tier    │  │ Worker Tier  │  │ Job Executor │                 │
│  │ (Deployment) │  │ (Deployment) │  │  (CronJob)   │                 │
│  └──────────────┘  └──────────────┘  └──────────────┘                 │
└────────────────────────────────────────────────────────────────────────┘
                                    ▲
┌────────────────────────────────────────────────────────────────────────┐
│                    Service Mesh & Networking Layer                      │
│       Istio/Linkerd (mTLS, Traffic Management, Observability)          │
└────────────────────────────────────────────────────────────────────────┘
                                    ▲
┌────────────────────────────────────────────────────────────────────────┐
│                      Kubernetes Control Plane                           │
│     API Server | Scheduler | Controller Manager | etcd (HA)            │
└────────────────────────────────────────────────────────────────────────┘
                                    ▲
┌────────────────────────────────────────────────────────────────────────┐
│                       Persistent Storage Layer                          │
│  Object Storage (S3 API) | PostgreSQL (HA) | Redis (Cluster)           │
└────────────────────────────────────────────────────────────────────────┘
                                    ▲
┌────────────────────────────────────────────────────────────────────────┐
│                    Cloud Provider / Bare Metal                          │
│          Compute | Networking | Block Storage | IAM                    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Kubernetes Architecture

### 2.1 Namespace Design

**Logical Isolation Strategy:**
```
┌─────────────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │ Namespace: llm-vault-prod                               │       │
│  │ ├─ API Gateway (Deployment, HPA)                        │       │
│  │ ├─ Core API (StatefulSet for leader election)           │       │
│  │ ├─ Worker Pool (Deployment, HPA)                        │       │
│  │ ├─ Policy Enforcer (DaemonSet)                          │       │
│  │ └─ Audit Logger (Deployment)                            │       │
│  │                                                          │       │
│  │ NetworkPolicy: deny-all-ingress (default deny)          │       │
│  │ ResourceQuota: cpu=100, memory=256Gi, pods=200          │       │
│  │ LimitRange: container max cpu=8, memory=16Gi            │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │ Namespace: llm-vault-data                               │       │
│  │ ├─ PostgreSQL Cluster (StatefulSet, 3 replicas)         │       │
│  │ ├─ Redis Cluster (StatefulSet, 6 replicas)              │       │
│  │ └─ PgBouncer (Deployment)                               │       │
│  │                                                          │       │
│  │ NetworkPolicy: allow from llm-vault-prod only           │       │
│  │ ResourceQuota: cpu=64, memory=384Gi, storage=10Ti       │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │ Namespace: llm-vault-jobs                               │       │
│  │ ├─ PII Scanner (CronJob, daily)                         │       │
│  │ ├─ Backup Orchestrator (CronJob, hourly)                │       │
│  │ └─ Compliance Reporter (CronJob, weekly)                │       │
│  │                                                          │       │
│  │ NetworkPolicy: egress to vault-prod API only            │       │
│  │ ResourceQuota: cpu=32, memory=128Gi                     │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │ Namespace: istio-system (Service Mesh)                  │       │
│  │ ├─ Istiod (Control Plane)                               │       │
│  │ ├─ Ingress Gateway (LoadBalancer)                       │       │
│  │ └─ Egress Gateway (for external KMS)                    │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │ Namespace: monitoring                                   │       │
│  │ ├─ Prometheus (StatefulSet)                             │       │
│  │ ├─ Grafana (Deployment)                                 │       │
│  │ └─ Loki (StatefulSet)                                   │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Namespace Tagging Strategy:**
```yaml
metadata:
  labels:
    environment: production
    component: llm-data-vault
    tier: application
    compliance: pci-dss,hipaa,gdpr
    cost-center: ml-infrastructure
  annotations:
    opa.policy/enforce: "true"
    network.policy/default-deny: "true"
```

### 2.2 Pod Specifications

**API Tier Pod Template:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: vault-api
  labels:
    app: vault-api
    version: v1.2.3
    tier: api
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
spec:
  # Security Context (Pod Level)
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    runAsGroup: 10000
    fsGroup: 10000
    seccompProfile:
      type: RuntimeDefault
    supplementalGroups: [10000]

  # Service Account with IRSA/Workload Identity
  serviceAccountName: vault-api-sa
  automountServiceAccountToken: true

  # Node Affinity (prefer AMD64, avoid spot for API)
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/arch
            operator: In
            values: [amd64, arm64]
          - key: node.kubernetes.io/instance-type
            operator: NotIn
            values: [spot, preemptible]
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app: vault-api
          topologyKey: kubernetes.io/hostname

  # Tolerations (for tainted nodes)
  tolerations:
  - key: vault-dedicated
    operator: Equal
    value: "true"
    effect: NoSchedule

  # Container Specification
  containers:
  - name: vault-api
    image: ghcr.io/llm-data-vault/api:v1.2.3
    imagePullPolicy: IfNotPresent

    # Security Context (Container Level)
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 10000
      capabilities:
        drop: [ALL]

    # Resource Management
    resources:
      requests:
        cpu: 1000m          # 1 vCPU guaranteed
        memory: 2Gi         # 2GB guaranteed
        ephemeral-storage: 1Gi
      limits:
        cpu: 2000m          # Max 2 vCPU burst
        memory: 4Gi         # OOM kill at 4GB
        ephemeral-storage: 2Gi

    # Port Configuration
    ports:
    - name: http
      containerPort: 8080
      protocol: TCP
    - name: grpc
      containerPort: 50051
      protocol: TCP
    - name: metrics
      containerPort: 9090
      protocol: TCP

    # Health Probes
    startupProbe:
      httpGet:
        path: /health/startup
        port: 8080
        scheme: HTTP
      initialDelaySeconds: 10
      periodSeconds: 5
      timeoutSeconds: 3
      successThreshold: 1
      failureThreshold: 30    # 150s max startup time

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

    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8080
        scheme: HTTP
      initialDelaySeconds: 5
      periodSeconds: 5
      timeoutSeconds: 3
      successThreshold: 1
      failureThreshold: 2

    # Environment Configuration
    env:
    - name: RUST_LOG
      value: "info,vault_api=debug"
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: vault-db-credentials
          key: connection-string
    - name: REDIS_URL
      valueFrom:
        configMapKeyRef:
          name: vault-config
          key: redis-url
    - name: KMS_ENDPOINT
      valueFrom:
        configMapKeyRef:
          name: vault-config
          key: kms-endpoint
    - name: POD_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
    - name: POD_NAMESPACE
      valueFrom:
        fieldRef:
          fieldPath: metadata.namespace

    # Volume Mounts
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache/vault
    - name: config
      mountPath: /etc/vault
      readOnly: true
    - name: tls-certs
      mountPath: /etc/tls
      readOnly: true

  # Volumes
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 500Mi
  - name: cache
    emptyDir:
      sizeLimit: 1Gi
  - name: config
    configMap:
      name: vault-config
      defaultMode: 0444
  - name: tls-certs
    secret:
      secretName: vault-tls
      defaultMode: 0400

  # DNS Configuration
  dnsPolicy: ClusterFirst
  dnsConfig:
    options:
    - name: ndots
      value: "2"
    - name: timeout
      value: "2"

  # Termination Grace Period
  terminationGracePeriodSeconds: 60

  # Priority Class
  priorityClassName: high-priority
```

### 2.3 Service Mesh Integration

**Istio Configuration:**
```yaml
---
# Virtual Service (Traffic Routing)
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: vault-api
  namespace: llm-vault-prod
spec:
  hosts:
  - vault-api.llm-vault-prod.svc.cluster.local
  - api.vault.example.com
  http:
  - match:
    - headers:
        x-api-version:
          exact: v2
    route:
    - destination:
        host: vault-api.llm-vault-prod.svc.cluster.local
        subset: v2
      weight: 100
  - route:
    - destination:
        host: vault-api.llm-vault-prod.svc.cluster.local
        subset: v1
      weight: 90
    - destination:
        host: vault-api.llm-vault-prod.svc.cluster.local
        subset: v2
      weight: 10
  timeout: 30s
  retries:
    attempts: 3
    perTryTimeout: 10s
    retryOn: 5xx,reset,connect-failure,refused-stream

---
# Destination Rule (Connection Pool, Circuit Breaker)
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: vault-api
  namespace: llm-vault-prod
spec:
  host: vault-api.llm-vault-prod.svc.cluster.local
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 1000
      http:
        http1MaxPendingRequests: 1000
        http2MaxRequests: 1000
        maxRequestsPerConnection: 10
    loadBalancer:
      consistentHash:
        httpHeaderName: x-tenant-id
    outlierDetection:
      consecutiveErrors: 5
      interval: 30s
      baseEjectionTime: 60s
      maxEjectionPercent: 50
      minHealthPercent: 50
    tls:
      mode: ISTIO_MUTUAL
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2

---
# Peer Authentication (mTLS Enforcement)
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: llm-vault-prod
spec:
  mtls:
    mode: STRICT

---
# Authorization Policy (L7 Access Control)
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: vault-api-authz
  namespace: llm-vault-prod
spec:
  selector:
    matchLabels:
      app: vault-api
  action: ALLOW
  rules:
  - from:
    - source:
        namespaces: ["llm-vault-prod", "llm-monitor", "llm-analytics"]
        principals: ["cluster.local/ns/*/sa/vault-client"]
    to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE"]
        paths: ["/api/v1/*"]
    when:
    - key: request.headers[authorization]
      values: ["Bearer *"]
```

---

## 3. Compute Resources

### 3.1 Tier Definitions

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Compute Tier Architecture                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌────────────────────┐         ┌────────────────────┐              │
│  │    API Tier        │         │   Worker Tier      │              │
│  ├────────────────────┤         ├────────────────────┤              │
│  │ Purpose:           │         │ Purpose:           │              │
│  │ - REST/gRPC API    │         │ - PII Detection    │              │
│  │ - Request routing  │         │ - Anonymization    │              │
│  │ - Auth/Policy      │         │ - Encryption       │              │
│  │                    │         │ - Batch Jobs       │              │
│  │ Workload:          │         │                    │              │
│  │ - Deployment (HPA) │         │ Workload:          │              │
│  │ - Replicas: 3-20   │         │ - Deployment (HPA) │              │
│  │                    │         │ - Replicas: 2-50   │              │
│  │ Node Pool:         │         │                    │              │
│  │ - General Purpose  │         │ Node Pool:         │              │
│  │ - Low latency      │         │ - Compute-Opt      │              │
│  │ - No spot          │         │ - Spot allowed     │              │
│  └────────────────────┘         └────────────────────┘              │
│                                                                       │
│  ┌────────────────────┐         ┌────────────────────┐              │
│  │   Job Executor     │         │   Data Tier        │              │
│  ├────────────────────┤         ├────────────────────┤              │
│  │ Purpose:           │         │ Purpose:           │              │
│  │ - Scheduled tasks  │         │ - PostgreSQL       │              │
│  │ - Compliance jobs  │         │ - Redis            │              │
│  │ - Backup/restore   │         │ - Message Queue    │              │
│  │                    │         │                    │              │
│  │ Workload:          │         │ Workload:          │              │
│  │ - CronJob/Job      │         │ - StatefulSet      │              │
│  │ - Parallel: 1-10   │         │ - Fixed replicas   │              │
│  │                    │         │                    │              │
│  │ Node Pool:         │         │ Node Pool:         │              │
│  │ - Spot instances   │         │ - Memory-Opt       │              │
│  │ - Preemptible OK   │         │ - SSD-backed       │              │
│  └────────────────────┘         │ - No spot          │              │
│                                  └────────────────────┘              │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.2 Resource Sizing Table

| Component | Replicas | CPU Request | CPU Limit | Memory Request | Memory Limit | Storage | Notes |
|-----------|----------|-------------|-----------|----------------|--------------|---------|-------|
| **API Gateway** | 3-10 | 500m | 1000m | 1Gi | 2Gi | - | Nginx/Envoy proxy |
| **Core API** | 3-20 | 1000m | 2000m | 2Gi | 4Gi | - | Rust async runtime |
| **Worker Pool** | 2-50 | 2000m | 4000m | 4Gi | 8Gi | - | CPU-intensive PII detection |
| **Policy Enforcer** | 1/node | 250m | 500m | 512Mi | 1Gi | - | DaemonSet, OPA sidecar |
| **Audit Logger** | 2-6 | 500m | 1000m | 1Gi | 2Gi | - | High throughput writes |
| **PostgreSQL Primary** | 1 | 4000m | 8000m | 16Gi | 32Gi | 500Gi SSD | ACID metadata store |
| **PostgreSQL Replica** | 2 | 2000m | 4000m | 8Gi | 16Gi | 500Gi SSD | Read replicas |
| **Redis Cluster** | 6 | 1000m | 2000m | 4Gi | 8Gi | 50Gi SSD | 3 master + 3 replica |
| **PgBouncer** | 2 | 500m | 1000m | 512Mi | 1Gi | - | Connection pooling |
| **PII Scanner Job** | 1-10 | 2000m | 4000m | 8Gi | 16Gi | - | Parallel batch processing |
| **Backup Job** | 1 | 1000m | 2000m | 4Gi | 8Gi | - | Velero + custom scripts |

**Total Cluster Baseline (Minimum HA):**
- **Control Plane:** 3 nodes (managed by cloud provider)
- **Worker Nodes:** 12 nodes
  - API Pool: 3x c6i.2xlarge (8 vCPU, 16GB)
  - Worker Pool: 6x c6i.4xlarge (16 vCPU, 32GB)
  - Data Pool: 3x r6i.2xlarge (8 vCPU, 64GB)
- **Total Compute:** 192 vCPUs, 576GB RAM
- **Total Storage:** 3.5TB SSD (PostgreSQL + Redis + local caching)

### 3.3 Node Pool Configuration

**AWS EKS Example:**
```yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: llm-vault-prod
  region: us-west-2
  version: "1.28"

managedNodeGroups:
  # API Tier - Low Latency, No Spot
  - name: api-pool
    instanceType: c6i.2xlarge
    minSize: 3
    maxSize: 10
    desiredCapacity: 3
    volumeSize: 100
    volumeType: gp3
    volumeIOPS: 3000
    volumeThroughput: 125
    privateNetworking: true
    availabilityZones: [us-west-2a, us-west-2b, us-west-2c]
    labels:
      workload: api
      tier: frontend
    taints:
      - key: workload
        value: api
        effect: NoSchedule
    tags:
      cost-center: llm-infrastructure
      backup: daily

  # Worker Tier - Compute Optimized, 50% Spot
  - name: worker-pool
    instanceTypes: [c6i.4xlarge, c6a.4xlarge, c5.4xlarge]
    minSize: 2
    maxSize: 50
    desiredCapacity: 6
    spot: true
    instancesDistribution:
      onDemandBaseCapacity: 3
      onDemandPercentageAboveBaseCapacity: 50
      spotAllocationStrategy: capacity-optimized
    volumeSize: 150
    volumeType: gp3
    privateNetworking: true
    availabilityZones: [us-west-2a, us-west-2b, us-west-2c]
    labels:
      workload: worker
      tier: backend
    tags:
      cost-center: llm-infrastructure

  # Data Tier - Memory Optimized, No Spot
  - name: data-pool
    instanceType: r6i.2xlarge
    minSize: 3
    maxSize: 6
    desiredCapacity: 3
    volumeSize: 200
    volumeType: io2
    volumeIOPS: 10000
    privateNetworking: true
    availabilityZones: [us-west-2a, us-west-2b, us-west-2c]
    labels:
      workload: database
      tier: data
    taints:
      - key: workload
        value: database
        effect: NoSchedule
    tags:
      cost-center: llm-infrastructure
      backup: hourly

cloudWatch:
  clusterLogging:
    enableTypes: ["api", "audit", "authenticator", "controllerManager", "scheduler"]
```

---

## 4. Storage Infrastructure

### 4.1 Storage Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Storage Layer Architecture                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │            Object Storage (S3-Compatible)                 │      │
│  ├──────────────────────────────────────────────────────────┤      │
│  │  Primary Use: Encrypted blob storage (prompts, datasets) │      │
│  │                                                           │      │
│  │  Buckets:                                                 │      │
│  │  ├─ vault-data-prod (Versioning: ON, Encryption: SSE-KMS)│      │
│  │  │  └─ Lifecycle: Transition to IA after 90 days         │      │
│  │  ├─ vault-backups (Versioning: ON, Replication: ON)      │      │
│  │  │  └─ Lifecycle: Expire after 90 days                   │      │
│  │  └─ vault-audit-logs (WORM, Legal Hold, 7yr retention)   │      │
│  │                                                           │      │
│  │  Performance:                                             │      │
│  │  - Request rate: 5,500 PUT/s, 50,000 GET/s per prefix    │      │
│  │  - Throughput: 100 GB/s aggregate                        │      │
│  │  - Latency: P50=10ms, P99=50ms                           │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │              PostgreSQL (Metadata Store)                  │      │
│  ├──────────────────────────────────────────────────────────┤      │
│  │  Primary Use: Transactional metadata, lineage, policies  │      │
│  │                                                           │      │
│  │  Configuration:                                           │      │
│  │  ├─ Version: PostgreSQL 15.x                             │      │
│  │  ├─ Deployment: StatefulSet with Patroni (HA)            │      │
│  │  ├─ Storage: 500GB gp3 EBS (10,000 IOPS, 500 MB/s)       │      │
│  │  └─ Backup: Continuous WAL archiving to S3               │      │
│  │                                                           │      │
│  │  Topology:                                                │      │
│  │  ├─ 1 Primary (Read-Write, leader election via etcd)     │      │
│  │  └─ 2 Replicas (Read-Only, async replication)            │      │
│  │                                                           │      │
│  │  Performance:                                             │      │
│  │  - Max connections: 1000 (via PgBouncer pooling)         │      │
│  │  - Shared buffers: 8GB                                   │      │
│  │  - Effective cache: 24GB                                 │      │
│  │  - Write throughput: 10,000 TPS                          │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │                Redis (Caching Layer)                      │      │
│  ├──────────────────────────────────────────────────────────┤      │
│  │  Primary Use: Policy cache, DEK cache, rate limiting     │      │
│  │                                                           │      │
│  │  Configuration:                                           │      │
│  │  ├─ Mode: Cluster (6 nodes: 3 master, 3 replica)         │      │
│  │  ├─ Persistence: AOF every second + RDB snapshot hourly  │      │
│  │  ├─ Storage: 50GB SSD per node (300GB total)             │      │
│  │  └─ Eviction: allkeys-lru (auto-evict on memory pressure)│      │
│  │                                                           │      │
│  │  Performance:                                             │      │
│  │  - Max throughput: 250,000 ops/s                         │      │
│  │  - P99 latency: <1ms                                     │      │
│  │  - Hit ratio target: >95%                                │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Persistent Volume Configuration

**PostgreSQL StatefulSet Storage:**
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data-postgres-0
  namespace: llm-vault-data
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-ssd
  resources:
    requests:
      storage: 500Gi
  volumeMode: Filesystem

---
# Storage Class (AWS EBS gp3 example)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
  iops: "10000"
  throughput: "500"
  encrypted: "true"
  kmsKeyId: "arn:aws:kms:us-west-2:123456789:key/abc-def"
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
```

### 4.3 Storage Classes by Use Case

| Use Case | Storage Class | Provisioner | Performance | Cost | Backup |
|----------|---------------|-------------|-------------|------|--------|
| PostgreSQL Data | `fast-ssd` | EBS io2 / Azure Premium SSD | 10K IOPS, 500 MB/s | $$$ | Hourly snapshots |
| Redis Persistence | `balanced-ssd` | EBS gp3 / Azure Standard SSD | 3K IOPS, 125 MB/s | $$ | Daily snapshots |
| Audit Logs (local) | `standard-hdd` | EBS st1 / Azure Standard HDD | 500 MB/s throughput | $ | Weekly snapshots |
| Temporary Scratch | `ephemeral` | emptyDir (node local) | Node disk speed | Free | None |
| Shared Config | `nfs` | EFS / Azure Files | 50 MB/s | $ | Daily snapshots |

---

## 5. Networking

### 5.1 Network Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         External Traffic Flow                         │
└──────────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   Public Load Balancer    │
                    │  (AWS ALB / Azure AppGW)  │
                    │  - TLS 1.3 termination    │
                    │  - WAF enabled            │
                    │  - DDoS protection        │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   Istio Ingress Gateway   │
                    │  - mTLS re-encryption     │
                    │  - Rate limiting (100 rps)│
                    │  - JWT validation         │
                    └─────────────┬─────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                  Service Mesh (Istio)             │
        │              ┌───────────▼────────────┐            │
        │              │     Virtual Service    │            │
        │              │  - Traffic splitting   │            │
        │              │  - Retries & timeouts  │            │
        │              └───────────┬────────────┘            │
        │                          │                         │
        │    ┌─────────────────────┼─────────────────────┐  │
        │    │                     │                     │  │
        │    ▼                     ▼                     ▼  │
        │ ┌──────┐             ┌──────┐             ┌──────┐│
        │ │ API  │             │ API  │             │ API  ││
        │ │ Pod 1│             │ Pod 2│             │ Pod 3││
        │ └──┬───┘             └──┬───┘             └──┬───┘│
        └────┼───────────────────┼───────────────────┼─────┘
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Internal Services    │
                    ├─────────────────────────┤
                    │ PostgreSQL (ClusterIP)  │
                    │ Redis (ClusterIP)       │
                    │ KMS (via Egress Gateway)│
                    └─────────────────────────┘
```

### 5.2 Network Policies

**Default Deny + Explicit Allow:**
```yaml
---
# Default Deny All Ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: llm-vault-prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress

---
# Allow API -> PostgreSQL
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-postgres
  namespace: llm-vault-data
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: llm-vault-prod
      podSelector:
        matchLabels:
          tier: api
    ports:
    - protocol: TCP
      port: 5432

---
# Allow Ingress -> API (only via Istio)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-api
  namespace: llm-vault-prod
spec:
  podSelector:
    matchLabels:
      app: vault-api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: istio-system
      podSelector:
        matchLabels:
          app: istio-ingressgateway
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 50051

---
# Egress to KMS only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-kms
  namespace: llm-vault-prod
spec:
  podSelector:
    matchLabels:
      tier: api
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 53  # DNS
  - to:
    - podSelector:
        matchLabels:
          app: istio-egressgateway
    ports:
    - protocol: TCP
      port: 443  # HTTPS to KMS
```

### 5.3 Multi-Region Networking

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Multi-Region Architecture                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Region: US-West-2 (Primary)          Region: EU-West-1 (Secondary)  │
│  ┌─────────────────────────┐          ┌─────────────────────────┐   │
│  │  VPC: 10.0.0.0/16       │          │  VPC: 10.1.0.0/16       │   │
│  │  ┌───────────────────┐  │          │  ┌───────────────────┐  │   │
│  │  │ EKS Cluster       │  │          │  │ EKS Cluster       │  │   │
│  │  │ - API: 10.0.1.0/24│  │          │  │ - API: 10.1.1.0/24│  │   │
│  │  │ - Data: 10.0.2.0/24  │          │  │ - Data: 10.1.2.0/24  │   │
│  │  └───────────────────┘  │          │  └───────────────────┘  │   │
│  │  ┌───────────────────┐  │          │  ┌───────────────────┐  │   │
│  │  │ RDS PostgreSQL    │  │          │  │ RDS Read Replica  │  │   │
│  │  │ (Primary)         │◄─┼──────────┼──│ (Async Repl)      │  │   │
│  │  └───────────────────┘  │          │  └───────────────────┘  │   │
│  │  ┌───────────────────┐  │          │  ┌───────────────────┐  │   │
│  │  │ S3 Bucket         │  │          │  │ S3 Bucket         │  │   │
│  │  │ (Primary)         │◄─┼──────────┼──│ (CRR Enabled)     │  │   │
│  │  └───────────────────┘  │          │  └───────────────────┘  │   │
│  └─────────────────────────┘          └─────────────────────────┘   │
│             │                                      │                 │
│             └──────────────────┬───────────────────┘                 │
│                                │                                     │
│                    ┌───────────▼──────────┐                          │
│                    │  Route 53 / Traffic  │                          │
│                    │  Manager (GeoDNS)    │                          │
│                    │  - Latency routing   │                          │
│                    │  - Health checks     │                          │
│                    └──────────────────────┘                          │
│                                                                       │
│  Cross-Region Connectivity:                                          │
│  - VPC Peering (10 Gbps encrypted)                                   │
│  - S3 Cross-Region Replication (15min RPO)                           │
│  - PostgreSQL Async Replication (1min lag)                           │
└──────────────────────────────────────────────────────────────────────┘
```

**Ingress Configuration (Multi-Region):**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vault-api
  namespace: llm-vault-prod
  annotations:
    # AWS ALB
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-west-2:123:cert/abc
    alb.ingress.kubernetes.io/ssl-policy: ELBSecurityPolicy-TLS13-1-2-2021-06
    alb.ingress.kubernetes.io/healthcheck-path: /health/ready
    alb.ingress.kubernetes.io/healthcheck-interval-seconds: "15"
    alb.ingress.kubernetes.io/healthy-threshold-count: "2"
    alb.ingress.kubernetes.io/unhealthy-threshold-count: "3"
    alb.ingress.kubernetes.io/load-balancer-attributes: >
      access_logs.s3.enabled=true,
      access_logs.s3.bucket=vault-alb-logs,
      idle_timeout.timeout_seconds=120
    # Rate limiting
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/limit-rps: "10"
    # CORS
    nginx.ingress.kubernetes.io/cors-allow-origin: "https://vault.example.com"
spec:
  ingressClassName: alb
  rules:
  - host: api.vault.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: vault-api
            port:
              number: 8080
  tls:
  - hosts:
    - api.vault.example.com
    secretName: vault-tls
```

---

## 6. Scaling Architecture

### 6.1 Horizontal Pod Autoscaling (HPA)

**API Tier HPA Configuration:**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vault-api-hpa
  namespace: llm-vault-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vault-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
  # CPU-based scaling
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  # Memory-based scaling
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  # Custom metrics (from Prometheus)
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
  - type: Pods
    pods:
      metric:
        name: grpc_concurrent_requests
      target:
        type: AverageValue
        averageValue: "500"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
      - type: Pods
        value: 2
        periodSeconds: 60
      selectPolicy: Max
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
      - type: Pods
        value: 1
        periodSeconds: 120
      selectPolicy: Min
```

**Worker Tier HPA (KEDA for advanced scaling):**
```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: vault-worker-scaler
  namespace: llm-vault-prod
spec:
  scaleTargetRef:
    name: vault-worker
  minReplicaCount: 2
  maxReplicaCount: 50
  pollingInterval: 15
  cooldownPeriod: 300
  triggers:
  # Scale based on Kafka message lag
  - type: kafka
    metadata:
      bootstrapServers: kafka.kafka.svc:9092
      consumerGroup: vault-workers
      topic: pii-detection-queue
      lagThreshold: "100"
  # Scale based on custom Prometheus metrics
  - type: prometheus
    metadata:
      serverAddress: http://prometheus.monitoring:9090
      metricName: vault_worker_queue_depth
      threshold: "50"
      query: |
        sum(vault_worker_queue_depth{namespace="llm-vault-prod"})
  # Scale based on CPU (backup trigger)
  - type: cpu
    metadataType: Utilization
    metadata:
      value: "75"
```

### 6.2 Database Scaling

**PostgreSQL Scaling Strategy:**
```
┌──────────────────────────────────────────────────────────────────────┐
│                     PostgreSQL Scaling Approach                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Vertical Scaling (Primary):                                         │
│  ┌────────────────────────────────────────────────────────┐          │
│  │ Stage 1: r6i.2xlarge (8 vCPU, 64GB)  - 10K TPS        │          │
│  │ Stage 2: r6i.4xlarge (16 vCPU, 128GB) - 25K TPS       │          │
│  │ Stage 3: r6i.8xlarge (32 vCPU, 256GB) - 50K TPS       │          │
│  │ Stage 4: r6i.16xlarge (64 vCPU, 512GB) - 100K TPS     │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  Horizontal Scaling (Read Replicas):                                 │
│  ┌────────────────────────────────────────────────────────┐          │
│  │            ┌─────────────┐                             │          │
│  │            │   Primary   │                             │          │
│  │            │  (Write)    │                             │          │
│  │            └──────┬──────┘                             │          │
│  │                   │                                    │          │
│  │        ┌──────────┼──────────┬──────────┐             │          │
│  │        ▼          ▼          ▼          ▼             │          │
│  │    ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐           │          │
│  │    │Replica│ │Replica│ │Replica│ │Replica│           │          │
│  │    │  (R)  │ │  (R)  │ │  (R)  │ │  (R)  │           │          │
│  │    └───────┘ └───────┘ └───────┘ └───────┘           │          │
│  │                                                        │          │
│  │  Load Distribution:                                   │          │
│  │  - PgBouncer routes reads to replicas (round-robin)   │          │
│  │  - Writes always to primary                           │          │
│  │  - 80% read / 20% write ratio                         │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  Connection Pooling (PgBouncer):                                     │
│  ┌────────────────────────────────────────────────────────┐          │
│  │ Max Client Connections: 10,000                         │          │
│  │ Max Server Connections: 1,000                          │          │
│  │ Pool Mode: Transaction (best for short queries)        │          │
│  │ Default Pool Size: 25 per database                     │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.3 Scaling Triggers and Thresholds

| Metric | Warning Threshold | Critical Threshold | Auto-Scale Action | Manual Action Required |
|--------|-------------------|--------------------|--------------------|----------------------|
| **API CPU Utilization** | 60% avg | 80% avg | Scale out (+2 pods) | Review code efficiency |
| **API Memory** | 70% avg | 85% avg | Scale out (+2 pods) | Investigate memory leak |
| **API Request Latency** | P95 > 200ms | P95 > 500ms | Scale out (+2 pods) | Check downstream deps |
| **API Error Rate** | 1% | 5% | Alert only | Incident response |
| **Worker Queue Depth** | 500 msgs | 2000 msgs | Scale out (+5 pods) | Check job failures |
| **PostgreSQL CPU** | 60% | 80% | Alert only | Vertical scale or add replica |
| **PostgreSQL Connections** | 700/1000 | 900/1000 | Alert only | Review connection leaks |
| **PostgreSQL Replication Lag** | 30s | 60s | Alert + failover prep | Check network/load |
| **Redis Memory** | 80% | 90% | Increase eviction rate | Add nodes or vertical scale |
| **Redis Hit Rate** | < 90% | < 80% | Alert only | Review caching strategy |
| **S3 Request Rate** | 4000/s/prefix | 5000/s/prefix | Alert only | Add prefixes/sharding |
| **Node CPU** | 70% | 85% | Cluster autoscaler +1 node | Review pod requests |
| **Node Memory** | 75% | 90% | Cluster autoscaler +1 node | Review pod requests |

---

## 7. High Availability

### 7.1 Multi-AZ Deployment Topology

```
┌──────────────────────────────────────────────────────────────────────┐
│                 AWS Region: us-west-2 (3-AZ Deployment)              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌────────────────────┐ ┌────────────────────┐ ┌────────────────────┐│
│  │ Availability Zone A│ │ Availability Zone B│ │ Availability Zone C││
│  ├────────────────────┤ ├────────────────────┤ ├────────────────────┤│
│  │                    │ │                    │ │                    ││
│  │ Control Plane      │ │ Control Plane      │ │ Control Plane      ││
│  │ ┌────────────┐     │ │ ┌────────────┐     │ │ ┌────────────┐     ││
│  │ │ API Server │     │ │ │ API Server │     │ │ │ API Server │     ││
│  │ │ etcd member│     │ │ │ etcd member│     │ │ │ etcd member│     ││
│  │ └────────────┘     │ │ └────────────┘     │ │ └────────────┘     ││
│  │                    │ │                    │ │                    ││
│  │ Worker Nodes       │ │ Worker Nodes       │ │ Worker Nodes       ││
│  │ ┌────────────┐     │ │ ┌────────────┐     │ │ ┌────────────┐     ││
│  │ │ API Pod 1  │     │ │ │ API Pod 2  │     │ │ │ API Pod 3  │     ││
│  │ │ Worker 1-2 │     │ │ │ Worker 3-4 │     │ │ │ Worker 5-6 │     ││
│  │ └────────────┘     │ │ └────────────┘     │ │ └────────────┘     ││
│  │                    │ │                    │ │                    ││
│  │ Data Layer         │ │ Data Layer         │ │ Data Layer         ││
│  │ ┌────────────┐     │ │ ┌────────────┐     │ │ ┌────────────┐     ││
│  │ │ PG Primary │     │ │ │ PG Replica │     │ │ │ PG Replica │     ││
│  │ │ Redis M1   │     │ │ │ Redis M2   │     │ │ │ Redis M3   │     ││
│  │ │ Redis R3   │     │ │ │ Redis R1   │     │ │ │ Redis R2   │     ││
│  │ └────────────┘     │ │ └────────────┘     │ │ └────────────┘     ││
│  │                    │ │                    │ │                    ││
│  │ Load Balancer      │ │ Load Balancer      │ │ Load Balancer      ││
│  │ ┌────────────┐     │ │ ┌────────────┐     │ │ ┌────────────┐     ││
│  │ │ ALB Target │     │ │ │ ALB Target │     │ │ │ ALB Target │     ││
│  │ └────────────┘     │ │ └────────────┘     │ │ └────────────┘     ││
│  │                    │ │                    │ │                    ││
│  └────────────────────┘ └────────────────────┘ └────────────────────┘│
│                                                                       │
│  Failure Scenarios:                                                  │
│  ├─ AZ Failure: Continue with 2/3 AZs (66% capacity)                │
│  ├─ Pod Failure: K8s restarts pod within 30s                        │
│  ├─ Node Failure: K8s reschedules pods to healthy nodes (2-3min)    │
│  └─ Database Primary Failure: Patroni promotes replica (<30s)       │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### 7.2 Failure Mode Analysis

| Component | SPOF? | Failure Detection | Failover Time | Data Loss | Mitigation |
|-----------|-------|-------------------|---------------|-----------|------------|
| **API Pod** | No | Liveness probe (10s) | 10-30s | None | 3+ replicas, pod anti-affinity |
| **Worker Pod** | No | Job timeout (5min) | Auto-retry | None | Queue-based processing |
| **PostgreSQL Primary** | No | Patroni health check (5s) | 20-30s | ~5s of commits | Synchronous replication to 1 replica |
| **PostgreSQL Replica** | No | Connection failure | Immediate | None | PgBouncer routes to healthy replicas |
| **Redis Master** | No | Sentinel health check (3s) | 10-15s | AOF: 1s | Redis Cluster with replicas |
| **Redis Replica** | No | Cluster health check | Immediate | None | 3 masters + 3 replicas |
| **S3 Bucket** | No | AWS internal (99.99% SLA) | Automatic | None | Cross-region replication |
| **Load Balancer** | No | Health checks (15s) | Automatic | None | Multi-AZ ALB |
| **Kubernetes Node** | No | Node controller (40s) | 2-3min | None | Multi-node, pod disruption budgets |
| **Availability Zone** | No | Multi-AZ health | Automatic | None | Spread across 3 AZs |

### 7.3 Failover Procedures

**PostgreSQL Primary Failover (Patroni):**
```bash
# Automatic failover (no manual intervention)
# 1. Patroni detects primary failure (health check timeout: 5s)
# 2. DCS (etcd) consensus confirms failure (quorum: 2/3 nodes)
# 3. Patroni elects new primary from healthy replicas
# 4. New primary promoted (timeline increment)
# 5. Remaining replicas re-point to new primary
# Total time: 20-30 seconds

# Manual failover (maintenance)
patronictl -c /etc/patroni/patroni.yml switchover --master postgres-0 --candidate postgres-1

# Verify cluster status
patronictl -c /etc/patroni/patroni.yml list
```

**Redis Cluster Failover:**
```bash
# Automatic failover (no manual intervention)
# Redis Cluster handles this internally via gossip protocol
# Detection: 2s (NODE_TIMEOUT), Failover: 5-10s

# Manual failover (maintenance)
redis-cli --cluster failover <replica-ip>:6379

# Verify cluster status
redis-cli --cluster check <any-node-ip>:6379
kubectl exec -it redis-0 -n llm-vault-data -- redis-cli cluster nodes
```

**Pod Disruption Budget (Prevent Cascading Failures):**
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: vault-api-pdb
  namespace: llm-vault-prod
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: vault-api

---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: postgres-pdb
  namespace: llm-vault-data
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app: postgres
```

---

## 8. Disaster Recovery

### 8.1 Backup Strategy

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Backup Architecture                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Object Storage (S3):                                                │
│  ┌────────────────────────────────────────────────────────┐          │
│  │ Backup Method: S3 Versioning + Cross-Region Replication│          │
│  │ Frequency: Continuous (versioning)                     │          │
│  │ Retention:                                             │          │
│  │   ├─ Current version: Indefinite                       │          │
│  │   ├─ Previous versions: 90 days                        │          │
│  │   └─ Delete markers: 30 days                           │          │
│  │ RPO: 0 seconds (synchronous versioning)                │          │
│  │ RTO: 5 minutes (restore from version)                  │          │
│  │ Storage Cost: ~$0.023/GB/month (Standard + versioning) │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  PostgreSQL:                                                         │
│  ┌────────────────────────────────────────────────────────┐          │
│  │ Backup Method: Continuous WAL archiving + pg_basebackup│          │
│  │ Frequency:                                             │          │
│  │   ├─ WAL shipping: Continuous (every 16MB or 1min)     │          │
│  │   ├─ Full backup: Daily at 02:00 UTC                   │          │
│  │   └─ EBS snapshots: Hourly                             │          │
│  │ Retention:                                             │          │
│  │   ├─ WAL archives: 7 days                              │          │
│  │   ├─ Full backups: 30 days                             │          │
│  │   └─ EBS snapshots: 7 days                             │          │
│  │ RPO: 1 minute (WAL shipping lag)                       │          │
│  │ RTO: 15 minutes (restore + recovery)                   │          │
│  │ Backup Size: 500GB base + 50GB WAL/day                 │          │
│  │ Verification: Daily restore test to ephemeral instance │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  Redis:                                                              │
│  ┌────────────────────────────────────────────────────────┐          │
│  │ Backup Method: RDB snapshots + AOF persistence         │          │
│  │ Frequency:                                             │          │
│  │   ├─ RDB: Hourly (via BGSAVE)                          │          │
│  │   ├─ AOF: Every second (fsync)                         │          │
│  │   └─ EBS snapshots: Daily                              │          │
│  │ Retention:                                             │          │
│  │   ├─ RDB snapshots: 7 days                             │          │
│  │   └─ EBS snapshots: 3 days                             │          │
│  │ RPO: 1 second (AOF)                                    │          │
│  │ RTO: 5 minutes (load RDB + replay AOF)                 │          │
│  │ Backup Size: 50GB RDB + 5GB AOF/day                    │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
│  Kubernetes State:                                                   │
│  ┌────────────────────────────────────────────────────────┐          │
│  │ Backup Method: Velero (etcd + PVs)                     │          │
│  │ Frequency: Daily at 01:00 UTC                          │          │
│  │ Retention: 30 days                                     │          │
│  │ Scope:                                                 │          │
│  │   ├─ All namespaces (except kube-system)               │          │
│  │   ├─ PersistentVolumes (snapshot)                      │          │
│  │   └─ Custom resources                                  │          │
│  │ RPO: 24 hours                                          │          │
│  │ RTO: 2 hours (full cluster restore)                    │          │
│  └────────────────────────────────────────────────────────┘          │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### 8.2 RPO/RTO Matrix

| Disaster Scenario | RPO | RTO | Recovery Procedure | Tested |
|-------------------|-----|-----|-------------------|--------|
| **Single pod failure** | 0s | 30s | Automatic (K8s restart) | Weekly |
| **Node failure** | 0s | 3min | Automatic (K8s reschedule) | Weekly |
| **AZ failure** | 0s | 5min | Automatic (multi-AZ routing) | Monthly |
| **PostgreSQL data corruption** | 1min | 15min | Restore from WAL archives | Weekly |
| **Redis cache loss** | 1s | 5min | Restore from RDB+AOF | Weekly |
| **S3 bucket deletion** | 0s | 5min | Restore from version/CRR | Monthly |
| **Namespace deletion** | 24h | 2h | Velero restore | Monthly |
| **Region failure** | 15min | 4h | Failover to secondary region | Quarterly |
| **Ransomware attack** | 24h | 8h | Restore from immutable backups | Quarterly |
| **Complete cluster loss** | 24h | 12h | Rebuild from IaC + Velero | Annually |

### 8.3 Recovery Procedures

**PostgreSQL Point-in-Time Recovery:**
```bash
# 1. Stop PostgreSQL on target instance
kubectl scale statefulset postgres -n llm-vault-data --replicas=0

# 2. Restore base backup
kubectl exec -it postgres-recovery -n llm-vault-data -- bash
pg_basebackup -h s3://vault-backups/postgres/daily/2025-11-27 -D /var/lib/postgresql/data

# 3. Create recovery configuration
cat > /var/lib/postgresql/data/recovery.conf <<EOF
restore_command = 'aws s3 cp s3://vault-backups/postgres/wal/%f %p'
recovery_target_time = '2025-11-27 14:30:00 UTC'
recovery_target_action = 'promote'
EOF

# 4. Start PostgreSQL and verify recovery
kubectl scale statefulset postgres -n llm-vault-data --replicas=1
kubectl logs postgres-0 -n llm-vault-data -f

# 5. Verify data integrity
kubectl exec -it postgres-0 -n llm-vault-data -- psql -U vault -c "SELECT pg_last_wal_replay_lsn();"
```

**S3 Version Restore:**
```bash
# List all versions of a deleted object
aws s3api list-object-versions \
  --bucket vault-data-prod \
  --prefix datasets/experiment-123

# Restore specific version
aws s3api copy-object \
  --copy-source vault-data-prod/datasets/experiment-123?versionId=abc123 \
  --bucket vault-data-prod \
  --key datasets/experiment-123
```

**Velero Cluster Restore:**
```bash
# List available backups
velero backup get

# Restore entire namespace
velero restore create --from-backup daily-20251127-0100 \
  --include-namespaces llm-vault-prod \
  --wait

# Restore specific resources
velero restore create --from-backup daily-20251127-0100 \
  --include-resources deployments,configmaps,secrets \
  --namespace-mappings llm-vault-prod:llm-vault-dr \
  --wait

# Monitor restore progress
velero restore describe <restore-name> --details
kubectl get all -n llm-vault-prod
```

### 8.4 Backup Validation

**Automated Backup Testing (CronJob):**
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-validator
  namespace: llm-vault-ops
spec:
  schedule: "0 4 * * *"  # Daily at 4 AM UTC
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: validator
            image: vault-backup-validator:latest
            env:
            - name: BACKUP_BUCKET
              value: "vault-backups"
            - name: TEST_DB_INSTANCE
              value: "postgres-test.llm-vault-data.svc"
            command:
            - /bin/bash
            - -c
            - |
              # Download latest PostgreSQL backup
              LATEST_BACKUP=$(aws s3 ls s3://vault-backups/postgres/daily/ | tail -1 | awk '{print $4}')
              aws s3 cp s3://vault-backups/postgres/daily/$LATEST_BACKUP /tmp/backup.tar.gz

              # Restore to test instance
              pg_restore -h $TEST_DB_INSTANCE -U validator -d test_restore /tmp/backup.tar.gz

              # Validate data integrity
              psql -h $TEST_DB_INSTANCE -U validator -d test_restore -c "
                SELECT
                  COUNT(*) as total_objects,
                  MAX(updated_at) as latest_update
                FROM objects;
              " | tee /tmp/validation.log

              # Report results to monitoring
              curl -X POST https://monitoring.vault.svc/api/metrics \
                -d "backup_validation_success=1" \
                -d "backup_age_hours=$(($(date +%s) - $(stat -c %Y /tmp/backup.tar.gz)))"

              # Cleanup
              dropdb -h $TEST_DB_INSTANCE -U validator test_restore
```

---

## 9. Infrastructure as Code

### 9.1 Terraform Module Structure

```
terraform/
├── environments/
│   ├── production/
│   │   ├── main.tf                    # Root module composition
│   │   ├── variables.tf               # Environment-specific vars
│   │   ├── terraform.tfvars           # Production values
│   │   ├── backend.tf                 # S3 state backend config
│   │   └── outputs.tf                 # Cluster endpoints, IDs
│   ├── staging/
│   └── development/
│
├── modules/
│   ├── networking/
│   │   ├── vpc/
│   │   │   ├── main.tf                # VPC, subnets, NAT, IGW
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── security-groups/
│   │   │   ├── main.tf                # SG rules for EKS, RDS, Redis
│   │   │   └── variables.tf
│   │   └── load-balancers/
│   │       ├── alb.tf                 # Application Load Balancer
│   │       └── nlb.tf                 # Network Load Balancer (optional)
│   │
│   ├── kubernetes/
│   │   ├── eks/
│   │   │   ├── cluster.tf             # EKS control plane
│   │   │   ├── node-groups.tf         # Managed node groups (API, Worker, Data)
│   │   │   ├── irsa.tf                # IAM Roles for Service Accounts
│   │   │   ├── addons.tf              # EBS CSI, VPC CNI, CoreDNS
│   │   │   └── kms.tf                 # EKS secrets encryption
│   │   ├── aks/                       # Azure alternative
│   │   └── gke/                       # GCP alternative
│   │
│   ├── data-stores/
│   │   ├── rds-postgres/
│   │   │   ├── main.tf                # RDS cluster (primary + replicas)
│   │   │   ├── parameter-groups.tf    # PostgreSQL tuning
│   │   │   ├── backup.tf              # Automated backup config
│   │   │   └── monitoring.tf          # CloudWatch alarms
│   │   ├── elasticache-redis/
│   │   │   ├── cluster.tf             # Redis cluster mode
│   │   │   ├── parameter-groups.tf
│   │   │   └── monitoring.tf
│   │   └── s3/
│   │       ├── buckets.tf             # vault-data, vault-backups, vault-logs
│   │       ├── lifecycle.tf           # Transition to IA, Glacier
│   │       ├── replication.tf         # Cross-region replication
│   │       └── kms.tf                 # Bucket encryption keys
│   │
│   ├── security/
│   │   ├── kms/
│   │   │   ├── main.tf                # Master encryption keys
│   │   │   └── aliases.tf
│   │   ├── iam/
│   │   │   ├── roles.tf               # EKS node roles, pod roles
│   │   │   ├── policies.tf            # S3, KMS, RDS access policies
│   │   │   └── service-accounts.tf    # IRSA mappings
│   │   └── secrets-manager/
│   │       └── secrets.tf             # Database credentials, API keys
│   │
│   └── monitoring/
│       ├── cloudwatch/
│       │   ├── log-groups.tf          # Centralized logging
│       │   └── alarms.tf              # CPU, memory, disk alarms
│       └── prometheus/
│           └── remote-write.tf        # AMP or self-hosted config
│
└── shared/
    ├── providers.tf                   # AWS, Kubernetes, Helm providers
    ├── versions.tf                    # Terraform version constraints
    └── data-sources.tf                # AMI lookups, AZ discovery
```

**Example Module (RDS PostgreSQL):**
```hcl
# modules/data-stores/rds-postgres/main.tf

resource "aws_db_subnet_group" "postgres" {
  name       = "${var.cluster_name}-postgres"
  subnet_ids = var.private_subnet_ids
  tags       = var.tags
}

resource "aws_rds_cluster" "postgres" {
  cluster_identifier      = "${var.cluster_name}-postgres"
  engine                  = "aurora-postgresql"
  engine_version          = "15.4"
  engine_mode             = "provisioned"
  database_name           = "vault"
  master_username         = "vault_admin"
  master_password         = random_password.postgres.result

  # High Availability
  availability_zones              = var.availability_zones
  db_subnet_group_name            = aws_db_subnet_group.postgres.name
  vpc_security_group_ids          = [var.security_group_id]

  # Backup Configuration
  backup_retention_period         = 30
  preferred_backup_window         = "03:00-04:00"
  preferred_maintenance_window    = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot           = true

  # Encryption
  storage_encrypted               = true
  kms_key_id                      = var.kms_key_arn

  # Performance
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.postgres.name
  enabled_cloudwatch_logs_exports = ["postgresql"]

  # Point-in-Time Recovery
  backtrack_window               = 72  # 72 hours (Aurora-specific)

  skip_final_snapshot            = false
  final_snapshot_identifier      = "${var.cluster_name}-final-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  tags = var.tags
}

resource "aws_rds_cluster_instance" "postgres" {
  count              = var.instance_count
  identifier         = "${var.cluster_name}-postgres-${count.index}"
  cluster_identifier = aws_rds_cluster.postgres.id
  instance_class     = var.instance_class
  engine             = aws_rds_cluster.postgres.engine
  engine_version     = aws_rds_cluster.postgres.engine_version

  # Performance Insights
  performance_insights_enabled    = true
  performance_insights_kms_key_id = var.kms_key_arn
  performance_insights_retention_period = 7

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  tags = merge(var.tags, {
    Role = count.index == 0 ? "primary" : "replica"
  })
}

# Parameter group for PostgreSQL tuning
resource "aws_rds_cluster_parameter_group" "postgres" {
  name   = "${var.cluster_name}-postgres-params"
  family = "aurora-postgresql15"

  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements,auto_explain"
  }

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"  # Log queries > 1s
  }

  parameter {
    name  = "max_connections"
    value = "1000"
  }

  tags = var.tags
}
```

### 9.2 Helm Chart Structure

```
helm/
├── llm-vault/
│   ├── Chart.yaml                     # Chart metadata
│   ├── values.yaml                    # Default values
│   ├── values-production.yaml         # Production overrides
│   ├── values-staging.yaml
│   │
│   ├── templates/
│   │   ├── _helpers.tpl               # Template helpers
│   │   │
│   │   ├── api/
│   │   │   ├── deployment.yaml        # API tier deployment
│   │   │   ├── service.yaml           # ClusterIP service
│   │   │   ├── hpa.yaml               # Horizontal Pod Autoscaler
│   │   │   ├── pdb.yaml               # Pod Disruption Budget
│   │   │   └── servicemonitor.yaml    # Prometheus metrics scraping
│   │   │
│   │   ├── worker/
│   │   │   ├── deployment.yaml
│   │   │   ├── hpa.yaml
│   │   │   └── servicemonitor.yaml
│   │   │
│   │   ├── jobs/
│   │   │   ├── pii-scanner-cronjob.yaml
│   │   │   ├── backup-cronjob.yaml
│   │   │   └── compliance-report-job.yaml
│   │   │
│   │   ├── networking/
│   │   │   ├── ingress.yaml           # Istio VirtualService
│   │   │   ├── gateway.yaml           # Istio Gateway
│   │   │   ├── networkpolicy.yaml     # Kubernetes NetworkPolicy
│   │   │   └── destinationrule.yaml   # Istio traffic policy
│   │   │
│   │   ├── security/
│   │   │   ├── serviceaccount.yaml
│   │   │   ├── role.yaml
│   │   │   ├── rolebinding.yaml
│   │   │   └── podsecuritypolicy.yaml (deprecated, use PSS)
│   │   │
│   │   ├── config/
│   │   │   ├── configmap.yaml         # Application config
│   │   │   └── secret.yaml            # External secrets operator ref
│   │   │
│   │   └── monitoring/
│   │       ├── prometheusrule.yaml    # Alerting rules
│   │       └── grafana-dashboard.yaml # Dashboard ConfigMap
│   │
│   └── charts/                        # Subcharts (dependencies)
│       ├── postgresql/                # Bitnami PostgreSQL (optional)
│       └── redis/                     # Bitnami Redis (optional)
│
└── umbrella-chart/
    ├── Chart.yaml
    ├── values.yaml
    └── requirements.yaml              # Dependency on llm-vault + Istio + monitoring
```

**Example Helm Template (API Deployment):**
```yaml
# helm/llm-vault/templates/api/deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "llm-vault.fullname" . }}-api
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "llm-vault.labels" . | nindent 4 }}
    component: api
spec:
  replicas: {{ .Values.api.replicaCount }}
  selector:
    matchLabels:
      {{- include "llm-vault.selectorLabels" . | nindent 6 }}
      component: api
  template:
    metadata:
      annotations:
        checksum/config: {{ include (print $.Template.BasePath "/config/configmap.yaml") . | sha256sum }}
        prometheus.io/scrape: "true"
        prometheus.io/port: "{{ .Values.api.metrics.port }}"
      labels:
        {{- include "llm-vault.selectorLabels" . | nindent 8 }}
        component: api
        version: {{ .Chart.AppVersion }}
    spec:
      serviceAccountName: {{ include "llm-vault.serviceAccountName" . }}
      securityContext:
        {{- toYaml .Values.api.podSecurityContext | nindent 8 }}

      affinity:
        {{- if .Values.api.affinity }}
        {{- toYaml .Values.api.affinity | nindent 8 }}
        {{- else }}
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  {{- include "llm-vault.selectorLabels" . | nindent 18 }}
                  component: api
              topologyKey: kubernetes.io/hostname
        {{- end }}

      containers:
      - name: api
        image: "{{ .Values.api.image.repository }}:{{ .Values.api.image.tag | default .Chart.AppVersion }}"
        imagePullPolicy: {{ .Values.api.image.pullPolicy }}

        securityContext:
          {{- toYaml .Values.api.securityContext | nindent 10 }}

        ports:
        - name: http
          containerPort: {{ .Values.api.service.port }}
          protocol: TCP
        - name: grpc
          containerPort: {{ .Values.api.grpc.port }}
          protocol: TCP
        - name: metrics
          containerPort: {{ .Values.api.metrics.port }}
          protocol: TCP

        livenessProbe:
          {{- toYaml .Values.api.livenessProbe | nindent 10 }}
        readinessProbe:
          {{- toYaml .Values.api.readinessProbe | nindent 10 }}

        resources:
          {{- toYaml .Values.api.resources | nindent 10 }}

        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: {{ .Values.database.secretName }}
              key: connection-url
        - name: REDIS_URL
          value: {{ .Values.redis.url }}
        - name: LOG_LEVEL
          value: {{ .Values.api.logLevel }}
        {{- range $key, $value := .Values.api.extraEnv }}
        - name: {{ $key }}
          value: {{ $value | quote }}
        {{- end }}

        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: config
          mountPath: /etc/vault
          readOnly: true
        {{- if .Values.api.extraVolumeMounts }}
        {{- toYaml .Values.api.extraVolumeMounts | nindent 8 }}
        {{- end }}

      volumes:
      - name: tmp
        emptyDir: {}
      - name: config
        configMap:
          name: {{ include "llm-vault.fullname" . }}-config
      {{- if .Values.api.extraVolumes }}
      {{- toYaml .Values.api.extraVolumes | nindent 6 }}
      {{- end }}
```

### 9.3 GitOps Workflow (ArgoCD)

```
┌──────────────────────────────────────────────────────────────────────┐
│                       GitOps Deployment Flow                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌────────────┐         ┌────────────┐         ┌────────────┐       │
│  │   GitHub   │         │   ArgoCD   │         │ Kubernetes │       │
│  │ Repository │         │   Server   │         │  Cluster   │       │
│  └─────┬──────┘         └──────┬─────┘         └──────┬─────┘       │
│        │                       │                      │              │
│   1. Developer                 │                      │              │
│      commits Helm              │                      │              │
│      values change             │                      │              │
│        │                       │                      │              │
│        ├──────────────────────>│                      │              │
│        │   2. ArgoCD polls     │                      │              │
│        │      repo every 3min  │                      │              │
│        │                       │                      │              │
│        │                       ├─ 3. Detect drift     │              │
│        │                       │    (Git != Cluster)  │              │
│        │                       │                      │              │
│        │                       ├─ 4. Render Helm      │              │
│        │                       │    templates         │              │
│        │                       │                      │              │
│        │                       ├─ 5. Apply manifests ─>              │
│        │                       │                      │              │
│        │                       │                      ├─ 6. Rolling  │
│        │                       │                      │    update    │
│        │                       │                      │              │
│        │                       │<─ 7. Health check ───┤              │
│        │                       │                      │              │
│        │<──────────────────────┤                      │              │
│           8. Slack notification                       │              │
│              "Deployment success"                     │              │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

**ArgoCD Application Manifest:**
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: llm-vault-prod
  namespace: argocd
  finalizers:
  - resources-finalizer.argocd.argoproj.io
spec:
  project: llm-platform

  source:
    repoURL: https://github.com/org/llm-vault-infra
    targetRevision: main
    path: helm/llm-vault
    helm:
      valueFiles:
      - values-production.yaml
      parameters:
      - name: api.image.tag
        value: v1.2.3
      - name: api.replicaCount
        value: "5"

  destination:
    server: https://kubernetes.default.svc
    namespace: llm-vault-prod

  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
    - CreateNamespace=true
    - PruneLast=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m

  ignoreDifferences:
  - group: apps
    kind: Deployment
    jsonPointers:
    - /spec/replicas  # Ignore HPA-managed replicas

  health:
    checks:
    - kind: Deployment
      wait: 300s
```

---

## 10. Cost Optimization

### 10.1 Right-Sizing Strategy

**Resource Optimization Process:**
```
┌──────────────────────────────────────────────────────────────────────┐
│                    Right-Sizing Methodology                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Step 1: Measure (7-day observation)                                 │
│  ├─ Prometheus metrics: CPU/memory P50, P95, P99                     │
│  ├─ Kubecost: Cost allocation by pod, namespace                      │
│  └─ VPA Recommender: Analyze resource usage patterns                 │
│                                                                       │
│  Step 2: Analyze                                                     │
│  ├─ Over-provisioned: P95 usage < 50% of request                     │
│  ├─ Under-provisioned: P95 usage > 90% of limit                      │
│  └─ Well-sized: P95 usage 60-80% of request                          │
│                                                                       │
│  Step 3: Adjust                                                      │
│  ├─ Decrease request: If P95 < 50% for 7 days                        │
│  ├─ Increase request: If P95 > 90% OR throttling events              │
│  └─ Adjust limits: Set to 1.5-2x request for burstable workloads     │
│                                                                       │
│  Step 4: Validate (24h canary)                                       │
│  ├─ Deploy changes to 10% of pods (canary)                           │
│  ├─ Monitor error rate, latency, OOM kills                           │
│  └─ Rollback if P99 latency increases >20% OR error rate >1%         │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

**Before/After Right-Sizing Example:**
| Component | Before (Request/Limit) | After (Request/Limit) | Savings/Month | Notes |
|-----------|------------------------|----------------------|---------------|-------|
| API Pod | 2 vCPU / 4 vCPU | 1 vCPU / 2 vCPU | $450 | P95 CPU: 0.7 vCPU |
| API Pod | 4 GB / 8 GB | 2 GB / 4 GB | $180 | P95 mem: 1.5 GB |
| Worker Pod | 4 vCPU / 8 vCPU | 3 vCPU / 6 vCPU | $600 | CPU-bound workload |
| Worker Pod | 8 GB / 16 GB | 6 GB / 12 GB | $320 | P95 mem: 4.5 GB |
| **Total** | - | - | **$1,550/mo** | **18% cost reduction** |

### 10.2 Spot Instance Strategy

**Spot vs On-Demand Mix:**
```
┌──────────────────────────────────────────────────────────────────────┐
│                  Spot Instance Configuration                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  API Tier (Stateless, Low-Latency):                                  │
│  ├─ On-Demand: 100% (no spot)                                        │
│  ├─ Reasoning: User-facing, cannot tolerate interruptions            │
│  └─ Monthly Cost: $2,400 (3x c6i.2xlarge * $800/mo)                  │
│                                                                       │
│  Worker Tier (Batch Jobs, Fault-Tolerant):                           │
│  ├─ On-Demand Base: 2 nodes (minimum capacity)                       │
│  ├─ Spot: 4-48 nodes (burst capacity)                                │
│  ├─ Spot Mix: c6i.4xlarge (60%), c6a.4xlarge (20%), c5.4xlarge (20%) │
│  ├─ Spot Savings: 70% ($1,600/mo → $480/mo per node)                 │
│  └─ Monthly Cost: $2,880 (base) + $1,920 (spot avg) = $4,800         │
│     vs On-Demand: $9,600 → 50% savings                               │
│                                                                       │
│  Data Tier (Stateful, Critical):                                     │
│  ├─ On-Demand: 100% (no spot)                                        │
│  ├─ Reasoning: StatefulSets require stable nodes                     │
│  └─ Monthly Cost: $3,600 (3x r6i.2xlarge * $1,200/mo)                │
│                                                                       │
│  Total Cluster Cost:                                                 │
│  ├─ With Spot: $10,800/mo                                            │
│  ├─ Without Spot: $15,600/mo                                         │
│  └─ Savings: $4,800/mo (31%)                                         │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

**Spot Interruption Handling:**
```yaml
# Worker deployment with spot-friendly configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-worker
spec:
  replicas: 10
  template:
    spec:
      # Tolerate spot instance taints
      tolerations:
      - key: "node.kubernetes.io/instance-type"
        operator: "Equal"
        value: "spot"
        effect: "NoSchedule"

      # Graceful shutdown on spot termination
      terminationGracePeriodSeconds: 120

      # Priority class (preemptible)
      priorityClassName: low-priority-preemptible

      containers:
      - name: worker
        lifecycle:
          preStop:
            exec:
              command:
              - /bin/bash
              - -c
              - |
                # Signal worker to stop accepting new jobs
                kill -TERM 1

                # Wait for current job to complete (max 2min)
                sleep 120

---
# Node termination handler (DaemonSet)
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spot-termination-handler
spec:
  selector:
    matchLabels:
      app: spot-termination-handler
  template:
    metadata:
      labels:
        app: spot-termination-handler
    spec:
      nodeSelector:
        node.kubernetes.io/instance-type: spot
      containers:
      - name: handler
        image: aws-spot-termination-handler:latest
        env:
        - name: DRAIN_TIMEOUT
          value: "120"
        # Monitors EC2 metadata for spot termination notice (2min warning)
        # Cordons node and drains pods gracefully
```

### 10.3 Storage Cost Optimization

**S3 Lifecycle Policies:**
```yaml
# Terraform resource for S3 lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "vault_data" {
  bucket = aws_s3_bucket.vault_data.id

  rule {
    id     = "transition-old-versions"
    status = "Enabled"

    # Current version transitions
    transition {
      days          = 90
      storage_class = "STANDARD_IA"  # $0.0125/GB vs $0.023/GB (46% savings)
    }

    transition {
      days          = 180
      storage_class = "GLACIER_IR"   # $0.004/GB (83% savings)
    }

    # Old versions
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 90
      storage_class   = "GLACIER_IR"
    }

    noncurrent_version_expiration {
      noncurrent_days = 180
    }

    # Delete incomplete multipart uploads
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-temporary-data"
    status = "Enabled"

    filter {
      prefix = "tmp/"
    }

    expiration {
      days = 7
    }
  }
}
```

**Storage Cost Breakdown (1 PB dataset):**
| Storage Type | Size | Monthly Cost | Lifecycle Policy | Savings |
|--------------|------|--------------|------------------|---------|
| S3 Standard | 400 TB | $9,200 | Current (0-90 days) | Baseline |
| S3 Standard-IA | 300 TB | $3,750 | Transition 90-180 days | $3,150 |
| S3 Glacier IR | 300 TB | $1,200 | Transition 180+ days | $5,700 |
| **Total** | **1 PB** | **$14,150** | vs Standard: $23,000 | **$8,850 (38%)** |

### 10.4 Cost Monitoring Dashboard

**Key Metrics to Track:**
```
┌──────────────────────────────────────────────────────────────────────┐
│                     Cost Monitoring Metrics                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Compute Costs:                                                      │
│  ├─ Cost per API request: $0.0002                                    │
│  ├─ Cost per PII scan job: $0.15                                     │
│  ├─ Cost per GB processed: $0.05                                     │
│  └─ Idle node cost: $450/mo (target: <5% of total)                   │
│                                                                       │
│  Storage Costs:                                                      │
│  ├─ S3 storage: $14,150/mo (1 PB)                                    │
│  ├─ S3 requests: $800/mo (50M GET, 5M PUT)                           │
│  ├─ EBS volumes: $2,500/mo (5 TB SSD)                                │
│  └─ Cross-region transfer: $1,200/mo (12 TB/mo)                      │
│                                                                       │
│  Data Stores:                                                        │
│  ├─ RDS PostgreSQL: $3,600/mo (3x r6i.2xlarge)                       │
│  ├─ ElastiCache Redis: $2,400/mo (6x r6g.xlarge)                     │
│  └─ Backups (S3): $600/mo (lifecycle optimized)                      │
│                                                                       │
│  Network:                                                            │
│  ├─ Load balancers: $240/mo (3x ALB)                                 │
│  ├─ NAT gateways: $360/mo (3x Multi-AZ)                              │
│  └─ Data transfer out: $2,000/mo (200 TB/mo @ $0.09/GB)              │
│                                                                       │
│  Total Monthly Cost: $28,300                                         │
│  Cost per 1M API requests: $85                                       │
│  Cost per TB stored: $14.15                                          │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

**Kubecost Integration:**
```yaml
# Kubecost Helm values for cost visibility
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubecost-config
  namespace: kubecost
data:
  config.yaml: |
    prometheus:
      serverAddress: http://prometheus.monitoring:9090

    # Cost allocation by namespace, label, pod
    allocation:
      defaultAggregation: namespace
      defaultIdle: true
      sharedNamespaces:
      - kube-system
      - istio-system

    # Cloud provider integration
    cloudProvider: aws
    awsSpotDataBucket: s3://vault-kubecost-spot-data

    # Alerts
    alerts:
    - name: HighNamespaceCost
      threshold: 5000  # Alert if namespace costs > $5k/mo
      window: 7d
    - name: UnusedResources
      threshold: 0.3  # Alert if resources <30% utilized
      window: 24h
```

---

## Summary

This infrastructure architecture provides:

1. **Cloud-Agnostic Design**: Kubernetes-native with pluggable cloud providers (AWS/Azure/GCP/on-prem)

2. **Production-Grade HA**: Multi-AZ deployment, 99.95% uptime SLA, <30s failover

3. **Elastic Scaling**: HPA for stateless tiers (3-20 API pods, 2-50 workers), vertical scaling for databases

4. **Comprehensive DR**: RPO 1min (PostgreSQL), 0s (S3), RTO 15min (database), 5min (object storage)

5. **Security in Depth**: Network policies, service mesh mTLS, pod security contexts, secrets management

6. **Cost Optimized**: 31% savings via spot instances, 38% storage savings via lifecycle policies, right-sizing tooling

7. **Full IaC**: Terraform modules for cloud resources, Helm charts for Kubernetes, GitOps via ArgoCD

**Next Steps**:
- Implement monitoring dashboards (Grafana + Prometheus)
- Set up disaster recovery runbooks
- Conduct quarterly DR drills
- Optimize based on production metrics (right-sizing iterations)
