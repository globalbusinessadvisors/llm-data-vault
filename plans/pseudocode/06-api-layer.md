# LLM-Data-Vault Pseudocode: API Layer

**Document:** 06-api-layer.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines the API layer and service interfaces:
- REST API (OpenAPI 3.0 compliant)
- gRPC for high-performance paths
- Middleware stack (auth, rate limiting, validation)
- Error handling and response formatting

---

## 1. REST API Routes and Handlers

```rust
// src/api/routes.rs

use axum::{Router, routing::{get, post, put, delete}, extract::*, response::*, Json};

pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Dataset endpoints
        .route("/api/v1/datasets", post(create_dataset))
        .route("/api/v1/datasets", get(list_datasets))
        .route("/api/v1/datasets/:id", get(get_dataset))
        .route("/api/v1/datasets/:id", put(update_dataset))
        .route("/api/v1/datasets/:id", delete(delete_dataset))

        // Version endpoints
        .route("/api/v1/datasets/:id/versions", get(list_versions))
        .route("/api/v1/datasets/:id/versions", post(create_version))
        .route("/api/v1/datasets/:id/versions/:version_id", get(get_version))

        // Record endpoints
        .route("/api/v1/datasets/:id/records", get(list_records))
        .route("/api/v1/datasets/:id/records", post(ingest_records))
        .route("/api/v1/datasets/:id/records/stream", get(stream_records))

        // Anonymization endpoints
        .route("/api/v1/anonymize", post(anonymize_text))
        .route("/api/v1/detect-pii", post(detect_pii))
        .route("/api/v1/anonymization-policies", get(list_anonymization_policies))
        .route("/api/v1/anonymization-policies/:id", get(get_anonymization_policy))

        // Corpus endpoints
        .route("/api/v1/corpora", post(create_corpus))
        .route("/api/v1/corpora", get(list_corpora))
        .route("/api/v1/corpora/:id", get(get_corpus))
        .route("/api/v1/corpora/:id/entries", post(add_corpus_entries))

        // Audit endpoints
        .route("/api/v1/audit/events", get(query_audit_events))
        .route("/api/v1/audit/reports/:report_type", get(generate_audit_report))

        // Health endpoints
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/metrics", get(metrics))

        // Apply middleware
        .layer(from_fn(request_id_middleware))
        .layer(from_fn(logging_middleware))
        .layer(from_fn(tracing_middleware))
        .layer(from_fn(rate_limit_middleware))
        .layer(from_fn(auth_middleware))
        .layer(from_fn(authz_middleware))

        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize, Validate)]
pub struct CreateDatasetRequest {
    #[validate(length(min = 1, max = 256))]
    pub name: String,
    #[validate(length(max = 4096))]
    pub description: Option<String>,
    pub schema: Option<DatasetSchemaDto>,
    pub tags: Option<Vec<String>>,
    pub retention_policy_id: Option<Uuid>,
    pub anonymization_policy_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct DatasetResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub schema: Option<DatasetSchemaDto>,
    pub current_version: VersionInfoDto,
    pub status: String,
    pub visibility: String,
    pub tags: Vec<String>,
    pub record_count: u64,
    pub total_size: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,
    #[serde(rename = "_links")]
    pub links: HATEOASLinks,
}

#[derive(Debug, Serialize)]
pub struct HATEOASLinks {
    #[serde(rename = "self")]
    pub self_link: Link,
    pub versions: Option<Link>,
    pub records: Option<Link>,
    pub schema: Option<Link>,
}

#[derive(Debug, Serialize)]
pub struct Link {
    pub href: String,
    pub method: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationInfo,
    #[serde(rename = "_links")]
    pub links: PaginationLinks,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub total_count: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct PaginationLinks {
    #[serde(rename = "self")]
    pub self_link: String,
    pub first: String,
    pub last: String,
    pub prev: Option<String>,
    pub next: Option<String>,
}

// ============================================================================
// Dataset Handlers
// ============================================================================

async fn create_dataset(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<CreateDatasetRequest>,
) -> Result<(StatusCode, Json<DatasetResponse>), ApiError> {
    // Validate request
    request.validate().map_err(|e| ApiError::validation(e))?;

    // Create dataset
    let dataset = state.dataset_service
        .create_dataset(CreateDatasetCommand {
            name: request.name,
            description: request.description,
            schema: request.schema.map(|s| s.into()),
            tags: request.tags.unwrap_or_default(),
            retention_policy_id: request.retention_policy_id.map(PolicyId),
            anonymization_policy_id: request.anonymization_policy_id.map(PolicyId),
            created_by: user.user_id,
            workspace_id: user.current_workspace,
        })
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    let response = DatasetResponse::from_domain(dataset, &state.config.base_url);

    Ok((StatusCode::CREATED, Json(response)))
}

async fn get_dataset(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<DatasetResponse>, ApiError> {
    let dataset = state.dataset_service
        .get_dataset(&DatasetId(id), &user.user_id)
        .await
        .map_err(|e| ApiError::from_service_error(e))?
        .ok_or(ApiError::not_found("Dataset", id))?;

    let response = DatasetResponse::from_domain(dataset, &state.config.base_url);
    Ok(Json(response))
}

async fn list_datasets(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(params): Query<ListDatasetsParams>,
) -> Result<Json<PaginatedResponse<DatasetResponse>>, ApiError> {
    let result = state.dataset_service
        .list_datasets(ListDatasetsQuery {
            workspace_id: user.current_workspace,
            page: params.page.unwrap_or(1),
            per_page: params.per_page.unwrap_or(20).min(100),
            sort_by: params.sort_by,
            sort_order: params.sort_order,
            filter: params.filter,
        })
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    let response = PaginatedResponse {
        data: result.items.into_iter()
            .map(|d| DatasetResponse::from_domain(d, &state.config.base_url))
            .collect(),
        pagination: PaginationInfo {
            total_count: result.total_count,
            page: result.page,
            per_page: result.per_page,
            total_pages: (result.total_count as f64 / result.per_page as f64).ceil() as u32,
        },
        links: build_pagination_links(&params, result.total_count, &state.config.base_url),
    };

    Ok(Json(response))
}

async fn update_dataset(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateDatasetRequest>,
) -> Result<Json<DatasetResponse>, ApiError> {
    let dataset = state.dataset_service
        .update_dataset(UpdateDatasetCommand {
            dataset_id: DatasetId(id),
            name: request.name,
            description: request.description,
            tags: request.tags,
            updated_by: user.user_id,
        })
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    let response = DatasetResponse::from_domain(dataset, &state.config.base_url);
    Ok(Json(response))
}

async fn delete_dataset(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.dataset_service
        .delete_dataset(&DatasetId(id), &user.user_id)
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Record Handlers
// ============================================================================

async fn ingest_records(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(dataset_id): Path<Uuid>,
    Json(request): Json<IngestRecordsRequest>,
) -> Result<(StatusCode, Json<IngestResponse>), ApiError> {
    let result = state.record_service
        .ingest_records(IngestRecordsCommand {
            dataset_id: DatasetId(dataset_id),
            records: request.records.into_iter().map(|r| r.into()).collect(),
            options: IngestOptions {
                validate_schema: request.validate_schema.unwrap_or(true),
                auto_anonymize: request.auto_anonymize.unwrap_or(false),
                dedup_strategy: request.dedup_strategy,
            },
            ingested_by: user.user_id,
        })
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    Ok((StatusCode::CREATED, Json(IngestResponse {
        ingested_count: result.ingested_count,
        skipped_count: result.skipped_count,
        errors: result.errors,
        version_id: result.version_id.0,
    })))
}

async fn stream_records(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(dataset_id): Path<Uuid>,
    Query(params): Query<StreamRecordsParams>,
) -> Result<impl IntoResponse, ApiError> {
    let stream = state.record_service
        .stream_records(StreamRecordsQuery {
            dataset_id: DatasetId(dataset_id),
            version_id: params.version_id.map(VersionId),
            filter: params.filter,
            batch_size: params.batch_size.unwrap_or(1000),
        }, &user.user_id)
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    // Return Server-Sent Events stream
    let sse_stream = stream.map(|result| {
        match result {
            Ok(batch) => {
                let json = serde_json::to_string(&batch).unwrap_or_default();
                Ok::<_, std::convert::Infallible>(Event::default().data(json))
            }
            Err(e) => {
                Ok(Event::default().event("error").data(e.to_string()))
            }
        }
    });

    Ok(Sse::new(sse_stream)
        .keep_alive(axum::response::sse::KeepAlive::default()))
}

// ============================================================================
// Anonymization Handlers
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AnonymizeRequest {
    pub text: String,
    pub policy_id: Option<Uuid>,
    pub pii_types: Option<Vec<String>>,
    pub strategy: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AnonymizeResponse {
    pub original_text: String,
    pub anonymized_text: String,
    pub detections: Vec<PIIDetectionDto>,
    pub replacements: Vec<ReplacementDto>,
    pub policy_applied: Option<Uuid>,
}

async fn anonymize_text(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<AnonymizeRequest>,
) -> Result<Json<AnonymizeResponse>, ApiError> {
    let result = state.anonymization_service
        .anonymize(AnonymizeCommand {
            text: request.text.clone(),
            policy_id: request.policy_id.map(PolicyId),
            pii_types: request.pii_types,
            strategy: request.strategy,
            requested_by: user.user_id,
        })
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    Ok(Json(AnonymizeResponse {
        original_text: request.text,
        anonymized_text: result.anonymized_text,
        detections: result.detections.into_iter().map(PIIDetectionDto::from).collect(),
        replacements: result.replacements.into_iter().map(ReplacementDto::from).collect(),
        policy_applied: result.policy_id.map(|p| p.0),
    }))
}

async fn detect_pii(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<DetectPIIRequest>,
) -> Result<Json<DetectPIIResponse>, ApiError> {
    let result = state.anonymization_service
        .detect_pii(DetectPIICommand {
            text: request.text,
            pii_types: request.pii_types,
            confidence_threshold: request.confidence_threshold,
        })
        .await
        .map_err(|e| ApiError::from_service_error(e))?;

    Ok(Json(DetectPIIResponse {
        detections: result.detections.into_iter().map(PIIDetectionDto::from).collect(),
        summary: PIISummaryDto {
            total_count: result.total_count,
            by_type: result.by_type,
            high_confidence_count: result.high_confidence_count,
        },
    }))
}
```

---

## 2. Middleware Stack

```rust
// src/api/middleware/mod.rs

// ============================================================================
// Request ID Middleware
// ============================================================================

pub async fn request_id_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .headers()
        .get("X-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    request.extensions_mut().insert(RequestId(request_id.clone()));

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-Request-ID",
        HeaderValue::from_str(&request_id).unwrap(),
    );

    response
}

// ============================================================================
// Logging Middleware
// ============================================================================

pub async fn logging_middleware(
    Extension(request_id): Extension<RequestId>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start = Instant::now();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        request_id = %request_id.0,
        method = %method,
        uri = %uri,
        status = %status.as_u16(),
        duration_ms = %duration.as_millis(),
        "Request completed"
    );

    response
}

// ============================================================================
// Tracing Middleware
// ============================================================================

pub async fn tracing_middleware(
    Extension(request_id): Extension<RequestId>,
    request: Request,
    next: Next,
) -> Response {
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id.0,
        method = %request.method(),
        uri = %request.uri(),
    );

    async move {
        next.run(request).await
    }
    .instrument(span)
    .await
}

// ============================================================================
// Rate Limiting Middleware
// ============================================================================

pub struct RateLimiter {
    store: Arc<RwLock<HashMap<String, TokenBucket>>>,
    config: RateLimitConfig,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub key_extractor: KeyExtractor,
}

#[derive(Debug, Clone)]
pub enum KeyExtractor {
    IpAddress,
    UserId,
    ApiKey,
    Custom(String),
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    capacity: f64,
    rate: f64,
}

impl TokenBucket {
    fn new(capacity: u32, rate: u32) -> Self {
        Self {
            tokens: capacity as f64,
            last_update: Instant::now(),
            capacity: capacity as f64,
            rate: rate as f64,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let key = limiter.extract_key(&request);

    let allowed = {
        let mut store = limiter.store.write().await;
        let bucket = store.entry(key.clone()).or_insert_with(|| {
            TokenBucket::new(limiter.config.burst_size, limiter.config.requests_per_second)
        });
        bucket.try_consume()
    };

    if !allowed {
        return Err(ApiError::rate_limited());
    }

    Ok(next.run(request).await)
}

impl RateLimiter {
    fn extract_key(&self, request: &Request) -> String {
        match &self.config.key_extractor {
            KeyExtractor::IpAddress => {
                request
                    .headers()
                    .get("X-Forwarded-For")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            }
            KeyExtractor::UserId => {
                request
                    .extensions()
                    .get::<AuthenticatedUser>()
                    .map(|u| u.user_id.0.to_string())
                    .unwrap_or_else(|| "anonymous".to_string())
            }
            KeyExtractor::ApiKey => {
                request
                    .headers()
                    .get("X-API-Key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            }
            KeyExtractor::Custom(header) => {
                request
                    .headers()
                    .get(header.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            }
        }
    }
}

// ============================================================================
// Authentication Middleware
// ============================================================================

pub async fn auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Skip auth for health endpoints
    if request.uri().path().starts_with("/health") || request.uri().path() == "/metrics" {
        return Ok(next.run(request).await);
    }

    // Extract token from header
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError::unauthorized("Missing authorization header"))?;

    // Validate token
    let user = auth_service
        .validate_token(token)
        .await
        .map_err(|e| ApiError::unauthorized(e.to_string()))?;

    // Add user to request extensions
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

// ============================================================================
// Authorization Middleware
// ============================================================================

pub async fn authz_middleware(
    State(authz_engine): State<Arc<dyn AuthorizationEngine>>,
    Extension(user): Extension<AuthenticatedUser>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let action = method_to_action(request.method());
    let resource = path_to_resource(request.uri().path());

    let authz_request = AuthzRequest {
        request_id: RequestId::new(),
        principal: Principal {
            id: PrincipalId(user.user_id.0),
            principal_type: PrincipalType::User(user.user_id),
            attributes: user.attributes.clone(),
        },
        action,
        resource,
        context: AuthzContext {
            timestamp: Utc::now(),
            ip_address: None,
            user_agent: None,
            request_path: Some(request.uri().path().to_string()),
            mfa_verified: user.mfa_verified,
            session_age: None,
            custom: HashMap::new(),
        },
    };

    let decision = authz_engine
        .authorize(&authz_request)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    match decision {
        AuthzDecision::Allow { .. } => Ok(next.run(request).await),
        AuthzDecision::Deny { reason, .. } => Err(ApiError::forbidden(reason)),
        AuthzDecision::NotApplicable { reason } => Err(ApiError::forbidden(reason)),
    }
}

fn method_to_action(method: &Method) -> Action {
    match *method {
        Method::GET | Method::HEAD => Action::read(),
        Method::POST => Action::write(),
        Method::PUT | Method::PATCH => Action::write(),
        Method::DELETE => Action::delete(),
        _ => Action::read(),
    }
}

fn path_to_resource(path: &str) -> Resource {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let (resource_type, resource_id) = match segments.as_slice() {
        ["api", "v1", "datasets", id, ..] => {
            (ResourceType::Dataset, Some(id.to_string()))
        }
        ["api", "v1", "datasets", ..] => {
            (ResourceType::Dataset, None)
        }
        ["api", "v1", "corpora", id, ..] => {
            (ResourceType::Corpus, Some(id.to_string()))
        }
        ["api", "v1", "corpora", ..] => {
            (ResourceType::Corpus, None)
        }
        ["api", "v1", "audit", ..] => {
            (ResourceType::AuditLog, None)
        }
        _ => (ResourceType::Dataset, None),
    };

    Resource {
        id: ResourceId(resource_id.unwrap_or_default()),
        resource_type,
        attributes: HashMap::new(),
        owner: None,
        workspace: None,
    }
}

// ============================================================================
// Validation Middleware
// ============================================================================

pub async fn validation_middleware<T: DeserializeOwned + Validate>(
    Json(payload): Json<T>,
) -> Result<Json<T>, ApiError> {
    payload.validate().map_err(|e| ApiError::validation(e))?;
    Ok(Json(payload))
}
```

---

## 3. Error Handling

```rust
// src/api/error.rs

#[derive(Debug)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub status: StatusCode,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // 4xx Client Errors
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    PayloadTooLarge,
    UnprocessableEntity,
    RateLimitExceeded,
    ValidationError,

    // 5xx Server Errors
    InternalServerError,
    ServiceUnavailable,
    GatewayTimeout,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetails,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetails {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::BadRequest,
            message: message.into(),
            details: None,
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::Unauthorized,
            message: message.into(),
            details: None,
            status: StatusCode::UNAUTHORIZED,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::Forbidden,
            message: message.into(),
            details: None,
            status: StatusCode::FORBIDDEN,
        }
    }

    pub fn not_found(resource_type: &str, id: impl std::fmt::Display) -> Self {
        Self {
            code: ErrorCode::NotFound,
            message: format!("{} with id '{}' not found", resource_type, id),
            details: None,
            status: StatusCode::NOT_FOUND,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::Conflict,
            message: message.into(),
            details: None,
            status: StatusCode::CONFLICT,
        }
    }

    pub fn rate_limited() -> Self {
        Self {
            code: ErrorCode::RateLimitExceeded,
            message: "Rate limit exceeded. Please retry later.".into(),
            details: None,
            status: StatusCode::TOO_MANY_REQUESTS,
        }
    }

    pub fn validation(errors: validator::ValidationErrors) -> Self {
        let details = serde_json::to_value(&errors).ok();
        Self {
            code: ErrorCode::ValidationError,
            message: "Validation failed".into(),
            details,
            status: StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InternalServerError,
            message: message.into(),
            details: None,
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn from_service_error(error: ServiceError) -> Self {
        match error {
            ServiceError::NotFound { resource_type, id } => {
                Self::not_found(&resource_type, id)
            }
            ServiceError::Unauthorized { message } => {
                Self::unauthorized(message)
            }
            ServiceError::Forbidden { message } => {
                Self::forbidden(message)
            }
            ServiceError::Validation { message, details } => {
                Self {
                    code: ErrorCode::ValidationError,
                    message,
                    details,
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                }
            }
            ServiceError::Conflict { message } => {
                Self::conflict(message)
            }
            ServiceError::Internal { message } => {
                Self::internal(message)
            }
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = "unknown".to_string(); // Would be extracted from request context

        let error_response = ErrorResponse {
            error: ErrorDetails {
                code: self.code,
                message: self.message,
                details: self.details,
                request_id,
                documentation_url: Some("https://docs.llm-data-vault.io/errors".into()),
            },
        };

        (self.status, Json(error_response)).into_response()
    }
}
```

---

## 4. gRPC Service Definitions

```rust
// src/api/grpc/mod.rs

// Proto definitions (would be in .proto files)
/*
syntax = "proto3";
package llm_data_vault.v1;

service DataVaultService {
    // Streaming operations
    rpc StreamRecords(StreamRecordsRequest) returns (stream DataRecord);
    rpc BatchIngest(stream IngestRequest) returns (IngestResponse);
    rpc BulkAnonymize(stream AnonymizeRequest) returns (stream AnonymizeResponse);

    // Unary operations
    rpc GetDataset(GetDatasetRequest) returns (Dataset);
    rpc CreateDataset(CreateDatasetRequest) returns (Dataset);
}
*/

use tonic::{Request, Response, Status, Streaming};

pub struct DataVaultGrpcService {
    dataset_service: Arc<DatasetService>,
    record_service: Arc<RecordService>,
    anonymization_service: Arc<AnonymizationService>,
}

#[tonic::async_trait]
impl DataVaultService for DataVaultGrpcService {
    type StreamRecordsStream = ReceiverStream<Result<DataRecord, Status>>;

    async fn stream_records(
        &self,
        request: Request<StreamRecordsRequest>,
    ) -> Result<Response<Self::StreamRecordsStream>, Status> {
        let req = request.into_inner();
        let dataset_id = DatasetId(Uuid::parse_str(&req.dataset_id)
            .map_err(|_| Status::invalid_argument("Invalid dataset ID"))?);

        let (tx, rx) = mpsc::channel(100);

        let record_service = self.record_service.clone();

        tokio::spawn(async move {
            let stream = record_service
                .stream_records_internal(&dataset_id)
                .await;

            match stream {
                Ok(mut stream) => {
                    while let Some(result) = stream.next().await {
                        match result {
                            Ok(record) => {
                                let proto_record = DataRecord::from(record);
                                if tx.send(Ok(proto_record)).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn batch_ingest(
        &self,
        request: Request<Streaming<IngestRequest>>,
    ) -> Result<Response<IngestResponse>, Status> {
        let mut stream = request.into_inner();
        let mut total_ingested = 0u64;
        let mut errors = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(req) => {
                    match self.process_ingest_request(req).await {
                        Ok(count) => total_ingested += count,
                        Err(e) => errors.push(e.to_string()),
                    }
                }
                Err(e) => {
                    errors.push(e.to_string());
                }
            }
        }

        Ok(Response::new(IngestResponse {
            ingested_count: total_ingested,
            error_count: errors.len() as u64,
            errors,
        }))
    }

    type BulkAnonymizeStream = ReceiverStream<Result<AnonymizeResponse, Status>>;

    async fn bulk_anonymize(
        &self,
        request: Request<Streaming<AnonymizeRequest>>,
    ) -> Result<Response<Self::BulkAnonymizeStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(100);

        let anonymization_service = self.anonymization_service.clone();

        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                match result {
                    Ok(req) => {
                        let response = anonymization_service
                            .anonymize_text(&req.text, req.policy_id.as_deref())
                            .await;

                        let proto_response = match response {
                            Ok(result) => AnonymizeResponse {
                                original_text: req.text,
                                anonymized_text: result.anonymized_text,
                                success: true,
                                error: None,
                            },
                            Err(e) => AnonymizeResponse {
                                original_text: req.text,
                                anonymized_text: String::new(),
                                success: false,
                                error: Some(e.to_string()),
                            },
                        };

                        if tx.send(Ok(proto_response)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_dataset(
        &self,
        request: Request<GetDatasetRequest>,
    ) -> Result<Response<Dataset>, Status> {
        let req = request.into_inner();
        let dataset_id = DatasetId(Uuid::parse_str(&req.id)
            .map_err(|_| Status::invalid_argument("Invalid dataset ID"))?);

        let dataset = self.dataset_service
            .get_dataset_internal(&dataset_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("Dataset not found"))?;

        Ok(Response::new(Dataset::from(dataset)))
    }

    async fn create_dataset(
        &self,
        request: Request<CreateDatasetRequest>,
    ) -> Result<Response<Dataset>, Status> {
        let req = request.into_inner();

        let dataset = self.dataset_service
            .create_dataset_internal(req.into())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Dataset::from(dataset)))
    }
}
```

---

## 5. Health and Metrics

```rust
// src/api/health.rs

async fn liveness(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, StatusCode> {
    Ok(Json(HealthResponse {
        status: "ok".into(),
        timestamp: Utc::now(),
    }))
}

async fn readiness(
    State(state): State<AppState>,
) -> Result<Json<ReadinessResponse>, StatusCode> {
    let checks = vec![
        check_database(&state.db_pool).await,
        check_storage(&state.storage).await,
        check_kms(&state.kms).await,
    ];

    let all_healthy = checks.iter().all(|c| c.status == "ok");

    let response = ReadinessResponse {
        status: if all_healthy { "ok" } else { "degraded" }.into(),
        checks,
        timestamp: Utc::now(),
    };

    if all_healthy {
        Ok(Json(response))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

async fn check_database(pool: &PgPool) -> HealthCheck {
    let start = Instant::now();
    let result = sqlx::query("SELECT 1").execute(pool).await;

    HealthCheck {
        name: "database".into(),
        status: if result.is_ok() { "ok" } else { "error" }.into(),
        latency_ms: start.elapsed().as_millis() as u64,
        message: result.err().map(|e| e.to_string()),
    }
}

async fn check_storage(storage: &Arc<dyn StorageBackend>) -> HealthCheck {
    let start = Instant::now();
    let result = storage.health_check().await;

    HealthCheck {
        name: "storage".into(),
        status: if result.is_ok() { "ok" } else { "error" }.into(),
        latency_ms: start.elapsed().as_millis() as u64,
        message: result.err().map(|e| e.to_string()),
    }
}

async fn check_kms(kms: &Arc<dyn KmsProvider>) -> HealthCheck {
    let start = Instant::now();
    let result = kms.health_check().await;

    HealthCheck {
        name: "kms".into(),
        status: if result.is_ok() { "ok" } else { "error" }.into(),
        latency_ms: start.elapsed().as_millis() as u64,
        message: result.err().map(|e| e.to_string()),
    }
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub checks: Vec<HealthCheck>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: String,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ============================================================================
// Metrics Endpoint
// ============================================================================

async fn metrics(
    State(state): State<AppState>,
) -> Result<String, StatusCode> {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = state.metrics_registry.gather();

    encoder
        .encode_to_string(&metric_families)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
```

---

## Summary

This document defines the API layer for LLM-Data-Vault:

| Component | Purpose |
|-----------|---------|
| **REST Routes** | OpenAPI 3.0 compliant HTTP endpoints |
| **Middleware** | Request ID, logging, auth, rate limiting |
| **Error Handling** | Structured error responses with codes |
| **gRPC Services** | High-performance streaming operations |
| **Health Endpoints** | Liveness, readiness, and metrics |

**Key Features:**
- HATEOAS links for discoverability
- Pagination with cursor support
- Rate limiting with token bucket
- Request validation
- Structured error responses
- Streaming for large datasets
- Prometheus metrics export

---

*Next Document: [07-versioning-lineage.md](./07-versioning-lineage.md)*
