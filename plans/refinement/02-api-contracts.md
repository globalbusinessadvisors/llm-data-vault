# API Contracts

Complete API specifications for LLM-Data-Vault implementation.

## 1. OpenAPI Specification

```yaml
openapi: 3.1.0
info:
  title: LLM-Data-Vault API
  version: 1.0.0
  description: Secure data vault for LLM training datasets with versioning and anonymization
  contact:
    name: API Support
    email: support@llm-data-vault.io

servers:
  - url: https://api.llm-data-vault.io/api/v1
    description: Production
  - url: http://localhost:8080/api/v1
    description: Local development

security:
  - BearerAuth: []
  - ApiKeyAuth: []

paths:
  /datasets:
    post:
      summary: Create dataset
      tags: [Datasets]
      operationId: createDataset
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DatasetCreateRequest'
      responses:
        '201':
          description: Dataset created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DatasetResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '409':
          $ref: '#/components/responses/Conflict'

    get:
      summary: List datasets
      tags: [Datasets]
      operationId: listDatasets
      parameters:
        - $ref: '#/components/parameters/Limit'
        - $ref: '#/components/parameters/Cursor'
        - $ref: '#/components/parameters/Sort'
        - name: name
          in: query
          schema:
            type: string
        - name: task_type
          in: query
          schema:
            type: string
            enum: [conversation, instruction, classification, completion]
        - name: created_after
          in: query
          schema:
            type: string
            format: date-time
      responses:
        '200':
          description: Datasets list
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DatasetListResponse'

  /datasets/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
          format: uuid

    get:
      summary: Get dataset
      tags: [Datasets]
      operationId: getDataset
      responses:
        '200':
          description: Dataset details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DatasetResponse'
        '404':
          $ref: '#/components/responses/NotFound'

    put:
      summary: Update dataset
      tags: [Datasets]
      operationId: updateDataset
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DatasetUpdateRequest'
      responses:
        '200':
          description: Dataset updated
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DatasetResponse'
        '404':
          $ref: '#/components/responses/NotFound'

    delete:
      summary: Delete dataset
      tags: [Datasets]
      operationId: deleteDataset
      responses:
        '204':
          description: Dataset deleted
        '404':
          $ref: '#/components/responses/NotFound'
        '409':
          description: Cannot delete dataset with published versions

  /datasets/{id}/versions:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
          format: uuid

    post:
      summary: Create version
      tags: [Versions]
      operationId: createVersion
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/VersionCreateRequest'
      responses:
        '201':
          description: Version created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VersionResponse'

    get:
      summary: List versions
      tags: [Versions]
      operationId: listVersions
      parameters:
        - $ref: '#/components/parameters/Limit'
        - $ref: '#/components/parameters/Cursor'
        - name: status
          in: query
          schema:
            type: string
            enum: [draft, published, archived]
      responses:
        '200':
          description: Versions list
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VersionListResponse'

  /datasets/{id}/versions/{version}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
          format: uuid
      - name: version
        in: path
        required: true
        schema:
          type: string
          pattern: '^v\d+\.\d+\.\d+$'

    get:
      summary: Get version
      tags: [Versions]
      operationId: getVersion
      responses:
        '200':
          description: Version details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VersionResponse'

  /datasets/{id}/versions/{version}/publish:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
          format: uuid
      - name: version
        in: path
        required: true
        schema:
          type: string

    post:
      summary: Publish version
      tags: [Versions]
      operationId: publishVersion
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                changelog:
                  type: string
      responses:
        '200':
          description: Version published
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/VersionResponse'

  /datasets/{id}/versions/{version}/records:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
          format: uuid
      - name: version
        in: path
        required: true
        schema:
          type: string

    post:
      summary: Create records (batch)
      tags: [Records]
      operationId: createRecords
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RecordBatchRequest'
      responses:
        '201':
          description: Records created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RecordBatchResponse'

    get:
      summary: Query records
      tags: [Records]
      operationId: queryRecords
      parameters:
        - $ref: '#/components/parameters/Limit'
        - $ref: '#/components/parameters/Cursor'
        - name: filter
          in: query
          description: JSON filter expression
          schema:
            type: string
        - name: fields
          in: query
          description: Comma-separated fields to return
          schema:
            type: string
      responses:
        '200':
          description: Records list
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RecordListResponse'

  /datasets/{id}/versions/{version}/records/{record_id}:
    parameters:
      - name: id
        in: path
        required: true
        schema:
          type: string
          format: uuid
      - name: version
        in: path
        required: true
        schema:
          type: string
      - name: record_id
        in: path
        required: true
        schema:
          type: string

    get:
      summary: Get record
      tags: [Records]
      operationId: getRecord
      responses:
        '200':
          description: Record details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RecordResponse'

  /anonymize:
    post:
      summary: Anonymize data
      tags: [Anonymization]
      operationId: anonymize
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AnonymizeRequest'
      responses:
        '200':
          description: Anonymized data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AnonymizeResponse'

  /detect-pii:
    post:
      summary: Detect PII
      tags: [Anonymization]
      operationId: detectPII
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DetectPIIRequest'
      responses:
        '200':
          description: PII detection results
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DetectPIIResponse'

  /tokenize:
    post:
      summary: Tokenize values
      tags: [Anonymization]
      operationId: tokenize
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TokenizeRequest'
      responses:
        '200':
          description: Tokenized values
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TokenizeResponse'

  /detokenize:
    post:
      summary: Detokenize values
      tags: [Anonymization]
      operationId: detokenize
      security:
        - BearerAuth: [admin]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DetokenizeRequest'
      responses:
        '200':
          description: Original values
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DetokenizeResponse'

  /health:
    get:
      summary: Health check
      tags: [Admin]
      operationId: healthCheck
      security: []
      responses:
        '200':
          description: Service healthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'

  /health/ready:
    get:
      summary: Readiness check
      tags: [Admin]
      operationId: readinessCheck
      security: []
      responses:
        '200':
          description: Service ready
        '503':
          description: Service not ready

  /health/live:
    get:
      summary: Liveness check
      tags: [Admin]
      operationId: livenessCheck
      security: []
      responses:
        '200':
          description: Service alive

  /metrics:
    get:
      summary: Prometheus metrics
      tags: [Admin]
      operationId: getMetrics
      security: []
      responses:
        '200':
          description: Metrics in Prometheus format
          content:
            text/plain:
              schema:
                type: string

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

  parameters:
    Limit:
      name: limit
      in: query
      description: Maximum number of items to return
      schema:
        type: integer
        minimum: 1
        maximum: 1000
        default: 100

    Cursor:
      name: cursor
      in: query
      description: Pagination cursor
      schema:
        type: string

    Sort:
      name: sort
      in: query
      description: Sort field and order (e.g., created_at:desc)
      schema:
        type: string

  schemas:
    DatasetCreateRequest:
      type: object
      required:
        - name
        - task_type
        - schema
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 255
        description:
          type: string
          maxLength: 2000
        task_type:
          type: string
          enum: [conversation, instruction, classification, completion]
        schema:
          $ref: '#/components/schemas/DatasetSchema'
        tags:
          type: array
          items:
            type: string
          maxItems: 50

    DatasetUpdateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 255
        description:
          type: string
        tags:
          type: array
          items:
            type: string

    DatasetResponse:
      type: object
      required:
        - id
        - name
        - task_type
        - schema
        - created_at
        - updated_at
      properties:
        id:
          type: string
          format: uuid
        name:
          type: string
        description:
          type: string
        task_type:
          type: string
        schema:
          $ref: '#/components/schemas/DatasetSchema'
        tags:
          type: array
          items:
            type: string
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time
        statistics:
          $ref: '#/components/schemas/DatasetStatistics'

    DatasetListResponse:
      type: object
      required:
        - data
        - pagination
      properties:
        data:
          type: array
          items:
            $ref: '#/components/schemas/DatasetResponse'
        pagination:
          $ref: '#/components/schemas/PaginationInfo'

    DatasetSchema:
      type: object
      required:
        - fields
      properties:
        fields:
          type: array
          items:
            $ref: '#/components/schemas/FieldDefinition'
        validation_rules:
          type: object
          additionalProperties: true

    FieldDefinition:
      type: object
      required:
        - name
        - type
      properties:
        name:
          type: string
        type:
          type: string
          enum: [string, number, boolean, object, array]
        required:
          type: boolean
          default: false
        pii_type:
          type: string
          enum: [email, phone, ssn, name, address, credit_card, none]
        anonymization_strategy:
          type: string
          enum: [mask, hash, tokenize, redact, preserve]

    DatasetStatistics:
      type: object
      properties:
        total_versions:
          type: integer
        total_records:
          type: integer
        latest_version:
          type: string
        storage_size_bytes:
          type: integer

    VersionCreateRequest:
      type: object
      required:
        - version
      properties:
        version:
          type: string
          pattern: '^v\d+\.\d+\.\d+$'
        description:
          type: string
        parent_version:
          type: string

    VersionResponse:
      type: object
      required:
        - id
        - version
        - dataset_id
        - status
        - created_at
      properties:
        id:
          type: string
          format: uuid
        version:
          type: string
        dataset_id:
          type: string
          format: uuid
        description:
          type: string
        status:
          type: string
          enum: [draft, published, archived]
        parent_version:
          type: string
        record_count:
          type: integer
        checksum:
          type: string
        created_at:
          type: string
          format: date-time
        published_at:
          type: string
          format: date-time

    VersionListResponse:
      type: object
      required:
        - data
        - pagination
      properties:
        data:
          type: array
          items:
            $ref: '#/components/schemas/VersionResponse'
        pagination:
          $ref: '#/components/schemas/PaginationInfo'

    RecordBatchRequest:
      type: object
      required:
        - records
      properties:
        records:
          type: array
          items:
            $ref: '#/components/schemas/RecordInput'
          minItems: 1
          maxItems: 10000
        anonymize:
          type: boolean
          default: false

    RecordInput:
      type: object
      required:
        - data
      properties:
        id:
          type: string
        data:
          type: object
          additionalProperties: true
        metadata:
          type: object
          additionalProperties: true

    RecordBatchResponse:
      type: object
      required:
        - created
        - failed
      properties:
        created:
          type: array
          items:
            $ref: '#/components/schemas/RecordResponse'
        failed:
          type: array
          items:
            $ref: '#/components/schemas/RecordError'

    RecordResponse:
      type: object
      required:
        - id
        - dataset_id
        - version
        - data
        - created_at
      properties:
        id:
          type: string
        dataset_id:
          type: string
          format: uuid
        version:
          type: string
        data:
          type: object
          additionalProperties: true
        metadata:
          type: object
          additionalProperties: true
        anonymized:
          type: boolean
        created_at:
          type: string
          format: date-time

    RecordListResponse:
      type: object
      required:
        - data
        - pagination
      properties:
        data:
          type: array
          items:
            $ref: '#/components/schemas/RecordResponse'
        pagination:
          $ref: '#/components/schemas/PaginationInfo'

    RecordError:
      type: object
      properties:
        index:
          type: integer
        id:
          type: string
        error:
          type: string

    AnonymizeRequest:
      type: object
      required:
        - data
      properties:
        data:
          type: object
          additionalProperties: true
        schema:
          $ref: '#/components/schemas/DatasetSchema'
        preserve_format:
          type: boolean
          default: true

    AnonymizeResponse:
      type: object
      required:
        - anonymized_data
      properties:
        anonymized_data:
          type: object
          additionalProperties: true
        pii_detected:
          type: array
          items:
            $ref: '#/components/schemas/PIIDetection'

    DetectPIIRequest:
      type: object
      required:
        - text
      properties:
        text:
          type: string
        entity_types:
          type: array
          items:
            type: string

    DetectPIIResponse:
      type: object
      required:
        - detections
      properties:
        detections:
          type: array
          items:
            $ref: '#/components/schemas/PIIDetection'

    PIIDetection:
      type: object
      properties:
        entity_type:
          type: string
        text:
          type: string
        start:
          type: integer
        end:
          type: integer
        confidence:
          type: number
          format: float

    TokenizeRequest:
      type: object
      required:
        - values
      properties:
        values:
          type: array
          items:
            type: string
        entity_type:
          type: string

    TokenizeResponse:
      type: object
      required:
        - tokens
      properties:
        tokens:
          type: array
          items:
            type: object
            properties:
              original:
                type: string
              token:
                type: string

    DetokenizeRequest:
      type: object
      required:
        - tokens
      properties:
        tokens:
          type: array
          items:
            type: string

    DetokenizeResponse:
      type: object
      required:
        - values
      properties:
        values:
          type: array
          items:
            type: object
            properties:
              token:
                type: string
              original:
                type: string

    PaginationInfo:
      type: object
      required:
        - has_next
      properties:
        next_cursor:
          type: string
        has_next:
          type: boolean
        total:
          type: integer

    HealthResponse:
      type: object
      required:
        - status
      properties:
        status:
          type: string
          enum: [healthy, degraded, unhealthy]
        version:
          type: string
        uptime_seconds:
          type: integer
        checks:
          type: object
          additionalProperties:
            type: object
            properties:
              status:
                type: string
              message:
                type: string

    ErrorResponse:
      type: object
      required:
        - type
        - title
        - status
      properties:
        type:
          type: string
          format: uri
          description: Error type URI (RFC 7807)
        title:
          type: string
          description: Human-readable error summary
        status:
          type: integer
          description: HTTP status code
        detail:
          type: string
          description: Human-readable error details
        instance:
          type: string
          format: uri
          description: Request identifier
        errors:
          type: array
          description: Validation errors
          items:
            type: object
            properties:
              field:
                type: string
              message:
                type: string
              code:
                type: string

  responses:
    BadRequest:
      description: Bad request
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
      headers:
        X-Request-ID:
          schema:
            type: string

    Unauthorized:
      description: Unauthorized
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
      headers:
        WWW-Authenticate:
          schema:
            type: string

    NotFound:
      description: Resource not found
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'

    Conflict:
      description: Resource conflict
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'

    TooManyRequests:
      description: Rate limit exceeded
      headers:
        X-RateLimit-Limit:
          schema:
            type: integer
          description: Request limit per window
        X-RateLimit-Remaining:
          schema:
            type: integer
          description: Requests remaining
        X-RateLimit-Reset:
          schema:
            type: integer
          description: Unix timestamp when limit resets
        Retry-After:
          schema:
            type: integer
          description: Seconds until retry
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/ErrorResponse'
```

## 2. Authentication

### JWT Bearer Token
```json
{
  "sub": "user-id",
  "iss": "llm-data-vault",
  "aud": "api",
  "exp": 1700000000,
  "iat": 1699999000,
  "scope": ["read:datasets", "write:datasets", "admin"]
}
```

Header: `Authorization: Bearer <token>`

### API Key
Header: `X-API-Key: <api-key>`

### mTLS
Service-to-service authentication via mutual TLS. Client certificate CN must match registered service identifier.

## 3. Pagination

### Request
```
GET /api/v1/datasets?limit=100&cursor=eyJpZCI6IjEyMyJ9&sort=created_at:desc
```

### Response
```json
{
  "data": [...],
  "pagination": {
    "next_cursor": "eyJpZCI6IjIyMyJ9",
    "has_next": true,
    "total": 1543
  }
}
```

Cursor is base64-encoded JSON containing position information.

## 4. Error Responses

### Standard Format (RFC 7807)

```json
{
  "type": "https://api.llm-data-vault.io/errors/validation-error",
  "title": "Validation Failed",
  "status": 400,
  "detail": "Request body contains invalid fields",
  "instance": "/api/v1/datasets/550e8400-e29b-41d4-a716-446655440000",
  "errors": [
    {
      "field": "schema.fields[0].name",
      "message": "Field name cannot be empty",
      "code": "FIELD_REQUIRED"
    }
  ]
}
```

### Error Code Catalog

| Code | HTTP | Description |
|------|------|-------------|
| VALIDATION_ERROR | 400 | Request validation failed |
| INVALID_SCHEMA | 400 | Dataset schema is invalid |
| UNAUTHORIZED | 401 | Authentication required |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Resource conflict (duplicate, state) |
| VERSION_CONFLICT | 409 | Version already exists |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Internal server error |
| SERVICE_UNAVAILABLE | 503 | Service temporarily unavailable |

## 5. Rate Limiting

### Headers
All responses include rate limit information:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1699999600
```

### Rate Limit Exceeded Response
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1699999600
Retry-After: 120

{
  "type": "https://api.llm-data-vault.io/errors/rate-limit",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "Request limit of 1000 per hour exceeded",
  "instance": "/api/v1/datasets"
}
```

### Rate Limit Tiers

| Tier | Requests/Hour | Burst |
|------|---------------|-------|
| Free | 1,000 | 100 |
| Pro | 10,000 | 500 |
| Enterprise | 100,000 | 2,000 |

## 6. gRPC Service Definitions

### DataVaultService

```protobuf
syntax = "proto3";

package datavault.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/struct.proto";

service DataVaultService {
  // Datasets
  rpc CreateDataset(CreateDatasetRequest) returns (DatasetResponse);
  rpc GetDataset(GetDatasetRequest) returns (DatasetResponse);
  rpc ListDatasets(ListDatasetsRequest) returns (ListDatasetsResponse);
  rpc UpdateDataset(UpdateDatasetRequest) returns (DatasetResponse);
  rpc DeleteDataset(DeleteDatasetRequest) returns (DeleteDatasetResponse);

  // Versions
  rpc CreateVersion(CreateVersionRequest) returns (VersionResponse);
  rpc GetVersion(GetVersionRequest) returns (VersionResponse);
  rpc ListVersions(ListVersionsRequest) returns (ListVersionsResponse);
  rpc PublishVersion(PublishVersionRequest) returns (VersionResponse);

  // Records
  rpc CreateRecords(CreateRecordsRequest) returns (CreateRecordsResponse);
  rpc GetRecord(GetRecordRequest) returns (RecordResponse);
  rpc QueryRecords(QueryRecordsRequest) returns (stream RecordResponse);
}

// Dataset Messages
message CreateDatasetRequest {
  string name = 1;
  string description = 2;
  TaskType task_type = 3;
  DatasetSchema schema = 4;
  repeated string tags = 5;
}

message GetDatasetRequest {
  string id = 1;
}

message ListDatasetsRequest {
  int32 page_size = 1;
  string page_token = 2;
  string filter = 3;
  string order_by = 4;
}

message UpdateDatasetRequest {
  string id = 1;
  optional string name = 2;
  optional string description = 3;
  repeated string tags = 4;
}

message DeleteDatasetRequest {
  string id = 1;
}

message DeleteDatasetResponse {
  bool success = 1;
}

message DatasetResponse {
  string id = 1;
  string name = 2;
  string description = 3;
  TaskType task_type = 4;
  DatasetSchema schema = 5;
  repeated string tags = 6;
  google.protobuf.Timestamp created_at = 7;
  google.protobuf.Timestamp updated_at = 8;
  DatasetStatistics statistics = 9;
}

message ListDatasetsResponse {
  repeated DatasetResponse datasets = 1;
  string next_page_token = 2;
  int32 total_count = 3;
}

message DatasetSchema {
  repeated FieldDefinition fields = 1;
  google.protobuf.Struct validation_rules = 2;
}

message FieldDefinition {
  string name = 1;
  FieldType type = 2;
  bool required = 3;
  PIIType pii_type = 4;
  AnonymizationStrategy anonymization_strategy = 5;
}

message DatasetStatistics {
  int32 total_versions = 1;
  int64 total_records = 2;
  string latest_version = 3;
  int64 storage_size_bytes = 4;
}

// Version Messages
message CreateVersionRequest {
  string dataset_id = 1;
  string version = 2;
  string description = 3;
  optional string parent_version = 4;
}

message GetVersionRequest {
  string dataset_id = 1;
  string version = 2;
}

message ListVersionsRequest {
  string dataset_id = 1;
  int32 page_size = 2;
  string page_token = 3;
  optional VersionStatus status = 4;
}

message PublishVersionRequest {
  string dataset_id = 1;
  string version = 2;
  string changelog = 3;
}

message VersionResponse {
  string id = 1;
  string version = 2;
  string dataset_id = 3;
  string description = 4;
  VersionStatus status = 5;
  optional string parent_version = 6;
  int64 record_count = 7;
  string checksum = 8;
  google.protobuf.Timestamp created_at = 9;
  optional google.protobuf.Timestamp published_at = 10;
}

message ListVersionsResponse {
  repeated VersionResponse versions = 1;
  string next_page_token = 2;
}

// Record Messages
message CreateRecordsRequest {
  string dataset_id = 1;
  string version = 2;
  repeated RecordInput records = 3;
  bool anonymize = 4;
}

message RecordInput {
  optional string id = 1;
  google.protobuf.Struct data = 2;
  google.protobuf.Struct metadata = 3;
}

message CreateRecordsResponse {
  repeated RecordResponse created = 1;
  repeated RecordError failed = 2;
}

message RecordError {
  int32 index = 1;
  string id = 2;
  string error = 3;
}

message GetRecordRequest {
  string dataset_id = 1;
  string version = 2;
  string record_id = 3;
}

message QueryRecordsRequest {
  string dataset_id = 1;
  string version = 2;
  string filter = 3;
  repeated string fields = 4;
  int32 page_size = 5;
  string page_token = 6;
}

message RecordResponse {
  string id = 1;
  string dataset_id = 2;
  string version = 3;
  google.protobuf.Struct data = 4;
  google.protobuf.Struct metadata = 5;
  bool anonymized = 6;
  google.protobuf.Timestamp created_at = 7;
}

// Enums
enum TaskType {
  TASK_TYPE_UNSPECIFIED = 0;
  TASK_TYPE_CONVERSATION = 1;
  TASK_TYPE_INSTRUCTION = 2;
  TASK_TYPE_CLASSIFICATION = 3;
  TASK_TYPE_COMPLETION = 4;
}

enum FieldType {
  FIELD_TYPE_UNSPECIFIED = 0;
  FIELD_TYPE_STRING = 1;
  FIELD_TYPE_NUMBER = 2;
  FIELD_TYPE_BOOLEAN = 3;
  FIELD_TYPE_OBJECT = 4;
  FIELD_TYPE_ARRAY = 5;
}

enum PIIType {
  PII_TYPE_NONE = 0;
  PII_TYPE_EMAIL = 1;
  PII_TYPE_PHONE = 2;
  PII_TYPE_SSN = 3;
  PII_TYPE_NAME = 4;
  PII_TYPE_ADDRESS = 5;
  PII_TYPE_CREDIT_CARD = 6;
}

enum AnonymizationStrategy {
  ANONYMIZATION_STRATEGY_PRESERVE = 0;
  ANONYMIZATION_STRATEGY_MASK = 1;
  ANONYMIZATION_STRATEGY_HASH = 2;
  ANONYMIZATION_STRATEGY_TOKENIZE = 3;
  ANONYMIZATION_STRATEGY_REDACT = 4;
}

enum VersionStatus {
  VERSION_STATUS_UNSPECIFIED = 0;
  VERSION_STATUS_DRAFT = 1;
  VERSION_STATUS_PUBLISHED = 2;
  VERSION_STATUS_ARCHIVED = 3;
}
```

### AnonymizationService

```protobuf
syntax = "proto3";

package anonymization.v1;

import "google/protobuf/struct.proto";

service AnonymizationService {
  rpc Anonymize(AnonymizeRequest) returns (AnonymizeResponse);
  rpc DetectPII(DetectPIIRequest) returns (DetectPIIResponse);
  rpc Tokenize(TokenizeRequest) returns (TokenizeResponse);
  rpc Detokenize(DetokenizeRequest) returns (DetokenizeResponse);
}

message AnonymizeRequest {
  google.protobuf.Struct data = 1;
  DatasetSchema schema = 2;
  bool preserve_format = 3;
}

message AnonymizeResponse {
  google.protobuf.Struct anonymized_data = 1;
  repeated PIIDetection pii_detected = 2;
}

message DetectPIIRequest {
  string text = 1;
  repeated string entity_types = 2;
}

message DetectPIIResponse {
  repeated PIIDetection detections = 1;
}

message PIIDetection {
  string entity_type = 1;
  string text = 2;
  int32 start = 3;
  int32 end = 4;
  float confidence = 5;
}

message TokenizeRequest {
  repeated string values = 1;
  string entity_type = 2;
}

message TokenizeResponse {
  repeated TokenPair tokens = 1;
}

message TokenPair {
  string original = 1;
  string token = 2;
}

message DetokenizeRequest {
  repeated string tokens = 1;
}

message DetokenizeResponse {
  repeated TokenPair values = 1;
}

message DatasetSchema {
  repeated FieldDefinition fields = 1;
  google.protobuf.Struct validation_rules = 2;
}

message FieldDefinition {
  string name = 1;
  FieldType type = 2;
  bool required = 3;
  PIIType pii_type = 4;
  AnonymizationStrategy anonymization_strategy = 5;
}

enum FieldType {
  FIELD_TYPE_UNSPECIFIED = 0;
  FIELD_TYPE_STRING = 1;
  FIELD_TYPE_NUMBER = 2;
  FIELD_TYPE_BOOLEAN = 3;
  FIELD_TYPE_OBJECT = 4;
  FIELD_TYPE_ARRAY = 5;
}

enum PIIType {
  PII_TYPE_NONE = 0;
  PII_TYPE_EMAIL = 1;
  PII_TYPE_PHONE = 2;
  PII_TYPE_SSN = 3;
  PII_TYPE_NAME = 4;
  PII_TYPE_ADDRESS = 5;
  PII_TYPE_CREDIT_CARD = 6;
}

enum AnonymizationStrategy {
  ANONYMIZATION_STRATEGY_PRESERVE = 0;
  ANONYMIZATION_STRATEGY_MASK = 1;
  ANONYMIZATION_STRATEGY_HASH = 2;
  ANONYMIZATION_STRATEGY_TOKENIZE = 3;
  ANONYMIZATION_STRATEGY_REDACT = 4;
}
```

## 7. Common Headers

### Request Headers
```
Authorization: Bearer <token>
X-API-Key: <api-key>
Content-Type: application/json
Accept: application/json
X-Request-ID: <uuid>
X-Idempotency-Key: <uuid>
```

### Response Headers
```
X-Request-ID: <uuid>
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1699999600
Content-Type: application/json
```

## 8. Idempotency

POST, PUT, DELETE operations support idempotency via `X-Idempotency-Key` header. Same key within 24 hours returns cached response.

```http
POST /api/v1/datasets
X-Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
```

## 9. Versioning

API version in URL path: `/api/v1/`

Breaking changes require new major version: `/api/v2/`

Non-breaking changes (new fields, endpoints) added to current version.
