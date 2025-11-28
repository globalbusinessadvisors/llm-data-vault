# Error Handling Standards

**Document Version:** 1.0
**Last Updated:** 2025-11-27
**Status:** Draft

## Overview

This document defines comprehensive error handling standards for LLM-Data-Vault, including error codes, response formats, logging practices, and client handling strategies.

## 1. Error Code System

### Format

All error codes follow the format: `VAULT_{CATEGORY}_{NUMBER}`

### Categories

| Category | Code Range | Description |
|----------|------------|-------------|
| AUTH | 1000-1999 | Authentication errors (identity verification) |
| AUTHZ | 2000-2999 | Authorization errors (permission checks) |
| VALID | 3000-3999 | Validation errors (input/data validation) |
| DATA | 4000-4999 | Data/storage errors (database, storage operations) |
| CRYPTO | 5000-5999 | Encryption/decryption errors |
| ANON | 6000-6999 | Anonymization/de-identification errors |
| SYS | 9000-9999 | System errors (infrastructure, internal) |

## 2. Complete Error Catalog

### Authentication Errors (1000-1999)

| Code | Name | HTTP | Message | Resolution |
|------|------|------|---------|------------|
| VAULT_AUTH_1001 | InvalidToken | 401 | The provided JWT token is malformed or invalid | Verify token format and signature |
| VAULT_AUTH_1002 | TokenExpired | 401 | The authentication token has expired | Refresh token or re-authenticate |
| VAULT_AUTH_1003 | TokenNotYetValid | 401 | The authentication token is not yet valid (nbf claim) | Check system clock synchronization |
| VAULT_AUTH_1004 | InvalidSignature | 401 | Token signature verification failed | Ensure correct signing key is used |
| VAULT_AUTH_1005 | MissingToken | 401 | No authentication token provided | Include Authorization header with valid token |
| VAULT_AUTH_1006 | InvalidIssuer | 401 | Token issuer is not recognized | Verify token issuer matches expected value |
| VAULT_AUTH_1007 | InvalidAudience | 401 | Token audience claim does not match | Ensure token is issued for this service |
| VAULT_AUTH_1008 | InvalidCredentials | 401 | Username or password is incorrect | Verify credentials and try again |
| VAULT_AUTH_1009 | AccountLocked | 401 | Account has been locked due to security policy | Contact administrator to unlock account |
| VAULT_AUTH_1010 | AccountDisabled | 401 | Account has been disabled | Contact administrator to enable account |
| VAULT_AUTH_1011 | MFARequired | 401 | Multi-factor authentication is required | Complete MFA challenge |
| VAULT_AUTH_1012 | InvalidMFACode | 401 | The provided MFA code is invalid | Verify MFA code and try again |
| VAULT_AUTH_1013 | MFACodeExpired | 401 | The MFA code has expired | Request new MFA code |
| VAULT_AUTH_1014 | SessionExpired | 401 | The user session has expired | Create new session by authenticating |
| VAULT_AUTH_1015 | InvalidSessionID | 401 | The session ID is invalid or not found | Start new session |
| VAULT_AUTH_1016 | ConcurrentSessionLimit | 401 | Maximum concurrent sessions exceeded | Terminate existing sessions |
| VAULT_AUTH_1017 | InvalidRefreshToken | 401 | The refresh token is invalid or revoked | Re-authenticate to obtain new tokens |
| VAULT_AUTH_1018 | RefreshTokenExpired | 401 | The refresh token has expired | Re-authenticate to obtain new tokens |
| VAULT_AUTH_1019 | APIKeyInvalid | 401 | The provided API key is invalid | Verify API key is correct and active |
| VAULT_AUTH_1020 | APIKeyExpired | 401 | The API key has expired | Generate new API key |
| VAULT_AUTH_1021 | APIKeyRevoked | 401 | The API key has been revoked | Generate new API key |
| VAULT_AUTH_1022 | UnsupportedAuthMethod | 401 | The authentication method is not supported | Use supported authentication method |

### Authorization Errors (2000-2999)

| Code | Name | HTTP | Message | Resolution |
|------|------|------|---------|------------|
| VAULT_AUTHZ_2001 | PermissionDenied | 403 | Insufficient permissions to perform this operation | Request appropriate permissions from administrator |
| VAULT_AUTHZ_2002 | ResourceAccessDenied | 403 | Access to this resource is denied | Verify resource permissions |
| VAULT_AUTHZ_2003 | RoleRequired | 403 | Required role is missing | Request role assignment from administrator |
| VAULT_AUTHZ_2004 | ScopeInsufficient | 403 | Token scope insufficient for this operation | Request token with appropriate scope |
| VAULT_AUTHZ_2005 | DatasetAccessDenied | 403 | Access to dataset is not permitted | Request dataset access permissions |
| VAULT_AUTHZ_2006 | NamespaceAccessDenied | 403 | Access to namespace is not permitted | Verify namespace permissions |
| VAULT_AUTHZ_2007 | VaultAccessDenied | 403 | Access to vault is not permitted | Request vault access from owner |
| VAULT_AUTHZ_2008 | OperationNotPermitted | 403 | This operation is not permitted for your role | Contact administrator for permission escalation |
| VAULT_AUTHZ_2009 | ReadOnlyMode | 403 | System is in read-only mode | Wait for maintenance window to complete |
| VAULT_AUTHZ_2010 | IPAddressBlocked | 403 | Request from blocked IP address | Contact administrator to whitelist IP |
| VAULT_AUTHZ_2011 | RateLimitExceeded | 429 | API rate limit exceeded | Reduce request rate and retry after cooldown |
| VAULT_AUTHZ_2012 | QuotaExceeded | 403 | Storage or resource quota exceeded | Increase quota or delete unused resources |
| VAULT_AUTHZ_2013 | OwnershipRequired | 403 | Only resource owner can perform this operation | Transfer ownership or request owner action |
| VAULT_AUTHZ_2014 | AdminRequired | 403 | Administrator privileges required | Contact system administrator |
| VAULT_AUTHZ_2015 | PolicyViolation | 403 | Operation violates security policy | Review and comply with security policies |
| VAULT_AUTHZ_2016 | GeofenceViolation | 403 | Request originates from restricted geography | Access from permitted location |
| VAULT_AUTHZ_2017 | TimeRestriction | 403 | Access not permitted during this time period | Retry during permitted time window |
| VAULT_AUTHZ_2018 | ConcurrentAccessDenied | 403 | Resource is locked by another user | Wait for resource to be released |
| VAULT_AUTHZ_2019 | DelegationNotPermitted | 403 | Permission delegation is not allowed | Use direct permissions instead |
| VAULT_AUTHZ_2020 | ServiceAccountRestricted | 403 | Service account has restricted permissions | Use user account or request permission expansion |

### Validation Errors (3000-3999)

| Code | Name | HTTP | Message | Resolution |
|------|------|------|---------|------------|
| VAULT_VALID_3001 | InvalidRequestFormat | 400 | Request body format is invalid | Verify JSON/request structure |
| VAULT_VALID_3002 | MissingRequiredField | 400 | Required field is missing | Include all required fields |
| VAULT_VALID_3003 | InvalidFieldType | 400 | Field has incorrect data type | Correct field data type |
| VAULT_VALID_3004 | InvalidFieldValue | 400 | Field value is not valid | Provide valid field value |
| VAULT_VALID_3005 | FieldTooLong | 400 | Field value exceeds maximum length | Reduce field length to within limits |
| VAULT_VALID_3006 | FieldTooShort | 400 | Field value below minimum length | Increase field length to meet minimum |
| VAULT_VALID_3007 | InvalidFormat | 400 | Field format does not match expected pattern | Match expected format pattern |
| VAULT_VALID_3008 | InvalidEmail | 400 | Email address format is invalid | Provide valid email address |
| VAULT_VALID_3009 | InvalidURL | 400 | URL format is invalid | Provide valid URL |
| VAULT_VALID_3010 | InvalidUUID | 400 | UUID format is invalid | Provide valid UUID |
| VAULT_VALID_3011 | InvalidDateFormat | 400 | Date format is invalid | Use ISO 8601 date format |
| VAULT_VALID_3012 | InvalidTimeRange | 400 | Time range is invalid or illogical | Ensure end time is after start time |
| VAULT_VALID_3013 | InvalidEnumValue | 400 | Value not in allowed enumeration | Use one of the allowed values |
| VAULT_VALID_3014 | InvalidArraySize | 400 | Array size outside permitted range | Adjust array size to permitted range |
| VAULT_VALID_3015 | DuplicateValue | 400 | Duplicate value where uniqueness required | Provide unique value |
| VAULT_VALID_3016 | InvalidSchema | 400 | Schema definition is invalid | Correct schema definition |
| VAULT_VALID_3017 | SchemaValidationFailed | 400 | Data does not match schema | Ensure data conforms to schema |
| VAULT_VALID_3018 | InvalidDatasetName | 400 | Dataset name contains invalid characters | Use alphanumeric, underscore, hyphen only |
| VAULT_VALID_3019 | InvalidNamespace | 400 | Namespace format is invalid | Follow namespace naming conventions |
| VAULT_VALID_3020 | InvalidVersionFormat | 400 | Version string format is invalid | Use semantic versioning (e.g., 1.0.0) |
| VAULT_VALID_3021 | InvalidChecksum | 400 | Checksum does not match data | Verify data integrity and recalculate |
| VAULT_VALID_3022 | InvalidEncoding | 400 | Data encoding is not supported | Use supported encoding (UTF-8, Base64) |
| VAULT_VALID_3023 | InvalidContentType | 400 | Content-Type header is invalid or unsupported | Set appropriate Content-Type header |
| VAULT_VALID_3024 | PayloadTooLarge | 413 | Request payload exceeds size limit | Reduce payload size or use chunked upload |
| VAULT_VALID_3025 | InvalidQueryParameter | 400 | Query parameter is invalid | Correct query parameter format/value |

### Data Errors (4000-4999)

| Code | Name | HTTP | Message | Resolution |
|------|------|------|---------|------------|
| VAULT_DATA_4001 | ResourceNotFound | 404 | Requested resource does not exist | Verify resource ID/path is correct |
| VAULT_DATA_4002 | DatasetNotFound | 404 | Dataset does not exist | Verify dataset ID and namespace |
| VAULT_DATA_4003 | VaultNotFound | 404 | Vault does not exist | Create vault or verify vault ID |
| VAULT_DATA_4004 | RecordNotFound | 404 | Record does not exist in dataset | Verify record ID |
| VAULT_DATA_4005 | VersionNotFound | 404 | Requested version does not exist | Use valid version number |
| VAULT_DATA_4006 | ResourceAlreadyExists | 409 | Resource with this identifier already exists | Use different identifier or update existing |
| VAULT_DATA_4007 | DatasetAlreadyExists | 409 | Dataset already exists in namespace | Use different name or delete existing |
| VAULT_DATA_4008 | DuplicateRecord | 409 | Record with this ID already exists | Update existing record or use new ID |
| VAULT_DATA_4009 | ConflictingUpdate | 409 | Resource was modified by another request | Refresh data and retry update |
| VAULT_DATA_4010 | StaleVersion | 409 | Attempting to modify outdated version | Fetch latest version and retry |
| VAULT_DATA_4011 | DatabaseConnectionFailed | 503 | Unable to connect to database | Check database availability and retry |
| VAULT_DATA_4012 | DatabaseQueryTimeout | 504 | Database query exceeded timeout | Optimize query or increase timeout |
| VAULT_DATA_4013 | DatabaseConstraintViolation | 409 | Database constraint violated | Check data against constraints |
| VAULT_DATA_4014 | TransactionFailed | 500 | Database transaction failed | Review transaction and retry |
| VAULT_DATA_4015 | StorageUnavailable | 503 | Storage backend is unavailable | Check storage service status |
| VAULT_DATA_4016 | StorageReadError | 500 | Failed to read from storage | Verify storage permissions and connectivity |
| VAULT_DATA_4017 | StorageWriteError | 500 | Failed to write to storage | Check storage capacity and permissions |
| VAULT_DATA_4018 | StorageDeleteError | 500 | Failed to delete from storage | Verify storage permissions |
| VAULT_DATA_4019 | DataCorruption | 500 | Stored data is corrupted | Restore from backup if available |
| VAULT_DATA_4020 | ChecksumMismatch | 500 | Data checksum does not match stored value | Data may be corrupted, restore from backup |
| VAULT_DATA_4021 | InsufficientStorage | 507 | Insufficient storage space available | Free up space or increase storage capacity |
| VAULT_DATA_4022 | IndexingFailed | 500 | Failed to index data | Retry indexing operation |
| VAULT_DATA_4023 | SearchFailed | 500 | Search operation failed | Verify search query and retry |
| VAULT_DATA_4024 | BackupFailed | 500 | Data backup operation failed | Check backup configuration and storage |
| VAULT_DATA_4025 | RestoreFailed | 500 | Data restore operation failed | Verify backup integrity and permissions |

### Crypto Errors (5000-5999)

| Code | Name | HTTP | Message | Resolution |
|------|------|------|---------|------------|
| VAULT_CRYPTO_5001 | EncryptionFailed | 500 | Data encryption operation failed | Check encryption configuration and retry |
| VAULT_CRYPTO_5002 | DecryptionFailed | 500 | Data decryption operation failed | Verify encryption key and data integrity |
| VAULT_CRYPTO_5003 | InvalidEncryptionKey | 400 | Encryption key is invalid or corrupted | Provide valid encryption key |
| VAULT_CRYPTO_5004 | KeyNotFound | 404 | Encryption key not found | Verify key ID and key store availability |
| VAULT_CRYPTO_5005 | KeyExpired | 400 | Encryption key has expired | Rotate to new key |
| VAULT_CRYPTO_5006 | KeyRotationFailed | 500 | Key rotation operation failed | Review rotation policy and retry |
| VAULT_CRYPTO_5007 | UnsupportedAlgorithm | 400 | Encryption algorithm not supported | Use supported algorithm (AES-256-GCM, ChaCha20) |
| VAULT_CRYPTO_5008 | InvalidKeyLength | 400 | Key length does not meet requirements | Use appropriate key length (256-bit minimum) |
| VAULT_CRYPTO_5009 | KeyDerivationFailed | 500 | Key derivation operation failed | Check KDF parameters and retry |
| VAULT_CRYPTO_5010 | HSMUnavailable | 503 | Hardware Security Module unavailable | Check HSM connectivity and status |
| VAULT_CRYPTO_5011 | HSMOperationFailed | 500 | HSM operation failed | Review HSM logs and retry |
| VAULT_CRYPTO_5012 | InvalidCiphertext | 400 | Ciphertext is malformed or corrupted | Verify ciphertext integrity |
| VAULT_CRYPTO_5013 | InvalidNonce | 400 | Nonce/IV is invalid or reused | Generate new unique nonce |
| VAULT_CRYPTO_5014 | AuthenticationTagMismatch | 400 | AEAD authentication tag verification failed | Data may be tampered, verify integrity |
| VAULT_CRYPTO_5015 | RNGFailed | 500 | Random number generation failed | Check system entropy and CSPRNG |

### Anonymization Errors (6000-6999)

| Code | Name | HTTP | Message | Resolution |
|------|------|------|---------|------------|
| VAULT_ANON_6001 | AnonymizationFailed | 500 | Data anonymization operation failed | Review anonymization policy and retry |
| VAULT_ANON_6002 | DeidentificationFailed | 500 | De-identification operation failed | Check de-identification rules |
| VAULT_ANON_6003 | InvalidAnonymizationPolicy | 400 | Anonymization policy is invalid | Correct policy definition |
| VAULT_ANON_6004 | PolicyNotFound | 404 | Anonymization policy not found | Create policy or verify policy ID |
| VAULT_ANON_6005 | UnsupportedTechnique | 400 | Anonymization technique not supported | Use supported technique (k-anonymity, etc.) |
| VAULT_ANON_6006 | InsufficientKAnonymity | 400 | K-anonymity threshold not met | Adjust parameters or generalize further |
| VAULT_ANON_6007 | InsufficientLDiversity | 400 | L-diversity threshold not met | Increase diversity or adjust threshold |
| VAULT_ANON_6008 | ReidentificationRisk | 400 | Re-identification risk exceeds threshold | Apply stronger anonymization |
| VAULT_ANON_6009 | PIIDetectionFailed | 500 | PII detection operation failed | Review detection configuration |
| VAULT_ANON_6010 | MaskingFailed | 500 | Data masking operation failed | Check masking rules and data format |
| VAULT_ANON_6011 | TokenizationFailed | 500 | Tokenization operation failed | Verify tokenization service availability |
| VAULT_ANON_6012 | DetokenizationFailed | 500 | Detokenization operation failed | Verify token validity and service availability |
| VAULT_ANON_6013 | InvalidSyntheticData | 400 | Synthetic data generation parameters invalid | Adjust generation parameters |
| VAULT_ANON_6014 | SyntheticDataGenerationFailed | 500 | Failed to generate synthetic data | Review source data and generation model |
| VAULT_ANON_6015 | DifferentialPrivacyBudgetExceeded | 400 | Privacy budget exhausted | Reset budget period or reduce queries |

### System Errors (9000-9999)

| Code | Name | HTTP | Message | Resolution |
|------|------|------|---------|------------|
| VAULT_SYS_9001 | InternalServerError | 500 | An unexpected internal error occurred | Retry request or contact support |
| VAULT_SYS_9002 | ServiceUnavailable | 503 | Service temporarily unavailable | Retry after backoff period |
| VAULT_SYS_9003 | ConfigurationError | 500 | System configuration error detected | Check configuration files and environment |
| VAULT_SYS_9004 | DependencyUnavailable | 503 | Required dependency service unavailable | Check dependency service status |
| VAULT_SYS_9005 | TimeoutError | 504 | Operation timed out | Retry with longer timeout or optimize operation |
| VAULT_SYS_9006 | ResourceExhausted | 503 | System resources exhausted | Scale resources or reduce load |
| VAULT_SYS_9007 | MemoryAllocationFailed | 500 | Failed to allocate memory | Reduce memory usage or increase available memory |
| VAULT_SYS_9008 | ThreadPoolExhausted | 503 | Thread pool capacity reached | Reduce concurrent requests or scale workers |
| VAULT_SYS_9009 | CircuitBreakerOpen | 503 | Circuit breaker is open for this service | Wait for circuit breaker reset |
| VAULT_SYS_9010 | HealthCheckFailed | 503 | System health check failed | Review system health metrics |
| VAULT_SYS_9011 | MaintenanceMode | 503 | System is in maintenance mode | Wait for maintenance completion |
| VAULT_SYS_9012 | VersionMismatch | 400 | API version mismatch | Use compatible API version |
| VAULT_SYS_9013 | DeprecatedEndpoint | 410 | Endpoint is deprecated and removed | Use newer API endpoint |
| VAULT_SYS_9014 | InvalidConfiguration | 500 | Invalid system configuration detected | Correct configuration and restart |
| VAULT_SYS_9015 | CacheFailed | 500 | Cache operation failed | Clear cache or disable caching temporarily |

## 3. Error Response Format

### RFC 7807 Problem Details

All error responses follow RFC 7807 Problem Details for HTTP APIs standard.

#### Standard Format

```json
{
  "type": "https://api.vault.example/errors/VAULT_AUTH_1001",
  "title": "Invalid Token",
  "status": 401,
  "detail": "The provided JWT token is malformed or does not match the expected format",
  "instance": "/api/v1/datasets/ds_123/records",
  "code": "VAULT_AUTH_1001",
  "trace_id": "abc123def456",
  "timestamp": "2025-01-01T12:34:56.789Z",
  "errors": []
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | Yes | URI reference identifying the problem type |
| title | string | Yes | Short, human-readable summary |
| status | integer | Yes | HTTP status code |
| detail | string | Yes | Human-readable explanation specific to this occurrence |
| instance | string | Yes | URI reference identifying the specific occurrence |
| code | string | Yes | Machine-readable error code (VAULT_XXX_NNNN) |
| trace_id | string | Yes | Correlation ID for tracing across services |
| timestamp | string | Yes | ISO 8601 timestamp when error occurred |
| errors | array | No | Additional validation errors (for multi-field validation) |

#### Validation Error Format

For validation errors affecting multiple fields:

```json
{
  "type": "https://api.vault.example/errors/VAULT_VALID_3002",
  "title": "Validation Failed",
  "status": 400,
  "detail": "One or more fields failed validation",
  "instance": "/api/v1/datasets",
  "code": "VAULT_VALID_3002",
  "trace_id": "xyz789abc123",
  "timestamp": "2025-01-01T12:34:56.789Z",
  "errors": [
    {
      "field": "name",
      "code": "VAULT_VALID_3002",
      "message": "Required field is missing"
    },
    {
      "field": "schema.fields[2].type",
      "code": "VAULT_VALID_3013",
      "message": "Value 'string_invalid' not in allowed enumeration: [string, integer, float, boolean, timestamp]"
    }
  ]
}
```

#### Error with Retry Information

For transient errors, include retry guidance:

```json
{
  "type": "https://api.vault.example/errors/VAULT_AUTHZ_2011",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "API rate limit of 100 requests per minute exceeded",
  "instance": "/api/v1/datasets",
  "code": "VAULT_AUTHZ_2011",
  "trace_id": "rate123limit456",
  "timestamp": "2025-01-01T12:34:56.789Z",
  "errors": [],
  "retry_after": 45,
  "rate_limit": {
    "limit": 100,
    "remaining": 0,
    "reset": "2025-01-01T12:35:00.000Z"
  }
}
```

## 4. Rust Error Types

### Base Error Framework

```rust
use thiserror::Error;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Base error type for all vault errors
#[derive(Debug, Error)]
pub enum VaultError {
    #[error(transparent)]
    Auth(#[from] AuthError),

    #[error(transparent)]
    Authz(#[from] AuthzError),

    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error(transparent)]
    Data(#[from] DataError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Anonymization(#[from] AnonymizationError),

    #[error(transparent)]
    System(#[from] SystemError),
}

/// Error response structure matching RFC 7807
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: String,
    pub code: String,
    pub trace_id: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FieldError {
    pub field: String,
    pub code: String,
    pub message: String,
}
```

### Authentication Errors

```rust
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("VAULT_AUTH_1001: The provided JWT token is malformed or invalid")]
    InvalidToken,

    #[error("VAULT_AUTH_1002: The authentication token has expired")]
    TokenExpired,

    #[error("VAULT_AUTH_1003: The authentication token is not yet valid (nbf claim)")]
    TokenNotYetValid,

    #[error("VAULT_AUTH_1004: Token signature verification failed")]
    InvalidSignature,

    #[error("VAULT_AUTH_1005: No authentication token provided")]
    MissingToken,

    #[error("VAULT_AUTH_1006: Token issuer is not recognized")]
    InvalidIssuer,

    #[error("VAULT_AUTH_1007: Token audience claim does not match")]
    InvalidAudience,

    #[error("VAULT_AUTH_1008: Username or password is incorrect")]
    InvalidCredentials,

    #[error("VAULT_AUTH_1009: Account has been locked due to security policy")]
    AccountLocked,

    #[error("VAULT_AUTH_1010: Account has been disabled")]
    AccountDisabled,

    #[error("VAULT_AUTH_1011: Multi-factor authentication is required")]
    MFARequired,

    #[error("VAULT_AUTH_1012: The provided MFA code is invalid")]
    InvalidMFACode,

    #[error("VAULT_AUTH_1013: The MFA code has expired")]
    MFACodeExpired,

    #[error("VAULT_AUTH_1014: The user session has expired")]
    SessionExpired,

    #[error("VAULT_AUTH_1015: The session ID is invalid or not found")]
    InvalidSessionID,

    #[error("VAULT_AUTH_1016: Maximum concurrent sessions exceeded")]
    ConcurrentSessionLimit,

    #[error("VAULT_AUTH_1017: The refresh token is invalid or revoked")]
    InvalidRefreshToken,

    #[error("VAULT_AUTH_1018: The refresh token has expired")]
    RefreshTokenExpired,

    #[error("VAULT_AUTH_1019: The provided API key is invalid")]
    APIKeyInvalid,

    #[error("VAULT_AUTH_1020: The API key has expired")]
    APIKeyExpired,

    #[error("VAULT_AUTH_1021: The API key has been revoked")]
    APIKeyRevoked,

    #[error("VAULT_AUTH_1022: The authentication method is not supported")]
    UnsupportedAuthMethod,
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidToken => "VAULT_AUTH_1001",
            Self::TokenExpired => "VAULT_AUTH_1002",
            Self::TokenNotYetValid => "VAULT_AUTH_1003",
            Self::InvalidSignature => "VAULT_AUTH_1004",
            Self::MissingToken => "VAULT_AUTH_1005",
            Self::InvalidIssuer => "VAULT_AUTH_1006",
            Self::InvalidAudience => "VAULT_AUTH_1007",
            Self::InvalidCredentials => "VAULT_AUTH_1008",
            Self::AccountLocked => "VAULT_AUTH_1009",
            Self::AccountDisabled => "VAULT_AUTH_1010",
            Self::MFARequired => "VAULT_AUTH_1011",
            Self::InvalidMFACode => "VAULT_AUTH_1012",
            Self::MFACodeExpired => "VAULT_AUTH_1013",
            Self::SessionExpired => "VAULT_AUTH_1014",
            Self::InvalidSessionID => "VAULT_AUTH_1015",
            Self::ConcurrentSessionLimit => "VAULT_AUTH_1016",
            Self::InvalidRefreshToken => "VAULT_AUTH_1017",
            Self::RefreshTokenExpired => "VAULT_AUTH_1018",
            Self::APIKeyInvalid => "VAULT_AUTH_1019",
            Self::APIKeyExpired => "VAULT_AUTH_1020",
            Self::APIKeyRevoked => "VAULT_AUTH_1021",
            Self::UnsupportedAuthMethod => "VAULT_AUTH_1022",
        }
    }

    pub fn http_status(&self) -> u16 {
        401
    }
}
```

### Authorization Errors

```rust
#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("VAULT_AUTHZ_2001: Insufficient permissions to perform this operation")]
    PermissionDenied,

    #[error("VAULT_AUTHZ_2002: Access to this resource is denied")]
    ResourceAccessDenied,

    #[error("VAULT_AUTHZ_2003: Required role is missing")]
    RoleRequired,

    #[error("VAULT_AUTHZ_2004: Token scope insufficient for this operation")]
    ScopeInsufficient,

    #[error("VAULT_AUTHZ_2005: Access to dataset is not permitted")]
    DatasetAccessDenied,

    #[error("VAULT_AUTHZ_2006: Access to namespace is not permitted")]
    NamespaceAccessDenied,

    #[error("VAULT_AUTHZ_2007: Access to vault is not permitted")]
    VaultAccessDenied,

    #[error("VAULT_AUTHZ_2008: This operation is not permitted for your role")]
    OperationNotPermitted,

    #[error("VAULT_AUTHZ_2009: System is in read-only mode")]
    ReadOnlyMode,

    #[error("VAULT_AUTHZ_2010: Request from blocked IP address")]
    IPAddressBlocked,

    #[error("VAULT_AUTHZ_2011: API rate limit exceeded")]
    RateLimitExceeded,

    #[error("VAULT_AUTHZ_2012: Storage or resource quota exceeded")]
    QuotaExceeded,

    #[error("VAULT_AUTHZ_2013: Only resource owner can perform this operation")]
    OwnershipRequired,

    #[error("VAULT_AUTHZ_2014: Administrator privileges required")]
    AdminRequired,

    #[error("VAULT_AUTHZ_2015: Operation violates security policy")]
    PolicyViolation,

    #[error("VAULT_AUTHZ_2016: Request originates from restricted geography")]
    GeofenceViolation,

    #[error("VAULT_AUTHZ_2017: Access not permitted during this time period")]
    TimeRestriction,

    #[error("VAULT_AUTHZ_2018: Resource is locked by another user")]
    ConcurrentAccessDenied,

    #[error("VAULT_AUTHZ_2019: Permission delegation is not allowed")]
    DelegationNotPermitted,

    #[error("VAULT_AUTHZ_2020: Service account has restricted permissions")]
    ServiceAccountRestricted,
}

impl AuthzError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PermissionDenied => "VAULT_AUTHZ_2001",
            Self::ResourceAccessDenied => "VAULT_AUTHZ_2002",
            Self::RoleRequired => "VAULT_AUTHZ_2003",
            Self::ScopeInsufficient => "VAULT_AUTHZ_2004",
            Self::DatasetAccessDenied => "VAULT_AUTHZ_2005",
            Self::NamespaceAccessDenied => "VAULT_AUTHZ_2006",
            Self::VaultAccessDenied => "VAULT_AUTHZ_2007",
            Self::OperationNotPermitted => "VAULT_AUTHZ_2008",
            Self::ReadOnlyMode => "VAULT_AUTHZ_2009",
            Self::IPAddressBlocked => "VAULT_AUTHZ_2010",
            Self::RateLimitExceeded => "VAULT_AUTHZ_2011",
            Self::QuotaExceeded => "VAULT_AUTHZ_2012",
            Self::OwnershipRequired => "VAULT_AUTHZ_2013",
            Self::AdminRequired => "VAULT_AUTHZ_2014",
            Self::PolicyViolation => "VAULT_AUTHZ_2015",
            Self::GeofenceViolation => "VAULT_AUTHZ_2016",
            Self::TimeRestriction => "VAULT_AUTHZ_2017",
            Self::ConcurrentAccessDenied => "VAULT_AUTHZ_2018",
            Self::DelegationNotPermitted => "VAULT_AUTHZ_2019",
            Self::ServiceAccountRestricted => "VAULT_AUTHZ_2020",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::RateLimitExceeded => 429,
            _ => 403,
        }
    }
}
```

### Validation Errors

```rust
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("VAULT_VALID_3001: Request body format is invalid")]
    InvalidRequestFormat,

    #[error("VAULT_VALID_3002: Required field is missing: {field}")]
    MissingRequiredField { field: String },

    #[error("VAULT_VALID_3003: Field has incorrect data type: {field}")]
    InvalidFieldType { field: String },

    #[error("VAULT_VALID_3004: Field value is not valid: {field}")]
    InvalidFieldValue { field: String },

    #[error("VAULT_VALID_3005: Field value exceeds maximum length: {field}")]
    FieldTooLong { field: String },

    #[error("VAULT_VALID_3006: Field value below minimum length: {field}")]
    FieldTooShort { field: String },

    #[error("VAULT_VALID_3007: Field format does not match expected pattern: {field}")]
    InvalidFormat { field: String },

    #[error("VAULT_VALID_3008: Email address format is invalid")]
    InvalidEmail,

    #[error("VAULT_VALID_3009: URL format is invalid")]
    InvalidURL,

    #[error("VAULT_VALID_3010: UUID format is invalid")]
    InvalidUUID,

    #[error("VAULT_VALID_3011: Date format is invalid")]
    InvalidDateFormat,

    #[error("VAULT_VALID_3012: Time range is invalid or illogical")]
    InvalidTimeRange,

    #[error("VAULT_VALID_3013: Value not in allowed enumeration: {field}")]
    InvalidEnumValue { field: String },

    #[error("VAULT_VALID_3014: Array size outside permitted range")]
    InvalidArraySize,

    #[error("VAULT_VALID_3015: Duplicate value where uniqueness required")]
    DuplicateValue,

    #[error("VAULT_VALID_3016: Schema definition is invalid")]
    InvalidSchema,

    #[error("VAULT_VALID_3017: Data does not match schema")]
    SchemaValidationFailed,

    #[error("VAULT_VALID_3018: Dataset name contains invalid characters")]
    InvalidDatasetName,

    #[error("VAULT_VALID_3019: Namespace format is invalid")]
    InvalidNamespace,

    #[error("VAULT_VALID_3020: Version string format is invalid")]
    InvalidVersionFormat,

    #[error("VAULT_VALID_3021: Checksum does not match data")]
    InvalidChecksum,

    #[error("VAULT_VALID_3022: Data encoding is not supported")]
    InvalidEncoding,

    #[error("VAULT_VALID_3023: Content-Type header is invalid or unsupported")]
    InvalidContentType,

    #[error("VAULT_VALID_3024: Request payload exceeds size limit")]
    PayloadTooLarge,

    #[error("VAULT_VALID_3025: Query parameter is invalid: {param}")]
    InvalidQueryParameter { param: String },
}
```

### Data Errors

```rust
#[derive(Debug, Error)]
pub enum DataError {
    #[error("VAULT_DATA_4001: Requested resource does not exist")]
    ResourceNotFound,

    #[error("VAULT_DATA_4002: Dataset does not exist")]
    DatasetNotFound,

    #[error("VAULT_DATA_4003: Vault does not exist")]
    VaultNotFound,

    #[error("VAULT_DATA_4004: Record does not exist in dataset")]
    RecordNotFound,

    #[error("VAULT_DATA_4005: Requested version does not exist")]
    VersionNotFound,

    #[error("VAULT_DATA_4006: Resource with this identifier already exists")]
    ResourceAlreadyExists,

    #[error("VAULT_DATA_4007: Dataset already exists in namespace")]
    DatasetAlreadyExists,

    #[error("VAULT_DATA_4008: Record with this ID already exists")]
    DuplicateRecord,

    #[error("VAULT_DATA_4009: Resource was modified by another request")]
    ConflictingUpdate,

    #[error("VAULT_DATA_4010: Attempting to modify outdated version")]
    StaleVersion,

    #[error("VAULT_DATA_4011: Unable to connect to database")]
    DatabaseConnectionFailed,

    #[error("VAULT_DATA_4012: Database query exceeded timeout")]
    DatabaseQueryTimeout,

    #[error("VAULT_DATA_4013: Database constraint violated")]
    DatabaseConstraintViolation,

    #[error("VAULT_DATA_4014: Database transaction failed")]
    TransactionFailed,

    #[error("VAULT_DATA_4015: Storage backend is unavailable")]
    StorageUnavailable,

    #[error("VAULT_DATA_4016: Failed to read from storage")]
    StorageReadError,

    #[error("VAULT_DATA_4017: Failed to write to storage")]
    StorageWriteError,

    #[error("VAULT_DATA_4018: Failed to delete from storage")]
    StorageDeleteError,

    #[error("VAULT_DATA_4019: Stored data is corrupted")]
    DataCorruption,

    #[error("VAULT_DATA_4020: Data checksum does not match stored value")]
    ChecksumMismatch,

    #[error("VAULT_DATA_4021: Insufficient storage space available")]
    InsufficientStorage,

    #[error("VAULT_DATA_4022: Failed to index data")]
    IndexingFailed,

    #[error("VAULT_DATA_4023: Search operation failed")]
    SearchFailed,

    #[error("VAULT_DATA_4024: Data backup operation failed")]
    BackupFailed,

    #[error("VAULT_DATA_4025: Data restore operation failed")]
    RestoreFailed,
}
```

### Crypto Errors

```rust
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("VAULT_CRYPTO_5001: Data encryption operation failed")]
    EncryptionFailed,

    #[error("VAULT_CRYPTO_5002: Data decryption operation failed")]
    DecryptionFailed,

    #[error("VAULT_CRYPTO_5003: Encryption key is invalid or corrupted")]
    InvalidEncryptionKey,

    #[error("VAULT_CRYPTO_5004: Encryption key not found")]
    KeyNotFound,

    #[error("VAULT_CRYPTO_5005: Encryption key has expired")]
    KeyExpired,

    #[error("VAULT_CRYPTO_5006: Key rotation operation failed")]
    KeyRotationFailed,

    #[error("VAULT_CRYPTO_5007: Encryption algorithm not supported")]
    UnsupportedAlgorithm,

    #[error("VAULT_CRYPTO_5008: Key length does not meet requirements")]
    InvalidKeyLength,

    #[error("VAULT_CRYPTO_5009: Key derivation operation failed")]
    KeyDerivationFailed,

    #[error("VAULT_CRYPTO_5010: Hardware Security Module unavailable")]
    HSMUnavailable,

    #[error("VAULT_CRYPTO_5011: HSM operation failed")]
    HSMOperationFailed,

    #[error("VAULT_CRYPTO_5012: Ciphertext is malformed or corrupted")]
    InvalidCiphertext,

    #[error("VAULT_CRYPTO_5013: Nonce/IV is invalid or reused")]
    InvalidNonce,

    #[error("VAULT_CRYPTO_5014: AEAD authentication tag verification failed")]
    AuthenticationTagMismatch,

    #[error("VAULT_CRYPTO_5015: Random number generation failed")]
    RNGFailed,
}
```

### Anonymization Errors

```rust
#[derive(Debug, Error)]
pub enum AnonymizationError {
    #[error("VAULT_ANON_6001: Data anonymization operation failed")]
    AnonymizationFailed,

    #[error("VAULT_ANON_6002: De-identification operation failed")]
    DeidentificationFailed,

    #[error("VAULT_ANON_6003: Anonymization policy is invalid")]
    InvalidAnonymizationPolicy,

    #[error("VAULT_ANON_6004: Anonymization policy not found")]
    PolicyNotFound,

    #[error("VAULT_ANON_6005: Anonymization technique not supported")]
    UnsupportedTechnique,

    #[error("VAULT_ANON_6006: K-anonymity threshold not met")]
    InsufficientKAnonymity,

    #[error("VAULT_ANON_6007: L-diversity threshold not met")]
    InsufficientLDiversity,

    #[error("VAULT_ANON_6008: Re-identification risk exceeds threshold")]
    ReidentificationRisk,

    #[error("VAULT_ANON_6009: PII detection operation failed")]
    PIIDetectionFailed,

    #[error("VAULT_ANON_6010: Data masking operation failed")]
    MaskingFailed,

    #[error("VAULT_ANON_6011: Tokenization operation failed")]
    TokenizationFailed,

    #[error("VAULT_ANON_6012: Detokenization operation failed")]
    DetokenizationFailed,

    #[error("VAULT_ANON_6013: Synthetic data generation parameters invalid")]
    InvalidSyntheticData,

    #[error("VAULT_ANON_6014: Failed to generate synthetic data")]
    SyntheticDataGenerationFailed,

    #[error("VAULT_ANON_6015: Privacy budget exhausted")]
    DifferentialPrivacyBudgetExceeded,
}
```

### System Errors

```rust
#[derive(Debug, Error)]
pub enum SystemError {
    #[error("VAULT_SYS_9001: An unexpected internal error occurred")]
    InternalServerError,

    #[error("VAULT_SYS_9002: Service temporarily unavailable")]
    ServiceUnavailable,

    #[error("VAULT_SYS_9003: System configuration error detected")]
    ConfigurationError,

    #[error("VAULT_SYS_9004: Required dependency service unavailable")]
    DependencyUnavailable,

    #[error("VAULT_SYS_9005: Operation timed out")]
    TimeoutError,

    #[error("VAULT_SYS_9006: System resources exhausted")]
    ResourceExhausted,

    #[error("VAULT_SYS_9007: Failed to allocate memory")]
    MemoryAllocationFailed,

    #[error("VAULT_SYS_9008: Thread pool capacity reached")]
    ThreadPoolExhausted,

    #[error("VAULT_SYS_9009: Circuit breaker is open for this service")]
    CircuitBreakerOpen,

    #[error("VAULT_SYS_9010: System health check failed")]
    HealthCheckFailed,

    #[error("VAULT_SYS_9011: System is in maintenance mode")]
    MaintenanceMode,

    #[error("VAULT_SYS_9012: API version mismatch")]
    VersionMismatch,

    #[error("VAULT_SYS_9013: Endpoint is deprecated and removed")]
    DeprecatedEndpoint,

    #[error("VAULT_SYS_9014: Invalid system configuration detected")]
    InvalidConfiguration,

    #[error("VAULT_SYS_9015: Cache operation failed")]
    CacheFailed,
}
```

## 5. Error Logging Standards

### Log Levels by Error Category

| Error Category | Log Level | Rationale |
|----------------|-----------|-----------|
| AUTH_1001-1007 | WARN | Token validation issues - expected in normal operation |
| AUTH_1008-1010 | WARN | Failed login attempts - security monitoring |
| AUTH_1011-1022 | INFO | Session/API key issues - routine operational events |
| AUTHZ_2001-2020 | WARN | Authorization failures - potential security concern |
| VALID_3001-3025 | INFO | Validation errors - client issues, not service issues |
| DATA_4001-4010 | INFO | Resource not found/conflicts - normal operation |
| DATA_4011-4025 | ERROR | Storage/database failures - requires investigation |
| CRYPTO_5001-5015 | ERROR | Cryptographic failures - critical security issues |
| ANON_6001-6015 | ERROR | Anonymization failures - privacy-critical |
| SYS_9001-9015 | ERROR | System failures - requires immediate attention |

### Structured Logging Format

```rust
use tracing::{error, warn, info, debug};
use serde_json::json;

// Example logging implementation
fn log_error(error: &VaultError, request_id: &str, user_id: Option<&str>) {
    let error_code = error.code();
    let error_message = error.to_string();

    // Redact PII from error details
    let sanitized_message = redact_pii(&error_message);

    match error {
        VaultError::Auth(e) => {
            warn!(
                error_code = error_code,
                request_id = request_id,
                user_id = user_id,
                error_type = "authentication",
                message = sanitized_message,
                "Authentication error"
            );
        }
        VaultError::Data(e) if matches!(e, DataError::ResourceNotFound | DataError::DatasetNotFound) => {
            info!(
                error_code = error_code,
                request_id = request_id,
                user_id = user_id,
                error_type = "data",
                message = sanitized_message,
                "Resource not found"
            );
        }
        VaultError::Crypto(e) => {
            error!(
                error_code = error_code,
                request_id = request_id,
                user_id = user_id,
                error_type = "cryptography",
                message = sanitized_message,
                "Cryptographic operation failed"
            );
        }
        _ => {
            error!(
                error_code = error_code,
                request_id = request_id,
                user_id = user_id,
                message = sanitized_message,
                "Error occurred"
            );
        }
    }
}
```

### PII Redaction Rules

PII must be redacted from all logs:

```rust
fn redact_pii(message: &str) -> String {
    let mut redacted = message.to_string();

    // Redact email addresses
    let email_regex = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
    redacted = email_regex.replace_all(&redacted, "[EMAIL_REDACTED]").to_string();

    // Redact phone numbers (various formats)
    let phone_regex = regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();
    redacted = phone_regex.replace_all(&redacted, "[PHONE_REDACTED]").to_string();

    // Redact JWT tokens
    let jwt_regex = regex::Regex::new(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*").unwrap();
    redacted = jwt_regex.replace_all(&redacted, "[TOKEN_REDACTED]").to_string();

    // Redact API keys (common patterns)
    let api_key_regex = regex::Regex::new(r"[A-Za-z0-9_-]{32,}").unwrap();
    redacted = api_key_regex.replace_all(&redacted, "[KEY_REDACTED]").to_string();

    redacted
}
```

### Correlation IDs

All errors must include correlation IDs for distributed tracing:

```rust
use uuid::Uuid;

pub struct RequestContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            trace_id: Uuid::new_v4().to_string(),
            span_id: Uuid::new_v4().to_string(),
            parent_span_id: None,
        }
    }

    pub fn from_headers(headers: &HeaderMap) -> Self {
        let trace_id = headers
            .get("X-Trace-ID")
            .and_then(|h| h.to_str().ok())
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let span_id = Uuid::new_v4().to_string();

        let parent_span_id = headers
            .get("X-Parent-Span-ID")
            .and_then(|h| h.to_str().ok())
            .map(String::from);

        Self {
            trace_id,
            span_id,
            parent_span_id,
        }
    }
}
```

### Log Retention Policy

| Log Level | Retention Period | Storage | Purpose |
|-----------|------------------|---------|---------|
| ERROR | 90 days | Hot storage | Active investigation |
| WARN | 60 days | Warm storage | Security monitoring |
| INFO | 30 days | Warm storage | Operational visibility |
| DEBUG | 7 days | Cold storage | Development debugging |

## 6. Client Error Handling Guide

### Retry Strategies by Error Type

#### Retryable Errors (with Exponential Backoff)

| Error Code | Initial Delay | Max Delay | Max Retries | Backoff Factor |
|------------|---------------|-----------|-------------|----------------|
| VAULT_AUTHZ_2011 (Rate Limit) | 1s | 60s | 5 | 2.0 |
| VAULT_DATA_4011 (DB Connection) | 100ms | 10s | 3 | 2.0 |
| VAULT_DATA_4012 (Query Timeout) | 500ms | 30s | 2 | 2.0 |
| VAULT_SYS_9002 (Service Unavailable) | 1s | 60s | 5 | 2.0 |
| VAULT_SYS_9005 (Timeout) | 500ms | 30s | 3 | 2.0 |
| VAULT_SYS_9009 (Circuit Breaker) | 5s | 60s | 3 | 2.0 |

#### Non-Retryable Errors (Fail Fast)

- All AUTH errors (1001-1022) - Re-authentication required
- All AUTHZ errors (2001-2020) except rate limit - Permission changes required
- All VALID errors (3001-3025) - Client must fix input
- Conflict errors (4006-4010) - Business logic resolution required
- All CRYPTO errors (5001-5015) - Configuration/key issues
- All ANON errors (6001-6015) - Policy/configuration issues

### Client Retry Implementation Example

```typescript
// TypeScript/JavaScript client example
interface RetryConfig {
  maxRetries: number;
  initialDelay: number;
  maxDelay: number;
  backoffFactor: number;
}

const RETRY_CONFIGS: Record<string, RetryConfig> = {
  'VAULT_AUTHZ_2011': { maxRetries: 5, initialDelay: 1000, maxDelay: 60000, backoffFactor: 2.0 },
  'VAULT_DATA_4011': { maxRetries: 3, initialDelay: 100, maxDelay: 10000, backoffFactor: 2.0 },
  'VAULT_SYS_9002': { maxRetries: 5, initialDelay: 1000, maxDelay: 60000, backoffFactor: 2.0 },
};

async function retryableRequest<T>(
  fn: () => Promise<T>,
  errorCode?: string
): Promise<T> {
  const config = errorCode ? RETRY_CONFIGS[errorCode] : null;

  if (!config) {
    // Non-retryable, execute once
    return await fn();
  }

  let lastError: Error;
  let delay = config.initialDelay;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      if (attempt < config.maxRetries) {
        // Wait with exponential backoff
        await sleep(delay);
        delay = Math.min(delay * config.backoffFactor, config.maxDelay);
      }
    }
  }

  throw lastError;
}

// Example usage
try {
  const dataset = await retryableRequest(
    () => vaultClient.getDataset('ds_123'),
    'VAULT_DATA_4011'
  );
} catch (error) {
  handleError(error);
}
```

### User-Facing Message Guidelines

#### Error Message Principles

1. **Be Clear and Specific**: Explain what went wrong in plain language
2. **Be Actionable**: Tell users what they can do to resolve the issue
3. **Be Appropriate**: Don't expose internal implementation details
4. **Be Consistent**: Use consistent terminology across all errors

#### Message Templates by Category

**Authentication Errors (1000-1999)**
- Template: "Authentication failed. [Specific reason]. Please [action]."
- Example: "Authentication failed. Your session has expired. Please log in again."

**Authorization Errors (2000-2999)**
- Template: "Access denied. You don't have permission to [action]. Contact your administrator to request access."
- Example: "Access denied. You don't have permission to delete this dataset. Contact your administrator to request access."

**Validation Errors (3000-3999)**
- Template: "[Field] is invalid. [Requirement]. Please correct and try again."
- Example: "Dataset name is invalid. Names must contain only letters, numbers, underscores, and hyphens. Please correct and try again."

**Data Errors (4000-4999)**
- Template: "[Resource] not found. Please verify [identifier] and try again."
- Example: "Dataset not found. Please verify the dataset ID and try again."

**System Errors (9000-9999)**
- Template: "Service temporarily unavailable. Please try again in a few moments. If the problem persists, contact support with error code [code]."
- Example: "Service temporarily unavailable. Please try again in a few moments. If the problem persists, contact support with error code VAULT_SYS_9002."

### Error Display Best Practices

#### API Error Response Parsing

```typescript
interface VaultError {
  type: string;
  title: string;
  status: number;
  detail: string;
  code: string;
  trace_id: string;
  errors?: Array<{
    field: string;
    code: string;
    message: string;
  }>;
}

function getUserFriendlyMessage(error: VaultError): string {
  // For validation errors with multiple field errors
  if (error.code.startsWith('VAULT_VALID_') && error.errors?.length) {
    const fieldMessages = error.errors.map(e => `- ${e.field}: ${e.message}`);
    return `Please correct the following:\n${fieldMessages.join('\n')}`;
  }

  // For specific error codes, provide customized messages
  const customMessages: Record<string, string> = {
    'VAULT_AUTH_1002': 'Your session has expired. Please log in again.',
    'VAULT_AUTHZ_2001': 'You don\'t have permission to perform this action. Please contact your administrator.',
    'VAULT_DATA_4002': 'The requested dataset could not be found. Please check the dataset ID.',
  };

  return customMessages[error.code] || error.detail;
}
```

#### UI Error Display Components

```typescript
// React component example
function ErrorDisplay({ error }: { error: VaultError }) {
  const message = getUserFriendlyMessage(error);
  const severity = getSeverity(error.code);

  return (
    <Alert severity={severity}>
      <AlertTitle>{error.title}</AlertTitle>
      <Typography variant="body2">{message}</Typography>
      {error.trace_id && (
        <Typography variant="caption" color="textSecondary">
          Error ID: {error.trace_id}
        </Typography>
      )}
    </Alert>
  );
}

function getSeverity(code: string): 'error' | 'warning' | 'info' {
  if (code.startsWith('VAULT_AUTH_') || code.startsWith('VAULT_AUTHZ_')) {
    return 'warning';
  }
  if (code.startsWith('VAULT_VALID_')) {
    return 'info';
  }
  return 'error';
}
```

## 7. Monitoring and Alerting

### Error Rate Thresholds

| Error Category | Warning Threshold | Critical Threshold | Window |
|----------------|-------------------|-------------------|--------|
| AUTH errors | >100/min | >500/min | 5 min |
| AUTHZ errors | >50/min | >200/min | 5 min |
| CRYPTO errors | >1/min | >10/min | 5 min |
| DATA storage errors | >10/min | >50/min | 5 min |
| SYS errors | >5/min | >20/min | 5 min |

### Error Metrics to Track

1. **Error rate by code**: Track frequency of each error code
2. **Error rate by endpoint**: Identify problematic APIs
3. **Error rate by user**: Detect abuse or client issues
4. **Mean time to recovery (MTTR)**: For system errors
5. **Error distribution**: Understand error patterns over time

### Health Check Integration

```rust
use axum::{Json, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
struct HealthStatus {
    status: String,
    version: String,
    timestamp: String,
    checks: Vec<ComponentHealth>,
}

#[derive(Serialize)]
struct ComponentHealth {
    name: String,
    status: String,
    error_code: Option<String>,
}

async fn health_check() -> impl IntoResponse {
    let mut checks = vec![];

    // Database check
    match check_database().await {
        Ok(_) => checks.push(ComponentHealth {
            name: "database".to_string(),
            status: "healthy".to_string(),
            error_code: None,
        }),
        Err(e) => checks.push(ComponentHealth {
            name: "database".to_string(),
            status: "unhealthy".to_string(),
            error_code: Some(e.code().to_string()),
        }),
    }

    // Storage check
    match check_storage().await {
        Ok(_) => checks.push(ComponentHealth {
            name: "storage".to_string(),
            status: "healthy".to_string(),
            error_code: None,
        }),
        Err(e) => checks.push(ComponentHealth {
            name: "storage".to_string(),
            status: "unhealthy".to_string(),
            error_code: Some(e.code().to_string()),
        }),
    }

    let overall_status = if checks.iter().all(|c| c.status == "healthy") {
        "healthy"
    } else {
        "unhealthy"
    };

    let health = HealthStatus {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        checks,
    };

    Json(health)
}
```

## Conclusion

This error handling standard provides:
- Comprehensive error code taxonomy covering all failure modes
- Standardized RFC 7807 error responses for API consistency
- Type-safe Rust error handling with proper propagation
- Security-conscious logging with PII redaction
- Client-friendly retry strategies and user messaging
- Production-ready monitoring and alerting guidelines

All implementations must adhere to these standards to ensure consistent, secure, and maintainable error handling across LLM-Data-Vault.
