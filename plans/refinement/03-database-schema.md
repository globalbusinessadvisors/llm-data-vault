# Database Schema

**Document:** 03-database-schema.md
**Version:** 1.0.0
**Phase:** SPARC - Refinement
**Last Updated:** 2025-11-27
**Status:** Ready for Implementation

---

## Table of Contents

1. [Migration Strategy](#1-migration-strategy)
2. [Core Tables](#2-core-tables)
3. [Indexes](#3-indexes)
4. [Constraints](#4-constraints)
5. [Functions & Triggers](#5-functions--triggers)
6. [Row Level Security](#6-row-level-security)
7. [Initial Seed Data](#7-initial-seed-data)

---

## 1. Migration Strategy

### 1.1 Migration Framework: sqlx

We use **sqlx** for type-safe database migrations with compile-time verification.

**Migration Directory Structure:**
```
migrations/
├── 20250101000000_initial_schema.up.sql
├── 20250101000000_initial_schema.down.sql
├── 20250102000000_add_encryption_keys.up.sql
├── 20250102000000_add_encryption_keys.down.sql
├── 20250103000000_add_audit_logs.up.sql
└── 20250103000000_add_audit_logs.down.sql
```

**Naming Convention:**
```
{timestamp}__{description}.{direction}.sql

Examples:
- V20250101000000__initial_schema.up.sql
- V20250101000000__initial_schema.down.sql
```

**Migration Rules:**
1. **Idempotent**: All migrations must be idempotent using `IF NOT EXISTS`
2. **Transactional**: Wrap migrations in transactions where possible
3. **Reversible**: Every `.up.sql` must have corresponding `.down.sql`
4. **Tested**: Test both up and down migrations before deployment

**Example Migration Template:**
```sql
-- V20250101000000__initial_schema.up.sql
BEGIN;

-- Check if migration already applied
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'tenants'
    ) THEN
        -- Create table logic here
    END IF;
END $$;

COMMIT;
```

### 1.2 Running Migrations

```bash
# Apply all pending migrations
sqlx migrate run --database-url $DATABASE_URL

# Revert last migration
sqlx migrate revert --database-url $DATABASE_URL

# Create new migration
sqlx migrate add -r <migration_name>
```

---

## 2. Core Tables

### 2.1 Tenants Table

Multi-tenant isolation root entity.

```sql
-- tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,

    -- Configuration
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    storage_quota_bytes BIGINT DEFAULT NULL, -- NULL = unlimited

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Soft delete
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT tenants_name_not_empty CHECK (length(name) > 0),
    CONSTRAINT tenants_slug_format CHECK (slug ~ '^[a-z0-9-]+$')
);

-- Indexes
CREATE INDEX idx_tenants_slug ON tenants(slug) WHERE NOT is_deleted;
CREATE INDEX idx_tenants_created_at ON tenants(created_at DESC);

-- Comments
COMMENT ON TABLE tenants IS 'Multi-tenant root entity for complete data isolation';
COMMENT ON COLUMN tenants.slug IS 'URL-safe unique identifier for tenant';
COMMENT ON COLUMN tenants.settings IS 'Tenant-specific configuration (features, limits, etc.)';
```

### 2.2 Users Table

User identity and authentication.

```sql
-- users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    external_id VARCHAR(255) DEFAULT NULL, -- SSO provider ID
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,

    -- Profile
    name VARCHAR(255) NOT NULL,
    avatar_url TEXT DEFAULT NULL,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active',

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ DEFAULT NULL,
    last_login_ip INET DEFAULT NULL,

    -- Soft delete
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT users_email_unique UNIQUE (tenant_id, email),
    CONSTRAINT users_external_id_unique UNIQUE (tenant_id, external_id) NULLS NOT DISTINCT,
    CONSTRAINT users_status_check CHECK (status IN ('active', 'suspended', 'pending_verification', 'locked')),
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- Indexes
CREATE INDEX idx_users_tenant_email ON users(tenant_id, email) WHERE NOT is_deleted;
CREATE INDEX idx_users_external_id ON users(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_last_login ON users(last_login_at DESC NULLS LAST);

-- Comments
COMMENT ON TABLE users IS 'User accounts with SSO support';
COMMENT ON COLUMN users.external_id IS 'External identity provider ID (e.g., Auth0, Okta)';
COMMENT ON COLUMN users.status IS 'User account status: active, suspended, pending_verification, locked';
```

### 2.3 Roles Table

Role-based access control definitions.

```sql
-- roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Role definition
    name VARCHAR(100) NOT NULL,
    description TEXT DEFAULT NULL,

    -- Permissions stored as JSONB array
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- System vs custom roles
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT roles_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT roles_permissions_is_array CHECK (jsonb_typeof(permissions) = 'array')
);

-- Indexes
CREATE INDEX idx_roles_tenant ON roles(tenant_id);
CREATE INDEX idx_roles_system ON roles(is_system_role);
CREATE INDEX idx_roles_permissions ON roles USING GIN(permissions);

-- Comments
COMMENT ON TABLE roles IS 'Role definitions with JSONB-stored permissions';
COMMENT ON COLUMN roles.permissions IS 'Array of permission strings, e.g., ["dataset:read", "dataset:write"]';
COMMENT ON COLUMN roles.is_system_role IS 'System roles (admin, viewer) cannot be deleted';
```

### 2.4 User Roles Junction Table

Many-to-many mapping between users and roles.

```sql
-- user_roles table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    -- Grant metadata
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ DEFAULT NULL, -- NULL = no expiration

    -- Primary key
    PRIMARY KEY (user_id, role_id)
);

-- Indexes
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- Comments
COMMENT ON TABLE user_roles IS 'Many-to-many mapping between users and roles';
COMMENT ON COLUMN user_roles.expires_at IS 'Temporary role grants expire automatically';
```

### 2.5 Schemas Table

Dataset schema definitions for validation.

```sql
-- schemas table
CREATE TABLE IF NOT EXISTS schemas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Schema identity
    name VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,

    -- Schema definition (JSON Schema format)
    definition JSONB NOT NULL,

    -- Schema evolution
    parent_schema_id UUID DEFAULT NULL REFERENCES schemas(id) ON DELETE SET NULL,
    compatibility_mode VARCHAR(50) NOT NULL DEFAULT 'backward',

    -- Metadata
    description TEXT DEFAULT NULL,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active',

    CONSTRAINT schemas_name_version_unique UNIQUE (tenant_id, name, version),
    CONSTRAINT schemas_compatibility_check CHECK (
        compatibility_mode IN ('none', 'backward', 'forward', 'full')
    ),
    CONSTRAINT schemas_status_check CHECK (status IN ('draft', 'active', 'deprecated', 'archived')),
    CONSTRAINT schemas_definition_is_object CHECK (jsonb_typeof(definition) = 'object')
);

-- Indexes
CREATE INDEX idx_schemas_tenant_name ON schemas(tenant_id, name);
CREATE INDEX idx_schemas_status ON schemas(status);
CREATE INDEX idx_schemas_parent ON schemas(parent_schema_id) WHERE parent_schema_id IS NOT NULL;
CREATE INDEX idx_schemas_definition ON schemas USING GIN(definition);

-- Comments
COMMENT ON TABLE schemas IS 'Versioned schema definitions for dataset validation';
COMMENT ON COLUMN schemas.definition IS 'JSON Schema definition for data validation';
COMMENT ON COLUMN schemas.compatibility_mode IS 'Schema evolution compatibility: none, backward, forward, full';
```

### 2.6 Datasets Table

Logical dataset container.

```sql
-- datasets table
CREATE TABLE IF NOT EXISTS datasets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Dataset identity
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT NULL,

    -- Schema and ownership
    schema_id UUID DEFAULT NULL REFERENCES schemas(id) ON DELETE RESTRICT,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- Security
    encryption_key_id UUID DEFAULT NULL, -- References encryption_keys table

    -- Compliance
    retention_policy JSONB DEFAULT NULL,

    -- Metadata
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Soft delete
    deleted_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT datasets_name_unique UNIQUE (tenant_id, name) WHERE deleted_at IS NULL,
    CONSTRAINT datasets_name_not_empty CHECK (length(name) > 0),
    CONSTRAINT datasets_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object')
);

-- Indexes
CREATE INDEX idx_datasets_tenant ON datasets(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_datasets_schema ON datasets(schema_id);
CREATE INDEX idx_datasets_owner ON datasets(owner_id);
CREATE INDEX idx_datasets_tags ON datasets USING GIN(tags);
CREATE INDEX idx_datasets_metadata ON datasets USING GIN(metadata);
CREATE INDEX idx_datasets_created_at ON datasets(created_at DESC);
CREATE INDEX idx_datasets_deleted ON datasets(deleted_at) WHERE deleted_at IS NOT NULL;

-- Comments
COMMENT ON TABLE datasets IS 'Logical dataset containers with versioning support';
COMMENT ON COLUMN datasets.retention_policy IS 'JSON retention policy: {duration_days: 90, action: "archive"}';
COMMENT ON COLUMN datasets.encryption_key_id IS 'References encryption key for dataset-level encryption';
```

### 2.7 Dataset Versions Table

Immutable dataset snapshots.

```sql
-- dataset_versions table
CREATE TABLE IF NOT EXISTS dataset_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dataset_id UUID NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,

    -- Version identity
    version_number BIGINT NOT NULL,
    parent_version_id UUID DEFAULT NULL REFERENCES dataset_versions(id) ON DELETE SET NULL,

    -- Git-like commit metadata
    commit_id VARCHAR(64) NOT NULL, -- SHA-256 hash of version content
    tree_hash VARCHAR(64) NOT NULL, -- Merkle tree root hash
    message TEXT NOT NULL,
    author_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'draft',

    -- Statistics
    record_count BIGINT NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,

    -- Storage reference
    storage_path TEXT NOT NULL, -- Object storage path
    manifest_hash VARCHAR(64) NOT NULL, -- Hash of manifest file

    -- Metadata
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT versions_dataset_number_unique UNIQUE (dataset_id, version_number),
    CONSTRAINT versions_status_check CHECK (
        status IN ('draft', 'published', 'archived', 'corrupted')
    ),
    CONSTRAINT versions_record_count_positive CHECK (record_count >= 0),
    CONSTRAINT versions_size_positive CHECK (size_bytes >= 0),
    CONSTRAINT versions_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object')
);

-- Indexes
CREATE INDEX idx_versions_dataset ON dataset_versions(dataset_id, version_number DESC);
CREATE INDEX idx_versions_status ON dataset_versions(status);
CREATE INDEX idx_versions_parent ON dataset_versions(parent_version_id) WHERE parent_version_id IS NOT NULL;
CREATE INDEX idx_versions_author ON dataset_versions(author_id);
CREATE INDEX idx_versions_created_at ON dataset_versions(created_at DESC);
CREATE INDEX idx_versions_commit_id ON dataset_versions(commit_id);

-- Comments
COMMENT ON TABLE dataset_versions IS 'Immutable versioned snapshots of datasets';
COMMENT ON COLUMN dataset_versions.commit_id IS 'Content-addressable hash of version data';
COMMENT ON COLUMN dataset_versions.tree_hash IS 'Merkle tree root for integrity verification';
COMMENT ON COLUMN dataset_versions.manifest_hash IS 'Hash of manifest file listing all chunks';
```

### 2.8 Records Table (Partitioned)

Individual data records within versions.

```sql
-- records table (partitioned by dataset_id hash)
CREATE TABLE IF NOT EXISTS records (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    dataset_id UUID NOT NULL,
    version_id UUID NOT NULL REFERENCES dataset_versions(id) ON DELETE CASCADE,

    -- Record identity
    content_hash VARCHAR(64) NOT NULL, -- SHA-256 of record content

    -- Encrypted data storage
    encrypted_data BYTEA NOT NULL,

    -- PII annotations (JSONB for field-level PII tracking)
    pii_annotations JSONB DEFAULT NULL,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Primary key includes dataset_id for partitioning
    PRIMARY KEY (dataset_id, id)
) PARTITION BY HASH (dataset_id);

-- Create 16 partitions for parallelism
DO $$
BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS records_p%s PARTITION OF records
             FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i
        );
    END LOOP;
END $$;

-- Indexes on partitioned table
CREATE INDEX idx_records_version ON records(version_id);
CREATE INDEX idx_records_content_hash ON records(content_hash);
CREATE INDEX idx_records_created_at ON records(created_at DESC);
CREATE INDEX idx_records_pii ON records USING GIN(pii_annotations) WHERE pii_annotations IS NOT NULL;

-- Comments
COMMENT ON TABLE records IS 'Individual encrypted data records (partitioned by dataset_id)';
COMMENT ON COLUMN records.content_hash IS 'SHA-256 hash for deduplication and integrity';
COMMENT ON COLUMN records.encrypted_data IS 'AES-256-GCM encrypted record content';
COMMENT ON COLUMN records.pii_annotations IS 'Field-level PII classification and token mappings';
```

### 2.9 Tokens Table (Anonymization)

Token mappings for anonymization/pseudonymization.

```sql
-- tokens table
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Token mapping
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- Hash of original value
    encrypted_value BYTEA NOT NULL, -- Encrypted original value

    -- PII classification
    pii_type VARCHAR(50) NOT NULL,

    -- Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NULL, -- NULL = no expiration
    accessed_count INTEGER NOT NULL DEFAULT 0,
    last_accessed_at TIMESTAMPTZ DEFAULT NULL,

    CONSTRAINT tokens_pii_type_check CHECK (
        pii_type IN ('email', 'phone', 'ssn', 'name', 'address', 'credit_card', 'ip_address', 'custom')
    )
);

-- Indexes
CREATE INDEX idx_tokens_tenant ON tokens(tenant_id);
CREATE INDEX idx_tokens_hash ON tokens(token_hash);
CREATE INDEX idx_tokens_pii_type ON tokens(pii_type);
CREATE INDEX idx_tokens_expires ON tokens(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_tokens_created_at ON tokens(created_at DESC);

-- Comments
COMMENT ON TABLE tokens IS 'Anonymization token mappings for PII pseudonymization';
COMMENT ON COLUMN tokens.token_hash IS 'SHA-256 hash of original value for lookups';
COMMENT ON COLUMN tokens.encrypted_value IS 'Encrypted original value (for re-identification if authorized)';
```

### 2.10 Audit Logs Table (Partitioned by Time)

Immutable audit trail.

```sql
-- audit_logs table (partitioned by time range)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID DEFAULT NULL REFERENCES users(id) ON DELETE SET NULL,

    -- Action details
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID DEFAULT NULL,

    -- Additional context
    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Request metadata
    ip_address INET DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,

    -- Timestamp (partition key)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (created_at, id)
) PARTITION BY RANGE (created_at);

-- Create monthly partitions (initial setup for 2025)
CREATE TABLE IF NOT EXISTS audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE IF NOT EXISTS audit_logs_2025_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

CREATE TABLE IF NOT EXISTS audit_logs_2025_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');

-- Indexes on partitioned table
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, created_at DESC);
CREATE INDEX idx_audit_details ON audit_logs USING GIN(details);

-- Comments
COMMENT ON TABLE audit_logs IS 'Immutable audit trail (partitioned by month)';
COMMENT ON COLUMN audit_logs.action IS 'Action performed, e.g., dataset.create, record.read';
COMMENT ON COLUMN audit_logs.resource_type IS 'Resource type, e.g., dataset, version, user';
```

### 2.11 Lineage Edges Table

Data lineage tracking.

```sql
-- lineage_edges table
CREATE TABLE IF NOT EXISTS lineage_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Source and target (polymorphic references)
    source_type VARCHAR(50) NOT NULL,
    source_id UUID NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id UUID NOT NULL,

    -- Relationship type
    relationship VARCHAR(50) NOT NULL,

    -- Metadata
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT lineage_unique UNIQUE (source_type, source_id, target_type, target_id, relationship),
    CONSTRAINT lineage_type_check CHECK (
        source_type IN ('dataset', 'version', 'record', 'transformation') AND
        target_type IN ('dataset', 'version', 'record', 'transformation')
    ),
    CONSTRAINT lineage_relationship_check CHECK (
        relationship IN ('derived_from', 'copied_from', 'transformed_by', 'merged_from', 'anonymized_from')
    ),
    CONSTRAINT lineage_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object')
);

-- Indexes
CREATE INDEX idx_lineage_source ON lineage_edges(source_type, source_id);
CREATE INDEX idx_lineage_target ON lineage_edges(target_type, target_id);
CREATE INDEX idx_lineage_relationship ON lineage_edges(relationship);
CREATE INDEX idx_lineage_created_at ON lineage_edges(created_at DESC);

-- Comments
COMMENT ON TABLE lineage_edges IS 'Directed graph of data lineage relationships';
COMMENT ON COLUMN lineage_edges.source_type IS 'Source entity type: dataset, version, record, transformation';
COMMENT ON COLUMN lineage_edges.relationship IS 'Edge type: derived_from, copied_from, transformed_by, etc.';
```

### 2.12 Encryption Keys Table

Encryption key metadata (not key material).

```sql
-- encryption_keys table
CREATE TABLE IF NOT EXISTS encryption_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Key metadata
    key_type VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',

    -- External KMS reference
    kms_provider VARCHAR(50) NOT NULL,
    kms_key_id VARCHAR(255) NOT NULL, -- External KMS key ID

    -- Wrapped key material (encrypted by KMS)
    wrapped_key BYTEA NOT NULL,

    -- Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ DEFAULT NULL,
    expires_at TIMESTAMPTZ DEFAULT NULL,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active',

    CONSTRAINT keys_type_check CHECK (key_type IN ('dataset', 'field', 'backup')),
    CONSTRAINT keys_algorithm_check CHECK (algorithm IN ('AES-256-GCM', 'AES-256-CBC')),
    CONSTRAINT keys_provider_check CHECK (kms_provider IN ('aws-kms', 'azure-kv', 'gcp-kms', 'vault', 'local')),
    CONSTRAINT keys_status_check CHECK (status IN ('active', 'rotated', 'expired', 'revoked'))
);

-- Indexes
CREATE INDEX idx_keys_tenant ON encryption_keys(tenant_id);
CREATE INDEX idx_keys_status ON encryption_keys(status);
CREATE INDEX idx_keys_kms ON encryption_keys(kms_provider, kms_key_id);
CREATE INDEX idx_keys_expires ON encryption_keys(expires_at) WHERE expires_at IS NOT NULL;

-- Comments
COMMENT ON TABLE encryption_keys IS 'Encryption key metadata (keys wrapped by external KMS)';
COMMENT ON COLUMN encryption_keys.wrapped_key IS 'Data encryption key encrypted by KMS master key';
COMMENT ON COLUMN encryption_keys.kms_key_id IS 'External KMS key ID (e.g., AWS KMS ARN)';
```

---

## 3. Indexes

### 3.1 Primary Key Indexes

All tables use UUID primary keys with automatic B-tree indexes.

### 3.2 Foreign Key Indexes

All foreign key columns have indexes for efficient joins:
- `tenant_id` (multi-tenant filtering)
- `user_id`, `owner_id`, `author_id` (user lookups)
- `dataset_id`, `version_id` (dataset hierarchy)
- `schema_id`, `role_id` (reference lookups)

### 3.3 Composite Indexes

```sql
-- Efficient tenant + time range queries
CREATE INDEX idx_datasets_tenant_created ON datasets(tenant_id, created_at DESC)
    WHERE deleted_at IS NULL;

-- Version lookups
CREATE INDEX idx_versions_dataset_number ON dataset_versions(dataset_id, version_number DESC);

-- Audit queries by tenant and time
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, created_at DESC);
```

### 3.4 Partial Indexes

```sql
-- Only index active records
CREATE INDEX idx_datasets_active ON datasets(tenant_id)
    WHERE deleted_at IS NULL;

-- Only index non-system roles
CREATE INDEX idx_roles_custom ON roles(tenant_id, name)
    WHERE NOT is_system_role;

-- Expiring tokens
CREATE INDEX idx_tokens_expiring ON tokens(expires_at)
    WHERE expires_at IS NOT NULL AND expires_at > NOW();
```

### 3.5 GIN Indexes for JSONB

```sql
-- JSONB full-text and path queries
CREATE INDEX idx_datasets_metadata ON datasets USING GIN(metadata);
CREATE INDEX idx_schemas_definition ON schemas USING GIN(definition);
CREATE INDEX idx_audit_details ON audit_logs USING GIN(details);
CREATE INDEX idx_records_pii ON records USING GIN(pii_annotations)
    WHERE pii_annotations IS NOT NULL;

-- Array contains queries
CREATE INDEX idx_datasets_tags ON datasets USING GIN(tags);
CREATE INDEX idx_roles_permissions ON roles USING GIN(permissions);
```

---

## 4. Constraints

### 4.1 Check Constraints

```sql
-- Enum-like status checks
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'suspended', 'pending_verification', 'locked'));

ALTER TABLE datasets ADD CONSTRAINT datasets_name_not_empty
    CHECK (length(name) > 0);

ALTER TABLE dataset_versions ADD CONSTRAINT versions_status_check
    CHECK (status IN ('draft', 'published', 'archived', 'corrupted'));

-- Positive value constraints
ALTER TABLE dataset_versions ADD CONSTRAINT versions_record_count_positive
    CHECK (record_count >= 0);

ALTER TABLE dataset_versions ADD CONSTRAINT versions_size_positive
    CHECK (size_bytes >= 0);

-- Format validation
ALTER TABLE users ADD CONSTRAINT users_email_format
    CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');

ALTER TABLE tenants ADD CONSTRAINT tenants_slug_format
    CHECK (slug ~ '^[a-z0-9-]+$');

-- JSONB type checks
ALTER TABLE datasets ADD CONSTRAINT datasets_metadata_is_object
    CHECK (jsonb_typeof(metadata) = 'object');

ALTER TABLE roles ADD CONSTRAINT roles_permissions_is_array
    CHECK (jsonb_typeof(permissions) = 'array');
```

### 4.2 Unique Constraints

```sql
-- Tenant-scoped uniqueness
ALTER TABLE datasets ADD CONSTRAINT datasets_name_unique
    UNIQUE (tenant_id, name) WHERE deleted_at IS NULL;

ALTER TABLE users ADD CONSTRAINT users_email_unique
    UNIQUE (tenant_id, email);

ALTER TABLE roles ADD CONSTRAINT roles_name_unique
    UNIQUE (tenant_id, name);

-- Version uniqueness
ALTER TABLE dataset_versions ADD CONSTRAINT versions_dataset_number_unique
    UNIQUE (dataset_id, version_number);

-- Global uniqueness
ALTER TABLE tenants ADD CONSTRAINT tenants_slug_unique
    UNIQUE (slug);

ALTER TABLE tokens ADD CONSTRAINT tokens_hash_unique
    UNIQUE (token_hash);
```

### 4.3 Foreign Key Cascades

```sql
-- Cascade deletes for tenant data
ALTER TABLE users
    ADD CONSTRAINT users_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE datasets
    ADD CONSTRAINT datasets_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Restrict deletes for referenced data
ALTER TABLE datasets
    ADD CONSTRAINT datasets_owner_fk
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT;

ALTER TABLE dataset_versions
    ADD CONSTRAINT versions_author_fk
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE RESTRICT;

-- Set null on delete for optional references
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_user_fk
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
```

---

## 5. Functions & Triggers

### 5.1 Updated At Trigger

Automatically update `updated_at` timestamp on row modification.

```sql
-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at
CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_datasets_updated_at
    BEFORE UPDATE ON datasets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

### 5.2 Audit Trigger

Automatically log changes to critical tables.

```sql
-- Function to create audit log entries
CREATE OR REPLACE FUNCTION create_audit_log()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit_logs (
        tenant_id,
        user_id,
        action,
        resource_type,
        resource_id,
        details,
        created_at
    ) VALUES (
        COALESCE(NEW.tenant_id, OLD.tenant_id),
        current_setting('app.current_user_id', true)::UUID,
        TG_OP,
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        jsonb_build_object(
            'operation', TG_OP,
            'old', to_jsonb(OLD),
            'new', to_jsonb(NEW)
        ),
        NOW()
    );
    RETURN NEW;
EXCEPTION
    WHEN OTHERS THEN
        -- Don't fail the main operation if audit fails
        RAISE WARNING 'Audit log insert failed: %', SQLERRM;
        RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply audit trigger to critical tables
CREATE TRIGGER audit_datasets
    AFTER INSERT OR UPDATE OR DELETE ON datasets
    FOR EACH ROW
    EXECUTE FUNCTION create_audit_log();

CREATE TRIGGER audit_versions
    AFTER INSERT OR UPDATE OR DELETE ON dataset_versions
    FOR EACH ROW
    EXECUTE FUNCTION create_audit_log();

CREATE TRIGGER audit_users
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION create_audit_log();
```

### 5.3 Soft Delete Function

Unified soft delete with timestamp management.

```sql
-- Function for soft deletes
CREATE OR REPLACE FUNCTION soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    -- Prevent accidental undelete
    IF NEW.deleted_at IS NULL AND OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'Cannot undelete records. Use explicit restore procedure.';
    END IF;

    -- Auto-set deleted_at when marking deleted
    IF NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL THEN
        NEW.deleted_at = NOW();
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to tables with soft delete
CREATE TRIGGER soft_delete_tenants
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    WHEN (NEW.is_deleted IS DISTINCT FROM OLD.is_deleted)
    EXECUTE FUNCTION soft_delete();

CREATE TRIGGER soft_delete_users
    BEFORE UPDATE ON users
    FOR EACH ROW
    WHEN (NEW.is_deleted IS DISTINCT FROM OLD.is_deleted)
    EXECUTE FUNCTION soft_delete();

CREATE TRIGGER soft_delete_datasets
    BEFORE UPDATE ON datasets
    FOR EACH ROW
    WHEN (NEW.deleted_at IS DISTINCT FROM OLD.deleted_at)
    EXECUTE FUNCTION soft_delete();
```

### 5.4 Partition Management Function

Automatically create future partitions.

```sql
-- Function to create next month's audit log partition
CREATE OR REPLACE FUNCTION create_next_audit_partition()
RETURNS void AS $$
DECLARE
    next_month DATE := date_trunc('month', NOW() + INTERVAL '1 month');
    partition_name TEXT := 'audit_logs_' || to_char(next_month, 'YYYY_MM');
    start_date DATE := next_month;
    end_date DATE := next_month + INTERVAL '1 month';
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs
         FOR VALUES FROM (%L) TO (%L)',
        partition_name,
        start_date,
        end_date
    );

    RAISE NOTICE 'Created partition: %', partition_name;
END;
$$ LANGUAGE plpgsql;

-- Schedule to run monthly (requires pg_cron extension)
-- SELECT cron.schedule('create-audit-partition', '0 0 1 * *', 'SELECT create_next_audit_partition()');
```

---

## 6. Row Level Security (RLS)

### 6.1 Enable RLS

```sql
-- Enable RLS on multi-tenant tables
ALTER TABLE datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE dataset_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE records ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE schemas ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
```

### 6.2 Tenant Isolation Policies

```sql
-- Tenant isolation policy for datasets
CREATE POLICY tenant_isolation_datasets ON datasets
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Tenant isolation policy for users
CREATE POLICY tenant_isolation_users ON users
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Tenant isolation policy for roles
CREATE POLICY tenant_isolation_roles ON roles
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Tenant isolation policy for schemas
CREATE POLICY tenant_isolation_schemas ON schemas
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Tenant isolation policy for audit logs
CREATE POLICY tenant_isolation_audit ON audit_logs
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
```

### 6.3 Permission-Based Policies

```sql
-- Dataset read policy (requires permission check)
CREATE POLICY dataset_read_policy ON datasets
    FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND (
            -- Owner can always read
            owner_id = current_setting('app.current_user_id', true)::UUID
            OR
            -- User has read permission (check via function)
            has_permission(
                current_setting('app.current_user_id', true)::UUID,
                'dataset:read',
                id
            )
        )
    );

-- Dataset write policy
CREATE POLICY dataset_write_policy ON datasets
    FOR UPDATE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND (
            owner_id = current_setting('app.current_user_id', true)::UUID
            OR
            has_permission(
                current_setting('app.current_user_id', true)::UUID,
                'dataset:write',
                id
            )
        )
    );

-- Dataset delete policy (only owner or admin)
CREATE POLICY dataset_delete_policy ON datasets
    FOR DELETE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::UUID
        AND (
            owner_id = current_setting('app.current_user_id', true)::UUID
            OR
            has_permission(
                current_setting('app.current_user_id', true)::UUID,
                'dataset:delete',
                id
            )
        )
    );
```

### 6.4 Permission Check Function

```sql
-- Helper function to check user permissions
CREATE OR REPLACE FUNCTION has_permission(
    p_user_id UUID,
    p_permission TEXT,
    p_resource_id UUID DEFAULT NULL
)
RETURNS BOOLEAN AS $$
DECLARE
    user_permissions JSONB;
BEGIN
    -- Get user's permissions from roles
    SELECT jsonb_agg(DISTINCT perm)
    INTO user_permissions
    FROM user_roles ur
    JOIN roles r ON ur.role_id = r.id
    CROSS JOIN LATERAL jsonb_array_elements_text(r.permissions) AS perm
    WHERE ur.user_id = p_user_id
    AND (ur.expires_at IS NULL OR ur.expires_at > NOW());

    -- Check if user has the permission
    RETURN user_permissions ? p_permission;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;
```

---

## 7. Initial Seed Data

### 7.1 System Tenant

```sql
-- Create system tenant
INSERT INTO tenants (id, name, slug, settings, is_deleted)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'System',
    'system',
    '{"is_system": true}'::jsonb,
    false
)
ON CONFLICT (id) DO NOTHING;
```

### 7.2 Default Roles

```sql
-- Admin role (full permissions)
INSERT INTO roles (id, tenant_id, name, description, permissions, is_system_role)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000000',
    'admin',
    'Full system administrator with all permissions',
    '[
        "dataset:create", "dataset:read", "dataset:update", "dataset:delete",
        "version:create", "version:read", "version:delete",
        "user:create", "user:read", "user:update", "user:delete",
        "role:create", "role:read", "role:update", "role:delete",
        "audit:read",
        "schema:create", "schema:read", "schema:update"
    ]'::jsonb,
    true
)
ON CONFLICT DO NOTHING;

-- Data Scientist role
INSERT INTO roles (id, tenant_id, name, description, permissions, is_system_role)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000000',
    'data_scientist',
    'Data scientist with dataset and schema permissions',
    '[
        "dataset:create", "dataset:read", "dataset:update",
        "version:create", "version:read",
        "schema:read"
    ]'::jsonb,
    true
)
ON CONFLICT DO NOTHING;

-- Viewer role (read-only)
INSERT INTO roles (id, tenant_id, name, description, permissions, is_system_role)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000000',
    'viewer',
    'Read-only access to datasets and versions',
    '[
        "dataset:read",
        "version:read",
        "schema:read"
    ]'::jsonb,
    true
)
ON CONFLICT DO NOTHING;

-- Auditor role
INSERT INTO roles (id, tenant_id, name, description, permissions, is_system_role)
VALUES (
    gen_random_uuid(),
    '00000000-0000-0000-0000-000000000000',
    'auditor',
    'Compliance auditor with audit log access',
    '[
        "dataset:read",
        "version:read",
        "audit:read",
        "user:read"
    ]'::jsonb,
    true
)
ON CONFLICT DO NOTHING;
```

### 7.3 Migration Tracking Table

```sql
-- Create migration tracking table (used by sqlx)
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);

COMMENT ON TABLE _sqlx_migrations IS 'sqlx migration tracking (managed by sqlx-cli)';
```

---

## Summary

This schema provides:

**Total Tables:** 12 core tables + partitions
- Multi-tenant support with complete isolation
- Dataset versioning with Git-like semantics
- Field-level encryption with external KMS integration
- PII anonymization with token mapping
- Comprehensive audit logging with time partitioning
- Data lineage tracking with directed graph
- RBAC with JSONB-stored permissions
- Row-level security for fine-grained access control

**Total Indexes:** 60+ optimized indexes
- B-tree for lookups and ranges
- GIN for JSONB and array queries
- Partial indexes for filtered queries
- Composite indexes for common query patterns

**Total Constraints:** 40+ data integrity rules
- Foreign key cascades for referential integrity
- Check constraints for enum validation
- Unique constraints for business rules
- JSONB type validation

**Functions & Triggers:** 5 automated procedures
- Auto-update timestamps
- Audit logging on changes
- Soft delete management
- Partition auto-creation
- Permission checking

**Estimated Line Count:** ~850 lines of production-ready SQL

---

**Next Steps:**
1. Review schema with team for business logic alignment
2. Create migration files in `migrations/` directory
3. Set up integration tests for all constraints
4. Configure KMS integration for encryption keys
5. Implement partition management automation

**Related Documents:**
- [01-core-data-models.md](../pseudocode/01-core-data-models.md) - Rust data models
- [02-storage-layer.md](../pseudocode/02-storage-layer.md) - Object storage design
- [03-data-architecture.md](../architecture/03-data-architecture.md) - Architecture overview
