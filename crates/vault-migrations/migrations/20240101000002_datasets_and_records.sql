-- Datasets and records tables

-- Datasets table
CREATE TABLE IF NOT EXISTS datasets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,
    slug VARCHAR(100),

    -- Format and schema
    format dataset_format NOT NULL DEFAULT 'jsonl',
    schema JSONB, -- JSON Schema definition for records

    -- Status
    status dataset_status NOT NULL DEFAULT 'pending',
    status_message TEXT,
    status_updated_at TIMESTAMPTZ,

    -- Statistics (denormalized for performance)
    record_count BIGINT NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    pii_record_count BIGINT NOT NULL DEFAULT 0,

    -- Metadata
    labels JSONB NOT NULL DEFAULT '{}',
    annotations JSONB NOT NULL DEFAULT '{}',

    -- Versioning
    version INTEGER NOT NULL DEFAULT 1,

    -- Retention and archival
    retention_days INTEGER, -- NULL = forever
    archived_at TIMESTAMPTZ,
    archive_location TEXT, -- S3 URI for archived data

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT datasets_slug_org_unique UNIQUE (organization_id, slug)
);

CREATE TRIGGER update_datasets_updated_at
    BEFORE UPDATE ON datasets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Dataset versions (for versioning/snapshots)
CREATE TABLE IF NOT EXISTS dataset_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    dataset_id UUID NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,

    version INTEGER NOT NULL,
    description TEXT,

    -- Snapshot of dataset state
    record_count BIGINT NOT NULL,
    size_bytes BIGINT NOT NULL,
    schema JSONB,

    -- Who created this version
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Storage location for this version
    storage_location TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT dataset_versions_unique UNIQUE (dataset_id, version)
);

-- Records table
CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    dataset_id UUID NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,

    -- Content storage
    content_type VARCHAR(100) NOT NULL DEFAULT 'application/json',
    content JSONB, -- For JSON content
    content_text TEXT, -- For text content
    content_ref VARCHAR(255), -- Reference to external storage (S3 URI)

    -- Content hash for deduplication
    content_hash VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,

    -- Status
    status record_status NOT NULL DEFAULT 'pending',
    status_message TEXT,
    status_updated_at TIMESTAMPTZ,

    -- PII status
    pii_status pii_scan_status NOT NULL DEFAULT 'pending',
    pii_count INTEGER NOT NULL DEFAULT 0,
    pii_scanned_at TIMESTAMPTZ,

    -- Metadata
    labels JSONB NOT NULL DEFAULT '{}',
    annotations JSONB NOT NULL DEFAULT '{}',

    -- Sequencing (for ordered datasets)
    sequence_number BIGINT,

    -- Versioning
    version INTEGER NOT NULL DEFAULT 1,

    -- Quarantine info
    quarantined_at TIMESTAMPTZ,
    quarantine_reason TEXT,
    quarantined_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Idempotency
    idempotency_key VARCHAR(255),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT records_idempotency_unique UNIQUE (dataset_id, idempotency_key)
);

CREATE TRIGGER update_records_updated_at
    BEFORE UPDATE ON records
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Record versions (for audit trail)
CREATE TABLE IF NOT EXISTS record_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    record_id UUID NOT NULL REFERENCES records(id) ON DELETE CASCADE,

    version INTEGER NOT NULL,

    -- Snapshot of record state
    content JSONB,
    content_text TEXT,
    content_hash VARCHAR(64) NOT NULL,

    -- Change info
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    change_type VARCHAR(20) NOT NULL, -- 'create', 'update', 'delete'
    change_reason TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT record_versions_unique UNIQUE (record_id, version)
);

-- Content store table (for content-addressable storage)
CREATE TABLE IF NOT EXISTS content_store (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),

    -- Content hash (BLAKE3)
    content_hash VARCHAR(64) NOT NULL UNIQUE,

    -- Content
    content BYTEA, -- For small content stored directly
    content_ref VARCHAR(255), -- S3 URI for large content

    -- Metadata
    content_type VARCHAR(100) NOT NULL,
    size_bytes BIGINT NOT NULL,
    compression VARCHAR(20), -- 'gzip', 'zstd', NULL

    -- Encryption (for encrypted-at-rest)
    encrypted BOOLEAN NOT NULL DEFAULT false,
    key_id VARCHAR(100), -- KMS key ID if encrypted

    -- Reference counting
    ref_count INTEGER NOT NULL DEFAULT 1,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Function to update dataset statistics
CREATE OR REPLACE FUNCTION update_dataset_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE datasets
        SET record_count = record_count + 1,
            size_bytes = size_bytes + NEW.size_bytes,
            pii_record_count = CASE WHEN NEW.pii_status = 'detected' THEN pii_record_count + 1 ELSE pii_record_count END
        WHERE id = NEW.dataset_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE datasets
        SET record_count = GREATEST(record_count - 1, 0),
            size_bytes = GREATEST(size_bytes - OLD.size_bytes, 0),
            pii_record_count = CASE WHEN OLD.pii_status = 'detected' THEN GREATEST(pii_record_count - 1, 0) ELSE pii_record_count END
        WHERE id = OLD.dataset_id;
    ELSIF TG_OP = 'UPDATE' THEN
        -- Handle size change
        IF OLD.size_bytes != NEW.size_bytes THEN
            UPDATE datasets
            SET size_bytes = size_bytes - OLD.size_bytes + NEW.size_bytes
            WHERE id = NEW.dataset_id;
        END IF;

        -- Handle PII status change
        IF OLD.pii_status != NEW.pii_status THEN
            IF OLD.pii_status = 'detected' AND NEW.pii_status != 'detected' THEN
                UPDATE datasets SET pii_record_count = GREATEST(pii_record_count - 1, 0) WHERE id = NEW.dataset_id;
            ELSIF OLD.pii_status != 'detected' AND NEW.pii_status = 'detected' THEN
                UPDATE datasets SET pii_record_count = pii_record_count + 1 WHERE id = NEW.dataset_id;
            END IF;
        END IF;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_dataset_stats_trigger
    AFTER INSERT OR UPDATE OR DELETE ON records
    FOR EACH ROW
    EXECUTE FUNCTION update_dataset_stats();
