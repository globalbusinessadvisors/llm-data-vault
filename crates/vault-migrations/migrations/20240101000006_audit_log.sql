-- Audit logging tables

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),

    -- Who
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    service_account_id UUID REFERENCES service_accounts(id) ON DELETE SET NULL,

    -- What
    action audit_action NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- 'dataset', 'record', 'user', etc.
    resource_id UUID,

    -- Details
    description TEXT,
    old_value JSONB, -- Previous state (for updates)
    new_value JSONB, -- New state (for creates/updates)
    metadata JSONB NOT NULL DEFAULT '{}',

    -- Request context
    request_id UUID,
    ip_address INET,
    user_agent TEXT,

    -- Result
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log partitioning by month (for performance)
-- Note: In production, you'd create actual partitions
-- This is a comment placeholder for the partitioning strategy
-- CREATE TABLE audit_log_2024_01 PARTITION OF audit_log
--     FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Data access log (for compliance - who accessed what data)
CREATE TABLE IF NOT EXISTS data_access_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),

    -- Who
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,

    -- What was accessed
    dataset_id UUID REFERENCES datasets(id) ON DELETE SET NULL,
    record_ids UUID[], -- Array of accessed records

    -- Access type
    access_type VARCHAR(20) NOT NULL, -- 'read', 'export', 'download'
    record_count INTEGER NOT NULL,
    data_size_bytes BIGINT,

    -- Context
    purpose TEXT, -- Why the data was accessed
    request_id UUID,

    -- Export info (if applicable)
    export_format VARCHAR(20),
    export_location TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compliance reports table
CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Report info
    report_type VARCHAR(50) NOT NULL, -- 'gdpr_dsar', 'data_inventory', 'access_report', etc.
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Parameters
    parameters JSONB NOT NULL DEFAULT '{}',
    date_range_start TIMESTAMPTZ,
    date_range_end TIMESTAMPTZ,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'generating', 'completed', 'failed'
    progress_percent INTEGER DEFAULT 0,
    error_message TEXT,

    -- Output
    output_format VARCHAR(20), -- 'pdf', 'csv', 'json'
    output_location TEXT, -- S3 URI
    output_size_bytes BIGINT,

    -- Who requested
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

-- Data subject requests (GDPR/CCPA)
CREATE TABLE IF NOT EXISTS data_subject_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Request type
    request_type VARCHAR(50) NOT NULL, -- 'access', 'deletion', 'rectification', 'portability', 'restriction'

    -- Subject info (encrypted)
    subject_email VARCHAR(255), -- May be encrypted
    subject_identifier TEXT, -- Other identifier
    verification_token_hash VARCHAR(64),
    verified BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'verified', 'in_progress', 'completed', 'rejected'
    status_message TEXT,

    -- Processing
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    notes TEXT,

    -- Completion
    completed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    completion_notes TEXT,
    response_sent BOOLEAN NOT NULL DEFAULT false,
    response_sent_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    due_at TIMESTAMPTZ, -- Regulatory deadline
    completed_at TIMESTAMPTZ
);

CREATE TRIGGER update_data_subject_requests_updated_at
    BEFORE UPDATE ON data_subject_requests
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- System events log (for operational monitoring)
CREATE TABLE IF NOT EXISTS system_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),

    -- Event info
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info', -- 'debug', 'info', 'warning', 'error', 'critical'

    -- Source
    service VARCHAR(50) NOT NULL,
    instance_id VARCHAR(100),
    hostname VARCHAR(255),

    -- Details
    message TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    stack_trace TEXT,

    -- Correlation
    trace_id VARCHAR(64),
    span_id VARCHAR(64),
    request_id UUID,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Retention policies table
CREATE TABLE IF NOT EXISTS retention_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,

    -- Policy info
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Target
    resource_type VARCHAR(50) NOT NULL, -- 'dataset', 'record', 'audit_log', etc.
    conditions JSONB NOT NULL DEFAULT '{}', -- Filter conditions

    -- Retention rules
    retention_days INTEGER NOT NULL,
    action VARCHAR(20) NOT NULL DEFAULT 'delete', -- 'delete', 'archive', 'anonymize'
    archive_location TEXT, -- For archive action

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT retention_policies_name_org_unique UNIQUE (organization_id, name)
);

CREATE TRIGGER update_retention_policies_updated_at
    BEFORE UPDATE ON retention_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
