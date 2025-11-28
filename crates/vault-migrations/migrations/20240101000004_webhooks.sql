-- Webhooks and event delivery tables

-- Webhook event types
CREATE TABLE IF NOT EXISTS webhook_event_types (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL, -- 'dataset', 'record', 'pii', 'system'
    payload_schema JSONB, -- JSON Schema for event payload
    active BOOLEAN NOT NULL DEFAULT true
);

INSERT INTO webhook_event_types (name, display_name, description, category) VALUES
    ('dataset.created', 'Dataset Created', 'A new dataset was created', 'dataset'),
    ('dataset.updated', 'Dataset Updated', 'A dataset was updated', 'dataset'),
    ('dataset.deleted', 'Dataset Deleted', 'A dataset was deleted', 'dataset'),
    ('dataset.archived', 'Dataset Archived', 'A dataset was archived', 'dataset'),
    ('record.created', 'Record Created', 'A new record was created', 'record'),
    ('record.updated', 'Record Updated', 'A record was updated', 'record'),
    ('record.deleted', 'Record Deleted', 'A record was deleted', 'record'),
    ('record.quarantined', 'Record Quarantined', 'A record was quarantined', 'record'),
    ('record.released', 'Record Released', 'A record was released from quarantine', 'record'),
    ('pii.detected', 'PII Detected', 'PII was detected in a record', 'pii'),
    ('pii.scan_completed', 'PII Scan Completed', 'A PII scan completed', 'pii'),
    ('import.completed', 'Import Completed', 'A bulk import completed', 'system'),
    ('import.failed', 'Import Failed', 'A bulk import failed', 'system'),
    ('export.completed', 'Export Completed', 'A data export completed', 'system'),
    ('export.failed', 'Export Failed', 'A data export failed', 'system')
ON CONFLICT (name) DO NOTHING;

-- Webhooks table
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    -- Configuration
    name VARCHAR(255) NOT NULL,
    description TEXT,
    url TEXT NOT NULL,

    -- Authentication
    secret_hash VARCHAR(64) NOT NULL, -- HMAC secret for signature verification
    secret_prefix VARCHAR(10), -- For identifying the secret version

    -- Custom headers (encrypted)
    custom_headers JSONB DEFAULT '{}',

    -- Events
    events TEXT[] NOT NULL, -- Array of event type names

    -- Filtering
    dataset_filter UUID[], -- Only trigger for specific datasets
    label_filter JSONB, -- Only trigger for records with specific labels

    -- Status
    status webhook_status NOT NULL DEFAULT 'active',
    status_message TEXT,
    suspended_at TIMESTAMPTZ,
    suspended_reason TEXT,

    -- Retry configuration
    max_retries INTEGER NOT NULL DEFAULT 5,
    retry_backoff_seconds INTEGER NOT NULL DEFAULT 60,

    -- Rate limiting
    rate_limit_per_minute INTEGER DEFAULT 60,

    -- Statistics (denormalized)
    total_deliveries BIGINT NOT NULL DEFAULT 0,
    successful_deliveries BIGINT NOT NULL DEFAULT 0,
    failed_deliveries BIGINT NOT NULL DEFAULT 0,
    last_delivery_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_webhooks_updated_at
    BEFORE UPDATE ON webhooks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Webhook secret history (for rotation)
CREATE TABLE IF NOT EXISTS webhook_secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,

    -- Secret (hashed)
    secret_hash VARCHAR(64) NOT NULL,
    secret_prefix VARCHAR(10) NOT NULL,

    -- Validity period
    active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ, -- NULL = doesn't expire until next rotation

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Webhook events (generated events to be delivered)
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),

    -- Event info
    event_type VARCHAR(50) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Source
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Related entities
    dataset_id UUID REFERENCES datasets(id) ON DELETE SET NULL,
    record_id UUID REFERENCES records(id) ON DELETE SET NULL,

    -- Payload
    payload JSONB NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Webhook deliveries (delivery attempts)
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES webhook_events(id) ON DELETE CASCADE,

    -- Delivery status
    status delivery_status NOT NULL DEFAULT 'pending',

    -- Request details
    request_url TEXT NOT NULL,
    request_headers JSONB,
    request_body JSONB,

    -- Response details
    response_status INTEGER,
    response_headers JSONB,
    response_body TEXT, -- Truncated response
    response_time_ms INTEGER,

    -- Error info
    error_message TEXT,
    error_code VARCHAR(50),

    -- Retry info
    attempt_number INTEGER NOT NULL DEFAULT 1,
    next_retry_at TIMESTAMPTZ,
    max_retries INTEGER NOT NULL,

    -- Idempotency
    idempotency_key VARCHAR(64) NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    CONSTRAINT webhook_deliveries_idempotency_unique UNIQUE (webhook_id, idempotency_key)
);

-- Function to update webhook statistics
CREATE OR REPLACE FUNCTION update_webhook_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'delivered' AND (OLD.status IS NULL OR OLD.status != 'delivered') THEN
        UPDATE webhooks
        SET total_deliveries = total_deliveries + 1,
            successful_deliveries = successful_deliveries + 1,
            last_delivery_at = NEW.completed_at,
            last_success_at = NEW.completed_at
        WHERE id = NEW.webhook_id;
    ELSIF NEW.status = 'failed' AND (OLD.status IS NULL OR OLD.status != 'failed') THEN
        UPDATE webhooks
        SET total_deliveries = total_deliveries + 1,
            failed_deliveries = failed_deliveries + 1,
            last_delivery_at = NEW.completed_at,
            last_failure_at = NEW.completed_at
        WHERE id = NEW.webhook_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_webhook_stats_trigger
    AFTER INSERT OR UPDATE ON webhook_deliveries
    FOR EACH ROW
    EXECUTE FUNCTION update_webhook_stats();

-- Webhook delivery queue (for async processing)
CREATE TABLE IF NOT EXISTS webhook_delivery_queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    delivery_id UUID NOT NULL REFERENCES webhook_deliveries(id) ON DELETE CASCADE,

    -- Scheduling
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    priority INTEGER NOT NULL DEFAULT 0, -- Higher = more urgent

    -- Processing
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(100), -- Worker ID

    -- Status
    processed BOOLEAN NOT NULL DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
