-- API keys and programmatic access tables

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Key identification
    name VARCHAR(255) NOT NULL,
    description TEXT,
    prefix VARCHAR(12) NOT NULL, -- e.g., "vk_live_" or "vk_test_"

    -- Key hash (the actual key is never stored)
    key_hash VARCHAR(64) NOT NULL UNIQUE,

    -- Permissions
    permissions TEXT[] NOT NULL, -- Array of permission strings
    scopes TEXT[], -- OAuth-style scopes (optional, for fine-grained control)

    -- Restrictions
    allowed_ips INET[], -- IP allowlist (NULL = all IPs allowed)
    allowed_origins TEXT[], -- CORS origins (for browser usage)
    allowed_datasets UUID[], -- Restrict to specific datasets

    -- Rate limiting
    rate_limit_per_minute INTEGER DEFAULT 60,
    rate_limit_per_hour INTEGER DEFAULT 1000,
    rate_limit_per_day INTEGER DEFAULT 10000,

    -- Status
    status api_key_status NOT NULL DEFAULT 'active',
    status_message TEXT,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_reason TEXT,

    -- Expiration
    expires_at TIMESTAMPTZ,

    -- Usage tracking
    last_used_at TIMESTAMPTZ,
    last_used_ip INET,
    total_requests BIGINT NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT api_keys_name_org_unique UNIQUE (organization_id, name)
);

CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- API key rotation history
CREATE TABLE IF NOT EXISTS api_key_rotations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    api_key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,

    -- Old key (hashed)
    old_key_hash VARCHAR(64) NOT NULL,
    old_prefix VARCHAR(12) NOT NULL,

    -- Rotation info
    rotated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    rotation_reason TEXT,

    -- Grace period
    old_key_valid_until TIMESTAMPTZ NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- API usage log (for analytics and rate limiting)
CREATE TABLE IF NOT EXISTS api_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),

    -- Identity
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,

    -- Request info
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    query_params JSONB,

    -- Response info
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER NOT NULL,
    response_size_bytes BIGINT,

    -- Client info
    ip_address INET,
    user_agent TEXT,
    origin TEXT,

    -- Resource accessed
    resource_type VARCHAR(50), -- 'dataset', 'record', 'pii', etc.
    resource_id UUID,

    -- Error info (if applicable)
    error_code VARCHAR(50),
    error_message TEXT,

    -- Request ID for correlation
    request_id UUID NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rate limit tracking (for sliding window rate limiting)
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),

    -- Identity
    api_key_id UUID REFERENCES api_keys(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    ip_address INET,

    -- Bucket info
    bucket_key VARCHAR(255) NOT NULL, -- Composite key for the rate limit
    bucket_window VARCHAR(20) NOT NULL, -- 'minute', 'hour', 'day'
    bucket_start TIMESTAMPTZ NOT NULL,

    -- Counters
    request_count INTEGER NOT NULL DEFAULT 0,
    last_request_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique per bucket
    CONSTRAINT rate_limit_buckets_unique UNIQUE (bucket_key, bucket_window, bucket_start)
);

-- Service accounts (for system integrations)
CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Credentials
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(64) NOT NULL,

    -- Permissions
    permissions TEXT[] NOT NULL,
    scopes TEXT[],

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,

    -- Usage tracking
    last_used_at TIMESTAMPTZ,
    total_requests BIGINT NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT service_accounts_name_org_unique UNIQUE (organization_id, name)
);

CREATE TRIGGER update_service_accounts_updated_at
    BEFORE UPDATE ON service_accounts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to update API key usage
CREATE OR REPLACE FUNCTION update_api_key_usage()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.api_key_id IS NOT NULL THEN
        UPDATE api_keys
        SET last_used_at = NEW.created_at,
            last_used_ip = NEW.ip_address,
            total_requests = total_requests + 1
        WHERE id = NEW.api_key_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_api_key_usage_trigger
    AFTER INSERT ON api_usage_log
    FOR EACH ROW
    EXECUTE FUNCTION update_api_key_usage();
