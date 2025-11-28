-- Users and authentication tables

-- Organizations table (multi-tenant support)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    settings JSONB NOT NULL DEFAULT '{}',

    -- Quotas and limits
    max_datasets INTEGER DEFAULT 100,
    max_records_per_dataset BIGINT DEFAULT 10000000,
    max_storage_bytes BIGINT DEFAULT 107374182400, -- 100GB default

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,
    suspended_at TIMESTAMPTZ,
    suspended_reason TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Identity
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    email_verified_at TIMESTAMPTZ,

    -- Profile
    display_name VARCHAR(255),
    avatar_url TEXT,
    timezone VARCHAR(50) DEFAULT 'UTC',
    locale VARCHAR(10) DEFAULT 'en',

    -- Authentication
    password_hash VARCHAR(255), -- NULL for SSO-only users
    password_changed_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    mfa_secret VARCHAR(255),
    mfa_backup_codes TEXT[], -- Encrypted backup codes

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,
    locked BOOLEAN NOT NULL DEFAULT false,
    locked_at TIMESTAMPTZ,
    locked_reason TEXT,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at TIMESTAMPTZ,

    -- Activity tracking
    last_login_at TIMESTAMPTZ,
    last_login_ip INET,
    last_activity_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT users_username_org_unique UNIQUE (organization_id, username),
    CONSTRAINT users_email_org_unique UNIQUE (organization_id, email)
);

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,

    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Permissions as JSONB array
    permissions JSONB NOT NULL DEFAULT '[]',

    -- Built-in roles have NULL organization_id
    builtin BOOLEAN NOT NULL DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Allow same name in different orgs, but unique within org
    CONSTRAINT roles_name_org_unique UNIQUE (organization_id, name)
);

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- User-Role assignments
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    -- Who assigned this role
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Optional expiration
    expires_at TIMESTAMPTZ,

    PRIMARY KEY (user_id, role_id)
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Session token (hashed)
    token_hash VARCHAR(64) NOT NULL UNIQUE,

    -- Refresh token (hashed)
    refresh_token_hash VARCHAR(64) UNIQUE,
    refresh_token_expires_at TIMESTAMPTZ,

    -- Session metadata
    ip_address INET,
    user_agent TEXT,
    device_info JSONB,

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Token (hashed)
    token_hash VARCHAR(64) NOT NULL UNIQUE,

    -- Status
    used BOOLEAN NOT NULL DEFAULT false,
    used_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Email verification tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,

    -- Token (hashed)
    token_hash VARCHAR(64) NOT NULL UNIQUE,

    -- Status
    used BOOLEAN NOT NULL DEFAULT false,
    used_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- OAuth connections (for SSO)
CREATE TABLE IF NOT EXISTS oauth_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    provider VARCHAR(50) NOT NULL, -- 'google', 'github', 'okta', etc.
    provider_user_id VARCHAR(255) NOT NULL,

    -- Tokens (encrypted)
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMPTZ,

    -- Profile data from provider
    profile_data JSONB,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT oauth_connections_provider_unique UNIQUE (provider, provider_user_id)
);

CREATE TRIGGER update_oauth_connections_updated_at
    BEFORE UPDATE ON oauth_connections
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default built-in roles
INSERT INTO roles (id, name, description, permissions, builtin, organization_id)
VALUES
    (uuid_generate_v7(), 'admin', 'Full administrative access',
     '["*"]'::JSONB, true, NULL),
    (uuid_generate_v7(), 'editor', 'Can manage datasets and records',
     '["datasets:*", "records:*", "pii:read", "pii:scan"]'::JSONB, true, NULL),
    (uuid_generate_v7(), 'viewer', 'Read-only access',
     '["datasets:read", "records:read"]'::JSONB, true, NULL),
    (uuid_generate_v7(), 'api_user', 'API access only',
     '["datasets:read", "records:read", "records:create", "pii:scan"]'::JSONB, true, NULL)
ON CONFLICT DO NOTHING;
