-- Seed data for development and testing
-- This migration is idempotent and safe to run multiple times

-- ============================================================================
-- Development organization and admin user
-- ============================================================================

-- Create development organization
INSERT INTO organizations (
    id,
    name,
    slug,
    settings,
    active
) VALUES (
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Development Organization',
    'dev-org',
    '{
        "features": {
            "pii_detection": true,
            "anonymization": true,
            "webhooks": true,
            "api_access": true
        },
        "limits": {
            "max_datasets": 1000,
            "max_records_per_dataset": 1000000,
            "max_file_size_mb": 100,
            "max_api_keys": 100
        },
        "retention": {
            "audit_log_days": 365,
            "data_access_log_days": 90
        }
    }'::jsonb,
    true
) ON CONFLICT (id) DO NOTHING;

-- Create admin user (password: 'admin123' - argon2 hash)
INSERT INTO users (
    id,
    organization_id,
    email,
    username,
    password_hash,
    first_name,
    last_name,
    active,
    email_verified,
    email_verified_at
) VALUES (
    '00000000-0000-0000-0000-000000000002'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'admin@example.com',
    'admin',
    -- Note: This is a placeholder hash. In production, use a proper argon2 hash.
    '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash_placeholder',
    'Admin',
    'User',
    true,
    true,
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Create test user
INSERT INTO users (
    id,
    organization_id,
    email,
    username,
    password_hash,
    first_name,
    last_name,
    active,
    email_verified,
    email_verified_at
) VALUES (
    '00000000-0000-0000-0000-000000000003'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'test@example.com',
    'testuser',
    '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash_placeholder',
    'Test',
    'User',
    true,
    true,
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id)
SELECT
    '00000000-0000-0000-0000-000000000002'::uuid,
    r.id
FROM roles r
WHERE r.name = 'admin' AND r.builtin = true
ON CONFLICT DO NOTHING;

-- Assign viewer role to test user
INSERT INTO user_roles (user_id, role_id)
SELECT
    '00000000-0000-0000-0000-000000000003'::uuid,
    r.id
FROM roles r
WHERE r.name = 'viewer' AND r.builtin = true
ON CONFLICT DO NOTHING;

-- ============================================================================
-- Sample datasets
-- ============================================================================

-- Create sample dataset
INSERT INTO datasets (
    id,
    organization_id,
    owner_id,
    name,
    description,
    format,
    status,
    labels,
    settings
) VALUES (
    '00000000-0000-0000-0000-000000000010'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    'Sample Customer Data',
    'Sample dataset for testing PII detection and anonymization',
    'json',
    'active',
    '["sample", "testing", "customers"]'::jsonb,
    '{
        "pii_detection": {
            "enabled": true,
            "auto_anonymize": false,
            "min_confidence": 0.8
        },
        "encryption": {
            "at_rest": true,
            "key_rotation_days": 90
        }
    }'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- Create sample conversation dataset
INSERT INTO datasets (
    id,
    organization_id,
    owner_id,
    name,
    description,
    format,
    status,
    labels,
    settings
) VALUES (
    '00000000-0000-0000-0000-000000000011'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    'LLM Conversation Logs',
    'Sample dataset containing LLM conversation transcripts',
    'jsonl',
    'active',
    '["llm", "conversations", "training"]'::jsonb,
    '{
        "pii_detection": {
            "enabled": true,
            "auto_anonymize": true,
            "min_confidence": 0.85
        }
    }'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- Sample API key for development
-- ============================================================================

-- Create development API key
-- Key: vk_dev_sample_key_for_development_testing (this is just for display - the hash is what matters)
INSERT INTO api_keys (
    id,
    organization_id,
    user_id,
    name,
    description,
    prefix,
    key_hash,
    permissions,
    scopes,
    rate_limit_per_minute,
    rate_limit_per_hour,
    rate_limit_per_day,
    status
) VALUES (
    '00000000-0000-0000-0000-000000000020'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    'Development API Key',
    'API key for local development and testing',
    'vk_dev_',
    -- SHA256 hash of 'development_secret_key'
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    ARRAY['read', 'write', 'delete', 'admin'],
    ARRAY['datasets:read', 'datasets:write', 'records:read', 'records:write', 'pii:scan', 'pii:anonymize'],
    1000,
    10000,
    100000,
    'active'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- Sample anonymization rules
-- ============================================================================

-- Email anonymization rule
INSERT INTO anonymization_rules (
    id,
    organization_id,
    name,
    description,
    pii_type_id,
    strategy_id,
    priority,
    conditions,
    active
)
SELECT
    '00000000-0000-0000-0000-000000000030'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Email Masking',
    'Mask email addresses in all records',
    pt.id,
    s.id,
    100,
    '{"apply_to_all_datasets": true}'::jsonb,
    true
FROM pii_types pt, anonymization_strategies s
WHERE pt.name = 'email' AND s.name = 'mask'
ON CONFLICT (id) DO NOTHING;

-- SSN redaction rule
INSERT INTO anonymization_rules (
    id,
    organization_id,
    name,
    description,
    pii_type_id,
    strategy_id,
    priority,
    conditions,
    active
)
SELECT
    '00000000-0000-0000-0000-000000000031'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'SSN Redaction',
    'Fully redact Social Security Numbers',
    pt.id,
    s.id,
    200,
    '{"apply_to_all_datasets": true}'::jsonb,
    true
FROM pii_types pt, anonymization_strategies s
WHERE pt.name = 'ssn' AND s.name = 'redact'
ON CONFLICT (id) DO NOTHING;

-- Credit card redaction rule
INSERT INTO anonymization_rules (
    id,
    organization_id,
    name,
    description,
    pii_type_id,
    strategy_id,
    priority,
    conditions,
    active
)
SELECT
    '00000000-0000-0000-0000-000000000032'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Credit Card Redaction',
    'Fully redact credit card numbers',
    pt.id,
    s.id,
    200,
    '{"apply_to_all_datasets": true}'::jsonb,
    true
FROM pii_types pt, anonymization_strategies s
WHERE pt.name = 'credit_card' AND s.name = 'redact'
ON CONFLICT (id) DO NOTHING;

-- Phone number masking rule
INSERT INTO anonymization_rules (
    id,
    organization_id,
    name,
    description,
    pii_type_id,
    strategy_id,
    priority,
    conditions,
    active
)
SELECT
    '00000000-0000-0000-0000-000000000033'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Phone Number Masking',
    'Partially mask phone numbers',
    pt.id,
    s.id,
    100,
    '{"apply_to_all_datasets": true}'::jsonb,
    true
FROM pii_types pt, anonymization_strategies s
WHERE pt.name = 'phone' AND s.name = 'mask'
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- Sample webhook configuration
-- ============================================================================

-- Create sample webhook for PII detection events
INSERT INTO webhooks (
    id,
    organization_id,
    created_by,
    name,
    description,
    url,
    secret_hash,
    secret_prefix,
    events,
    status,
    max_retries,
    retry_backoff_seconds,
    rate_limit_per_minute
) VALUES (
    '00000000-0000-0000-0000-000000000040'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    'PII Detection Webhook',
    'Notify when PII is detected in records',
    'https://webhook.example.com/pii-detected',
    'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2',
    'whsec_',
    ARRAY['pii.detected', 'pii.scan_completed'],
    'active',
    5,
    60,
    60
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- Default retention policy
-- ============================================================================

-- Create default audit log retention policy
INSERT INTO retention_policies (
    id,
    organization_id,
    name,
    description,
    resource_type,
    conditions,
    retention_days,
    action,
    active
) VALUES (
    '00000000-0000-0000-0000-000000000050'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Audit Log Retention',
    'Retain audit logs for 1 year, then archive',
    'audit_log',
    '{"severity": ["info", "warning", "error"]}'::jsonb,
    365,
    'archive',
    true
) ON CONFLICT (id) DO NOTHING;

-- Create data access log retention policy
INSERT INTO retention_policies (
    id,
    organization_id,
    name,
    description,
    resource_type,
    conditions,
    retention_days,
    action,
    active
) VALUES (
    '00000000-0000-0000-0000-000000000051'::uuid,
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Data Access Log Retention',
    'Retain data access logs for 90 days',
    'data_access_log',
    '{}'::jsonb,
    90,
    'delete',
    true
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- Sample records with PII for testing
-- ============================================================================

-- Note: These records contain simulated PII for testing purposes only.
-- In production, never store real PII in seed data.

INSERT INTO records (
    id,
    dataset_id,
    status,
    pii_status,
    labels,
    content,
    content_hash,
    metadata
) VALUES (
    '00000000-0000-0000-0000-000000000100'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    'active',
    'pending',
    '["sample", "customer"]'::jsonb,
    '{
        "customer_id": "CUST-001",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "phone": "+1-555-123-4567",
        "address": "123 Main Street, Anytown, CA 90210"
    }'::jsonb,
    'hash_sample_record_001',
    '{"source": "sample_data", "imported_at": "2024-01-01T00:00:00Z"}'::jsonb
) ON CONFLICT (id) DO NOTHING;

INSERT INTO records (
    id,
    dataset_id,
    status,
    pii_status,
    labels,
    content,
    content_hash,
    metadata
) VALUES (
    '00000000-0000-0000-0000-000000000101'::uuid,
    '00000000-0000-0000-0000-000000000010'::uuid,
    'active',
    'pending',
    '["sample", "customer"]'::jsonb,
    '{
        "customer_id": "CUST-002",
        "name": "Jane Smith",
        "email": "jane.smith@example.com",
        "phone": "+1-555-987-6543",
        "ssn": "123-45-6789"
    }'::jsonb,
    'hash_sample_record_002',
    '{"source": "sample_data", "imported_at": "2024-01-01T00:00:00Z"}'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- Sample conversation record
INSERT INTO records (
    id,
    dataset_id,
    status,
    pii_status,
    labels,
    content_text,
    content_hash,
    metadata
) VALUES (
    '00000000-0000-0000-0000-000000000102'::uuid,
    '00000000-0000-0000-0000-000000000011'::uuid,
    'active',
    'pending',
    '["conversation", "support"]'::jsonb,
    'User: Hi, I need help with my account. My email is sarah.jones@example.com and my phone number is 555-234-5678.
Assistant: I can help you with that. I see you have an account registered under sarah.jones@example.com. What seems to be the issue?
User: I forgot my password and cant log in.
Assistant: No problem! I will send a password reset link to sarah.jones@example.com. You should receive it within a few minutes.',
    'hash_sample_conversation_001',
    '{"source": "support_chat", "session_id": "SESS-2024-001", "imported_at": "2024-01-01T00:00:00Z"}'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- Additional test scenarios
-- ============================================================================

-- Create a second organization for multi-tenant testing
INSERT INTO organizations (
    id,
    name,
    slug,
    settings,
    active
) VALUES (
    '00000000-0000-0000-0000-000000000002'::uuid,
    'Test Organization',
    'test-org',
    '{
        "features": {
            "pii_detection": true,
            "anonymization": true,
            "webhooks": false,
            "api_access": true
        },
        "limits": {
            "max_datasets": 100,
            "max_records_per_dataset": 100000,
            "max_file_size_mb": 50,
            "max_api_keys": 10
        }
    }'::jsonb,
    true
) ON CONFLICT (id) DO NOTHING;

-- Create user for second organization
INSERT INTO users (
    id,
    organization_id,
    email,
    username,
    password_hash,
    first_name,
    last_name,
    active,
    email_verified,
    email_verified_at
) VALUES (
    '00000000-0000-0000-0000-000000000004'::uuid,
    '00000000-0000-0000-0000-000000000002'::uuid,
    'user@testorg.com',
    'testorguser',
    '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash_placeholder',
    'Test',
    'OrgUser',
    true,
    true,
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Assign admin role to test org user
INSERT INTO user_roles (user_id, role_id)
SELECT
    '00000000-0000-0000-0000-000000000004'::uuid,
    r.id
FROM roles r
WHERE r.name = 'admin' AND r.builtin = true
ON CONFLICT DO NOTHING;