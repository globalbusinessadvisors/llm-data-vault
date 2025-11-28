-- PII detection and anonymization tables

-- PII types lookup table
CREATE TABLE IF NOT EXISTS pii_types (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL, -- 'personal', 'financial', 'health', 'government', 'technical'
    severity VARCHAR(20) NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    regex_patterns TEXT[], -- Array of regex patterns
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default PII types
INSERT INTO pii_types (name, display_name, description, category, severity, regex_patterns) VALUES
    ('email', 'Email Address', 'Email addresses', 'personal', 'medium',
     ARRAY['[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}']),
    ('phone', 'Phone Number', 'Phone numbers in various formats', 'personal', 'medium',
     ARRAY['(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', '\+\d{1,3}[-.\s]?\d{4,14}']),
    ('ssn', 'Social Security Number', 'US Social Security Numbers', 'government', 'critical',
     ARRAY['\d{3}-\d{2}-\d{4}', '\d{9}']),
    ('credit_card', 'Credit Card Number', 'Credit card numbers', 'financial', 'critical',
     ARRAY['\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}', '\d{15,16}']),
    ('person_name', 'Person Name', 'Person names', 'personal', 'medium', ARRAY[]::TEXT[]),
    ('address', 'Physical Address', 'Street addresses', 'personal', 'medium', ARRAY[]::TEXT[]),
    ('date_of_birth', 'Date of Birth', 'Dates of birth', 'personal', 'high', ARRAY[]::TEXT[]),
    ('ip_address', 'IP Address', 'IPv4 and IPv6 addresses', 'technical', 'low',
     ARRAY['\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}']),
    ('passport', 'Passport Number', 'Passport numbers', 'government', 'critical', ARRAY[]::TEXT[]),
    ('drivers_license', 'Drivers License', 'Drivers license numbers', 'government', 'high', ARRAY[]::TEXT[]),
    ('bank_account', 'Bank Account Number', 'Bank account numbers', 'financial', 'critical', ARRAY[]::TEXT[]),
    ('medical_record_number', 'Medical Record Number', 'Healthcare identifiers', 'health', 'critical', ARRAY[]::TEXT[]),
    ('national_id', 'National ID', 'National identification numbers', 'government', 'critical', ARRAY[]::TEXT[]),
    ('tax_id', 'Tax ID', 'Tax identification numbers', 'financial', 'critical', ARRAY[]::TEXT[]),
    ('vin', 'Vehicle Identification Number', 'VIN numbers', 'personal', 'low',
     ARRAY['[A-HJ-NPR-Z0-9]{17}']),
    ('license_plate', 'License Plate', 'Vehicle license plates', 'personal', 'low', ARRAY[]::TEXT[]),
    ('username', 'Username', 'Account usernames', 'technical', 'low', ARRAY[]::TEXT[]),
    ('password', 'Password', 'Passwords and credentials', 'technical', 'critical', ARRAY[]::TEXT[]),
    ('api_key', 'API Key', 'API keys and secrets', 'technical', 'critical',
     ARRAY['(api[_-]?key|secret|token)["\s:=]+[a-zA-Z0-9_-]{20,}'])
ON CONFLICT (name) DO NOTHING;

-- PII scan results table
CREATE TABLE IF NOT EXISTS pii_scan_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    record_id UUID NOT NULL REFERENCES records(id) ON DELETE CASCADE,

    -- Scan metadata
    scan_started_at TIMESTAMPTZ NOT NULL,
    scan_completed_at TIMESTAMPTZ,
    scan_duration_ms INTEGER,

    -- Results
    status pii_scan_status NOT NULL DEFAULT 'pending',
    entity_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,

    -- Configuration used
    min_confidence DECIMAL(3,2) NOT NULL DEFAULT 0.80,
    pii_types_scanned TEXT[],

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PII entities table (individual detections)
CREATE TABLE IF NOT EXISTS pii_entities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    scan_result_id UUID NOT NULL REFERENCES pii_scan_results(id) ON DELETE CASCADE,
    record_id UUID NOT NULL REFERENCES records(id) ON DELETE CASCADE,

    -- Entity details
    pii_type_id INTEGER NOT NULL REFERENCES pii_types(id),
    start_position INTEGER NOT NULL,
    end_position INTEGER NOT NULL,

    -- Detected text (may be stored hashed for sensitive data)
    text_value TEXT, -- Original value (if allowed)
    text_hash VARCHAR(64), -- Hash of the value
    text_length INTEGER NOT NULL,

    -- Confidence and metadata
    confidence DECIMAL(3,2) NOT NULL,
    field_path TEXT, -- JSON path where found
    context TEXT, -- Surrounding text context

    -- Anonymization info
    anonymized BOOLEAN NOT NULL DEFAULT false,
    anonymized_at TIMESTAMPTZ,
    anonymization_strategy VARCHAR(50),
    replacement_value TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Anonymization strategies table
CREATE TABLE IF NOT EXISTS anonymization_strategies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT true
);

INSERT INTO anonymization_strategies (name, display_name, description) VALUES
    ('redact', 'Redact', 'Replace with placeholder like [EMAIL]'),
    ('mask', 'Mask', 'Partially mask value like j***@***.com'),
    ('replace', 'Replace', 'Replace with realistic fake data'),
    ('pseudonymize', 'Pseudonymize', 'Replace with consistent hash-based pseudonym'),
    ('generalize', 'Generalize', 'Generalize value like "New York" -> "US City"'),
    ('encrypt', 'Encrypt', 'Encrypt the value'),
    ('remove', 'Remove', 'Remove the value entirely')
ON CONFLICT (name) DO NOTHING;

-- Anonymization rules (per-organization)
CREATE TABLE IF NOT EXISTS anonymization_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Rule configuration
    pii_type_id INTEGER REFERENCES pii_types(id),
    strategy_id INTEGER NOT NULL REFERENCES anonymization_strategies(id),

    -- Priority (higher = applied first)
    priority INTEGER NOT NULL DEFAULT 0,

    -- Conditions (JSON)
    conditions JSONB NOT NULL DEFAULT '{}',

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT anonymization_rules_name_org_unique UNIQUE (organization_id, name)
);

CREATE TRIGGER update_anonymization_rules_updated_at
    BEFORE UPDATE ON anonymization_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Anonymized records table (stores anonymized versions)
CREATE TABLE IF NOT EXISTS anonymized_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    original_record_id UUID NOT NULL REFERENCES records(id) ON DELETE CASCADE,

    -- Anonymized content
    content JSONB,
    content_text TEXT,
    content_hash VARCHAR(64) NOT NULL,

    -- Anonymization metadata
    entities_anonymized INTEGER NOT NULL DEFAULT 0,
    strategies_used TEXT[],

    -- Who/when
    anonymized_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT anonymized_records_unique UNIQUE (original_record_id)
);

-- PII allowlist (for false positive management)
CREATE TABLE IF NOT EXISTS pii_allowlist (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Pattern to allow
    pii_type_id INTEGER REFERENCES pii_types(id),
    pattern TEXT NOT NULL, -- Exact value or regex pattern
    is_regex BOOLEAN NOT NULL DEFAULT false,

    -- Reason for allowlisting
    reason TEXT NOT NULL,

    -- Who added
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Status
    active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Function to update record PII status after scan
CREATE OR REPLACE FUNCTION update_record_pii_status()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'detected' OR NEW.status = 'clean' THEN
        UPDATE records
        SET pii_status = NEW.status,
            pii_count = NEW.entity_count,
            pii_scanned_at = NEW.scan_completed_at
        WHERE id = NEW.record_id;
    ELSIF NEW.status = 'failed' THEN
        UPDATE records
        SET pii_status = 'failed',
            pii_scanned_at = NEW.scan_completed_at
        WHERE id = NEW.record_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_record_pii_status_trigger
    AFTER UPDATE ON pii_scan_results
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION update_record_pii_status();
