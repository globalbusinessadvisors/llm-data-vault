-- Performance indexes for all tables

-- ============================================================================
-- Organizations indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_active ON organizations(active) WHERE active = true;

-- ============================================================================
-- Users indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(organization_id, active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at DESC NULLS LAST);

-- ============================================================================
-- Sessions indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token_hash) WHERE refresh_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(user_id, active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at) WHERE active = true;

-- ============================================================================
-- Datasets indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_datasets_organization_id ON datasets(organization_id);
CREATE INDEX IF NOT EXISTS idx_datasets_owner_id ON datasets(owner_id);
CREATE INDEX IF NOT EXISTS idx_datasets_status ON datasets(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_datasets_name_search ON datasets USING gin(name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_datasets_labels ON datasets USING gin(labels);
CREATE INDEX IF NOT EXISTS idx_datasets_created_at ON datasets(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_datasets_updated_at ON datasets(updated_at DESC);

-- ============================================================================
-- Records indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_records_dataset_id ON records(dataset_id);
CREATE INDEX IF NOT EXISTS idx_records_status ON records(dataset_id, status);
CREATE INDEX IF NOT EXISTS idx_records_pii_status ON records(dataset_id, pii_status);
CREATE INDEX IF NOT EXISTS idx_records_content_hash ON records(content_hash);
CREATE INDEX IF NOT EXISTS idx_records_labels ON records USING gin(labels);
CREATE INDEX IF NOT EXISTS idx_records_created_at ON records(dataset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_records_updated_at ON records(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_records_sequence ON records(dataset_id, sequence_number) WHERE sequence_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_records_quarantined ON records(dataset_id, quarantined_at) WHERE quarantined_at IS NOT NULL;

-- Partial indexes for common queries
CREATE INDEX IF NOT EXISTS idx_records_active ON records(dataset_id, created_at DESC) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_records_with_pii ON records(dataset_id, pii_scanned_at DESC) WHERE pii_status = 'detected';
CREATE INDEX IF NOT EXISTS idx_records_pending_scan ON records(dataset_id, created_at) WHERE pii_status = 'pending';

-- ============================================================================
-- Content store indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_content_store_hash ON content_store(content_hash);
CREATE INDEX IF NOT EXISTS idx_content_store_accessed ON content_store(last_accessed_at);

-- ============================================================================
-- PII scan results indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_pii_scan_results_record ON pii_scan_results(record_id);
CREATE INDEX IF NOT EXISTS idx_pii_scan_results_status ON pii_scan_results(status, scan_started_at DESC);

-- ============================================================================
-- PII entities indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_pii_entities_scan ON pii_entities(scan_result_id);
CREATE INDEX IF NOT EXISTS idx_pii_entities_record ON pii_entities(record_id);
CREATE INDEX IF NOT EXISTS idx_pii_entities_type ON pii_entities(pii_type_id);
CREATE INDEX IF NOT EXISTS idx_pii_entities_not_anonymized ON pii_entities(record_id) WHERE anonymized = false;

-- ============================================================================
-- Anonymized records indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_anonymized_records_original ON anonymized_records(original_record_id);

-- ============================================================================
-- Webhooks indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_webhooks_organization ON webhooks(organization_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_status ON webhooks(organization_id, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_webhooks_events ON webhooks USING gin(events);

-- ============================================================================
-- Webhook events indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_webhook_events_organization ON webhook_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_type ON webhook_events(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_events_dataset ON webhook_events(dataset_id) WHERE dataset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at DESC);

-- ============================================================================
-- Webhook deliveries indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event ON webhook_deliveries(event_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status, next_retry_at) WHERE status IN ('pending', 'retrying');
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON webhook_deliveries(created_at DESC);

-- ============================================================================
-- Webhook delivery queue indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_webhook_queue_scheduled ON webhook_delivery_queue(scheduled_at, priority DESC) WHERE processed = false AND locked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_queue_locked ON webhook_delivery_queue(locked_by, locked_at) WHERE locked_at IS NOT NULL;

-- ============================================================================
-- API keys indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_api_keys_organization ON api_keys(organization_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(organization_id, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL AND status = 'active';

-- ============================================================================
-- API usage log indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_api_usage_api_key ON api_usage_log(api_key_id, created_at DESC) WHERE api_key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_api_usage_user ON api_usage_log(user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_api_usage_organization ON api_usage_log(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_usage_path ON api_usage_log(path, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_usage_request_id ON api_usage_log(request_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_created ON api_usage_log(created_at DESC);

-- ============================================================================
-- Rate limit buckets indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_rate_limit_api_key ON rate_limit_buckets(api_key_id, bucket_window, bucket_start DESC) WHERE api_key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rate_limit_ip ON rate_limit_buckets(ip_address, bucket_window, bucket_start DESC) WHERE ip_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rate_limit_cleanup ON rate_limit_buckets(bucket_start);

-- ============================================================================
-- Audit log indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_audit_log_organization ON audit_log(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_request ON audit_log(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC);

-- ============================================================================
-- Data access log indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_data_access_organization ON data_access_log(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_data_access_user ON data_access_log(user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_data_access_dataset ON data_access_log(dataset_id, created_at DESC) WHERE dataset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_data_access_type ON data_access_log(access_type, created_at DESC);

-- ============================================================================
-- System events indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_events_severity ON system_events(severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_events_service ON system_events(service, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_events_trace ON system_events(trace_id) WHERE trace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_system_events_created ON system_events(created_at DESC);

-- ============================================================================
-- Roles and user_roles indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_roles_organization ON roles(organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_roles_builtin ON roles(builtin) WHERE builtin = true;
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

-- ============================================================================
-- OAuth connections indexes
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_oauth_user ON oauth_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_connections(provider, provider_user_id);
