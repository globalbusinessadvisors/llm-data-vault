//! Tenant types for multi-tenancy support.

use crate::TenantId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A tenant represents an isolated customer/organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique tenant identifier.
    pub id: TenantId,

    /// Tenant name.
    pub name: String,

    /// Tenant slug (URL-friendly identifier).
    pub slug: String,

    /// Description.
    pub description: Option<String>,

    /// Tenant status.
    pub status: TenantStatus,

    /// Subscription plan.
    pub plan: TenantPlan,

    /// Resource quotas.
    pub quotas: TenantQuotas,

    /// Current resource usage.
    pub usage: TenantUsage,

    /// Custom settings.
    pub settings: TenantSettings,

    /// Custom metadata.
    pub metadata: HashMap<String, serde_json::Value>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    /// Creates a new tenant builder.
    #[must_use]
    pub fn builder() -> TenantBuilder {
        TenantBuilder::default()
    }

    /// Returns true if the tenant is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, TenantStatus::Active)
    }

    /// Checks if the tenant has exceeded any quotas.
    #[must_use]
    pub fn is_over_quota(&self) -> bool {
        self.usage.datasets >= self.quotas.max_datasets
            || self.usage.storage_bytes >= self.quotas.max_storage_bytes
            || self.usage.api_calls_month >= self.quotas.max_api_calls_month
    }
}

/// Builder for tenants.
#[derive(Debug, Default)]
pub struct TenantBuilder {
    name: Option<String>,
    slug: Option<String>,
    description: Option<String>,
    plan: Option<TenantPlan>,
    metadata: HashMap<String, serde_json::Value>,
}

impl TenantBuilder {
    /// Sets the name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the slug.
    #[must_use]
    pub fn slug(mut self, slug: impl Into<String>) -> Self {
        self.slug = Some(slug.into());
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets the plan.
    #[must_use]
    pub fn plan(mut self, plan: TenantPlan) -> Self {
        self.plan = Some(plan);
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Builds the tenant.
    #[must_use]
    pub fn build(self) -> Tenant {
        let now = Utc::now();
        let plan = self.plan.unwrap_or_default();
        let quotas = plan.default_quotas();

        Tenant {
            id: TenantId::new(),
            name: self.name.expect("name is required"),
            slug: self.slug.expect("slug is required"),
            description: self.description,
            status: TenantStatus::Active,
            plan,
            quotas,
            usage: TenantUsage::default(),
            settings: TenantSettings::default(),
            metadata: self.metadata,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Tenant status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    /// Tenant is active.
    Active,
    /// Tenant is suspended (overdue payment, policy violation).
    Suspended,
    /// Tenant is being deleted.
    Deleting,
    /// Tenant trial period.
    Trial,
}

impl Default for TenantStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Subscription plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantPlan {
    /// Free tier.
    Free,
    /// Starter plan.
    Starter,
    /// Professional plan.
    Professional,
    /// Enterprise plan.
    Enterprise,
    /// Custom plan.
    Custom,
}

impl Default for TenantPlan {
    fn default() -> Self {
        Self::Free
    }
}

impl TenantPlan {
    /// Returns the default quotas for this plan.
    #[must_use]
    pub const fn default_quotas(&self) -> TenantQuotas {
        match self {
            Self::Free => TenantQuotas {
                max_datasets: 5,
                max_records_per_dataset: 10_000,
                max_storage_bytes: 1_073_741_824, // 1 GB
                max_api_calls_month: 10_000,
                max_users: 3,
                max_concurrent_connections: 5,
            },
            Self::Starter => TenantQuotas {
                max_datasets: 25,
                max_records_per_dataset: 100_000,
                max_storage_bytes: 10_737_418_240, // 10 GB
                max_api_calls_month: 100_000,
                max_users: 10,
                max_concurrent_connections: 20,
            },
            Self::Professional => TenantQuotas {
                max_datasets: 100,
                max_records_per_dataset: 1_000_000,
                max_storage_bytes: 107_374_182_400, // 100 GB
                max_api_calls_month: 1_000_000,
                max_users: 50,
                max_concurrent_connections: 100,
            },
            Self::Enterprise | Self::Custom => TenantQuotas {
                max_datasets: u64::MAX,
                max_records_per_dataset: u64::MAX,
                max_storage_bytes: u64::MAX,
                max_api_calls_month: u64::MAX,
                max_users: u64::MAX,
                max_concurrent_connections: u64::MAX,
            },
        }
    }
}

/// Resource quotas for a tenant.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TenantQuotas {
    /// Maximum number of datasets.
    pub max_datasets: u64,
    /// Maximum records per dataset.
    pub max_records_per_dataset: u64,
    /// Maximum total storage in bytes.
    pub max_storage_bytes: u64,
    /// Maximum API calls per month.
    pub max_api_calls_month: u64,
    /// Maximum number of users.
    pub max_users: u64,
    /// Maximum concurrent connections.
    pub max_concurrent_connections: u64,
}

impl Default for TenantQuotas {
    fn default() -> Self {
        TenantPlan::Free.default_quotas()
    }
}

/// Current resource usage for a tenant.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TenantUsage {
    /// Number of datasets.
    pub datasets: u64,
    /// Total storage used in bytes.
    pub storage_bytes: u64,
    /// API calls this month.
    pub api_calls_month: u64,
    /// Number of users.
    pub users: u64,
    /// Current concurrent connections.
    pub concurrent_connections: u64,
}

/// Tenant settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettings {
    /// Default encryption key ID.
    pub default_encryption_key_id: Option<String>,
    /// Default retention policy days.
    pub default_retention_days: u32,
    /// Whether to auto-anonymize on ingest.
    pub auto_anonymize: bool,
    /// Allowed PII types.
    pub allowed_pii_types: Vec<String>,
    /// Webhook settings.
    pub webhook_settings: WebhookSettings,
    /// Audit settings.
    pub audit_settings: AuditSettings,
}

impl Default for TenantSettings {
    fn default() -> Self {
        Self {
            default_encryption_key_id: None,
            default_retention_days: 365,
            auto_anonymize: false,
            allowed_pii_types: Vec::new(),
            webhook_settings: WebhookSettings::default(),
            audit_settings: AuditSettings::default(),
        }
    }
}

/// Webhook settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSettings {
    /// Whether webhooks are enabled.
    pub enabled: bool,
    /// Maximum number of webhooks.
    pub max_webhooks: u32,
    /// Retry count for failed deliveries.
    pub retry_count: u32,
    /// Timeout in seconds.
    pub timeout_seconds: u32,
}

impl Default for WebhookSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_webhooks: 10,
            retry_count: 3,
            timeout_seconds: 30,
        }
    }
}

/// Audit logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Whether audit logging is enabled.
    pub enabled: bool,
    /// Events to log.
    pub log_events: Vec<String>,
    /// Retention period in days.
    pub retention_days: u32,
    /// Whether to include request/response bodies.
    pub include_bodies: bool,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            log_events: vec![
                "dataset.created".to_string(),
                "dataset.deleted".to_string(),
                "record.created".to_string(),
                "access.denied".to_string(),
            ],
            retention_days: 90,
            include_bodies: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_builder() {
        let tenant = Tenant::builder()
            .name("Test Corp")
            .slug("test-corp")
            .description("A test tenant")
            .plan(TenantPlan::Professional)
            .build();

        assert_eq!(tenant.name, "Test Corp");
        assert!(tenant.is_active());
        assert_eq!(tenant.plan, TenantPlan::Professional);
    }

    #[test]
    fn test_quota_limits() {
        let mut tenant = Tenant::builder()
            .name("Test")
            .slug("test")
            .plan(TenantPlan::Free)
            .build();

        tenant.usage.datasets = 10;
        assert!(tenant.is_over_quota());
    }
}
