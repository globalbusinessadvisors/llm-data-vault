# LLM-Data-Vault Pseudocode: Access Control

**Document:** 05-access-control.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines the access control and policy enforcement layer:
- RBAC (Role-Based Access Control)
- ABAC (Attribute-Based Access Control)
- Zero-trust authentication
- Integration with OIDC, LDAP, SAML
- Sub-100ms authorization decisions

---

## 1. Authorization Engine Core

```rust
// src/auth/mod.rs

use async_trait::async_trait;

// ============================================================================
// Authorization Engine Trait
// ============================================================================

#[async_trait]
pub trait AuthorizationEngine: Send + Sync {
    /// Authorize a single request
    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision, AuthzError>;

    /// Batch authorization for efficiency
    async fn authorize_batch(
        &self,
        requests: &[AuthzRequest],
    ) -> Result<Vec<AuthzDecision>, AuthzError>;

    /// Check if principal has permission
    async fn has_permission(
        &self,
        principal: &Principal,
        permission: &Permission,
        resource: &Resource,
    ) -> Result<bool, AuthzError>;
}

// ============================================================================
// Authorization Request/Response Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct AuthzRequest {
    pub request_id: RequestId,
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
    pub context: AuthzContext,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub id: PrincipalId,
    pub principal_type: PrincipalType,
    pub attributes: HashMap<String, AttributeValue>,
}

#[derive(Debug, Clone)]
pub enum PrincipalType {
    User(UserId),
    ServiceAccount(ServiceAccountId),
    Group(GroupId),
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Action {
    pub name: String,
    pub category: ActionCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionCategory {
    Read,
    Write,
    Delete,
    Admin,
    Anonymize,
    Export,
    Share,
}

impl Action {
    pub fn read() -> Self { Self { name: "read".into(), category: ActionCategory::Read } }
    pub fn write() -> Self { Self { name: "write".into(), category: ActionCategory::Write } }
    pub fn delete() -> Self { Self { name: "delete".into(), category: ActionCategory::Delete } }
    pub fn anonymize() -> Self { Self { name: "anonymize".into(), category: ActionCategory::Anonymize } }
    pub fn export() -> Self { Self { name: "export".into(), category: ActionCategory::Export } }
    pub fn share() -> Self { Self { name: "share".into(), category: ActionCategory::Share } }
    pub fn admin() -> Self { Self { name: "admin".into(), category: ActionCategory::Admin } }
}

#[derive(Debug, Clone)]
pub struct Resource {
    pub id: ResourceId,
    pub resource_type: ResourceType,
    pub attributes: HashMap<String, AttributeValue>,
    pub owner: Option<PrincipalId>,
    pub workspace: Option<WorkspaceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Dataset,
    Record,
    Corpus,
    Version,
    Policy,
    AuditLog,
    User,
    Role,
    Workspace,
    Organization,
}

#[derive(Debug, Clone)]
pub struct AuthzContext {
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub request_path: Option<String>,
    pub mfa_verified: bool,
    pub session_age: Option<Duration>,
    pub custom: HashMap<String, AttributeValue>,
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    List(Vec<AttributeValue>),
    Timestamp(DateTime<Utc>),
    IpAddress(IpAddr),
    Null,
}

// ============================================================================
// Authorization Decision
// ============================================================================

#[derive(Debug, Clone)]
pub enum AuthzDecision {
    Allow {
        reason: String,
        matched_policies: Vec<PolicyId>,
        granted_permissions: Vec<Permission>,
    },
    Deny {
        reason: String,
        violations: Vec<PolicyViolation>,
    },
    NotApplicable {
        reason: String,
    },
}

impl AuthzDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthzDecision::Allow { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, AuthzDecision::Deny { .. })
    }
}

#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub policy_id: PolicyId,
    pub rule_id: String,
    pub message: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, Copy)]
pub enum ViolationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("Principal not found: {id}")]
    PrincipalNotFound { id: String },

    #[error("Resource not found: {id}")]
    ResourceNotFound { id: String },

    #[error("Policy evaluation failed: {message}")]
    PolicyEvaluationFailed { message: String },

    #[error("Invalid attribute: {name}")]
    InvalidAttribute { name: String },

    #[error("Authorization timeout")]
    Timeout,

    #[error("Internal error: {message}")]
    Internal { message: String },
}
```

---

## 2. RBAC Implementation

```rust
// src/auth/rbac.rs

pub struct RBACEngine {
    role_store: Arc<dyn RoleStore>,
    permission_cache: Arc<RwLock<PermissionCache>>,
    config: RBACConfig,
    metrics: Arc<AuthzMetrics>,
}

#[derive(Debug, Clone)]
pub struct RBACConfig {
    pub cache_ttl: Duration,
    pub max_role_depth: usize,
    pub enable_inheritance: bool,
}

// ============================================================================
// Role and Permission Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub description: Option<String>,
    pub permissions: HashSet<Permission>,
    pub parent_roles: Vec<RoleId>,
    pub scope: RoleScope,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleScope {
    Global,
    Organization(OrganizationId),
    Workspace(WorkspaceId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission {
    pub resource_type: ResourceType,
    pub action: ActionCategory,
    pub constraints: Vec<PermissionConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PermissionConstraint {
    OwnedOnly,
    WorkspaceOnly,
    TagMatch(String),
    FieldRestriction(Vec<String>),
}

impl Permission {
    pub fn new(resource_type: ResourceType, action: ActionCategory) -> Self {
        Self {
            resource_type,
            action,
            constraints: Vec::new(),
        }
    }

    pub fn with_constraint(mut self, constraint: PermissionConstraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    pub fn matches(&self, action: &Action, resource: &Resource) -> bool {
        if self.resource_type != resource.resource_type {
            return false;
        }
        if self.action != action.category {
            return false;
        }
        true
    }
}

// ============================================================================
// Role Assignment
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub principal_id: PrincipalId,
    pub role_id: RoleId,
    pub scope: AssignmentScope,
    pub granted_by: UserId,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub condition: Option<AssignmentCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssignmentScope {
    Global,
    Organization(OrganizationId),
    Workspace(WorkspaceId),
    Resource(ResourceId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentCondition {
    pub time_range: Option<TimeRange>,
    pub ip_allowlist: Option<Vec<IpAddr>>,
    pub mfa_required: bool,
}

// ============================================================================
// RBAC Engine Implementation
// ============================================================================

impl RBACEngine {
    pub fn new(role_store: Arc<dyn RoleStore>, config: RBACConfig) -> Self {
        Self {
            role_store,
            permission_cache: Arc::new(RwLock::new(PermissionCache::new(config.cache_ttl))),
            config,
            metrics: Arc::new(AuthzMetrics::new("rbac")),
        }
    }

    /// Get all effective permissions for a principal
    pub async fn get_effective_permissions(
        &self,
        principal: &Principal,
    ) -> Result<HashSet<Permission>, AuthzError> {
        // Check cache first
        if let Some(perms) = self.check_cache(&principal.id).await {
            self.metrics.record_cache_hit();
            return Ok(perms);
        }

        self.metrics.record_cache_miss();

        // Get all role assignments
        let assignments = self.role_store
            .get_assignments(&principal.id)
            .await?;

        let mut permissions = HashSet::new();

        for assignment in assignments {
            // Check if assignment is valid
            if !self.is_assignment_valid(&assignment) {
                continue;
            }

            // Get role and its permissions (including inherited)
            let role_perms = self.get_role_permissions(&assignment.role_id, 0).await?;
            permissions.extend(role_perms);
        }

        // Update cache
        self.update_cache(&principal.id, &permissions).await;

        Ok(permissions)
    }

    /// Get permissions for a role (with inheritance)
    async fn get_role_permissions(
        &self,
        role_id: &RoleId,
        depth: usize,
    ) -> Result<HashSet<Permission>, AuthzError> {
        if depth > self.config.max_role_depth {
            return Err(AuthzError::PolicyEvaluationFailed {
                message: "Maximum role inheritance depth exceeded".into(),
            });
        }

        let role = self.role_store.get_role(role_id).await?
            .ok_or(AuthzError::PrincipalNotFound { id: role_id.0.to_string() })?;

        let mut permissions = role.permissions.clone();

        // Add inherited permissions
        if self.config.enable_inheritance {
            for parent_id in &role.parent_roles {
                let parent_perms = Box::pin(self.get_role_permissions(parent_id, depth + 1)).await?;
                permissions.extend(parent_perms);
            }
        }

        Ok(permissions)
    }

    fn is_assignment_valid(&self, assignment: &RoleAssignment) -> bool {
        // Check expiration
        if let Some(expires_at) = assignment.expires_at {
            if Utc::now() > expires_at {
                return false;
            }
        }

        // Additional condition checks would go here
        true
    }

    async fn check_cache(&self, principal_id: &PrincipalId) -> Option<HashSet<Permission>> {
        let cache = self.permission_cache.read().await;
        cache.get(principal_id)
    }

    async fn update_cache(&self, principal_id: &PrincipalId, permissions: &HashSet<Permission>) {
        let mut cache = self.permission_cache.write().await;
        cache.insert(principal_id.clone(), permissions.clone());
    }

    /// Invalidate cache for a principal
    pub async fn invalidate_cache(&self, principal_id: &PrincipalId) {
        let mut cache = self.permission_cache.write().await;
        cache.remove(principal_id);
    }
}

#[async_trait]
impl AuthorizationEngine for RBACEngine {
    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision, AuthzError> {
        let _timer = self.metrics.operation_timer("authorize");

        let permissions = self.get_effective_permissions(&request.principal).await?;

        // Check if any permission matches the request
        for perm in &permissions {
            if perm.matches(&request.action, &request.resource) {
                // Check constraints
                if self.check_constraints(perm, &request).await? {
                    return Ok(AuthzDecision::Allow {
                        reason: format!("Permission {} granted via RBAC", perm.action),
                        matched_policies: vec![],
                        granted_permissions: vec![perm.clone()],
                    });
                }
            }
        }

        Ok(AuthzDecision::Deny {
            reason: "No matching permission found".into(),
            violations: vec![PolicyViolation {
                policy_id: PolicyId::new(),
                rule_id: "rbac_check".into(),
                message: format!(
                    "Principal {} lacks {:?} permission on {:?}",
                    request.principal.id.0,
                    request.action.category,
                    request.resource.resource_type
                ),
                severity: ViolationSeverity::Error,
            }],
        })
    }

    async fn authorize_batch(
        &self,
        requests: &[AuthzRequest],
    ) -> Result<Vec<AuthzDecision>, AuthzError> {
        let mut results = Vec::with_capacity(requests.len());

        // Group by principal for efficiency
        let mut by_principal: HashMap<&PrincipalId, Vec<&AuthzRequest>> = HashMap::new();
        for request in requests {
            by_principal.entry(&request.principal.id).or_default().push(request);
        }

        for (principal_id, principal_requests) in by_principal {
            let principal = &principal_requests[0].principal;
            let permissions = self.get_effective_permissions(principal).await?;

            for request in principal_requests {
                let decision = self.authorize_with_permissions(request, &permissions).await?;
                results.push(decision);
            }
        }

        Ok(results)
    }

    async fn has_permission(
        &self,
        principal: &Principal,
        permission: &Permission,
        _resource: &Resource,
    ) -> Result<bool, AuthzError> {
        let permissions = self.get_effective_permissions(principal).await?;
        Ok(permissions.contains(permission))
    }
}

impl RBACEngine {
    async fn authorize_with_permissions(
        &self,
        request: &AuthzRequest,
        permissions: &HashSet<Permission>,
    ) -> Result<AuthzDecision, AuthzError> {
        for perm in permissions {
            if perm.matches(&request.action, &request.resource) {
                if self.check_constraints(perm, request).await? {
                    return Ok(AuthzDecision::Allow {
                        reason: "Permission granted via RBAC".into(),
                        matched_policies: vec![],
                        granted_permissions: vec![perm.clone()],
                    });
                }
            }
        }

        Ok(AuthzDecision::Deny {
            reason: "No matching permission found".into(),
            violations: vec![],
        })
    }

    async fn check_constraints(
        &self,
        permission: &Permission,
        request: &AuthzRequest,
    ) -> Result<bool, AuthzError> {
        for constraint in &permission.constraints {
            match constraint {
                PermissionConstraint::OwnedOnly => {
                    if request.resource.owner.as_ref() != Some(&request.principal.id) {
                        return Ok(false);
                    }
                }
                PermissionConstraint::WorkspaceOnly => {
                    // Check if resource is in principal's workspace
                    if let Some(ref workspace) = request.resource.workspace {
                        let principal_workspaces = request.principal.attributes
                            .get("workspaces")
                            .and_then(|v| match v {
                                AttributeValue::List(list) => Some(list),
                                _ => None,
                            });

                        if let Some(workspaces) = principal_workspaces {
                            let has_access = workspaces.iter().any(|w| {
                                matches!(w, AttributeValue::String(s) if s == &workspace.0.to_string())
                            });
                            if !has_access {
                                return Ok(false);
                            }
                        }
                    }
                }
                PermissionConstraint::TagMatch(required_tag) => {
                    let has_tag = request.resource.attributes
                        .get("tags")
                        .and_then(|v| match v {
                            AttributeValue::List(tags) => Some(tags),
                            _ => None,
                        })
                        .map(|tags| tags.iter().any(|t| {
                            matches!(t, AttributeValue::String(s) if s == required_tag)
                        }))
                        .unwrap_or(false);

                    if !has_tag {
                        return Ok(false);
                    }
                }
                PermissionConstraint::FieldRestriction(_) => {
                    // Field-level restrictions are handled at data retrieval time
                }
            }
        }

        Ok(true)
    }
}

// ============================================================================
// Role Store Trait
// ============================================================================

#[async_trait]
pub trait RoleStore: Send + Sync {
    async fn get_role(&self, role_id: &RoleId) -> Result<Option<Role>, AuthzError>;
    async fn get_assignments(&self, principal_id: &PrincipalId) -> Result<Vec<RoleAssignment>, AuthzError>;
    async fn create_role(&self, role: &Role) -> Result<(), AuthzError>;
    async fn update_role(&self, role: &Role) -> Result<(), AuthzError>;
    async fn delete_role(&self, role_id: &RoleId) -> Result<(), AuthzError>;
    async fn assign_role(&self, assignment: &RoleAssignment) -> Result<(), AuthzError>;
    async fn revoke_role(&self, assignment_id: &Uuid) -> Result<(), AuthzError>;
}

// ============================================================================
// Permission Cache
// ============================================================================

struct PermissionCache {
    entries: HashMap<PrincipalId, CacheEntry>,
    ttl: Duration,
}

struct CacheEntry {
    permissions: HashSet<Permission>,
    cached_at: Instant,
}

impl PermissionCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
        }
    }

    fn get(&self, principal_id: &PrincipalId) -> Option<HashSet<Permission>> {
        self.entries.get(principal_id).and_then(|entry| {
            if entry.cached_at.elapsed() < self.ttl {
                Some(entry.permissions.clone())
            } else {
                None
            }
        })
    }

    fn insert(&mut self, principal_id: PrincipalId, permissions: HashSet<Permission>) {
        self.entries.insert(principal_id, CacheEntry {
            permissions,
            cached_at: Instant::now(),
        });
    }

    fn remove(&mut self, principal_id: &PrincipalId) {
        self.entries.remove(principal_id);
    }
}
```

---

## 3. ABAC Implementation

```rust
// src/auth/abac.rs

pub struct ABACEngine {
    policy_store: Arc<dyn ABACPolicyStore>,
    attribute_providers: Vec<Arc<dyn AttributeProvider>>,
    config: ABACConfig,
    metrics: Arc<AuthzMetrics>,
}

#[derive(Debug, Clone)]
pub struct ABACConfig {
    pub default_effect: Effect,
    pub combine_algorithm: CombineAlgorithm,
    pub attribute_cache_ttl: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum CombineAlgorithm {
    DenyOverrides,    // If any policy denies, deny
    PermitOverrides,  // If any policy permits, permit
    FirstApplicable,  // Use first applicable policy
    OnlyOneApplicable, // Exactly one policy must apply
}

// ============================================================================
// ABAC Policy Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACPolicy {
    pub id: PolicyId,
    pub name: String,
    pub description: Option<String>,
    pub target: PolicyTarget,
    pub rules: Vec<ABACRule>,
    pub effect: Effect,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTarget {
    pub subjects: Option<SubjectMatch>,
    pub resources: Option<ResourceMatch>,
    pub actions: Option<ActionMatch>,
    pub environment: Option<EnvironmentMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectMatch {
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMatch {
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMatch {
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentMatch {
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABACRule {
    pub id: String,
    pub condition: Condition,
    pub effect: Effect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Permit,
    Deny,
}

// ============================================================================
// Conditions
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    // Comparison operators
    StringEquals { attribute: String, value: String },
    StringNotEquals { attribute: String, value: String },
    StringLike { attribute: String, pattern: String },
    StringStartsWith { attribute: String, prefix: String },

    NumericEquals { attribute: String, value: f64 },
    NumericGreaterThan { attribute: String, value: f64 },
    NumericLessThan { attribute: String, value: f64 },
    NumericBetween { attribute: String, min: f64, max: f64 },

    DateGreaterThan { attribute: String, value: DateTime<Utc> },
    DateLessThan { attribute: String, value: DateTime<Utc> },
    DateBetween { attribute: String, start: DateTime<Utc>, end: DateTime<Utc> },

    Bool { attribute: String, value: bool },

    IpAddress { attribute: String, cidr: String },
    IpAddressIn { attribute: String, cidrs: Vec<String> },

    // Set operations
    StringIn { attribute: String, values: Vec<String> },
    StringNotIn { attribute: String, values: Vec<String> },
    SetContains { attribute: String, value: String },
    SetContainsAny { attribute: String, values: Vec<String> },
    SetContainsAll { attribute: String, values: Vec<String> },

    // Logical operators
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),

    // Special
    IsNull { attribute: String },
    IsNotNull { attribute: String },
    AttributeEquals { left: String, right: String },
}

// ============================================================================
// ABAC Engine Implementation
// ============================================================================

impl ABACEngine {
    pub fn new(
        policy_store: Arc<dyn ABACPolicyStore>,
        config: ABACConfig,
    ) -> Self {
        Self {
            policy_store,
            attribute_providers: Vec::new(),
            config,
            metrics: Arc::new(AuthzMetrics::new("abac")),
        }
    }

    pub fn add_attribute_provider(&mut self, provider: Arc<dyn AttributeProvider>) {
        self.attribute_providers.push(provider);
    }

    /// Evaluate a condition against attributes
    fn evaluate_condition(
        &self,
        condition: &Condition,
        attributes: &AttributeContext,
    ) -> Result<bool, AuthzError> {
        match condition {
            Condition::StringEquals { attribute, value } => {
                let attr_value = attributes.get_string(attribute)?;
                Ok(attr_value == *value)
            }
            Condition::StringNotEquals { attribute, value } => {
                let attr_value = attributes.get_string(attribute)?;
                Ok(attr_value != *value)
            }
            Condition::StringLike { attribute, pattern } => {
                let attr_value = attributes.get_string(attribute)?;
                let regex = regex::Regex::new(&pattern.replace("*", ".*"))
                    .map_err(|_| AuthzError::InvalidAttribute { name: attribute.clone() })?;
                Ok(regex.is_match(&attr_value))
            }
            Condition::NumericEquals { attribute, value } => {
                let attr_value = attributes.get_number(attribute)?;
                Ok((attr_value - value).abs() < f64::EPSILON)
            }
            Condition::NumericGreaterThan { attribute, value } => {
                let attr_value = attributes.get_number(attribute)?;
                Ok(attr_value > *value)
            }
            Condition::NumericLessThan { attribute, value } => {
                let attr_value = attributes.get_number(attribute)?;
                Ok(attr_value < *value)
            }
            Condition::Bool { attribute, value } => {
                let attr_value = attributes.get_bool(attribute)?;
                Ok(attr_value == *value)
            }
            Condition::IpAddress { attribute, cidr } => {
                let ip = attributes.get_ip_address(attribute)?;
                let network: ipnetwork::IpNetwork = cidr.parse()
                    .map_err(|_| AuthzError::InvalidAttribute { name: attribute.clone() })?;
                Ok(network.contains(ip))
            }
            Condition::StringIn { attribute, values } => {
                let attr_value = attributes.get_string(attribute)?;
                Ok(values.contains(&attr_value))
            }
            Condition::And(conditions) => {
                for cond in conditions {
                    if !self.evaluate_condition(cond, attributes)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Condition::Or(conditions) => {
                for cond in conditions {
                    if self.evaluate_condition(cond, attributes)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Condition::Not(condition) => {
                Ok(!self.evaluate_condition(condition, attributes)?)
            }
            Condition::IsNull { attribute } => {
                Ok(attributes.get(attribute).is_none())
            }
            Condition::IsNotNull { attribute } => {
                Ok(attributes.get(attribute).is_some())
            }
            _ => Ok(false), // Handle other conditions
        }
    }

    /// Check if a policy's target matches the request
    fn target_matches(
        &self,
        target: &PolicyTarget,
        attributes: &AttributeContext,
    ) -> Result<bool, AuthzError> {
        // Check subject conditions
        if let Some(ref subjects) = target.subjects {
            for condition in &subjects.conditions {
                if !self.evaluate_condition(condition, attributes)? {
                    return Ok(false);
                }
            }
        }

        // Check resource conditions
        if let Some(ref resources) = target.resources {
            for condition in &resources.conditions {
                if !self.evaluate_condition(condition, attributes)? {
                    return Ok(false);
                }
            }
        }

        // Check action
        if let Some(ref actions) = target.actions {
            let request_action = attributes.get_string("action.name")?;
            if !actions.actions.contains(&request_action) {
                return Ok(false);
            }
        }

        // Check environment conditions
        if let Some(ref environment) = target.environment {
            for condition in &environment.conditions {
                if !self.evaluate_condition(condition, attributes)? {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Evaluate a single policy
    fn evaluate_policy(
        &self,
        policy: &ABACPolicy,
        attributes: &AttributeContext,
    ) -> Result<Option<Effect>, AuthzError> {
        // Check if policy target matches
        if !self.target_matches(&policy.target, attributes)? {
            return Ok(None);
        }

        // Evaluate rules
        for rule in &policy.rules {
            if self.evaluate_condition(&rule.condition, attributes)? {
                return Ok(Some(rule.effect));
            }
        }

        // Return policy's default effect
        Ok(Some(policy.effect))
    }

    /// Combine multiple policy decisions
    fn combine_decisions(
        &self,
        decisions: Vec<(PolicyId, Effect)>,
    ) -> AuthzDecision {
        if decisions.is_empty() {
            return match self.config.default_effect {
                Effect::Permit => AuthzDecision::Allow {
                    reason: "Default permit".into(),
                    matched_policies: vec![],
                    granted_permissions: vec![],
                },
                Effect::Deny => AuthzDecision::Deny {
                    reason: "Default deny".into(),
                    violations: vec![],
                },
            };
        }

        match self.config.combine_algorithm {
            CombineAlgorithm::DenyOverrides => {
                for (policy_id, effect) in &decisions {
                    if *effect == Effect::Deny {
                        return AuthzDecision::Deny {
                            reason: format!("Denied by policy {}", policy_id.0),
                            violations: vec![PolicyViolation {
                                policy_id: policy_id.clone(),
                                rule_id: "abac".into(),
                                message: "Policy explicitly denies access".into(),
                                severity: ViolationSeverity::Error,
                            }],
                        };
                    }
                }
                AuthzDecision::Allow {
                    reason: "All applicable policies permit".into(),
                    matched_policies: decisions.iter().map(|(id, _)| id.clone()).collect(),
                    granted_permissions: vec![],
                }
            }
            CombineAlgorithm::PermitOverrides => {
                for (policy_id, effect) in &decisions {
                    if *effect == Effect::Permit {
                        return AuthzDecision::Allow {
                            reason: format!("Permitted by policy {}", policy_id.0),
                            matched_policies: vec![policy_id.clone()],
                            granted_permissions: vec![],
                        };
                    }
                }
                AuthzDecision::Deny {
                    reason: "No policy permits access".into(),
                    violations: vec![],
                }
            }
            CombineAlgorithm::FirstApplicable => {
                let (policy_id, effect) = &decisions[0];
                match effect {
                    Effect::Permit => AuthzDecision::Allow {
                        reason: format!("First applicable policy {} permits", policy_id.0),
                        matched_policies: vec![policy_id.clone()],
                        granted_permissions: vec![],
                    },
                    Effect::Deny => AuthzDecision::Deny {
                        reason: format!("First applicable policy {} denies", policy_id.0),
                        violations: vec![],
                    },
                }
            }
            CombineAlgorithm::OnlyOneApplicable => {
                if decisions.len() != 1 {
                    return AuthzDecision::Deny {
                        reason: format!(
                            "Expected exactly one applicable policy, found {}",
                            decisions.len()
                        ),
                        violations: vec![],
                    };
                }
                let (policy_id, effect) = &decisions[0];
                match effect {
                    Effect::Permit => AuthzDecision::Allow {
                        reason: format!("Single applicable policy {} permits", policy_id.0),
                        matched_policies: vec![policy_id.clone()],
                        granted_permissions: vec![],
                    },
                    Effect::Deny => AuthzDecision::Deny {
                        reason: format!("Single applicable policy {} denies", policy_id.0),
                        violations: vec![],
                    },
                }
            }
        }
    }

    /// Build attribute context from request
    async fn build_attribute_context(
        &self,
        request: &AuthzRequest,
    ) -> Result<AttributeContext, AuthzError> {
        let mut context = AttributeContext::new();

        // Add subject attributes
        context.set("subject.id", AttributeValue::String(request.principal.id.0.to_string()));
        for (key, value) in &request.principal.attributes {
            context.set(&format!("subject.{}", key), value.clone());
        }

        // Add resource attributes
        context.set("resource.id", AttributeValue::String(request.resource.id.0.to_string()));
        context.set("resource.type", AttributeValue::String(format!("{:?}", request.resource.resource_type)));
        for (key, value) in &request.resource.attributes {
            context.set(&format!("resource.{}", key), value.clone());
        }

        // Add action
        context.set("action.name", AttributeValue::String(request.action.name.clone()));
        context.set("action.category", AttributeValue::String(format!("{:?}", request.action.category)));

        // Add environment/context
        context.set("environment.timestamp", AttributeValue::Timestamp(request.context.timestamp));
        if let Some(ip) = request.context.ip_address {
            context.set("environment.ip_address", AttributeValue::IpAddress(ip));
        }
        context.set("environment.mfa_verified", AttributeValue::Boolean(request.context.mfa_verified));

        // Fetch additional attributes from providers
        for provider in &self.attribute_providers {
            let attrs = provider.get_attributes(&request.principal.id).await?;
            for (key, value) in attrs {
                context.set(&key, value);
            }
        }

        Ok(context)
    }
}

#[async_trait]
impl AuthorizationEngine for ABACEngine {
    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision, AuthzError> {
        let _timer = self.metrics.operation_timer("authorize");

        // Build attribute context
        let attributes = self.build_attribute_context(request).await?;

        // Get all policies
        let policies = self.policy_store.get_enabled_policies().await?;

        // Sort by priority
        let mut sorted_policies = policies;
        sorted_policies.sort_by_key(|p| -p.priority);

        // Evaluate each policy
        let mut decisions = Vec::new();
        for policy in &sorted_policies {
            if let Some(effect) = self.evaluate_policy(policy, &attributes)? {
                decisions.push((policy.id.clone(), effect));
            }
        }

        // Combine decisions
        Ok(self.combine_decisions(decisions))
    }

    async fn authorize_batch(
        &self,
        requests: &[AuthzRequest],
    ) -> Result<Vec<AuthzDecision>, AuthzError> {
        let mut results = Vec::with_capacity(requests.len());
        for request in requests {
            results.push(self.authorize(request).await?);
        }
        Ok(results)
    }

    async fn has_permission(
        &self,
        principal: &Principal,
        permission: &Permission,
        resource: &Resource,
    ) -> Result<bool, AuthzError> {
        let request = AuthzRequest {
            request_id: RequestId::new(),
            principal: principal.clone(),
            action: Action {
                name: format!("{:?}", permission.action),
                category: permission.action,
            },
            resource: resource.clone(),
            context: AuthzContext {
                timestamp: Utc::now(),
                ip_address: None,
                user_agent: None,
                request_path: None,
                mfa_verified: false,
                session_age: None,
                custom: HashMap::new(),
            },
        };

        let decision = self.authorize(&request).await?;
        Ok(decision.is_allowed())
    }
}

// ============================================================================
// Attribute Context
// ============================================================================

pub struct AttributeContext {
    attributes: HashMap<String, AttributeValue>,
}

impl AttributeContext {
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: &str, value: AttributeValue) {
        self.attributes.insert(key.to_string(), value);
    }

    pub fn get(&self, key: &str) -> Option<&AttributeValue> {
        self.attributes.get(key)
    }

    pub fn get_string(&self, key: &str) -> Result<String, AuthzError> {
        match self.attributes.get(key) {
            Some(AttributeValue::String(s)) => Ok(s.clone()),
            _ => Err(AuthzError::InvalidAttribute { name: key.to_string() }),
        }
    }

    pub fn get_number(&self, key: &str) -> Result<f64, AuthzError> {
        match self.attributes.get(key) {
            Some(AttributeValue::Float(f)) => Ok(*f),
            Some(AttributeValue::Integer(i)) => Ok(*i as f64),
            _ => Err(AuthzError::InvalidAttribute { name: key.to_string() }),
        }
    }

    pub fn get_bool(&self, key: &str) -> Result<bool, AuthzError> {
        match self.attributes.get(key) {
            Some(AttributeValue::Boolean(b)) => Ok(*b),
            _ => Err(AuthzError::InvalidAttribute { name: key.to_string() }),
        }
    }

    pub fn get_ip_address(&self, key: &str) -> Result<IpAddr, AuthzError> {
        match self.attributes.get(key) {
            Some(AttributeValue::IpAddress(ip)) => Ok(*ip),
            _ => Err(AuthzError::InvalidAttribute { name: key.to_string() }),
        }
    }
}

// ============================================================================
// Traits
// ============================================================================

#[async_trait]
pub trait ABACPolicyStore: Send + Sync {
    async fn get_enabled_policies(&self) -> Result<Vec<ABACPolicy>, AuthzError>;
    async fn get_policy(&self, policy_id: &PolicyId) -> Result<Option<ABACPolicy>, AuthzError>;
    async fn create_policy(&self, policy: &ABACPolicy) -> Result<(), AuthzError>;
    async fn update_policy(&self, policy: &ABACPolicy) -> Result<(), AuthzError>;
    async fn delete_policy(&self, policy_id: &PolicyId) -> Result<(), AuthzError>;
}

#[async_trait]
pub trait AttributeProvider: Send + Sync {
    async fn get_attributes(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<HashMap<String, AttributeValue>, AuthzError>;
}
```

---

## 4. Authentication Providers

```rust
// src/auth/providers/mod.rs

#[async_trait]
pub trait AuthenticationProvider: Send + Sync {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthenticatedUser, AuthError>;
    async fn validate_token(&self, token: &str) -> Result<TokenClaims, AuthError>;
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError>;
    fn provider_type(&self) -> &'static str;
}

#[derive(Debug, Clone)]
pub enum Credentials {
    UsernamePassword { username: String, password: SecureString },
    ApiKey { key: SecureString },
    Certificate { cert: Vec<u8> },
    OAuth { code: String, redirect_uri: String },
    RefreshToken { token: SecureString },
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<RoleId>,
    pub groups: Vec<GroupId>,
    pub attributes: HashMap<String, AttributeValue>,
    pub authenticated_at: DateTime<Utc>,
    pub auth_method: String,
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: Duration,
}

#[derive(Debug, Clone)]
pub struct TokenClaims {
    pub subject: String,
    pub issuer: String,
    pub audience: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
    pub custom_claims: HashMap<String, serde_json::Value>,
}

// ============================================================================
// OIDC Provider
// ============================================================================

pub struct OIDCProvider {
    client: OIDCClient,
    config: OIDCConfig,
}

#[derive(Debug, Clone)]
pub struct OIDCConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: SecureString,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub audience: Option<String>,
}

impl OIDCProvider {
    pub async fn new(config: OIDCConfig) -> Result<Self, AuthError> {
        let client = OIDCClient::discover(&config.issuer_url).await?;
        Ok(Self { client, config })
    }
}

#[async_trait]
impl AuthenticationProvider for OIDCProvider {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthenticatedUser, AuthError> {
        match credentials {
            Credentials::OAuth { code, redirect_uri } => {
                // Exchange code for tokens
                let tokens = self.client.exchange_code(code, redirect_uri).await?;

                // Verify ID token
                let claims = self.client.verify_id_token(&tokens.id_token).await?;

                Ok(AuthenticatedUser {
                    user_id: UserId(Uuid::parse_str(&claims.subject).unwrap_or_else(|_| Uuid::new_v4())),
                    username: claims.preferred_username.unwrap_or(claims.subject.clone()),
                    email: claims.email,
                    roles: Vec::new(),
                    groups: claims.groups.unwrap_or_default().into_iter()
                        .map(|g| GroupId(Uuid::new_v4()))
                        .collect(),
                    attributes: HashMap::new(),
                    authenticated_at: Utc::now(),
                    auth_method: "oidc".into(),
                })
            }
            _ => Err(AuthError::UnsupportedCredentialType),
        }
    }

    async fn validate_token(&self, token: &str) -> Result<TokenClaims, AuthError> {
        let claims = self.client.verify_access_token(token).await?;
        Ok(claims)
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        self.client.refresh_tokens(refresh_token).await
    }

    fn provider_type(&self) -> &'static str {
        "oidc"
    }
}

// ============================================================================
// API Key Provider
// ============================================================================

pub struct APIKeyProvider {
    store: Arc<dyn APIKeyStore>,
    hasher: ArgonHasher,
}

#[async_trait]
pub trait APIKeyStore: Send + Sync {
    async fn get_key_info(&self, key_hash: &str) -> Result<Option<APIKeyInfo>, AuthError>;
    async fn create_key(&self, info: &APIKeyInfo) -> Result<String, AuthError>;
    async fn revoke_key(&self, key_id: &str) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct APIKeyInfo {
    pub id: String,
    pub key_hash: String,
    pub user_id: UserId,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[async_trait]
impl AuthenticationProvider for APIKeyProvider {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthenticatedUser, AuthError> {
        match credentials {
            Credentials::ApiKey { key } => {
                let key_hash = self.hasher.hash(key.expose_secret())?;
                let key_info = self.store.get_key_info(&key_hash).await?
                    .ok_or(AuthError::InvalidCredentials)?;

                if key_info.revoked {
                    return Err(AuthError::KeyRevoked);
                }

                if let Some(expires_at) = key_info.expires_at {
                    if Utc::now() > expires_at {
                        return Err(AuthError::KeyExpired);
                    }
                }

                Ok(AuthenticatedUser {
                    user_id: key_info.user_id,
                    username: key_info.name.clone(),
                    email: None,
                    roles: Vec::new(),
                    groups: Vec::new(),
                    attributes: HashMap::from([
                        ("api_key_id".to_string(), AttributeValue::String(key_info.id)),
                        ("scopes".to_string(), AttributeValue::List(
                            key_info.scopes.iter().map(|s| AttributeValue::String(s.clone())).collect()
                        )),
                    ]),
                    authenticated_at: Utc::now(),
                    auth_method: "api_key".into(),
                })
            }
            _ => Err(AuthError::UnsupportedCredentialType),
        }
    }

    async fn validate_token(&self, _token: &str) -> Result<TokenClaims, AuthError> {
        Err(AuthError::UnsupportedOperation)
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<TokenPair, AuthError> {
        Err(AuthError::UnsupportedOperation)
    }

    fn provider_type(&self) -> &'static str {
        "api_key"
    }
}

// ============================================================================
// Auth Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token invalid: {message}")]
    TokenInvalid { message: String },

    #[error("API key revoked")]
    KeyRevoked,

    #[error("API key expired")]
    KeyExpired,

    #[error("Unsupported credential type")]
    UnsupportedCredentialType,

    #[error("Unsupported operation")]
    UnsupportedOperation,

    #[error("Provider error: {message}")]
    ProviderError { message: String },

    #[error("MFA required")]
    MFARequired,
}
```

---

## 5. Session Management

```rust
// src/auth/session.rs

pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
    metrics: Arc<SessionMetrics>,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_ttl: Duration,
    pub refresh_threshold: Duration,
    pub max_concurrent_sessions: usize,
    pub require_mfa_for_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub mfa_verified: bool,
    pub metadata: HashMap<String, String>,
}

impl SessionManager {
    pub fn new(store: Arc<dyn SessionStore>, config: SessionConfig) -> Self {
        Self {
            store,
            config,
            metrics: Arc::new(SessionMetrics::new()),
        }
    }

    pub async fn create_session(
        &self,
        user: &AuthenticatedUser,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<Session, AuthError> {
        // Check concurrent session limit
        let existing = self.store.get_user_sessions(&user.user_id).await?;
        if existing.len() >= self.config.max_concurrent_sessions {
            // Revoke oldest session
            if let Some(oldest) = existing.iter().min_by_key(|s| s.created_at) {
                self.store.delete_session(&oldest.id).await?;
            }
        }

        let now = Utc::now();
        let session = Session {
            id: SessionId::new(),
            user_id: user.user_id,
            created_at: now,
            expires_at: now + self.config.session_ttl,
            last_activity: now,
            ip_address,
            user_agent,
            mfa_verified: false,
            metadata: HashMap::new(),
        };

        self.store.create_session(&session).await?;
        self.metrics.record_session_created();

        Ok(session)
    }

    pub async fn validate_session(&self, session_id: &SessionId) -> Result<Session, AuthError> {
        let session = self.store.get_session(session_id).await?
            .ok_or(AuthError::TokenInvalid { message: "Session not found".into() })?;

        if Utc::now() > session.expires_at {
            self.store.delete_session(session_id).await?;
            return Err(AuthError::TokenExpired);
        }

        // Refresh session if approaching expiry
        let time_until_expiry = session.expires_at - Utc::now();
        if time_until_expiry < self.config.refresh_threshold {
            let mut updated = session.clone();
            updated.expires_at = Utc::now() + self.config.session_ttl;
            updated.last_activity = Utc::now();
            self.store.update_session(&updated).await?;
            return Ok(updated);
        }

        Ok(session)
    }

    pub async fn verify_mfa(&self, session_id: &SessionId) -> Result<(), AuthError> {
        let mut session = self.store.get_session(session_id).await?
            .ok_or(AuthError::TokenInvalid { message: "Session not found".into() })?;

        session.mfa_verified = true;
        self.store.update_session(&session).await?;

        Ok(())
    }

    pub async fn revoke_session(&self, session_id: &SessionId) -> Result<(), AuthError> {
        self.store.delete_session(session_id).await?;
        self.metrics.record_session_revoked();
        Ok(())
    }

    pub async fn revoke_all_user_sessions(&self, user_id: &UserId) -> Result<usize, AuthError> {
        let sessions = self.store.get_user_sessions(user_id).await?;
        let count = sessions.len();

        for session in sessions {
            self.store.delete_session(&session.id).await?;
        }

        Ok(count)
    }
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, session: &Session) -> Result<(), AuthError>;
    async fn get_session(&self, session_id: &SessionId) -> Result<Option<Session>, AuthError>;
    async fn update_session(&self, session: &Session) -> Result<(), AuthError>;
    async fn delete_session(&self, session_id: &SessionId) -> Result<(), AuthError>;
    async fn get_user_sessions(&self, user_id: &UserId) -> Result<Vec<Session>, AuthError>;
}
```

---

## Summary

This document defines the access control layer for LLM-Data-Vault:

| Component | Purpose |
|-----------|---------|
| **AuthorizationEngine** | Abstract interface for authorization decisions |
| **RBACEngine** | Role-based access control with inheritance |
| **ABACEngine** | Attribute-based access control with policy evaluation |
| **AuthenticationProviders** | OIDC, API Key, Certificate authentication |
| **SessionManager** | Session lifecycle management |

**Key Features:**
- Sub-100ms authorization decisions with caching
- RBAC with role inheritance and constraints
- ABAC with comprehensive condition evaluation
- Multiple combine algorithms (deny overrides, permit overrides)
- Session management with MFA support
- Extensible attribute providers

---

*Next Document: [06-api-layer.md](./06-api-layer.md)*
