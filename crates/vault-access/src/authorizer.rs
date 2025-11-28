//! Authorization service.

use crate::{
    AbacContext, AbacEngine, AccessError, AccessResult, Action, Effect, PolicyDecision,
    PolicyEngine, RbacManager, ResourceId, ResourceType, TokenClaims, TokenManager,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Authorization context.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// User ID.
    pub user_id: String,
    /// User roles.
    pub roles: Vec<String>,
    /// User permissions.
    pub permissions: Vec<String>,
    /// Tenant ID.
    pub tenant_id: Option<String>,
    /// Request metadata.
    pub metadata: HashMap<String, String>,
    /// Token claims (if from JWT).
    pub claims: Option<TokenClaims>,
}

impl AuthContext {
    /// Creates from token claims.
    pub fn from_claims(claims: TokenClaims) -> Self {
        Self {
            user_id: claims.sub.clone(),
            roles: claims.roles.clone(),
            permissions: claims.permissions.clone(),
            tenant_id: claims.tenant_id.clone(),
            metadata: HashMap::new(),
            claims: Some(claims),
        }
    }

    /// Creates a system context (for internal operations).
    pub fn system() -> Self {
        Self {
            user_id: "system".to_string(),
            roles: vec!["system".to_string()],
            permissions: vec!["*".to_string()],
            tenant_id: None,
            metadata: HashMap::new(),
            claims: None,
        }
    }

    /// Creates an anonymous context.
    pub fn anonymous() -> Self {
        Self {
            user_id: "anonymous".to_string(),
            roles: Vec::new(),
            permissions: Vec::new(),
            tenant_id: None,
            metadata: HashMap::new(),
            claims: None,
        }
    }

    /// Adds metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Checks if this is a system context.
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.user_id == "system"
    }

    /// Checks if this is anonymous.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.user_id == "anonymous"
    }
}

/// Authorization request.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// Action to perform.
    pub action: String,
    /// Resource being accessed.
    pub resource: ResourceId,
    /// Additional context.
    pub context: HashMap<String, String>,
}

impl AuthRequest {
    /// Creates a new request.
    pub fn new(action: impl Into<String>, resource: ResourceId) -> Self {
        Self {
            action: action.into(),
            resource,
            context: HashMap::new(),
        }
    }

    /// Adds context.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

/// Authorization response.
#[derive(Debug, Clone)]
pub struct AuthResponse {
    /// Whether access is allowed.
    pub allowed: bool,
    /// Reason for the decision.
    pub reason: Option<String>,
    /// Decision source.
    pub decision_source: DecisionSource,
    /// Obligations to fulfill.
    pub obligations: Vec<String>,
}

impl AuthResponse {
    /// Creates an allow response.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
            decision_source: DecisionSource::Default,
            obligations: Vec::new(),
        }
    }

    /// Creates a deny response.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            decision_source: DecisionSource::Default,
            obligations: Vec::new(),
        }
    }

    /// Sets decision source.
    #[must_use]
    pub fn from_source(mut self, source: DecisionSource) -> Self {
        self.decision_source = source;
        self
    }
}

/// Decision source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionSource {
    /// RBAC decision.
    Rbac,
    /// ABAC decision.
    Abac,
    /// Policy decision.
    Policy,
    /// Default decision.
    Default,
    /// System override.
    System,
}

/// Main authorizer combining RBAC, ABAC, and policies.
pub struct Authorizer {
    rbac: Arc<RbacManager>,
    abac: Arc<AbacEngine>,
    policy_engine: Arc<PolicyEngine>,
    token_manager: Arc<TokenManager>,
}

impl Authorizer {
    /// Creates a new authorizer.
    pub fn new(
        rbac: Arc<RbacManager>,
        abac: Arc<AbacEngine>,
        policy_engine: Arc<PolicyEngine>,
        token_manager: Arc<TokenManager>,
    ) -> Self {
        Self {
            rbac,
            abac,
            policy_engine,
            token_manager,
        }
    }

    /// Creates with default components.
    pub fn with_defaults() -> Self {
        Self {
            rbac: Arc::new(RbacManager::new()),
            abac: Arc::new(AbacEngine::new()),
            policy_engine: Arc::new(PolicyEngine::new()),
            token_manager: Arc::new(TokenManager::new(Default::default())),
        }
    }

    /// Authenticates a token and returns context.
    pub fn authenticate(&self, token: &str) -> AccessResult<AuthContext> {
        let claims = self.token_manager.validate(token)?;
        Ok(AuthContext::from_claims(claims))
    }

    /// Authorizes a request.
    pub fn authorize(&self, auth: &AuthContext, request: &AuthRequest) -> AuthResponse {
        // System context always allowed
        if auth.is_system() {
            return AuthResponse::allow().from_source(DecisionSource::System);
        }

        // Anonymous only allowed for public resources
        if auth.is_anonymous() {
            return self.check_anonymous_access(request);
        }

        // 1. Check explicit policies first (deny wins)
        let policy_decision = self.check_policies(auth, request);
        if let Some(ref decision) = policy_decision {
            if !decision.is_allowed() {
                return AuthResponse::deny(decision.reason.clone().unwrap_or_default())
                    .from_source(DecisionSource::Policy);
            }
        }

        // 2. Check RBAC
        let rbac_allowed = self.rbac.check_permission(
            &auth.user_id,
            &request.resource.resource_type.to_string(),
            &request.action,
            request.resource.id.as_deref(),
        );

        if rbac_allowed {
            return AuthResponse::allow().from_source(DecisionSource::Rbac);
        }

        // 3. Check ABAC
        let abac_context = self.build_abac_context(auth, request);
        let abac_effect = self.abac.evaluate(
            &abac_context,
            Some(&request.resource.resource_type.to_string()),
            Some(&request.action),
        );

        if abac_effect == crate::abac::PolicyEffect::Allow {
            return AuthResponse::allow().from_source(DecisionSource::Abac);
        }

        // 4. Check explicit allows from policies
        if let Some(ref decision) = policy_decision {
            if decision.is_allowed() {
                return AuthResponse::allow().from_source(DecisionSource::Policy);
            }
        }

        // Default deny
        AuthResponse::deny("Access denied: no matching permission")
    }

    /// Checks if a specific permission is granted.
    pub fn has_permission(
        &self,
        auth: &AuthContext,
        resource_type: &str,
        action: &str,
        resource_id: Option<&str>,
    ) -> bool {
        let request = AuthRequest::new(
            action,
            match resource_id {
                Some(id) => ResourceId::with_id(ResourceType::Custom(resource_type.to_string()), id),
                None => ResourceId::new(ResourceType::Custom(resource_type.to_string())),
            },
        );

        self.authorize(auth, &request).allowed
    }

    /// Checks anonymous access.
    fn check_anonymous_access(&self, request: &AuthRequest) -> AuthResponse {
        // Only allow read on public resources
        let is_public = request.context.get("public").map_or(false, |v| v == "true");

        if is_public && request.action == "read" {
            AuthResponse::allow().from_source(DecisionSource::Default)
        } else {
            AuthResponse::deny("Anonymous access denied")
        }
    }

    /// Checks policies.
    fn check_policies(&self, auth: &AuthContext, request: &AuthRequest) -> Option<PolicyDecision> {
        let mut context = request.context.clone();
        context.insert("user_id".to_string(), auth.user_id.clone());

        for role in &auth.roles {
            context.insert("role".to_string(), role.clone());
        }

        if let Some(ref tenant) = auth.tenant_id {
            context.insert("tenant_id".to_string(), tenant.clone());
        }

        let resource_str = request.resource.to_resource_string();

        // Build principal string
        let principal = if auth.roles.contains(&"admin".to_string()) {
            "role:admin".to_string()
        } else {
            format!("user:{}", auth.user_id)
        };

        let decision = self.policy_engine.evaluate(
            &principal,
            &request.action,
            &resource_str,
            &context,
        );

        Some(decision)
    }

    /// Builds ABAC context.
    fn build_abac_context(&self, auth: &AuthContext, request: &AuthRequest) -> AbacContext {
        let mut ctx = AbacContext::new();

        // Subject attributes
        ctx.subject_attributes.insert(
            "user_id".to_string(),
            crate::abac::AttributeValue::String(auth.user_id.clone()),
        );

        for role in &auth.roles {
            ctx.subject_attributes.insert(
                "role".to_string(),
                crate::abac::AttributeValue::String(role.clone()),
            );
        }

        if let Some(ref tenant) = auth.tenant_id {
            ctx.subject_attributes.insert(
                "tenant_id".to_string(),
                crate::abac::AttributeValue::String(tenant.clone()),
            );
        }

        // Resource attributes
        ctx.resource_attributes.insert(
            "type".to_string(),
            crate::abac::AttributeValue::String(request.resource.resource_type.to_string()),
        );

        if let Some(ref id) = request.resource.id {
            ctx.resource_attributes.insert(
                "id".to_string(),
                crate::abac::AttributeValue::String(id.clone()),
            );
        }

        if let Some(ref tenant) = request.resource.tenant_id {
            ctx.resource_attributes.insert(
                "tenant_id".to_string(),
                crate::abac::AttributeValue::String(tenant.clone()),
            );
        }

        // Action attributes
        ctx.action_attributes.insert(
            "name".to_string(),
            crate::abac::AttributeValue::String(request.action.clone()),
        );

        // Environment attributes
        ctx.environment_attributes.insert(
            "time".to_string(),
            crate::abac::AttributeValue::String(chrono::Utc::now().to_rfc3339()),
        );

        // Add request context
        for (k, v) in &request.context {
            ctx.environment_attributes.insert(
                k.clone(),
                crate::abac::AttributeValue::String(v.clone()),
            );
        }

        ctx
    }

    /// Returns the RBAC manager.
    #[must_use]
    pub fn rbac(&self) -> &RbacManager {
        &self.rbac
    }

    /// Returns the ABAC engine.
    #[must_use]
    pub fn abac(&self) -> &AbacEngine {
        &self.abac
    }

    /// Returns the policy engine.
    #[must_use]
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Returns the token manager.
    #[must_use]
    pub fn token_manager(&self) -> &TokenManager {
        &self.token_manager
    }
}

/// Authorization middleware helper.
pub struct AuthMiddleware {
    authorizer: Arc<Authorizer>,
}

impl AuthMiddleware {
    /// Creates a new middleware.
    pub fn new(authorizer: Arc<Authorizer>) -> Self {
        Self { authorizer }
    }

    /// Extracts and validates token from Authorization header.
    pub fn extract_token(header: &str) -> Option<&str> {
        header.strip_prefix("Bearer ")
    }

    /// Authenticates from header.
    pub fn authenticate(&self, auth_header: Option<&str>) -> AccessResult<AuthContext> {
        match auth_header {
            Some(header) => {
                let token = Self::extract_token(header)
                    .ok_or_else(|| AccessError::InvalidToken("Invalid Authorization header".to_string()))?;
                self.authorizer.authenticate(token)
            }
            None => Ok(AuthContext::anonymous()),
        }
    }

    /// Full authentication and authorization check.
    pub fn check(
        &self,
        auth_header: Option<&str>,
        action: &str,
        resource: ResourceId,
    ) -> AccessResult<AuthContext> {
        let auth = self.authenticate(auth_header)?;
        let request = AuthRequest::new(action, resource);
        let response = self.authorizer.authorize(&auth, &request);

        if response.allowed {
            Ok(auth)
        } else {
            Err(AccessError::Forbidden(
                response.reason.unwrap_or_else(|| "Access denied".to_string()),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_authorizer() -> Authorizer {
        Authorizer::with_defaults()
    }

    #[test]
    fn test_system_context() {
        let authorizer = create_authorizer();
        let auth = AuthContext::system();
        let request = AuthRequest::new("delete", ResourceId::new(ResourceType::System));

        let response = authorizer.authorize(&auth, &request);
        assert!(response.allowed);
        assert_eq!(response.decision_source, DecisionSource::System);
    }

    #[test]
    fn test_anonymous_denied() {
        let authorizer = create_authorizer();
        let auth = AuthContext::anonymous();
        let request = AuthRequest::new("write", ResourceId::new(ResourceType::Dataset));

        let response = authorizer.authorize(&auth, &request);
        assert!(!response.allowed);
    }

    #[test]
    fn test_rbac_permission() {
        let authorizer = create_authorizer();

        // Assign admin role to user
        authorizer.rbac.assign_role("user123", "admin").unwrap();

        let auth = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["admin".to_string()],
            permissions: Vec::new(),
            tenant_id: None,
            metadata: HashMap::new(),
            claims: None,
        };

        let request = AuthRequest::new("admin", ResourceId::new(ResourceType::System));
        let response = authorizer.authorize(&auth, &request);

        assert!(response.allowed);
    }

    #[test]
    fn test_auth_middleware() {
        let authorizer = Arc::new(create_authorizer());
        let middleware = AuthMiddleware::new(authorizer);

        // No header = anonymous
        let auth = middleware.authenticate(None).unwrap();
        assert!(auth.is_anonymous());

        // Invalid header
        let result = middleware.authenticate(Some("Invalid"));
        assert!(result.is_err());
    }

    #[test]
    fn test_token_extraction() {
        assert_eq!(
            AuthMiddleware::extract_token("Bearer token123"),
            Some("token123")
        );
        assert_eq!(AuthMiddleware::extract_token("token123"), None);
    }
}
