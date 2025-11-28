//! Policy-based authorization.

use crate::{AccessError, AccessResult, Action, ResourceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Policy effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    /// Allow access.
    Allow,
    /// Deny access.
    Deny,
}

/// Policy decision.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The decision effect.
    pub effect: Effect,
    /// Policy ID that made the decision.
    pub policy_id: Option<String>,
    /// Reason for the decision.
    pub reason: Option<String>,
    /// Obligations to fulfill.
    pub obligations: Vec<Obligation>,
    /// Advice (non-binding).
    pub advice: Vec<String>,
}

impl PolicyDecision {
    /// Creates an allow decision.
    pub fn allow() -> Self {
        Self {
            effect: Effect::Allow,
            policy_id: None,
            reason: None,
            obligations: Vec::new(),
            advice: Vec::new(),
        }
    }

    /// Creates a deny decision.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            effect: Effect::Deny,
            policy_id: None,
            reason: Some(reason.into()),
            obligations: Vec::new(),
            advice: Vec::new(),
        }
    }

    /// Sets the policy ID.
    #[must_use]
    pub fn from_policy(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    /// Adds an obligation.
    #[must_use]
    pub fn with_obligation(mut self, obligation: Obligation) -> Self {
        self.obligations.push(obligation);
        self
    }

    /// Adds advice.
    #[must_use]
    pub fn with_advice(mut self, advice: impl Into<String>) -> Self {
        self.advice.push(advice.into());
        self
    }

    /// Returns true if access is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.effect == Effect::Allow
    }
}

/// Obligation that must be fulfilled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    /// Obligation ID.
    pub id: String,
    /// Action to perform.
    pub action: String,
    /// Parameters.
    pub params: HashMap<String, String>,
}

impl Obligation {
    /// Creates a new obligation.
    pub fn new(id: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            action: action.into(),
            params: HashMap::new(),
        }
    }

    /// Adds a parameter.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }
}

/// Policy statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    /// Statement ID.
    pub id: Option<String>,
    /// Effect (allow/deny).
    pub effect: Effect,
    /// Principals (who).
    pub principals: Vec<String>,
    /// Actions (what).
    pub actions: Vec<String>,
    /// Resources (on what).
    pub resources: Vec<String>,
    /// Conditions.
    pub conditions: Vec<PolicyCondition>,
}

impl Statement {
    /// Creates an allow statement.
    pub fn allow() -> Self {
        Self {
            id: None,
            effect: Effect::Allow,
            principals: Vec::new(),
            actions: Vec::new(),
            resources: Vec::new(),
            conditions: Vec::new(),
        }
    }

    /// Creates a deny statement.
    pub fn deny() -> Self {
        let mut stmt = Self::allow();
        stmt.effect = Effect::Deny;
        stmt
    }

    /// Sets principals.
    #[must_use]
    pub fn for_principals(mut self, principals: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.principals = principals.into_iter().map(|p| p.into()).collect();
        self
    }

    /// Sets actions.
    #[must_use]
    pub fn for_actions(mut self, actions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.actions = actions.into_iter().map(|a| a.into()).collect();
        self
    }

    /// Sets resources.
    #[must_use]
    pub fn on_resources(mut self, resources: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.resources = resources.into_iter().map(|r| r.into()).collect();
        self
    }

    /// Adds a condition.
    #[must_use]
    pub fn when(mut self, condition: PolicyCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Checks if the statement matches the request.
    pub fn matches(&self, principal: &str, action: &str, resource: &str) -> bool {
        // Check principal
        let principal_match = self.principals.is_empty()
            || self.principals.iter().any(|p| {
                p == "*" || p == principal || Self::glob_match(p, principal)
            });

        if !principal_match {
            return false;
        }

        // Check action
        let action_match = self.actions.is_empty()
            || self.actions.iter().any(|a| {
                a == "*" || a == action || Self::glob_match(a, action)
            });

        if !action_match {
            return false;
        }

        // Check resource
        let resource_match = self.resources.is_empty()
            || self.resources.iter().any(|r| {
                r == "*" || r == resource || Self::glob_match(r, resource)
            });

        resource_match
    }

    /// Simple glob matching.
    fn glob_match(pattern: &str, value: &str) -> bool {
        let regex_pattern = pattern
            .replace('.', "\\.")
            .replace('*', ".*")
            .replace('?', ".");

        regex::Regex::new(&format!("^{}$", regex_pattern))
            .map(|r| r.is_match(value))
            .unwrap_or(false)
    }

    /// Evaluates conditions.
    pub fn evaluate_conditions(&self, context: &HashMap<String, String>) -> bool {
        self.conditions.iter().all(|c| c.evaluate(context))
    }
}

/// Policy condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// Condition type.
    pub condition_type: ConditionType,
    /// Key to check.
    pub key: String,
    /// Values to compare.
    pub values: Vec<String>,
}

/// Condition type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionType {
    /// String equals.
    StringEquals,
    /// String not equals.
    StringNotEquals,
    /// String like (glob).
    StringLike,
    /// IP address in range.
    IpAddress,
    /// Date less than.
    DateLessThan,
    /// Date greater than.
    DateGreaterThan,
    /// Numeric equals.
    NumericEquals,
    /// Numeric less than.
    NumericLessThan,
    /// Numeric greater than.
    NumericGreaterThan,
    /// Boolean.
    Bool,
}

impl PolicyCondition {
    /// Creates a string equals condition.
    pub fn string_equals(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            condition_type: ConditionType::StringEquals,
            key: key.into(),
            values: vec![value.into()],
        }
    }

    /// Creates a string like condition.
    pub fn string_like(key: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            condition_type: ConditionType::StringLike,
            key: key.into(),
            values: vec![pattern.into()],
        }
    }

    /// Evaluates the condition.
    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        let value = match context.get(&self.key) {
            Some(v) => v,
            None => return false,
        };

        match self.condition_type {
            ConditionType::StringEquals => self.values.contains(value),
            ConditionType::StringNotEquals => !self.values.contains(value),
            ConditionType::StringLike => {
                self.values.iter().any(|pattern| {
                    Statement::glob_match(pattern, value)
                })
            }
            ConditionType::Bool => {
                let bool_val = value.parse::<bool>().unwrap_or(false);
                self.values.iter().any(|v| {
                    v.parse::<bool>().map(|b| b == bool_val).unwrap_or(false)
                })
            }
            ConditionType::NumericEquals => {
                let num_val: f64 = value.parse().unwrap_or(0.0);
                self.values.iter().any(|v| {
                    v.parse::<f64>().map(|n| (n - num_val).abs() < f64::EPSILON).unwrap_or(false)
                })
            }
            ConditionType::NumericLessThan => {
                let num_val: f64 = value.parse().unwrap_or(0.0);
                self.values.iter().any(|v| {
                    v.parse::<f64>().map(|n| num_val < n).unwrap_or(false)
                })
            }
            ConditionType::NumericGreaterThan => {
                let num_val: f64 = value.parse().unwrap_or(0.0);
                self.values.iter().any(|v| {
                    v.parse::<f64>().map(|n| num_val > n).unwrap_or(false)
                })
            }
            _ => true, // Other conditions not fully implemented
        }
    }
}

/// Policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID.
    pub id: String,
    /// Policy name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Version.
    pub version: String,
    /// Statements.
    pub statements: Vec<Statement>,
    /// Tenant ID (for tenant-scoped policies).
    pub tenant_id: Option<String>,
    /// Is enabled.
    pub enabled: bool,
    /// Priority.
    pub priority: i32,
    /// Metadata.
    pub metadata: HashMap<String, String>,
}

impl Policy {
    /// Creates a new policy.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            version: "1".to_string(),
            statements: Vec::new(),
            tenant_id: None,
            enabled: true,
            priority: 0,
            metadata: HashMap::new(),
        }
    }

    /// Adds a statement.
    #[must_use]
    pub fn with_statement(mut self, statement: Statement) -> Self {
        self.statements.push(statement);
        self
    }

    /// Sets tenant.
    #[must_use]
    pub fn in_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Evaluates the policy.
    pub fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: &HashMap<String, String>,
    ) -> Option<PolicyDecision> {
        if !self.enabled {
            return None;
        }

        // Find matching statement
        for statement in &self.statements {
            if statement.matches(principal, action, resource)
                && statement.evaluate_conditions(context)
            {
                let decision = match statement.effect {
                    Effect::Allow => PolicyDecision::allow(),
                    Effect::Deny => PolicyDecision::deny("Explicitly denied by policy"),
                };

                return Some(decision.from_policy(&self.id));
            }
        }

        None
    }
}

/// Policy engine.
pub struct PolicyEngine {
    policies: RwLock<HashMap<String, Policy>>,
    default_effect: Effect,
}

impl PolicyEngine {
    /// Creates a new policy engine (default deny).
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            default_effect: Effect::Deny,
        }
    }

    /// Creates with default allow.
    #[must_use]
    pub fn default_allow() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            default_effect: Effect::Allow,
        }
    }

    /// Adds a policy.
    pub fn add_policy(&self, policy: Policy) {
        self.policies.write().insert(policy.id.clone(), policy);
    }

    /// Removes a policy.
    pub fn remove_policy(&self, id: &str) {
        self.policies.write().remove(id);
    }

    /// Gets a policy.
    pub fn get_policy(&self, id: &str) -> Option<Policy> {
        self.policies.read().get(id).cloned()
    }

    /// Evaluates all policies.
    pub fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: &HashMap<String, String>,
    ) -> PolicyDecision {
        let policies = self.policies.read();

        // Sort policies by priority
        let mut sorted: Vec<&Policy> = policies.values().collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Explicit denies first
        for policy in &sorted {
            if let Some(decision) = policy.evaluate(principal, action, resource, context) {
                if decision.effect == Effect::Deny {
                    return decision;
                }
            }
        }

        // Then allows
        for policy in &sorted {
            if let Some(decision) = policy.evaluate(principal, action, resource, context) {
                if decision.effect == Effect::Allow {
                    return decision;
                }
            }
        }

        // Default decision
        match self.default_effect {
            Effect::Allow => PolicyDecision::allow(),
            Effect::Deny => PolicyDecision::deny("No matching policy found"),
        }
    }

    /// Lists all policies.
    pub fn list_policies(&self) -> Vec<Policy> {
        self.policies.read().values().cloned().collect()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statement_matching() {
        let stmt = Statement::allow()
            .for_principals(["user:*"])
            .for_actions(["read", "list"])
            .on_resources(["dataset:*"]);

        assert!(stmt.matches("user:123", "read", "dataset:456"));
        assert!(!stmt.matches("user:123", "delete", "dataset:456"));
        assert!(!stmt.matches("user:123", "read", "record:456"));
    }

    #[test]
    fn test_policy_evaluation() {
        let policy = Policy::new("p1", "Test Policy")
            .with_statement(
                Statement::allow()
                    .for_principals(["user:admin"])
                    .for_actions(["*"])
                    .on_resources(["*"]),
            )
            .with_statement(
                Statement::allow()
                    .for_principals(["user:*"])
                    .for_actions(["read"])
                    .on_resources(["dataset:public-*"]),
            );

        let ctx = HashMap::new();

        // Admin can do anything
        let decision = policy.evaluate("user:admin", "delete", "dataset:123", &ctx);
        assert!(decision.is_some());
        assert!(decision.unwrap().is_allowed());

        // Regular user can read public datasets
        let decision = policy.evaluate("user:john", "read", "dataset:public-1", &ctx);
        assert!(decision.is_some());
        assert!(decision.unwrap().is_allowed());

        // Regular user cannot read private datasets
        let decision = policy.evaluate("user:john", "read", "dataset:private-1", &ctx);
        assert!(decision.is_none());
    }

    #[test]
    fn test_policy_conditions() {
        let policy = Policy::new("p1", "Conditional Policy")
            .with_statement(
                Statement::allow()
                    .for_principals(["*"])
                    .for_actions(["read"])
                    .on_resources(["*"])
                    .when(PolicyCondition::string_equals("tenant", "tenant-123")),
            );

        let mut ctx = HashMap::new();
        ctx.insert("tenant".to_string(), "tenant-123".to_string());

        let decision = policy.evaluate("user:john", "read", "dataset:1", &ctx);
        assert!(decision.is_some());
        assert!(decision.unwrap().is_allowed());

        ctx.insert("tenant".to_string(), "tenant-456".to_string());
        let decision = policy.evaluate("user:john", "read", "dataset:1", &ctx);
        assert!(decision.is_none());
    }

    #[test]
    fn test_policy_engine() {
        let engine = PolicyEngine::new();

        engine.add_policy(
            Policy::new("admin", "Admin Policy")
                .with_statement(
                    Statement::allow()
                        .for_principals(["role:admin"])
                        .for_actions(["*"])
                        .on_resources(["*"]),
                )
                .with_priority(100),
        );

        engine.add_policy(
            Policy::new("deny-delete", "Deny Delete")
                .with_statement(
                    Statement::deny()
                        .for_principals(["*"])
                        .for_actions(["delete"])
                        .on_resources(["dataset:protected-*"]),
                )
                .with_priority(200), // Higher priority for deny
        );

        let ctx = HashMap::new();

        // Admin can read protected
        let decision = engine.evaluate("role:admin", "read", "dataset:protected-1", &ctx);
        assert!(decision.is_allowed());

        // But cannot delete protected (explicit deny wins)
        let decision = engine.evaluate("role:admin", "delete", "dataset:protected-1", &ctx);
        assert!(!decision.is_allowed());
    }
}
