//! Attribute-Based Access Control (ABAC).

use crate::{AccessError, AccessResult, Action, ResourceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Attribute value types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// String value.
    String(String),
    /// Integer value.
    Integer(i64),
    /// Float value.
    Float(f64),
    /// Boolean value.
    Boolean(bool),
    /// List of values.
    List(Vec<AttributeValue>),
    /// Null value.
    Null,
}

impl AttributeValue {
    /// Converts to string if possible.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Converts to integer if possible.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            Self::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    /// Converts to bool if possible.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Checks if this is a list.
    pub fn as_list(&self) -> Option<&Vec<AttributeValue>> {
        match self {
            Self::List(l) => Some(l),
            _ => None,
        }
    }
}

impl From<String> for AttributeValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for AttributeValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<i64> for AttributeValue {
    fn from(i: i64) -> Self {
        Self::Integer(i)
    }
}

impl From<bool> for AttributeValue {
    fn from(b: bool) -> Self {
        Self::Boolean(b)
    }
}

/// Attribute definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    /// Attribute name.
    pub name: String,
    /// Attribute category (subject, resource, action, environment).
    pub category: AttributeCategory,
    /// Data type.
    pub data_type: AttributeType,
    /// Description.
    pub description: Option<String>,
    /// Is required.
    pub required: bool,
    /// Default value.
    pub default_value: Option<AttributeValue>,
}

/// Attribute category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributeCategory {
    /// Subject attributes (user properties).
    Subject,
    /// Resource attributes (data properties).
    Resource,
    /// Action attributes.
    Action,
    /// Environment attributes (time, location, etc.).
    Environment,
}

/// Attribute data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributeType {
    String,
    Integer,
    Float,
    Boolean,
    List,
    Any,
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    /// Equals.
    Eq,
    /// Not equals.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Contains (for lists/strings).
    Contains,
    /// Starts with (for strings).
    StartsWith,
    /// Ends with (for strings).
    EndsWith,
    /// Matches regex.
    Matches,
    /// In list.
    In,
    /// Not in list.
    NotIn,
}

impl ComparisonOp {
    /// Evaluates the comparison.
    pub fn evaluate(&self, left: &AttributeValue, right: &AttributeValue) -> bool {
        match self {
            Self::Eq => left == right,
            Self::Ne => left != right,
            Self::Lt => {
                match (left.as_int(), right.as_int()) {
                    (Some(l), Some(r)) => l < r,
                    _ => false,
                }
            }
            Self::Le => {
                match (left.as_int(), right.as_int()) {
                    (Some(l), Some(r)) => l <= r,
                    _ => false,
                }
            }
            Self::Gt => {
                match (left.as_int(), right.as_int()) {
                    (Some(l), Some(r)) => l > r,
                    _ => false,
                }
            }
            Self::Ge => {
                match (left.as_int(), right.as_int()) {
                    (Some(l), Some(r)) => l >= r,
                    _ => false,
                }
            }
            Self::Contains => {
                match (left, right) {
                    (AttributeValue::String(s), AttributeValue::String(sub)) => {
                        s.contains(sub.as_str())
                    }
                    (AttributeValue::List(list), _) => list.contains(right),
                    _ => false,
                }
            }
            Self::StartsWith => {
                match (left.as_str(), right.as_str()) {
                    (Some(s), Some(prefix)) => s.starts_with(prefix),
                    _ => false,
                }
            }
            Self::EndsWith => {
                match (left.as_str(), right.as_str()) {
                    (Some(s), Some(suffix)) => s.ends_with(suffix),
                    _ => false,
                }
            }
            Self::Matches => {
                match (left.as_str(), right.as_str()) {
                    (Some(s), Some(pattern)) => {
                        regex::Regex::new(pattern)
                            .map(|r| r.is_match(s))
                            .unwrap_or(false)
                    }
                    _ => false,
                }
            }
            Self::In => {
                match right.as_list() {
                    Some(list) => list.contains(left),
                    _ => false,
                }
            }
            Self::NotIn => {
                match right.as_list() {
                    Some(list) => !list.contains(left),
                    _ => true,
                }
            }
        }
    }
}

/// ABAC condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// Attribute name.
    pub attribute: String,
    /// Comparison operator.
    pub operator: ComparisonOp,
    /// Value to compare against.
    pub value: AttributeValue,
}

impl Condition {
    /// Creates a new condition.
    pub fn new(
        attribute: impl Into<String>,
        operator: ComparisonOp,
        value: impl Into<AttributeValue>,
    ) -> Self {
        Self {
            attribute: attribute.into(),
            operator,
            value: value.into(),
        }
    }

    /// Evaluates the condition against attributes.
    pub fn evaluate(&self, attributes: &HashMap<String, AttributeValue>) -> bool {
        match attributes.get(&self.attribute) {
            Some(attr_value) => self.operator.evaluate(attr_value, &self.value),
            None => false,
        }
    }
}

/// Logical operator for combining conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalOp {
    And,
    Or,
    Not,
}

/// ABAC rule (combination of conditions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule conditions.
    pub conditions: Vec<Condition>,
    /// How to combine conditions.
    pub operator: LogicalOp,
    /// Nested rules.
    pub nested_rules: Vec<Rule>,
}

impl Rule {
    /// Creates an AND rule.
    pub fn all(conditions: Vec<Condition>) -> Self {
        Self {
            conditions,
            operator: LogicalOp::And,
            nested_rules: Vec::new(),
        }
    }

    /// Creates an OR rule.
    pub fn any(conditions: Vec<Condition>) -> Self {
        Self {
            conditions,
            operator: LogicalOp::Or,
            nested_rules: Vec::new(),
        }
    }

    /// Creates a single condition rule.
    pub fn single(condition: Condition) -> Self {
        Self {
            conditions: vec![condition],
            operator: LogicalOp::And,
            nested_rules: Vec::new(),
        }
    }

    /// Adds a nested rule.
    #[must_use]
    pub fn with_nested(mut self, rule: Rule) -> Self {
        self.nested_rules.push(rule);
        self
    }

    /// Evaluates the rule against attributes.
    pub fn evaluate(&self, attributes: &HashMap<String, AttributeValue>) -> bool {
        let condition_results: Vec<bool> = self
            .conditions
            .iter()
            .map(|c| c.evaluate(attributes))
            .collect();

        let nested_results: Vec<bool> = self
            .nested_rules
            .iter()
            .map(|r| r.evaluate(attributes))
            .collect();

        let all_results: Vec<bool> = condition_results
            .into_iter()
            .chain(nested_results)
            .collect();

        if all_results.is_empty() {
            return true;
        }

        match self.operator {
            LogicalOp::And => all_results.iter().all(|&r| r),
            LogicalOp::Or => all_results.iter().any(|&r| r),
            LogicalOp::Not => !all_results.iter().any(|&r| r),
        }
    }
}

/// ABAC policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicy {
    /// Policy ID.
    pub id: String,
    /// Policy name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Target resource type.
    pub resource_type: Option<String>,
    /// Target actions.
    pub actions: Vec<String>,
    /// Subject rules (who can access).
    pub subject_rules: Option<Rule>,
    /// Resource rules (what can be accessed).
    pub resource_rules: Option<Rule>,
    /// Environment rules (when/where).
    pub environment_rules: Option<Rule>,
    /// Effect (allow/deny).
    pub effect: PolicyEffect,
    /// Priority (higher = evaluated first).
    pub priority: i32,
    /// Is enabled.
    pub enabled: bool,
}

/// Policy effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl AbacPolicy {
    /// Creates a new allow policy.
    pub fn allow(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            resource_type: None,
            actions: Vec::new(),
            subject_rules: None,
            resource_rules: None,
            environment_rules: None,
            effect: PolicyEffect::Allow,
            priority: 0,
            enabled: true,
        }
    }

    /// Creates a new deny policy.
    pub fn deny(id: impl Into<String>, name: impl Into<String>) -> Self {
        let mut policy = Self::allow(id, name);
        policy.effect = PolicyEffect::Deny;
        policy
    }

    /// Sets resource type.
    #[must_use]
    pub fn for_resource(mut self, resource_type: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self
    }

    /// Sets actions.
    #[must_use]
    pub fn for_actions(mut self, actions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.actions = actions.into_iter().map(|a| a.into()).collect();
        self
    }

    /// Sets subject rules.
    #[must_use]
    pub fn when_subject(mut self, rule: Rule) -> Self {
        self.subject_rules = Some(rule);
        self
    }

    /// Sets resource rules.
    #[must_use]
    pub fn when_resource(mut self, rule: Rule) -> Self {
        self.resource_rules = Some(rule);
        self
    }

    /// Sets environment rules.
    #[must_use]
    pub fn when_environment(mut self, rule: Rule) -> Self {
        self.environment_rules = Some(rule);
        self
    }

    /// Sets priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Checks if the policy applies to the given context.
    pub fn applies_to(
        &self,
        resource_type: Option<&str>,
        action: Option<&str>,
    ) -> bool {
        // Check resource type
        if let Some(ref rt) = self.resource_type {
            if let Some(given_rt) = resource_type {
                if rt != "*" && rt != given_rt {
                    return false;
                }
            }
        }

        // Check action
        if !self.actions.is_empty() {
            if let Some(given_action) = action {
                if !self.actions.iter().any(|a| a == "*" || a == given_action) {
                    return false;
                }
            }
        }

        true
    }

    /// Evaluates the policy against the given attributes.
    pub fn evaluate(&self, context: &AbacContext) -> Option<PolicyEffect> {
        if !self.enabled {
            return None;
        }

        // Check subject rules
        if let Some(ref rules) = self.subject_rules {
            if !rules.evaluate(&context.subject_attributes) {
                return None;
            }
        }

        // Check resource rules
        if let Some(ref rules) = self.resource_rules {
            if !rules.evaluate(&context.resource_attributes) {
                return None;
            }
        }

        // Check environment rules
        if let Some(ref rules) = self.environment_rules {
            if !rules.evaluate(&context.environment_attributes) {
                return None;
            }
        }

        Some(self.effect)
    }
}

/// ABAC evaluation context.
#[derive(Debug, Clone, Default)]
pub struct AbacContext {
    /// Subject (user) attributes.
    pub subject_attributes: HashMap<String, AttributeValue>,
    /// Resource attributes.
    pub resource_attributes: HashMap<String, AttributeValue>,
    /// Action attributes.
    pub action_attributes: HashMap<String, AttributeValue>,
    /// Environment attributes.
    pub environment_attributes: HashMap<String, AttributeValue>,
}

impl AbacContext {
    /// Creates a new context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a subject attribute.
    #[must_use]
    pub fn with_subject(mut self, key: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.subject_attributes.insert(key.into(), value.into());
        self
    }

    /// Adds a resource attribute.
    #[must_use]
    pub fn with_resource(mut self, key: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.resource_attributes.insert(key.into(), value.into());
        self
    }

    /// Adds an environment attribute.
    #[must_use]
    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.environment_attributes.insert(key.into(), value.into());
        self
    }

    /// Adds an action attribute.
    #[must_use]
    pub fn with_action(mut self, key: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.action_attributes.insert(key.into(), value.into());
        self
    }
}

/// ABAC engine.
pub struct AbacEngine {
    policies: RwLock<Vec<AbacPolicy>>,
    default_effect: PolicyEffect,
}

impl AbacEngine {
    /// Creates a new ABAC engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            default_effect: PolicyEffect::Deny,
        }
    }

    /// Creates with default allow.
    #[must_use]
    pub fn default_allow() -> Self {
        Self {
            policies: RwLock::new(Vec::new()),
            default_effect: PolicyEffect::Allow,
        }
    }

    /// Adds a policy.
    pub fn add_policy(&self, policy: AbacPolicy) {
        let mut policies = self.policies.write();
        policies.push(policy);
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Removes a policy.
    pub fn remove_policy(&self, id: &str) {
        self.policies.write().retain(|p| p.id != id);
    }

    /// Gets a policy by ID.
    pub fn get_policy(&self, id: &str) -> Option<AbacPolicy> {
        self.policies.read().iter().find(|p| p.id == id).cloned()
    }

    /// Evaluates access request.
    pub fn evaluate(
        &self,
        context: &AbacContext,
        resource_type: Option<&str>,
        action: Option<&str>,
    ) -> PolicyEffect {
        let policies = self.policies.read();

        for policy in policies.iter() {
            if !policy.applies_to(resource_type, action) {
                continue;
            }

            if let Some(effect) = policy.evaluate(context) {
                return effect;
            }
        }

        self.default_effect
    }

    /// Lists all policies.
    pub fn list_policies(&self) -> Vec<AbacPolicy> {
        self.policies.read().clone()
    }
}

impl Default for AbacEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_evaluation() {
        let mut attrs = HashMap::new();
        attrs.insert("role".to_string(), AttributeValue::String("admin".to_string()));
        attrs.insert("level".to_string(), AttributeValue::Integer(5));

        let cond1 = Condition::new("role", ComparisonOp::Eq, "admin");
        assert!(cond1.evaluate(&attrs));

        let cond2 = Condition::new("level", ComparisonOp::Ge, AttributeValue::Integer(3));
        assert!(cond2.evaluate(&attrs));

        let cond3 = Condition::new("role", ComparisonOp::Eq, "user");
        assert!(!cond3.evaluate(&attrs));
    }

    #[test]
    fn test_rule_and() {
        let mut attrs = HashMap::new();
        attrs.insert("role".to_string(), AttributeValue::String("admin".to_string()));
        attrs.insert("active".to_string(), AttributeValue::Boolean(true));

        let rule = Rule::all(vec![
            Condition::new("role", ComparisonOp::Eq, "admin"),
            Condition::new("active", ComparisonOp::Eq, AttributeValue::Boolean(true)),
        ]);

        assert!(rule.evaluate(&attrs));

        attrs.insert("active".to_string(), AttributeValue::Boolean(false));
        assert!(!rule.evaluate(&attrs));
    }

    #[test]
    fn test_rule_or() {
        let mut attrs = HashMap::new();
        attrs.insert("role".to_string(), AttributeValue::String("user".to_string()));

        let rule = Rule::any(vec![
            Condition::new("role", ComparisonOp::Eq, "admin"),
            Condition::new("role", ComparisonOp::Eq, "user"),
        ]);

        assert!(rule.evaluate(&attrs));
    }

    #[test]
    fn test_abac_policy() {
        let policy = AbacPolicy::allow("p1", "Admin Access")
            .for_resource("dataset")
            .for_actions(["read", "write"])
            .when_subject(Rule::single(Condition::new("role", ComparisonOp::Eq, "admin")));

        let context = AbacContext::new()
            .with_subject("role", "admin");

        assert_eq!(policy.evaluate(&context), Some(PolicyEffect::Allow));

        let context2 = AbacContext::new()
            .with_subject("role", "user");

        assert_eq!(policy.evaluate(&context2), None);
    }

    #[test]
    fn test_abac_engine() {
        let engine = AbacEngine::new();

        engine.add_policy(
            AbacPolicy::allow("admin-all", "Admin Full Access")
                .when_subject(Rule::single(Condition::new("role", ComparisonOp::Eq, "admin")))
                .with_priority(100),
        );

        engine.add_policy(
            AbacPolicy::allow("user-read", "User Read Access")
                .for_actions(["read"])
                .when_subject(Rule::single(Condition::new("role", ComparisonOp::Eq, "user")))
                .with_priority(50),
        );

        // Admin should have access
        let admin_ctx = AbacContext::new().with_subject("role", "admin");
        assert_eq!(engine.evaluate(&admin_ctx, None, Some("write")), PolicyEffect::Allow);

        // User should only have read access
        let user_ctx = AbacContext::new().with_subject("role", "user");
        assert_eq!(engine.evaluate(&user_ctx, None, Some("read")), PolicyEffect::Allow);
        assert_eq!(engine.evaluate(&user_ctx, None, Some("write")), PolicyEffect::Deny);
    }
}
