//! Role-Based Access Control (RBAC).

use crate::{AccessError, AccessResult, Action, ResourceType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;

/// Permission definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    /// Permission ID.
    pub id: String,
    /// Resource type.
    pub resource_type: String,
    /// Allowed actions.
    pub actions: HashSet<String>,
    /// Optional resource filter (pattern).
    pub resource_filter: Option<String>,
    /// Description.
    pub description: Option<String>,
}

impl std::hash::Hash for Permission {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Permission {
    /// Creates a new permission.
    pub fn new(
        id: impl Into<String>,
        resource_type: impl Into<String>,
        actions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            id: id.into(),
            resource_type: resource_type.into(),
            actions: actions.into_iter().map(|a| a.into()).collect(),
            resource_filter: None,
            description: None,
        }
    }

    /// Creates a full CRUD permission.
    pub fn crud(id: impl Into<String>, resource_type: impl Into<String>) -> Self {
        Self::new(
            id,
            resource_type,
            ["create", "read", "update", "delete", "list"],
        )
    }

    /// Creates a read-only permission.
    pub fn read_only(id: impl Into<String>, resource_type: impl Into<String>) -> Self {
        Self::new(id, resource_type, ["read", "list"])
    }

    /// Sets resource filter.
    #[must_use]
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.resource_filter = Some(filter.into());
        self
    }

    /// Sets description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Checks if this permission allows the given action.
    pub fn allows_action(&self, action: &str) -> bool {
        self.actions.contains("*") || self.actions.contains(action)
    }

    /// Checks if this permission applies to the resource type.
    pub fn applies_to(&self, resource_type: &str) -> bool {
        self.resource_type == "*" || self.resource_type == resource_type
    }

    /// Checks if the resource filter matches.
    pub fn matches_resource(&self, resource_id: Option<&str>) -> bool {
        match (&self.resource_filter, resource_id) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(filter), Some(id)) => {
                if filter == "*" {
                    return true;
                }
                // Simple glob matching
                let pattern = filter.replace('*', ".*");
                regex::Regex::new(&format!("^{}$", pattern))
                    .map(|r| r.is_match(id))
                    .unwrap_or(false)
            }
        }
    }
}

/// Role definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role ID.
    pub id: String,
    /// Role name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Permission IDs assigned to this role.
    pub permissions: HashSet<String>,
    /// Parent roles (for inheritance).
    pub parents: HashSet<String>,
    /// Tenant ID (for tenant-scoped roles).
    pub tenant_id: Option<String>,
    /// Is system role (cannot be deleted).
    pub is_system: bool,
    /// Metadata.
    pub metadata: HashMap<String, String>,
}

impl Role {
    /// Creates a new role.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            permissions: HashSet::new(),
            parents: HashSet::new(),
            tenant_id: None,
            is_system: false,
            metadata: HashMap::new(),
        }
    }

    /// Creates a system role.
    pub fn system(id: impl Into<String>, name: impl Into<String>) -> Self {
        let mut role = Self::new(id, name);
        role.is_system = true;
        role
    }

    /// Adds a permission.
    #[must_use]
    pub fn with_permission(mut self, permission_id: impl Into<String>) -> Self {
        self.permissions.insert(permission_id.into());
        self
    }

    /// Adds multiple permissions.
    #[must_use]
    pub fn with_permissions(mut self, permission_ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for id in permission_ids {
            self.permissions.insert(id.into());
        }
        self
    }

    /// Adds a parent role.
    #[must_use]
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parents.insert(parent_id.into());
        self
    }

    /// Sets tenant.
    #[must_use]
    pub fn in_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// RBAC manager.
pub struct RbacManager {
    roles: RwLock<HashMap<String, Role>>,
    permissions: RwLock<HashMap<String, Permission>>,
    user_roles: RwLock<HashMap<String, HashSet<String>>>,
}

impl RbacManager {
    /// Creates a new RBAC manager.
    #[must_use]
    pub fn new() -> Self {
        let manager = Self {
            roles: RwLock::new(HashMap::new()),
            permissions: RwLock::new(HashMap::new()),
            user_roles: RwLock::new(HashMap::new()),
        };

        // Initialize with built-in roles and permissions
        manager.initialize_builtins();

        manager
    }

    fn initialize_builtins(&self) {
        // Built-in permissions
        let builtin_permissions = vec![
            Permission::new("datasets:read", "dataset", ["read", "list"]),
            Permission::new("datasets:write", "dataset", ["create", "update", "delete"]),
            Permission::new("datasets:admin", "dataset", ["*"]),
            Permission::new("records:read", "record", ["read", "list"]),
            Permission::new("records:write", "record", ["create", "update", "delete"]),
            Permission::new("records:admin", "record", ["*"]),
            Permission::new("users:read", "user", ["read", "list"]),
            Permission::new("users:write", "user", ["create", "update"]),
            Permission::new("users:admin", "user", ["*"]),
            Permission::new("roles:read", "role", ["read", "list"]),
            Permission::new("roles:admin", "role", ["*"]),
            Permission::new("policies:read", "policy", ["read", "list"]),
            Permission::new("policies:admin", "policy", ["*"]),
            Permission::new("audit:read", "audit_log", ["read", "list"]),
            Permission::new("system:admin", "system", ["*"]),
        ];

        {
            let mut perms = self.permissions.write();
            for perm in builtin_permissions {
                perms.insert(perm.id.clone(), perm);
            }
        }

        // Built-in roles
        let builtin_roles = vec![
            Role::system("admin", "Administrator")
                .with_permissions(["system:admin"])
                .with_description("Full system access"),
            Role::system("data-admin", "Data Administrator")
                .with_permissions([
                    "datasets:admin",
                    "records:admin",
                ])
                .with_description("Full data access"),
            Role::system("data-analyst", "Data Analyst")
                .with_permissions([
                    "datasets:read",
                    "records:read",
                ])
                .with_description("Read-only data access"),
            Role::system("auditor", "Auditor")
                .with_permissions([
                    "audit:read",
                    "datasets:read",
                    "records:read",
                ])
                .with_description("Audit and read access"),
            Role::system("user-admin", "User Administrator")
                .with_permissions([
                    "users:admin",
                    "roles:read",
                ])
                .with_description("User management access"),
        ];

        {
            let mut roles = self.roles.write();
            for role in builtin_roles {
                roles.insert(role.id.clone(), role);
            }
        }
    }

    /// Adds a permission.
    pub fn add_permission(&self, permission: Permission) {
        self.permissions.write().insert(permission.id.clone(), permission);
    }

    /// Gets a permission by ID.
    pub fn get_permission(&self, id: &str) -> Option<Permission> {
        self.permissions.read().get(id).cloned()
    }

    /// Adds a role.
    pub fn add_role(&self, role: Role) {
        self.roles.write().insert(role.id.clone(), role);
    }

    /// Gets a role by ID.
    pub fn get_role(&self, id: &str) -> Option<Role> {
        self.roles.read().get(id).cloned()
    }

    /// Deletes a role.
    pub fn delete_role(&self, id: &str) -> AccessResult<()> {
        let mut roles = self.roles.write();
        if let Some(role) = roles.get(id) {
            if role.is_system {
                return Err(AccessError::Forbidden(
                    "Cannot delete system role".to_string(),
                ));
            }
        }
        roles.remove(id);
        Ok(())
    }

    /// Assigns a role to a user.
    pub fn assign_role(&self, user_id: &str, role_id: &str) -> AccessResult<()> {
        // Verify role exists
        if !self.roles.read().contains_key(role_id) {
            return Err(AccessError::RoleNotFound(role_id.to_string()));
        }

        self.user_roles
            .write()
            .entry(user_id.to_string())
            .or_default()
            .insert(role_id.to_string());

        Ok(())
    }

    /// Removes a role from a user.
    pub fn revoke_role(&self, user_id: &str, role_id: &str) {
        if let Some(roles) = self.user_roles.write().get_mut(user_id) {
            roles.remove(role_id);
        }
    }

    /// Gets all roles for a user.
    pub fn get_user_roles(&self, user_id: &str) -> Vec<Role> {
        let role_ids = self
            .user_roles
            .read()
            .get(user_id)
            .cloned()
            .unwrap_or_default();

        let roles = self.roles.read();
        let mut result = Vec::new();

        // Get direct roles and inherited roles
        let mut to_process: Vec<String> = role_ids.into_iter().collect();
        let mut processed = HashSet::new();

        while let Some(role_id) = to_process.pop() {
            if processed.contains(&role_id) {
                continue;
            }
            processed.insert(role_id.clone());

            if let Some(role) = roles.get(&role_id) {
                result.push(role.clone());

                // Add parent roles
                for parent_id in &role.parents {
                    if !processed.contains(parent_id) {
                        to_process.push(parent_id.clone());
                    }
                }
            }
        }

        result
    }

    /// Gets all effective permissions for a user.
    pub fn get_user_permissions(&self, user_id: &str) -> Vec<Permission> {
        let user_roles = self.get_user_roles(user_id);
        let permissions = self.permissions.read();

        let mut result = HashSet::new();

        for role in &user_roles {
            for perm_id in &role.permissions {
                if let Some(perm) = permissions.get(perm_id) {
                    result.insert(perm.clone());
                }
            }
        }

        result.into_iter().collect()
    }

    /// Checks if a user has a specific permission.
    pub fn check_permission(
        &self,
        user_id: &str,
        resource_type: &str,
        action: &str,
        resource_id: Option<&str>,
    ) -> bool {
        let permissions = self.get_user_permissions(user_id);

        permissions.iter().any(|perm| {
            perm.applies_to(resource_type)
                && perm.allows_action(action)
                && perm.matches_resource(resource_id)
        })
    }

    /// Lists all roles.
    pub fn list_roles(&self) -> Vec<Role> {
        self.roles.read().values().cloned().collect()
    }

    /// Lists all permissions.
    pub fn list_permissions(&self) -> Vec<Permission> {
        self.permissions.read().values().cloned().collect()
    }
}

impl Default for RbacManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_creation() {
        let perm = Permission::crud("datasets:crud", "dataset");
        assert!(perm.allows_action("create"));
        assert!(perm.allows_action("read"));
        assert!(perm.allows_action("update"));
        assert!(perm.allows_action("delete"));
        assert!(!perm.allows_action("admin"));
    }

    #[test]
    fn test_permission_wildcard() {
        let perm = Permission::new("all", "*", ["*"]);
        assert!(perm.allows_action("anything"));
        assert!(perm.applies_to("anything"));
    }

    #[test]
    fn test_role_permissions() {
        let role = Role::new("test", "Test Role")
            .with_permissions(["perm1", "perm2"]);

        assert!(role.permissions.contains("perm1"));
        assert!(role.permissions.contains("perm2"));
    }

    #[test]
    fn test_rbac_manager() {
        let manager = RbacManager::new();

        // Assign admin role
        manager.assign_role("user1", "admin").unwrap();

        // Check permissions
        assert!(manager.check_permission("user1", "system", "admin", None));
        assert!(manager.check_permission("user1", "system", "anything", None));
    }

    #[test]
    fn test_role_inheritance() {
        let manager = RbacManager::new();

        // Create child role
        let child = Role::new("child", "Child Role")
            .with_parent("data-analyst");
        manager.add_role(child);

        manager.assign_role("user1", "child").unwrap();

        // Should inherit data-analyst permissions
        let roles = manager.get_user_roles("user1");
        assert!(roles.iter().any(|r| r.id == "child"));
        assert!(roles.iter().any(|r| r.id == "data-analyst"));
    }

    #[test]
    fn test_permission_filter() {
        let perm = Permission::new("datasets:tenant", "dataset", ["read"])
            .with_filter("tenant-*");

        assert!(perm.matches_resource(Some("tenant-123")));
        assert!(!perm.matches_resource(Some("other-123")));
    }
}
