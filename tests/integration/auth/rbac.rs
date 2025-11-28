//! RBAC (Role-Based Access Control) integration tests.

use vault_access::{
    RbacManager, Role, Permission, Authorizer, AuthRequest, AuthContext,
    AbacEngine, PolicyEngine, ResourceType, Action, ResourceId,
};
use std::sync::Arc;

/// Creates a test RBAC manager with default roles.
fn create_rbac_manager() -> RbacManager {
    let mut rbac = RbacManager::new();

    // Admin role - full access
    let admin_role = Role::new("admin")
        .with_permission(Permission::new("*", "*"))
        .with_description("Administrator with full access");
    rbac.add_role(admin_role);

    // User role - standard access
    let user_role = Role::new("user")
        .with_permission(Permission::new("dataset", "read"))
        .with_permission(Permission::new("dataset", "create"))
        .with_permission(Permission::new("dataset", "update"))
        .with_permission(Permission::new("record", "read"))
        .with_permission(Permission::new("record", "create"))
        .with_description("Standard user access");
    rbac.add_role(user_role);

    // Reader role - read-only access
    let reader_role = Role::new("reader")
        .with_permission(Permission::new("dataset", "read"))
        .with_permission(Permission::new("record", "read"))
        .with_description("Read-only access");
    rbac.add_role(reader_role);

    // Moderator role
    let moderator_role = Role::new("moderator")
        .with_permission(Permission::new("dataset", "read"))
        .with_permission(Permission::new("dataset", "update"))
        .with_permission(Permission::new("record", "read"))
        .with_permission(Permission::new("record", "update"))
        .with_permission(Permission::new("record", "delete"))
        .with_description("Moderator access");
    rbac.add_role(moderator_role);

    rbac
}

/// Creates a test authorizer.
fn create_authorizer() -> Authorizer {
    let rbac = create_rbac_manager();
    let abac = AbacEngine::new();
    let policy = PolicyEngine::new();
    Authorizer::new(rbac, abac, policy, true)
}

/// Tests role creation and retrieval.
#[test]
fn test_role_creation() {
    let rbac = create_rbac_manager();

    let admin = rbac.get_role("admin");
    assert!(admin.is_some());
    assert_eq!(admin.unwrap().name(), "admin");

    let user = rbac.get_role("user");
    assert!(user.is_some());

    let nonexistent = rbac.get_role("nonexistent");
    assert!(nonexistent.is_none());
}

/// Tests permission checking for admin role.
#[test]
fn test_admin_permissions() {
    let rbac = create_rbac_manager();

    // Admin should have access to everything
    assert!(rbac.has_permission("admin", "dataset", "read"));
    assert!(rbac.has_permission("admin", "dataset", "create"));
    assert!(rbac.has_permission("admin", "dataset", "delete"));
    assert!(rbac.has_permission("admin", "record", "read"));
    assert!(rbac.has_permission("admin", "any_resource", "any_action"));
}

/// Tests permission checking for user role.
#[test]
fn test_user_permissions() {
    let rbac = create_rbac_manager();

    // User should have standard permissions
    assert!(rbac.has_permission("user", "dataset", "read"));
    assert!(rbac.has_permission("user", "dataset", "create"));
    assert!(rbac.has_permission("user", "dataset", "update"));
    assert!(rbac.has_permission("user", "record", "read"));
    assert!(rbac.has_permission("user", "record", "create"));

    // User should not have delete permissions
    assert!(!rbac.has_permission("user", "dataset", "delete"));
    assert!(!rbac.has_permission("user", "record", "delete"));
}

/// Tests permission checking for reader role.
#[test]
fn test_reader_permissions() {
    let rbac = create_rbac_manager();

    // Reader should only have read access
    assert!(rbac.has_permission("reader", "dataset", "read"));
    assert!(rbac.has_permission("reader", "record", "read"));

    // Reader should not have write permissions
    assert!(!rbac.has_permission("reader", "dataset", "create"));
    assert!(!rbac.has_permission("reader", "dataset", "update"));
    assert!(!rbac.has_permission("reader", "dataset", "delete"));
    assert!(!rbac.has_permission("reader", "record", "create"));
}

/// Tests adding a custom role.
#[test]
fn test_add_custom_role() {
    let mut rbac = create_rbac_manager();

    let custom_role = Role::new("data_scientist")
        .with_permission(Permission::new("dataset", "read"))
        .with_permission(Permission::new("record", "read"))
        .with_permission(Permission::new("model", "create"))
        .with_description("Data scientist role");

    rbac.add_role(custom_role);

    assert!(rbac.get_role("data_scientist").is_some());
    assert!(rbac.has_permission("data_scientist", "dataset", "read"));
    assert!(rbac.has_permission("data_scientist", "model", "create"));
}

/// Tests removing a role.
#[test]
fn test_remove_role() {
    let mut rbac = create_rbac_manager();

    assert!(rbac.get_role("reader").is_some());

    rbac.remove_role("reader");

    assert!(rbac.get_role("reader").is_none());
}

/// Tests listing all roles.
#[test]
fn test_list_roles() {
    let rbac = create_rbac_manager();

    let roles = rbac.list_roles();

    assert!(roles.len() >= 4);
    assert!(roles.iter().any(|r| r.name() == "admin"));
    assert!(roles.iter().any(|r| r.name() == "user"));
    assert!(roles.iter().any(|r| r.name() == "reader"));
}

/// Tests authorizer with admin context.
#[test]
fn test_authorizer_admin() {
    let authorizer = create_authorizer();

    let context = AuthContext::new("admin-user", vec!["admin".to_string()]);
    let request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Delete,
    );

    let response = authorizer.authorize(&context, &request);

    assert!(response.allowed);
}

/// Tests authorizer with user context.
#[test]
fn test_authorizer_user() {
    let authorizer = create_authorizer();

    let context = AuthContext::new("regular-user", vec!["user".to_string()]);

    // User should be able to read
    let read_request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Read,
    );
    assert!(authorizer.authorize(&context, &read_request).allowed);

    // User should be able to create
    let create_request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Create,
    );
    assert!(authorizer.authorize(&context, &create_request).allowed);

    // User should not be able to delete
    let delete_request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Delete,
    );
    assert!(!authorizer.authorize(&context, &delete_request).allowed);
}

/// Tests authorizer with reader context.
#[test]
fn test_authorizer_reader() {
    let authorizer = create_authorizer();

    let context = AuthContext::new("reader-user", vec!["reader".to_string()]);

    // Reader should be able to read
    let read_request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Read,
    );
    assert!(authorizer.authorize(&context, &read_request).allowed);

    // Reader should not be able to create
    let create_request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Create,
    );
    assert!(!authorizer.authorize(&context, &create_request).allowed);
}

/// Tests authorizer with multiple roles.
#[test]
fn test_authorizer_multiple_roles() {
    let authorizer = create_authorizer();

    // User with both reader and moderator roles
    let context = AuthContext::new("multi-role-user", vec![
        "reader".to_string(),
        "moderator".to_string(),
    ]);

    // Should have combined permissions
    let read_request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Read,
    );
    assert!(authorizer.authorize(&context, &read_request).allowed);

    // Should have moderator's delete permission for records
    let delete_request = AuthRequest::new(
        ResourceId::new(ResourceType::Record),
        Action::Delete,
    );
    assert!(authorizer.authorize(&context, &delete_request).allowed);
}

/// Tests authorizer with no roles.
#[test]
fn test_authorizer_no_roles() {
    let authorizer = create_authorizer();

    let context = AuthContext::new("no-role-user", vec![]);

    let request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Read,
    );

    let response = authorizer.authorize(&context, &request);
    assert!(!response.allowed);
}

/// Tests authorizer with unknown role.
#[test]
fn test_authorizer_unknown_role() {
    let authorizer = create_authorizer();

    let context = AuthContext::new("user", vec!["nonexistent_role".to_string()]);

    let request = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Read,
    );

    let response = authorizer.authorize(&context, &request);
    assert!(!response.allowed);
}

/// Tests resource-specific permissions.
#[test]
fn test_resource_specific_permissions() {
    let authorizer = create_authorizer();

    let context = AuthContext::new("user", vec!["user".to_string()]);

    // Dataset permissions
    let dataset_read = AuthRequest::new(
        ResourceId::new(ResourceType::Dataset),
        Action::Read,
    );
    assert!(authorizer.authorize(&context, &dataset_read).allowed);

    // Record permissions
    let record_read = AuthRequest::new(
        ResourceId::new(ResourceType::Record),
        Action::Read,
    );
    assert!(authorizer.authorize(&context, &record_read).allowed);

    // Schema permissions (user doesn't have)
    let schema_create = AuthRequest::new(
        ResourceId::new(ResourceType::Schema),
        Action::Create,
    );
    assert!(!authorizer.authorize(&context, &schema_create).allowed);
}

/// Tests permission inheritance.
#[test]
fn test_permission_inheritance() {
    let mut rbac = RbacManager::new();

    // Base role
    let base_role = Role::new("base")
        .with_permission(Permission::new("dataset", "read"));
    rbac.add_role(base_role);

    // Extended role (inherits from base conceptually)
    let extended_role = Role::new("extended")
        .with_permission(Permission::new("dataset", "read"))
        .with_permission(Permission::new("dataset", "create"));
    rbac.add_role(extended_role);

    assert!(rbac.has_permission("base", "dataset", "read"));
    assert!(!rbac.has_permission("base", "dataset", "create"));

    assert!(rbac.has_permission("extended", "dataset", "read"));
    assert!(rbac.has_permission("extended", "dataset", "create"));
}

/// Tests concurrent authorization checks.
#[tokio::test]
async fn test_concurrent_authorization() {
    let authorizer = Arc::new(create_authorizer());

    let mut handles = vec![];

    for i in 0..100 {
        let authorizer = authorizer.clone();
        handles.push(tokio::spawn(async move {
            let role = if i % 3 == 0 { "admin" } else if i % 2 == 0 { "user" } else { "reader" };
            let context = AuthContext::new(&format!("user-{}", i), vec![role.to_string()]);
            let request = AuthRequest::new(
                ResourceId::new(ResourceType::Dataset),
                Action::Read,
            );
            authorizer.authorize(&context, &request)
        }));
    }

    for handle in handles {
        let response = handle.await.expect("Task panicked");
        // All should be able to read
        assert!(response.allowed);
    }
}
