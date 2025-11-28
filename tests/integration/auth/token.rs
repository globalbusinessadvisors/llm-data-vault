//! Token management integration tests.

use vault_access::{TokenManager, TokenConfig, TokenClaims};
use chrono::{Duration, Utc};

/// Creates a test token manager.
fn create_token_manager() -> TokenManager {
    let config = TokenConfig {
        secret: "test_jwt_secret_at_least_32_characters_long".to_string(),
        issuer: "test-issuer".to_string(),
        audience: Some("test-audience".to_string()),
        access_token_ttl: 3600, // 1 hour
        refresh_token_ttl: 86400, // 24 hours
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    TokenManager::new(config)
}

/// Tests generating an access token.
#[tokio::test]
async fn test_generate_access_token() {
    let manager = create_token_manager();

    let claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let token = manager.generate_access_token(&claims).expect("Token generation failed");

    assert!(!token.is_empty());
    assert!(token.starts_with("eyJ")); // JWT header starts with eyJ
}

/// Tests generating a refresh token.
#[tokio::test]
async fn test_generate_refresh_token() {
    let manager = create_token_manager();

    let claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::days(7),
    );

    let token = manager.generate_refresh_token(&claims).expect("Token generation failed");

    assert!(!token.is_empty());
}

/// Tests validating a valid token.
#[tokio::test]
async fn test_validate_valid_token() {
    let manager = create_token_manager();

    let claims = TokenClaims::new(
        "user-123",
        vec!["admin".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let token = manager.generate_access_token(&claims).unwrap();
    let validated = manager.validate_token(&token).expect("Validation failed");

    assert_eq!(validated.sub, "user-123");
    assert!(validated.roles.contains(&"admin".to_string()));
}

/// Tests validating an expired token.
#[tokio::test]
async fn test_validate_expired_token() {
    let manager = create_token_manager();

    // Create claims that are already expired
    let claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::seconds(-10), // Already expired
    );

    let token = manager.generate_access_token(&claims).unwrap();
    let result = manager.validate_token(&token);

    assert!(result.is_err());
}

/// Tests validating a token with wrong secret.
#[tokio::test]
async fn test_validate_wrong_secret() {
    let manager1 = create_token_manager();

    let config2 = TokenConfig {
        secret: "different_secret_at_least_32_characters".to_string(),
        issuer: "test-issuer".to_string(),
        audience: Some("test-audience".to_string()),
        access_token_ttl: 3600,
        refresh_token_ttl: 86400,
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    let manager2 = TokenManager::new(config2);

    let claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    // Generate with manager1
    let token = manager1.generate_access_token(&claims).unwrap();

    // Validate with manager2 (different secret)
    let result = manager2.validate_token(&token);

    assert!(result.is_err());
}

/// Tests validating a malformed token.
#[tokio::test]
async fn test_validate_malformed_token() {
    let manager = create_token_manager();

    let result = manager.validate_token("not-a-valid-jwt-token");

    assert!(result.is_err());
}

/// Tests validating an empty token.
#[tokio::test]
async fn test_validate_empty_token() {
    let manager = create_token_manager();

    let result = manager.validate_token("");

    assert!(result.is_err());
}

/// Tests token claims include required fields.
#[tokio::test]
async fn test_token_claims_fields() {
    let manager = create_token_manager();

    let claims = TokenClaims::new(
        "user-123",
        vec!["admin".to_string(), "user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let token = manager.generate_access_token(&claims).unwrap();
    let validated = manager.validate_token(&token).unwrap();

    assert_eq!(validated.sub, "user-123");
    assert_eq!(validated.iss, "test-issuer");
    assert_eq!(validated.aud, Some("test-audience".to_string()));
    assert!(validated.exp > Utc::now().timestamp());
    assert!(validated.iat <= Utc::now().timestamp());
}

/// Tests generating tokens for different users.
#[tokio::test]
async fn test_tokens_for_different_users() {
    let manager = create_token_manager();

    let claims1 = TokenClaims::new(
        "user-1",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let claims2 = TokenClaims::new(
        "user-2",
        vec!["admin".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let token1 = manager.generate_access_token(&claims1).unwrap();
    let token2 = manager.generate_access_token(&claims2).unwrap();

    // Tokens should be different
    assert_ne!(token1, token2);

    // Each should validate to correct user
    let validated1 = manager.validate_token(&token1).unwrap();
    let validated2 = manager.validate_token(&token2).unwrap();

    assert_eq!(validated1.sub, "user-1");
    assert_eq!(validated2.sub, "user-2");
}

/// Tests token with multiple roles.
#[tokio::test]
async fn test_token_multiple_roles() {
    let manager = create_token_manager();

    let claims = TokenClaims::new(
        "user-123",
        vec!["admin".to_string(), "user".to_string(), "moderator".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let token = manager.generate_access_token(&claims).unwrap();
    let validated = manager.validate_token(&token).unwrap();

    assert_eq!(validated.roles.len(), 3);
    assert!(validated.roles.contains(&"admin".to_string()));
    assert!(validated.roles.contains(&"user".to_string()));
    assert!(validated.roles.contains(&"moderator".to_string()));
}

/// Tests token without audience.
#[tokio::test]
async fn test_token_without_audience() {
    let config = TokenConfig {
        secret: "test_jwt_secret_at_least_32_characters_long".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        access_token_ttl: 3600,
        refresh_token_ttl: 86400,
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    let manager = TokenManager::new(config);

    let claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        None,
        Duration::hours(1),
    );

    let token = manager.generate_access_token(&claims).unwrap();
    let validated = manager.validate_token(&token).unwrap();

    assert!(validated.aud.is_none());
}

/// Tests refresh token expiry is longer than access token.
#[tokio::test]
async fn test_refresh_token_longer_expiry() {
    let manager = create_token_manager();

    let access_claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let refresh_claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::days(7),
    );

    let access_token = manager.generate_access_token(&access_claims).unwrap();
    let refresh_token = manager.generate_refresh_token(&refresh_claims).unwrap();

    let access_validated = manager.validate_token(&access_token).unwrap();
    let refresh_validated = manager.validate_token(&refresh_token).unwrap();

    assert!(refresh_validated.exp > access_validated.exp);
}

/// Tests token generation is idempotent (same claims produce same structure).
#[tokio::test]
async fn test_token_generation_structure() {
    let manager = create_token_manager();

    let claims = TokenClaims::new(
        "user-123",
        vec!["user".to_string()],
        "test-issuer",
        Some("test-audience".to_string()),
        Duration::hours(1),
    );

    let token1 = manager.generate_access_token(&claims).unwrap();
    let token2 = manager.generate_access_token(&claims).unwrap();

    // Tokens will be different (different iat times), but should have same structure
    let validated1 = manager.validate_token(&token1).unwrap();
    let validated2 = manager.validate_token(&token2).unwrap();

    assert_eq!(validated1.sub, validated2.sub);
    assert_eq!(validated1.roles, validated2.roles);
    assert_eq!(validated1.iss, validated2.iss);
}

/// Tests concurrent token generation.
#[tokio::test]
async fn test_concurrent_token_generation() {
    let manager = std::sync::Arc::new(create_token_manager());

    let mut handles = vec![];

    for i in 0..100 {
        let manager = manager.clone();
        handles.push(tokio::spawn(async move {
            let claims = TokenClaims::new(
                &format!("user-{}", i),
                vec!["user".to_string()],
                "test-issuer",
                Some("test-audience".to_string()),
                Duration::hours(1),
            );
            manager.generate_access_token(&claims)
        }));
    }

    for handle in handles {
        let result = handle.await.expect("Task panicked");
        assert!(result.is_ok());
    }
}
