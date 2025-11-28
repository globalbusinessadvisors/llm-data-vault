//! Authentication service.

use std::sync::Arc;

use crate::error::Result;
use crate::models::{LoginRequest, TokenResponse, RefreshTokenRequest, User, SessionInfo};

use super::super::http::HttpClient;

/// Service for authentication operations.
#[derive(Clone)]
pub struct AuthService {
    http: Arc<HttpClient>,
}

impl AuthService {
    /// Creates a new authentication service.
    pub(crate) fn new(http: Arc<HttpClient>) -> Self {
        Self { http }
    }

    /// Logs in with username and password.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let token = client.auth().login("user@example.com", "password123").await?;
    ///
    /// println!("Access token: {}", token.access_token);
    /// println!("Expires in: {} seconds", token.expires_in);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login(&self, username: &str, password: &str) -> Result<TokenResponse> {
        let request = LoginRequest::new(username, password);
        self.http.post("/api/v1/auth/login", &request).await
    }

    /// Logs in with MFA code.
    pub async fn login_with_mfa(
        &self,
        username: &str,
        password: &str,
        mfa_code: &str,
    ) -> Result<TokenResponse> {
        let request = LoginRequest::new(username, password).with_mfa(mfa_code);
        self.http.post("/api/v1/auth/login", &request).await
    }

    /// Refreshes an access token using a refresh token.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let new_token = client.auth().refresh("refresh_token_here").await?;
    /// println!("New access token: {}", new_token.access_token);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        let request = RefreshTokenRequest {
            refresh_token: refresh_token.to_string(),
        };
        self.http.post("/api/v1/auth/refresh", &request).await
    }

    /// Logs out and invalidates the current session.
    pub async fn logout(&self) -> Result<()> {
        self.http.post::<(), _>("/api/v1/auth/logout", &()).await?;
        Ok(())
    }

    /// Gets the current user's profile.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let user = client.auth().me().await?;
    /// println!("Logged in as: {} ({})", user.username, user.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn me(&self) -> Result<User> {
        self.http.get("/api/v1/auth/me").await
    }

    /// Gets the current session information.
    pub async fn session(&self) -> Result<SessionInfo> {
        self.http.get("/api/v1/auth/session").await
    }

    /// Verifies that the current token is valid.
    pub async fn verify(&self) -> Result<bool> {
        match self.me().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService").finish_non_exhaustive()
    }
}
