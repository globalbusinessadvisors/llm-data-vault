//! Enterprise Security Hardening for LLM Data Vault.
//!
//! This crate provides comprehensive security hardening features including:
//!
//! - **Configuration Security**: Secure configuration management with validation
//! - **Secrets Management**: Encrypted secrets storage and rotation
//! - **Request Security**: Request signing, verification, and replay protection
//! - **Input Validation**: Comprehensive input sanitization and validation
//! - **Security Headers**: HTTP security headers middleware
//! - **Threat Detection**: Rate limiting, IP blocking, and anomaly detection
//! - **Session Management**: Secure distributed session handling
//! - **Audit Hardening**: Immutable audit logs with integrity verification
//!
//! # Example
//!
//! ```rust,no_run
//! use vault_security::{SecurityConfig, SecurityService};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load security configuration
//!     let config = SecurityConfig::from_env()?;
//!
//!     // Initialize security service
//!     let security = SecurityService::new(config)?;
//!
//!     // Validate configuration
//!     security.validate_configuration()?;
//!
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod error;
pub mod headers;
pub mod input;
pub mod secrets;
pub mod session;
pub mod signing;
pub mod threat;
pub mod audit;

pub use config::{SecurityConfig, SecurityConfigBuilder, TlsConfig, CorsSecurityConfig, RateLimitConfig};
pub use error::{SecurityError, Result, ThreatLevel};
pub use headers::{SecurityHeaders, SecurityHeadersLayer};
pub use input::{InputValidator, SanitizationRules, ValidationResult};
pub use secrets::{SecretStore, SecretValue, EncryptedSecret};
pub use session::{SessionManager, Session, SessionId};
pub use signing::{RequestSigner, SignatureVerifier, SignedRequest};
pub use threat::{ThreatDetector, IpBlocklist};
pub use audit::{SecureAuditLog, AuditEntry, AuditIntegrity};

use std::sync::Arc;

/// Main security service that coordinates all security components.
#[derive(Clone)]
pub struct SecurityService {
    config: Arc<SecurityConfig>,
    secret_store: Arc<SecretStore>,
    session_manager: Arc<SessionManager>,
    threat_detector: Arc<ThreatDetector>,
    audit_log: Arc<SecureAuditLog>,
    input_validator: Arc<InputValidator>,
    request_signer: Arc<RequestSigner>,
}

impl SecurityService {
    /// Creates a new security service with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or initialization fails.
    pub fn new(config: SecurityConfig) -> Result<Self> {
        config.validate()?;

        let config = Arc::new(config);
        let secret_store = Arc::new(SecretStore::new(config.secrets.clone())?);
        let session_manager = Arc::new(SessionManager::new(config.session.clone()));
        let threat_detector = Arc::new(ThreatDetector::new(config.threat.clone()));
        let audit_log = Arc::new(SecureAuditLog::new(config.audit.clone())?);
        let input_validator = Arc::new(InputValidator::new(config.input.clone()));
        let request_signer = Arc::new(RequestSigner::new(config.signing.clone())?);

        Ok(Self {
            config,
            secret_store,
            session_manager,
            threat_detector,
            audit_log,
            input_validator,
            request_signer,
        })
    }

    /// Validates the entire security configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any configuration is invalid or insecure.
    pub fn validate_configuration(&self) -> Result<()> {
        self.config.validate()
    }

    /// Returns the security configuration.
    #[must_use]
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }

    /// Returns the secret store.
    #[must_use]
    pub fn secrets(&self) -> &SecretStore {
        &self.secret_store
    }

    /// Returns the session manager.
    #[must_use]
    pub fn sessions(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Returns the threat detector.
    #[must_use]
    pub fn threats(&self) -> &ThreatDetector {
        &self.threat_detector
    }

    /// Returns the audit log.
    #[must_use]
    pub fn audit(&self) -> &SecureAuditLog {
        &self.audit_log
    }

    /// Returns the input validator.
    #[must_use]
    pub fn validator(&self) -> &InputValidator {
        &self.input_validator
    }

    /// Returns the request signer.
    #[must_use]
    pub fn signer(&self) -> &RequestSigner {
        &self.request_signer
    }

    /// Creates security headers middleware layer.
    #[must_use]
    pub fn headers_layer(&self) -> SecurityHeadersLayer {
        SecurityHeadersLayer::new(self.config.headers.clone())
    }

    /// Checks if the current environment is production.
    #[must_use]
    pub fn is_production(&self) -> bool {
        self.config.environment == config::Environment::Production
    }
}
