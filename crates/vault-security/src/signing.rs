//! Request signing and verification.
//!
//! Provides HMAC-based request signing for:
//! - API request authentication
//! - Replay attack prevention via nonces
//! - Signature expiration handling
//! - Webhook payload verification

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use tracing::{debug, warn};

use crate::config::SigningConfig;
use crate::error::{SecurityError, Result};

type HmacSha256 = Hmac<Sha256>;

/// A signed request with signature metadata.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// The signature.
    pub signature: String,
    /// When the request was signed.
    pub timestamp: DateTime<Utc>,
    /// Unique nonce for replay protection.
    pub nonce: String,
    /// Headers that were signed.
    pub signed_headers: Vec<String>,
    /// Algorithm used for signing.
    pub algorithm: String,
}

impl SignedRequest {
    /// Creates a new signed request.
    #[must_use]
    pub fn new(
        signature: String,
        timestamp: DateTime<Utc>,
        nonce: String,
        signed_headers: Vec<String>,
    ) -> Self {
        Self {
            signature,
            timestamp,
            nonce,
            signed_headers,
            algorithm: "HMAC-SHA256".to_string(),
        }
    }

    /// Returns the signature header value.
    #[must_use]
    pub fn to_header(&self) -> String {
        format!(
            "algorithm={},timestamp={},nonce={},signed_headers={},signature={}",
            self.algorithm,
            self.timestamp.timestamp(),
            self.nonce,
            self.signed_headers.join(";"),
            self.signature
        )
    }

    /// Parses a signature from a header value.
    ///
    /// # Errors
    ///
    /// Returns an error if the header format is invalid.
    pub fn from_header(header: &str) -> Result<Self> {
        let mut parts: HashMap<&str, &str> = HashMap::new();

        for part in header.split(',') {
            let mut kv = part.splitn(2, '=');
            if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
                parts.insert(key.trim(), value.trim());
            }
        }

        let algorithm = parts
            .get("algorithm")
            .ok_or_else(|| SecurityError::Signature("Missing algorithm".to_string()))?
            .to_string();

        let timestamp = parts
            .get("timestamp")
            .ok_or_else(|| SecurityError::Signature("Missing timestamp".to_string()))?
            .parse::<i64>()
            .map_err(|_| SecurityError::Signature("Invalid timestamp".to_string()))?;

        let timestamp = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| SecurityError::Signature("Invalid timestamp value".to_string()))?;

        let nonce = parts
            .get("nonce")
            .ok_or_else(|| SecurityError::Signature("Missing nonce".to_string()))?
            .to_string();

        let signed_headers = parts
            .get("signed_headers")
            .ok_or_else(|| SecurityError::Signature("Missing signed_headers".to_string()))?
            .split(';')
            .map(String::from)
            .collect();

        let signature = parts
            .get("signature")
            .ok_or_else(|| SecurityError::Signature("Missing signature".to_string()))?
            .to_string();

        Ok(Self {
            signature,
            timestamp,
            nonce,
            signed_headers,
            algorithm,
        })
    }
}

/// Request signer for creating HMAC signatures.
pub struct RequestSigner {
    config: SigningConfig,
    signing_key: Vec<u8>,
    nonce_cache: RwLock<NonceCache>,
}

struct NonceCache {
    nonces: HashMap<String, Instant>,
    max_size: usize,
}

impl NonceCache {
    fn new(max_size: usize) -> Self {
        Self {
            nonces: HashMap::new(),
            max_size,
        }
    }

    fn contains(&self, nonce: &str) -> bool {
        self.nonces.contains_key(nonce)
    }

    fn insert(&mut self, nonce: String) {
        // Clean up old entries if at capacity
        if self.nonces.len() >= self.max_size {
            let now = Instant::now();
            let cutoff = Duration::from_secs(300); // 5 minutes

            self.nonces.retain(|_, inserted| now.duration_since(*inserted) < cutoff);
        }

        self.nonces.insert(nonce, Instant::now());
    }

    fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.nonces.retain(|_, inserted| now.duration_since(*inserted) < max_age);
    }
}

impl RequestSigner {
    /// Creates a new request signer with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing key is missing or invalid.
    pub fn new(config: SigningConfig) -> Result<Self> {
        let signing_key = if let Some(ref key) = config.signing_key {
            if key.len() < 32 {
                return Err(SecurityError::configuration_field(
                    "Signing key must be at least 32 characters",
                    "signing_key",
                ));
            }
            key.as_bytes().to_vec()
        } else if config.enabled {
            return Err(SecurityError::configuration_field(
                "Signing key required when signing is enabled",
                "signing_key",
            ));
        } else {
            // Generate a placeholder key for disabled signing
            vec![0u8; 32]
        };

        Ok(Self {
            nonce_cache: RwLock::new(NonceCache::new(config.nonce_cache_size)),
            config,
            signing_key,
        })
    }

    /// Signs a request.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<SignedRequest> {
        let timestamp = Utc::now();
        let nonce = self.generate_nonce();

        // Build canonical request
        let canonical = self.build_canonical_request(
            method,
            path,
            headers,
            body,
            &timestamp,
            &nonce,
        )?;

        // Create signature
        let signature = self.create_signature(&canonical)?;

        // Store nonce to prevent replay
        {
            let mut cache = self.nonce_cache.write().map_err(|_| {
                SecurityError::Internal("Failed to acquire nonce cache lock".to_string())
            })?;
            cache.insert(nonce.clone());
        }

        Ok(SignedRequest::new(
            signature,
            timestamp,
            nonce,
            self.config.signed_headers.clone(),
        ))
    }

    /// Verifies a signed request.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        signed_request: &SignedRequest,
    ) -> Result<()> {
        // Check if signing is enabled
        if !self.config.enabled {
            return Ok(());
        }

        // Check signature expiration
        let age = Utc::now().signed_duration_since(signed_request.timestamp);
        if age.num_seconds() > self.config.validity_secs as i64 {
            return Err(SecurityError::SignatureExpired {
                signed_at: signed_request.timestamp,
                valid_for_secs: self.config.validity_secs,
            });
        }

        // Check for replay attack
        {
            let cache = self.nonce_cache.read().map_err(|_| {
                SecurityError::Internal("Failed to acquire nonce cache lock".to_string())
            })?;

            if cache.contains(&signed_request.nonce) {
                warn!("Replay attack detected: nonce {} already used", signed_request.nonce);
                return Err(SecurityError::ReplayAttack {
                    nonce: signed_request.nonce.clone(),
                });
            }
        }

        // Build canonical request
        let canonical = self.build_canonical_request(
            method,
            path,
            headers,
            body,
            &signed_request.timestamp,
            &signed_request.nonce,
        )?;

        // Verify signature
        let expected_signature = self.create_signature(&canonical)?;

        if !constant_time_compare(&signed_request.signature, &expected_signature) {
            return Err(SecurityError::InvalidSignature(
                "Signature verification failed".to_string(),
            ));
        }

        // Store nonce to prevent future replay
        {
            let mut cache = self.nonce_cache.write().map_err(|_| {
                SecurityError::Internal("Failed to acquire nonce cache lock".to_string())
            })?;
            cache.insert(signed_request.nonce.clone());
        }

        debug!("Request signature verified successfully");
        Ok(())
    }

    /// Verifies a webhook signature.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify_webhook(
        &self,
        payload: &[u8],
        signature: &str,
        timestamp: i64,
    ) -> Result<()> {
        // Check timestamp is within validity window
        let signed_at = DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| SecurityError::Signature("Invalid timestamp".to_string()))?;

        let age = Utc::now().signed_duration_since(signed_at);
        if age.num_seconds().unsigned_abs() > self.config.validity_secs {
            return Err(SecurityError::SignatureExpired {
                signed_at,
                valid_for_secs: self.config.validity_secs,
            });
        }

        // Build signing string
        let signing_string = format!("{}.{}", timestamp, base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload,
        ));

        // Create expected signature
        let expected = self.create_signature(&signing_string)?;

        if !constant_time_compare(signature, &expected) {
            return Err(SecurityError::InvalidSignature(
                "Webhook signature verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Creates a webhook signature.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_webhook(&self, payload: &[u8]) -> Result<(String, i64)> {
        let timestamp = Utc::now().timestamp();

        let signing_string = format!("{}.{}", timestamp, base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload,
        ));

        let signature = self.create_signature(&signing_string)?;
        Ok((signature, timestamp))
    }

    /// Cleans up expired nonces from the cache.
    pub fn cleanup_nonces(&self) -> Result<()> {
        let mut cache = self.nonce_cache.write().map_err(|_| {
            SecurityError::Internal("Failed to acquire nonce cache lock".to_string())
        })?;

        cache.cleanup(Duration::from_secs(self.config.validity_secs * 2));
        Ok(())
    }

    // Private helper methods

    fn generate_nonce(&self) -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    fn build_canonical_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        timestamp: &DateTime<Utc>,
        nonce: &str,
    ) -> Result<String> {
        let mut parts = Vec::new();

        // Method
        parts.push(method.to_uppercase());

        // Path
        parts.push(path.to_string());

        // Timestamp
        parts.push(timestamp.timestamp().to_string());

        // Nonce
        parts.push(nonce.to_string());

        // Signed headers
        for header in &self.config.signed_headers {
            let value = headers
                .get(&header.to_lowercase())
                .or_else(|| headers.get(header))
                .map(String::as_str)
                .unwrap_or("");
            parts.push(format!("{}:{}", header.to_lowercase(), value));
        }

        // Body hash
        if let Some(body) = body {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(body);
            parts.push(hex::encode(hasher.finalize()));
        } else {
            parts.push("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()); // SHA256 of empty string
        }

        Ok(parts.join("\n"))
    }

    fn create_signature(&self, data: &str) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| SecurityError::Signature(format!("HMAC creation failed: {e}")))?;

        mac.update(data.as_bytes());
        let result = mac.finalize();

        Ok(hex::encode(result.into_bytes()))
    }
}

/// Signature verifier for incoming requests.
pub struct SignatureVerifier {
    signer: RequestSigner,
}

impl SignatureVerifier {
    /// Creates a new signature verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if creation fails.
    pub fn new(config: SigningConfig) -> Result<Self> {
        Ok(Self {
            signer: RequestSigner::new(config)?,
        })
    }

    /// Verifies a request signature from headers.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify_from_headers(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        signature_header: &str,
    ) -> Result<()> {
        let signed_request = SignedRequest::from_header(signature_header)?;
        self.signer.verify(method, path, headers, body, &signed_request)
    }
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }

    result == 0
}

impl std::fmt::Debug for RequestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSigner")
            .field("config", &self.config)
            .field("has_key", &!self.signing_key.is_empty())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SigningConfig {
        SigningConfig {
            enabled: true,
            signing_key: Some("a-very-secure-signing-key-for-testing-purposes".to_string()),
            validity_secs: 300,
            nonce_cache_size: 1000,
            signed_headers: vec!["host".to_string(), "content-type".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn test_sign_and_verify() {
        let signer = RequestSigner::new(test_config()).unwrap();

        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "api.example.com".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());

        let body = br#"{"test": "data"}"#;

        let signed = signer.sign("POST", "/api/v1/test", &headers, Some(body)).unwrap();

        // Create a new signer (simulating server-side)
        let verifier = RequestSigner::new(test_config()).unwrap();
        let result = verifier.verify("POST", "/api/v1/test", &headers, Some(body), &signed);

        assert!(result.is_ok());
    }

    #[test]
    fn test_replay_protection() {
        // Use separate signers to simulate client/server separation
        let client_signer = RequestSigner::new(test_config()).unwrap();
        let server_verifier = RequestSigner::new(test_config()).unwrap();

        let headers = HashMap::new();
        let signed = client_signer.sign("GET", "/api/test", &headers, None).unwrap();

        // First verification should succeed
        server_verifier.verify("GET", "/api/test", &headers, None, &signed).unwrap();

        // Second verification with same nonce should fail (replay attack)
        let result = server_verifier.verify("GET", "/api/test", &headers, None, &signed);
        assert!(matches!(result, Err(SecurityError::ReplayAttack { .. })));
    }

    #[test]
    fn test_signature_expiration() {
        let mut config = test_config();
        config.validity_secs = 0; // Immediate expiration

        let signer = RequestSigner::new(config).unwrap();
        let headers = HashMap::new();

        // Create a signed request with past timestamp
        let signed = SignedRequest {
            signature: "test".to_string(),
            timestamp: Utc::now() - chrono::Duration::hours(1),
            nonce: "test-nonce".to_string(),
            signed_headers: vec![],
            algorithm: "HMAC-SHA256".to_string(),
        };

        let result = signer.verify("GET", "/test", &headers, None, &signed);
        assert!(matches!(result, Err(SecurityError::SignatureExpired { .. })));
    }

    #[test]
    fn test_invalid_signature() {
        let signer = RequestSigner::new(test_config()).unwrap();
        let headers = HashMap::new();

        let signed = signer.sign("GET", "/test", &headers, None).unwrap();

        // Tamper with the signature
        let tampered = SignedRequest {
            signature: "invalid-signature".to_string(),
            ..signed
        };

        // Create fresh signer for verification (no nonce collision)
        let verifier = RequestSigner::new(test_config()).unwrap();
        let result = verifier.verify("GET", "/test", &headers, None, &tampered);
        assert!(matches!(result, Err(SecurityError::InvalidSignature(_))));
    }

    #[test]
    fn test_webhook_signing() {
        let signer = RequestSigner::new(test_config()).unwrap();
        let payload = br#"{"event": "test"}"#;

        let (signature, timestamp) = signer.sign_webhook(payload).unwrap();

        let result = signer.verify_webhook(payload, &signature, timestamp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_signed_request_header() {
        let signed = SignedRequest::new(
            "abc123".to_string(),
            Utc::now(),
            "nonce123".to_string(),
            vec!["host".to_string()],
        );

        let header = signed.to_header();
        let parsed = SignedRequest::from_header(&header).unwrap();

        assert_eq!(parsed.signature, signed.signature);
        assert_eq!(parsed.nonce, signed.nonce);
    }
}
