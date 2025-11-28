//! Secrets management with encryption.
//!
//! Provides secure secrets storage including:
//! - Encrypted storage of sensitive values
//! - Key derivation for secret encryption
//! - Secret rotation support
//! - Secure memory handling with zeroization

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rand::RngCore;
use tracing::info;
use zeroize::Zeroize;

use crate::config::SecretsConfig;
use crate::error::{SecurityError, Result};

type HmacSha256 = Hmac<Sha256>;

/// A secret value that is automatically zeroized on drop.
#[derive(Clone)]
pub struct SecretValue {
    value: Vec<u8>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    version: u32,
}

impl SecretValue {
    /// Creates a new secret value.
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value,
            created_at: Utc::now(),
            expires_at: None,
            version: 1,
        }
    }

    /// Creates a new secret value with expiration.
    #[must_use]
    pub fn with_expiry(value: Vec<u8>, expires_at: DateTime<Utc>) -> Self {
        Self {
            value,
            created_at: Utc::now(),
            expires_at: Some(expires_at),
            version: 1,
        }
    }

    /// Returns the secret value as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Returns the secret value as a string if valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }

    /// Returns when the secret was created.
    #[must_use]
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Returns when the secret expires, if set.
    #[must_use]
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Returns true if the secret has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| Utc::now() > exp)
    }

    /// Returns the secret version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("value", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("version", &self.version)
            .finish()
    }
}

/// An encrypted secret for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// Encrypted data.
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: Vec<u8>,
    /// Salt used for key derivation.
    pub salt: Vec<u8>,
    /// Key version used for encryption.
    pub key_version: u32,
    /// When the secret was encrypted.
    pub encrypted_at: DateTime<Utc>,
    /// Optional expiration time.
    pub expires_at: Option<DateTime<Utc>>,
    /// Authentication tag.
    pub tag: Vec<u8>,
}

/// Secure secrets store.
pub struct SecretStore {
    config: SecretsConfig,
    master_key: RwLock<Option<DerivedKey>>,
    cache: RwLock<HashMap<String, CachedSecret>>,
    key_version: RwLock<u32>,
}

struct DerivedKey {
    key: Vec<u8>,
    derived_at: Instant,
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

struct CachedSecret {
    value: SecretValue,
    cached_at: Instant,
}

impl SecretStore {
    /// Creates a new secret store with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the master key is invalid.
    pub fn new(config: SecretsConfig) -> Result<Self> {
        let store = Self {
            config,
            master_key: RwLock::new(None),
            cache: RwLock::new(HashMap::new()),
            key_version: RwLock::new(1),
        };

        // Initialize master key if provided
        if let Some(ref key) = store.config.master_key {
            store.set_master_key(key)?;
        }

        Ok(store)
    }

    /// Sets the master key for the store.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is invalid.
    pub fn set_master_key(&self, key: &str) -> Result<()> {
        if key.len() < 32 {
            return Err(SecurityError::configuration_field(
                "Master key must be at least 32 characters",
                "master_key",
            ));
        }

        // Derive a key from the master key
        let salt = self.derive_salt(key);
        let derived = self.derive_key(key.as_bytes(), &salt)?;

        let mut master_key = self.master_key.write().map_err(|_| {
            SecurityError::Internal("Failed to acquire master key lock".to_string())
        })?;

        *master_key = Some(DerivedKey {
            key: derived,
            derived_at: Instant::now(),
        });

        info!("Master key initialized successfully");
        Ok(())
    }

    /// Stores a secret securely.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn store(&self, name: &str, value: &[u8]) -> Result<EncryptedSecret> {
        self.store_with_expiry(name, value, None)
    }

    /// Stores a secret with an expiration time.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn store_with_expiry(
        &self,
        name: &str,
        value: &[u8],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<EncryptedSecret> {
        let master_key = self.get_master_key()?;
        let key_version = *self.key_version.read().map_err(|_| {
            SecurityError::Internal("Failed to acquire key version lock".to_string())
        })?;

        // Generate a unique salt for this secret
        let mut salt = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        // Derive a secret-specific key
        let secret_key = self.derive_secret_key(&master_key, name, &salt)?;

        // Encrypt the value
        let (ciphertext, nonce, tag) = self.encrypt_value(value, &secret_key)?;

        // Update cache
        if self.config.cache_ttl_secs > 0 {
            let secret_value = if let Some(exp) = expires_at {
                SecretValue::with_expiry(value.to_vec(), exp)
            } else {
                SecretValue::new(value.to_vec())
            };

            let mut cache = self.cache.write().map_err(|_| {
                SecurityError::Internal("Failed to acquire cache lock".to_string())
            })?;

            cache.insert(
                name.to_string(),
                CachedSecret {
                    value: secret_value,
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(EncryptedSecret {
            ciphertext,
            nonce,
            salt,
            key_version,
            encrypted_at: Utc::now(),
            expires_at,
            tag,
        })
    }

    /// Retrieves and decrypts a secret.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails or the secret is expired.
    pub fn retrieve(&self, name: &str, encrypted: &EncryptedSecret) -> Result<SecretValue> {
        // Check expiration
        if let Some(expires_at) = encrypted.expires_at {
            if Utc::now() > expires_at {
                return Err(SecurityError::Secret(format!(
                    "Secret '{}' has expired",
                    name
                )));
            }
        }

        // Check cache first
        if self.config.cache_ttl_secs > 0 {
            let cache = self.cache.read().map_err(|_| {
                SecurityError::Internal("Failed to acquire cache lock".to_string())
            })?;

            if let Some(cached) = cache.get(name) {
                let age = cached.cached_at.elapsed();
                if age < Duration::from_secs(self.config.cache_ttl_secs) && !cached.value.is_expired() {
                    return Ok(cached.value.clone());
                }
            }
        }

        // Decrypt the secret
        let master_key = self.get_master_key()?;
        let secret_key = self.derive_secret_key(&master_key, name, &encrypted.salt)?;
        let plaintext = self.decrypt_value(
            &encrypted.ciphertext,
            &encrypted.nonce,
            &encrypted.tag,
            &secret_key,
        )?;

        let mut secret_value = SecretValue::new(plaintext);
        secret_value.version = encrypted.key_version;
        if let Some(exp) = encrypted.expires_at {
            secret_value.expires_at = Some(exp);
        }

        // Update cache
        if self.config.cache_ttl_secs > 0 {
            let mut cache = self.cache.write().map_err(|_| {
                SecurityError::Internal("Failed to acquire cache lock".to_string())
            })?;

            cache.insert(
                name.to_string(),
                CachedSecret {
                    value: secret_value.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(secret_value)
    }

    /// Rotates a secret to a new key version.
    ///
    /// # Errors
    ///
    /// Returns an error if rotation fails.
    pub fn rotate(&self, name: &str, encrypted: &EncryptedSecret) -> Result<EncryptedSecret> {
        // Decrypt with old key
        let value = self.retrieve(name, encrypted)?;

        // Increment key version
        {
            let mut version = self.key_version.write().map_err(|_| {
                SecurityError::Internal("Failed to acquire key version lock".to_string())
            })?;
            *version += 1;
        }

        // Re-encrypt with new key version
        let new_encrypted = self.store_with_expiry(name, value.as_bytes(), encrypted.expires_at)?;

        info!("Secret '{}' rotated to version {}", name, new_encrypted.key_version);
        Ok(new_encrypted)
    }

    /// Clears the secret cache.
    pub fn clear_cache(&self) -> Result<()> {
        let mut cache = self.cache.write().map_err(|_| {
            SecurityError::Internal("Failed to acquire cache lock".to_string())
        })?;

        // Zeroize all cached values
        for (_, cached) in cache.drain() {
            drop(cached);
        }

        info!("Secret cache cleared");
        Ok(())
    }

    /// Generates a secure random secret.
    #[must_use]
    pub fn generate_secret(length: usize) -> Vec<u8> {
        let mut secret = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut secret);
        secret
    }

    /// Generates a secure random secret as a hex string.
    #[must_use]
    pub fn generate_secret_hex(length: usize) -> String {
        hex::encode(Self::generate_secret(length))
    }

    /// Generates a secure random secret as a base64 string.
    #[must_use]
    pub fn generate_secret_base64(length: usize) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, Self::generate_secret(length))
    }

    // Private helper methods

    fn get_master_key(&self) -> Result<Vec<u8>> {
        let master_key = self.master_key.read().map_err(|_| {
            SecurityError::Internal("Failed to acquire master key lock".to_string())
        })?;

        match &*master_key {
            Some(key) => Ok(key.key.clone()),
            None => Err(SecurityError::Secret("Master key not initialized".to_string())),
        }
    }

    fn derive_salt(&self, key: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.update(b"vault-security-salt");
        hasher.finalize().to_vec()
    }

    fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
        // Simple PBKDF2-like derivation using HMAC-SHA256
        let mut key = vec![0u8; 32];
        let mut block = salt.to_vec();
        block.extend_from_slice(&[0, 0, 0, 1]); // Block number

        for _ in 0..self.config.kdf_iterations {
            let mut mac = HmacSha256::new_from_slice(password)
                .map_err(|e| SecurityError::Secret(format!("HMAC creation failed: {e}")))?;
            mac.update(&block);
            let result = mac.finalize().into_bytes();
            block = result.to_vec();

            for (i, b) in block.iter().enumerate() {
                if i < 32 {
                    key[i] ^= b;
                }
            }
        }

        Ok(key)
    }

    fn derive_secret_key(&self, master_key: &[u8], name: &str, salt: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(master_key)
            .map_err(|e| SecurityError::Secret(format!("HMAC creation failed: {e}")))?;

        mac.update(salt);
        mac.update(name.as_bytes());
        mac.update(b"secret-key-derivation");

        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn encrypt_value(&self, plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        if key.len() != 32 {
            return Err(SecurityError::Encryption("Invalid key length".to_string()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecurityError::Encryption(format!("Cipher creation failed: {e}")))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| SecurityError::Encryption(format!("Encryption failed: {e}")))?;

        // Extract tag (last 16 bytes of ciphertext)
        let tag_start = ciphertext.len().saturating_sub(16);
        let tag = ciphertext[tag_start..].to_vec();
        let ciphertext_only = ciphertext[..tag_start].to_vec();

        Ok((ciphertext_only, nonce_bytes.to_vec(), tag))
    }

    fn decrypt_value(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        tag: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;

        if key.len() != 32 {
            return Err(SecurityError::Decryption("Invalid key length".to_string()));
        }

        if nonce.len() != 12 {
            return Err(SecurityError::Decryption("Invalid nonce length".to_string()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecurityError::Decryption(format!("Cipher creation failed: {e}")))?;

        let nonce = Nonce::from_slice(nonce);

        // Reconstruct ciphertext with tag
        let mut full_ciphertext = ciphertext.to_vec();
        full_ciphertext.extend_from_slice(tag);

        let plaintext = cipher
            .decrypt(nonce, full_ciphertext.as_ref())
            .map_err(|e| SecurityError::Decryption(format!("Decryption failed: {e}")))?;

        Ok(plaintext)
    }
}

impl std::fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStore")
            .field("config", &self.config)
            .field("has_master_key", &self.master_key.read().map(|k| k.is_some()).unwrap_or(false))
            .field("cache_size", &self.cache.read().map(|c| c.len()).unwrap_or(0))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SecretsConfig {
        SecretsConfig {
            master_key: Some("a-very-secure-master-key-that-is-long-enough".to_string()),
            kdf_iterations: 1000, // Lower for tests
            cache_ttl_secs: 60,
            ..Default::default()
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        let store = SecretStore::new(test_config()).unwrap();
        let secret_data = b"my-secret-value";

        let encrypted = store.store("test-secret", secret_data).unwrap();
        let retrieved = store.retrieve("test-secret", &encrypted).unwrap();

        assert_eq!(retrieved.as_bytes(), secret_data);
    }

    #[test]
    fn test_secret_expiration() {
        let store = SecretStore::new(test_config()).unwrap();
        let secret_data = b"expiring-secret";

        // Create already expired secret
        let expired_time = Utc::now() - chrono::Duration::hours(1);
        let encrypted = store.store_with_expiry("test", secret_data, Some(expired_time)).unwrap();

        let result = store.retrieve("test", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_rotation() {
        let store = SecretStore::new(test_config()).unwrap();
        let secret_data = b"rotating-secret";

        let encrypted = store.store("rotation-test", secret_data).unwrap();
        let initial_version = encrypted.key_version;

        let rotated = store.rotate("rotation-test", &encrypted).unwrap();
        assert!(rotated.key_version > initial_version);

        let retrieved = store.retrieve("rotation-test", &rotated).unwrap();
        assert_eq!(retrieved.as_bytes(), secret_data);
    }

    #[test]
    fn test_generate_secret() {
        let secret1 = SecretStore::generate_secret(32);
        let secret2 = SecretStore::generate_secret(32);

        assert_eq!(secret1.len(), 32);
        assert_eq!(secret2.len(), 32);
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_invalid_master_key() {
        // Test that construction fails with a short master key in config
        let config = SecretsConfig {
            master_key: Some("short".to_string()),
            ..Default::default()
        };

        let result = SecretStore::new(config);
        assert!(result.is_err(), "Should fail with short master key");

        // Test that setting a short master key fails
        let config = SecretsConfig::default();
        let store = SecretStore::new(config).expect("Should create store without master key");
        let result = store.set_master_key("short");
        assert!(result.is_err(), "Should fail when setting short master key");
    }
}
