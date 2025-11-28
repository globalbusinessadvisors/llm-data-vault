//! Secure key types with zeroization.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure bytes that are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    /// Creates new secure bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Creates secure bytes from a slice.
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    /// Returns the bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Converts to a regular Vec (use with caution).
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0.clone()
    }
}

impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBytes([REDACTED, {} bytes])", self.0.len())
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A data encryption key (DEK).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey {
    /// Plaintext key material.
    plaintext: SecureBytes,
    /// Encrypted key (for storage).
    encrypted: Vec<u8>,
    /// Key ID from KMS.
    key_id: String,
}

impl DataKey {
    /// Creates a new data key.
    #[must_use]
    pub fn new(plaintext: SecureBytes, encrypted: Vec<u8>, key_id: String) -> Self {
        Self {
            plaintext,
            encrypted,
            key_id,
        }
    }

    /// Returns the plaintext key.
    #[must_use]
    pub fn plaintext(&self) -> &SecureBytes {
        &self.plaintext
    }

    /// Returns the encrypted key.
    #[must_use]
    pub fn encrypted(&self) -> &[u8] {
        &self.encrypted
    }

    /// Returns the key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataKey")
            .field("plaintext", &"[REDACTED]")
            .field("encrypted_len", &self.encrypted.len())
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Key metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key ID.
    pub key_id: String,
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Key usage.
    pub usage: KeyUsage,
    /// Creation time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Expiration time.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the key is enabled.
    pub enabled: bool,
    /// Key version.
    pub version: u32,
}

/// Key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyAlgorithm {
    /// AES-256-GCM.
    Aes256Gcm,
    /// AES-128-GCM.
    Aes128Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

impl KeyAlgorithm {
    /// Returns the key size in bytes.
    #[must_use]
    pub const fn key_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Returns the nonce size in bytes.
    #[must_use]
    pub const fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::Aes128Gcm => 12,
            Self::ChaCha20Poly1305 => 12,
        }
    }

    /// Returns the tag size in bytes.
    #[must_use]
    pub const fn tag_size(&self) -> usize {
        16
    }
}

/// Key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyUsage {
    /// Encrypt/decrypt data.
    EncryptDecrypt,
    /// Sign/verify data.
    SignVerify,
    /// Generate/verify MACs.
    GenerateVerifyMac,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self::EncryptDecrypt
    }
}

/// Key configuration for key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Key usage.
    pub usage: KeyUsage,
    /// Description.
    pub description: Option<String>,
    /// Expiration in days (None = no expiration).
    pub expires_in_days: Option<u32>,
    /// Tags.
    pub tags: std::collections::HashMap<String, String>,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            algorithm: KeyAlgorithm::default(),
            usage: KeyUsage::default(),
            description: None,
            expires_in_days: None,
            tags: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let secure = SecureBytes::new(data.clone());
        assert_eq!(secure.as_slice(), &data);
        assert_eq!(secure.len(), 5);
    }

    #[test]
    fn test_key_algorithm_sizes() {
        assert_eq!(KeyAlgorithm::Aes256Gcm.key_size(), 32);
        assert_eq!(KeyAlgorithm::Aes256Gcm.nonce_size(), 12);
        assert_eq!(KeyAlgorithm::Aes256Gcm.tag_size(), 16);
    }
}
