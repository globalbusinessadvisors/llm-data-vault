//! AES-256-GCM encryption implementation.

use crate::{CryptoError, CryptoResult, KeyAlgorithm, SecureBytes};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Encrypted data with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Algorithm used.
    pub algorithm: KeyAlgorithm,
    /// Nonce/IV.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// Ciphertext (includes authentication tag).
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
    /// Additional authenticated data (AAD) used.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "option_base64_serde")]
    #[serde(default)]
    pub aad: Option<Vec<u8>>,
}

impl EncryptedData {
    /// Returns the total size of the encrypted data.
    #[must_use]
    pub fn size(&self) -> usize {
        self.nonce.len() + self.ciphertext.len()
    }
}

/// AES-256-GCM cipher.
pub struct AesGcmCipher {
    algorithm: KeyAlgorithm,
}

impl AesGcmCipher {
    /// Creates a new AES-256-GCM cipher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            algorithm: KeyAlgorithm::Aes256Gcm,
        }
    }

    /// Encrypts data with the given key.
    pub fn encrypt(
        &self,
        key: &SecureBytes,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> CryptoResult<EncryptedData> {
        self.validate_key(key)?;

        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt with optional AAD
        let ciphertext = if let Some(aad_data) = aad {
            cipher
                .encrypt(nonce, aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: aad_data,
                })
                .map_err(|_| CryptoError::EncryptionFailed("AEAD encryption failed".to_string()))?
        } else {
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| CryptoError::EncryptionFailed("AEAD encryption failed".to_string()))?
        };

        Ok(EncryptedData {
            algorithm: self.algorithm,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            aad: aad.map(|a| a.to_vec()),
        })
    }

    /// Decrypts data with the given key.
    pub fn decrypt(&self, key: &SecureBytes, data: &EncryptedData) -> CryptoResult<SecureBytes> {
        self.validate_key(key)?;

        if data.algorithm != self.algorithm {
            return Err(CryptoError::UnsupportedAlgorithm(format!(
                "Expected {:?}, got {:?}",
                self.algorithm, data.algorithm
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let nonce = Nonce::from_slice(&data.nonce);

        // Decrypt with optional AAD
        let plaintext = if let Some(ref aad_data) = data.aad {
            cipher
                .decrypt(nonce, aes_gcm::aead::Payload {
                    msg: &data.ciphertext,
                    aad: aad_data,
                })
                .map_err(|_| CryptoError::DecryptionFailed("AEAD decryption failed".to_string()))?
        } else {
            cipher
                .decrypt(nonce, data.ciphertext.as_slice())
                .map_err(|_| CryptoError::DecryptionFailed("AEAD decryption failed".to_string()))?
        };

        Ok(SecureBytes::new(plaintext))
    }

    /// Generates a new random key.
    #[must_use]
    pub fn generate_key(&self) -> SecureBytes {
        let mut key = vec![0u8; self.algorithm.key_size()];
        rand::thread_rng().fill_bytes(&mut key);
        SecureBytes::new(key)
    }

    fn validate_key(&self, key: &SecureBytes) -> CryptoResult<()> {
        if key.len() != self.algorithm.key_size() {
            return Err(CryptoError::InvalidKey(format!(
                "Expected {} bytes, got {}",
                self.algorithm.key_size(),
                key.len()
            )));
        }
        Ok(())
    }
}

impl Default for AesGcmCipher {
    fn default() -> Self {
        Self::new()
    }
}

/// Base64 serialization helpers.
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

mod option_base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&STANDARD.encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

/// Encryption context for AEAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionContext {
    /// Context fields.
    pub fields: std::collections::HashMap<String, String>,
}

impl EncryptionContext {
    /// Creates a new empty context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fields: std::collections::HashMap::new(),
        }
    }

    /// Adds a field to the context.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// Converts the context to bytes for AAD.
    #[must_use]
    pub fn to_aad(&self) -> Vec<u8> {
        // Sort keys for deterministic output
        let mut pairs: Vec<_> = self.fields.iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));

        let mut aad = Vec::new();
        for (key, value) in pairs {
            aad.extend_from_slice(key.as_bytes());
            aad.push(0);
            aad.extend_from_slice(value.as_bytes());
            aad.push(0);
        }
        aad
    }
}

impl Default for EncryptionContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let cipher = AesGcmCipher::new();
        let key = cipher.generate_key();
        let plaintext = b"Hello, World!";

        let encrypted = cipher.encrypt(&key, plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let cipher = AesGcmCipher::new();
        let key = cipher.generate_key();
        let plaintext = b"Secret data";
        let aad = b"additional authenticated data";

        let encrypted = cipher.encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let cipher = AesGcmCipher::new();
        let key1 = cipher.generate_key();
        let key2 = cipher.generate_key();
        let plaintext = b"Secret";

        let encrypted = cipher.encrypt(&key1, plaintext, None).unwrap();
        let result = cipher.decrypt(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let cipher = AesGcmCipher::new();
        let key = cipher.generate_key();
        let plaintext = b"Secret";

        let mut encrypted = cipher.encrypt(&key, plaintext, None).unwrap();
        encrypted.ciphertext[0] ^= 0xFF; // Tamper with ciphertext

        let result = cipher.decrypt(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_context() {
        let ctx = EncryptionContext::new()
            .with("tenant_id", "tenant-123")
            .with("dataset_id", "ds-456");

        let aad = ctx.to_aad();
        assert!(!aad.is_empty());
    }
}
