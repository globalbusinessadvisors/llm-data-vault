//! Envelope encryption for data at rest.

use crate::{
    AesGcmCipher, CryptoError, CryptoResult, DataKey, EncryptedData, EncryptionContext,
    KmsProvider, SecureBytes,
};
use lru::LruCache;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Envelope-encrypted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncryptedData {
    /// Encrypted data encryption key (DEK).
    #[serde(with = "base64_serde")]
    pub encrypted_dek: Vec<u8>,
    /// Master key ID used to encrypt the DEK.
    pub master_key_id: String,
    /// The encrypted data.
    pub encrypted_data: EncryptedData,
    /// Encryption context (for AAD).
    pub context: Option<EncryptionContext>,
}

/// Envelope encryption service.
pub struct EnvelopeEncryption {
    kms: Arc<dyn KmsProvider>,
    master_key_id: String,
    cipher: AesGcmCipher,
    dek_cache: RwLock<LruCache<String, CachedDek>>,
    cache_ttl: Duration,
}

struct CachedDek {
    dek: SecureBytes,
    cached_at: Instant,
}

impl EnvelopeEncryption {
    /// Creates a new envelope encryption service.
    #[must_use]
    pub fn new(kms: Arc<dyn KmsProvider>, master_key_id: String) -> Self {
        Self {
            kms,
            master_key_id,
            cipher: AesGcmCipher::new(),
            dek_cache: RwLock::new(LruCache::new(NonZeroUsize::new(1000).unwrap())),
            cache_ttl: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Creates with custom cache settings.
    #[must_use]
    pub fn with_cache(
        kms: Arc<dyn KmsProvider>,
        master_key_id: String,
        cache_size: usize,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            kms,
            master_key_id,
            cipher: AesGcmCipher::new(),
            dek_cache: RwLock::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1).unwrap()),
            )),
            cache_ttl,
        }
    }

    /// Encrypts data using envelope encryption.
    pub async fn encrypt(
        &self,
        plaintext: &[u8],
        context: Option<EncryptionContext>,
    ) -> CryptoResult<EnvelopeEncryptedData> {
        // Generate a new DEK
        let dek = self.kms.generate_data_key(&self.master_key_id).await?;

        // Compute AAD from context
        let aad = context.as_ref().map(EncryptionContext::to_aad);

        // Encrypt the data with the DEK
        let encrypted_data =
            self.cipher
                .encrypt(dek.plaintext(), plaintext, aad.as_deref())?;

        Ok(EnvelopeEncryptedData {
            encrypted_dek: dek.encrypted().to_vec(),
            master_key_id: self.master_key_id.clone(),
            encrypted_data,
            context,
        })
    }

    /// Decrypts envelope-encrypted data.
    pub async fn decrypt(&self, data: &EnvelopeEncryptedData) -> CryptoResult<SecureBytes> {
        // Create cache key
        let cache_key = hex::encode(&data.encrypted_dek);

        // Check cache for DEK
        let dek = {
            let mut cache = self.dek_cache.write();
            if let Some(cached) = cache.get(&cache_key) {
                if cached.cached_at.elapsed() < self.cache_ttl {
                    Some(cached.dek.clone())
                } else {
                    cache.pop(&cache_key);
                    None
                }
            } else {
                None
            }
        };

        let dek = match dek {
            Some(dek) => dek,
            None => {
                // Decrypt DEK via KMS
                let decrypted_dek = self
                    .kms
                    .decrypt_data_key(&data.master_key_id, &data.encrypted_dek)
                    .await?;

                // Cache the DEK
                {
                    let mut cache = self.dek_cache.write();
                    cache.put(
                        cache_key,
                        CachedDek {
                            dek: decrypted_dek.clone(),
                            cached_at: Instant::now(),
                        },
                    );
                }

                decrypted_dek
            }
        };

        // Decrypt the data with the DEK
        self.cipher.decrypt(&dek, &data.encrypted_data)
    }

    /// Re-encrypts data with a new DEK (for key rotation).
    pub async fn re_encrypt(
        &self,
        data: &EnvelopeEncryptedData,
    ) -> CryptoResult<EnvelopeEncryptedData> {
        let plaintext = self.decrypt(data).await?;
        self.encrypt(plaintext.as_slice(), data.context.clone())
            .await
    }

    /// Clears the DEK cache.
    pub fn clear_cache(&self) {
        self.dek_cache.write().clear();
    }

    /// Returns the cache size.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.dek_cache.read().len()
    }
}

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

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Field-level encryption for specific fields.
pub struct FieldEncryption {
    envelope: Arc<EnvelopeEncryption>,
}

impl FieldEncryption {
    /// Creates a new field encryption service.
    #[must_use]
    pub fn new(envelope: Arc<EnvelopeEncryption>) -> Self {
        Self { envelope }
    }

    /// Encrypts a JSON value at specific field paths.
    pub async fn encrypt_fields(
        &self,
        mut data: serde_json::Value,
        field_paths: &[&str],
        context: Option<EncryptionContext>,
    ) -> CryptoResult<serde_json::Value> {
        for path in field_paths {
            if let Some(value) = self.get_field_mut(&mut data, path) {
                let value_str = value.to_string();
                let encrypted = self
                    .envelope
                    .encrypt(value_str.as_bytes(), context.clone())
                    .await?;
                let encrypted_json = serde_json::to_value(&encrypted)
                    .map_err(|e| CryptoError::Internal(e.to_string()))?;
                *value = encrypted_json;
            }
        }
        Ok(data)
    }

    /// Decrypts a JSON value at specific field paths.
    pub async fn decrypt_fields(
        &self,
        mut data: serde_json::Value,
        field_paths: &[&str],
    ) -> CryptoResult<serde_json::Value> {
        for path in field_paths {
            if let Some(value) = self.get_field_mut(&mut data, path) {
                if value.is_object() {
                    let encrypted: EnvelopeEncryptedData = serde_json::from_value(value.clone())
                        .map_err(|e| CryptoError::InvalidCiphertext(e.to_string()))?;
                    let decrypted = self.envelope.decrypt(&encrypted).await?;
                    let decrypted_str = String::from_utf8(decrypted.as_slice().to_vec())
                        .map_err(|e| CryptoError::Internal(e.to_string()))?;
                    let original_value: serde_json::Value = serde_json::from_str(&decrypted_str)
                        .map_err(|e| CryptoError::Internal(e.to_string()))?;
                    *value = original_value;
                }
            }
        }
        Ok(data)
    }

    fn get_field_mut<'a>(
        &self,
        data: &'a mut serde_json::Value,
        path: &str,
    ) -> Option<&'a mut serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = data;

        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                return current.get_mut(*part);
            }
            current = current.get_mut(*part)?;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalKmsProvider;

    #[tokio::test]
    async fn test_envelope_encrypt_decrypt() {
        let kms = LocalKmsProvider::with_default_key();
        let envelope = EnvelopeEncryption::new(kms, "default-master-key".to_string());

        let plaintext = b"Hello, World!";
        let encrypted = envelope.encrypt(plaintext, None).await.unwrap();
        let decrypted = envelope.decrypt(&encrypted).await.unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn test_envelope_with_context() {
        let kms = LocalKmsProvider::with_default_key();
        let envelope = EnvelopeEncryption::new(kms, "default-master-key".to_string());

        let context = EncryptionContext::new()
            .with("tenant_id", "tenant-123")
            .with("dataset_id", "ds-456");

        let plaintext = b"Secret data";
        let encrypted = envelope.encrypt(plaintext, Some(context)).await.unwrap();
        let decrypted = envelope.decrypt(&encrypted).await.unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn test_dek_cache() {
        let kms = LocalKmsProvider::with_default_key();
        let envelope = EnvelopeEncryption::new(kms, "default-master-key".to_string());

        let plaintext = b"Test";
        let encrypted = envelope.encrypt(plaintext, None).await.unwrap();

        // First decrypt - should cache the DEK
        let _ = envelope.decrypt(&encrypted).await.unwrap();
        assert_eq!(envelope.cache_size(), 1);

        // Second decrypt - should use cached DEK
        let decrypted = envelope.decrypt(&encrypted).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn test_re_encrypt() {
        let kms = LocalKmsProvider::with_default_key();
        let envelope = EnvelopeEncryption::new(kms, "default-master-key".to_string());

        let plaintext = b"Original data";
        let encrypted1 = envelope.encrypt(plaintext, None).await.unwrap();
        let encrypted2 = envelope.re_encrypt(&encrypted1).await.unwrap();

        // DEKs should be different
        assert_ne!(encrypted1.encrypted_dek, encrypted2.encrypted_dek);

        // But decrypted data should be the same
        let decrypted = envelope.decrypt(&encrypted2).await.unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
