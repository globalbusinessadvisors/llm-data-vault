//! Key Management Service (KMS) providers.

use crate::{CryptoError, CryptoResult, DataKey, KeyConfig, KeyMetadata, SecureBytes};
use async_trait::async_trait;
use std::sync::Arc;

/// KMS provider trait for key management operations.
#[async_trait]
pub trait KmsProvider: Send + Sync {
    /// Generates a new data encryption key.
    async fn generate_data_key(&self, master_key_id: &str) -> CryptoResult<DataKey>;

    /// Decrypts an encrypted data key.
    async fn decrypt_data_key(
        &self,
        master_key_id: &str,
        encrypted_key: &[u8],
    ) -> CryptoResult<SecureBytes>;

    /// Encrypts data directly with a master key.
    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Decrypts data directly with a master key.
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> CryptoResult<SecureBytes>;

    /// Creates a new master key.
    async fn create_key(&self, config: KeyConfig) -> CryptoResult<KeyMetadata>;

    /// Gets key metadata.
    async fn get_key_metadata(&self, key_id: &str) -> CryptoResult<KeyMetadata>;

    /// Rotates a key (creates new version).
    async fn rotate_key(&self, key_id: &str) -> CryptoResult<KeyMetadata>;

    /// Enables a key.
    async fn enable_key(&self, key_id: &str) -> CryptoResult<()>;

    /// Disables a key.
    async fn disable_key(&self, key_id: &str) -> CryptoResult<()>;

    /// Schedules key deletion.
    async fn schedule_key_deletion(&self, key_id: &str, days: u32) -> CryptoResult<()>;
}

/// Local KMS provider for development/testing.
pub struct LocalKmsProvider {
    keys: parking_lot::RwLock<std::collections::HashMap<String, LocalKey>>,
}

struct LocalKey {
    key_material: SecureBytes,
    metadata: KeyMetadata,
}

impl LocalKmsProvider {
    /// Creates a new local KMS provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Creates a local KMS with a default master key.
    #[must_use]
    pub fn with_default_key() -> Arc<Self> {
        let kms = Self::new();

        // Generate a default master key
        let mut key_bytes = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);

        let key = LocalKey {
            key_material: SecureBytes::new(key_bytes),
            metadata: KeyMetadata {
                key_id: "default-master-key".to_string(),
                algorithm: crate::KeyAlgorithm::Aes256Gcm,
                usage: crate::KeyUsage::EncryptDecrypt,
                created_at: chrono::Utc::now(),
                expires_at: None,
                enabled: true,
                version: 1,
            },
        };

        kms.keys.write().insert("default-master-key".to_string(), key);
        Arc::new(kms)
    }

    fn get_key(&self, key_id: &str) -> CryptoResult<SecureBytes> {
        let keys = self.keys.read();
        let key = keys
            .get(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;

        if !key.metadata.enabled {
            return Err(CryptoError::InvalidKey("Key is disabled".to_string()));
        }

        Ok(key.key_material.clone())
    }
}

impl Default for LocalKmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KmsProvider for LocalKmsProvider {
    async fn generate_data_key(&self, master_key_id: &str) -> CryptoResult<DataKey> {
        let master_key = self.get_key(master_key_id)?;

        // Generate a new data key
        let mut dek_bytes = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut dek_bytes);
        let dek = SecureBytes::new(dek_bytes);

        // Encrypt the data key with the master key
        let cipher = crate::AesGcmCipher::new();
        let encrypted = cipher.encrypt(&master_key, dek.as_slice(), None)?;
        let encrypted_dek = serde_json::to_vec(&encrypted)
            .map_err(|e| CryptoError::Internal(e.to_string()))?;

        Ok(DataKey::new(dek, encrypted_dek, master_key_id.to_string()))
    }

    async fn decrypt_data_key(
        &self,
        master_key_id: &str,
        encrypted_key: &[u8],
    ) -> CryptoResult<SecureBytes> {
        let master_key = self.get_key(master_key_id)?;

        let encrypted: crate::EncryptedData = serde_json::from_slice(encrypted_key)
            .map_err(|e| CryptoError::InvalidCiphertext(e.to_string()))?;

        let cipher = crate::AesGcmCipher::new();
        cipher.decrypt(&master_key, &encrypted)
    }

    async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let key = self.get_key(key_id)?;
        let cipher = crate::AesGcmCipher::new();
        let encrypted = cipher.encrypt(&key, plaintext, None)?;
        serde_json::to_vec(&encrypted).map_err(|e| CryptoError::Internal(e.to_string()))
    }

    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> CryptoResult<SecureBytes> {
        let key = self.get_key(key_id)?;
        let encrypted: crate::EncryptedData = serde_json::from_slice(ciphertext)
            .map_err(|e| CryptoError::InvalidCiphertext(e.to_string()))?;
        let cipher = crate::AesGcmCipher::new();
        cipher.decrypt(&key, &encrypted)
    }

    async fn create_key(&self, config: KeyConfig) -> CryptoResult<KeyMetadata> {
        let key_id = uuid::Uuid::new_v4().to_string();

        let mut key_bytes = vec![0u8; config.algorithm.key_size()];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);

        let now = chrono::Utc::now();
        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            algorithm: config.algorithm,
            usage: config.usage,
            created_at: now,
            expires_at: config
                .expires_in_days
                .map(|d| now + chrono::Duration::days(i64::from(d))),
            enabled: true,
            version: 1,
        };

        let key = LocalKey {
            key_material: SecureBytes::new(key_bytes),
            metadata: metadata.clone(),
        };

        self.keys.write().insert(key_id, key);

        Ok(metadata)
    }

    async fn get_key_metadata(&self, key_id: &str) -> CryptoResult<KeyMetadata> {
        let keys = self.keys.read();
        let key = keys
            .get(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;
        Ok(key.metadata.clone())
    }

    async fn rotate_key(&self, key_id: &str) -> CryptoResult<KeyMetadata> {
        let mut keys = self.keys.write();
        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;

        // Generate new key material
        let mut new_key_bytes = vec![0u8; key.metadata.algorithm.key_size()];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_key_bytes);

        key.key_material = SecureBytes::new(new_key_bytes);
        key.metadata.version += 1;

        Ok(key.metadata.clone())
    }

    async fn enable_key(&self, key_id: &str) -> CryptoResult<()> {
        let mut keys = self.keys.write();
        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;
        key.metadata.enabled = true;
        Ok(())
    }

    async fn disable_key(&self, key_id: &str) -> CryptoResult<()> {
        let mut keys = self.keys.write();
        let key = keys
            .get_mut(key_id)
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))?;
        key.metadata.enabled = false;
        Ok(())
    }

    async fn schedule_key_deletion(&self, key_id: &str, _days: u32) -> CryptoResult<()> {
        // In local mode, just disable the key
        self.disable_key(key_id).await
    }
}

#[cfg(feature = "aws-kms")]
pub mod aws {
    //! AWS KMS provider implementation.

    use super::*;
    use aws_sdk_kms::Client as KmsClient;

    /// AWS KMS provider.
    pub struct AwsKmsProvider {
        client: KmsClient,
    }

    impl AwsKmsProvider {
        /// Creates a new AWS KMS provider.
        pub async fn new() -> Self {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let client = KmsClient::new(&config);
            Self { client }
        }

        /// Creates a new AWS KMS provider with custom config.
        pub fn with_client(client: KmsClient) -> Self {
            Self { client }
        }
    }

    #[async_trait]
    impl KmsProvider for AwsKmsProvider {
        async fn generate_data_key(&self, master_key_id: &str) -> CryptoResult<DataKey> {
            let result = self
                .client
                .generate_data_key()
                .key_id(master_key_id)
                .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;

            let plaintext = result
                .plaintext()
                .ok_or_else(|| CryptoError::KmsError("No plaintext in response".to_string()))?;

            let encrypted = result
                .ciphertext_blob()
                .ok_or_else(|| CryptoError::KmsError("No ciphertext in response".to_string()))?;

            Ok(DataKey::new(
                SecureBytes::from_slice(plaintext.as_ref()),
                encrypted.as_ref().to_vec(),
                master_key_id.to_string(),
            ))
        }

        async fn decrypt_data_key(
            &self,
            _master_key_id: &str,
            encrypted_key: &[u8],
        ) -> CryptoResult<SecureBytes> {
            let result = self
                .client
                .decrypt()
                .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(encrypted_key))
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;

            let plaintext = result
                .plaintext()
                .ok_or_else(|| CryptoError::KmsError("No plaintext in response".to_string()))?;

            Ok(SecureBytes::from_slice(plaintext.as_ref()))
        }

        async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
            let result = self
                .client
                .encrypt()
                .key_id(key_id)
                .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext))
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;

            let ciphertext = result
                .ciphertext_blob()
                .ok_or_else(|| CryptoError::KmsError("No ciphertext in response".to_string()))?;

            Ok(ciphertext.as_ref().to_vec())
        }

        async fn decrypt(&self, _key_id: &str, ciphertext: &[u8]) -> CryptoResult<SecureBytes> {
            let result = self
                .client
                .decrypt()
                .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;

            let plaintext = result
                .plaintext()
                .ok_or_else(|| CryptoError::KmsError("No plaintext in response".to_string()))?;

            Ok(SecureBytes::from_slice(plaintext.as_ref()))
        }

        async fn create_key(&self, config: KeyConfig) -> CryptoResult<KeyMetadata> {
            let mut req = self.client.create_key();

            if let Some(desc) = &config.description {
                req = req.description(desc);
            }

            for (k, v) in &config.tags {
                req = req.tags(
                    aws_sdk_kms::types::Tag::builder()
                        .tag_key(k)
                        .tag_value(v)
                        .build()
                        .map_err(|e| CryptoError::KmsError(e.to_string()))?,
                );
            }

            let result = req
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;

            let key_metadata = result
                .key_metadata()
                .ok_or_else(|| CryptoError::KmsError("No key metadata in response".to_string()))?;

            Ok(KeyMetadata {
                key_id: key_metadata.key_id().to_string(),
                algorithm: config.algorithm,
                usage: config.usage,
                created_at: chrono::Utc::now(),
                expires_at: None,
                enabled: key_metadata.enabled(),
                version: 1,
            })
        }

        async fn get_key_metadata(&self, key_id: &str) -> CryptoResult<KeyMetadata> {
            let result = self
                .client
                .describe_key()
                .key_id(key_id)
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;

            let key_metadata = result
                .key_metadata()
                .ok_or_else(|| CryptoError::KmsError("No key metadata in response".to_string()))?;

            Ok(KeyMetadata {
                key_id: key_metadata.key_id().to_string(),
                algorithm: crate::KeyAlgorithm::Aes256Gcm,
                usage: crate::KeyUsage::EncryptDecrypt,
                created_at: chrono::Utc::now(),
                expires_at: None,
                enabled: key_metadata.enabled(),
                version: 1,
            })
        }

        async fn rotate_key(&self, key_id: &str) -> CryptoResult<KeyMetadata> {
            self.client
                .enable_key_rotation()
                .key_id(key_id)
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;

            self.get_key_metadata(key_id).await
        }

        async fn enable_key(&self, key_id: &str) -> CryptoResult<()> {
            self.client
                .enable_key()
                .key_id(key_id)
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;
            Ok(())
        }

        async fn disable_key(&self, key_id: &str) -> CryptoResult<()> {
            self.client
                .disable_key()
                .key_id(key_id)
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;
            Ok(())
        }

        async fn schedule_key_deletion(&self, key_id: &str, days: u32) -> CryptoResult<()> {
            self.client
                .schedule_key_deletion()
                .key_id(key_id)
                .pending_window_in_days(days.try_into().unwrap_or(30))
                .send()
                .await
                .map_err(|e| CryptoError::KmsError(e.to_string()))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_kms_generate_data_key() {
        let kms = LocalKmsProvider::with_default_key();
        let dek = kms.generate_data_key("default-master-key").await.unwrap();
        assert_eq!(dek.plaintext().len(), 32);
        assert!(!dek.encrypted().is_empty());
    }

    #[tokio::test]
    async fn test_local_kms_encrypt_decrypt_data_key() {
        let kms = LocalKmsProvider::with_default_key();

        let dek = kms.generate_data_key("default-master-key").await.unwrap();
        let decrypted = kms
            .decrypt_data_key("default-master-key", dek.encrypted())
            .await
            .unwrap();

        assert_eq!(decrypted.as_slice(), dek.plaintext().as_slice());
    }

    #[tokio::test]
    async fn test_local_kms_create_key() {
        let kms = LocalKmsProvider::new();
        let config = KeyConfig::default();
        let metadata = kms.create_key(config).await.unwrap();

        assert!(metadata.enabled);
        assert_eq!(metadata.version, 1);
    }
}
