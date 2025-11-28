# LLM-Data-Vault Pseudocode: Encryption & Security Layer

**Document:** 03-encryption-security.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines the encryption and security layer for LLM-Data-Vault:
- AES-256-GCM encryption at rest
- Envelope encryption with KMS integration
- Support for AWS KMS, HashiCorp Vault, Azure Key Vault, GCP KMS
- Key rotation and secure memory handling

---

## 1. Encryption Provider Trait

```rust
// src/crypto/mod.rs

use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Core Encryption Trait
// ============================================================================

#[async_trait]
pub trait EncryptionProvider: Send + Sync {
    /// Encrypt plaintext data
    async fn encrypt(
        &self,
        plaintext: &[u8],
        context: &EncryptionContext,
    ) -> Result<EncryptedData, CryptoError>;

    /// Decrypt ciphertext data
    async fn decrypt(
        &self,
        ciphertext: &EncryptedData,
        context: &EncryptionContext,
    ) -> Result<SecureBytes, CryptoError>;

    /// Generate a new data encryption key
    async fn generate_data_key(&self) -> Result<DataKey, CryptoError>;

    /// Rotate the master key
    async fn rotate_key(&self, key_id: &KeyId) -> Result<KeyRotationResult, CryptoError>;

    /// Get key metadata
    async fn get_key_info(&self, key_id: &KeyId) -> Result<KeyInfo, CryptoError>;

    /// Provider identifier
    fn provider_type(&self) -> &'static str;
}

// ============================================================================
// Encryption Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct EncryptionContext {
    pub key_id: KeyId,
    pub algorithm: EncryptionAlgorithm,
    pub aad: Option<Vec<u8>>,  // Additional Authenticated Data
    pub purpose: EncryptionPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    Aes256Cbc,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy)]
pub enum EncryptionPurpose {
    DataAtRest,
    DataInTransit,
    KeyEncryption,
    TokenEncryption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub algorithm: EncryptionAlgorithm,
    pub key_id: KeyId,
    pub key_version: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,          // Authentication tag
    pub aad_hash: Option<[u8; 32]>,  // Hash of AAD for verification
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_id: KeyId,
    pub algorithm: EncryptionAlgorithm,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub version: u32,
    pub state: KeyState,
    pub usage: KeyUsage,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyState {
    Active,
    Inactive,
    PendingRotation,
    Destroyed,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyUsage {
    EncryptDecrypt,
    SignVerify,
    GenerateDataKey,
}

#[derive(Debug)]
pub struct KeyRotationResult {
    pub old_key_id: KeyId,
    pub new_key_id: KeyId,
    pub new_version: u32,
    pub rotated_at: DateTime<Utc>,
}

// ============================================================================
// Secure Memory Types
// ============================================================================

/// Secure byte buffer that zeroizes on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Data Encryption Key with secure handling
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey {
    pub plaintext: SecureBytes,
    pub encrypted: Vec<u8>,
    pub key_id: KeyId,
}

impl DataKey {
    pub fn new(plaintext: Vec<u8>, encrypted: Vec<u8>, key_id: KeyId) -> Self {
        Self {
            plaintext: SecureBytes::new(plaintext),
            encrypted,
            key_id,
        }
    }
}

// ============================================================================
// Crypto Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed: {message}")]
    EncryptionFailed { message: String },

    #[error("Decryption failed: {message}")]
    DecryptionFailed { message: String },

    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("Key expired: {key_id}")]
    KeyExpired { key_id: String },

    #[error("Invalid key state: {state:?}")]
    InvalidKeyState { state: KeyState },

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("KMS error: {message}")]
    KmsError {
        message: String,
        #[source] source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Invalid algorithm: {algorithm}")]
    InvalidAlgorithm { algorithm: String },

    #[error("Nonce generation failed")]
    NonceGenerationFailed,
}
```

---

## 2. Cryptographic Primitives

```rust
// src/crypto/primitives.rs

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use rand::{RngCore, rngs::OsRng};

pub struct CryptoEngine {
    rng: OsRng,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self { rng: OsRng }
    }

    /// Generate cryptographically secure random bytes
    pub fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a random nonce for AES-GCM (96 bits)
    pub fn generate_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut nonce);
        nonce
    }

    /// Generate a random 256-bit key
    pub fn generate_key(&mut self) -> SecureBytes {
        SecureBytes::new(self.random_bytes(32))
    }

    /// AES-256-GCM encryption
    pub fn aes_256_gcm_encrypt(
        &mut self,
        key: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidAlgorithm {
                algorithm: "AES-256-GCM requires 32-byte key".into(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionFailed {
                message: e.to_string(),
            })?;

        let nonce_bytes = self.generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = match aad {
            Some(aad_data) => Payload {
                msg: plaintext,
                aad: aad_data,
            },
            None => Payload {
                msg: plaintext,
                aad: &[],
            },
        };

        let ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionFailed {
                message: e.to_string(),
            })?;

        // Split ciphertext and tag (tag is last 16 bytes)
        let tag_start = ciphertext.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext[tag_start..]);
        let ciphertext_only = ciphertext[..tag_start].to_vec();

        Ok((ciphertext_only, nonce_bytes, tag))
    }

    /// AES-256-GCM decryption
    pub fn aes_256_gcm_decrypt(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
        aad: Option<&[u8]>,
    ) -> Result<SecureBytes, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidAlgorithm {
                algorithm: "AES-256-GCM requires 32-byte key".into(),
            });
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionFailed {
                message: e.to_string(),
            })?;

        let nonce = Nonce::from_slice(nonce);

        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(tag);

        let payload = match aad {
            Some(aad_data) => Payload {
                msg: &ciphertext_with_tag,
                aad: aad_data,
            },
            None => Payload {
                msg: &ciphertext_with_tag,
                aad: &[],
            },
        };

        let plaintext = cipher.decrypt(nonce, payload)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(SecureBytes::new(plaintext))
    }

    /// HMAC-SHA256
    pub fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        output
    }

    /// Constant-time comparison
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    /// Key derivation using HKDF
    pub fn hkdf_derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        length: usize,
    ) -> Result<SecureBytes, CryptoError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(salt, ikm);
        let mut okm = vec![0u8; length];
        hk.expand(info, &mut okm)
            .map_err(|e| CryptoError::EncryptionFailed {
                message: format!("HKDF expansion failed: {}", e),
            })?;

        Ok(SecureBytes::new(okm))
    }
}
```

---

## 3. Envelope Encryption

```rust
// src/crypto/envelope.rs

/// Envelope encryption: Encrypt data with DEK, encrypt DEK with KEK via KMS
pub struct EnvelopeEncryption {
    kms: Arc<dyn KmsProvider>,
    master_key_id: KeyId,
    engine: CryptoEngine,
    dek_cache: Arc<RwLock<DekCache>>,
    metrics: Arc<CryptoMetrics>,
}

/// Cache for decrypted DEKs to reduce KMS calls
struct DekCache {
    cache: HashMap<Vec<u8>, CachedDek>,
    max_size: usize,
    ttl: Duration,
}

struct CachedDek {
    plaintext: SecureBytes,
    cached_at: Instant,
}

impl EnvelopeEncryption {
    pub fn new(kms: Arc<dyn KmsProvider>, master_key_id: KeyId) -> Self {
        Self {
            kms,
            master_key_id,
            engine: CryptoEngine::new(),
            dek_cache: Arc::new(RwLock::new(DekCache {
                cache: HashMap::new(),
                max_size: 1000,
                ttl: Duration::from_secs(300), // 5 minutes
            })),
            metrics: Arc::new(CryptoMetrics::new()),
        }
    }

    /// Encrypt data using envelope encryption
    pub async fn encrypt(
        &self,
        plaintext: &[u8],
        context: &EncryptionContext,
    ) -> Result<EnvelopeEncryptedData, CryptoError> {
        let _timer = self.metrics.operation_timer("encrypt");

        // Generate a new DEK for each encryption
        let dek = self.kms.generate_data_key(&self.master_key_id).await?;

        // Encrypt data with DEK
        let (ciphertext, nonce, tag) = self.engine.aes_256_gcm_encrypt(
            dek.plaintext.as_slice(),
            plaintext,
            context.aad.as_deref(),
        )?;

        // Compute AAD hash if present
        let aad_hash = context.aad.as_ref().map(|aad| {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(aad);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        });

        self.metrics.record_bytes_encrypted(plaintext.len() as u64);

        Ok(EnvelopeEncryptedData {
            encrypted_dek: dek.encrypted,
            master_key_id: self.master_key_id.clone(),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: nonce.to_vec(),
            ciphertext,
            tag: tag.to_vec(),
            aad_hash,
        })
    }

    /// Decrypt envelope-encrypted data
    pub async fn decrypt(
        &self,
        encrypted: &EnvelopeEncryptedData,
        context: &EncryptionContext,
    ) -> Result<SecureBytes, CryptoError> {
        let _timer = self.metrics.operation_timer("decrypt");

        // Try to get DEK from cache
        let dek_plaintext = self.get_or_decrypt_dek(&encrypted.encrypted_dek).await?;

        // Verify AAD hash if present
        if let (Some(stored_hash), Some(ref aad)) = (&encrypted.aad_hash, &context.aad) {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(aad);
            let computed_hash: [u8; 32] = hasher.finalize().into();

            if !self.engine.constant_time_eq(stored_hash, &computed_hash) {
                return Err(CryptoError::AuthenticationFailed);
            }
        }

        // Decrypt data with DEK
        let nonce: [u8; 12] = encrypted.nonce.as_slice()
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed {
                message: "Invalid nonce length".into(),
            })?;

        let tag: [u8; 16] = encrypted.tag.as_slice()
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed {
                message: "Invalid tag length".into(),
            })?;

        let plaintext = self.engine.aes_256_gcm_decrypt(
            dek_plaintext.as_slice(),
            &encrypted.ciphertext,
            &nonce,
            &tag,
            context.aad.as_deref(),
        )?;

        self.metrics.record_bytes_decrypted(plaintext.len() as u64);

        Ok(plaintext)
    }

    /// Get DEK from cache or decrypt via KMS
    async fn get_or_decrypt_dek(&self, encrypted_dek: &[u8]) -> Result<SecureBytes, CryptoError> {
        // Check cache
        {
            let cache = self.dek_cache.read().await;
            if let Some(cached) = cache.cache.get(encrypted_dek) {
                if cached.cached_at.elapsed() < cache.ttl {
                    self.metrics.record_cache_hit();
                    return Ok(cached.plaintext.clone());
                }
            }
        }

        self.metrics.record_cache_miss();

        // Decrypt via KMS
        let plaintext = self.kms.decrypt_data_key(
            &self.master_key_id,
            encrypted_dek,
        ).await?;

        // Update cache
        {
            let mut cache = self.dek_cache.write().await;

            // Evict if at capacity
            if cache.cache.len() >= cache.max_size {
                // Remove oldest entry
                if let Some(oldest_key) = cache.cache.iter()
                    .min_by_key(|(_, v)| v.cached_at)
                    .map(|(k, _)| k.clone())
                {
                    cache.cache.remove(&oldest_key);
                }
            }

            cache.cache.insert(encrypted_dek.to_vec(), CachedDek {
                plaintext: plaintext.clone(),
                cached_at: Instant::now(),
            });
        }

        Ok(plaintext)
    }

    /// Re-encrypt data with a new master key (for key rotation)
    pub async fn re_encrypt(
        &self,
        encrypted: &EnvelopeEncryptedData,
        new_master_key_id: &KeyId,
        context: &EncryptionContext,
    ) -> Result<EnvelopeEncryptedData, CryptoError> {
        // Decrypt with old key
        let plaintext = self.decrypt(encrypted, context).await?;

        // Create new envelope encryption with new master key
        let new_envelope = EnvelopeEncryption::new(
            self.kms.clone(),
            new_master_key_id.clone(),
        );

        // Encrypt with new key
        new_envelope.encrypt(plaintext.as_slice(), context).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncryptedData {
    pub encrypted_dek: Vec<u8>,
    pub master_key_id: KeyId,
    pub algorithm: EncryptionAlgorithm,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
    pub aad_hash: Option<[u8; 32]>,
}
```

---

## 4. KMS Provider Trait and Implementations

```rust
// src/crypto/kms/mod.rs

#[async_trait]
pub trait KmsProvider: Send + Sync {
    /// Generate a data encryption key
    async fn generate_data_key(&self, key_id: &KeyId) -> Result<DataKey, CryptoError>;

    /// Decrypt an encrypted data key
    async fn decrypt_data_key(
        &self,
        key_id: &KeyId,
        encrypted_key: &[u8],
    ) -> Result<SecureBytes, CryptoError>;

    /// Encrypt data directly (for small payloads)
    async fn encrypt(&self, key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt data directly
    async fn decrypt(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<SecureBytes, CryptoError>;

    /// Create a new master key
    async fn create_key(&self, config: KeyConfig) -> Result<KeyId, CryptoError>;

    /// Schedule key for deletion
    async fn schedule_key_deletion(
        &self,
        key_id: &KeyId,
        pending_days: u32,
    ) -> Result<(), CryptoError>;

    /// Get key info
    async fn describe_key(&self, key_id: &KeyId) -> Result<KeyInfo, CryptoError>;

    /// Provider type
    fn provider_type(&self) -> &'static str;

    /// Health check
    async fn health_check(&self) -> Result<HealthStatus, CryptoError>;
}

#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub description: String,
    pub usage: KeyUsage,
    pub algorithm: EncryptionAlgorithm,
    pub tags: HashMap<String, String>,
}

// ============================================================================
// AWS KMS Implementation
// ============================================================================

// src/crypto/kms/aws.rs

pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
    config: AwsKmsConfig,
    metrics: Arc<KmsMetrics>,
}

#[derive(Debug, Clone)]
pub struct AwsKmsConfig {
    pub region: String,
    pub endpoint: Option<String>,
    pub assume_role_arn: Option<String>,
    pub timeout: Duration,
    pub retry_config: RetryConfig,
}

impl AwsKmsProvider {
    pub async fn new(config: AwsKmsConfig) -> Result<Self, CryptoError> {
        let aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .load()
            .await;

        let client = aws_sdk_kms::Client::new(&aws_config);

        Ok(Self {
            client,
            config,
            metrics: Arc::new(KmsMetrics::new("aws_kms")),
        })
    }
}

#[async_trait]
impl KmsProvider for AwsKmsProvider {
    async fn generate_data_key(&self, key_id: &KeyId) -> Result<DataKey, CryptoError> {
        let _timer = self.metrics.operation_timer("generate_data_key");

        let result = self.client
            .generate_data_key()
            .key_id(&key_id.0)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        let plaintext = result.plaintext()
            .ok_or(CryptoError::KmsError {
                message: "No plaintext returned".into(),
                source: None,
            })?
            .as_ref()
            .to_vec();

        let encrypted = result.ciphertext_blob()
            .ok_or(CryptoError::KmsError {
                message: "No ciphertext returned".into(),
                source: None,
            })?
            .as_ref()
            .to_vec();

        Ok(DataKey::new(plaintext, encrypted, key_id.clone()))
    }

    async fn decrypt_data_key(
        &self,
        key_id: &KeyId,
        encrypted_key: &[u8],
    ) -> Result<SecureBytes, CryptoError> {
        let _timer = self.metrics.operation_timer("decrypt_data_key");

        let result = self.client
            .decrypt()
            .key_id(&key_id.0)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(encrypted_key))
            .send()
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        let plaintext = result.plaintext()
            .ok_or(CryptoError::KmsError {
                message: "No plaintext returned".into(),
                source: None,
            })?
            .as_ref()
            .to_vec();

        Ok(SecureBytes::new(plaintext))
    }

    async fn encrypt(&self, key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let result = self.client
            .encrypt()
            .key_id(&key_id.0)
            .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext))
            .send()
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        Ok(result.ciphertext_blob()
            .ok_or(CryptoError::KmsError {
                message: "No ciphertext returned".into(),
                source: None,
            })?
            .as_ref()
            .to_vec())
    }

    async fn decrypt(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<SecureBytes, CryptoError> {
        self.decrypt_data_key(key_id, ciphertext).await
    }

    async fn create_key(&self, config: KeyConfig) -> Result<KeyId, CryptoError> {
        let mut request = self.client
            .create_key()
            .description(&config.description)
            .key_usage(aws_sdk_kms::types::KeyUsageType::EncryptDecrypt);

        for (key, value) in &config.tags {
            request = request.tags(
                aws_sdk_kms::types::Tag::builder()
                    .tag_key(key)
                    .tag_value(value)
                    .build()
                    .unwrap()
            );
        }

        let result = request.send().await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        let key_id = result.key_metadata()
            .and_then(|m| m.key_id())
            .ok_or(CryptoError::KmsError {
                message: "No key ID returned".into(),
                source: None,
            })?;

        Ok(KeyId::new(key_id))
    }

    async fn schedule_key_deletion(
        &self,
        key_id: &KeyId,
        pending_days: u32,
    ) -> Result<(), CryptoError> {
        self.client
            .schedule_key_deletion()
            .key_id(&key_id.0)
            .pending_window_in_days(pending_days as i32)
            .send()
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        Ok(())
    }

    async fn describe_key(&self, key_id: &KeyId) -> Result<KeyInfo, CryptoError> {
        let result = self.client
            .describe_key()
            .key_id(&key_id.0)
            .send()
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        let metadata = result.key_metadata()
            .ok_or(CryptoError::KmsError {
                message: "No key metadata returned".into(),
                source: None,
            })?;

        Ok(KeyInfo {
            key_id: KeyId::new(metadata.key_id()),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            created_at: metadata.creation_date()
                .and_then(|d| DateTime::from_timestamp(d.secs(), 0))
                .unwrap_or_else(Utc::now),
            rotated_at: None,
            version: 1,
            state: match metadata.key_state() {
                Some(aws_sdk_kms::types::KeyState::Enabled) => KeyState::Active,
                Some(aws_sdk_kms::types::KeyState::Disabled) => KeyState::Inactive,
                Some(aws_sdk_kms::types::KeyState::PendingDeletion) => KeyState::PendingRotation,
                _ => KeyState::Inactive,
            },
            usage: KeyUsage::EncryptDecrypt,
        })
    }

    fn provider_type(&self) -> &'static str {
        "aws_kms"
    }

    async fn health_check(&self) -> Result<HealthStatus, CryptoError> {
        let start = Instant::now();

        // List keys with limit 1 to test connectivity
        self.client
            .list_keys()
            .limit(1)
            .send()
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        Ok(HealthStatus {
            healthy: true,
            latency: start.elapsed(),
            message: None,
        })
    }
}

// ============================================================================
// HashiCorp Vault Implementation
// ============================================================================

// src/crypto/kms/vault.rs

pub struct VaultKmsProvider {
    client: VaultClient,
    config: VaultConfig,
    transit_mount: String,
    metrics: Arc<KmsMetrics>,
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: Option<SecureString>,
    pub role_id: Option<String>,
    pub secret_id: Option<SecureString>,
    pub namespace: Option<String>,
    pub transit_mount: String,
    pub timeout: Duration,
    pub tls_config: Option<TlsConfig>,
}

impl VaultKmsProvider {
    pub async fn new(config: VaultConfig) -> Result<Self, CryptoError> {
        let client = VaultClient::new(&config.address, config.timeout)?;

        // Authenticate
        let token = if let Some(ref token) = config.token {
            token.clone()
        } else if let (Some(ref role_id), Some(ref secret_id)) = (&config.role_id, &config.secret_id) {
            client.approle_login(role_id, secret_id.expose_secret()).await?
        } else {
            return Err(CryptoError::KmsError {
                message: "No authentication method provided".into(),
                source: None,
            });
        };

        let mut authenticated_client = client;
        authenticated_client.set_token(token);

        Ok(Self {
            client: authenticated_client,
            config: config.clone(),
            transit_mount: config.transit_mount,
            metrics: Arc::new(KmsMetrics::new("vault")),
        })
    }
}

#[async_trait]
impl KmsProvider for VaultKmsProvider {
    async fn generate_data_key(&self, key_id: &KeyId) -> Result<DataKey, CryptoError> {
        let _timer = self.metrics.operation_timer("generate_data_key");

        let path = format!("{}/datakey/plaintext/{}", self.transit_mount, key_id.0);

        let response: VaultDataKeyResponse = self.client
            .post(&path, &serde_json::json!({}))
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        let plaintext = base64::decode(&response.data.plaintext)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to decode plaintext: {}", e),
                source: None,
            })?;

        let encrypted = base64::decode(&response.data.ciphertext)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to decode ciphertext: {}", e),
                source: None,
            })?;

        Ok(DataKey::new(plaintext, encrypted, key_id.clone()))
    }

    async fn decrypt_data_key(
        &self,
        key_id: &KeyId,
        encrypted_key: &[u8],
    ) -> Result<SecureBytes, CryptoError> {
        let _timer = self.metrics.operation_timer("decrypt_data_key");

        let path = format!("{}/decrypt/{}", self.transit_mount, key_id.0);
        let ciphertext = base64::encode(encrypted_key);

        let response: VaultDecryptResponse = self.client
            .post(&path, &serde_json::json!({
                "ciphertext": ciphertext
            }))
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        let plaintext = base64::decode(&response.data.plaintext)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to decode plaintext: {}", e),
                source: None,
            })?;

        Ok(SecureBytes::new(plaintext))
    }

    async fn encrypt(&self, key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let path = format!("{}/encrypt/{}", self.transit_mount, key_id.0);
        let plaintext_b64 = base64::encode(plaintext);

        let response: VaultEncryptResponse = self.client
            .post(&path, &serde_json::json!({
                "plaintext": plaintext_b64
            }))
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        // Vault returns ciphertext with version prefix (e.g., "vault:v1:...")
        Ok(response.data.ciphertext.into_bytes())
    }

    async fn decrypt(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<SecureBytes, CryptoError> {
        let path = format!("{}/decrypt/{}", self.transit_mount, key_id.0);
        let ciphertext_str = String::from_utf8_lossy(ciphertext);

        let response: VaultDecryptResponse = self.client
            .post(&path, &serde_json::json!({
                "ciphertext": ciphertext_str
            }))
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        let plaintext = base64::decode(&response.data.plaintext)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to decode plaintext: {}", e),
                source: None,
            })?;

        Ok(SecureBytes::new(plaintext))
    }

    async fn create_key(&self, config: KeyConfig) -> Result<KeyId, CryptoError> {
        let key_name = format!("key-{}", Uuid::new_v4());
        let path = format!("{}/keys/{}", self.transit_mount, key_name);

        self.client
            .post(&path, &serde_json::json!({
                "type": "aes256-gcm96",
                "exportable": false,
                "allow_plaintext_backup": false
            }))
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        Ok(KeyId::new(key_name))
    }

    async fn schedule_key_deletion(
        &self,
        key_id: &KeyId,
        _pending_days: u32,
    ) -> Result<(), CryptoError> {
        let path = format!("{}/keys/{}/config", self.transit_mount, key_id.0);

        // Mark key for deletion
        self.client
            .post(&path, &serde_json::json!({
                "deletion_allowed": true
            }))
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        // Delete the key
        let delete_path = format!("{}/keys/{}", self.transit_mount, key_id.0);
        self.client
            .delete(&delete_path)
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        Ok(())
    }

    async fn describe_key(&self, key_id: &KeyId) -> Result<KeyInfo, CryptoError> {
        let path = format!("{}/keys/{}", self.transit_mount, key_id.0);

        let response: VaultKeyInfoResponse = self.client
            .get(&path)
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        Ok(KeyInfo {
            key_id: key_id.clone(),
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            created_at: Utc::now(), // Vault doesn't always expose this
            rotated_at: None,
            version: response.data.latest_version,
            state: if response.data.deletion_allowed {
                KeyState::PendingRotation
            } else {
                KeyState::Active
            },
            usage: KeyUsage::EncryptDecrypt,
        })
    }

    fn provider_type(&self) -> &'static str {
        "vault"
    }

    async fn health_check(&self) -> Result<HealthStatus, CryptoError> {
        let start = Instant::now();

        self.client
            .get::<serde_json::Value>("/v1/sys/health")
            .await
            .map_err(|e| CryptoError::KmsError {
                message: e.to_string(),
                source: Some(Box::new(e)),
            })?;

        Ok(HealthStatus {
            healthy: true,
            latency: start.elapsed(),
            message: None,
        })
    }
}
```

---

## 5. Key Rotation Manager

```rust
// src/crypto/rotation.rs

pub struct KeyRotationManager {
    kms: Arc<dyn KmsProvider>,
    storage: Arc<dyn StorageBackend>,
    config: RotationConfig,
    metrics: Arc<RotationMetrics>,
}

#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub rotation_interval: Duration,
    pub re_encryption_batch_size: usize,
    pub max_concurrent_re_encryptions: usize,
    pub notify_before_rotation: Duration,
}

impl KeyRotationManager {
    pub fn new(
        kms: Arc<dyn KmsProvider>,
        storage: Arc<dyn StorageBackend>,
        config: RotationConfig,
    ) -> Self {
        Self {
            kms,
            storage,
            config,
            metrics: Arc::new(RotationMetrics::new()),
        }
    }

    /// Initiate key rotation
    pub async fn rotate_key(&self, key_id: &KeyId) -> Result<KeyRotationResult, CryptoError> {
        let _timer = self.metrics.operation_timer("rotate_key");

        // Get current key info
        let old_key_info = self.kms.describe_key(key_id).await?;

        // Create new key
        let new_key_id = self.kms.create_key(KeyConfig {
            description: format!("Rotated from {}", key_id.0),
            usage: old_key_info.usage,
            algorithm: old_key_info.algorithm,
            tags: HashMap::from([
                ("rotated_from".to_string(), key_id.0.clone()),
                ("rotation_date".to_string(), Utc::now().to_rfc3339()),
            ]),
        }).await?;

        self.metrics.record_rotation();

        Ok(KeyRotationResult {
            old_key_id: key_id.clone(),
            new_key_id,
            new_version: old_key_info.version + 1,
            rotated_at: Utc::now(),
        })
    }

    /// Re-encrypt all data encrypted with old key
    pub async fn re_encrypt_data(
        &self,
        old_key_id: &KeyId,
        new_key_id: &KeyId,
        data_refs: &[DataReference],
    ) -> Result<ReEncryptionResult, CryptoError> {
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_re_encryptions));
        let mut futures = Vec::new();

        let mut success_count = 0;
        let mut failure_count = 0;
        let mut failures = Vec::new();

        for chunk in data_refs.chunks(self.config.re_encryption_batch_size) {
            for data_ref in chunk {
                let sem = semaphore.clone();
                let kms = self.kms.clone();
                let storage = self.storage.clone();
                let old_key = old_key_id.clone();
                let new_key = new_key_id.clone();
                let reference = data_ref.clone();

                futures.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    re_encrypt_single(&kms, &storage, &old_key, &new_key, &reference).await
                }));
            }
        }

        for future in futures {
            match future.await {
                Ok(Ok(())) => success_count += 1,
                Ok(Err(e)) => {
                    failure_count += 1;
                    failures.push(e.to_string());
                }
                Err(e) => {
                    failure_count += 1;
                    failures.push(format!("Task panicked: {}", e));
                }
            }
        }

        Ok(ReEncryptionResult {
            success_count,
            failure_count,
            failures,
        })
    }

    /// Check if key needs rotation
    pub async fn should_rotate(&self, key_id: &KeyId) -> Result<bool, CryptoError> {
        let key_info = self.kms.describe_key(key_id).await?;

        let age = Utc::now() - key_info.created_at;
        Ok(age.to_std().unwrap_or(Duration::ZERO) >= self.config.rotation_interval)
    }
}

async fn re_encrypt_single(
    kms: &Arc<dyn KmsProvider>,
    storage: &Arc<dyn StorageBackend>,
    old_key_id: &KeyId,
    new_key_id: &KeyId,
    data_ref: &DataReference,
) -> Result<(), CryptoError> {
    // Read encrypted data
    let encrypted_data = storage.get(&data_ref.storage_key).await
        .map_err(|e| CryptoError::KmsError {
            message: format!("Failed to read data: {}", e),
            source: None,
        })?;

    // Decrypt with old key
    let plaintext = kms.decrypt(old_key_id, &encrypted_data).await?;

    // Encrypt with new key
    let new_ciphertext = kms.encrypt(new_key_id, plaintext.as_slice()).await?;

    // Write back
    storage.put(
        &data_ref.storage_key,
        Bytes::from(new_ciphertext),
        PutOptions::default(),
    ).await.map_err(|e| CryptoError::KmsError {
        message: format!("Failed to write data: {}", e),
        source: None,
    })?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct DataReference {
    pub storage_key: StorageKey,
    pub data_type: DataType,
}

#[derive(Debug, Clone)]
pub struct ReEncryptionResult {
    pub success_count: usize,
    pub failure_count: usize,
    pub failures: Vec<String>,
}
```

---

## 6. TLS/mTLS Configuration

```rust
// src/crypto/tls.rs

use rustls::{Certificate, PrivateKey, ServerConfig, ClientConfig};

pub struct TlsManager {
    config: TlsManagerConfig,
}

#[derive(Debug, Clone)]
pub struct TlsManagerConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
    pub client_auth: ClientAuth,
    pub min_protocol_version: TlsVersion,
    pub cipher_suites: Vec<CipherSuite>,
}

#[derive(Debug, Clone, Copy)]
pub enum ClientAuth {
    None,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsManager {
    pub fn new(config: TlsManagerConfig) -> Result<Self, CryptoError> {
        Ok(Self { config })
    }

    /// Build server TLS config
    pub fn server_config(&self) -> Result<ServerConfig, CryptoError> {
        let certs = self.load_certificates(&self.config.cert_path)?;
        let key = self.load_private_key(&self.config.key_path)?;

        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to build server config: {}", e),
                source: None,
            })?;

        // Configure client authentication if required
        if matches!(self.config.client_auth, ClientAuth::Required | ClientAuth::Optional) {
            if let Some(ref ca_path) = self.config.ca_path {
                let ca_certs = self.load_certificates(ca_path)?;
                let mut roots = rustls::RootCertStore::empty();
                for cert in ca_certs {
                    roots.add(&cert).map_err(|e| CryptoError::KmsError {
                        message: format!("Failed to add CA cert: {}", e),
                        source: None,
                    })?;
                }

                let verifier = if matches!(self.config.client_auth, ClientAuth::Required) {
                    rustls::server::AllowAnyAuthenticatedClient::new(roots)
                } else {
                    rustls::server::AllowAnyAnonymousOrAuthenticatedClient::new(roots)
                };

                config = ServerConfig::builder()
                    .with_safe_defaults()
                    .with_client_cert_verifier(Arc::new(verifier))
                    .with_single_cert(
                        self.load_certificates(&self.config.cert_path)?,
                        self.load_private_key(&self.config.key_path)?
                    )
                    .map_err(|e| CryptoError::KmsError {
                        message: format!("Failed to build server config: {}", e),
                        source: None,
                    })?;
            }
        }

        Ok(config)
    }

    /// Build client TLS config for mTLS
    pub fn client_config(&self) -> Result<ClientConfig, CryptoError> {
        let certs = self.load_certificates(&self.config.cert_path)?;
        let key = self.load_private_key(&self.config.key_path)?;

        let mut roots = rustls::RootCertStore::empty();
        if let Some(ref ca_path) = self.config.ca_path {
            let ca_certs = self.load_certificates(ca_path)?;
            for cert in ca_certs {
                roots.add(&cert).map_err(|e| CryptoError::KmsError {
                    message: format!("Failed to add CA cert: {}", e),
                    source: None,
                })?;
            }
        }

        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to build client config: {}", e),
                source: None,
            })
    }

    fn load_certificates(&self, path: &Path) -> Result<Vec<Certificate>, CryptoError> {
        let file = std::fs::File::open(path)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to open cert file: {}", e),
                source: None,
            })?;
        let mut reader = std::io::BufReader::new(file);

        let certs = rustls_pemfile::certs(&mut reader)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to parse certs: {}", e),
                source: None,
            })?
            .into_iter()
            .map(Certificate)
            .collect();

        Ok(certs)
    }

    fn load_private_key(&self, path: &Path) -> Result<PrivateKey, CryptoError> {
        let file = std::fs::File::open(path)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to open key file: {}", e),
                source: None,
            })?;
        let mut reader = std::io::BufReader::new(file);

        let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .map_err(|e| CryptoError::KmsError {
                message: format!("Failed to parse private key: {}", e),
                source: None,
            })?;

        keys.into_iter()
            .next()
            .map(PrivateKey)
            .ok_or(CryptoError::KmsError {
                message: "No private key found".into(),
                source: None,
            })
    }
}
```

---

## Summary

This document defines the encryption and security layer for LLM-Data-Vault:

| Component | Purpose |
|-----------|---------|
| **EncryptionProvider Trait** | Abstract interface for encryption operations |
| **CryptoEngine** | Low-level cryptographic primitives (AES-GCM, HMAC, HKDF) |
| **EnvelopeEncryption** | DEK/KEK architecture with caching |
| **KmsProvider** | KMS abstraction with AWS KMS and Vault implementations |
| **KeyRotationManager** | Automated key rotation and re-encryption |
| **TlsManager** | TLS/mTLS configuration for secure communication |

**Security Features:**
- AES-256-GCM encryption with authenticated encryption
- Envelope encryption pattern for scalability
- Secure memory handling with zeroization
- Key caching with TTL to reduce KMS calls
- Support for multiple KMS providers
- Automated key rotation
- mTLS for service-to-service authentication

---

*Next Document: [04-anonymization-engine.md](./04-anonymization-engine.md)*
