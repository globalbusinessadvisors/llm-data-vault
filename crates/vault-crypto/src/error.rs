//! Cryptographic error types.

use thiserror::Error;

/// Cryptographic errors.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid key.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// KMS error.
    #[error("KMS error: {0}")]
    KmsError(String),

    /// Invalid nonce.
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Invalid ciphertext.
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Authentication failed (AEAD tag mismatch).
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Hash verification failed.
    #[error("hash verification failed")]
    HashVerificationFailed,

    /// Unsupported algorithm.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for crypto operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

impl From<aes_gcm::Error> for CryptoError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::AuthenticationFailed
    }
}
