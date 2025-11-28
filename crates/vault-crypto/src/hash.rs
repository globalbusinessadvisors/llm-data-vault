//! Hashing utilities.

use crate::{CryptoResult, SecureBytes};
use sha2::{Digest, Sha256, Sha512};

/// Hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// BLAKE3.
    Blake3,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Returns the output size in bytes.
    #[must_use]
    pub const fn output_size(&self) -> usize {
        match self {
            Self::Blake3 => 32,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Computes a hash of the given data.
#[must_use]
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
    }
}

/// Computes a hash and returns it as a hex string.
#[must_use]
pub fn hash_hex(algorithm: HashAlgorithm, data: &[u8]) -> String {
    hex_encode(&hash(algorithm, data))
}

/// BLAKE3 hash.
#[must_use]
pub fn blake3(data: &[u8]) -> Vec<u8> {
    hash(HashAlgorithm::Blake3, data)
}

/// BLAKE3 hash as hex.
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    hash_hex(HashAlgorithm::Blake3, data)
}

/// SHA-256 hash.
#[must_use]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    hash(HashAlgorithm::Sha256, data)
}

/// SHA-256 hash as hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hash_hex(HashAlgorithm::Sha256, data)
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA256 as hex.
#[must_use]
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    hex_encode(&hmac_sha256(key, data))
}

/// Verifies an HMAC-SHA256.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let computed = hmac_sha256(key, data);
    constant_time_eq(&computed, expected)
}

/// Derives a key using Argon2id.
pub fn derive_key_argon2(
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> CryptoResult<SecureBytes> {
    use argon2::{Argon2, Algorithm, Version, Params};

    let params = Params::new(65536, 3, 4, Some(output_len))
        .map_err(|e| crate::CryptoError::KeyGenerationFailed(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| crate::CryptoError::KeyGenerationFailed(e.to_string()))?;

    Ok(SecureBytes::new(output))
}

/// Generates random bytes.
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes
}

/// Generates a random salt for key derivation.
#[must_use]
pub fn random_salt() -> Vec<u8> {
    random_bytes(32)
}

/// Constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Hex encoding.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Checksum for data integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// Algorithm used.
    pub algorithm: HashAlgorithm,
    /// Hash value.
    pub value: Vec<u8>,
}

impl Checksum {
    /// Computes a checksum.
    #[must_use]
    pub fn compute(algorithm: HashAlgorithm, data: &[u8]) -> Self {
        Self {
            algorithm,
            value: hash(algorithm, data),
        }
    }

    /// Computes a BLAKE3 checksum.
    #[must_use]
    pub fn blake3(data: &[u8]) -> Self {
        Self::compute(HashAlgorithm::Blake3, data)
    }

    /// Verifies data against this checksum.
    #[must_use]
    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = hash(self.algorithm, data);
        constant_time_eq(&computed, &self.value)
    }

    /// Returns the checksum as a hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_encode(&self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3() {
        let data = b"test data";
        let hash1 = blake3(data);
        let hash2 = blake3(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let data = b"message";

        let mac = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &mac));
        assert!(!hmac_sha256_verify(key, b"different", &mac));
    }

    #[test]
    fn test_argon2() {
        let password = b"password123";
        let salt = random_salt();

        let key = derive_key_argon2(password, &salt, 32).unwrap();
        assert_eq!(key.len(), 32);

        // Same password and salt should produce same key
        let key2 = derive_key_argon2(password, &salt, 32).unwrap();
        assert_eq!(key.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_checksum() {
        let data = b"test data";
        let checksum = Checksum::blake3(data);

        assert!(checksum.verify(data));
        assert!(!checksum.verify(b"different data"));
    }
}
