//! Type-safe identifiers using the newtype pattern.
//!
//! These types prevent accidental mixing of different ID types at compile time.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new random ID.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Creates an ID from an existing UUID.
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Returns the inner UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Returns the inner UUID value.
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Creates an ID from bytes.
            ///
            /// # Errors
            /// Returns an error if the bytes don't represent a valid UUID.
            pub fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(bytes))
            }

            /// Returns the ID as bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Creates a nil (all zeros) ID.
            #[must_use]
            pub const fn nil() -> Self {
                Self(Uuid::nil())
            }

            /// Returns true if this is a nil ID.
            #[must_use]
            pub fn is_nil(&self) -> bool {
                self.0.is_nil()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl AsRef<Uuid> for $name {
            fn as_ref(&self) -> &Uuid {
                &self.0
            }
        }
    };
}

define_id!(DatasetId, "Unique identifier for a dataset.");
define_id!(VersionId, "Unique identifier for a dataset version.");
define_id!(RecordId, "Unique identifier for a data record.");
define_id!(TenantId, "Unique identifier for a tenant.");
define_id!(UserId, "Unique identifier for a user.");
define_id!(KeyId, "Unique identifier for an encryption key.");
define_id!(PolicyId, "Unique identifier for an access policy.");
define_id!(RoleId, "Unique identifier for a role.");
define_id!(TokenId, "Unique identifier for an anonymization token.");
define_id!(AuditEventId, "Unique identifier for an audit event.");
define_id!(CorpusId, "Unique identifier for a corpus.");
define_id!(WebhookId, "Unique identifier for a webhook.");
define_id!(RequestId, "Unique identifier for a request (tracing).");
define_id!(SchemaId, "Unique identifier for a schema.");
define_id!(LineageNodeId, "Unique identifier for a lineage node.");

/// Content hash for content-addressable storage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash {
    /// The hash algorithm used.
    pub algorithm: HashAlgorithm,
    /// The hash bytes (hex-encoded).
    pub hash: String,
}

impl ContentHash {
    /// Creates a new content hash.
    #[must_use]
    pub fn new(algorithm: HashAlgorithm, hash: String) -> Self {
        Self { algorithm, hash }
    }

    /// Creates a BLAKE3 hash from bytes.
    #[must_use]
    pub fn blake3(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self {
            algorithm: HashAlgorithm::Blake3,
            hash: hash.to_hex().to_string(),
        }
    }

    /// Creates a SHA-256 hash from bytes.
    #[must_use]
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Self {
            algorithm: HashAlgorithm::Sha256,
            hash: hex::encode(result),
        }
    }

    /// Returns the hash as a storage key.
    #[must_use]
    pub fn to_storage_key(&self) -> String {
        format!("{}/{}", self.algorithm.as_str(), self.hash)
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm.as_str(), self.hash)
    }
}

/// Hash algorithm used for content addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// BLAKE3 (fast, secure).
    Blake3,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Returns the algorithm name as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Blake3
    }
}

// Add hex encoding support
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataset_id_creation() {
        let id1 = DatasetId::new();
        let id2 = DatasetId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_id_from_str() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let id: DatasetId = uuid_str.parse().unwrap();
        assert_eq!(id.to_string(), uuid_str);
    }

    #[test]
    fn test_content_hash_blake3() {
        let data = b"test data";
        let hash = ContentHash::blake3(data);
        assert_eq!(hash.algorithm, HashAlgorithm::Blake3);
        assert!(!hash.hash.is_empty());
    }

    #[test]
    fn test_nil_id() {
        let id = DatasetId::nil();
        assert!(id.is_nil());
    }
}
