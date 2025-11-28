//! # Vault Crypto
//!
//! Cryptographic services for LLM Data Vault including:
//! - AES-256-GCM encryption
//! - Envelope encryption with KMS
//! - Secure key management
//! - Data key caching

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod encryption;
pub mod kms;
pub mod envelope;
pub mod key;
pub mod hash;
pub mod error;

pub use encryption::*;
pub use kms::*;
pub use envelope::*;
pub use key::*;
pub use hash::*;
pub use error::*;
