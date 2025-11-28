//! # Vault Core
//!
//! Core domain types, identifiers, and interfaces for LLM Data Vault.
//!
//! This crate provides the foundational types used throughout the system:
//! - Type-safe identifiers (newtype pattern)
//! - Domain entities (Dataset, Version, Record)
//! - Error types
//! - Common traits and interfaces

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod error;
pub mod id;
pub mod dataset;
pub mod record;
pub mod schema;
pub mod version;
pub mod tenant;
pub mod user;
pub mod metadata;
pub mod audit;

pub use error::{VaultError, VaultResult};
pub use id::*;
pub use dataset::*;
pub use record::*;
pub use schema::*;
pub use version::*;
pub use tenant::*;
pub use user::*;
pub use metadata::*;
pub use audit::*;
