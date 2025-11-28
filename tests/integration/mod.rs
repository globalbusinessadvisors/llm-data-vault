//! Integration tests for LLM Data Vault.
//!
//! This module contains comprehensive integration tests covering:
//! - API endpoints
//! - Authentication and authorization
//! - Storage backends
//! - PII detection and anonymization
//! - Webhooks and events

pub mod common;
pub mod api;
pub mod auth;
pub mod storage;
pub mod pii;
pub mod webhooks;
