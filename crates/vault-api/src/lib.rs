//! REST and gRPC API layer for LLM Data Vault.
//!
//! This crate provides:
//! - REST API with Axum
//! - API versioning
//! - Request validation
//! - Rate limiting
//! - Metrics and observability
//! - OpenAPI documentation

pub mod error;
pub mod routes;
pub mod handlers;
pub mod middleware;
pub mod state;
pub mod response;
pub mod pagination;
pub mod validation;

pub use error::{ApiError, ApiResult};
pub use routes::create_router;
pub use state::AppState;
pub use response::{ApiResponse, JsonResponse};
pub use pagination::{Pagination, PagedResponse};
