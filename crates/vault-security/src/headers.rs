//! Security headers middleware.
//!
//! Implements HTTP security headers including:
//! - Content-Security-Policy
//! - X-Frame-Options
//! - X-Content-Type-Options
//! - Referrer-Policy
//! - Permissions-Policy
//! - Strict-Transport-Security
//! - Cross-Origin policies

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::{header, HeaderValue, Request, Response};
use tower::{Layer, Service};

use crate::config::{HeadersConfig, TlsConfig};

/// Security headers configuration for middleware.
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    config: HeadersConfig,
    tls_config: Option<TlsConfig>,
}

impl SecurityHeaders {
    /// Creates new security headers from configuration.
    #[must_use]
    pub fn new(config: HeadersConfig) -> Self {
        Self {
            config,
            tls_config: None,
        }
    }

    /// Sets TLS configuration for HSTS header.
    #[must_use]
    pub fn with_tls(mut self, tls_config: TlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Returns the X-Frame-Options header value.
    #[must_use]
    pub fn frame_options(&self) -> &str {
        &self.config.frame_options
    }

    /// Returns the X-Content-Type-Options header value.
    #[must_use]
    pub fn content_type_options(&self) -> &str {
        &self.config.content_type_options
    }

    /// Returns the Referrer-Policy header value.
    #[must_use]
    pub fn referrer_policy(&self) -> &str {
        &self.config.referrer_policy
    }

    /// Returns the Content-Security-Policy header value if set.
    #[must_use]
    pub fn content_security_policy(&self) -> Option<&str> {
        self.config.content_security_policy.as_deref()
    }

    /// Returns the Permissions-Policy header value if set.
    #[must_use]
    pub fn permissions_policy(&self) -> Option<&str> {
        self.config.permissions_policy.as_deref()
    }

    /// Returns the Cross-Origin-Opener-Policy header value.
    #[must_use]
    pub fn cross_origin_opener_policy(&self) -> &str {
        &self.config.cross_origin_opener_policy
    }

    /// Returns the Cross-Origin-Resource-Policy header value.
    #[must_use]
    pub fn cross_origin_resource_policy(&self) -> &str {
        &self.config.cross_origin_resource_policy
    }

    /// Returns the Cross-Origin-Embedder-Policy header value if set.
    #[must_use]
    pub fn cross_origin_embedder_policy(&self) -> Option<&str> {
        self.config.cross_origin_embedder_policy.as_deref()
    }

    /// Returns the HSTS header value if TLS is configured.
    #[must_use]
    pub fn strict_transport_security(&self) -> Option<String> {
        self.tls_config.as_ref().map(|tls| {
            let mut value = format!("max-age={}", tls.hsts_max_age_secs);

            if tls.hsts_include_subdomains {
                value.push_str("; includeSubDomains");
            }

            if tls.hsts_preload {
                value.push_str("; preload");
            }

            value
        })
    }

    /// Returns whether XSS protection header should be added.
    #[must_use]
    pub fn xss_protection_enabled(&self) -> bool {
        self.config.xss_protection
    }
}

/// Tower layer for adding security headers.
#[derive(Debug, Clone)]
pub struct SecurityHeadersLayer {
    headers: SecurityHeaders,
}

impl SecurityHeadersLayer {
    /// Creates a new security headers layer.
    #[must_use]
    pub fn new(config: HeadersConfig) -> Self {
        Self {
            headers: SecurityHeaders::new(config),
        }
    }

    /// Creates a layer with TLS configuration.
    #[must_use]
    pub fn with_tls(config: HeadersConfig, tls_config: TlsConfig) -> Self {
        Self {
            headers: SecurityHeaders::new(config).with_tls(tls_config),
        }
    }

    /// Creates a production-ready layer with all security headers.
    #[must_use]
    pub fn production() -> Self {
        Self {
            headers: SecurityHeaders::new(HeadersConfig::production_defaults())
                .with_tls(TlsConfig::production_defaults()),
        }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            headers: self.headers.clone(),
        }
    }
}

/// Tower service for adding security headers.
#[derive(Debug, Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    headers: SecurityHeaders,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let headers = self.headers.clone();
        let future = self.inner.call(request);

        Box::pin(async move {
            let mut response = future.await?;

            // Add security headers
            let response_headers = response.headers_mut();

            // X-Frame-Options
            if let Ok(value) = HeaderValue::from_str(headers.frame_options()) {
                response_headers.insert(header::X_FRAME_OPTIONS, value);
            }

            // X-Content-Type-Options
            if let Ok(value) = HeaderValue::from_str(headers.content_type_options()) {
                response_headers.insert(header::X_CONTENT_TYPE_OPTIONS, value);
            }

            // Referrer-Policy
            if let Ok(value) = HeaderValue::from_str(headers.referrer_policy()) {
                response_headers.insert(header::REFERRER_POLICY, value);
            }

            // Content-Security-Policy
            if let Some(csp) = headers.content_security_policy() {
                if let Ok(value) = HeaderValue::from_str(csp) {
                    response_headers.insert(header::CONTENT_SECURITY_POLICY, value);
                }
            }

            // Permissions-Policy
            if let Some(pp) = headers.permissions_policy() {
                if let Ok(value) = HeaderValue::from_str(pp) {
                    let name = header::HeaderName::from_static("permissions-policy");
                    response_headers.insert(name, value);
                }
            }

            // Strict-Transport-Security
            if let Some(hsts) = headers.strict_transport_security() {
                if let Ok(value) = HeaderValue::from_str(&hsts) {
                    response_headers.insert(header::STRICT_TRANSPORT_SECURITY, value);
                }
            }

            // X-XSS-Protection (legacy, but still useful for older browsers)
            if headers.xss_protection_enabled() {
                if let Ok(value) = HeaderValue::from_str("1; mode=block") {
                    response_headers.insert(header::X_XSS_PROTECTION, value);
                }
            }

            // Cross-Origin-Opener-Policy
            if let Ok(value) = HeaderValue::from_str(headers.cross_origin_opener_policy()) {
                let name = header::HeaderName::from_static("cross-origin-opener-policy");
                response_headers.insert(name, value);
            }

            // Cross-Origin-Resource-Policy
            if let Ok(value) = HeaderValue::from_str(headers.cross_origin_resource_policy()) {
                let name = header::HeaderName::from_static("cross-origin-resource-policy");
                response_headers.insert(name, value);
            }

            // Cross-Origin-Embedder-Policy
            if let Some(coep) = headers.cross_origin_embedder_policy() {
                if let Ok(value) = HeaderValue::from_str(coep) {
                    let name = header::HeaderName::from_static("cross-origin-embedder-policy");
                    response_headers.insert(name, value);
                }
            }

            // Remove potentially dangerous headers
            response_headers.remove(header::SERVER);
            response_headers.remove("x-powered-by");

            Ok(response)
        })
    }
}

/// Builder for custom security headers.
#[derive(Debug, Clone, Default)]
pub struct SecurityHeadersBuilder {
    config: HeadersConfig,
    tls_config: Option<TlsConfig>,
}

impl SecurityHeadersBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Content-Security-Policy.
    #[must_use]
    pub fn content_security_policy(mut self, csp: impl Into<String>) -> Self {
        self.config.content_security_policy = Some(csp.into());
        self
    }

    /// Sets the X-Frame-Options.
    #[must_use]
    pub fn frame_options(mut self, value: impl Into<String>) -> Self {
        self.config.frame_options = value.into();
        self
    }

    /// Sets the Referrer-Policy.
    #[must_use]
    pub fn referrer_policy(mut self, value: impl Into<String>) -> Self {
        self.config.referrer_policy = value.into();
        self
    }

    /// Sets the Permissions-Policy.
    #[must_use]
    pub fn permissions_policy(mut self, value: impl Into<String>) -> Self {
        self.config.permissions_policy = Some(value.into());
        self
    }

    /// Enables HSTS with the given max age.
    #[must_use]
    pub fn hsts(mut self, max_age_secs: u64, include_subdomains: bool, preload: bool) -> Self {
        self.tls_config = Some(TlsConfig {
            require_tls: true,
            hsts_max_age_secs: max_age_secs,
            hsts_include_subdomains: include_subdomains,
            hsts_preload: preload,
            ..Default::default()
        });
        self
    }

    /// Enables XSS protection header.
    #[must_use]
    pub fn xss_protection(mut self, enabled: bool) -> Self {
        self.config.xss_protection = enabled;
        self
    }

    /// Sets Cross-Origin-Opener-Policy.
    #[must_use]
    pub fn cross_origin_opener_policy(mut self, value: impl Into<String>) -> Self {
        self.config.cross_origin_opener_policy = value.into();
        self
    }

    /// Sets Cross-Origin-Resource-Policy.
    #[must_use]
    pub fn cross_origin_resource_policy(mut self, value: impl Into<String>) -> Self {
        self.config.cross_origin_resource_policy = value.into();
        self
    }

    /// Sets Cross-Origin-Embedder-Policy.
    #[must_use]
    pub fn cross_origin_embedder_policy(mut self, value: impl Into<String>) -> Self {
        self.config.cross_origin_embedder_policy = Some(value.into());
        self
    }

    /// Builds the security headers layer.
    #[must_use]
    pub fn build(self) -> SecurityHeadersLayer {
        let mut headers = SecurityHeaders::new(self.config);

        if let Some(tls) = self.tls_config {
            headers = headers.with_tls(tls);
        }

        SecurityHeadersLayer { headers }
    }
}

/// Predefined CSP policies.
pub mod csp {
    /// A strict CSP for API-only services.
    pub const API_ONLY: &str = "default-src 'none'; frame-ancestors 'none'";

    /// A CSP for single-page applications.
    pub const SPA: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                           img-src 'self' data: https:; font-src 'self'; connect-src 'self' https:; \
                           frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

    /// A CSP for traditional web applications.
    pub const WEB_APP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                               img-src 'self' data:; font-src 'self'; connect-src 'self'; \
                               frame-ancestors 'self'; base-uri 'self'; form-action 'self'; \
                               upgrade-insecure-requests";

    /// A very strict CSP that disallows most resources.
    pub const STRICT: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                              img-src 'self'; font-src 'self'; connect-src 'self'; \
                              frame-ancestors 'none'; base-uri 'self'; form-action 'self'; \
                              upgrade-insecure-requests; block-all-mixed-content";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_headers_default() {
        let headers = SecurityHeaders::new(HeadersConfig::default());

        assert_eq!(headers.frame_options(), "DENY");
        assert_eq!(headers.content_type_options(), "nosniff");
        assert!(headers.xss_protection_enabled());
    }

    #[test]
    fn test_security_headers_production() {
        let headers = SecurityHeaders::new(HeadersConfig::production_defaults())
            .with_tls(TlsConfig::production_defaults());

        assert!(headers.content_security_policy().is_some());
        assert!(headers.permissions_policy().is_some());
        assert!(headers.strict_transport_security().is_some());
    }

    #[test]
    fn test_hsts_value() {
        let tls = TlsConfig {
            hsts_max_age_secs: 31536000,
            hsts_include_subdomains: true,
            hsts_preload: true,
            ..Default::default()
        };

        let headers = SecurityHeaders::new(HeadersConfig::default()).with_tls(tls);
        let hsts = headers.strict_transport_security().unwrap();

        assert!(hsts.contains("max-age=31536000"));
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("preload"));
    }

    #[test]
    fn test_builder() {
        let layer = SecurityHeadersBuilder::new()
            .content_security_policy(csp::API_ONLY)
            .frame_options("SAMEORIGIN")
            .hsts(63072000, true, true)
            .build();

        assert!(layer.headers.content_security_policy().is_some());
        assert!(layer.headers.strict_transport_security().is_some());
    }
}
