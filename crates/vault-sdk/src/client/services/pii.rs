//! PII detection and anonymization service.

use std::sync::Arc;

use crate::error::Result;
use crate::models::{
    PiiDetectionRequest, PiiDetectionResult, AnonymizationRequest, AnonymizationResult,
    PiiType, AnonymizationStrategy,
};

use super::super::http::HttpClient;

/// Service for PII detection and anonymization.
#[derive(Clone)]
pub struct PiiService {
    http: Arc<HttpClient>,
}

impl PiiService {
    /// Creates a new PII service.
    pub(crate) fn new(http: Arc<HttpClient>) -> Self {
        Self { http }
    }

    /// Detects PII in text.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, PiiDetectionRequest};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let text = "Contact John Doe at john.doe@example.com or 555-123-4567";
    ///
    /// let result = client.pii().detect(text).await?;
    ///
    /// for entity in result.entities {
    ///     println!("{}: {} (confidence: {:.2})",
    ///         entity.pii_type, entity.text, entity.confidence);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn detect(&self, text: &str) -> Result<PiiDetectionResult> {
        let request = PiiDetectionRequest::new(text);
        self.detect_with_options(&request).await
    }

    /// Detects PII with custom options.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, PiiDetectionRequest, PiiType};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let request = PiiDetectionRequest::new("Contact john@example.com")
    ///     .with_types(vec![PiiType::Email, PiiType::Phone])
    ///     .with_min_confidence(0.9)
    ///     .with_context();
    ///
    /// let result = client.pii().detect_with_options(&request).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn detect_with_options(&self, request: &PiiDetectionRequest) -> Result<PiiDetectionResult> {
        self.http.post("/api/v1/pii/detect", request).await
    }

    /// Anonymizes text by replacing PII.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let text = "Contact John Doe at john.doe@example.com";
    ///
    /// let result = client.pii().anonymize(text).await?;
    ///
    /// println!("Original: {}", text);
    /// println!("Anonymized: {}", result.anonymized_text);
    /// // Output: "Contact [PERSON_NAME] at [EMAIL]"
    /// # Ok(())
    /// # }
    /// ```
    pub async fn anonymize(&self, text: &str) -> Result<AnonymizationResult> {
        let request = AnonymizationRequest::new(text);
        self.anonymize_with_options(&request).await
    }

    /// Anonymizes text with custom options.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, AnonymizationRequest, AnonymizationStrategy, PiiType};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let request = AnonymizationRequest::new("Email: john@example.com, SSN: 123-45-6789")
    ///     .with_strategy(AnonymizationStrategy::Mask)
    ///     .with_type_strategy(PiiType::Ssn, AnonymizationStrategy::Redact);
    ///
    /// let result = client.pii().anonymize_with_options(&request).await?;
    /// // Output: "Email: j***@***.com, SSN: [SSN]"
    /// # Ok(())
    /// # }
    /// ```
    pub async fn anonymize_with_options(&self, request: &AnonymizationRequest) -> Result<AnonymizationResult> {
        self.http.post("/api/v1/pii/anonymize", request).await
    }

    /// Detects and anonymizes in one call.
    ///
    /// More efficient than calling detect and anonymize separately.
    pub async fn detect_and_anonymize(
        &self,
        text: &str,
        strategy: AnonymizationStrategy,
    ) -> Result<(PiiDetectionResult, AnonymizationResult)> {
        #[derive(serde::Serialize)]
        struct Request<'a> {
            text: &'a str,
            strategy: AnonymizationStrategy,
        }

        #[derive(serde::Deserialize)]
        struct Response {
            detection: PiiDetectionResult,
            anonymization: AnonymizationResult,
        }

        let response: Response = self.http
            .post("/api/v1/pii/process", &Request { text, strategy })
            .await?;

        Ok((response.detection, response.anonymization))
    }

    /// Validates that text contains no PII.
    ///
    /// Returns `true` if no PII was detected, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let text = "The weather is nice today.";
    ///
    /// if client.pii().is_clean(text).await? {
    ///     println!("Text is clean - no PII detected");
    /// } else {
    ///     println!("Warning: PII detected!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn is_clean(&self, text: &str) -> Result<bool> {
        let result = self.detect(text).await?;
        Ok(result.entities.is_empty())
    }

    /// Gets supported PII types.
    pub async fn supported_types(&self) -> Result<Vec<PiiTypeInfo>> {
        self.http.get("/api/v1/pii/types").await
    }

    /// Gets supported anonymization strategies.
    pub async fn supported_strategies(&self) -> Result<Vec<StrategyInfo>> {
        self.http.get("/api/v1/pii/strategies").await
    }
}

/// Information about a supported PII type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiiTypeInfo {
    /// PII type identifier.
    pub pii_type: PiiType,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Example patterns.
    pub examples: Vec<String>,
}

/// Information about a supported anonymization strategy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StrategyInfo {
    /// Strategy identifier.
    pub strategy: AnonymizationStrategy,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Example transformation.
    pub example: String,
}

impl std::fmt::Debug for PiiService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiiService").finish_non_exhaustive()
    }
}
