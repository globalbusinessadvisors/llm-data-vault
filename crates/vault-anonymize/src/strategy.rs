//! Anonymization strategies.

use crate::{AnonymizeError, AnonymizeResult, Detection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::record::PIIType;

/// Anonymization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnonymizationStrategy {
    /// Replace with asterisks/X's.
    Mask,
    /// Replace with random placeholder.
    Redact,
    /// Replace with synthetic data.
    Substitute,
    /// Replace with consistent token.
    Tokenize,
    /// Encrypt the value.
    Encrypt,
    /// Hash the value.
    Hash,
    /// Remove entirely.
    Remove,
    /// Generalize (e.g., exact age -> age range).
    Generalize,
    /// Truncate (e.g., ZIP code -> first 3 digits).
    Truncate,
    /// Shuffle within dataset.
    Shuffle,
    /// Add noise (for numeric values).
    Noise,
    /// No anonymization (pass through).
    None,
}

impl Default for AnonymizationStrategy {
    fn default() -> Self {
        Self::Mask
    }
}

/// Strategy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyConfig {
    /// Default strategy for all PII types.
    pub default_strategy: AnonymizationStrategy,
    /// Per-type strategy overrides.
    pub type_strategies: HashMap<PIIType, AnonymizationStrategy>,
    /// Mask character.
    pub mask_char: char,
    /// Preserve format when masking.
    pub preserve_format: bool,
    /// Token prefix.
    pub token_prefix: String,
    /// Use deterministic tokens.
    pub deterministic_tokens: bool,
    /// Encryption key ID (for Encrypt strategy).
    pub encryption_key_id: Option<String>,
    /// Hash algorithm (for Hash strategy).
    pub hash_algorithm: HashAlgorithm,
    /// Generalization rules.
    pub generalization_rules: HashMap<PIIType, GeneralizationRule>,
    /// Truncation lengths.
    pub truncation_lengths: HashMap<PIIType, usize>,
    /// Noise level (for Noise strategy).
    pub noise_level: f64,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        let mut type_strategies = HashMap::new();
        type_strategies.insert(PIIType::CreditCard, AnonymizationStrategy::Mask);
        type_strategies.insert(PIIType::Ssn, AnonymizationStrategy::Mask);
        type_strategies.insert(PIIType::Email, AnonymizationStrategy::Substitute);
        type_strategies.insert(PIIType::Phone, AnonymizationStrategy::Mask);
        type_strategies.insert(PIIType::Password, AnonymizationStrategy::Redact);
        type_strategies.insert(PIIType::ApiKey, AnonymizationStrategy::Redact);

        Self {
            default_strategy: AnonymizationStrategy::Mask,
            type_strategies,
            mask_char: '*',
            preserve_format: true,
            token_prefix: "TOK_".to_string(),
            deterministic_tokens: true,
            encryption_key_id: None,
            hash_algorithm: HashAlgorithm::Sha256,
            generalization_rules: HashMap::new(),
            truncation_lengths: HashMap::new(),
            noise_level: 0.1,
        }
    }
}

impl StrategyConfig {
    /// Returns the strategy for a PII type.
    #[must_use]
    pub fn strategy_for(&self, pii_type: &PIIType) -> AnonymizationStrategy {
        self.type_strategies
            .get(pii_type)
            .copied()
            .unwrap_or(self.default_strategy)
    }
}

/// Hash algorithm for hashing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
    Sha512,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

/// Generalization rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralizationRule {
    /// Rule type.
    pub rule_type: GeneralizationType,
    /// Parameters.
    pub params: HashMap<String, String>,
}

/// Generalization type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneralizationType {
    /// Age to age range.
    AgeRange,
    /// Date to year only.
    DateToYear,
    /// Location to region.
    LocationToRegion,
    /// Number to range.
    NumberRange,
    /// Custom.
    Custom,
}

/// Strategy executor.
pub struct StrategyExecutor {
    config: StrategyConfig,
    token_map: parking_lot::RwLock<HashMap<String, String>>,
    substitute_generators: HashMap<PIIType, Box<dyn SubstituteGenerator>>,
}

/// Substitute data generator trait.
pub trait SubstituteGenerator: Send + Sync {
    /// Generates a substitute value.
    fn generate(&self) -> String;

    /// Generates a deterministic substitute based on input.
    fn generate_deterministic(&self, input: &str) -> String;
}

impl StrategyExecutor {
    /// Creates a new strategy executor.
    pub fn new(config: StrategyConfig) -> Self {
        let mut generators: HashMap<PIIType, Box<dyn SubstituteGenerator>> = HashMap::new();

        // Register default generators
        generators.insert(PIIType::Email, Box::new(EmailGenerator));
        generators.insert(PIIType::Phone, Box::new(PhoneGenerator));
        generators.insert(PIIType::Name, Box::new(NameGenerator));
        generators.insert(PIIType::Address, Box::new(AddressGenerator));

        Self {
            config,
            token_map: parking_lot::RwLock::new(HashMap::new()),
            substitute_generators: generators,
        }
    }

    /// Registers a custom substitute generator.
    pub fn register_generator(&mut self, pii_type: PIIType, generator: Box<dyn SubstituteGenerator>) {
        self.substitute_generators.insert(pii_type, generator);
    }

    /// Anonymizes a detection.
    pub fn anonymize(&self, detection: &Detection) -> AnonymizeResult<String> {
        let strategy = self.config.strategy_for(&detection.pii_type);
        self.apply_strategy(strategy, &detection.value, &detection.pii_type)
    }

    /// Applies a strategy to a value.
    pub fn apply_strategy(
        &self,
        strategy: AnonymizationStrategy,
        value: &str,
        pii_type: &PIIType,
    ) -> AnonymizeResult<String> {
        match strategy {
            AnonymizationStrategy::Mask => Ok(self.mask(value, pii_type)),
            AnonymizationStrategy::Redact => Ok(self.redact(value)),
            AnonymizationStrategy::Substitute => Ok(self.substitute(value, pii_type)),
            AnonymizationStrategy::Tokenize => Ok(self.tokenize(value)),
            AnonymizationStrategy::Encrypt => self.encrypt(value),
            AnonymizationStrategy::Hash => Ok(self.hash(value)),
            AnonymizationStrategy::Remove => Ok(String::new()),
            AnonymizationStrategy::Generalize => self.generalize(value, pii_type),
            AnonymizationStrategy::Truncate => Ok(self.truncate(value, pii_type)),
            AnonymizationStrategy::Shuffle => Ok(value.to_string()), // Shuffle requires dataset context
            AnonymizationStrategy::Noise => self.add_noise(value),
            AnonymizationStrategy::None => Ok(value.to_string()),
        }
    }

    /// Masks a value.
    fn mask(&self, value: &str, pii_type: &PIIType) -> String {
        let mask_char = self.config.mask_char;

        if self.config.preserve_format {
            // Preserve format while masking
            match pii_type {
                PIIType::CreditCard => {
                    // Show last 4 digits
                    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                    if clean.len() >= 4 {
                        let masked = format!(
                            "{}{}",
                            std::iter::repeat(mask_char).take(clean.len() - 4).collect::<String>(),
                            &clean[clean.len() - 4..]
                        );
                        return self.format_like(value, &masked);
                    }
                }
                PIIType::Ssn => {
                    // Show last 4 digits
                    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                    if clean.len() >= 4 {
                        return format!(
                            "{}{}{}{}",
                            std::iter::repeat(mask_char).take(3).collect::<String>(),
                            "-",
                            std::iter::repeat(mask_char).take(2).collect::<String>(),
                            format!("-{}", &clean[clean.len() - 4..])
                        );
                    }
                }
                PIIType::Email => {
                    // Mask local part, keep domain
                    if let Some(at_pos) = value.find('@') {
                        let local = &value[..at_pos];
                        let domain = &value[at_pos..];
                        let masked_local: String = if local.len() <= 2 {
                            std::iter::repeat(mask_char).take(local.len()).collect()
                        } else {
                            format!(
                                "{}{}{}",
                                &local[0..1],
                                std::iter::repeat(mask_char).take(local.len() - 2).collect::<String>(),
                                &local[local.len() - 1..]
                            )
                        };
                        return format!("{}{}", masked_local, domain);
                    }
                }
                PIIType::Phone => {
                    // Mask middle digits
                    let digits: Vec<char> = value.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 6 {
                        let mut masked: Vec<char> = digits.clone();
                        for i in 3..digits.len() - 2 {
                            masked[i] = mask_char;
                        }
                        let masked_str: String = masked.iter().collect();
                        return self.format_like(value, &masked_str);
                    }
                }
                _ => {}
            }
        }

        // Default: mask all characters
        std::iter::repeat(mask_char).take(value.len()).collect()
    }

    /// Formats masked digits like original format.
    fn format_like(&self, original: &str, masked: &str) -> String {
        let mut result = String::new();
        let mut masked_chars = masked.chars();

        for c in original.chars() {
            if c.is_ascii_digit() || c.is_alphabetic() {
                if let Some(m) = masked_chars.next() {
                    result.push(m);
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Redacts a value.
    fn redact(&self, _value: &str) -> String {
        "[REDACTED]".to_string()
    }

    /// Substitutes with synthetic data.
    fn substitute(&self, value: &str, pii_type: &PIIType) -> String {
        if let Some(generator) = self.substitute_generators.get(pii_type) {
            if self.config.deterministic_tokens {
                generator.generate_deterministic(value)
            } else {
                generator.generate()
            }
        } else {
            self.redact(value)
        }
    }

    /// Tokenizes a value.
    fn tokenize(&self, value: &str) -> String {
        if self.config.deterministic_tokens {
            // Check existing mapping
            {
                let map = self.token_map.read();
                if let Some(token) = map.get(value) {
                    return token.clone();
                }
            }

            // Generate deterministic token
            let hash = blake3::hash(value.as_bytes()).to_hex();
            let token = format!("{}{}", self.config.token_prefix, &hash.as_str()[..16]);

            // Store mapping
            {
                let mut map = self.token_map.write();
                map.insert(value.to_string(), token.clone());
            }

            token
        } else {
            // Random token
            let id = uuid::Uuid::new_v4();
            format!("{}{}", self.config.token_prefix, id.simple())
        }
    }

    /// Encrypts a value.
    fn encrypt(&self, value: &str) -> AnonymizeResult<String> {
        use vault_crypto::{AesGcmCipher, SecureBytes};

        // This is a simplified implementation - in production, use envelope encryption
        let cipher = AesGcmCipher::new();
        let key = cipher.generate_key();

        let encrypted = cipher
            .encrypt(&key, value.as_bytes(), None)
            .map_err(|e| AnonymizeError::Encryption(e.to_string()))?;

        // Return as base64
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(format!(
            "ENC:{}",
            STANDARD.encode(serde_json::to_vec(&encrypted).unwrap_or_default())
        ))
    }

    /// Hashes a value.
    fn hash(&self, value: &str) -> String {
        match self.config.hash_algorithm {
            HashAlgorithm::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(value.as_bytes());
                format!("{:x}", hasher.finalize())
            }
            HashAlgorithm::Blake3 => {
                blake3::hash(value.as_bytes()).to_hex().to_string()
            }
            HashAlgorithm::Sha512 => {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(value.as_bytes());
                format!("{:x}", hasher.finalize())
            }
        }
    }

    /// Generalizes a value.
    fn generalize(&self, value: &str, pii_type: &PIIType) -> AnonymizeResult<String> {
        if let Some(rule) = self.config.generalization_rules.get(pii_type) {
            match rule.rule_type {
                GeneralizationType::AgeRange => {
                    if let Ok(age) = value.parse::<u32>() {
                        let range = match age {
                            0..=17 => "0-17",
                            18..=24 => "18-24",
                            25..=34 => "25-34",
                            35..=44 => "35-44",
                            45..=54 => "45-54",
                            55..=64 => "55-64",
                            65..=74 => "65-74",
                            _ => "75+",
                        };
                        return Ok(range.to_string());
                    }
                }
                GeneralizationType::DateToYear => {
                    // Extract year from date
                    if let Some(year) = value.split('-').next() {
                        if year.len() == 4 {
                            return Ok(year.to_string());
                        }
                    }
                }
                GeneralizationType::NumberRange => {
                    if let Ok(num) = value.parse::<f64>() {
                        let step = rule.params.get("step").and_then(|s| s.parse::<f64>().ok()).unwrap_or(10.0);
                        let lower = (num / step).floor() * step;
                        let upper = lower + step;
                        return Ok(format!("{}-{}", lower as i64, upper as i64));
                    }
                }
                _ => {}
            }
        }

        // Default: return original
        Ok(value.to_string())
    }

    /// Truncates a value.
    fn truncate(&self, value: &str, pii_type: &PIIType) -> String {
        let length = self
            .config
            .truncation_lengths
            .get(pii_type)
            .copied()
            .unwrap_or(3);

        if value.len() > length {
            format!("{}...", &value[..length])
        } else {
            value.to_string()
        }
    }

    /// Adds noise to a numeric value.
    fn add_noise(&self, value: &str) -> AnonymizeResult<String> {
        if let Ok(num) = value.parse::<f64>() {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let noise = rng.gen_range(-self.config.noise_level..self.config.noise_level);
            let noisy = num * (1.0 + noise);
            Ok(format!("{:.2}", noisy))
        } else {
            Err(AnonymizeError::StrategyError(
                "Cannot add noise to non-numeric value".to_string(),
            ))
        }
    }

    /// Returns the token mapping (for reverse lookup).
    pub fn get_token_map(&self) -> HashMap<String, String> {
        self.token_map.read().clone()
    }

    /// Clears the token mapping.
    pub fn clear_token_map(&self) {
        self.token_map.write().clear();
    }
}

// Default substitute generators

struct EmailGenerator;
impl SubstituteGenerator for EmailGenerator {
    fn generate(&self) -> String {
        let id = uuid::Uuid::new_v4().simple().to_string();
        format!("user{}@example.com", &id[..8])
    }

    fn generate_deterministic(&self, input: &str) -> String {
        let hash = blake3::hash(input.as_bytes()).to_hex();
        format!("user{}@example.com", &hash.as_str()[..8])
    }
}

struct PhoneGenerator;
impl SubstituteGenerator for PhoneGenerator {
    fn generate(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!(
            "555-{:03}-{:04}",
            rng.gen_range(100..999),
            rng.gen_range(1000..9999)
        )
    }

    fn generate_deterministic(&self, input: &str) -> String {
        let hash = blake3::hash(input.as_bytes()).to_hex();
        let hex_str = hash.as_str();
        let digits: String = hex_str.chars().filter(|c| c.is_ascii_digit()).take(7).collect();
        if digits.len() >= 7 {
            format!("555-{}-{}", &digits[..3], &digits[3..7])
        } else {
            format!("555-000-{:04}", u32::from_str_radix(&hex_str[..4], 16).unwrap_or(0) % 10000)
        }
    }
}

struct NameGenerator;
impl SubstituteGenerator for NameGenerator {
    fn generate(&self) -> String {
        let names = ["John Doe", "Jane Smith", "Alex Johnson", "Sam Wilson"];
        use rand::seq::SliceRandom;
        names.choose(&mut rand::thread_rng()).unwrap_or(&"Anonymous").to_string()
    }

    fn generate_deterministic(&self, input: &str) -> String {
        let hash = blake3::hash(input.as_bytes());
        let names = ["John Doe", "Jane Smith", "Alex Johnson", "Sam Wilson", "Morgan Lee", "Taylor Brown"];
        let idx = hash.as_bytes()[0] as usize % names.len();
        names[idx].to_string()
    }
}

struct AddressGenerator;
impl SubstituteGenerator for AddressGenerator {
    fn generate(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        format!("{} Main St, Anytown, ST 00000", rng.gen_range(100..999))
    }

    fn generate_deterministic(&self, input: &str) -> String {
        let hash = blake3::hash(input.as_bytes()).to_hex();
        let num: u32 = u32::from_str_radix(&hash.as_str()[..3], 16).unwrap_or(100) % 900 + 100;
        format!("{} Main St, Anytown, ST 00000", num)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_credit_card() {
        let executor = StrategyExecutor::new(StrategyConfig::default());
        let result = executor.mask("4111-1111-1111-1111", &PIIType::CreditCard);
        assert!(result.ends_with("1111"));
        assert!(result.contains('*'));
    }

    #[test]
    fn test_mask_email() {
        let executor = StrategyExecutor::new(StrategyConfig::default());
        let result = executor.mask("john.doe@example.com", &PIIType::Email);
        assert!(result.contains('@'));
        assert!(result.ends_with("@example.com"));
    }

    #[test]
    fn test_tokenize_deterministic() {
        let executor = StrategyExecutor::new(StrategyConfig {
            deterministic_tokens: true,
            ..Default::default()
        });

        let token1 = executor.tokenize("secret123");
        let token2 = executor.tokenize("secret123");

        assert_eq!(token1, token2);
        assert!(token1.starts_with("TOK_"));
    }

    #[test]
    fn test_hash() {
        let executor = StrategyExecutor::new(StrategyConfig::default());
        let hash1 = executor.hash("test");
        let hash2 = executor.hash("test");
        let hash3 = executor.hash("different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_substitute_email() {
        let executor = StrategyExecutor::new(StrategyConfig::default());
        let result = executor.substitute("real@email.com", &PIIType::Email);
        assert!(result.contains('@'));
        assert!(result.contains("example.com"));
    }

    #[test]
    fn test_truncate() {
        let mut config = StrategyConfig::default();
        config.truncation_lengths.insert(PIIType::Address, 10);

        let executor = StrategyExecutor::new(config);
        let result = executor.truncate("123 Very Long Street Name", &PIIType::Address);

        assert!(result.len() <= 13); // 10 chars + "..."
        assert!(result.ends_with("..."));
    }
}
