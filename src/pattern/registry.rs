use regex::Regex;
use crate::types::HashCategory;

/// Configuration for creating a HashPattern
///
/// This struct reduces the number of parameters needed for pattern creation.
/// Use with `HashPattern::from_config()` or `HashPatternBuilder` for more flexibility.
#[derive(Debug, Clone)]
pub struct HashPatternConfig {
    /// Name of the hash type
    pub name: String,
    /// Regex pattern for matching hashes
    pub pattern: String,
    /// Hashcat mode number if available
    pub hashcat_mode: Option<u32>,
    /// John the Ripper format name if available
    pub john_format: Option<String>,
    /// Category of this hash type
    pub category: HashCategory,
    /// Human-readable description
    pub description: String,
    /// Base confidence score for this pattern
    pub base_confidence: f32,
    /// Whether this pattern requires salt detection
    pub requires_salt_check: bool,
}

/// A compiled hash pattern for matching
#[derive(Debug, Clone)]
pub struct HashPattern {
    /// Name of the hash type
    pub name: String,
    /// Compiled regex for pattern matching
    pub regex: Regex,
    /// Hashcat mode number if available
    pub hashcat_mode: Option<u32>,
    /// John the Ripper format name if available
    pub john_format: Option<String>,
    /// Category of this hash type
    pub category: HashCategory,
    /// Human-readable description
    pub description: String,
    /// Base confidence score for this pattern
    pub base_confidence: f32,
    /// Whether this pattern requires salt detection
    pub requires_salt_check: bool,
}

/// Builder for creating HashPattern instances
///
/// This builder provides a fluent API for constructing HashPattern instances
/// with all optional and required parameters clearly separated.
///
/// # Example
/// ```ignore
/// let pattern = HashPattern::builder("MD5".to_string(), r"^[a-fA-F0-9]{32}$".to_string(), HashCategory::Basic)
///     .hashcat_mode(Some(0))
///     .john_format(Some("Raw-MD5".to_string()))
///     .description("MD5 message digest".to_string())
///     .base_confidence(0.6)
///     .requires_salt_check(false)
///     .build()?;
/// ```
#[derive(Debug)]
pub struct HashPatternBuilder {
    name: String,
    pattern: String,
    hashcat_mode: Option<u32>,
    john_format: Option<String>,
    category: HashCategory,
    description: String,
    base_confidence: f32,
    requires_salt_check: bool,
}

impl HashPatternBuilder {
    /// Create a new builder with required fields
    ///
    /// # Arguments
    /// * `name` - Name of the hash type
    /// * `pattern` - Regex pattern string for matching
    /// * `category` - Category classification for this hash
    pub fn new(name: String, pattern: String, category: HashCategory) -> Self {
        Self {
            name,
            pattern,
            hashcat_mode: None,
            john_format: None,
            category,
            description: String::new(),
            base_confidence: 0.5,
            requires_salt_check: false,
        }
    }

    /// Set the hashcat mode
    pub fn hashcat_mode(mut self, mode: Option<u32>) -> Self {
        self.hashcat_mode = mode;
        self
    }

    /// Set the John the Ripper format
    pub fn john_format(mut self, format: Option<String>) -> Self {
        self.john_format = format;
        self
    }

    /// Set the description
    pub fn description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// Set the base confidence score
    pub fn base_confidence(mut self, confidence: f32) -> Self {
        self.base_confidence = confidence;
        self
    }

    /// Set whether salt detection is required
    pub fn requires_salt_check(mut self, requires: bool) -> Self {
        self.requires_salt_check = requires;
        self
    }

    /// Build the HashPattern
    ///
    /// # Errors
    /// Returns an error if the regex pattern is invalid.
    pub fn build(self) -> crate::Result<HashPattern> {
        let regex = Regex::new(&self.pattern)?;

        Ok(HashPattern {
            name: self.name,
            regex,
            hashcat_mode: self.hashcat_mode,
            john_format: self.john_format,
            category: self.category,
            description: self.description,
            base_confidence: self.base_confidence.clamp(0.0, 1.0),
            requires_salt_check: self.requires_salt_check,
        })
    }
}

impl HashPattern {
    /// Create a new HashPattern from a configuration struct
    ///
    /// This method accepts a single `HashPatternConfig` struct instead of
    /// individual parameters, reducing the number of function parameters.
    ///
    /// # Errors
    /// Returns an error if the regex pattern is invalid.
    pub fn from_config(config: HashPatternConfig) -> crate::Result<Self> {
        let regex = Regex::new(&config.pattern)?;

        Ok(Self {
            name: config.name,
            regex,
            hashcat_mode: config.hashcat_mode,
            john_format: config.john_format,
            category: config.category,
            description: config.description,
            base_confidence: config.base_confidence.clamp(0.0, 1.0),
            requires_salt_check: config.requires_salt_check,
        })
    }

    /// Create a new HashPattern (backward compatibility wrapper)
    ///
    /// This method is maintained for backward compatibility with existing code.
    /// For new code, prefer using `HashPatternBuilder` for better readability,
    /// or `HashPattern::from_config()` if you have all parameters in a struct.
    ///
    /// # Errors
    /// Returns an error if the regex pattern is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        pattern: &str,
        hashcat_mode: Option<u32>,
        john_format: Option<String>,
        category: HashCategory,
        description: String,
        base_confidence: f32,
        requires_salt_check: bool,
    ) -> crate::Result<Self> {
        Self::from_config(HashPatternConfig {
            name,
            pattern: pattern.to_string(),
            hashcat_mode,
            john_format,
            category,
            description,
            base_confidence,
            requires_salt_check,
        })
    }

    /// Create a builder for constructing a HashPattern
    ///
    /// This is the recommended approach for new code.
    ///
    /// # Example
    /// ```ignore
    /// let pattern = HashPattern::builder(
    ///     "MD5".to_string(),
    ///     r"^[a-fA-F0-9]{32}$".to_string(),
    ///     HashCategory::Basic
    /// )
    /// .hashcat_mode(Some(0))
    /// .description("MD5 message digest".to_string())
    /// .base_confidence(0.6)
    /// .build()?;
    /// ```
    pub fn builder(name: String, pattern: String, category: HashCategory) -> HashPatternBuilder {
        HashPatternBuilder::new(name, pattern, category)
    }

    /// Test if this pattern matches the given hash
    pub fn matches(&self, hash: &str) -> bool {
        self.regex.is_match(hash)
    }
}

/// Registry for managing hash patterns
#[derive(Debug)]
pub struct PatternRegistry {
    patterns: Vec<HashPattern>,
}

impl PatternRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Add a pattern to the registry
    pub fn add_pattern(&mut self, pattern: HashPattern) {
        self.patterns.push(pattern);
    }

    /// Get all patterns
    pub fn patterns(&self) -> &[HashPattern] {
        &self.patterns
    }

    /// Sort patterns by base confidence (highest first)
    pub fn sort_by_confidence(&mut self) {
        self.patterns.sort_by(|a, b|
            b.base_confidence.partial_cmp(&a.base_confidence).unwrap()
        );
    }

    /// Find all patterns that match a given hash
    pub fn find_matches(&self, hash: &str) -> Vec<&HashPattern> {
        self.patterns.iter()
            .filter(|pattern| pattern.matches(hash))
            .collect()
    }
}

impl Default for PatternRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_creation() {
        let pattern = HashPattern::new(
            "MD5".to_string(),
            r"^[a-fA-F0-9]{32}$",
            Some(0),
            Some("Raw-MD5".to_string()),
            HashCategory::Basic,
            "MD5 hash".to_string(),
            0.6,
            false,
        ).unwrap();

        assert_eq!(pattern.name, "MD5");
        assert!(pattern.matches("5d41402abc4b2a76b9719d911017c592"));
        assert!(!pattern.matches("invalid"));
    }

    #[test]
    fn test_registry() {
        let mut registry = PatternRegistry::new();

        let pattern = HashPattern::new(
            "MD5".to_string(),
            r"^[a-fA-F0-9]{32}$",
            Some(0),
            None,
            HashCategory::Basic,
            "MD5".to_string(),
            0.6,
            false,
        ).unwrap();

        registry.add_pattern(pattern);

        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c592");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "MD5");
    }

    #[test]
    fn test_confidence_clamping() {
        let pattern = HashPattern::new(
            "Test".to_string(),
            r".*",
            None,
            None,
            HashCategory::Other,
            "Test".to_string(),
            1.5, // > 1.0, should be clamped
            false,
        ).unwrap();

        assert_eq!(pattern.base_confidence, 1.0);
    }
}