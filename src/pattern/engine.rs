use std::time::Instant;
use crate::types::{HashType, HashIdentification, DetectionResult};
use super::{PatternRegistry, ConfidenceScorer, DetectionContext};

/// Main pattern engine for hash detection
pub struct PatternEngine {
    registry: PatternRegistry,
}

impl PatternEngine {
    /// Create a new pattern engine
    pub fn new() -> Self {
        Self {
            registry: PatternRegistry::new(),
        }
    }

    /// Create pattern engine with default patterns loaded
    pub fn with_default_patterns() -> crate::Result<Self> {
        let mut engine = Self::new();
        engine.load_default_patterns()?;
        Ok(engine)
    }

    /// Get mutable access to the pattern registry
    pub fn registry_mut(&mut self) -> &mut PatternRegistry {
        &mut self.registry
    }

    /// Detect hash types for a single hash
    pub fn detect(&self, hash: &str) -> DetectionResult {
        self.detect_with_context(hash, &DetectionContext::default())
    }

    /// Detect hash types with additional context
    pub fn detect_with_context(&self, hash: &str, context: &DetectionContext) -> DetectionResult {
        let start_time = Instant::now();

        // Find matching patterns
        let matching_patterns = self.registry.find_matches(hash);

        if matching_patterns.is_empty() {
            let identification = HashIdentification::new(
                hash.to_string(),
                vec![],
                start_time.elapsed().as_millis() as u64,
            );

            return DetectionResult::new(identification)
                .with_warning("No patterns matched the input hash".to_string());
        }

        // Calculate confidence scores and create HashType instances
        let mut detected_types = Vec::new();

        for pattern in matching_patterns {
            let confidence = ConfidenceScorer::calculate(hash, pattern, context);

            let hash_type = HashType::new(
                pattern.name.clone(),
                pattern.hashcat_mode,
                pattern.john_format.clone(),
                confidence,
                pattern.category.clone(),
                pattern.description.clone(),
                pattern.requires_salt_check && Self::detect_salt(hash),
                format!("{}_pattern", pattern.name.to_lowercase().replace(' ', "_")),
            );

            detected_types.push(hash_type);
        }

        let identification = HashIdentification::new(
            hash.to_string(),
            detected_types,
            start_time.elapsed().as_millis() as u64,
        );

        DetectionResult::new(identification)
    }

    /// Detect multiple hashes in batch
    pub fn detect_batch(&self, hashes: &[String]) -> Vec<DetectionResult> {
        let context = DetectionContext {
            file_extension: None,
            is_batch: true,
            batch_size: Some(hashes.len()),
        };

        hashes.iter()
            .map(|hash| self.detect_with_context(hash, &context))
            .collect()
    }

    /// Simple salt detection (placeholder implementation)
    fn detect_salt(hash: &str) -> bool {
        // Basic salt detection - look for common salt separators
        hash.contains(':') || hash.contains('$') || hash.contains('.')
    }

    /// Load default patterns from all pattern modules
    fn load_default_patterns(&mut self) -> crate::Result<()> {
        self.registry = crate::patterns::load_all_patterns()?;
        Ok(())
    }
}

impl Default for PatternEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = PatternEngine::new();
        assert!(engine.registry.patterns().is_empty());
    }

    #[test]
    fn test_engine_with_defaults() {
        let engine = PatternEngine::with_default_patterns().unwrap();
        assert!(!engine.registry.patterns().is_empty());
    }

    #[test]
    fn test_hash_detection() {
        let engine = PatternEngine::with_default_patterns().unwrap();

        let result = engine.detect("5d41402abc4b2a76b9719d911017c592");

        assert!(result.has_matches());
        assert_eq!(result.best_match().unwrap().name, "MD5");
    }

    #[test]
    fn test_batch_detection() {
        let engine = PatternEngine::with_default_patterns().unwrap();

        let hashes = vec![
            "5d41402abc4b2a76b9719d911017c592".to_string(), // MD5
            "invalid_hash".to_string(),
        ];

        let results = engine.detect_batch(&hashes);

        assert_eq!(results.len(), 2);
        assert!(results[0].has_matches());
        assert!(!results[1].has_matches());
    }

    #[test]
    fn test_no_matches() {
        let engine = PatternEngine::with_default_patterns().unwrap();

        let result = engine.detect("invalid");

        assert!(!result.has_matches());
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_salt_detection() {
        assert!(PatternEngine::detect_salt("hash:salt"));
        assert!(PatternEngine::detect_salt("$1$salt$hash"));
        assert!(PatternEngine::detect_salt("hash.salt"));
        assert!(!PatternEngine::detect_salt("plainhash"));
    }
}