use serde::{Serialize, Deserialize};
use super::HashCategory;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashType {
    /// Name of the hash type (e.g., "MD5", "bcrypt")
    pub name: String,
    /// Hashcat mode number (e.g., 0 for MD5)
    pub hashcat_mode: Option<u32>,
    /// John the Ripper format name
    pub john_format: Option<String>,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Category of the hash type
    pub category: HashCategory,
    /// Human-readable description
    pub description: String,
    /// Whether salt was detected
    pub salt_detected: bool,
    /// Name of the regex pattern that matched
    pub pattern_matched: String,
}

impl HashType {
    /// Create a new HashType
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        hashcat_mode: Option<u32>,
        john_format: Option<String>,
        confidence: f32,
        category: HashCategory,
        description: String,
        salt_detected: bool,
        pattern_matched: String,
    ) -> Self {
        Self {
            name,
            hashcat_mode,
            john_format,
            confidence: confidence.clamp(0.0, 1.0),
            category,
            description,
            salt_detected,
            pattern_matched,
        }
    }

    /// Get hashcat command fragment
    pub fn hashcat_command(&self) -> Option<String> {
        self.hashcat_mode.map(|mode| format!("-m {}", mode))
    }

    /// Get john command fragment
    pub fn john_command(&self) -> Option<String> {
        self.john_format.as_ref().map(|fmt| format!("--format={}", fmt))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashIdentification {
    /// The original hash that was analyzed
    pub hash: String,
    /// List of detected hash types, sorted by confidence (highest first)
    pub detected_types: Vec<HashType>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

impl HashIdentification {
    /// Create a new HashIdentification
    pub fn new(hash: String, mut detected_types: Vec<HashType>, processing_time_ms: u64) -> Self {
        // Sort by confidence (highest first)
        detected_types.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        Self {
            hash,
            detected_types,
            processing_time_ms,
        }
    }

    /// Get the most likely hash type (highest confidence)
    pub fn best_match(&self) -> Option<&HashType> {
        self.detected_types.first()
    }

    /// Filter results by minimum confidence
    pub fn filter_by_confidence(mut self, min_confidence: f32) -> Self {
        self.detected_types.retain(|ht| ht.confidence >= min_confidence);
        self
    }

    /// Limit number of results
    pub fn limit_results(mut self, max_results: usize) -> Self {
        self.detected_types.truncate(max_results);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type_creation() {
        let hash_type = HashType::new(
            "MD5".to_string(),
            Some(0),
            Some("Raw-MD5".to_string()),
            0.9,
            HashCategory::Basic,
            "MD5 hash".to_string(),
            false,
            "md5_pattern".to_string(),
        );

        assert_eq!(hash_type.name, "MD5");
        assert_eq!(hash_type.confidence, 0.9);
    }

    #[test]
    fn test_hashcat_command() {
        let hash_type = HashType::new(
            "MD5".to_string(),
            Some(0),
            None,
            0.9,
            HashCategory::Basic,
            "MD5".to_string(),
            false,
            "pattern".to_string(),
        );

        assert_eq!(hash_type.hashcat_command(), Some("-m 0".to_string()));
    }

    #[test]
    fn test_hash_identification_sorting() {
        let low_confidence = HashType::new(
            "Low".to_string(), None, None, 0.3, HashCategory::Basic,
            "Low confidence".to_string(), false, "pattern".to_string(),
        );

        let high_confidence = HashType::new(
            "High".to_string(), None, None, 0.9, HashCategory::Basic,
            "High confidence".to_string(), false, "pattern".to_string(),
        );

        let identification = HashIdentification::new(
            "testhash".to_string(),
            vec![low_confidence, high_confidence],
            10,
        );

        assert_eq!(identification.best_match().unwrap().name, "High");
    }

    #[test]
    fn test_confidence_filtering() {
        let low = HashType::new(
            "Low".to_string(), None, None, 0.3, HashCategory::Basic,
            "Low".to_string(), false, "pattern".to_string(),
        );
        let high = HashType::new(
            "High".to_string(), None, None, 0.9, HashCategory::Basic,
            "High".to_string(), false, "pattern".to_string(),
        );

        let identification = HashIdentification::new(
            "test".to_string(),
            vec![low, high],
            10,
        ).filter_by_confidence(0.5);

        assert_eq!(identification.detected_types.len(), 1);
        assert_eq!(identification.detected_types[0].name, "High");
    }
}