use super::{HashIdentification, HashType};

/// Result of hash detection process
#[derive(Debug, Clone, PartialEq)]
pub struct DetectionResult {
    /// The identified hash information
    pub identification: HashIdentification,
    /// Any warnings or notices during detection
    pub warnings: Vec<String>,
}

impl DetectionResult {
    /// Create a new DetectionResult
    pub fn new(identification: HashIdentification) -> Self {
        Self {
            identification,
            warnings: Vec::new(),
        }
    }

    /// Add a warning message
    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }

    /// Check if detection was successful (found at least one match)
    pub fn has_matches(&self) -> bool {
        !self.identification.detected_types.is_empty()
    }

    /// Get the best match if available
    pub fn best_match(&self) -> Option<&HashType> {
        self.identification.best_match()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HashCategory, HashType, HashIdentification};

    #[test]
    fn test_detection_result_creation() {
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

        let identification = HashIdentification::new(
            "test".to_string(),
            vec![hash_type],
            10,
        );

        let result = DetectionResult::new(identification);
        assert!(result.has_matches());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_detection_with_warning() {
        let identification = HashIdentification::new(
            "test".to_string(),
            vec![],
            10,
        );

        let result = DetectionResult::new(identification)
            .with_warning("No patterns matched".to_string());

        assert!(!result.has_matches());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0], "No patterns matched");
    }
}