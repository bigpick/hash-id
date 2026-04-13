//! Common trait for output formatters

use crate::{Result, types::{HashIdentification, DetectionResult}};

/// Trait for formatting hash identification results
pub trait OutputFormatter {
    /// Format a single hash identification result
    fn format_single(&self, result: &HashIdentification) -> Result<String>;

    /// Format a batch of hash identification results
    fn format_batch(&self, results: &[HashIdentification]) -> Result<String>;

    /// Format a detection result (includes warnings)
    fn format_detection(&self, result: &DetectionResult) -> Result<String> {
        // Default implementation just formats the identification
        // Subclasses can override to include warnings
        self.format_single(&result.identification)
    }

    /// Format multiple detection results
    fn format_detections(&self, results: &[DetectionResult]) -> Result<String> {
        let identifications: Vec<HashIdentification> = results.iter()
            .map(|r| r.identification.clone())
            .collect();
        self.format_batch(&identifications)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HashCategory, HashType, HashIdentification, DetectionResult};

    // Mock formatter for testing
    struct MockFormatter;

    impl OutputFormatter for MockFormatter {
        fn format_single(&self, result: &HashIdentification) -> Result<String> {
            Ok(format!("MOCK_SINGLE:{}", result.hash))
        }

        fn format_batch(&self, results: &[HashIdentification]) -> Result<String> {
            let hashes: Vec<&str> = results.iter().map(|r| r.hash.as_str()).collect();
            Ok(format!("MOCK_BATCH:{}", hashes.join(",")))
        }

        fn format_detection(&self, result: &DetectionResult) -> Result<String> {
            let base = self.format_single(&result.identification)?;
            if result.warnings.is_empty() {
                Ok(base)
            } else {
                Ok(format!("{}|WARNINGS:{}", base, result.warnings.len()))
            }
        }
    }

    fn create_test_hash_type() -> HashType {
        HashType::new(
            "MD5".to_string(),
            Some(0),
            Some("Raw-MD5".to_string()),
            0.9,
            HashCategory::Basic,
            "MD5 hash".to_string(),
            false,
            "md5_pattern".to_string(),
        )
    }

    fn create_test_identification() -> HashIdentification {
        HashIdentification::new(
            "5d41402abc4b2a76b9719d911017c592".to_string(),
            vec![create_test_hash_type()],
            10,
        )
    }

    #[test]
    fn test_format_single() {
        let formatter = MockFormatter;
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();
        assert_eq!(result, "MOCK_SINGLE:5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_format_batch() {
        let formatter = MockFormatter;
        let id1 = create_test_identification();
        let mut id2 = create_test_identification();
        id2.hash = "other_hash".to_string();

        let result = formatter.format_batch(&[id1, id2]).unwrap();
        assert_eq!(result, "MOCK_BATCH:5d41402abc4b2a76b9719d911017c592,other_hash");
    }

    #[test]
    fn test_format_detection_without_warnings() {
        let formatter = MockFormatter;
        let identification = create_test_identification();
        let detection = DetectionResult::new(identification);

        let result = formatter.format_detection(&detection).unwrap();
        assert_eq!(result, "MOCK_SINGLE:5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_format_detection_with_warnings() {
        let formatter = MockFormatter;
        let identification = create_test_identification();
        let detection = DetectionResult::new(identification)
            .with_warning("Test warning".to_string());

        let result = formatter.format_detection(&detection).unwrap();
        assert_eq!(result, "MOCK_SINGLE:5d41402abc4b2a76b9719d911017c592|WARNINGS:1");
    }

    #[test]
    fn test_format_detections() {
        let formatter = MockFormatter;
        let id1 = create_test_identification();
        let mut id2 = create_test_identification();
        id2.hash = "other_hash".to_string();

        let detection1 = DetectionResult::new(id1);
        let detection2 = DetectionResult::new(id2);

        let result = formatter.format_detections(&[detection1, detection2]).unwrap();
        assert_eq!(result, "MOCK_BATCH:5d41402abc4b2a76b9719d911017c592,other_hash");
    }
}