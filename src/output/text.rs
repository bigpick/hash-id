//! Text output formatter

use crate::{Result, types::{HashIdentification, DetectionResult, HashType}};
use super::OutputFormatter;

/// Verbosity levels for text output
#[derive(Debug, Clone, PartialEq)]
pub enum VerbosityLevel {
    /// Only show hash type names and confidence
    Minimal,
    /// Include basic information (default)
    Normal,
    /// Include all available details
    Verbose,
}

/// Text output formatter with multiple verbosity levels
pub struct TextFormatter {
    verbosity: VerbosityLevel,
}

impl TextFormatter {
    /// Create a new TextFormatter with default settings (normal verbosity)
    pub fn new() -> Self {
        Self {
            verbosity: VerbosityLevel::Normal,
        }
    }

    /// Create a TextFormatter with verbose output
    pub fn verbose() -> Self {
        Self {
            verbosity: VerbosityLevel::Verbose,
        }
    }

    /// Create a TextFormatter with minimal output
    pub fn minimal() -> Self {
        Self {
            verbosity: VerbosityLevel::Minimal,
        }
    }

    fn format_hash_type(&self, hash_type: &HashType, index: usize, total: usize) -> String {
        match self.verbosity {
            VerbosityLevel::Minimal => {
                format!("{} ({:.0}%)", hash_type.name, hash_type.confidence * 100.0)
            }
            VerbosityLevel::Normal => {
                let mut result = format!(
                    "[{}] {} ({:.0}%)",
                    index + 1,
                    hash_type.name,
                    hash_type.confidence * 100.0
                );

                if let Some(hashcat_mode) = hash_type.hashcat_mode {
                    result.push_str(&format!(" - hashcat -m {}", hashcat_mode));
                }

                if let Some(john_format) = &hash_type.john_format {
                    result.push_str(&format!(" - john --format={}", john_format));
                }

                result
            }
            VerbosityLevel::Verbose => {
                let mut result = format!(
                    "[{}] {} ({:.0}%)\n",
                    index + 1,
                    hash_type.name,
                    hash_type.confidence * 100.0
                );

                result.push_str(&format!("    Description: {}\n", hash_type.description));
                result.push_str(&format!("    Category: {} ({})\n",
                    hash_type.category.description(),
                    format!("{:?}", hash_type.category).to_lowercase()
                ));
                result.push_str(&format!("    Pattern matched: {}\n", hash_type.pattern_matched));

                if hash_type.salt_detected {
                    result.push_str("    Salt detected: Yes\n");
                }

                if let Some(hashcat_mode) = hash_type.hashcat_mode {
                    result.push_str(&format!("    Hashcat: -m {}\n", hashcat_mode));
                }

                if let Some(john_format) = &hash_type.john_format {
                    result.push_str(&format!("    John: --format={}\n", john_format));
                }

                // Remove the trailing newline for the last item
                if index == total - 1 {
                    result.pop();
                }

                result
            }
        }
    }

    fn format_identification_header(&self, result: &HashIdentification) -> String {
        match self.verbosity {
            VerbosityLevel::Minimal => String::new(),
            VerbosityLevel::Normal => {
                format!("Hash: {}\n", result.hash)
            }
            VerbosityLevel::Verbose => {
                format!("Hash: {}\nProcessing time: {}ms\nDetected {} possible type(s):\n",
                    result.hash,
                    result.processing_time_ms,
                    result.detected_types.len()
                )
            }
        }
    }

    fn format_warnings(&self, warnings: &[String]) -> String {
        if warnings.is_empty() {
            return String::new();
        }

        match self.verbosity {
            VerbosityLevel::Minimal => String::new(),
            VerbosityLevel::Normal | VerbosityLevel::Verbose => {
                let mut result = String::new();
                result.push_str("\nWarnings:\n");
                for (i, warning) in warnings.iter().enumerate() {
                    result.push_str(&format!("  {}. {}\n", i + 1, warning));
                }
                result
            }
        }
    }

    fn format_batch_header(&self, results: &[HashIdentification]) -> String {
        match self.verbosity {
            VerbosityLevel::Minimal => String::new(),
            VerbosityLevel::Normal => {
                format!("Analyzed {} hash(es):\n\n", results.len())
            }
            VerbosityLevel::Verbose => {
                format!("Hash Identification Results\n{}\nAnalyzed {} hash(es):\n\n",
                    "=".repeat(28),
                    results.len()
                )
            }
        }
    }

    fn format_batch_separator(&self, index: usize, total: usize) -> String {
        if index == total - 1 {
            String::new() // No separator after the last item
        } else {
            match self.verbosity {
                VerbosityLevel::Minimal => "\n".to_string(),
                VerbosityLevel::Normal => "\n".repeat(2),
                VerbosityLevel::Verbose => format!("\n{}\n\n", "-".repeat(50)),
            }
        }
    }
}

impl Default for TextFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter for TextFormatter {
    fn format_single(&self, result: &HashIdentification) -> Result<String> {
        if result.detected_types.is_empty() {
            return Ok("No matches found".to_string());
        }

        let mut output = String::new();

        // Add header
        output.push_str(&self.format_identification_header(result));

        // Add hash types
        for (i, hash_type) in result.detected_types.iter().enumerate() {
            output.push_str(&self.format_hash_type(hash_type, i, result.detected_types.len()));
            if i < result.detected_types.len() - 1 {
                output.push('\n');
            }
        }

        Ok(output)
    }

    fn format_batch(&self, results: &[HashIdentification]) -> Result<String> {
        if results.is_empty() {
            return Ok("No hashes to analyze.".to_string());
        }

        let mut output = String::new();

        // Add batch header
        output.push_str(&self.format_batch_header(results));

        // Add each result
        for (i, result) in results.iter().enumerate() {
            output.push_str(&self.format_single(result)?);
            output.push_str(&self.format_batch_separator(i, results.len()));
        }

        Ok(output)
    }

    fn format_detection(&self, result: &DetectionResult) -> Result<String> {
        let mut output = self.format_single(&result.identification)?;
        output.push_str(&self.format_warnings(&result.warnings));
        Ok(output)
    }

    fn format_detections(&self, results: &[DetectionResult]) -> Result<String> {
        if results.is_empty() {
            return Ok("No hashes to analyze.".to_string());
        }

        let mut output = String::new();

        // Create identifications for header
        let identifications: Vec<HashIdentification> = results.iter()
            .map(|r| r.identification.clone())
            .collect();
        output.push_str(&self.format_batch_header(&identifications));

        // Add each detection result
        for (i, result) in results.iter().enumerate() {
            output.push_str(&self.format_detection(result)?);
            output.push_str(&self.format_batch_separator(i, results.len()));
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HashCategory, HashType, HashIdentification, DetectionResult};

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

    fn create_bcrypt_hash_type() -> HashType {
        HashType::new(
            "bcrypt".to_string(),
            Some(3200),
            Some("bcrypt".to_string()),
            0.95,
            HashCategory::Authentication,
            "bcrypt with salt".to_string(),
            true,
            "bcrypt_pattern".to_string(),
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
    fn test_text_formatter_creation() {
        let formatter = TextFormatter::new();
        assert_eq!(formatter.verbosity, VerbosityLevel::Normal);

        let formatter = TextFormatter::minimal();
        assert_eq!(formatter.verbosity, VerbosityLevel::Minimal);

        let formatter = TextFormatter::verbose();
        assert_eq!(formatter.verbosity, VerbosityLevel::Verbose);
    }

    #[test]
    fn test_format_single_minimal() {
        let formatter = TextFormatter::minimal();
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();

        assert!(result.contains("MD5 (90%)"));
        assert!(!result.contains("Hash:"));
        assert!(!result.contains("Processing time:"));
        assert!(!result.contains("hashcat"));
    }

    #[test]
    fn test_format_single_normal() {
        let formatter = TextFormatter::new(); // Normal verbosity
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();

        assert!(result.contains("Hash: 5d41402abc4b2a76b9719d911017c592"));
        assert!(result.contains("[1] MD5 (90%)"));
        assert!(result.contains("hashcat -m 0"));
        assert!(result.contains("john --format=Raw-MD5"));
        assert!(!result.contains("Description:"));
        assert!(!result.contains("Category:"));
    }

    #[test]
    fn test_format_single_verbose() {
        let formatter = TextFormatter::verbose();
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();

        assert!(result.contains("Hash: 5d41402abc4b2a76b9719d911017c592"));
        assert!(result.contains("Processing time: 10ms"));
        assert!(result.contains("Detected 1 possible type(s):"));
        assert!(result.contains("[1] MD5 (90%)"));
        assert!(result.contains("Description: MD5 hash"));
        assert!(result.contains("Category: Basic hash functions (basic)"));
        assert!(result.contains("Pattern matched: md5_pattern"));
        assert!(result.contains("Hashcat: -m 0"));
        assert!(result.contains("John: --format=Raw-MD5"));
    }

    #[test]
    fn test_format_single_with_salt_detected() {
        let formatter = TextFormatter::verbose();
        let hash_type = create_bcrypt_hash_type();
        let identification = HashIdentification::new(
            "test_hash".to_string(),
            vec![hash_type],
            15,
        );

        let result = formatter.format_single(&identification).unwrap();

        assert!(result.contains("Salt detected: Yes"));
        assert!(result.contains("bcrypt (95%)"));
    }

    #[test]
    fn test_format_single_empty_results() {
        let formatter = TextFormatter::new();
        let identification = HashIdentification::new(
            "test_hash".to_string(),
            vec![],
            5,
        );

        let result = formatter.format_single(&identification).unwrap();
        assert_eq!(result, "No matches found");
    }

    #[test]
    fn test_format_batch() {
        let formatter = TextFormatter::minimal();
        let id1 = create_test_identification();
        let mut id2 = create_test_identification();
        id2.hash = "other_hash".to_string();

        let result = formatter.format_batch(&[id1, id2]).unwrap();

        assert!(result.contains("MD5 (90%)"));
        assert!(result.contains("\n")); // Should have separator
    }

    #[test]
    fn test_format_batch_verbose() {
        let formatter = TextFormatter::verbose();
        let id1 = create_test_identification();
        let mut id2 = create_test_identification();
        id2.hash = "other_hash".to_string();

        let result = formatter.format_batch(&[id1, id2]).unwrap();

        assert!(result.contains("Hash Identification Results"));
        assert!(result.contains("=".repeat(28).as_str()));
        assert!(result.contains("Analyzed 2 hash(es):"));
        assert!(result.contains("-".repeat(50).as_str())); // Should have verbose separator
    }

    #[test]
    fn test_format_detection_with_warnings() {
        let formatter = TextFormatter::new();
        let identification = create_test_identification();
        let detection = DetectionResult::new(identification)
            .with_warning("Test warning 1".to_string())
            .with_warning("Test warning 2".to_string());

        let result = formatter.format_detection(&detection).unwrap();

        assert!(result.contains("Warnings:"));
        assert!(result.contains("1. Test warning 1"));
        assert!(result.contains("2. Test warning 2"));
    }

    #[test]
    fn test_format_detection_minimal_ignores_warnings() {
        let formatter = TextFormatter::minimal();
        let identification = create_test_identification();
        let detection = DetectionResult::new(identification)
            .with_warning("Test warning".to_string());

        let result = formatter.format_detection(&detection).unwrap();

        assert!(!result.contains("Warnings:"));
        assert!(!result.contains("Test warning"));
    }

    #[test]
    fn test_format_detections() {
        let formatter = TextFormatter::new();
        let id1 = create_test_identification();
        let mut id2 = create_test_identification();
        id2.hash = "other_hash".to_string();

        let detection1 = DetectionResult::new(id1).with_warning("Warning 1".to_string());
        let detection2 = DetectionResult::new(id2);

        let result = formatter.format_detections(&[detection1, detection2]).unwrap();

        assert!(result.contains("Analyzed 2 hash(es):"));
        assert!(result.contains("Warning 1"));
        assert!(result.contains("5d41402abc4b2a76b9719d911017c592"));
        assert!(result.contains("other_hash"));
    }

    #[test]
    fn test_format_empty_results() {
        let formatter = TextFormatter::new();
        let empty_results: Vec<HashIdentification> = vec![];

        let result = formatter.format_batch(&empty_results).unwrap();
        assert_eq!(result, "No hashes to analyze.");
    }

    #[test]
    fn test_multiple_hash_types() {
        let formatter = TextFormatter::new();
        let identification = HashIdentification::new(
            "test_hash".to_string(),
            vec![create_test_hash_type(), create_bcrypt_hash_type()],
            20,
        );

        let result = formatter.format_single(&identification).unwrap();

        // Should show both hash types with indices
        assert!(result.contains("[1] bcrypt (95%)")); // Higher confidence first
        assert!(result.contains("[2] MD5 (90%)"));
    }

    #[test]
    fn test_hash_type_without_john_format() {
        let formatter = TextFormatter::new();
        let mut hash_type = create_test_hash_type();
        hash_type.john_format = None;

        let identification = HashIdentification::new(
            "test_hash".to_string(),
            vec![hash_type],
            10,
        );

        let result = formatter.format_single(&identification).unwrap();

        assert!(result.contains("hashcat -m 0"));
        assert!(!result.contains("john --format="));
    }

    #[test]
    fn test_hash_type_without_hashcat_mode() {
        let formatter = TextFormatter::new();
        let mut hash_type = create_test_hash_type();
        hash_type.hashcat_mode = None;

        let identification = HashIdentification::new(
            "test_hash".to_string(),
            vec![hash_type],
            10,
        );

        let result = formatter.format_single(&identification).unwrap();

        assert!(!result.contains("hashcat -m"));
        assert!(result.contains("john --format=Raw-MD5"));
    }
}