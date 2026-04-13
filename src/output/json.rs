//! JSON output formatter

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use serde_json;
use crate::{Result, types::{HashIdentification, DetectionResult, HashType}};
use super::OutputFormatter;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonMetadata {
    timestamp: DateTime<Utc>,
    version: String,
    processing_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonSingleResponse {
    hash: String,
    detected_types: Vec<HashType>,
    processing_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<JsonMetadata>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonBatchResponse {
    results: Vec<JsonSingleResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<JsonMetadata>,
}

/// JSON output formatter with multiple options
pub struct JsonFormatter {
    pretty: bool,
    include_metadata: bool,
}

impl JsonFormatter {
    /// Create a new JsonFormatter with default settings
    pub fn new() -> Self {
        Self {
            pretty: false,
            include_metadata: true,
        }
    }

    /// Create a JsonFormatter with pretty-printing enabled
    pub fn pretty() -> Self {
        Self {
            pretty: true,
            include_metadata: true,
        }
    }

    /// Create a JsonFormatter in compact mode (no metadata)
    pub fn compact() -> Self {
        Self {
            pretty: false,
            include_metadata: false,
        }
    }

    fn create_metadata(&self, count: usize) -> Option<JsonMetadata> {
        if self.include_metadata {
            Some(JsonMetadata {
                timestamp: Utc::now(),
                version: crate::VERSION.to_string(),
                processing_count: count,
            })
        } else {
            None
        }
    }

    fn serialize_json<T: Serialize>(&self, value: &T) -> Result<String> {
        if self.pretty {
            serde_json::to_string_pretty(value).map_err(Into::into)
        } else {
            serde_json::to_string(value).map_err(Into::into)
        }
    }

    fn identification_to_response(&self, result: &HashIdentification, warnings: Vec<String>) -> JsonSingleResponse {
        JsonSingleResponse {
            hash: result.hash.clone(),
            detected_types: result.detected_types.clone(),
            processing_time_ms: result.processing_time_ms,
            metadata: self.create_metadata(1),
            warnings,
        }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter for JsonFormatter {
    fn format_single(&self, result: &HashIdentification) -> Result<String> {
        let response = self.identification_to_response(result, vec![]);
        self.serialize_json(&response)
    }

    fn format_batch(&self, results: &[HashIdentification]) -> Result<String> {
        let json_results: Vec<JsonSingleResponse> = results.iter()
            .map(|result| self.identification_to_response(result, vec![]))
            .collect();

        let response = JsonBatchResponse {
            results: json_results,
            metadata: self.create_metadata(results.len()),
        };

        self.serialize_json(&response)
    }

    fn format_detection(&self, result: &DetectionResult) -> Result<String> {
        let response = self.identification_to_response(&result.identification, result.warnings.clone());
        self.serialize_json(&response)
    }

    fn format_detections(&self, results: &[DetectionResult]) -> Result<String> {
        let json_results: Vec<JsonSingleResponse> = results.iter()
            .map(|result| self.identification_to_response(&result.identification, result.warnings.clone()))
            .collect();

        let response = JsonBatchResponse {
            results: json_results,
            metadata: self.create_metadata(results.len()),
        };

        self.serialize_json(&response)
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

    fn create_test_identification() -> HashIdentification {
        HashIdentification::new(
            "5d41402abc4b2a76b9719d911017c592".to_string(),
            vec![create_test_hash_type()],
            10,
        )
    }

    #[test]
    fn test_json_formatter_creation() {
        let formatter = JsonFormatter::new();
        assert!(!formatter.pretty);
        assert!(formatter.include_metadata);

        let formatter = JsonFormatter::pretty();
        assert!(formatter.pretty);
        assert!(formatter.include_metadata);

        let formatter = JsonFormatter::compact();
        assert!(!formatter.pretty);
        assert!(!formatter.include_metadata);
    }

    #[test]
    fn test_format_single() {
        let formatter = JsonFormatter::compact(); // No metadata for deterministic testing
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();

        // Parse JSON to verify it's valid
        let parsed: JsonSingleResponse = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.hash, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(parsed.detected_types.len(), 1);
        assert_eq!(parsed.detected_types[0].name, "MD5");
        assert_eq!(parsed.processing_time_ms, 10);
        assert!(parsed.warnings.is_empty());
        assert!(parsed.metadata.is_none());
    }

    #[test]
    fn test_format_single_with_metadata() {
        let formatter = JsonFormatter::new(); // With metadata
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();

        // Parse JSON to verify it's valid
        let parsed: JsonSingleResponse = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.hash, "5d41402abc4b2a76b9719d911017c592");
        assert!(parsed.metadata.is_some());
        let metadata = parsed.metadata.unwrap();
        assert_eq!(metadata.processing_count, 1);
        assert_eq!(metadata.version, crate::VERSION);
    }

    #[test]
    fn test_format_batch() {
        let formatter = JsonFormatter::compact();
        let id1 = create_test_identification();
        let mut id2 = create_test_identification();
        id2.hash = "other_hash".to_string();

        let result = formatter.format_batch(&[id1, id2]).unwrap();

        // Parse JSON to verify it's valid
        let parsed: JsonBatchResponse = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.results.len(), 2);
        assert_eq!(parsed.results[0].hash, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(parsed.results[1].hash, "other_hash");
        assert!(parsed.metadata.is_none());
    }

    #[test]
    fn test_format_detection_with_warnings() {
        let formatter = JsonFormatter::compact();
        let identification = create_test_identification();
        let detection = DetectionResult::new(identification)
            .with_warning("Test warning 1".to_string())
            .with_warning("Test warning 2".to_string());

        let result = formatter.format_detection(&detection).unwrap();

        // Parse JSON to verify it's valid
        let parsed: JsonSingleResponse = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.warnings.len(), 2);
        assert_eq!(parsed.warnings[0], "Test warning 1");
        assert_eq!(parsed.warnings[1], "Test warning 2");
    }

    #[test]
    fn test_format_detections() {
        let formatter = JsonFormatter::compact();
        let id1 = create_test_identification();
        let mut id2 = create_test_identification();
        id2.hash = "other_hash".to_string();

        let detection1 = DetectionResult::new(id1).with_warning("Warning 1".to_string());
        let detection2 = DetectionResult::new(id2);

        let result = formatter.format_detections(&[detection1, detection2]).unwrap();

        // Parse JSON to verify it's valid
        let parsed: JsonBatchResponse = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.results.len(), 2);
        assert_eq!(parsed.results[0].warnings.len(), 1);
        assert_eq!(parsed.results[1].warnings.len(), 0);
    }

    #[test]
    fn test_pretty_formatting() {
        let formatter = JsonFormatter::pretty();
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();

        // Pretty-printed JSON should contain newlines and indentation
        assert!(result.contains('\n'));
        assert!(result.contains("  "));
    }

    #[test]
    fn test_compact_formatting() {
        let formatter = JsonFormatter::compact();
        let identification = create_test_identification();

        let result = formatter.format_single(&identification).unwrap();

        // Compact JSON should not contain newlines (except maybe at end)
        let line_count = result.lines().count();
        assert!(line_count <= 1);
    }

    #[test]
    fn test_empty_results() {
        let formatter = JsonFormatter::new();
        let empty_results: Vec<HashIdentification> = vec![];

        let result = formatter.format_batch(&empty_results).unwrap();

        // Parse JSON to verify it's valid
        let parsed: JsonBatchResponse = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.results.len(), 0);
    }
}