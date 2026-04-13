use super::HashPattern;

/// Context for confidence scoring
#[derive(Debug, Default)]
pub struct DetectionContext {
    /// File extension if hash came from a file
    pub file_extension: Option<String>,
    /// Whether this is part of a batch analysis
    pub is_batch: bool,
    /// Number of hashes in batch (if applicable)
    pub batch_size: Option<usize>,
}

/// Scorer for calculating confidence values
pub struct ConfidenceScorer;

impl ConfidenceScorer {
    /// Calculate confidence score for a hash/pattern match
    pub fn calculate(
        hash: &str,
        pattern: &HashPattern,
        context: &DetectionContext,
    ) -> f32 {
        let mut score = pattern.base_confidence;

        // Length-based confidence adjustment
        score *= Self::length_confidence(hash, pattern);

        // Character set analysis
        score *= Self::charset_confidence(hash, pattern);

        // Format specificity bonus
        score *= Self::format_specificity(hash, pattern);

        // Context-based adjustments
        score *= Self::context_bonus(pattern, context);

        score.min(1.0)
    }

    /// Adjust confidence based on hash length characteristics
    fn length_confidence(hash: &str, pattern: &HashPattern) -> f32 {
        // Common hash lengths get slight confidence boost
        match hash.len() {
            32 => 1.1,   // MD5, NTLM, MD4 length
            40 => 1.15,  // SHA1 length
            56 => 1.1,   // SHA224 length
            64 => 1.15,  // SHA256 length
            96 => 1.1,   // SHA384 length
            128 => 1.1,  // SHA512 length
            _ => {
                // Uncommon lengths get slight penalty unless it's a format-specific pattern
                if pattern.base_confidence >= 0.9 { 1.0 } else { 0.95 }
            }
        }
    }

    /// Adjust confidence based on character set
    fn charset_confidence(hash: &str, _pattern: &HashPattern) -> f32 {
        let chars: Vec<char> = hash.chars().collect();

        let has_upper = chars.iter().any(|c| c.is_ascii_uppercase());
        let has_lower = chars.iter().any(|c| c.is_ascii_lowercase());
        let has_digits = chars.iter().any(|c| c.is_ascii_digit());
        let has_special = chars.iter().any(|c| !c.is_alphanumeric());

        // Pure hex gets bonus for basic hashes
        if chars.iter().all(|c| c.is_ascii_hexdigit()) {
            1.1
        }
        // Mixed character sets (likely encoded formats)
        else if has_upper && has_lower && has_digits && has_special {
            1.05
        }
        // Only alphanumeric (base64-ish)
        else if has_upper && has_lower && has_digits && !has_special {
            1.02
        }
        else {
            1.0
        }
    }

    /// Adjust confidence based on format specificity
    fn format_specificity(hash: &str, pattern: &HashPattern) -> f32 {
        // Patterns with unique prefixes get bonus confidence
        if hash.starts_with('$') {
            // Format-specific patterns (bcrypt, scrypt, etc.)
            1.2
        } else if pattern.base_confidence >= 0.9 {
            // Already high-confidence patterns
            1.0
        } else {
            // Generic patterns (length-based matching)
            0.95
        }
    }

    /// Adjust confidence based on context
    fn context_bonus(pattern: &HashPattern, context: &DetectionContext) -> f32 {
        let mut multiplier = 1.0;

        // File extension hints
        if let Some(ref ext) = context.file_extension {
            match (ext.as_str(), &pattern.category) {
                ("txt", _) => multiplier *= 1.05, // Common hash dump format
                ("hash", _) => multiplier *= 1.1,  // Explicit hash file
                ("john", _) => multiplier *= 1.05, // John format
                ("hc", _) => multiplier *= 1.05,   // Hashcat format
                _ => {}
            }
        }

        // Batch analysis context
        if context.is_batch {
            if let Some(size) = context.batch_size {
                if size > 100 {
                    // Large batches slightly increase confidence
                    multiplier *= 1.02;
                }
            }
        }

        multiplier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashCategory;

    fn create_test_pattern() -> HashPattern {
        HashPattern::new(
            "MD5".to_string(),
            r"^[a-fA-F0-9]{32}$",
            Some(0),
            None,
            HashCategory::Basic,
            "MD5".to_string(),
            0.6,
            false,
        ).unwrap()
    }

    #[test]
    fn test_basic_confidence_calculation() {
        let pattern = create_test_pattern();
        let context = DetectionContext::default();

        let score = ConfidenceScorer::calculate(
            "5d41402abc4b2a76b9719d911017c592",
            &pattern,
            &context,
        );

        // Should be > base confidence due to length and charset bonuses
        assert!(score > pattern.base_confidence);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_format_specificity_bonus() {
        let mut pattern = create_test_pattern();
        pattern.base_confidence = 1.0; // High confidence pattern

        let context = DetectionContext::default();

        // Hash with $ prefix should get format bonus
        let score = ConfidenceScorer::calculate(
            "$2a$10$abcdefghijklmnopqrstuvwxyz123456789",
            &pattern,
            &context,
        );

        assert!(score >= 1.0);
    }

    #[test]
    fn test_context_bonus() {
        let pattern = create_test_pattern();
        let context = DetectionContext {
            file_extension: Some("hash".to_string()),
            is_batch: true,
            batch_size: Some(200),
        };

        let score = ConfidenceScorer::calculate(
            "5d41402abc4b2a76b9719d911017c592",
            &pattern,
            &context,
        );

        // Should get bonus from file extension and batch context
        assert!(score > pattern.base_confidence);
    }
}