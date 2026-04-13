//! Hash pattern definitions for various hash types

pub mod basic;
pub mod modern;
pub mod network;
pub mod database;
pub mod document;
pub mod crypto;

use crate::{Result, pattern::PatternRegistry};

/// Load all available hash patterns into a registry
pub fn load_all_patterns() -> Result<PatternRegistry> {
    let mut registry = PatternRegistry::new();

    // Load patterns by category
    basic::load_patterns(&mut registry)?;
    modern::load_patterns(&mut registry)?;
    network::load_patterns(&mut registry)?;
    database::load_patterns(&mut registry)?;
    document::load_patterns(&mut registry)?;
    crypto::load_patterns(&mut registry)?;

    // Sort by confidence (highest first)
    registry.sort_by_confidence();

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_all_patterns() {
        let registry = load_all_patterns().unwrap();
        assert!(!registry.patterns().is_empty());
    }

    #[test]
    fn test_patterns_sorted_by_confidence() {
        let registry = load_all_patterns().unwrap();
        let patterns = registry.patterns();

        // Verify patterns are sorted by confidence (highest first)
        for i in 1..patterns.len() {
            assert!(patterns[i-1].base_confidence >= patterns[i].base_confidence);
        }
    }

    #[test]
    fn test_basic_patterns_loaded() {
        let registry = load_all_patterns().unwrap();
        let patterns = registry.patterns();

        // Should have basic hash patterns
        let has_md5 = patterns.iter().any(|p| p.name == "MD5");
        let has_sha1 = patterns.iter().any(|p| p.name == "SHA1");
        let has_sha256 = patterns.iter().any(|p| p.name == "SHA256");

        assert!(has_md5, "Should contain MD5 pattern");
        assert!(has_sha1, "Should contain SHA1 pattern");
        assert!(has_sha256, "Should contain SHA256 pattern");
    }
}