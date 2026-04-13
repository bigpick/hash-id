//! Modern authentication hash patterns (bcrypt, scrypt, PBKDF2, Argon2)
//!
//! This module implements patterns for modern password hashing algorithms
//! used in authentication systems, providing strong security against
//! brute force attacks through computational cost.

use crate::{Result, pattern::{HashPattern, PatternRegistry}, types::HashCategory};

/// Load modern authentication patterns into the registry
pub fn load_patterns(registry: &mut PatternRegistry) -> Result<()> {
    // bcrypt - Most common modern hash
    let bcrypt = HashPattern::new(
        "bcrypt".to_string(),
        r"^\$2[abyxz]\$[0-9]{2}\$[./A-Za-z0-9]{53}$",
        Some(3200),
        Some("bcrypt".to_string()),
        HashCategory::Authentication,
        "bcrypt password hashing function".to_string(),
        1.0, // Perfect confidence due to unique format
        true,
    )?;
    registry.add_pattern(bcrypt);

    // scrypt
    let scrypt = HashPattern::new(
        "scrypt".to_string(),
        r"^\$scrypt\$[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        Some(8900),
        Some("scrypt".to_string()),
        HashCategory::Authentication,
        "scrypt password-based key derivation function".to_string(),
        1.0,
        true,
    )?;
    registry.add_pattern(scrypt);

    // PBKDF2-SHA256
    let pbkdf2_sha256 = HashPattern::new(
        "PBKDF2-SHA256".to_string(),
        r"^pbkdf2_sha256\$[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        Some(10900),
        Some("PBKDF2-HMAC-SHA256".to_string()),
        HashCategory::Authentication,
        "PBKDF2 with SHA-256".to_string(),
        0.95,
        true,
    )?;
    registry.add_pattern(pbkdf2_sha256);

    // PBKDF2-SHA1
    let pbkdf2_sha1 = HashPattern::new(
        "PBKDF2-SHA1".to_string(),
        r"^pbkdf2_sha1\$[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        Some(12000),
        Some("PBKDF2-HMAC-SHA1".to_string()),
        HashCategory::Authentication,
        "PBKDF2 with SHA-1".to_string(),
        0.95,
        true,
    )?;
    registry.add_pattern(pbkdf2_sha1);

    // PBKDF2-SHA512
    let pbkdf2_sha512 = HashPattern::new(
        "PBKDF2-SHA512".to_string(),
        r"^pbkdf2_sha512\$[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        Some(12100),
        Some("PBKDF2-HMAC-SHA512".to_string()),
        HashCategory::Authentication,
        "PBKDF2 with SHA-512".to_string(),
        0.95,
        true,
    )?;
    registry.add_pattern(pbkdf2_sha512);

    // Argon2i
    let argon2i = HashPattern::new(
        "Argon2i".to_string(),
        r"^\$argon2i\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        Some(10800), // Note: Check hashcat for correct mode
        Some("argon2".to_string()),
        HashCategory::Authentication,
        "Argon2i password hashing function".to_string(),
        1.0,
        true,
    )?;
    registry.add_pattern(argon2i);

    // Argon2d
    let argon2d = HashPattern::new(
        "Argon2d".to_string(),
        r"^\$argon2d\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        Some(10800),
        Some("argon2".to_string()),
        HashCategory::Authentication,
        "Argon2d password hashing function".to_string(),
        1.0,
        true,
    )?;
    registry.add_pattern(argon2d);

    // Argon2id
    let argon2id = HashPattern::new(
        "Argon2id".to_string(),
        r"^\$argon2id\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        Some(10800),
        Some("argon2".to_string()),
        HashCategory::Authentication,
        "Argon2id password hashing function".to_string(),
        1.0,
        true,
    )?;
    registry.add_pattern(argon2id);

    // sha256crypt (Unix)
    let sha256crypt = HashPattern::new(
        "sha256crypt".to_string(),
        r"^\$5\$[a-zA-Z0-9./]{0,16}\$[a-zA-Z0-9./]{43}$",
        Some(7400),
        Some("sha256crypt".to_string()),
        HashCategory::Authentication,
        "SHA-256 based Unix crypt".to_string(),
        0.95,
        true,
    )?;
    registry.add_pattern(sha256crypt);

    // sha512crypt (Unix)
    let sha512crypt = HashPattern::new(
        "sha512crypt".to_string(),
        r"^\$6\$[a-zA-Z0-9./]{0,16}\$[a-zA-Z0-9./]{86}$",
        Some(1800),
        Some("sha512crypt".to_string()),
        HashCategory::Authentication,
        "SHA-512 based Unix crypt".to_string(),
        0.95,
        true,
    )?;
    registry.add_pattern(sha512crypt);

    // md5crypt (Unix) - more flexible hash part to match actual lengths
    let md5crypt = HashPattern::new(
        "md5crypt".to_string(),
        r"^\$1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{22}$",
        Some(500),
        Some("md5crypt".to_string()),
        HashCategory::Legacy,
        "MD5 based Unix crypt".to_string(),
        0.9,
        true,
    )?;
    registry.add_pattern(md5crypt);

    // Apache APR1 (MD5) - same format as md5crypt but with apr1 prefix
    let apr1 = HashPattern::new(
        "Apache APR1".to_string(),
        r"^\$apr1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{22}$",
        Some(1600),
        Some("md5crypt".to_string()),
        HashCategory::Authentication,
        "Apache APR1 MD5 hash".to_string(),
        0.95,
        true,
    )?;
    registry.add_pattern(apr1);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HashCategory;

    #[test]
    fn test_load_patterns() {
        let mut registry = PatternRegistry::new();
        assert!(load_patterns(&mut registry).is_ok());
        assert!(!registry.patterns().is_empty());

        // Should have loaded multiple modern patterns
        assert!(registry.patterns().len() >= 10);
    }

    #[test]
    fn test_bcrypt_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test various bcrypt variants
        let test_cases = vec![
            ("$2a$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG", true),  // $2a$ variant
            ("$2b$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG", true),  // $2b$ variant
            ("$2x$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG", true),  // $2x$ variant
            ("$2y$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG", true),  // $2y$ variant
            ("$2z$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG", true),  // $2z$ variant
            ("$2a$12$R9h/cIPz0gi.URNNX3kh2OT7mQkSNfqVJCF07x78UJPUeJrF5k/fW", true),  // Different cost
            ("$2$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG", false), // Invalid variant
            ("$2a$1$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG", false),  // Invalid cost format
            ("$2a$100$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qq", false),  // Wrong hash length
        ];

        for (hash, should_match) in test_cases {
            let matches = registry.find_matches(hash);
            let bcrypt_match = matches.iter().any(|p| p.name == "bcrypt");
            assert_eq!(bcrypt_match, should_match, "Failed for hash: {}", hash);

            if should_match {
                let bcrypt_pattern = matches.iter().find(|p| p.name == "bcrypt").unwrap();
                assert_eq!(bcrypt_pattern.base_confidence, 1.0);
                assert_eq!(bcrypt_pattern.hashcat_mode, Some(3200));
                assert_eq!(bcrypt_pattern.john_format, Some("bcrypt".to_string()));
                assert!(bcrypt_pattern.requires_salt_check);
                assert_eq!(bcrypt_pattern.category, HashCategory::Authentication);
            }
        }
    }

    #[test]
    fn test_scrypt_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test scrypt patterns
        let test_cases = vec![
            ("$scrypt$1024$YWFhYWFhYWE$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh", true),
            ("$scrypt$16384$c2FsdA$hash123", true),
            ("$scrypt$invalid$YWFhYWFhYWE$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh", false),
            ("scrypt$1024$YWFhYWFhYWE$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh", false), // Missing $
        ];

        for (hash, should_match) in test_cases {
            let matches = registry.find_matches(hash);
            let scrypt_match = matches.iter().any(|p| p.name == "scrypt");
            assert_eq!(scrypt_match, should_match, "Failed for hash: {}", hash);

            if should_match {
                let scrypt_pattern = matches.iter().find(|p| p.name == "scrypt").unwrap();
                assert_eq!(scrypt_pattern.base_confidence, 1.0);
                assert_eq!(scrypt_pattern.hashcat_mode, Some(8900));
                assert_eq!(scrypt_pattern.john_format, Some("scrypt".to_string()));
                assert!(scrypt_pattern.requires_salt_check);
            }
        }
    }

    #[test]
    fn test_pbkdf2_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test PBKDF2 variants
        let test_cases = vec![
            ("pbkdf2_sha256$1000$c2FsdA$aGFzaA", "PBKDF2-SHA256"),
            ("pbkdf2_sha1$1000$c2FsdA$aGFzaA", "PBKDF2-SHA1"),
            ("pbkdf2_sha512$1000$c2FsdA$aGFzaA", "PBKDF2-SHA512"),
        ];

        for (hash, expected_name) in test_cases {
            let matches = registry.find_matches(hash);
            let pbkdf2_match = matches.iter().find(|p| p.name == expected_name);
            assert!(pbkdf2_match.is_some(), "Should match {} for hash: {}", expected_name, hash);

            let pattern = pbkdf2_match.unwrap();
            assert_eq!(pattern.base_confidence, 0.95);
            assert!(pattern.requires_salt_check);
            assert_eq!(pattern.category, HashCategory::Authentication);
        }

        // Test invalid PBKDF2
        let invalid_cases = vec![
            "pbkdf2_sha256$invalid$c2FsdA$aGFzaA", // Invalid iteration count
            "pbkdf2_sha256$1000$c2FsdA", // Missing hash part
            "pbkdf2_invalid$1000$c2FsdA$aGFzaA", // Invalid algorithm
        ];

        for hash in invalid_cases {
            let matches = registry.find_matches(hash);
            let has_pbkdf2 = matches.iter().any(|p| p.name.starts_with("PBKDF2"));
            assert!(!has_pbkdf2, "Should not match PBKDF2 for invalid hash: {}", hash);
        }
    }

    #[test]
    fn test_argon2_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test Argon2 variants
        let test_cases = vec![
            ("$argon2i$v=19$m=1024,t=2,p=2$c2FsdA$aGFzaA", "Argon2i"),
            ("$argon2d$v=19$m=1024,t=2,p=2$c2FsdA$aGFzaA", "Argon2d"),
            ("$argon2id$v=19$m=1024,t=2,p=2$c2FsdA$aGFzaA", "Argon2id"),
            ("$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", "Argon2i"), // Different params
        ];

        for (hash, expected_name) in test_cases {
            let matches = registry.find_matches(hash);
            let argon2_match = matches.iter().find(|p| p.name == expected_name);
            assert!(argon2_match.is_some(), "Should match {} for hash: {}", expected_name, hash);

            let pattern = argon2_match.unwrap();
            assert_eq!(pattern.base_confidence, 1.0);
            assert_eq!(pattern.hashcat_mode, Some(10800));
            assert_eq!(pattern.john_format, Some("argon2".to_string()));
            assert!(pattern.requires_salt_check);
        }

        // Test invalid Argon2
        let invalid_cases = vec![
            "$argon2$v=19$m=1024,t=2,p=2$c2FsdA$aGFzaA", // Invalid variant
            "$argon2i$v=invalid$m=1024,t=2,p=2$c2FsdA$aGFzaA", // Invalid version
            "$argon2i$v=19$m=invalid,t=2,p=2$c2FsdA$aGFzaA", // Invalid memory param
        ];

        for hash in invalid_cases {
            let matches = registry.find_matches(hash);
            let has_argon2 = matches.iter().any(|p| p.name.starts_with("Argon2"));
            assert!(!has_argon2, "Should not match Argon2 for invalid hash: {}", hash);
        }
    }

    #[test]
    fn test_unix_crypt_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test Unix crypt variants - using proper lengths and characters
        let test_cases = vec![
            ("$1$salt$QmQqvFZsLeqb7qZD1RSddM", "md5crypt"),      // md5crypt (22 chars)
            ("$5$salt$5dmV6ZWgD8T2ZENub6x.kUjGY0QM5X5vHmfHkl.QZqA", "sha256crypt"), // sha256crypt (43 chars)
            ("$6$salt$Cfm6/t.wOsA./LoHdMkvJI.TM11TnBjhyKJGrBtwfUd/2xF8j4J0kGPG2DdnyEd4SXdnzL5kFZW5z4mSkOq0QA", "sha512crypt"), // sha512crypt (86 chars)
            ("$5$$5dmV6ZWgD8T2ZENub6x.kUjGY0QM5X5vHmfHkl.QZqA", "sha256crypt"), // No salt
            ("$6$$Cfm6/t.wOsA./LoHdMkvJI.TM11TnBjhyKJGrBtwfUd/2xF8j4J0kGPG2DdnyEd4SXdnzL5kFZW5z4mSkOq0QA", "sha512crypt"), // No salt
        ];

        for (hash, expected_name) in test_cases {
            let matches = registry.find_matches(hash);
            let crypt_match = matches.iter().find(|p| p.name == expected_name);
            assert!(crypt_match.is_some(), "Should match {} for hash: {}", expected_name, hash);

            let pattern = crypt_match.unwrap();
            assert!(pattern.requires_salt_check);

            // Check specific properties
            match expected_name {
                "md5crypt" => {
                    assert_eq!(pattern.hashcat_mode, Some(500));
                    assert_eq!(pattern.category, HashCategory::Legacy);
                    assert_eq!(pattern.base_confidence, 0.9);
                },
                "sha256crypt" => {
                    assert_eq!(pattern.hashcat_mode, Some(7400));
                    assert_eq!(pattern.category, HashCategory::Authentication);
                    assert_eq!(pattern.base_confidence, 0.95);
                },
                "sha512crypt" => {
                    assert_eq!(pattern.hashcat_mode, Some(1800));
                    assert_eq!(pattern.category, HashCategory::Authentication);
                    assert_eq!(pattern.base_confidence, 0.95);
                },
                _ => {}
            }
        }

        // Test invalid Unix crypt
        let invalid_cases = vec![
            "$1$toolongsalt$QmQqvFZsLeqb7qZD1RSddM",  // Salt too long for md5crypt (>8 chars)
            "$5$salt$tooshorthash",                     // Hash too short for sha256crypt
            "$6$salt$tooshorthash",                     // Hash too short for sha512crypt
            "$7$salt$5dmV6ZWgD8T2ZENub6x.kUjGY0QM5X5vHmfHkl.QZq", // Invalid type
        ];

        for hash in invalid_cases {
            let matches = registry.find_matches(hash);
            let has_crypt = matches.iter().any(|p|
                p.name == "md5crypt" || p.name == "sha256crypt" || p.name == "sha512crypt"
            );
            assert!(!has_crypt, "Should not match crypt variants for invalid hash: {}", hash);
        }
    }

    #[test]
    fn test_apache_apr1_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test Apache APR1
        let test_cases = vec![
            ("$apr1$salt$QmQqvFZsLeqb7qZD1RSddM", true),
            ("$apr1$$QmQqvFZsLeqb7qZD1RSddM", true), // No salt
            ("$apr1$toolongsalt$QmQqvFZsLeqb7qZD1RSddM", false), // Salt too long (>8 chars)
            ("$apr1$salt$tooshort", false), // Hash too short
            ("apr1$salt$QmQqvFZsLeqb7qZD1RSddM", false), // Missing $
        ];

        for (hash, should_match) in test_cases {
            let matches = registry.find_matches(hash);
            let apr1_match = matches.iter().any(|p| p.name == "Apache APR1");
            assert_eq!(apr1_match, should_match, "Failed for hash: {}", hash);

            if should_match {
                let apr1_pattern = matches.iter().find(|p| p.name == "Apache APR1").unwrap();
                assert_eq!(apr1_pattern.base_confidence, 0.95);
                assert_eq!(apr1_pattern.hashcat_mode, Some(1600));
                assert_eq!(apr1_pattern.john_format, Some("md5crypt".to_string()));
                assert_eq!(apr1_pattern.category, HashCategory::Authentication);
            }
        }
    }

    #[test]
    fn test_confidence_levels() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        let patterns = registry.patterns();

        // Test confidence levels for modern patterns
        let confidence_tests = vec![
            ("bcrypt", 1.0),
            ("scrypt", 1.0),
            ("Argon2i", 1.0),
            ("Argon2d", 1.0),
            ("Argon2id", 1.0),
            ("PBKDF2-SHA256", 0.95),
            ("PBKDF2-SHA1", 0.95),
            ("PBKDF2-SHA512", 0.95),
            ("sha256crypt", 0.95),
            ("sha512crypt", 0.95),
            ("Apache APR1", 0.95),
            ("md5crypt", 0.9),
        ];

        for (name, expected_confidence) in confidence_tests {
            let pattern = patterns.iter().find(|p| p.name == name);
            assert!(pattern.is_some(), "Pattern {} should exist", name);
            assert_eq!(pattern.unwrap().base_confidence, expected_confidence,
                      "Wrong confidence for {}", name);
        }
    }

    #[test]
    fn test_hashcat_modes() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        let patterns = registry.patterns();

        // Test hashcat modes for modern patterns
        let mode_tests = vec![
            ("bcrypt", 3200),
            ("scrypt", 8900),
            ("PBKDF2-SHA256", 10900),
            ("PBKDF2-SHA1", 12000),
            ("PBKDF2-SHA512", 12100),
            ("Argon2i", 10800),
            ("Argon2d", 10800),
            ("Argon2id", 10800),
            ("sha256crypt", 7400),
            ("sha512crypt", 1800),
            ("md5crypt", 500),
            ("Apache APR1", 1600),
        ];

        for (name, expected_mode) in mode_tests {
            let pattern = patterns.iter().find(|p| p.name == name);
            assert!(pattern.is_some(), "Pattern {} should exist", name);
            assert_eq!(pattern.unwrap().hashcat_mode, Some(expected_mode),
                      "Wrong hashcat mode for {}", name);
        }
    }

    #[test]
    fn test_salt_requirements() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // All modern auth patterns should require salt check
        for pattern in registry.patterns() {
            if pattern.category == HashCategory::Authentication ||
               pattern.category == HashCategory::Legacy {
                assert!(pattern.requires_salt_check,
                       "Pattern {} should require salt check", pattern.name);
            }
        }
    }

    #[test]
    fn test_pattern_categories() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        let patterns = registry.patterns();

        // Test categories
        let category_tests = vec![
            ("bcrypt", HashCategory::Authentication),
            ("scrypt", HashCategory::Authentication),
            ("PBKDF2-SHA256", HashCategory::Authentication),
            ("Argon2i", HashCategory::Authentication),
            ("sha256crypt", HashCategory::Authentication),
            ("sha512crypt", HashCategory::Authentication),
            ("Apache APR1", HashCategory::Authentication),
            ("md5crypt", HashCategory::Legacy),
        ];

        for (name, expected_category) in category_tests {
            let pattern = patterns.iter().find(|p| p.name == name);
            assert!(pattern.is_some(), "Pattern {} should exist", name);
            assert_eq!(pattern.unwrap().category, expected_category,
                      "Wrong category for {}", name);
        }
    }

    #[test]
    fn test_edge_cases() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Empty string
        let matches = registry.find_matches("");
        assert!(matches.is_empty());

        // Partial matches should not work
        let partial_cases = vec![
            "$2a$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qq", // bcrypt missing char
            "$scrypt$1024$YWFhYWFhYWE", // scrypt missing hash
            "pbkdf2_sha256$1000$c2FsdA", // PBKDF2 missing hash
            "$argon2i$v=19$m=1024,t=2,p=2$c2FsdA", // Argon2 missing hash
            "$5$salt$5dmV6ZWgD8T2ZENub6x.kUjGY0QM5X5vHmfHkl.QZ", // sha256crypt wrong length (42 instead of 43)
        ];

        for hash in partial_cases {
            let matches = registry.find_matches(hash);
            let has_modern = matches.iter().any(|p|
                p.category == HashCategory::Authentication ||
                (p.category == HashCategory::Legacy && p.name == "md5crypt")
            );
            assert!(!has_modern, "Should not match modern patterns for partial hash: {}", hash);
        }
    }

    #[test]
    fn test_multiple_format_detection() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Some patterns might have similar formats but different meanings
        // Test that we get appropriate matches
        let test_hash = "$2a$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG";
        let matches = registry.find_matches(test_hash);

        // Should match bcrypt with high confidence
        let bcrypt_match = matches.iter().find(|p| p.name == "bcrypt");
        assert!(bcrypt_match.is_some());
        assert_eq!(bcrypt_match.unwrap().base_confidence, 1.0);
    }
}