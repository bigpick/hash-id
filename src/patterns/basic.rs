//! Basic hash function patterns (MD5, SHA family, NTLM, etc.)
//!
//! This module implements patterns for fundamental hash algorithms commonly
//! encountered in password cracking scenarios.

use crate::{
    Result,
    pattern::{HashPattern, PatternRegistry},
    types::HashCategory,
};

/// Load basic hash patterns into the registry
pub fn load_patterns(registry: &mut PatternRegistry) -> Result<()> {
    // MD5 - 32 hex characters (mode 0, confidence 0.6)
    let md5 = HashPattern::new(
        "MD5".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(0),
        Some("Raw-MD5".to_string()),
        HashCategory::Basic,
        "MD5 message digest".to_string(),
        0.6,
        false,
    )?;

    // Half MD5 - 16 hex characters (mode 5100, confidence 0.4)
    let md5_half = HashPattern::new(
        "Half MD5".to_string(),
        r"^[a-fA-F0-9]{16}$",
        Some(5100),
        Some("Raw-MD5-Half".to_string()),
        HashCategory::Basic,
        "Half MD5 (first 16 characters)".to_string(),
        0.4,
        false,
    )?;

    // NTLM - 32 hex characters (mode 1000, confidence 0.5)
    let ntlm = HashPattern::new(
        "NTLM".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(1000),
        Some("NT".to_string()),
        HashCategory::Basic,
        "NTLM hash".to_string(),
        0.5,
        false,
    )?;

    // MD4 - 32 hex characters (mode 900, confidence 0.4)
    let md4 = HashPattern::new(
        "MD4".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(900),
        Some("Raw-MD4".to_string()),
        HashCategory::Basic,
        "MD4 message digest".to_string(),
        0.4,
        false,
    )?;

    // LM hash - 32 hex characters (mode 3000, confidence 0.3)
    let lm = HashPattern::new(
        "LM".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(3000),
        Some("LM".to_string()),
        HashCategory::Legacy,
        "LM hash".to_string(),
        0.3,
        false,
    )?;

    // SHA1 - 40 hex characters (mode 100, confidence 0.8)
    let sha1 = HashPattern::new(
        "SHA1".to_string(),
        r"^[a-fA-F0-9]{40}$",
        Some(100),
        Some("Raw-SHA1".to_string()),
        HashCategory::Basic,
        "SHA1 hash".to_string(),
        0.8,
        false,
    )?;

    // SHA224 - 56 hex characters (mode 1300, confidence 0.85)
    let sha224 = HashPattern::new(
        "SHA224".to_string(),
        r"^[a-fA-F0-9]{56}$",
        Some(1300),
        Some("Raw-SHA224".to_string()),
        HashCategory::Basic,
        "SHA224 hash".to_string(),
        0.85,
        false,
    )?;

    // SHA256 - 64 hex characters (mode 1400, confidence 0.8)
    let sha256 = HashPattern::new(
        "SHA256".to_string(),
        r"^[a-fA-F0-9]{64}$",
        Some(1400),
        Some("Raw-SHA256".to_string()),
        HashCategory::Basic,
        "SHA256 hash".to_string(),
        0.8,
        false,
    )?;

    // SHA384 - 96 hex characters (mode 10800, confidence 0.9)
    let sha384 = HashPattern::new(
        "SHA384".to_string(),
        r"^[a-fA-F0-9]{96}$",
        Some(10800),
        Some("Raw-SHA384".to_string()),
        HashCategory::Basic,
        "SHA384 hash".to_string(),
        0.9,
        false,
    )?;

    // SHA512 - 128 hex characters (mode 1700, confidence 0.9)
    let sha512 = HashPattern::new(
        "SHA512".to_string(),
        r"^[a-fA-F0-9]{128}$",
        Some(1700),
        Some("Raw-SHA512".to_string()),
        HashCategory::Basic,
        "SHA512 hash".to_string(),
        0.9,
        false,
    )?;

    // Salted SHA1 - SHA1 with colon separator (mode 110, confidence 0.85)
    let sha1_salt = HashPattern::new(
        "SHA1(Salt)".to_string(),
        r"^[a-fA-F0-9]{40}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(110),
        Some("SSHA".to_string()),
        HashCategory::Basic,
        "SHA1 hash with salt".to_string(),
        0.85,
        true,
    )?;

    // Salted SHA256 - SHA256 with colon separator (mode 1410, confidence 0.85)
    let sha256_salt = HashPattern::new(
        "SHA256(Salt)".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1410),
        Some("SSHA256".to_string()),
        HashCategory::Basic,
        "SHA256 hash with salt".to_string(),
        0.85,
        true,
    )?;

    // Salted MD5 - MD5 with colon separator (mode 10, confidence 0.65)
    let md5_salt = HashPattern::new(
        "MD5(Salt)".to_string(),
        r"^[a-fA-F0-9]{32}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(10),
        Some("SSHA".to_string()),
        HashCategory::Basic,
        "MD5 hash with salt".to_string(),
        0.65,
        true,
    )?;

    // MD2 - 32 hex characters (mode 200, confidence 0.3)
    let md2 = HashPattern::new(
        "MD2".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(200),
        Some("Raw-MD2".to_string()),
        HashCategory::Legacy,
        "MD2 message digest".to_string(),
        0.3,
        false,
    )?;

    // RIPEMD128 - 32 hex characters (mode 8400, confidence 0.4)
    let ripemd128 = HashPattern::new(
        "RIPEMD128".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(8400),
        Some("RIPEMD128".to_string()),
        HashCategory::Basic,
        "RIPEMD-128 hash".to_string(),
        0.4,
        false,
    )?;

    // RIPEMD160 - 40 hex characters (mode 6000, confidence 0.5)
    let ripemd160 = HashPattern::new(
        "RIPEMD160".to_string(),
        r"^[a-fA-F0-9]{40}$",
        Some(6000),
        Some("RIPEMD160".to_string()),
        HashCategory::Basic,
        "RIPEMD-160 hash".to_string(),
        0.5,
        false,
    )?;

    // RIPEMD256 - 64 hex characters (mode 8500, confidence 0.4)
    let ripemd256 = HashPattern::new(
        "RIPEMD256".to_string(),
        r"^[a-fA-F0-9]{64}$",
        Some(8500),
        Some("RIPEMD256".to_string()),
        HashCategory::Basic,
        "RIPEMD-256 hash".to_string(),
        0.4,
        false,
    )?;

    // RIPEMD320 - 80 hex characters (mode 8600, confidence 0.4)
    let ripemd320 = HashPattern::new(
        "RIPEMD320".to_string(),
        r"^[a-fA-F0-9]{80}$",
        Some(8600),
        Some("RIPEMD320".to_string()),
        HashCategory::Basic,
        "RIPEMD-320 hash".to_string(),
        0.4,
        false,
    )?;

    // Whirlpool - 128 hex characters (mode 6100, confidence 0.5)
    let whirlpool = HashPattern::new(
        "Whirlpool".to_string(),
        r"^[a-fA-F0-9]{128}$",
        Some(6100),
        Some("Whirlpool".to_string()),
        HashCategory::Basic,
        "Whirlpool hash".to_string(),
        0.5,
        false,
    )?;

    // Tiger128 - 32 hex characters (mode 8700, confidence 0.4)
    let tiger128 = HashPattern::new(
        "Tiger128".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(8700),
        Some("Tiger".to_string()),
        HashCategory::Basic,
        "Tiger-128 hash".to_string(),
        0.4,
        false,
    )?;

    // Tiger160 - 40 hex characters (mode 8800, confidence 0.4)
    let tiger160 = HashPattern::new(
        "Tiger160".to_string(),
        r"^[a-fA-F0-9]{40}$",
        Some(8800),
        Some("Tiger".to_string()),
        HashCategory::Basic,
        "Tiger-160 hash".to_string(),
        0.4,
        false,
    )?;

    // Tiger192 - 48 hex characters (mode 8900, confidence 0.4)
    let tiger192 = HashPattern::new(
        "Tiger192".to_string(),
        r"^[a-fA-F0-9]{48}$",
        Some(8900),
        Some("Tiger".to_string()),
        HashCategory::Basic,
        "Tiger-192 hash".to_string(),
        0.4,
        false,
    )?;

    // BLAKE2b-256 - 64 hex characters (mode 600, confidence 0.7)
    let blake2b256 = HashPattern::new(
        "BLAKE2b-256".to_string(),
        r"^[a-fA-F0-9]{64}$",
        Some(600),
        Some("BLAKE2b-256".to_string()),
        HashCategory::Modern,
        "BLAKE2b-256 hash".to_string(),
        0.7,
        false,
    )?;

    // BLAKE2b-384 - 96 hex characters (mode 610, confidence 0.7)
    let blake2b384 = HashPattern::new(
        "BLAKE2b-384".to_string(),
        r"^[a-fA-F0-9]{96}$",
        Some(610),
        Some("BLAKE2b-384".to_string()),
        HashCategory::Modern,
        "BLAKE2b-384 hash".to_string(),
        0.7,
        false,
    )?;

    // BLAKE2b-512 - 128 hex characters (mode 620, confidence 0.7)
    let blake2b512 = HashPattern::new(
        "BLAKE2b-512".to_string(),
        r"^[a-fA-F0-9]{128}$",
        Some(620),
        Some("BLAKE2b-512".to_string()),
        HashCategory::Modern,
        "BLAKE2b-512 hash".to_string(),
        0.7,
        false,
    )?;

    // GOST R 34.11-94 - 64 hex characters (mode 6900, confidence 0.5)
    let gost = HashPattern::new(
        "GOST R 34.11-94".to_string(),
        r"^[a-fA-F0-9]{64}$",
        Some(6900),
        Some("GOST".to_string()),
        HashCategory::Basic,
        "GOST R 34.11-94 hash".to_string(),
        0.5,
        false,
    )?;

    // GOST R 34.11-2012 (Streebog) 256-bit - 64 hex characters (mode 11700, confidence 0.5)
    let gost2012_256 = HashPattern::new(
        "GOST R 34.11-2012 (256-bit)".to_string(),
        r"^[a-fA-F0-9]{64}$",
        Some(11700),
        Some("GOST2012-256".to_string()),
        HashCategory::Modern,
        "GOST R 34.11-2012 Streebog 256-bit".to_string(),
        0.5,
        false,
    )?;

    // GOST R 34.11-2012 (Streebog) 512-bit - 128 hex characters (mode 11800, confidence 0.5)
    let gost2012_512 = HashPattern::new(
        "GOST R 34.11-2012 (512-bit)".to_string(),
        r"^[a-fA-F0-9]{128}$",
        Some(11800),
        Some("GOST2012-512".to_string()),
        HashCategory::Modern,
        "GOST R 34.11-2012 Streebog 512-bit".to_string(),
        0.5,
        false,
    )?;

    // SHA3-224 - 56 hex characters (mode 17300, confidence 0.8)
    let sha3_224 = HashPattern::new(
        "SHA3-224".to_string(),
        r"^[a-fA-F0-9]{56}$",
        Some(17300),
        Some("SHA3-224".to_string()),
        HashCategory::Modern,
        "SHA3-224 hash".to_string(),
        0.8,
        false,
    )?;

    // SHA3-256 - 64 hex characters (mode 17400, confidence 0.8)
    let sha3_256 = HashPattern::new(
        "SHA3-256".to_string(),
        r"^[a-fA-F0-9]{64}$",
        Some(17400),
        Some("SHA3-256".to_string()),
        HashCategory::Modern,
        "SHA3-256 hash".to_string(),
        0.8,
        false,
    )?;

    // SHA3-384 - 96 hex characters (mode 17500, confidence 0.8)
    let sha3_384 = HashPattern::new(
        "SHA3-384".to_string(),
        r"^[a-fA-F0-9]{96}$",
        Some(17500),
        Some("SHA3-384".to_string()),
        HashCategory::Modern,
        "SHA3-384 hash".to_string(),
        0.8,
        false,
    )?;

    // SHA3-512 - 128 hex characters (mode 17600, confidence 0.8)
    let sha3_512 = HashPattern::new(
        "SHA3-512".to_string(),
        r"^[a-fA-F0-9]{128}$",
        Some(17600),
        Some("SHA3-512".to_string()),
        HashCategory::Modern,
        "SHA3-512 hash".to_string(),
        0.8,
        false,
    )?;

    // Add all patterns to registry
    registry.add_pattern(md5);
    registry.add_pattern(md5_half);
    registry.add_pattern(ntlm);
    registry.add_pattern(md4);
    registry.add_pattern(lm);
    registry.add_pattern(sha1);
    registry.add_pattern(sha224);
    registry.add_pattern(sha256);
    registry.add_pattern(sha384);
    registry.add_pattern(sha512);
    registry.add_pattern(sha1_salt);
    registry.add_pattern(sha256_salt);
    registry.add_pattern(md5_salt);
    registry.add_pattern(md2);
    registry.add_pattern(ripemd128);
    registry.add_pattern(ripemd160);
    registry.add_pattern(ripemd256);
    registry.add_pattern(ripemd320);
    registry.add_pattern(whirlpool);
    registry.add_pattern(tiger128);
    registry.add_pattern(tiger160);
    registry.add_pattern(tiger192);
    registry.add_pattern(blake2b256);
    registry.add_pattern(blake2b384);
    registry.add_pattern(blake2b512);
    registry.add_pattern(gost);
    registry.add_pattern(gost2012_256);
    registry.add_pattern(gost2012_512);
    registry.add_pattern(sha3_224);
    registry.add_pattern(sha3_256);
    registry.add_pattern(sha3_384);
    registry.add_pattern(sha3_512);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_patterns() {
        let mut registry = PatternRegistry::new();
        assert!(load_patterns(&mut registry).is_ok());
        assert!(!registry.patterns().is_empty());
    }

    #[test]
    fn test_md5_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Valid MD5 hashes
        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c592");
        assert!(!matches.is_empty());

        let matches = registry.find_matches("098f6bcd4621d373cade4e832627b4f6");
        assert!(!matches.is_empty());

        // Invalid cases
        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c59"); // too short
        assert!(matches.is_empty());

        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c592a"); // too long
        assert!(matches.is_empty());

        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c59G"); // invalid hex
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sha1_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Valid SHA1 hashes
        let matches = registry.find_matches("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        assert!(!matches.is_empty());

        let matches = registry.find_matches("356a192b7913b04c54574d18c28d46e6395428ab");
        assert!(!matches.is_empty());

        // Invalid cases
        let matches = registry.find_matches("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434"); // too short
        assert!(matches.is_empty());

        let matches = registry.find_matches("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434da"); // too long
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sha256_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Valid SHA256 hash
        let matches = registry.find_matches("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(!matches.is_empty());

        // Invalid cases
        let matches = registry.find_matches("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"); // too short
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sha384_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Valid SHA384 hash (96 hex chars)
        let matches = registry.find_matches("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        assert!(!matches.is_empty());

        // Too short
        let matches = registry.find_matches("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sha512_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Valid SHA512 hash (128 hex chars)
        let matches = registry.find_matches("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        assert!(!matches.is_empty());

        // Too short
        let matches = registry.find_matches("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ntlm_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Valid NTLM hash (same format as MD5, but different semantic meaning)
        let matches = registry.find_matches("b4b9b02e6f09a9bd760f388b67351e2b");
        assert!(!matches.is_empty());

        // Should match multiple patterns (MD5, NTLM, MD4, LM) due to same format
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_salted_hashes() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Valid salted SHA1
        let matches = registry.find_matches("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d:salt");
        assert!(!matches.is_empty());
        let salted_pattern = matches.iter().find(|p| p.name == "SHA1(Salt)");
        assert!(salted_pattern.is_some());
        assert!(salted_pattern.unwrap().requires_salt_check);

        // Valid salted SHA256
        let matches = registry.find_matches("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:mysalt123");
        assert!(!matches.is_empty());
        let salted_pattern = matches.iter().find(|p| p.name == "SHA256(Salt)");
        assert!(salted_pattern.is_some());

        // Valid salted MD5
        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c592:salt123");
        assert!(!matches.is_empty());
        let salted_pattern = matches.iter().find(|p| p.name == "MD5(Salt)");
        assert!(salted_pattern.is_some());

        // Invalid - no salt part
        let matches = registry.find_matches("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d:");
        assert!(matches.is_empty() || !matches.iter().any(|p| p.requires_salt_check));
    }

    #[test]
    fn test_confidence_levels() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        let patterns = registry.patterns();

        // Find specific patterns and verify their confidence levels
        let sha512 = patterns.iter().find(|p| p.name == "SHA512").unwrap();
        assert_eq!(sha512.base_confidence, 0.9);

        let sha384 = patterns.iter().find(|p| p.name == "SHA384").unwrap();
        assert_eq!(sha384.base_confidence, 0.9);

        let sha224 = patterns.iter().find(|p| p.name == "SHA224").unwrap();
        assert_eq!(sha224.base_confidence, 0.85);

        let sha1 = patterns.iter().find(|p| p.name == "SHA1").unwrap();
        assert_eq!(sha1.base_confidence, 0.8);

        let sha256 = patterns.iter().find(|p| p.name == "SHA256").unwrap();
        assert_eq!(sha256.base_confidence, 0.8);

        let md5 = patterns.iter().find(|p| p.name == "MD5").unwrap();
        assert_eq!(md5.base_confidence, 0.6);

        let ntlm = patterns.iter().find(|p| p.name == "NTLM").unwrap();
        assert_eq!(ntlm.base_confidence, 0.5);

        let md4 = patterns.iter().find(|p| p.name == "MD4").unwrap();
        assert_eq!(md4.base_confidence, 0.4);

        let lm = patterns.iter().find(|p| p.name == "LM").unwrap();
        assert_eq!(lm.base_confidence, 0.3);
    }

    #[test]
    fn test_hashcat_modes() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        let patterns = registry.patterns();

        let md5 = patterns.iter().find(|p| p.name == "MD5").unwrap();
        assert_eq!(md5.hashcat_mode, Some(0));

        let sha1 = patterns.iter().find(|p| p.name == "SHA1").unwrap();
        assert_eq!(sha1.hashcat_mode, Some(100));

        let ntlm = patterns.iter().find(|p| p.name == "NTLM").unwrap();
        assert_eq!(ntlm.hashcat_mode, Some(1000));

        let sha256 = patterns.iter().find(|p| p.name == "SHA256").unwrap();
        assert_eq!(sha256.hashcat_mode, Some(1400));

        let sha512 = patterns.iter().find(|p| p.name == "SHA512").unwrap();
        assert_eq!(sha512.hashcat_mode, Some(1700));
    }

    #[test]
    fn test_john_formats() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        let patterns = registry.patterns();

        let md5 = patterns.iter().find(|p| p.name == "MD5").unwrap();
        assert_eq!(md5.john_format, Some("Raw-MD5".to_string()));

        let sha1 = patterns.iter().find(|p| p.name == "SHA1").unwrap();
        assert_eq!(sha1.john_format, Some("Raw-SHA1".to_string()));

        let ntlm = patterns.iter().find(|p| p.name == "NTLM").unwrap();
        assert_eq!(ntlm.john_format, Some("NT".to_string()));
    }

    #[test]
    fn test_categories() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        let patterns = registry.patterns();

        let md5 = patterns.iter().find(|p| p.name == "MD5").unwrap();
        assert_eq!(md5.category, HashCategory::Basic);

        let lm = patterns.iter().find(|p| p.name == "LM").unwrap();
        assert_eq!(lm.category, HashCategory::Legacy);
    }

    #[test]
    fn test_edge_cases() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Empty string
        let matches = registry.find_matches("");
        assert!(matches.is_empty());

        // Mixed case hex (should work)
        let matches = registry.find_matches("5D41402ABC4B2A76B9719D911017C592");
        assert!(!matches.is_empty());

        // Lowercase hex (should work)
        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c592");
        assert!(!matches.is_empty());

        // Invalid characters
        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c59Z");
        assert!(matches.is_empty());

        // Exactly wrong length
        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c59");  // 31 chars instead of 32
        assert!(matches.is_empty());
    }
}