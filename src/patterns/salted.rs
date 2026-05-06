//! Salted hash patterns
//!
//! This module implements patterns for salted hash variants commonly used
//! in web applications, databases, and authentication systems.

use crate::{
    Result,
    pattern::{HashPattern, PatternRegistry},
    types::HashCategory,
};

/// Load salted hash patterns into the registry
pub fn load_patterns(registry: &mut PatternRegistry) -> Result<()> {
    // md5($pass.$salt) - mode 10
    let md5_pass_salt = HashPattern::new(
        "md5($pass.$salt)".to_string(),
        r"^[a-fA-F0-9]{32}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(10),
        Some("Raw-MD5".to_string()),
        HashCategory::Salted,
        "MD5 hash with salt appended".to_string(),
        0.7,
        true,
    )?;

    // md5($salt.$pass) - mode 20
    let md5_salt_pass = HashPattern::new(
        "md5($salt.$pass)".to_string(),
        r"^[a-fA-F0-9]{32}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(20),
        Some("Raw-MD5".to_string()),
        HashCategory::Salted,
        "MD5 hash with salt prepended".to_string(),
        0.7,
        true,
    )?;

    // md5(unicode($pass).$salt) - mode 30
    let md5_unicode_pass_salt = HashPattern::new(
        "md5(unicode($pass).$salt)".to_string(),
        r"^[a-fA-F0-9]{32}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(30),
        Some("Raw-MD5".to_string()),
        HashCategory::Salted,
        "MD5 hash with unicode password and salt".to_string(),
        0.6,
        true,
    )?;

    // md5($salt.unicode($pass)) - mode 40
    let md5_salt_unicode_pass = HashPattern::new(
        "md5($salt.unicode($pass))".to_string(),
        r"^[a-fA-F0-9]{32}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(40),
        Some("Raw-MD5".to_string()),
        HashCategory::Salted,
        "MD5 hash with salt and unicode password".to_string(),
        0.6,
        true,
    )?;

    // HMAC-MD5 (key = $pass) - mode 50
    let hmac_md5_pass = HashPattern::new(
        "HMAC-MD5 (key = $pass)".to_string(),
        r"^[a-fA-F0-9]{32}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(50),
        Some("HMAC-MD5".to_string()),
        HashCategory::Salted,
        "HMAC-MD5 with password as key".to_string(),
        0.7,
        true,
    )?;

    // HMAC-MD5 (key = $salt) - mode 60
    let hmac_md5_salt = HashPattern::new(
        "HMAC-MD5 (key = $salt)".to_string(),
        r"^[a-fA-F0-9]{32}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(60),
        Some("HMAC-MD5".to_string()),
        HashCategory::Salted,
        "HMAC-MD5 with salt as key".to_string(),
        0.7,
        true,
    )?;

    // sha1($pass.$salt) - mode 110
    let sha1_pass_salt = HashPattern::new(
        "sha1($pass.$salt)".to_string(),
        r"^[a-fA-F0-9]{40}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(110),
        Some("Raw-SHA1".to_string()),
        HashCategory::Salted,
        "SHA1 hash with salt appended".to_string(),
        0.8,
        true,
    )?;

    // sha1($salt.$pass) - mode 120
    let sha1_salt_pass = HashPattern::new(
        "sha1($salt.$pass)".to_string(),
        r"^[a-fA-F0-9]{40}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(120),
        Some("Raw-SHA1".to_string()),
        HashCategory::Salted,
        "SHA1 hash with salt prepended".to_string(),
        0.8,
        true,
    )?;

    // sha1(unicode($pass).$salt) - mode 130
    let sha1_unicode_pass_salt = HashPattern::new(
        "sha1(unicode($pass).$salt)".to_string(),
        r"^[a-fA-F0-9]{40}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(130),
        Some("Raw-SHA1".to_string()),
        HashCategory::Salted,
        "SHA1 hash with unicode password and salt".to_string(),
        0.7,
        true,
    )?;

    // sha1($salt.unicode($pass)) - mode 140
    let sha1_salt_unicode_pass = HashPattern::new(
        "sha1($salt.unicode($pass))".to_string(),
        r"^[a-fA-F0-9]{40}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(140),
        Some("Raw-SHA1".to_string()),
        HashCategory::Salted,
        "SHA1 hash with salt and unicode password".to_string(),
        0.7,
        true,
    )?;

    // HMAC-SHA1 (key = $pass) - mode 150
    let hmac_sha1_pass = HashPattern::new(
        "HMAC-SHA1 (key = $pass)".to_string(),
        r"^[a-fA-F0-9]{40}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(150),
        Some("HMAC-SHA1".to_string()),
        HashCategory::Salted,
        "HMAC-SHA1 with password as key".to_string(),
        0.8,
        true,
    )?;

    // HMAC-SHA1 (key = $salt) - mode 160
    let hmac_sha1_salt = HashPattern::new(
        "HMAC-SHA1 (key = $salt)".to_string(),
        r"^[a-fA-F0-9]{40}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(160),
        Some("HMAC-SHA1".to_string()),
        HashCategory::Salted,
        "HMAC-SHA1 with salt as key".to_string(),
        0.8,
        true,
    )?;

    // sha256($pass.$salt) - mode 1410
    let sha256_pass_salt = HashPattern::new(
        "sha256($pass.$salt)".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1410),
        Some("Raw-SHA256".to_string()),
        HashCategory::Salted,
        "SHA256 hash with salt appended".to_string(),
        0.8,
        true,
    )?;

    // sha256($salt.$pass) - mode 1420
    let sha256_salt_pass = HashPattern::new(
        "sha256($salt.$pass)".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1420),
        Some("Raw-SHA256".to_string()),
        HashCategory::Salted,
        "SHA256 hash with salt prepended".to_string(),
        0.8,
        true,
    )?;

    // sha256(unicode($pass).$salt) - mode 1430
    let sha256_unicode_pass_salt = HashPattern::new(
        "sha256(unicode($pass).$salt)".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1430),
        Some("Raw-SHA256".to_string()),
        HashCategory::Salted,
        "SHA256 hash with unicode password and salt".to_string(),
        0.7,
        true,
    )?;

    // sha256($salt.unicode($pass)) - mode 1440
    let sha256_salt_unicode_pass = HashPattern::new(
        "sha256($salt.unicode($pass))".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1440),
        Some("Raw-SHA256".to_string()),
        HashCategory::Salted,
        "SHA256 hash with salt and unicode password".to_string(),
        0.7,
        true,
    )?;

    // HMAC-SHA256 (key = $pass) - mode 1450
    let hmac_sha256_pass = HashPattern::new(
        "HMAC-SHA256 (key = $pass)".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1450),
        Some("HMAC-SHA256".to_string()),
        HashCategory::Salted,
        "HMAC-SHA256 with password as key".to_string(),
        0.8,
        true,
    )?;

    // HMAC-SHA256 (key = $salt) - mode 1460
    let hmac_sha256_salt = HashPattern::new(
        "HMAC-SHA256 (key = $salt)".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1460),
        Some("HMAC-SHA256".to_string()),
        HashCategory::Salted,
        "HMAC-SHA256 with salt as key".to_string(),
        0.8,
        true,
    )?;

    // sha512($pass.$salt) - mode 1710
    let sha512_pass_salt = HashPattern::new(
        "sha512($pass.$salt)".to_string(),
        r"^[a-fA-F0-9]{128}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1710),
        Some("Raw-SHA512".to_string()),
        HashCategory::Salted,
        "SHA512 hash with salt appended".to_string(),
        0.8,
        true,
    )?;

    // sha512($salt.$pass) - mode 1720
    let sha512_salt_pass = HashPattern::new(
        "sha512($salt.$pass)".to_string(),
        r"^[a-fA-F0-9]{128}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1720),
        Some("Raw-SHA512".to_string()),
        HashCategory::Salted,
        "SHA512 hash with salt prepended".to_string(),
        0.8,
        true,
    )?;

    // sha512(unicode($pass).$salt) - mode 1730
    let sha512_unicode_pass_salt = HashPattern::new(
        "sha512(unicode($pass).$salt)".to_string(),
        r"^[a-fA-F0-9]{128}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1730),
        Some("Raw-SHA512".to_string()),
        HashCategory::Salted,
        "SHA512 hash with unicode password and salt".to_string(),
        0.7,
        true,
    )?;

    // sha512($salt.unicode($pass)) - mode 1740
    let sha512_salt_unicode_pass = HashPattern::new(
        "sha512($salt.unicode($pass))".to_string(),
        r"^[a-fA-F0-9]{128}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1740),
        Some("Raw-SHA512".to_string()),
        HashCategory::Salted,
        "SHA512 hash with salt and unicode password".to_string(),
        0.7,
        true,
    )?;

    // HMAC-SHA512 (key = $pass) - mode 1750
    let hmac_sha512_pass = HashPattern::new(
        "HMAC-SHA512 (key = $pass)".to_string(),
        r"^[a-fA-F0-9]{128}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1750),
        Some("HMAC-SHA512".to_string()),
        HashCategory::Salted,
        "HMAC-SHA512 with password as key".to_string(),
        0.8,
        true,
    )?;

    // HMAC-SHA512 (key = $salt) - mode 1760
    let hmac_sha512_salt = HashPattern::new(
        "HMAC-SHA512 (key = $salt)".to_string(),
        r"^[a-fA-F0-9]{128}:[a-fA-F0-9A-Za-z./]{1,}$",
        Some(1760),
        Some("HMAC-SHA512".to_string()),
        HashCategory::Salted,
        "HMAC-SHA512 with salt as key".to_string(),
        0.8,
        true,
    )?;

    // Add all patterns to registry
    registry.add_pattern(md5_pass_salt);
    registry.add_pattern(md5_salt_pass);
    registry.add_pattern(md5_unicode_pass_salt);
    registry.add_pattern(md5_salt_unicode_pass);
    registry.add_pattern(hmac_md5_pass);
    registry.add_pattern(hmac_md5_salt);
    registry.add_pattern(sha1_pass_salt);
    registry.add_pattern(sha1_salt_pass);
    registry.add_pattern(sha1_unicode_pass_salt);
    registry.add_pattern(sha1_salt_unicode_pass);
    registry.add_pattern(hmac_sha1_pass);
    registry.add_pattern(hmac_sha1_salt);
    registry.add_pattern(sha256_pass_salt);
    registry.add_pattern(sha256_salt_pass);
    registry.add_pattern(sha256_unicode_pass_salt);
    registry.add_pattern(sha256_salt_unicode_pass);
    registry.add_pattern(hmac_sha256_pass);
    registry.add_pattern(hmac_sha256_salt);
    registry.add_pattern(sha512_pass_salt);
    registry.add_pattern(sha512_salt_pass);
    registry.add_pattern(sha512_unicode_pass_salt);
    registry.add_pattern(sha512_salt_unicode_pass);
    registry.add_pattern(hmac_sha512_pass);
    registry.add_pattern(hmac_sha512_salt);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_salted_patterns() {
        let mut registry = PatternRegistry::new();
        assert!(load_patterns(&mut registry).is_ok());
        assert!(!registry.patterns().is_empty());
    }

    #[test]
    fn test_md5_salt_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test md5($pass.$salt) format
        let matches = registry.find_matches("5d41402abc4b2a76b9719d911017c592:hello".to_string());
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_sha1_salt_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test sha1($pass.$salt) format
        let matches = registry.find_matches("356a192b7913b04c54574d18c28d46e6395428ab:salt".to_string());
        assert!(!matches.is_empty());
    }
}