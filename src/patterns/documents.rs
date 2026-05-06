//! Document and archive hash patterns
//!
//! This module implements patterns for password-protected documents and archives
//! including PDF, Microsoft Office, ZIP, 7-Zip, RAR, and other container formats.

use crate::{
    Result,
    pattern::{HashPattern, PatternRegistry},
    types::HashCategory,
};

/// Load document and archive hash patterns into the registry
pub fn load_patterns(registry: &mut PatternRegistry) -> Result<()> {
    // PDF 1.1 - 1.3 (Acrobat 2 - 4) - mode 10400
    let pdf_1_1_1_3 = HashPattern::new(
        "PDF 1.1 - 1.3 (Acrobat 2 - 4)".to_string(),
        r"^\$pdf\$1\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(10400),
        Some("pdf".to_string()),
        HashCategory::Document,
        "PDF 1.1-1.3 password hash".to_string(),
        0.9,
        true,
    )?;

    // PDF 1.4 - 1.6 (Acrobat 5 - 8) - mode 10410
    let pdf_1_4_1_6 = HashPattern::new(
        "PDF 1.4 - 1.6 (Acrobat 5 - 8)".to_string(),
        r"^\$pdf\$2\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(10410),
        Some("pdf".to_string()),
        HashCategory::Document,
        "PDF 1.4-1.6 password hash".to_string(),
        0.9,
        true,
    )?;

    // PDF 1.7 Level 3 (Acrobat 9) - mode 10420
    let pdf_1_7 = HashPattern::new(
        "PDF 1.7 Level 3 (Acrobat 9)".to_string(),
        r"^\$pdf\$5\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(10420),
        Some("pdf".to_string()),
        HashCategory::Document,
        "PDF 1.7 Level 3 password hash".to_string(),
        0.95,
        true,
    )?;

    // MS Office 2007 - mode 9400
    let ms_office_2007 = HashPattern::new(
        "MS Office 2007".to_string(),
        r"^\$office\$\*2007\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(9400),
        Some("office".to_string()),
        HashCategory::Document,
        "MS Office 2007 password hash".to_string(),
        0.95,
        true,
    )?;

    // MS Office 2010 - mode 9500
    let ms_office_2010 = HashPattern::new(
        "MS Office 2010".to_string(),
        r"^\$office\$\*2010\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(9500),
        Some("office".to_string()),
        HashCategory::Document,
        "MS Office 2010 password hash".to_string(),
        0.95,
        true,
    )?;

    // MS Office 2013 - mode 9600
    let ms_office_2013 = HashPattern::new(
        "MS Office 2013".to_string(),
        r"^\$office\$\*2013\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(9600),
        Some("office".to_string()),
        HashCategory::Document,
        "MS Office 2013 password hash".to_string(),
        0.95,
        true,
    )?;

    // MS Office ≤ 2003 $0 - mode 9700
    let ms_office_old_0 = HashPattern::new(
        "MS Office ≤ 2003 $0".to_string(),
        r"^\$oldoffice\$0\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(9700),
        Some("oldoffice".to_string()),
        HashCategory::Document,
        "MS Office ≤2003 MD5+RC4 hash".to_string(),
        0.9,
        true,
    )?;

    // MS Office ≤ 2003 $1 - mode 9710
    let ms_office_old_1 = HashPattern::new(
        "MS Office ≤ 2003 $1".to_string(),
        r"^\$oldoffice\$1\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(9710),
        Some("oldoffice".to_string()),
        HashCategory::Document,
        "MS Office ≤2003 MD5+RC4 hash".to_string(),
        0.9,
        true,
    )?;

    // MS Office ≤ 2003 $3 - mode 9720
    let ms_office_old_3 = HashPattern::new(
        "MS Office ≤ 2003 $3".to_string(),
        r"^\$oldoffice\$3\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(9720),
        Some("oldoffice".to_string()),
        HashCategory::Document,
        "MS Office ≤2003 SHA1+RC4 hash".to_string(),
        0.9,
        true,
    )?;

    // MS Office ≤ 2003 $4 - mode 9810
    let ms_office_old_4 = HashPattern::new(
        "MS Office ≤ 2003 $4".to_string(),
        r"^\$oldoffice\$4\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(9810),
        Some("oldoffice".to_string()),
        HashCategory::Document,
        "MS Office ≤2003 SHA1+RC4 hash".to_string(),
        0.9,
        true,
    )?;

    // ZIP (WinZip) - mode 13600
    let winzip = HashPattern::new(
        "WinZip".to_string(),
        r"^\$zip2\$\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9A-Za-z+/=]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(13600),
        Some("zip".to_string()),
        HashCategory::Archive,
        "WinZip encrypted archive".to_string(),
        0.95,
        true,
    )?;

    // 7-Zip - mode 11600
    let sevenzip = HashPattern::new(
        "7-Zip".to_string(),
        r"^\$7z\$[0-9]+\$[0-9]+\$[0-9]+\$[a-fA-F0-9]+\$[0-9]+\$[a-fA-F0-9]+\$[0-9]+\$[a-fA-F0-9]+\$[0-9]+\$[a-fA-F0-9]+$",
        Some(11600),
        Some("7z".to_string()),
        HashCategory::Archive,
        "7-Zip encrypted archive".to_string(),
        0.95,
        true,
    )?;

    // RAR3-hp - mode 12500
    let rar3 = HashPattern::new(
        "RAR3-hp".to_string(),
        r"^\$RAR3\$\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(12500),
        Some("rar".to_string()),
        HashCategory::Archive,
        "RAR3 encrypted archive".to_string(),
        0.9,
        true,
    )?;

    // RAR5 - mode 13000
    let rar5 = HashPattern::new(
        "RAR5".to_string(),
        r"^\$rar5\$16\$[a-fA-F0-9]{32}\$15\$[a-fA-F0-9]{30}\$8\$[a-fA-F0-9]{16}$",
        Some(13000),
        Some("rar".to_string()),
        HashCategory::Archive,
        "RAR5 encrypted archive".to_string(),
        0.95,
        true,
    )?;

    // AxCrypt - mode 13200
    let axcrypt = HashPattern::new(
        "AxCrypt".to_string(),
        r"^\$axcrypt\$\*[0-9]+\*[a-fA-F0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(13200),
        Some("axcrypt".to_string()),
        HashCategory::Document,
        "AxCrypt encrypted file".to_string(),
        0.9,
        true,
    )?;

    // AxCrypt in memory SHA1 - mode 13300
    let axcrypt_sha1 = HashPattern::new(
        "AxCrypt in memory SHA1".to_string(),
        r"^\$axcrypt_sha1\$[a-fA-F0-9]{40}$",
        Some(13300),
        Some("axcrypt".to_string()),
        HashCategory::Document,
        "AxCrypt in-memory SHA1".to_string(),
        0.8,
        false,
    )?;

    // Apple Secure Notes - mode 16200
    let apple_secure_notes = HashPattern::new(
        "Apple Secure Notes".to_string(),
        r"^\$ASN\$\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(16200),
        Some("apple-secure-notes".to_string()),
        HashCategory::Document,
        "Apple Secure Notes hash".to_string(),
        0.9,
        true,
    )?;

    // Ethereum Wallet, PBKDF2-HMAC-SHA256 - mode 15700
    let ethereum_pbkdf2 = HashPattern::new(
        "Ethereum Wallet, PBKDF2-HMAC-SHA256".to_string(),
        r"^\$ethereum\$p\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(15700),
        Some("ethereum".to_string()),
        HashCategory::Cryptocurrency,
        "Ethereum PBKDF2 wallet".to_string(),
        0.9,
        true,
    )?;

    // Ethereum Wallet, scrypt - mode 15800
    let ethereum_scrypt = HashPattern::new(
        "Ethereum Wallet, scrypt".to_string(),
        r"^\$ethereum\$s\*[0-9]+\*[0-9]+\*[0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(15800),
        Some("ethereum".to_string()),
        HashCategory::Cryptocurrency,
        "Ethereum scrypt wallet".to_string(),
        0.9,
        true,
    )?;

    // Bitcoin/Litecoin wallet.dat - mode 11300
    let bitcoin_wallet = HashPattern::new(
        "Bitcoin/Litecoin wallet.dat".to_string(),
        r"^\$bitcoin\$[0-9]+\$[a-fA-F0-9]+\$[0-9]+\$[a-fA-F0-9]+\$[0-9]+\$[0-9]+\$[a-fA-F0-9]+\$[0-9]+\$[a-fA-F0-9]+$",
        Some(11300),
        Some("bitcoin".to_string()),
        HashCategory::Cryptocurrency,
        "Bitcoin/Litecoin wallet".to_string(),
        0.95,
        true,
    )?;

    // Electrum Wallet (Salt-Type 1-3) - mode 12700
    let electrum_wallet = HashPattern::new(
        "Electrum Wallet (Salt-Type 1-3)".to_string(),
        r"^\$electrum\$[1-3]\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(12700),
        Some("electrum".to_string()),
        HashCategory::Cryptocurrency,
        "Electrum wallet hash".to_string(),
        0.9,
        true,
    )?;

    // Electrum Wallet (Salt-Type 4) - mode 21700
    let electrum_wallet_v4 = HashPattern::new(
        "Electrum Wallet (Salt-Type 4)".to_string(),
        r"^\$electrum\$4\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$",
        Some(21700),
        Some("electrum".to_string()),
        HashCategory::Cryptocurrency,
        "Electrum wallet v4 hash".to_string(),
        0.9,
        true,
    )?;

    // TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit - mode 6211
    let truecrypt_ripemd160_xts_512 = HashPattern::new(
        "TrueCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit".to_string(),
        r"^\$truecrypt\$[a-fA-F0-9]{512}$",
        Some(6211),
        Some("truecrypt".to_string()),
        HashCategory::Encryption,
        "TrueCrypt RIPEMD160 XTS 512-bit".to_string(),
        0.8,
        false,
    )?;

    // TrueCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit - mode 6212
    let truecrypt_sha512_xts_512 = HashPattern::new(
        "TrueCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit".to_string(),
        r"^\$truecrypt\$[a-fA-F0-9]{512}$",
        Some(6212),
        Some("truecrypt".to_string()),
        HashCategory::Encryption,
        "TrueCrypt SHA512 XTS 512-bit".to_string(),
        0.8,
        false,
    )?;

    // TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit - mode 6213
    let truecrypt_whirlpool_xts_512 = HashPattern::new(
        "TrueCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit".to_string(),
        r"^\$truecrypt\$[a-fA-F0-9]{512}$",
        Some(6213),
        Some("truecrypt".to_string()),
        HashCategory::Encryption,
        "TrueCrypt Whirlpool XTS 512-bit".to_string(),
        0.8,
        false,
    )?;

    // VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit - mode 13711
    let veracrypt_ripemd160_xts_512 = HashPattern::new(
        "VeraCrypt PBKDF2-HMAC-RIPEMD160 + XTS 512 bit".to_string(),
        r"^\$veracrypt\$[a-fA-F0-9]{512}$",
        Some(13711),
        Some("veracrypt".to_string()),
        HashCategory::Encryption,
        "VeraCrypt RIPEMD160 XTS 512-bit".to_string(),
        0.8,
        false,
    )?;

    // VeraCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit - mode 13712
    let veracrypt_sha512_xts_512 = HashPattern::new(
        "VeraCrypt PBKDF2-HMAC-SHA512 + XTS 512 bit".to_string(),
        r"^\$veracrypt\$[a-fA-F0-9]{512}$",
        Some(13712),
        Some("veracrypt".to_string()),
        HashCategory::Encryption,
        "VeraCrypt SHA512 XTS 512-bit".to_string(),
        0.8,
        false,
    )?;

    // VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit - mode 13713
    let veracrypt_whirlpool_xts_512 = HashPattern::new(
        "VeraCrypt PBKDF2-HMAC-Whirlpool + XTS 512 bit".to_string(),
        r"^\$veracrypt\$[a-fA-F0-9]{512}$",
        Some(13713),
        Some("veracrypt".to_string()),
        HashCategory::Encryption,
        "VeraCrypt Whirlpool XTS 512-bit".to_string(),
        0.8,
        false,
    )?;

    // Add all patterns to registry
    registry.add_pattern(pdf_1_1_1_3);
    registry.add_pattern(pdf_1_4_1_6);
    registry.add_pattern(pdf_1_7);
    registry.add_pattern(ms_office_2007);
    registry.add_pattern(ms_office_2010);
    registry.add_pattern(ms_office_2013);
    registry.add_pattern(ms_office_old_0);
    registry.add_pattern(ms_office_old_1);
    registry.add_pattern(ms_office_old_3);
    registry.add_pattern(ms_office_old_4);
    registry.add_pattern(winzip);
    registry.add_pattern(sevenzip);
    registry.add_pattern(rar3);
    registry.add_pattern(rar5);
    registry.add_pattern(axcrypt);
    registry.add_pattern(axcrypt_sha1);
    registry.add_pattern(apple_secure_notes);
    registry.add_pattern(ethereum_pbkdf2);
    registry.add_pattern(ethereum_scrypt);
    registry.add_pattern(bitcoin_wallet);
    registry.add_pattern(electrum_wallet);
    registry.add_pattern(electrum_wallet_v4);
    registry.add_pattern(truecrypt_ripemd160_xts_512);
    registry.add_pattern(truecrypt_sha512_xts_512);
    registry.add_pattern(truecrypt_whirlpool_xts_512);
    registry.add_pattern(veracrypt_ripemd160_xts_512);
    registry.add_pattern(veracrypt_sha512_xts_512);
    registry.add_pattern(veracrypt_whirlpool_xts_512);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_document_patterns() {
        let mut registry = PatternRegistry::new();
        assert!(load_patterns(&mut registry).is_ok());
        assert!(!registry.patterns().is_empty());
    }

    #[test]
    fn test_pdf_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test PDF pattern formats
        let test_cases = vec![
            ("$pdf$1*2*40*-1*0*16*01234567890123456789012345678901*32*0123456789012345678901234567890123456789012345678901234567890123*32*0123456789012345678901234567890123456789012345678901234567890123", "PDF 1.1 - 1.3 (Acrobat 2 - 4)".to_string()),
            ("$pdf$2*3*128*-1028*1*16*01234567890123456789012345678901*32*0123456789012345678901234567890123456789012345678901234567890123*32*0123456789012345678901234567890123456789012345678901234567890123", "PDF 1.4 - 1.6 (Acrobat 5 - 8)".to_string()),
        ];

        for (hash, expected_name) in test_cases {
            let matches = registry.find_matches(hash);
            let pdf_match = matches.iter().find(|p| p.name == expected_name);
            assert!(pdf_match.is_some(), "Should match {} for hash: {}", expected_name, hash);
        }
    }

    #[test]
    fn test_office_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test MS Office pattern formats
        let test_cases = vec![
            ("$office$*2007*20*128*16*salt*verifier*hash", "MS Office 2007".to_string()),
            ("$office$*2010*100000*128*16*salt*verifier*hash", "MS Office 2010".to_string()),
            ("$office$*2013*100000*256*16*salt*verifier*hash", "MS Office 2013".to_string()),
        ];

        for (hash, expected_name) in test_cases {
            let matches = registry.find_matches(hash);
            let office_match = matches.iter().find(|p| p.name == expected_name);
            assert!(office_match.is_some(), "Should match {} for hash: {}", expected_name, hash);
        }
    }

    #[test]
    fn test_archive_patterns() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test archive pattern formats
        let test_cases = vec![
            ("$zip2$*0*1*0*hash*salt*$/zip2$", "WinZip".to_string()),
            ("$7z$0$19$0$salt$8$hash$16$data$8$hash", "7-Zip".to_string()),
            ("$RAR3$*0*hash*salt", "RAR3-hp".to_string()),
        ];

        for (hash, expected_name) in test_cases {
            let matches = registry.find_matches(hash);
            let archive_match = matches.iter().find(|p| p.name == expected_name);
            assert!(archive_match.is_some(), "Should match {} for hash: {}", expected_name, hash);
        }
    }
}