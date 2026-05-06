//! Application-specific hash patterns
//!
//! This module implements patterns for hash formats used by specific applications,
//! including web frameworks, databases, content management systems, and operating systems.

use crate::{
    Result,
    pattern::{HashPattern, PatternRegistry},
    types::HashCategory,
};

/// Load application-specific hash patterns into the registry
pub fn load_patterns(registry: &mut PatternRegistry) -> Result<()> {
    // phpBB3 (MD5) - mode 400
    let phpbb3 = HashPattern::new(
        "phpBB3 (MD5)".to_string(),
        r"^\$H\$[./0-9A-Za-z]{31}$",
        Some(400),
        Some("phpass".to_string()),
        HashCategory::Application,
        "phpBB3 MD5 hash".to_string(),
        0.9,
        false,
    )?;

    // md5crypt (Unix) - mode 500
    let md5crypt = HashPattern::new(
        "md5crypt (Unix)".to_string(),
        r"^\$1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{22}$",
        Some(500),
        Some("md5crypt".to_string()),
        HashCategory::Application,
        "Unix MD5 crypt hash".to_string(),
        0.95,
        true,
    )?;

    // Apache $apr1$ MD5 - mode 1600
    let apache_md5 = HashPattern::new(
        "Apache $apr1$ MD5".to_string(),
        r"^\$apr1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{22}$",
        Some(1600),
        Some("md5crypt".to_string()),
        HashCategory::Application,
        "Apache APR1 MD5 hash".to_string(),
        0.95,
        true,
    )?;

    // SHA-512 (Unix) - mode 1800
    let sha512crypt = HashPattern::new(
        "SHA-512 (Unix)".to_string(),
        r"^\$6\$[a-zA-Z0-9./]{0,16}\$[a-zA-Z0-9./]{86}$",
        Some(1800),
        Some("sha512crypt".to_string()),
        HashCategory::Application,
        "Unix SHA-512 crypt hash".to_string(),
        0.95,
        true,
    )?;

    // Domain Cached Credentials (DCC) - mode 1100
    let dcc = HashPattern::new(
        "Domain Cached Credentials (DCC)".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(1100),
        Some("mscash".to_string()),
        HashCategory::Application,
        "Windows DCC hash".to_string(),
        0.4,
        false,
    )?;

    // Domain Cached Credentials 2 (DCC2) - mode 2100
    let dcc2 = HashPattern::new(
        "Domain Cached Credentials 2 (DCC2)".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(2100),
        Some("mscash2".to_string()),
        HashCategory::Application,
        "Windows DCC2 hash".to_string(),
        0.4,
        false,
    )?;

    // bcrypt $2*$ Blowfish (Unix) - mode 3200
    let bcrypt = HashPattern::new(
        "bcrypt $2*$ Blowfish (Unix)".to_string(),
        r"^\$2[abyxz]?\$[0-9]{2}\$[a-zA-Z0-9./]{53}$",
        Some(3200),
        Some("bcrypt".to_string()),
        HashCategory::Application,
        "bcrypt hash".to_string(),
        0.98,
        true,
    )?;

    // Cisco-PIX MD5 - mode 2400
    let cisco_pix = HashPattern::new(
        "Cisco-PIX MD5".to_string(),
        r"^[a-fA-F0-9]{16}$",
        Some(2400),
        Some("pix-md5".to_string()),
        HashCategory::Application,
        "Cisco PIX MD5 hash".to_string(),
        0.8,
        false,
    )?;

    // Cisco-ASA MD5 - mode 2410
    let cisco_asa = HashPattern::new(
        "Cisco-ASA MD5".to_string(),
        r"^[a-zA-Z0-9./]{16}$",
        Some(2410),
        Some("asa-md5".to_string()),
        HashCategory::Application,
        "Cisco ASA MD5 hash".to_string(),
        0.8,
        false,
    )?;

    // WPA-EAPOL-PBKDF2 - mode 2500
    let wpa_eapol = HashPattern::new(
        "WPA-EAPOL-PBKDF2".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9]{64}:[a-fA-F0-9]{12}:[a-fA-F0-9]{12}",
        Some(2500),
        Some("wpapsk".to_string()),
        HashCategory::Application,
        "WPA/WPA2 PBKDF2 hash".to_string(),
        0.9,
        true,
    )?;

    // WPA-PMKID-PBKDF2 - mode 16800
    let wpa_pmkid = HashPattern::new(
        "WPA-PMKID-PBKDF2".to_string(),
        r"^[a-fA-F0-9]{32}\*[a-fA-F0-9]{12}\*[a-fA-F0-9]{12}\*[a-fA-F0-9]{64}",
        Some(16800),
        Some("wpapsk".to_string()),
        HashCategory::Application,
        "WPA/WPA2 PMKID hash".to_string(),
        0.95,
        true,
    )?;

    // MySQL323 - mode 200
    let mysql323 = HashPattern::new(
        "MySQL323".to_string(),
        r"^[a-fA-F0-9]{16}$",
        Some(200),
        Some("mysql".to_string()),
        HashCategory::Application,
        "MySQL 3.2.3 hash".to_string(),
        0.7,
        false,
    )?;

    // MySQL4.1/MySQL5 - mode 300
    let mysql41 = HashPattern::new(
        "MySQL4.1/MySQL5".to_string(),
        r"^\*[a-fA-F0-9]{40}$",
        Some(300),
        Some("mysql-sha1".to_string()),
        HashCategory::Application,
        "MySQL 4.1/5.x hash".to_string(),
        0.95,
        false,
    )?;

    // PostgreSQL - mode 12
    let postgresql = HashPattern::new(
        "PostgreSQL".to_string(),
        r"^[a-fA-F0-9]{32}$",
        Some(12),
        Some("postgres".to_string()),
        HashCategory::Application,
        "PostgreSQL hash".to_string(),
        0.4,
        false,
    )?;

    // MSSQL (2000) - mode 131
    let mssql2000 = HashPattern::new(
        "MSSQL (2000)".to_string(),
        r"^0x0100[a-fA-F0-9]{8}[a-fA-F0-9]{40}$",
        Some(131),
        Some("mssql".to_string()),
        HashCategory::Application,
        "Microsoft SQL Server 2000 hash".to_string(),
        0.9,
        true,
    )?;

    // MSSQL (2005) - mode 132
    let mssql2005 = HashPattern::new(
        "MSSQL (2005)".to_string(),
        r"^0x0100[a-fA-F0-9]{8}[a-fA-F0-9]{40}$",
        Some(132),
        Some("mssql05".to_string()),
        HashCategory::Application,
        "Microsoft SQL Server 2005 hash".to_string(),
        0.9,
        true,
    )?;

    // MSSQL (2012/2014) - mode 1731
    let mssql2012 = HashPattern::new(
        "MSSQL (2012/2014)".to_string(),
        r"^0x02[a-fA-F0-9]{8}[a-fA-F0-9]{128}$",
        Some(1731),
        Some("mssql12".to_string()),
        HashCategory::Application,
        "Microsoft SQL Server 2012/2014 hash".to_string(),
        0.95,
        true,
    )?;

    // Oracle H: (DES) - mode 3100
    let oracle_des = HashPattern::new(
        "Oracle H: (DES)".to_string(),
        r"^[a-fA-F0-9]{16}$",
        Some(3100),
        Some("oracle".to_string()),
        HashCategory::Application,
        "Oracle DES hash".to_string(),
        0.7,
        false,
    )?;

    // Oracle S: (SHA1) - mode 112
    let oracle_sha1 = HashPattern::new(
        "Oracle S: (SHA1)".to_string(),
        r"^[a-fA-F0-9]{40}$",
        Some(112),
        Some("oracle11".to_string()),
        HashCategory::Application,
        "Oracle SHA1 hash".to_string(),
        0.6,
        false,
    )?;

    // Oracle T: (SHA256) - mode 12300
    let oracle_sha256 = HashPattern::new(
        "Oracle T: (SHA256)".to_string(),
        r"^[a-fA-F0-9]{64}:[a-fA-F0-9]{32}$",
        Some(12300),
        Some("oracle12c".to_string()),
        HashCategory::Application,
        "Oracle 12c SHA256 hash".to_string(),
        0.9,
        true,
    )?;

    // Drupal7 - mode 7900
    let drupal7 = HashPattern::new(
        "Drupal7".to_string(),
        r"^\$S\$[./0-9A-Za-z]{52}$",
        Some(7900),
        Some("drupal7".to_string()),
        HashCategory::Application,
        "Drupal 7 hash".to_string(),
        0.95,
        false,
    )?;

    // Joomla < 2.5.18 - mode 11
    let joomla_old = HashPattern::new(
        "Joomla < 2.5.18".to_string(),
        r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$",
        Some(11),
        Some("joomla".to_string()),
        HashCategory::Application,
        "Joomla legacy hash".to_string(),
        0.9,
        true,
    )?;

    // osCommerce, xt:Commerce - mode 21
    let oscommerce = HashPattern::new(
        "osCommerce, xt:Commerce".to_string(),
        r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$",
        Some(21),
        Some("oscommerce".to_string()),
        HashCategory::Application,
        "osCommerce hash".to_string(),
        0.9,
        true,
    )?;

    // vBulletin < v3.8.5 - mode 2611
    let vbulletin_old = HashPattern::new(
        "vBulletin < v3.8.5".to_string(),
        r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{3}$",
        Some(2611),
        Some("vbulletin".to_string()),
        HashCategory::Application,
        "vBulletin legacy hash".to_string(),
        0.9,
        true,
    )?;

    // vBulletin >= v3.8.5 - mode 2711
    let vbulletin_new = HashPattern::new(
        "vBulletin >= v3.8.5".to_string(),
        r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{30}$",
        Some(2711),
        Some("vbulletin".to_string()),
        HashCategory::Application,
        "vBulletin modern hash".to_string(),
        0.95,
        true,
    )?;

    // SMF (Simple Machines Forum) - mode 121
    let smf = HashPattern::new(
        "SMF (Simple Machines Forum)".to_string(),
        r"^[a-fA-F0-9]{40}:[a-zA-Z0-9./]{4,}$",
        Some(121),
        Some("smf".to_string()),
        HashCategory::Application,
        "Simple Machines Forum hash".to_string(),
        0.9,
        true,
    )?;

    // IPB (Invision Power Board) - mode 2811
    let ipb = HashPattern::new(
        "IPB (Invision Power Board)".to_string(),
        r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{5}$",
        Some(2811),
        Some("ipb2".to_string()),
        HashCategory::Application,
        "Invision Power Board hash".to_string(),
        0.9,
        true,
    )?;

    // MediaWiki B type - mode 3711
    let mediawiki = HashPattern::new(
        "MediaWiki B type".to_string(),
        r"^\$B\$[a-zA-Z0-9./]{31}$",
        Some(3711),
        Some("mediawiki".to_string()),
        HashCategory::Application,
        "MediaWiki hash".to_string(),
        0.9,
        false,
    )?;

    // DES crypt (Unix) - mode 1500
    let des_crypt = HashPattern::new(
        "DES crypt (Unix)".to_string(),
        r"^[a-zA-Z0-9./]{13}$",
        Some(1500),
        Some("descrypt".to_string()),
        HashCategory::Legacy,
        "Traditional DES crypt hash".to_string(),
        0.8,
        true,
    )?;

    // SHA (LDAP SHA1) - mode 101
    let sha_ldap = HashPattern::new(
        "SHA (LDAP SHA1)".to_string(),
        r"^\{SHA\}[A-Za-z0-9+/=]+$",
        Some(101),
        Some("LDAP".to_string()),
        HashCategory::Application,
        "LDAP SHA1 hash".to_string(),
        0.98,
        false,
    )?;

    // SSHA (LDAP Salted SHA1) - mode 111
    let ssha_ldap = HashPattern::new(
        "SSHA (LDAP Salted SHA1)".to_string(),
        r"^\{SSHA\}[A-Za-z0-9+/=]+$",
        Some(111),
        Some("SSHA".to_string()),
        HashCategory::Application,
        "LDAP SSHA (Salted SHA1) hash".to_string(),
        0.98,
        false,
    )?;

    // Wordpress (MD5) - mode 400
    let wordpress = HashPattern::new(
        "Wordpress (MD5)".to_string(),
        r"^\$P\$[./0-9A-Za-z]{31}$",
        Some(400),
        Some("phpass".to_string()),
        HashCategory::Application,
        "WordPress MD5 hash".to_string(),
        0.95,
        false,
    )?;

    // Add all patterns to registry
    registry.add_pattern(des_crypt);
    registry.add_pattern(sha_ldap);
    registry.add_pattern(ssha_ldap);
    registry.add_pattern(phpbb3);
    registry.add_pattern(md5crypt);
    registry.add_pattern(apache_md5);
    registry.add_pattern(sha512crypt);
    registry.add_pattern(dcc);
    registry.add_pattern(dcc2);
    registry.add_pattern(bcrypt);
    registry.add_pattern(cisco_pix);
    registry.add_pattern(cisco_asa);
    registry.add_pattern(wpa_eapol);
    registry.add_pattern(wpa_pmkid);
    registry.add_pattern(mysql323);
    registry.add_pattern(mysql41);
    registry.add_pattern(postgresql);
    registry.add_pattern(mssql2000);
    registry.add_pattern(mssql2005);
    registry.add_pattern(mssql2012);
    registry.add_pattern(oracle_des);
    registry.add_pattern(oracle_sha1);
    registry.add_pattern(oracle_sha256);
    registry.add_pattern(drupal7);
    registry.add_pattern(joomla_old);
    registry.add_pattern(oscommerce);
    registry.add_pattern(vbulletin_old);
    registry.add_pattern(vbulletin_new);
    registry.add_pattern(smf);
    registry.add_pattern(ipb);
    registry.add_pattern(mediawiki);
    registry.add_pattern(wordpress);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_application_patterns() {
        let mut registry = PatternRegistry::new();
        assert!(load_patterns(&mut registry).is_ok());
        assert!(!registry.patterns().is_empty());
    }

    #[test]
    fn test_bcrypt_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test bcrypt format
        let matches = registry.find_matches("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy".to_string());
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_wordpress_pattern() {
        let mut registry = PatternRegistry::new();
        load_patterns(&mut registry).unwrap();

        // Test WordPress format
        let matches = registry.find_matches("$P$B7889EMXQJFPiXnlRL.k/b1EYhsWqxM1".to_string());
        assert!(!matches.is_empty());
    }
}