use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashCategory {
    /// Basic hash functions (MD5, SHA1, SHA256, etc.)
    Basic,
    /// Modern authentication hashes (bcrypt, scrypt, PBKDF2)
    Authentication,
    /// Modern cryptographic algorithms (SHA3, Keccak, BLAKE2)
    Modern,
    /// Salted hash variants (salt+hash combinations)
    Salted,
    /// Application-specific formats (CMS, frameworks)
    Application,
    /// Network security formats (WPA, Kerberos, NetNTLM)
    Network,
    /// Database hash formats (MySQL, PostgreSQL)
    Database,
    /// Document encryption formats (Office, PDF)
    Document,
    /// Archive encryption (RAR, 7-Zip, etc.)
    Archive,
    /// Full disk/container encryption (TrueCrypt, VeraCrypt)
    Encryption,
    /// Cryptocurrency wallets (Bitcoin, Ethereum)
    Cryptocurrency,
    /// Legacy formats (DES, LM, etc.)
    Legacy,
    /// Other/unknown formats
    Other,
}

impl HashCategory {
    /// Get a human-readable description of the category
    pub fn description(&self) -> &'static str {
        match self {
            HashCategory::Basic => "Basic hash functions",
            HashCategory::Authentication => "Modern authentication hashes",
            HashCategory::Modern => "Modern cryptographic algorithms",
            HashCategory::Salted => "Salted hash variants",
            HashCategory::Application => "Application-specific formats",
            HashCategory::Network => "Network security formats",
            HashCategory::Database => "Database hash formats",
            HashCategory::Document => "Document encryption",
            HashCategory::Archive => "Archive encryption",
            HashCategory::Encryption => "Full disk/container encryption",
            HashCategory::Cryptocurrency => "Cryptocurrency wallets",
            HashCategory::Legacy => "Legacy hash formats",
            HashCategory::Other => "Other/unknown formats",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_description() {
        assert_eq!(HashCategory::Basic.description(), "Basic hash functions");
        assert_eq!(HashCategory::Authentication.description(), "Modern authentication hashes");
    }

    #[test]
    fn test_category_serialization() {
        let category = HashCategory::Basic;
        let json = serde_json::to_string(&category).unwrap();
        let deserialized: HashCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(category, deserialized);
    }
}