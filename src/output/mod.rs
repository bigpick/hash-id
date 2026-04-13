//! Output formatting for hash identification results
//!
//! This module provides formatters for converting hash identification results
//! into human-readable or machine-readable formats.
//!
//! # Examples
//!
//! ## JSON Output
//!
//! ```rust
//! use hash_id::types::{HashCategory, HashType, HashIdentification, DetectionResult};
//! use hash_id::output::{OutputFormatter, JsonFormatter};
//!
//! let hash_type = HashType::new(
//!     "MD5".to_string(),
//!     Some(0),
//!     Some("Raw-MD5".to_string()),
//!     0.95,
//!     HashCategory::Basic,
//!     "MD5 hash function".to_string(),
//!     false,
//!     "md5_pattern".to_string(),
//! );
//!
//! let identification = HashIdentification::new(
//!     "5d41402abc4b2a76b9719d911017c592".to_string(),
//!     vec![hash_type],
//!     10,
//! );
//!
//! let formatter = JsonFormatter::pretty();
//! let output = formatter.format_single(&identification).unwrap();
//! println!("{}", output);
//! ```
//!
//! ## Text Output
//!
//! ```rust
//! use hash_id::types::{HashCategory, HashType, HashIdentification};
//! use hash_id::output::{OutputFormatter, TextFormatter};
//!
//! let hash_type = HashType::new(
//!     "MD5".to_string(),
//!     Some(0),
//!     Some("Raw-MD5".to_string()),
//!     0.95,
//!     HashCategory::Basic,
//!     "MD5 hash function".to_string(),
//!     false,
//!     "md5_pattern".to_string(),
//! );
//!
//! let identification = HashIdentification::new(
//!     "5d41402abc4b2a76b9719d911017c592".to_string(),
//!     vec![hash_type],
//!     10,
//! );
//!
//! let formatter = TextFormatter::verbose();
//! let output = formatter.format_single(&identification).unwrap();
//! println!("{}", output);
//! ```

pub mod formatter;
pub mod json;
pub mod text;

pub use formatter::OutputFormatter;
pub use json::JsonFormatter;
pub use text::TextFormatter;