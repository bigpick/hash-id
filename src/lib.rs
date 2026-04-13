//! Hash identification library with comprehensive pattern matching
//!
//! Provides regex-based hash detection with confidence scoring for
//! integration with hashcat and john the ripper.

pub mod cli;
pub mod error;
pub mod pattern;
pub mod types;
pub mod output;
pub mod patterns;

pub use error::{HashIdError, Result};
pub use types::{HashCategory, HashIdentification, HashType, DetectionResult};
pub use pattern::PatternEngine;

/// Version of the hash-id library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Create a pattern engine with all default patterns loaded
pub fn create_engine() -> Result<PatternEngine> {
    PatternEngine::with_default_patterns()
}