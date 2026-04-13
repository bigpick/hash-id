//! Pattern engine for hash detection

pub mod engine;
pub mod registry;
pub mod confidence;

pub use engine::PatternEngine;
pub use registry::{HashPattern, HashPatternBuilder, HashPatternConfig, PatternRegistry};
pub use confidence::{ConfidenceScorer, DetectionContext};