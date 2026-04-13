//! Core type definitions for hash identification

pub mod category;
pub mod hash;
pub mod detection;

pub use category::HashCategory;
pub use hash::{HashType, HashIdentification};
pub use detection::DetectionResult;