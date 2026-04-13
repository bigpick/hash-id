use thiserror::Error;
use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum HashIdError {
    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    #[error("Missing input: {0}")]
    MissingInput(String),

    #[error("File not found: {path}")]
    FileNotFound { path: PathBuf },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Invalid confidence value: {0} (must be between 0.0 and 1.0)")]
    InvalidConfidence(f32),
}

pub type Result<T> = std::result::Result<T, HashIdError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = HashIdError::InvalidHashFormat("abc123".to_string());
        assert_eq!(error.to_string(), "Invalid hash format: abc123");
    }

    #[test]
    fn test_invalid_confidence_error() {
        let error = HashIdError::InvalidConfidence(1.5);
        assert!(error.to_string().contains("must be between 0.0 and 1.0"));
    }
}