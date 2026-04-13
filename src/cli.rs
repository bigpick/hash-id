use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hash-id")]
#[command(about = "Identify hash types with hashcat/john mode support")]
#[command(version)]
pub struct Cli {
    /// Hash to identify (or use --file/-f for batch processing)
    /// Mutually exclusive with --file and --stdin options
    pub hash: Option<String>,

    /// File containing hashes (one per line)
    /// Mutually exclusive with direct hash input and --stdin
    #[arg(short, long)]
    pub file: Option<PathBuf>,

    /// Output identification results in JSON format
    /// When enabled, outputs structured data suitable for automation
    #[arg(long)]
    pub json: bool,

    /// Minimum confidence threshold for hash type matches (0.0-1.0)
    /// Only results above this confidence level will be displayed
    #[arg(long, default_value = "0.1")]
    pub min_confidence: f32,

    /// Maximum number of hash type results to display per hash
    /// Useful for limiting output when multiple similar hash types are detected
    #[arg(long, default_value = "5")]
    pub max_results: usize,

    /// Read hashes from standard input (one per line)
    /// Mutually exclusive with direct hash input and --file option
    #[arg(long)]
    pub stdin: bool,
}

impl Cli {
    /// Validate CLI arguments
    pub fn validate(&self) -> crate::Result<()> {
        // Validate confidence range
        if self.min_confidence < 0.0 || self.min_confidence > 1.0 {
            return Err(crate::HashIdError::InvalidConfidence(self.min_confidence));
        }

        // Ensure at least one input method is specified
        if self.hash.is_none() && self.file.is_none() && !self.stdin {
            return Err(crate::HashIdError::MissingInput(
                "Must specify either hash, --file, or --stdin".to_string()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::parse_from(["hash-id", "abc123"]);
        assert_eq!(cli.hash, Some("abc123".to_string()));
        assert!(!cli.json);
    }

    #[test]
    fn test_cli_json_flag() {
        let cli = Cli::parse_from(["hash-id", "--json", "abc123"]);
        assert!(cli.json);
    }

    #[test]
    fn test_validate_confidence_range() {
        let mut cli = Cli::parse_from(["hash-id", "abc123"]);
        cli.min_confidence = 1.5;
        assert!(cli.validate().is_err());
    }

    #[test]
    fn test_validate_requires_input() {
        let cli = Cli::parse_from(["hash-id"]);
        assert!(cli.validate().is_err());
    }
}