use clap::Parser;
use hash_id::{
    cli::Cli,
    Result,
    create_engine,
    output::{JsonFormatter, TextFormatter, OutputFormatter},
    types::DetectionResult,
};
use std::io::{self, BufRead, BufReader};
use std::fs::File;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Cli::parse();
    args.validate()?;

    // Create pattern engine
    let engine = create_engine()?;

    // Determine output formatter
    let formatter: Box<dyn OutputFormatter> = if args.json {
        Box::new(JsonFormatter::new())
    } else {
        Box::new(TextFormatter::new())
    };

    // Process input based on mode
    let results = if let Some(hash) = &args.hash {
        // Single hash mode
        vec![engine.detect(hash)]
    } else if let Some(file_path) = &args.file {
        // File input mode
        let file = File::open(file_path)
            .map_err(|_| hash_id::HashIdError::FileNotFound {
                path: file_path.clone()
            })?;
        let reader = BufReader::new(file);
        let hashes: Vec<String> = reader.lines().collect::<io::Result<_>>()?;
        engine.detect_batch(&hashes)
    } else if args.stdin {
        // Stdin mode
        let stdin = io::stdin();
        let hashes: Vec<String> = stdin.lock().lines().collect::<io::Result<_>>()?;
        engine.detect_batch(&hashes)
    } else {
        // This should be caught by validation, but just in case
        return Err(hash_id::HashIdError::InvalidHashFormat(
            "No input provided".to_string()
        ));
    };

    // Apply filters
    let mut filtered_results = Vec::new();
    for result in results {
        let mut identification = result.identification;

        // Apply confidence filter
        identification = identification.filter_by_confidence(args.min_confidence);

        // Apply max results limit
        identification = identification.limit_results(args.max_results);

        // Recreate detection result with filtered identification
        let filtered_result = DetectionResult::new(identification);

        // Copy over warnings from original result
        let final_result = result.warnings.iter().fold(filtered_result, |acc, warning| {
            acc.with_warning(warning.clone())
        });

        filtered_results.push(final_result);
    }

    // Format and output results
    let output = if filtered_results.len() == 1 {
        formatter.format_detection(&filtered_results[0])?
    } else {
        formatter.format_detections(&filtered_results)?
    };

    print!("{}", output);

    Ok(())
}