use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn test_cli_single_hash() {
    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.arg("5d41402abc4b2a76b9719d911017c592")
        .assert()
        .success()
        .stdout(predicate::str::contains("MD5"));
}

#[test]
fn test_cli_json_output() {
    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.arg("--json")
        .arg("5d41402abc4b2a76b9719d911017c592")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"detected_types\""));
}

#[test]
fn test_cli_invalid_hash() {
    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.arg("invalid")
        .assert()
        .success()
        .stdout(predicate::str::contains("No matches found"));
}

#[test]
fn test_cli_confidence_filter() {
    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.arg("--min-confidence")
        .arg("0.8")
        .arg("5d41402abc4b2a76b9719d911017c592")
        .assert()
        .success();
}

#[test]
fn test_cli_file_input() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "5d41402abc4b2a76b9719d911017c592").unwrap();
    writeln!(temp_file, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12").unwrap();

    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.arg("--file")
        .arg(temp_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("MD5"))
        .stdout(predicate::str::contains("SHA1"));
}

#[test]
fn test_cli_validation_no_input() {
    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Must specify"));
}

#[test]
fn test_cli_validation_invalid_confidence() {
    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.arg("--min-confidence")
        .arg("1.5")
        .arg("test")
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be between 0.0 and 1.0"));
}

#[test]
fn test_cli_stdin_input() {
    let mut cmd = Command::cargo_bin("hash-id").unwrap();
    cmd.arg("--stdin")
        .write_stdin("5d41402abc4b2a76b9719d911017c592\n2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("MD5"))
        .stdout(predicate::str::contains("SHA1"));
}
