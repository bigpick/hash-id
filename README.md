# Hash-ID v2.0
[![forthebadge](https://forthebadge.com/images/badges/made-with-rust.svg)](https://forthebadge.com) [![forthebadge](https://forthebadge.com/images/badges/open-source.svg)](https://forthebadge.com)

____

**hash-id** is a modern command-line hash identification tool built for password cracking workflows. Completely rewritten in Rust v2.0 with comprehensive pattern matching, confidence scoring, and seamless integration with hashcat and John the Ripper.

**Perfect for:** DefCon CMIYC competition, penetration testing, security research, and password cracking workflows.

* [Features](#features)
* [Usage](#usage)
* [Installation](#installation)
* [Hash Type Coverage](#hash-type-coverage)
* [Contributing](CONTRIBUTING.md)

## Features

🔍 **Comprehensive Pattern Matching**
- 24+ hash types with regex-based detection
- Advanced confidence scoring system
- Support for salted hash variants

⚡ **Modern Architecture** 
- Complete Rust rewrite from scratch
- Extensible pattern engine
- Zero unsafe code, comprehensive error handling

🛠️ **Cracking Tool Integration**
- Direct hashcat mode numbers (`-m` flags)
- John the Ripper format names (`--format`)
- Ready-to-use command fragments

📊 **Multiple Output Formats**
- Clean text output (minimal/normal/verbose modes)
- Structured JSON output (pretty/compact options)
- Batch processing support

## Usage

### Basic Usage
```bash
# Identify a single hash
hash-id 5d41402abc4b2a76b9719d911017c592

# JSON output
hash-id --json 5d41402abc4b2a76b9719d911017c592

# Process file containing hashes
hash-id --file hashes.txt

# Read from stdin
cat hashes.txt | hash-id --stdin
```

### Advanced Options
```bash
# Filter by confidence threshold
hash-id --min-confidence 0.8 hash_value

# Limit number of results
hash-id --max-results 3 hash_value

# Combine options
hash-id --json --min-confidence 0.9 --file hashes.txt
```

### Example Output

**Text Format:**
```
$ hash-id 5d41402abc4b2a76b9719d911017c592
Hash: 5d41402abc4b2a76b9719d911017c592
  [+] MD5 (hashcat: -m 0, john: --format=Raw-MD5) [confidence: 0.66]
  [+] NTLM (hashcat: -m 1000, john: --format=NT) [confidence: 0.55]
  [+] MD4 (hashcat: -m 900, john: --format=Raw-MD4) [confidence: 0.44]
------------------------------------------
```

**JSON Format:**
```json
{
  "hash": "5d41402abc4b2a76b9719d911017c592",
  "detected_types": [
    {
      "name": "MD5",
      "hashcat_mode": 0,
      "john_format": "Raw-MD5",
      "confidence": 0.66,
      "category": "Basic",
      "description": "MD5 message digest algorithm"
    }
  ],
  "processing_time_ms": 2
}
```

**Modern Authentication Patterns:**
```
$ hash-id '$2a$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG'
Hash: $2a$10$N9qo8uLOickgx2ZMRZoMye7EjBF5n7w.9PG7OkWQ3Jk5O5wZk5qqG
  [+] bcrypt (hashcat: -m 3200, john: --format=bcrypt) [confidence: 1.00] [salted]
------------------------------------------
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `<HASH>` | Hash value to identify (positional argument) |
| `--file <FILE>` | File containing hashes (one per line) |
| `--stdin` | Read hashes from standard input |
| `--json` | Output results in JSON format |
| `--min-confidence <FLOAT>` | Only show results above confidence threshold (0.0-1.0) |
| `--max-results <NUM>` | Limit number of results per hash |
| `--help` | Show help information |
| `--version` | Show version information |

## Hash Type Coverage

### Basic Hash Functions (12 types)
- **MD5, MD4, NTLM, LM** - 32 hex characters
- **SHA1** - 40 hex characters  
- **SHA224** - 56 hex characters
- **SHA256** - 64 hex characters
- **SHA384** - 96 hex characters
- **SHA512** - 128 hex characters
- **Salted variants** - With colon separators

### Modern Authentication (12 types)
- **bcrypt** - All variants ($2a$, $2b$, $2x$, $2y$, $2z$)
- **scrypt** - scrypt key derivation function
- **PBKDF2** - SHA1, SHA256, SHA512 variants
- **Argon2** - Argon2i, Argon2d, Argon2id
- **Unix crypt** - md5crypt, sha256crypt, sha512crypt
- **Apache APR1** - Apache MD5 variant

### Confidence Scoring
- **1.0** - Unique format (bcrypt, Argon2)
- **0.9-0.95** - High confidence with minor ambiguity
- **0.6-0.8** - Medium confidence (common lengths)
- **0.3-0.5** - Lower confidence (high ambiguity)

## Installation

### From Source
```bash
# Clone repository
git clone https://github.com/your-repo/hash-id
cd hash-id

# Build release binary
cargo build --release

# Binary available at target/release/hash-id
```

### Development
```bash
# Run tests
cargo test

# Run with development build
cargo run -- <hash_value>

# Install for local development
cargo install --path .
```

## Integration Examples

### Hashcat Integration
```bash
# Get hashcat mode for a hash
HASH="5d41402abc4b2a76b9719d911017c592"
MODE=$(hash-id --json "$HASH" | jq -r '.detected_types[0].hashcat_mode')
hashcat -m "$MODE" hashes.txt wordlist.txt
```

### John the Ripper Integration  
```bash
# Get John format for a hash
HASH="$2a$10$abcdef..."
FORMAT=$(hash-id --json "$HASH" | jq -r '.detected_types[0].john_format')
john --format="$FORMAT" hashes.txt
```

### Batch Processing
```bash
# Process multiple hashes with confidence filtering
hash-id --file hashes.txt --min-confidence 0.8 --json > results.json
```

---

**Note:** This tool is for hash identification only. It does not crack passwords - use hashcat or John the Ripper for password recovery.