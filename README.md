# watc - What Are Those C libraries?

A powerful CLI tool for analyzing binaries to determine C library versions used during compilation. watc supports both ELF and PE formats and uses multiple analysis methods including symbol extraction, string analysis, and online database queries.

## Features

- **Multi-format Support**: Analyze ELF (Linux/Unix) and PE (Windows) binaries
- **Multiple Analysis Methods**:
  - Direct binary parsing using goblin
  - External tool integration (`strings`, `readelf`)
  - Symbol categorization and confidence scoring
  - Version string extraction
- **Online Database Integration**: Query libc.blukat.me for accurate version matching
- **Flexible Output**: Pretty-printed, JSON, CSV, and simple text formats
- **Comprehensive Symbol Analysis**: Categorizes symbols by type (memory, string, I/O, etc.)
- **Enhanced ELF Analysis**: Integrates with `readelf` for detailed ELF information

## Installation

### From Source

```bash
git clone <repository-url>
cd watc
cargo build --release
```

The binary will be available at `target/release/watc`.

### Dependencies

For full functionality, install these external tools:

```bash
# Ubuntu/Debian
sudo apt install binutils

# RHEL/CentOS/Fedora
sudo yum install binutils
# or
sudo dnf install binutils

# macOS
brew install binutils
```

## Usage

### Basic Analysis

Analyze a binary file to detect C library version:

```bash
watc analyze /path/to/binary
```

### Advanced Options

```bash
# Verbose output with detailed information
watc analyze --verbose /path/to/binary

# JSON output for programmatic use
watc analyze --format json /path/to/binary

# Offline mode (skip online database queries)
watc analyze --offline /path/to/binary

# Disable external tools
watc analyze --no-readelf --no-external-strings /path/to/binary

# Show symbol statistics
watc analyze --show-stats /path/to/binary
```

### Check Tool Status

Check availability of external tools:

```bash
watc tools
```

### Test API Connection

Test connectivity to the libc database:

```bash
watc test-api
```

### Show Supported Formats

List supported binary formats:

```bash
watc formats
```

## Examples

### Analyzing an ELF Binary

```bash
$ watc analyze /bin/ls --verbose
🔍 Binary Analysis Results
==================================================

📁 Binary Information
Path: /bin/ls
Format: ELF
Architecture: x86_64
Bitness: 64-bit
Entry Point: 0x6040
Dependencies:
  - libc.so.6
  - libselinux.so.1

🔤 Symbol Analysis
Total symbols found: 234
Libc-related symbols: 45
Version strings found: 12

🎯 Libc Detection Results
Detection strategy: VersionedSymbols
Symbols analyzed: 45
Best confidence: 95.2%

Top matches:
1. GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) (95.2%)
   Version: 2.31-0ubuntu9.9
   Architecture: x86_64
   OS: linux
   Symbols matched: 42

📄 Version Strings
  GLIBC_2.2.5
  GLIBC_2.3
  GLIBC_2.3.4
  GLIBC_2.4
  GLIBC_2.17
  GLIBC_2.28
```

### JSON Output

```bash
$ watc analyze /bin/ls --format json
{
  "binary_info": {
    "path": "/bin/ls",
    "format": "ELF",
    "architecture": "x86_64",
    "bitness": 64,
    "entry_point": 24640,
    "dependencies": ["libc.so.6", "libselinux.so.1"]
  },
  "symbol_analysis": {
    "total_symbols": 234,
    "libc_symbols": 45,
    "version_strings": ["GLIBC_2.31", "GLIBC_2.17"],
    "symbol_statistics": {
      "LibcStandard": 15,
      "Memory": 8,
      "String": 12,
      "FileIO": 10
    }
  },
  "libc_detection": {
    "best_confidence": 0.952,
    "strategy": "VersionedSymbols",
    "symbols_analyzed": 45,
    "matches": [
      {
        "name": "GNU C Library",
        "version": "2.31-0ubuntu9.9",
        "architecture": "x86_64",
        "overall_score": 0.952,
        "symbols_matched": 42
      }
    ]
  }
}
```

### Checking Tool Availability

```bash
$ watc tools
External Tools Status
=========================

readelf: ✓ Available
  Description: GNU readelf - displays information about ELF files
  Used for: Enhanced ELF analysis, version information, symbol versioning

strings: ✓ Available
  Description: Extracts printable strings from binary files
  Used for: Additional string extraction, complement to built-in parser

All external tools are available!
```

## Analysis Methods

watc uses multiple complementary analysis methods:

### 1. Direct Binary Parsing
- Uses the goblin crate to parse ELF and PE formats
- Extracts symbols, imports, exports, and basic metadata
- Works offline without external dependencies

### 2. External Tool Integration
- **readelf**: Enhanced ELF analysis including version requirements, symbol versioning
- **strings**: Additional string extraction to complement built-in parser

### 3. Symbol Categorization
Symbols are automatically categorized into:
- **LibcStandard**: Core C library functions (printf, malloc, etc.)
- **Memory**: Memory management functions
- **String**: String manipulation functions  
- **FileIO**: File I/O operations
- **SystemCall**: POSIX/Unix system calls
- **Threading**: pthread and threading functions
- **Math**: Mathematical functions
- **Network**: Socket and networking functions
- **Versioned**: Symbols with explicit version information

### 4. Online Database Queries
- Queries libc.blukat.me database for accurate version matching
- Uses intelligent symbol selection for optimal results
- Provides confidence scores for matches

## Configuration

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--verbose` | Enable verbose output | false |
| `--format` | Output format (pretty, json, csv, simple) | pretty |
| `--no-color` | Disable colored output | false |
| `--offline` | Skip online database queries | false |
| `--no-readelf` | Disable readelf integration | false |
| `--no-external-strings` | Disable external strings command | false |
| `--readelf-path` | Custom readelf executable path | readelf |
| `--min-string-length` | Minimum string length | 4 |
| `--max-string-length` | Maximum string length | 256 |
| `--api-timeout` | API request timeout (seconds) | 30 |

### Environment Variables

- `WATC_NO_COLOR`: Set to disable colored output
- `WATC_READELF_PATH`: Custom path to readelf executable

## Output Formats

### Pretty (Default)
Human-readable formatted output with colors and sections.

### JSON
Machine-readable JSON format suitable for integration with other tools.

### CSV
Comma-separated values format for spreadsheet analysis.

### Simple
Minimal text output with key information only.

## API Integration

watc integrates with the libc.blukat.me database to provide accurate C library version detection. The database contains fingerprints of various libc versions across different operating systems and architectures.

### Supported Libraries
- GNU C Library (glibc) - Linux
- Microsoft Visual C++ Runtime - Windows  
- musl libc - Alpine Linux and embedded systems
- uClibc - Embedded systems
- Bionic libc - Android

## Troubleshooting

### Common Issues

**"No matches found"**
- Binary might use static linking
- Library might not be in the database
- Try `--offline` mode to see local analysis results

**"readelf not available"**
- Install binutils package
- Use `--no-readelf` to disable
- Check with `watc tools`

**"API connection failed"**
- Check internet connectivity
- Use `watc test-api` to verify
- Use `--offline` mode as fallback

**"Unsupported binary format"**
- Currently supports ELF and PE formats only
- Check file type with `file` command
- Use `watc formats` to see supported formats

### Debug Mode

Enable verbose output for detailed analysis information:

```bash
watc analyze --verbose /path/to/binary
```

## Contributing

Contributions are welcome! Areas for improvement:

1. **Additional Binary Formats**: Support for Mach-O, WASM, etc.
2. **Enhanced Database**: Extend library fingerprint database
3. **Performance**: Optimize analysis for large binaries  
4. **Platform Support**: Windows-specific analysis improvements
5. **UI/UX**: Enhanced output formatting and error messages

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Architecture

```
watc/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library interface
│   ├── binary/              # Binary parsing
│   │   ├── common.rs        # Common types and traits
│   │   ├── elf.rs           # ELF format parser
│   │   └── pe.rs            # PE format parser
│   ├── analysis/            # Analysis modules  
│   │   ├── symbols.rs       # Symbol categorization
│   │   ├── strings.rs       # String extraction
│   │   └── readelf.rs       # readelf integration
│   ├── libc/                # Database integration
│   │   ├── api.rs           # API client
│   │   └── matcher.rs       # Matching logic
│   └── cli/                 # CLI interface
│       ├── args.rs          # Argument parsing
│       └── output.rs        # Output formatting
```

## Acknowledgments

- [goblin](https://github.com/m4b/goblin) - Binary parsing library
- [libc.blukat.me](https://libc.blukat.me) - C library database
- [clap](https://github.com/clap-rs/clap) - Command line argument parsing
- GNU binutils - readelf and strings tools