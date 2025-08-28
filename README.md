# watc - What Are Those C libraries?

A powerful CLI tool for analyzing binaries to determine C library versions used during compilation. watc supports both ELF and PE formats and uses multiple analysis methods including symbol extraction, string analysis, and online database queries.

## Features

- **Multi-format Support**: Analyze ELF (Linux/Unix) and PE (Windows) binaries
- **Multiple Analysis Methods**:
  - Direct binary parsing using goblin
  - External tool integration (`strings`, `readelf`)
  - Symbol categorization and confidence scoring
  - Version string extraction
- **Online Database Integration**: Query libc.rip for accurate version matching
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

# Save complete JSON analysis to file
watc analyze --json-file /path/to/binary

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
   Download: https://libc.rip/download/libc6_2.31-0ubuntu9.9_amd64.so

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
    },
    "all_symbols": [
      {
        "name": "printf",
        "address": "0x1234",
        "category": "LibcStandard",
        "confidence": 0.95,
        "clean_name": "printf",
        "version_info": null
      }
    ],
    "all_strings": ["GLIBC_2.31", "main", "printf"]
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

### JSON File Output

Save complete analysis results to a JSON file:

```bash
$ watc analyze /bin/ls --json-file
🔍 Binary Analysis Results
==================================================
[... normal output ...]
📄 JSON analysis saved to: analysis_ls.json

$ ls -la analysis_ls.json
-rw-rw-r-- 1 user user 54809 analysis_ls.json
```

The JSON file contains complete analysis data including all symbols, strings, and detection results, suitable for programmatic processing or integration with other tools.

### API Integration Example

The tool integrates with the libc.rip database to identify C library versions based on symbol addresses:

```bash
$ watc analyze /path/to/binary --verbose
🔍 Binary Analysis Results
==================================================
[... analysis output ...]

🎯 Libc Detection Results
Detection strategy: HighConfidenceSymbols
Symbols analyzed: 15
Best confidence: 95.2%

Top matches:
1. libc6_2.27-3ubuntu1.2_amd64 (95.2%)
   Version: 2.27-3ubuntu1.2
   Architecture: amd64
   OS: linux
   Symbols matched: 14/15
   Download: https://libc.rip/download/libc6_2.27-3ubuntu1.2_amd64.so

**Download URL**: The tool provides direct download links to the detected libc version for further analysis or exploitation development.

**Note**: The API requires actual runtime addresses for accurate matching. Dynamically linked binaries may not have sufficient address information for database matching.

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
- Queries libc.rip database for accurate version matching
- Uses intelligent symbol selection for optimal results
- Provides confidence scores for matches

## Configuration

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--verbose` | Enable verbose output | false |
| `--format` | Output format (pretty, json, csv, simple) | pretty |
| `--no-color` | Disable colored output | false |
| `--no-readelf` | Disable readelf integration | false |
| `--no-external-strings` | Disable external strings command | false |
| `--json-file` | Save JSON output to file (analysis_<binary_name>.json) | false |
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
Machine-readable JSON format suitable for integration with other tools. Includes complete symbol information, strings, and analysis results. Use `--json-file` to save the complete JSON analysis to a file named `analysis_<binary_name>.json`.

### CSV
Comma-separated values format for spreadsheet analysis.

### Simple
Minimal text output with key information only.

## API Integration

watc automatically queries the libc.rip database for every binary analysis to provide accurate C library version detection. The database contains fingerprints of various libc versions across different operating systems and architectures.

### How API Integration Works

The tool sends symbol names and their hexadecimal addresses to the libc.rip API:

```json
{
  "symbols": {
    "printf": "64f00",
    "malloc": "97e40", 
    "free": "97eb0"
  }
}
```

The API responds with matching libc versions that contain those symbols at those addresses:

```json
[
  {
    "id": "libc6_2.27-3ubuntu1.2_amd64",
    "buildid": "d3cf764b2f97ac3efe366ddd07ad902fb6928fd7",
    "download_url": "https://libc.rip/download/libc6_2.27-3ubuntu1.2_amd64.so",
    "symbols": {
      "printf": "0x64f00",
      "malloc": "0x97e40",
      "free": "0x97eb0"
    }
  }
]
```

### Limitations

- **Dynamic Libraries**: Most modern binaries use dynamic linking, where libc functions are resolved at runtime. These binaries typically don't contain the actual addresses needed for database matching.
- **Static Binaries**: Statically linked binaries or those with embedded addresses work best with the API.
- **Runtime Analysis**: For accurate results with dynamic binaries, analysis should be performed at runtime when addresses are resolved.
- **Network Dependency**: The tool requires internet connectivity to query the libc.rip database for version detection.

### Supported Libraries
- GNU C Library (glibc) - Linux
- Microsoft Visual C++ Runtime - Windows  
- musl libc - Alpine Linux and embedded systems
- uClibc - Embedded systems
- Bionic libc - Android

## Troubleshooting

### Common Issues

**"No matches found"**
- Binary uses dynamic linking with insufficient address information
- Library version might not be in the database
- Binary might use static linking or custom libc

**"readelf not available"**
- Install binutils package
- Use `--no-readelf` to disable
- Check with `watc tools`

**"API connection failed"**
- Check internet connectivity
- Use `watc test-api` to verify
- Check firewall or proxy settings
- API might be temporarily unavailable

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
- [libc.rip](https://libc.rip) - C library database
- [clap](https://github.com/clap-rs/clap) - Command line argument parsing
- GNU binutils - readelf and strings tools