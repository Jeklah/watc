//! CLI argument parsing module
//!
//! This module defines the command-line interface for the watc binary analysis tool.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// What Are Those C libraries? - Binary analysis tool for C library version detection
#[derive(Parser, Debug)]
#[command(name = "watc")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Analyze binaries to determine C library versions")]
#[command(long_about = r#"
watc (What Are Those C libraries?) analyzes ELF and PE binaries to determine
what version of C library was used during compilation. It uses multiple analysis
methods including symbol extraction, string analysis, and queries to the
libc.rip database.

Examples:
  watc analyze ./my_binary                 # Analyze a single binary
  watc analyze --verbose ./my_binary       # Detailed analysis output
  watc analyze --format json ./my_binary   # Output results as JSON
  watc analyze --offline ./my_binary       # Skip online database queries
  watc test-api                            # Test API connectivity
"#)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output format
    #[arg(short = 'f', long = "format", global = true, value_enum, default_value_t = OutputFormat::Pretty)]
    pub format: OutputFormat,

    /// Suppress colored output
    #[arg(long = "no-color", global = true)]
    pub no_color: bool,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Analyze a binary file to detect C library version
    Analyze {
        /// Path to the binary file to analyze
        #[arg(value_name = "BINARY")]
        file_path: PathBuf,

        /// Skip online database queries (offline mode)
        #[arg(long)]
        offline: bool,

        /// Minimum string length for string analysis
        #[arg(long, default_value_t = 4)]
        min_string_length: usize,

        /// Maximum string length for string analysis
        #[arg(long, default_value_t = 256)]
        max_string_length: usize,

        /// Disable external 'strings' command usage
        #[arg(long)]
        no_external_strings: bool,

        /// Show symbol statistics
        #[arg(long)]
        show_stats: bool,

        /// Show all extracted strings (can be very verbose)
        #[arg(long)]
        show_strings: bool,

        /// Show all symbols found in the binary
        #[arg(long)]
        show_symbols: bool,

        /// Only show high-confidence results
        #[arg(long)]
        high_confidence_only: bool,

        /// Disable readelf integration for ELF files
        #[arg(long)]
        no_readelf: bool,

        /// Custom path to readelf executable
        #[arg(long)]
        readelf_path: Option<String>,

        /// Timeout for readelf commands in seconds
        #[arg(long, default_value_t = 30)]
        readelf_timeout: u64,

        /// API timeout in seconds
        #[arg(long, default_value_t = 30)]
        api_timeout: u64,

        /// Maximum number of symbols to send in API requests
        #[arg(long, default_value_t = 20)]
        max_api_symbols: usize,
    },

    /// Test API connectivity to libc.rip
    TestApi {
        /// Custom API base URL
        #[arg(long)]
        api_url: Option<String>,

        /// API timeout in seconds
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },

    /// Show information about supported binary formats
    Formats,

    /// Show version information and exit
    Version,

    /// Check availability of external tools (readelf, strings)
    Tools,
}

/// Output format options
#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    /// Pretty-printed human-readable output (default)
    Pretty,
    /// JSON output
    Json,
    /// CSV output
    Csv,
    /// Simple text output (minimal formatting)
    Simple,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Pretty => write!(f, "pretty"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Csv => write!(f, "csv"),
            OutputFormat::Simple => write!(f, "simple"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Args::command().debug_assert()
    }

    #[test]
    fn test_basic_analyze_command() {
        let args = Args::try_parse_from(&["watc", "analyze", "/path/to/binary"]).unwrap();

        match args.command {
            Commands::Analyze {
                file_path, offline, ..
            } => {
                assert_eq!(file_path, PathBuf::from("/path/to/binary"));
                assert!(!offline);
            }
            _ => panic!("Expected Analyze command"),
        }
    }

    #[test]
    fn test_analyze_with_flags() {
        let args = Args::try_parse_from(&[
            "watc",
            "--verbose",
            "--format",
            "json",
            "analyze",
            "--offline",
            "--show-stats",
            "/path/to/binary",
        ])
        .unwrap();

        assert!(args.verbose);
        assert_eq!(args.format, OutputFormat::Json);

        match args.command {
            Commands::Analyze {
                file_path,
                offline,
                show_stats,
                ..
            } => {
                assert_eq!(file_path, PathBuf::from("/path/to/binary"));
                assert!(offline);
                assert!(show_stats);
            }
            _ => panic!("Expected Analyze command"),
        }
    }

    #[test]
    fn test_tools_command() {
        let args = Args::try_parse_from(&["watc", "tools"]).unwrap();

        match args.command {
            Commands::Tools => {}
            _ => panic!("Expected Tools command"),
        }
    }

    #[test]
    fn test_test_api_command() {
        let args = Args::try_parse_from(&["watc", "test-api"]).unwrap();

        match args.command {
            Commands::TestApi { api_url, timeout } => {
                assert_eq!(api_url, None);
                assert_eq!(timeout, 10);
            }
            _ => panic!("Expected TestApi command"),
        }
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Pretty.to_string(), "pretty");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Csv.to_string(), "csv");
        assert_eq!(OutputFormat::Simple.to_string(), "simple");
    }
}
