//! CLI module for the watc binary analysis tool
//!
//! This module provides the command-line interface functionality including
//! argument parsing and output formatting.

pub mod args;
pub mod output;

pub use args::{Args, Commands, OutputFormat};
pub use output::{Color, OutputFormatter};

use crate::analysis::{ComprehensiveAnalyzer, ReadelfConfig, StringsConfig};
use crate::binary::BinaryAnalyzer;
use crate::libc::{create_matcher, ApiConfig};
use anyhow::{anyhow, Result};
use std::io;
use std::time::Duration;

/// Main CLI application runner
pub struct CliApp {
    args: Args,
}

impl CliApp {
    /// Create a new CLI application with parsed arguments
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    /// Run the CLI application
    pub async fn run(&self) -> Result<i32> {
        match &self.args.command {
            Commands::Analyze {
                file_path,
                min_string_length,
                max_string_length,
                no_external_strings,
                show_stats: _,
                show_strings: _,
                show_symbols: _,
                high_confidence_only: _,
                json_file,
                no_readelf,
                readelf_path,
                readelf_timeout,
                api_timeout,
                max_api_symbols,
            } => {
                self.run_analyze(
                    file_path,
                    *min_string_length,
                    *max_string_length,
                    *no_external_strings,
                    *json_file,
                    *no_readelf,
                    readelf_path.as_deref(),
                    *readelf_timeout,
                    *api_timeout,
                    *max_api_symbols,
                )
                .await
            }
            Commands::TestApi { api_url, timeout } => {
                self.run_test_api(api_url.as_deref(), *timeout).await
            }
            Commands::Formats => self.run_formats().await,
            Commands::Version => self.run_version().await,
            Commands::Tools => self.run_tools().await,
        }
    }

    /// Run the analyze command
    async fn run_analyze(
        &self,
        file_path: &std::path::Path,
        min_string_length: usize,
        max_string_length: usize,
        no_external_strings: bool,
        json_file: bool,
        no_readelf: bool,
        readelf_path: Option<&str>,
        readelf_timeout: u64,
        api_timeout: u64,
        max_api_symbols: usize,
    ) -> Result<i32> {
        // Validate file exists
        if !file_path.exists() {
            return Err(anyhow!("File not found: {}", file_path.display()));
        }

        // Create binary analyzer
        let binary_analyzer = BinaryAnalyzer::new();

        // Check if we can analyze this file
        if !binary_analyzer.can_analyze_file(file_path)? {
            return Err(anyhow!(
                "Unsupported binary format. Supported formats: {}",
                binary_analyzer.supported_formats().join(", ")
            ));
        }

        // Analyze the binary
        let binary_result = binary_analyzer.analyze_file(file_path)?;

        // Read binary data for strings analysis
        let binary_data = std::fs::read(file_path)?;

        // Configure strings extractor
        let strings_config = StringsConfig {
            min_length: min_string_length,
            max_length: max_string_length,
            use_external_strings: !no_external_strings,
            strings_args: vec!["-a".to_string()],
            char_sets: vec![crate::analysis::CharSet::Both],
        };

        // Configure readelf if not disabled
        let analyzer = if no_readelf {
            ComprehensiveAnalyzer::with_config(strings_config)?
        } else {
            let readelf_config = ReadelfConfig {
                readelf_path: readelf_path.unwrap_or("readelf").to_string(),
                timeout_secs: readelf_timeout,
                verbose: self.args.verbose,
            };
            ComprehensiveAnalyzer::with_full_config(strings_config, readelf_config)?
        };

        // Perform comprehensive analysis
        let analysis = analyzer.analyze(
            binary_result,
            &binary_data,
            Some(&file_path.to_string_lossy()),
        )?;

        // Always perform libc detection via API
        let _api_config = ApiConfig {
            timeout: Duration::from_secs(api_timeout),
            max_symbols_per_request: max_api_symbols,
            ..Default::default()
        };

        let detection = match create_matcher() {
            Ok(matcher) => {
                if self.args.verbose {
                    eprintln!("Querying libc database...");
                }
                match matcher.detect_libc_version(&analysis).await {
                    Ok(result) => Some(result),
                    Err(e) => {
                        if self.args.verbose {
                            eprintln!("Warning: Failed to query libc database: {}", e);
                        }
                        None
                    }
                }
            }
            Err(e) => {
                if self.args.verbose {
                    eprintln!("Warning: Failed to create libc matcher: {}", e);
                }
                None
            }
        };

        // Format and output results
        let formatter = OutputFormatter::new(
            self.args.format.clone(),
            !self.args.no_color,
            self.args.verbose,
        );

        // Output to stdout
        let mut stdout = io::stdout();
        formatter.write_analysis_results(&mut stdout, &analysis, detection.as_ref())?;

        // Also output JSON to file if requested
        if json_file {
            let binary_name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            let json_filename = format!("analysis_{}.json", binary_name);

            let json_output = serde_json::json!({
                "binary_info": {
                    "path": analysis.binary_analysis.binary_info.path,
                    "format": analysis.binary_analysis.binary_info.format.to_string(),
                    "architecture": analysis.binary_analysis.binary_info.architecture,
                    "bitness": analysis.binary_analysis.binary_info.bitness,
                    "entry_point": analysis.binary_analysis.binary_info.entry_point,
                    "dependencies": analysis.binary_analysis.binary_info.dependencies
                },
                "symbol_analysis": {
                    "total_symbols": analysis.categorized_symbols.len(),
                    "libc_symbols": analysis.libc_symbols.len(),
                    "version_strings": analysis.version_strings,
                    "symbol_statistics": analysis.symbol_statistics,
                    "all_symbols": analysis.categorized_symbols.iter().map(|categorized| {
                        serde_json::json!({
                            "name": categorized.symbol.name,
                            "address": categorized.symbol.address.map(|a| format!("0x{:x}", a)),
                            "category": format!("{:?}", categorized.category),
                            "confidence": categorized.confidence,
                            "clean_name": categorized.clean_name,
                            "version_info": categorized.version_info
                        })
                    }).collect::<Vec<_>>(),
                    "libc_symbols_detailed": analysis.libc_symbols.iter().map(|categorized| {
                        serde_json::json!({
                            "name": categorized.symbol.name,
                            "address": categorized.symbol.address.map(|a| format!("0x{:x}", a)),
                            "confidence": categorized.confidence,
                            "clean_name": categorized.clean_name,
                            "category": format!("{:?}", categorized.category),
                            "version_info": categorized.version_info
                        })
                    }).collect::<Vec<_>>(),
                    "all_strings": analysis.filtered_strings
                },
                "libc_detection": detection.map(|d| serde_json::json!({
                    "best_confidence": d.best_confidence,
                    "strategy": format!("{:?}", d.strategy),
                    "symbols_analyzed": d.symbols_analyzed,
                    "readelf_enhanced": analysis.binary_analysis.binary_info.format.to_string() == "ELF" &&
                        analysis.filtered_strings.iter().any(|s| s.contains("Build ID:") || s.contains("/lib")),
                    "matches": d.matches.iter().map(|m| serde_json::json!({
                        "name": m.libc_match.name,
                        "version": m.libc_match.version,
                        "architecture": m.libc_match.arch,
                        "os": m.libc_match.os,
                        "overall_score": m.overall_score,
                        "symbol_score": m.symbol_score,
                        "symbols_matched": m.libc_match.symbols_matched,
                        "matched_symbols": m.libc_match.matched_symbols,
                        "confidence": m.libc_match.confidence
                    })).collect::<Vec<_>>(),
                    "warnings": d.warnings
                }))
            });

            std::fs::write(&json_filename, serde_json::to_string_pretty(&json_output)?)?;

            if self.args.verbose || self.args.format == crate::cli::OutputFormat::Pretty {
                eprintln!("📄 JSON analysis saved to: {}", json_filename);
            }
        }

        Ok(0)
    }

    /// Run the test-api command
    async fn run_test_api(&self, api_url: Option<&str>, timeout: u64) -> Result<i32> {
        let api_config = if let Some(url) = api_url {
            ApiConfig {
                base_url: url.to_string(),
                timeout: Duration::from_secs(timeout),
                ..Default::default()
            }
        } else {
            ApiConfig {
                timeout: Duration::from_secs(timeout),
                ..Default::default()
            }
        };

        let formatter = OutputFormatter::new(
            self.args.format.clone(),
            !self.args.no_color,
            self.args.verbose,
        );

        match crate::libc::create_matcher_with_config(api_config) {
            Ok(matcher) => {
                if self.args.verbose {
                    eprintln!("Testing connection to libc database...");
                }

                match matcher.api_client().test_connection().await {
                    Ok(true) => {
                        let mut stdout = io::stdout();
                        formatter.write_api_test_result(
                            &mut stdout,
                            true,
                            "Successfully connected to libc database",
                        )?;
                        Ok(0)
                    }
                    Ok(false) => {
                        let mut stdout = io::stdout();
                        formatter.write_api_test_result(
                            &mut stdout,
                            false,
                            "API returned non-success status",
                        )?;
                        Ok(1)
                    }
                    Err(e) => {
                        let mut stdout = io::stdout();
                        formatter.write_api_test_result(
                            &mut stdout,
                            false,
                            &format!("Connection failed: {}", e),
                        )?;
                        Ok(1)
                    }
                }
            }
            Err(e) => {
                let mut stdout = io::stdout();
                formatter.write_api_test_result(
                    &mut stdout,
                    false,
                    &format!("Failed to create API client: {}", e),
                )?;
                Ok(1)
            }
        }
    }

    /// Run the formats command
    async fn run_formats(&self) -> Result<i32> {
        let formatter = OutputFormatter::new(
            self.args.format.clone(),
            !self.args.no_color,
            self.args.verbose,
        );

        let mut stdout = io::stdout();
        formatter.write_formats_info(&mut stdout)?;
        Ok(0)
    }

    /// Run the version command
    async fn run_version(&self) -> Result<i32> {
        match self.args.format {
            OutputFormat::Json => {
                let version_info = serde_json::json!({
                    "name": env!("CARGO_PKG_NAME"),
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": env!("CARGO_PKG_DESCRIPTION"),
                    "authors": env!("CARGO_PKG_AUTHORS").split(':').collect::<Vec<_>>(),
                    "repository": env!("CARGO_PKG_REPOSITORY"),
                });
                println!("{}", serde_json::to_string_pretty(&version_info)?);
            }
            _ => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                println!("{}", env!("CARGO_PKG_DESCRIPTION"));
                if self.args.verbose {
                    println!("Authors: {}", env!("CARGO_PKG_AUTHORS"));
                    if !env!("CARGO_PKG_REPOSITORY").is_empty() {
                        println!("Repository: {}", env!("CARGO_PKG_REPOSITORY"));
                    }
                }
            }
        }
        Ok(0)
    }

    /// Run the tools command to check external tool availability
    async fn run_tools(&self) -> Result<i32> {
        let formatter = OutputFormatter::new(
            self.args.format.clone(),
            !self.args.no_color,
            self.args.verbose,
        );

        match self.args.format {
            OutputFormat::Json => {
                let tools_info = serde_json::json!({
                    "external_tools": {
                        "readelf": {
                            "available": crate::analysis::ReadelfAnalyzer::default()
                                .map(|analyzer| analyzer.is_available())
                                .unwrap_or(false),
                            "command": "readelf",
                            "description": "GNU readelf - displays information about ELF files"
                        },
                        "strings": {
                            "available": crate::analysis::StringsExtractor::is_strings_available(),
                            "command": "strings",
                            "description": "Extracts printable strings from binary files"
                        }
                    }
                });
                println!("{}", serde_json::to_string_pretty(&tools_info)?);
            }
            _ => {
                let readelf_available = crate::analysis::ReadelfAnalyzer::default()
                    .map(|analyzer| analyzer.is_available())
                    .unwrap_or(false);
                let strings_available = crate::analysis::StringsExtractor::is_strings_available();

                println!(
                    "{}",
                    formatter.colorize("External Tools Status", crate::cli::Color::Cyan)
                );
                println!("{}", "=".repeat(25));
                println!();

                // Readelf status
                let readelf_status = if readelf_available {
                    formatter.colorize("✓ Available", crate::cli::Color::Green)
                } else {
                    formatter.colorize("✗ Not found", crate::cli::Color::Red)
                };
                println!("readelf: {}", readelf_status);
                println!("  Description: GNU readelf - displays information about ELF files");
                println!(
                    "  Used for: Enhanced ELF analysis, version information, symbol versioning"
                );

                if !readelf_available {
                    println!("  Install with: sudo apt install binutils (Ubuntu/Debian)");
                    println!("               sudo yum install binutils (RHEL/CentOS)");
                }
                println!();

                // Strings status
                let strings_status = if strings_available {
                    formatter.colorize("✓ Available", crate::cli::Color::Green)
                } else {
                    formatter.colorize("✗ Not found", crate::cli::Color::Red)
                };
                println!("strings: {}", strings_status);
                println!("  Description: Extracts printable strings from binary files");
                println!("  Used for: Additional string extraction, complement to built-in parser");

                if !strings_available {
                    println!("  Install with: sudo apt install binutils (Ubuntu/Debian)");
                    println!("               sudo yum install binutils (RHEL/CentOS)");
                }
                println!();

                if readelf_available && strings_available {
                    println!(
                        "{}",
                        formatter.colorize(
                            "All external tools are available!",
                            crate::cli::Color::Green
                        )
                    );
                } else {
                    println!("{}", formatter.colorize("Some external tools are missing. The tool will work with reduced functionality.", crate::cli::Color::Yellow));
                }
            }
        }

        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{Commands, OutputFormat};
    use std::path::PathBuf;

    #[test]
    fn test_cli_app_creation() {
        let args = Args {
            command: Commands::Version,
            verbose: false,
            format: OutputFormat::Pretty,
            no_color: false,
        };

        let app = CliApp::new(args);
        assert!(!app.args.verbose);
    }

    #[tokio::test]
    async fn test_version_command() {
        let args = Args {
            command: Commands::Version,
            verbose: false,
            format: OutputFormat::Pretty,
            no_color: true,
        };

        let app = CliApp::new(args);
        let result = app.run_version().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_formats_command() {
        let args = Args {
            command: Commands::Formats,
            verbose: false,
            format: OutputFormat::Pretty,
            no_color: true,
        };

        let app = CliApp::new(args);
        let result = app.run_formats().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
