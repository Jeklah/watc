//! CLI output formatting module
//!
//! This module provides various output formatters for displaying analysis results
//! in different formats (pretty, JSON, CSV, simple text).

use crate::analysis::ComprehensiveAnalysis;
use crate::binary::{AnalysisResult, BinaryFormat};
use crate::cli::args::OutputFormat;
use crate::libc::DetectionResult;
use anyhow::Result;
use colored::*;
use serde_json;
use std::io::Write;

/// Main output formatter that handles different formats
pub struct OutputFormatter {
    format: OutputFormat,
    use_color: bool,
    verbose: bool,
}

impl OutputFormatter {
    /// Create a new output formatter
    pub fn new(format: OutputFormat, use_color: bool, verbose: bool) -> Self {
        Self {
            format,
            use_color,
            verbose,
        }
    }

    /// Format and write analysis results
    pub fn write_analysis_results<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
        detection: Option<&DetectionResult>,
    ) -> Result<()> {
        match self.format {
            OutputFormat::Pretty => self.write_pretty_output(writer, analysis, detection),
            OutputFormat::Json => self.write_json_output(writer, analysis, detection),
            OutputFormat::Csv => self.write_csv_output(writer, analysis, detection),
            OutputFormat::Simple => self.write_simple_output(writer, analysis, detection),
        }
    }

    /// Write API test results
    pub fn write_api_test_result<W: Write>(
        &self,
        writer: &mut W,
        success: bool,
        message: &str,
    ) -> Result<()> {
        match self.format {
            OutputFormat::Json => {
                let result = serde_json::json!({
                    "api_test": {
                        "success": success,
                        "message": message
                    }
                });
                writeln!(writer, "{}", serde_json::to_string_pretty(&result)?)?;
            }
            _ => {
                let status = if success {
                    self.colorize("✓ SUCCESS", Color::Green)
                } else {
                    self.colorize("✗ FAILED", Color::Red)
                };
                writeln!(writer, "API Test: {} - {}", status, message)?;
            }
        }
        Ok(())
    }

    /// Write supported formats information
    pub fn write_formats_info<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self.format {
            OutputFormat::Json => {
                let info = serde_json::json!({
                    "supported_formats": [
                        {
                            "name": "ELF",
                            "description": "Executable and Linkable Format (Linux, Unix)",
                            "extensions": [".so", ".out", ""]
                        },
                        {
                            "name": "PE",
                            "description": "Portable Executable (Windows)",
                            "extensions": [".exe", ".dll"]
                        }
                    ]
                });
                writeln!(writer, "{}", serde_json::to_string_pretty(&info)?)?;
            }
            _ => {
                writeln!(
                    writer,
                    "{}",
                    self.colorize("Supported Binary Formats:", Color::Blue)
                )?;
                writeln!(writer)?;
                writeln!(
                    writer,
                    "  {} - Executable and Linkable Format",
                    self.colorize("ELF", Color::Green)
                )?;
                writeln!(writer, "    Used on: Linux, Unix systems")?;
                writeln!(writer, "    Extensions: .so, .out, (no extension)")?;
                writeln!(writer)?;
                writeln!(
                    writer,
                    "  {} - Portable Executable",
                    self.colorize("PE", Color::Green)
                )?;
                writeln!(writer, "    Used on: Windows systems")?;
                writeln!(writer, "    Extensions: .exe, .dll")?;
            }
        }
        Ok(())
    }

    /// Write pretty-formatted output
    fn write_pretty_output<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
        detection: Option<&DetectionResult>,
    ) -> Result<()> {
        self.write_header(writer)?;
        self.write_binary_info(writer, &analysis.binary_analysis)?;
        self.write_symbol_summary(writer, analysis)?;

        if self.verbose {
            self.write_detailed_symbols(writer, analysis)?;
        }

        if let Some(detection) = detection {
            self.write_detection_results(writer, detection)?;
        } else {
            writeln!(
                writer,
                "\n{}",
                self.colorize(
                    "⚠ No libc detection performed (offline mode)",
                    Color::Yellow
                )
            )?;
        }

        if !analysis.version_strings.is_empty() {
            self.write_version_strings(writer, &analysis.version_strings)?;
        }

        // Show readelf information if ELF format
        if analysis.binary_analysis.binary_info.format == crate::binary::BinaryFormat::ELF {
            self.write_readelf_info(writer, analysis)?;
        }

        if !detection
            .as_ref()
            .map_or(Vec::new(), |d| d.warnings.clone())
            .is_empty()
        {
            self.write_warnings(writer, &detection.unwrap().warnings)?;
        }

        Ok(())
    }

    /// Write JSON output
    fn write_json_output<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
        detection: Option<&DetectionResult>,
    ) -> Result<()> {
        let output = serde_json::json!({
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

        writeln!(writer, "{}", serde_json::to_string_pretty(&output)?)?;
        Ok(())
    }

    /// Write CSV output
    fn write_csv_output<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
        detection: Option<&DetectionResult>,
    ) -> Result<()> {
        // Write header
        writeln!(
            writer,
            "binary_path,format,architecture,bitness,total_symbols,libc_symbols,best_match_name,best_match_version,best_confidence"
        )?;

        let best_match = detection.and_then(|d| d.matches.first());

        writeln!(
            writer,
            "\"{}\",{},{},{},{},{},\"{}\",\"{}\",{:.3}",
            analysis.binary_analysis.binary_info.path,
            analysis.binary_analysis.binary_info.format,
            analysis.binary_analysis.binary_info.architecture,
            analysis.binary_analysis.binary_info.bitness,
            analysis.categorized_symbols.len(),
            analysis.libc_symbols.len(),
            best_match
                .map(|m| &m.libc_match.name)
                .unwrap_or(&"Unknown".to_string()),
            best_match
                .and_then(|m| m.libc_match.version.as_ref())
                .unwrap_or(&"Unknown".to_string()),
            best_match.map(|m| m.overall_score).unwrap_or(0.0)
        )?;

        Ok(())
    }

    /// Write simple text output
    fn write_simple_output<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
        detection: Option<&DetectionResult>,
    ) -> Result<()> {
        writeln!(
            writer,
            "Binary: {}",
            analysis.binary_analysis.binary_info.path
        )?;
        writeln!(
            writer,
            "Format: {}",
            analysis.binary_analysis.binary_info.format
        )?;
        writeln!(
            writer,
            "Architecture: {}",
            analysis.binary_analysis.binary_info.architecture
        )?;
        writeln!(
            writer,
            "Symbols found: {}",
            analysis.categorized_symbols.len()
        )?;
        writeln!(writer, "Libc symbols: {}", analysis.libc_symbols.len())?;

        if let Some(detection) = detection {
            if let Some(best_match) = detection.matches.first() {
                writeln!(writer, "Best match: {}", best_match.libc_match.name)?;
                if let Some(ref version) = best_match.libc_match.version {
                    writeln!(writer, "Version: {}", version)?;
                }
                writeln!(
                    writer,
                    "Confidence: {:.1}%",
                    best_match.overall_score * 100.0
                )?;
            } else {
                writeln!(writer, "No matches found")?;
            }
        }

        Ok(())
    }

    /// Write header information
    fn write_header<W: Write>(&self, writer: &mut W) -> Result<()> {
        writeln!(
            writer,
            "{}",
            self.colorize("🔍 Binary Analysis Results", Color::Cyan)
        )?;
        writeln!(writer, "{}", "=".repeat(50))?;
        Ok(())
    }

    /// Write binary information section
    fn write_binary_info<W: Write>(&self, writer: &mut W, analysis: &AnalysisResult) -> Result<()> {
        writeln!(writer)?;
        writeln!(
            writer,
            "{}",
            self.colorize("📁 Binary Information", Color::Blue)
        )?;
        writeln!(writer, "Path: {}", analysis.binary_info.path)?;
        writeln!(
            writer,
            "Format: {}",
            self.format_binary_format(&analysis.binary_info.format)
        )?;
        writeln!(
            writer,
            "Architecture: {}",
            analysis.binary_info.architecture
        )?;
        writeln!(writer, "Bitness: {}-bit", analysis.binary_info.bitness)?;

        if let Some(entry_point) = analysis.binary_info.entry_point {
            writeln!(writer, "Entry Point: 0x{:x}", entry_point)?;
        }

        if !analysis.binary_info.dependencies.is_empty() {
            writeln!(writer, "Dependencies:")?;
            for dep in &analysis.binary_info.dependencies {
                writeln!(writer, "  - {}", dep)?;
            }
        }

        Ok(())
    }

    /// Write symbol summary
    fn write_symbol_summary<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
    ) -> Result<()> {
        writeln!(writer)?;
        writeln!(
            writer,
            "{}",
            self.colorize("🔤 Symbol Analysis", Color::Blue)
        )?;
        writeln!(
            writer,
            "Total symbols found: {}",
            analysis.categorized_symbols.len()
        )?;
        writeln!(
            writer,
            "Libc-related symbols: {}",
            analysis.libc_symbols.len()
        )?;
        writeln!(
            writer,
            "Version strings found: {}",
            analysis.version_strings.len()
        )?;

        if !analysis.symbol_statistics.is_empty() {
            writeln!(writer, "\nSymbol categories:")?;
            let mut stats: Vec<_> = analysis.symbol_statistics.iter().collect();
            stats.sort_by(|a, b| b.1.cmp(a.1));

            for (category, count) in stats {
                writeln!(writer, "  {:?}: {}", category, count)?;
            }
        }

        Ok(())
    }

    /// Write detailed symbols information
    fn write_detailed_symbols<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
    ) -> Result<()> {
        if !analysis.libc_symbols.is_empty() {
            writeln!(writer)?;
            writeln!(
                writer,
                "{}",
                self.colorize("📋 High-Confidence Libc Symbols", Color::Blue)
            )?;

            let mut symbols = analysis.libc_symbols.clone();
            symbols.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

            for symbol in symbols.iter().take(20) {
                let confidence_color = if symbol.confidence >= 0.8 {
                    Color::Green
                } else if symbol.confidence >= 0.5 {
                    Color::Yellow
                } else {
                    Color::Red
                };

                writeln!(
                    writer,
                    "  {} {} (confidence: {})",
                    symbol.clean_name,
                    format!("[{:?}]", symbol.category),
                    self.colorize(
                        &format!("{:.1}%", symbol.confidence * 100.0),
                        confidence_color
                    )
                )?;
            }
        }

        Ok(())
    }

    /// Write detection results
    fn write_detection_results<W: Write>(
        &self,
        writer: &mut W,
        detection: &DetectionResult,
    ) -> Result<()> {
        writeln!(writer)?;
        writeln!(
            writer,
            "{}",
            self.colorize("🎯 Libc Detection Results", Color::Blue)
        )?;
        writeln!(writer, "Detection strategy: {:?}", detection.strategy)?;
        writeln!(writer, "Symbols analyzed: {}", detection.symbols_analyzed)?;
        writeln!(
            writer,
            "Best confidence: {:.1}%",
            detection.best_confidence * 100.0
        )?;

        if detection.matches.is_empty() {
            writeln!(
                writer,
                "\n{}",
                self.colorize("No libc matches found", Color::Red)
            )?;
            return Ok(());
        }

        writeln!(writer, "\n{}", self.colorize("Top matches:", Color::Green))?;

        for (i, match_result) in detection.matches.iter().take(5).enumerate() {
            let rank_color = match i {
                0 => Color::Green,
                1 => Color::Yellow,
                _ => Color::White,
            };

            writeln!(writer)?;
            writeln!(
                writer,
                "{}. {} {}",
                i + 1,
                self.colorize(&match_result.libc_match.name, rank_color),
                self.colorize(
                    &format!("({:.1}%)", match_result.overall_score * 100.0),
                    rank_color
                )
            )?;

            if let Some(ref version) = match_result.libc_match.version {
                writeln!(writer, "   Version: {}", version)?;
            }
            if let Some(ref arch) = match_result.libc_match.arch {
                writeln!(writer, "   Architecture: {}", arch)?;
            }
            if let Some(ref os) = match_result.libc_match.os {
                writeln!(writer, "   OS: {}", os)?;
            }

            writeln!(
                writer,
                "   Symbols matched: {}",
                match_result.libc_match.symbols_matched
            )?;

            if let Some(ref download_url) = match_result.libc_match.download_url {
                writeln!(
                    writer,
                    "   {}",
                    self.colorize(&format!("Download: {}", download_url), Color::Cyan)
                )?;
            }

            if self.verbose && !match_result.libc_match.matched_symbols.is_empty() {
                writeln!(
                    writer,
                    "   Matched symbols: {}",
                    match_result.libc_match.matched_symbols.join(", ")
                )?;
            }
        }

        Ok(())
    }

    /// Write version strings
    fn write_version_strings<W: Write>(
        &self,
        writer: &mut W,
        version_strings: &[String],
    ) -> Result<()> {
        writeln!(writer)?;
        writeln!(
            writer,
            "{}",
            self.colorize("📄 Version Strings", Color::Blue)
        )?;
        for version_str in version_strings {
            writeln!(writer, "  {}", version_str)?;
        }
        Ok(())
    }

    /// Write readelf information for ELF files
    fn write_readelf_info<W: Write>(
        &self,
        writer: &mut W,
        analysis: &ComprehensiveAnalysis,
    ) -> Result<()> {
        if self.verbose {
            writeln!(writer)?;
            writeln!(
                writer,
                "{}",
                self.colorize("🔧 Enhanced ELF Analysis", Color::Blue)
            )?;

            // Check if readelf was used by looking for enhanced strings
            let has_enhanced_info = analysis
                .filtered_strings
                .iter()
                .any(|s| s.contains("Build ID:") || s.contains("/lib") || s.contains("ld-"));

            if has_enhanced_info {
                writeln!(writer, "Enhanced analysis using readelf: ✓")?;

                // Show some readelf-specific findings
                let readelf_strings: Vec<&String> = analysis
                    .filtered_strings
                    .iter()
                    .filter(|s| {
                        s.contains("Build ID:") || s.contains("/lib64/ld-") || s.contains("GCC:")
                    })
                    .collect();

                if !readelf_strings.is_empty() {
                    writeln!(writer, "Additional information found:")?;
                    for string in readelf_strings.iter().take(5) {
                        writeln!(writer, "  {}", string)?;
                    }
                }
            } else {
                writeln!(
                    writer,
                    "{}",
                    self.colorize(
                        "Readelf not available - install binutils for enhanced ELF analysis",
                        Color::Yellow
                    )
                )?;
            }
        }

        Ok(())
    }

    /// Write warnings
    fn write_warnings<W: Write>(&self, writer: &mut W, warnings: &[String]) -> Result<()> {
        if !warnings.is_empty() {
            writeln!(writer)?;
            writeln!(writer, "{}", self.colorize("⚠️  Warnings", Color::Yellow))?;
            for warning in warnings {
                writeln!(writer, "  {}", warning)?;
            }
        }
        Ok(())
    }

    /// Format binary format with color
    fn format_binary_format(&self, format: &BinaryFormat) -> String {
        let color = match format {
            BinaryFormat::ELF => Color::Green,
            BinaryFormat::PE => Color::Blue,
            BinaryFormat::MachO => Color::Magenta,
            BinaryFormat::Unknown => Color::Red,
        };
        self.colorize(&format.to_string(), color)
    }

    /// Apply color to text if colors are enabled
    pub fn colorize(&self, text: &str, color: Color) -> String {
        if self.use_color {
            match color {
                Color::Red => text.red().to_string(),
                Color::Green => text.green().to_string(),
                Color::Yellow => text.yellow().to_string(),
                Color::Blue => text.blue().to_string(),
                Color::Magenta => text.magenta().to_string(),
                Color::Cyan => text.cyan().to_string(),
                Color::White => text.white().to_string(),
                Color::Black => text.black().to_string(),
                Color::BrightRed => text.bright_red().to_string(),
                Color::BrightGreen => text.bright_green().to_string(),
                Color::BrightYellow => text.bright_yellow().to_string(),
                Color::BrightBlue => text.bright_blue().to_string(),
                Color::BrightMagenta => text.bright_magenta().to_string(),
                Color::BrightCyan => text.bright_cyan().to_string(),
                Color::BrightWhite => text.bright_white().to_string(),
                Color::BrightBlack => text.bright_black().to_string(),
            }
        } else {
            text.to_string()
        }
    }
}

/// Color enumeration for output formatting
#[derive(Debug, Clone, Copy)]
pub enum Color {
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    Black,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite,
    BrightBlack,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::SymbolCategory;
    use crate::binary::common::{BinaryInfo, Symbol, SymbolType};
    use std::collections::{HashMap, HashSet};

    fn create_test_analysis() -> ComprehensiveAnalysis {
        let binary_info = BinaryInfo {
            path: "/test/binary".to_string(),
            format: BinaryFormat::ELF,
            architecture: "x86_64".to_string(),
            bitness: 64,
            entry_point: Some(0x1000),
            dependencies: vec!["libc.so.6".to_string()],
        };

        let mut symbol_statistics = HashMap::new();
        symbol_statistics.insert(SymbolCategory::LibcStandard, 5);
        symbol_statistics.insert(SymbolCategory::Memory, 3);

        ComprehensiveAnalysis {
            binary_analysis: AnalysisResult {
                binary_info,
                symbols: HashSet::new(),
                imported_functions: HashSet::new(),
                strings: HashSet::new(),
                errors: Vec::new(),
            },
            categorized_symbols: Vec::new(),
            libc_symbols: Vec::new(),
            version_strings: vec!["GLIBC_2.31".to_string()],
            filtered_strings: HashSet::new(),
            symbol_statistics,
        }
    }

    #[test]
    fn test_formatter_creation() {
        let formatter = OutputFormatter::new(OutputFormat::Pretty, true, false);
        assert_eq!(formatter.format, OutputFormat::Pretty);
        assert!(formatter.use_color);
        assert!(!formatter.verbose);
    }

    #[test]
    fn test_json_output() {
        let formatter = OutputFormatter::new(OutputFormat::Json, false, false);
        let analysis = create_test_analysis();
        let mut buffer = Vec::new();

        let result = formatter.write_analysis_results(&mut buffer, &analysis, None);
        assert!(result.is_ok());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("binary_info"));
        assert!(output.contains("symbol_analysis"));
        assert!(output.contains("/test/binary"));
    }

    #[test]
    fn test_csv_output() {
        let formatter = OutputFormatter::new(OutputFormat::Csv, false, false);
        let analysis = create_test_analysis();
        let mut buffer = Vec::new();

        let result = formatter.write_analysis_results(&mut buffer, &analysis, None);
        assert!(result.is_ok());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("binary_path,format"));
        assert!(output.contains("/test/binary"));
        assert!(output.contains("ELF"));
    }

    #[test]
    fn test_colorize() {
        let formatter = OutputFormatter::new(OutputFormat::Pretty, true, false);
        let colored_text = formatter.colorize("test", Color::Red);
        // When colors are enabled, the text should contain ANSI escape codes
        assert!(colored_text.len() > 4); // "test" + ANSI codes

        let formatter_no_color = OutputFormatter::new(OutputFormat::Pretty, false, false);
        let plain_text = formatter_no_color.colorize("test", Color::Red);
        assert_eq!(plain_text, "test");
    }

    #[test]
    fn test_api_test_result_json() {
        let formatter = OutputFormatter::new(OutputFormat::Json, false, false);
        let mut buffer = Vec::new();

        let result = formatter.write_api_test_result(&mut buffer, true, "Connection successful");
        assert!(result.is_ok());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("api_test"));
        assert!(output.contains("success"));
        assert!(output.contains("true"));
    }
}
