//! Binary analysis module
//!
//! This module provides functionality for parsing and analyzing different binary formats
//! including ELF and PE files. It automatically detects the format and uses the
//! appropriate parser.

use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

pub mod common;
pub mod elf;
pub mod pe;

pub use common::{
    clean_symbol_name, extract_version_from_symbol, is_libc_symbol, AnalysisResult, BinaryFormat,
    BinaryInfo, BinaryParser, Symbol, SymbolType,
};
pub use elf::ElfParser;
pub use pe::PeParser;

/// Main binary analyzer that can handle multiple formats
pub struct BinaryAnalyzer {
    parsers: Vec<Box<dyn BinaryParser>>,
}

impl BinaryAnalyzer {
    /// Create a new binary analyzer with all supported parsers
    pub fn new() -> Self {
        let parsers: Vec<Box<dyn BinaryParser>> =
            vec![Box::new(ElfParser::new()), Box::new(PeParser::new())];

        Self { parsers }
    }

    /// Analyze a binary file from a file path
    pub fn analyze_file<P: AsRef<Path>>(&self, file_path: P) -> Result<AnalysisResult> {
        let path = file_path.as_ref();
        let data = fs::read(path)
            .map_err(|e| anyhow!("Failed to read file '{}': {}", path.display(), e))?;

        self.analyze_data(&data, &path.to_string_lossy())
    }

    /// Analyze binary data directly
    pub fn analyze_data(&self, data: &[u8], file_path: &str) -> Result<AnalysisResult> {
        // Find a parser that can handle this binary format
        for parser in &self.parsers {
            if parser.can_parse(data) {
                return parser.parse(data, file_path);
            }
        }

        Err(anyhow!(
            "No parser found for binary format. Supported formats: ELF, PE"
        ))
    }

    /// Get information about supported binary formats
    pub fn supported_formats(&self) -> Vec<String> {
        self.parsers.iter().map(|p| p.name().to_string()).collect()
    }

    /// Check if a file can be analyzed (without actually parsing it)
    pub fn can_analyze_file<P: AsRef<Path>>(&self, file_path: P) -> Result<bool> {
        let path = file_path.as_ref();
        let mut buffer = vec![0u8; 512]; // Read first 512 bytes for format detection

        let file = fs::File::open(path)
            .map_err(|e| anyhow!("Failed to open file '{}': {}", path.display(), e))?;

        use std::io::Read;
        let mut reader = std::io::BufReader::new(file);
        let bytes_read = reader
            .read(&mut buffer)
            .map_err(|e| anyhow!("Failed to read from file '{}': {}", path.display(), e))?;

        buffer.truncate(bytes_read);
        Ok(self.can_analyze_data(&buffer))
    }

    /// Check if binary data can be analyzed
    pub fn can_analyze_data(&self, data: &[u8]) -> bool {
        self.parsers.iter().any(|parser| parser.can_parse(data))
    }

    /// Get detected binary format without full parsing
    pub fn detect_format(&self, data: &[u8]) -> Option<BinaryFormat> {
        for parser in &self.parsers {
            if parser.can_parse(data) {
                return match parser.name() {
                    "ELF Parser" => Some(BinaryFormat::ELF),
                    "PE Parser" => Some(BinaryFormat::PE),
                    _ => Some(BinaryFormat::Unknown),
                };
            }
        }
        None
    }
}

impl Default for BinaryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to filter symbols that are likely to be libc functions
pub fn filter_libc_symbols(symbols: &[Symbol]) -> Vec<Symbol> {
    symbols
        .iter()
        .filter(|sym| is_libc_symbol(&sym.name))
        .cloned()
        .collect()
}

/// Helper function to extract unique function names from symbols
pub fn extract_function_names(symbols: &[Symbol]) -> Vec<String> {
    let mut names: Vec<String> = symbols
        .iter()
        .filter(|sym| sym.symbol_type == SymbolType::Function)
        .map(|sym| clean_symbol_name(&sym.name))
        .collect();

    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_binary_analyzer_creation() {
        let analyzer = BinaryAnalyzer::new();
        let formats = analyzer.supported_formats();

        assert!(formats.contains(&"ELF Parser".to_string()));
        assert!(formats.contains(&"PE Parser".to_string()));
    }

    #[test]
    fn test_format_detection() {
        let analyzer = BinaryAnalyzer::new();

        // Test ELF detection
        let elf_data = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(analyzer.detect_format(elf_data), Some(BinaryFormat::ELF));

        // Test PE detection
        let mut pe_data = vec![0u8; 256];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        let pe_offset = 128u32;
        pe_data[60..64].copy_from_slice(&pe_offset.to_le_bytes());
        pe_data[128..132].copy_from_slice(b"PE\x00\x00");
        assert_eq!(analyzer.detect_format(&pe_data), Some(BinaryFormat::PE));

        // Test unknown format
        let unknown_data = b"UNKNOWN";
        assert_eq!(analyzer.detect_format(unknown_data), None);
    }

    #[test]
    fn test_filter_libc_symbols() {
        let symbols = vec![
            Symbol {
                name: "printf".to_string(),
                address: Some(0x1000),
                is_import: true,
                section: None,
                symbol_type: SymbolType::Function,
            },
            Symbol {
                name: "custom_function".to_string(),
                address: Some(0x2000),
                is_import: false,
                section: None,
                symbol_type: SymbolType::Function,
            },
            Symbol {
                name: "malloc".to_string(),
                address: Some(0x3000),
                is_import: true,
                section: None,
                symbol_type: SymbolType::Function,
            },
        ];

        let libc_symbols = filter_libc_symbols(&symbols);
        assert_eq!(libc_symbols.len(), 2);
        assert!(libc_symbols.iter().any(|s| s.name == "printf"));
        assert!(libc_symbols.iter().any(|s| s.name == "malloc"));
        assert!(!libc_symbols.iter().any(|s| s.name == "custom_function"));
    }

    #[test]
    fn test_extract_function_names() {
        let symbols = vec![
            Symbol {
                name: "printf@@GLIBC_2.2.5".to_string(),
                address: Some(0x1000),
                is_import: true,
                section: None,
                symbol_type: SymbolType::Function,
            },
            Symbol {
                name: "malloc@GLIBC_2.1".to_string(),
                address: Some(0x2000),
                is_import: true,
                section: None,
                symbol_type: SymbolType::Function,
            },
            Symbol {
                name: "data_object".to_string(),
                address: Some(0x3000),
                is_import: false,
                section: None,
                symbol_type: SymbolType::Object,
            },
        ];

        let function_names = extract_function_names(&symbols);
        assert_eq!(function_names.len(), 2);
        assert!(function_names.contains(&"printf".to_string()));
        assert!(function_names.contains(&"malloc".to_string()));
        assert!(!function_names.contains(&"data_object".to_string()));
    }
}
