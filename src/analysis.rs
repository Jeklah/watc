//! Analysis module for binary symbol and string analysis
//!
//! This module provides comprehensive analysis capabilities for extracting
//! and categorizing symbols and strings from binary files.

pub mod readelf;
pub mod strings;
pub mod symbols;

pub use readelf::{ReadelfAnalyzer, ReadelfConfig, ReadelfInfo};
pub use strings::{CharSet, StringsConfig, StringsExtractor};
pub use symbols::{CategorizedSymbol, SymbolAnalyzer, SymbolCategory};

use crate::binary::{AnalysisResult, Symbol};
use anyhow::Result;
use std::collections::HashSet;

/// Comprehensive analysis results combining symbols and strings
#[derive(Debug, Clone)]
pub struct ComprehensiveAnalysis {
    /// Original analysis result from binary parser
    pub binary_analysis: AnalysisResult,
    /// Categorized symbols with confidence scores
    pub categorized_symbols: Vec<CategorizedSymbol>,
    /// High-confidence libc symbols
    pub libc_symbols: Vec<CategorizedSymbol>,
    /// Version strings found in the binary
    pub version_strings: Vec<String>,
    /// All extracted strings (filtered)
    pub filtered_strings: HashSet<String>,
    /// Statistics about symbol categories
    pub symbol_statistics: std::collections::HashMap<SymbolCategory, usize>,
}

/// Main analyzer that combines symbol and string analysis
pub struct ComprehensiveAnalyzer {
    symbol_analyzer: SymbolAnalyzer,
    strings_extractor: StringsExtractor,
    readelf_analyzer: Option<ReadelfAnalyzer>,
}

impl ComprehensiveAnalyzer {
    /// Create a new comprehensive analyzer with default settings
    pub fn new() -> Result<Self> {
        let readelf_analyzer = ReadelfAnalyzer::default().ok();

        Ok(Self {
            symbol_analyzer: SymbolAnalyzer::new()?,
            strings_extractor: StringsExtractor::default()?,
            readelf_analyzer,
        })
    }

    /// Create a new analyzer with custom configurations
    pub fn with_config(strings_config: StringsConfig) -> Result<Self> {
        let readelf_analyzer = ReadelfAnalyzer::default().ok();

        Ok(Self {
            symbol_analyzer: SymbolAnalyzer::new()?,
            strings_extractor: StringsExtractor::new(strings_config)?,
            readelf_analyzer,
        })
    }

    /// Create a new analyzer with custom configurations including readelf
    pub fn with_full_config(
        strings_config: StringsConfig,
        readelf_config: ReadelfConfig,
    ) -> Result<Self> {
        let readelf_analyzer = ReadelfAnalyzer::new(readelf_config).ok();

        Ok(Self {
            symbol_analyzer: SymbolAnalyzer::new()?,
            strings_extractor: StringsExtractor::new(strings_config)?,
            readelf_analyzer,
        })
    }

    /// Perform comprehensive analysis on binary analysis results
    pub fn analyze(
        &self,
        binary_result: AnalysisResult,
        binary_data: &[u8],
        file_path: Option<&str>,
    ) -> Result<ComprehensiveAnalysis> {
        // Convert symbols to vector for analysis
        let symbols: Vec<Symbol> = binary_result.symbols.iter().cloned().collect();

        // Analyze symbols
        let categorized_symbols = self.symbol_analyzer.analyze_symbols(&symbols);

        // Get high-confidence libc symbols
        let libc_symbols = self
            .symbol_analyzer
            .get_high_confidence_symbols(&categorized_symbols, 0.7);

        // Generate symbol statistics
        let symbol_statistics = self
            .symbol_analyzer
            .generate_statistics(&categorized_symbols);

        // Extract strings from binary
        let filtered_strings = self
            .strings_extractor
            .extract_strings(binary_data, file_path)?;

        // Extract version strings
        let mut version_strings = self
            .strings_extractor
            .extract_version_strings(&filtered_strings);

        // Enhanced analysis with readelf if available and dealing with ELF files
        let mut enhanced_strings = filtered_strings.clone();
        let mut enhanced_symbols = HashMap::new();

        if binary_result.binary_info.format == crate::binary::BinaryFormat::ELF {
            if let (Some(readelf), Some(path)) = (&self.readelf_analyzer, file_path) {
                if let Ok(readelf_info) = readelf.analyze_elf(path) {
                    // Merge readelf information
                    crate::analysis::readelf::merge_readelf_info(
                        &mut enhanced_strings,
                        &mut enhanced_symbols,
                        &readelf_info,
                    );

                    // Add readelf version strings
                    version_strings.extend(readelf_info.gnu_version_info);
                    version_strings.sort();
                    version_strings.dedup();
                }
            }
        }

        Ok(ComprehensiveAnalysis {
            binary_analysis: binary_result,
            categorized_symbols,
            libc_symbols,
            version_strings,
            filtered_strings: enhanced_strings,
            symbol_statistics,
        })
    }

    /// Get symbols that are most likely to be useful for libc detection
    pub fn get_detection_symbols(
        &self,
        analysis: &ComprehensiveAnalysis,
    ) -> Vec<CategorizedSymbol> {
        let mut detection_symbols = Vec::new();

        // Prioritize versioned symbols
        let versioned = self
            .symbol_analyzer
            .filter_by_category(&analysis.categorized_symbols, SymbolCategory::Versioned);
        detection_symbols.extend(versioned);

        // Add high-confidence libc symbols
        detection_symbols.extend(analysis.libc_symbols.clone());

        // Sort by confidence (highest first)
        detection_symbols.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        // Remove duplicates while preserving order
        let mut seen = HashSet::new();
        detection_symbols.retain(|symbol| seen.insert(symbol.clean_name.clone()));

        detection_symbols
    }

    /// Extract unique function names that are good candidates for libc detection
    pub fn get_function_candidates(&self, analysis: &ComprehensiveAnalysis) -> Vec<String> {
        let detection_symbols = self.get_detection_symbols(analysis);
        self.symbol_analyzer
            .extract_unique_names(&detection_symbols)
    }

    /// Get version information from multiple sources
    pub fn extract_version_info(&self, analysis: &ComprehensiveAnalysis) -> Vec<String> {
        let mut version_info = Vec::new();

        // From versioned symbols
        for symbol in &analysis.categorized_symbols {
            if let Some(ref version) = symbol.version_info {
                version_info.push(version.clone());
            }
        }

        // From version strings
        version_info.extend(analysis.version_strings.clone());

        // From filtered strings that might contain version info
        for string in &analysis.filtered_strings {
            if string.contains("GLIBC_") || string.contains("LIBC_") {
                version_info.push(string.clone());
            }
        }

        // Sort and deduplicate
        version_info.sort();
        version_info.dedup();
        version_info
    }

    /// Get the symbol analyzer reference
    pub fn symbol_analyzer(&self) -> &SymbolAnalyzer {
        &self.symbol_analyzer
    }

    /// Get the strings extractor reference
    pub fn strings_extractor(&self) -> &StringsExtractor {
        &self.strings_extractor
    }
}

impl Default for ComprehensiveAnalyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create default ComprehensiveAnalyzer")
    }
}

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::common::{BinaryFormat, BinaryInfo, Symbol, SymbolType};
    use std::collections::HashSet;

    fn create_test_analysis_result() -> AnalysisResult {
        let mut symbols = HashSet::new();
        symbols.insert(Symbol {
            name: "printf@@GLIBC_2.2.5".to_string(),
            address: Some(0x1000),
            is_import: true,
            section: None,
            symbol_type: SymbolType::Function,
        });
        symbols.insert(Symbol {
            name: "malloc".to_string(),
            address: Some(0x2000),
            is_import: true,
            section: None,
            symbol_type: SymbolType::Function,
        });
        symbols.insert(Symbol {
            name: "custom_function".to_string(),
            address: Some(0x3000),
            is_import: false,
            section: None,
            symbol_type: SymbolType::Function,
        });

        let mut imported_functions = HashSet::new();
        imported_functions.insert("printf@@GLIBC_2.2.5".to_string());
        imported_functions.insert("malloc".to_string());

        AnalysisResult {
            binary_info: BinaryInfo {
                path: "/test/binary".to_string(),
                format: BinaryFormat::ELF,
                architecture: "x86_64".to_string(),
                bitness: 64,
                entry_point: Some(0x1000),
                dependencies: vec!["libc.so.6".to_string()],
            },
            symbols,
            imported_functions,
            strings: HashSet::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn test_comprehensive_analyzer_creation() {
        let analyzer = ComprehensiveAnalyzer::new();
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_comprehensive_analysis() {
        let analyzer = ComprehensiveAnalyzer::new().unwrap();
        let binary_result = create_test_analysis_result();
        let binary_data = b"test data with printf and malloc strings";

        let analysis = analyzer
            .analyze(binary_result, binary_data, Some("/test/binary"))
            .unwrap();

        assert!(!analysis.categorized_symbols.is_empty());
        assert!(!analysis.symbol_statistics.is_empty());
        // Should have found some libc symbols
        assert!(!analysis.libc_symbols.is_empty());
    }

    #[test]
    fn test_detection_symbols() {
        let analyzer = ComprehensiveAnalyzer::new().unwrap();
        let binary_result = create_test_analysis_result();
        let binary_data = b"test data";

        let analysis = analyzer.analyze(binary_result, binary_data, None).unwrap();

        let detection_symbols = analyzer.get_detection_symbols(&analysis);

        // Should have symbols and they should be sorted by confidence
        assert!(!detection_symbols.is_empty());

        // Check that they're sorted by confidence (descending)
        for i in 1..detection_symbols.len() {
            assert!(detection_symbols[i - 1].confidence >= detection_symbols[i].confidence);
        }
    }

    #[test]
    fn test_function_candidates() {
        let analyzer = ComprehensiveAnalyzer::new().unwrap();
        let binary_result = create_test_analysis_result();
        let binary_data = b"test data";

        let analysis = analyzer.analyze(binary_result, binary_data, None).unwrap();

        let candidates = analyzer.get_function_candidates(&analysis);

        // Should have function names without duplicates
        assert!(!candidates.is_empty());

        // Should contain clean names (without version decorations)
        assert!(candidates.contains(&"printf".to_string()));
        assert!(candidates.contains(&"malloc".to_string()));
    }

    #[test]
    fn test_version_info_extraction() {
        let analyzer = ComprehensiveAnalyzer::new().unwrap();
        let binary_result = create_test_analysis_result();
        let binary_data = b"GLIBC_2.31 version string in binary";

        let analysis = analyzer.analyze(binary_result, binary_data, None).unwrap();

        let version_info = analyzer.extract_version_info(&analysis);

        // Should find version information from symbols and strings
        assert!(!version_info.is_empty());

        // Should be sorted and deduplicated
        for i in 1..version_info.len() {
            assert!(version_info[i - 1] <= version_info[i]);
        }
    }
}
