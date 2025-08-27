//! Symbol analysis and processing module
//!
//! This module provides functionality for analyzing symbols extracted from binaries,
//! including filtering, categorization, and extraction of relevant information for
//! libc version detection.

use crate::binary::common::{clean_symbol_name, is_libc_symbol, Symbol};
use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents a categorized symbol with metadata
#[derive(Debug, Clone, PartialEq)]
pub struct CategorizedSymbol {
    /// The original symbol
    pub symbol: Symbol,
    /// Cleaned name without version decorations
    pub clean_name: String,
    /// Category of the symbol
    pub category: SymbolCategory,
    /// Confidence level that this is a libc symbol (0.0 to 1.0)
    pub confidence: f64,
    /// Extracted version information if available
    pub version_info: Option<String>,
}

/// Categories of symbols
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolCategory {
    /// Standard C library functions (printf, malloc, etc.)
    LibcStandard,
    /// POSIX/Unix system calls
    SystemCall,
    /// Threading functions (pthread_*)
    Threading,
    /// Math library functions
    Math,
    /// Socket/Network functions
    Network,
    /// Memory management functions
    Memory,
    /// String manipulation functions
    String,
    /// File I/O functions
    FileIO,
    /// Time and date functions
    Time,
    /// Signal handling functions
    Signal,
    /// GNU-specific extensions
    GnuExtension,
    /// Versioned symbols
    Versioned,
    /// Unknown or non-libc symbols
    Unknown,
}

/// Symbol analyzer for categorizing and filtering symbols
pub struct SymbolAnalyzer {
    /// Regex patterns for different symbol categories
    patterns: HashMap<SymbolCategory, Vec<Regex>>,
}

impl SymbolAnalyzer {
    /// Create a new symbol analyzer with predefined patterns
    pub fn new() -> Result<Self> {
        let mut patterns: HashMap<SymbolCategory, Vec<Regex>> = HashMap::new();

        // Standard C library functions
        patterns.insert(
            SymbolCategory::LibcStandard,
            vec![
                Regex::new(r"^_?printf$")?,
                Regex::new(r"^_?scanf$")?,
                Regex::new(r"^_?sprintf$")?,
                Regex::new(r"^_?snprintf$")?,
                Regex::new(r"^_?fprintf$")?,
                Regex::new(r"^_?fscanf$")?,
                Regex::new(r"^_?vprintf$")?,
                Regex::new(r"^_?vsprintf$")?,
                Regex::new(r"^_?vsnprintf$")?,
                Regex::new(r"^_?atoi$")?,
                Regex::new(r"^_?atol$")?,
                Regex::new(r"^_?atof$")?,
                Regex::new(r"^_?strtol$")?,
                Regex::new(r"^_?strtoul$")?,
                Regex::new(r"^_?strtod$")?,
                Regex::new(r"^_?exit$")?,
                Regex::new(r"^_?abort$")?,
                Regex::new(r"^_?atexit$")?,
                Regex::new(r"^_?getenv$")?,
                Regex::new(r"^_?system$")?,
            ],
        );

        // Memory management
        patterns.insert(
            SymbolCategory::Memory,
            vec![
                Regex::new(r"^_?malloc$")?,
                Regex::new(r"^_?free$")?,
                Regex::new(r"^_?calloc$")?,
                Regex::new(r"^_?realloc$")?,
                Regex::new(r"^_?reallocf$")?,
                Regex::new(r"^_?memcpy$")?,
                Regex::new(r"^_?memmove$")?,
                Regex::new(r"^_?memset$")?,
                Regex::new(r"^_?memcmp$")?,
                Regex::new(r"^_?memchr$")?,
                Regex::new(r"^_?mmap$")?,
                Regex::new(r"^_?munmap$")?,
                Regex::new(r"^_?mprotect$")?,
                Regex::new(r"^_?brk$")?,
                Regex::new(r"^_?sbrk$")?,
            ],
        );

        // String functions
        patterns.insert(
            SymbolCategory::String,
            vec![
                Regex::new(r"^_?strlen$")?,
                Regex::new(r"^_?strcpy$")?,
                Regex::new(r"^_?strncpy$")?,
                Regex::new(r"^_?strcat$")?,
                Regex::new(r"^_?strncat$")?,
                Regex::new(r"^_?strcmp$")?,
                Regex::new(r"^_?strncmp$")?,
                Regex::new(r"^_?strchr$")?,
                Regex::new(r"^_?strrchr$")?,
                Regex::new(r"^_?strstr$")?,
                Regex::new(r"^_?strtok$")?,
                Regex::new(r"^_?strdup$")?,
                Regex::new(r"^_?strndup$")?,
                Regex::new(r"^_?strcoll$")?,
                Regex::new(r"^_?strxfrm$")?,
                Regex::new(r"^_?wcs.*$")?, // Wide character string functions
            ],
        );

        // File I/O functions
        patterns.insert(
            SymbolCategory::FileIO,
            vec![
                Regex::new(r"^_?fopen$")?,
                Regex::new(r"^_?fclose$")?,
                Regex::new(r"^_?fread$")?,
                Regex::new(r"^_?fwrite$")?,
                Regex::new(r"^_?fseek$")?,
                Regex::new(r"^_?ftell$")?,
                Regex::new(r"^_?rewind$")?,
                Regex::new(r"^_?fflush$")?,
                Regex::new(r"^_?feof$")?,
                Regex::new(r"^_?ferror$")?,
                Regex::new(r"^_?clearerr$")?,
                Regex::new(r"^_?fileno$")?,
                Regex::new(r"^_?open$")?,
                Regex::new(r"^_?close$")?,
                Regex::new(r"^_?read$")?,
                Regex::new(r"^_?write$")?,
                Regex::new(r"^_?lseek$")?,
                Regex::new(r"^_?stat$")?,
                Regex::new(r"^_?fstat$")?,
                Regex::new(r"^_?lstat$")?,
            ],
        );

        // System calls
        patterns.insert(
            SymbolCategory::SystemCall,
            vec![
                Regex::new(r"^_?fork$")?,
                Regex::new(r"^_?exec.*$")?,
                Regex::new(r"^_?wait$")?,
                Regex::new(r"^_?waitpid$")?,
                Regex::new(r"^_?pipe$")?,
                Regex::new(r"^_?dup$")?,
                Regex::new(r"^_?dup2$")?,
                Regex::new(r"^_?getpid$")?,
                Regex::new(r"^_?getppid$")?,
                Regex::new(r"^_?getuid$")?,
                Regex::new(r"^_?geteuid$")?,
                Regex::new(r"^_?getgid$")?,
                Regex::new(r"^_?getegid$")?,
                Regex::new(r"^_?setuid$")?,
                Regex::new(r"^_?setgid$")?,
                Regex::new(r"^_?chdir$")?,
                Regex::new(r"^_?getcwd$")?,
                Regex::new(r"^_?mkdir$")?,
                Regex::new(r"^_?rmdir$")?,
                Regex::new(r"^_?unlink$")?,
                Regex::new(r"^_?link$")?,
                Regex::new(r"^_?rename$")?,
                Regex::new(r"^_?chmod$")?,
                Regex::new(r"^_?chown$")?,
            ],
        );

        // Threading functions
        patterns.insert(
            SymbolCategory::Threading,
            vec![
                Regex::new(r"^_?pthread_.*$")?,
                Regex::new(r"^_?sem_.*$")?,
                Regex::new(r"^_?shm_.*$")?,
                Regex::new(r"^_?mq_.*$")?,
            ],
        );

        // Math functions
        patterns.insert(
            SymbolCategory::Math,
            vec![
                Regex::new(r"^_?sin$")?,
                Regex::new(r"^_?cos$")?,
                Regex::new(r"^_?tan$")?,
                Regex::new(r"^_?asin$")?,
                Regex::new(r"^_?acos$")?,
                Regex::new(r"^_?atan$")?,
                Regex::new(r"^_?atan2$")?,
                Regex::new(r"^_?sinh$")?,
                Regex::new(r"^_?cosh$")?,
                Regex::new(r"^_?tanh$")?,
                Regex::new(r"^_?exp$")?,
                Regex::new(r"^_?log$")?,
                Regex::new(r"^_?log10$")?,
                Regex::new(r"^_?pow$")?,
                Regex::new(r"^_?sqrt$")?,
                Regex::new(r"^_?ceil$")?,
                Regex::new(r"^_?floor$")?,
                Regex::new(r"^_?fabs$")?,
                Regex::new(r"^_?fmod$")?,
                Regex::new(r"^_?modf$")?,
                Regex::new(r"^_?frexp$")?,
                Regex::new(r"^_?ldexp$")?,
            ],
        );

        // Network functions
        patterns.insert(
            SymbolCategory::Network,
            vec![
                Regex::new(r"^_?socket$")?,
                Regex::new(r"^_?bind$")?,
                Regex::new(r"^_?listen$")?,
                Regex::new(r"^_?accept$")?,
                Regex::new(r"^_?connect$")?,
                Regex::new(r"^_?send$")?,
                Regex::new(r"^_?recv$")?,
                Regex::new(r"^_?sendto$")?,
                Regex::new(r"^_?recvfrom$")?,
                Regex::new(r"^_?getsockname$")?,
                Regex::new(r"^_?getpeername$")?,
                Regex::new(r"^_?setsockopt$")?,
                Regex::new(r"^_?getsockopt$")?,
                Regex::new(r"^_?shutdown$")?,
                Regex::new(r"^_?select$")?,
                Regex::new(r"^_?poll$")?,
                Regex::new(r"^_?epoll_.*$")?,
                Regex::new(r"^_?inet_.*$")?,
                Regex::new(r"^_?gethostbyname$")?,
                Regex::new(r"^_?getaddrinfo$")?,
                Regex::new(r"^_?freeaddrinfo$")?,
            ],
        );

        // Time functions
        patterns.insert(
            SymbolCategory::Time,
            vec![
                Regex::new(r"^_?time$")?,
                Regex::new(r"^_?ctime$")?,
                Regex::new(r"^_?gmtime$")?,
                Regex::new(r"^_?localtime$")?,
                Regex::new(r"^_?mktime$")?,
                Regex::new(r"^_?strftime$")?,
                Regex::new(r"^_?asctime$")?,
                Regex::new(r"^_?difftime$")?,
                Regex::new(r"^_?clock$")?,
                Regex::new(r"^_?gettimeofday$")?,
                Regex::new(r"^_?settimeofday$")?,
                Regex::new(r"^_?nanosleep$")?,
                Regex::new(r"^_?sleep$")?,
                Regex::new(r"^_?usleep$")?,
            ],
        );

        // Signal handling
        patterns.insert(
            SymbolCategory::Signal,
            vec![
                Regex::new(r"^_?signal$")?,
                Regex::new(r"^_?sigaction$")?,
                Regex::new(r"^_?kill$")?,
                Regex::new(r"^_?raise$")?,
                Regex::new(r"^_?alarm$")?,
                Regex::new(r"^_?pause$")?,
                Regex::new(r"^_?sigemptyset$")?,
                Regex::new(r"^_?sigfillset$")?,
                Regex::new(r"^_?sigaddset$")?,
                Regex::new(r"^_?sigdelset$")?,
                Regex::new(r"^_?sigismember$")?,
                Regex::new(r"^_?sigprocmask$")?,
                Regex::new(r"^_?sigsuspend$")?,
                Regex::new(r"^_?sigpending$")?,
            ],
        );

        // GNU extensions
        patterns.insert(
            SymbolCategory::GnuExtension,
            vec![
                Regex::new(r"^_?asprintf$")?,
                Regex::new(r"^_?vasprintf$")?,
                Regex::new(r"^_?dprintf$")?,
                Regex::new(r"^_?vdprintf$")?,
                Regex::new(r"^_?getline$")?,
                Regex::new(r"^_?getdelim$")?,
                Regex::new(r"^_?strnlen$")?,
                Regex::new(r"^_?stpcpy$")?,
                Regex::new(r"^_?stpncpy$")?,
                Regex::new(r"^_?strcasestr$")?,
                Regex::new(r"^_?strchrnul$")?,
                Regex::new(r"^_?rawmemchr$")?,
                Regex::new(r"^_?memrchr$")?,
                Regex::new(r"^_?memmem$")?,
            ],
        );

        // Versioned symbols
        patterns.insert(
            SymbolCategory::Versioned,
            vec![Regex::new(r".*@@(GLIBC|LIBC)_.*$")?],
        );

        Ok(Self { patterns })
    }

    /// Analyze and categorize a collection of symbols
    pub fn analyze_symbols(&self, symbols: &[Symbol]) -> Vec<CategorizedSymbol> {
        symbols
            .iter()
            .filter_map(|symbol| self.analyze_symbol(symbol))
            .collect()
    }

    /// Analyze and categorize a single symbol
    pub fn analyze_symbol(&self, symbol: &Symbol) -> Option<CategorizedSymbol> {
        let clean_name = clean_symbol_name(&symbol.name);

        // Extract version information if present
        let version_info = self.extract_version_info(&symbol.name);

        // Determine category and confidence
        let (category, confidence) = self.categorize_symbol(&clean_name, &symbol.name);

        // Only return symbols that have some likelihood of being libc-related
        if confidence > 0.0 || is_libc_symbol(&clean_name) {
            Some(CategorizedSymbol {
                symbol: symbol.clone(),
                clean_name,
                category,
                confidence,
                version_info,
            })
        } else {
            None
        }
    }

    /// Categorize a symbol and return confidence level
    fn categorize_symbol(&self, clean_name: &str, original_name: &str) -> (SymbolCategory, f64) {
        // First check for versioned symbols
        if original_name.contains("@@GLIBC_") || original_name.contains("@@LIBC_") {
            return (SymbolCategory::Versioned, 0.95);
        }

        // Check against all patterns
        for (category, patterns) in &self.patterns {
            for pattern in patterns {
                if pattern.is_match(clean_name) {
                    let confidence = match category {
                        SymbolCategory::LibcStandard => 0.9,
                        SymbolCategory::Memory => 0.85,
                        SymbolCategory::String => 0.85,
                        SymbolCategory::FileIO => 0.8,
                        SymbolCategory::SystemCall => 0.75,
                        SymbolCategory::Math => 0.7,
                        SymbolCategory::Threading => 0.8,
                        SymbolCategory::Network => 0.75,
                        SymbolCategory::Time => 0.75,
                        SymbolCategory::Signal => 0.75,
                        SymbolCategory::GnuExtension => 0.7,
                        SymbolCategory::Versioned => 0.95,
                        SymbolCategory::Unknown => 0.1,
                    };
                    return (category.clone(), confidence);
                }
            }
        }

        // Fallback: use basic heuristics
        if is_libc_symbol(clean_name) {
            (SymbolCategory::LibcStandard, 0.5)
        } else {
            (SymbolCategory::Unknown, 0.0)
        }
    }

    /// Extract version information from symbol name
    fn extract_version_info(&self, symbol_name: &str) -> Option<String> {
        if let Some(pos) = symbol_name.find("@@") {
            let version_part = &symbol_name[pos + 2..];
            Some(version_part.to_string())
        } else {
            None
        }
    }

    /// Filter symbols by category
    pub fn filter_by_category(
        &self,
        symbols: &[CategorizedSymbol],
        category: SymbolCategory,
    ) -> Vec<CategorizedSymbol> {
        symbols
            .iter()
            .filter(|s| s.category == category)
            .cloned()
            .collect()
    }

    /// Get symbols with high confidence (>= threshold)
    pub fn get_high_confidence_symbols(
        &self,
        symbols: &[CategorizedSymbol],
        threshold: f64,
    ) -> Vec<CategorizedSymbol> {
        symbols
            .iter()
            .filter(|s| s.confidence >= threshold)
            .cloned()
            .collect()
    }

    /// Get unique function names from categorized symbols
    pub fn extract_unique_names(&self, symbols: &[CategorizedSymbol]) -> Vec<String> {
        let mut names: Vec<String> = symbols
            .iter()
            .map(|s| s.clean_name.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        names.sort();
        names
    }

    /// Generate statistics about symbol categories
    pub fn generate_statistics(
        &self,
        symbols: &[CategorizedSymbol],
    ) -> HashMap<SymbolCategory, usize> {
        let mut stats = HashMap::new();

        for symbol in symbols {
            *stats.entry(symbol.category.clone()).or_insert(0) += 1;
        }

        stats
    }
}

impl Default for SymbolAnalyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create default SymbolAnalyzer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::common::{Symbol, SymbolType};

    fn create_test_symbol(name: &str, is_import: bool) -> Symbol {
        Symbol {
            name: name.to_string(),
            address: Some(0x1000),
            is_import,
            section: None,
            symbol_type: SymbolType::Function,
        }
    }

    #[test]
    fn test_symbol_analyzer_creation() {
        let analyzer = SymbolAnalyzer::new();
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_categorize_standard_functions() {
        let analyzer = SymbolAnalyzer::new().unwrap();

        let printf_symbol = create_test_symbol("printf", true);
        let categorized = analyzer.analyze_symbol(&printf_symbol).unwrap();

        assert_eq!(categorized.category, SymbolCategory::LibcStandard);
        assert!(categorized.confidence > 0.8);
    }

    #[test]
    fn test_categorize_memory_functions() {
        let analyzer = SymbolAnalyzer::new().unwrap();

        let malloc_symbol = create_test_symbol("malloc", true);
        let categorized = analyzer.analyze_symbol(&malloc_symbol).unwrap();

        assert_eq!(categorized.category, SymbolCategory::Memory);
        assert!(categorized.confidence > 0.8);
    }

    #[test]
    fn test_versioned_symbols() {
        let analyzer = SymbolAnalyzer::new().unwrap();

        let versioned_symbol = create_test_symbol("printf@@GLIBC_2.2.5", true);
        let categorized = analyzer.analyze_symbol(&versioned_symbol).unwrap();

        assert_eq!(categorized.category, SymbolCategory::Versioned);
        assert_eq!(categorized.clean_name, "printf");
        assert_eq!(categorized.version_info, Some("GLIBC_2.2.5".to_string()));
        assert!(categorized.confidence > 0.9);
    }

    #[test]
    fn test_filter_by_category() {
        let analyzer = SymbolAnalyzer::new().unwrap();

        let symbols = vec![
            create_test_symbol("printf", true),
            create_test_symbol("malloc", true),
            create_test_symbol("sin", true),
        ];

        let categorized = analyzer.analyze_symbols(&symbols);
        let memory_symbols = analyzer.filter_by_category(&categorized, SymbolCategory::Memory);

        assert_eq!(memory_symbols.len(), 1);
        assert_eq!(memory_symbols[0].clean_name, "malloc");
    }

    #[test]
    fn test_unknown_symbol_filtering() {
        let analyzer = SymbolAnalyzer::new().unwrap();

        let custom_symbol = create_test_symbol("my_custom_function", false);
        let result = analyzer.analyze_symbol(&custom_symbol);

        // Custom functions should be filtered out (return None)
        assert!(result.is_none());
    }

    #[test]
    fn test_statistics_generation() {
        let analyzer = SymbolAnalyzer::new().unwrap();

        let symbols = vec![
            create_test_symbol("printf", true),
            create_test_symbol("malloc", true),
            create_test_symbol("free", true),
            create_test_symbol("sin", true),
        ];

        let categorized = analyzer.analyze_symbols(&symbols);
        let stats = analyzer.generate_statistics(&categorized);

        assert!(stats.get(&SymbolCategory::LibcStandard).unwrap_or(&0) > &0);
        assert!(stats.get(&SymbolCategory::Memory).unwrap_or(&0) > &0);
        assert!(stats.get(&SymbolCategory::Math).unwrap_or(&0) > &0);
    }
}
