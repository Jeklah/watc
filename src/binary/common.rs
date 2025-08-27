//! Common types and traits for binary analysis

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents a symbol found in a binary
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Symbol {
    /// The name of the symbol
    pub name: String,
    /// The address of the symbol (if available)
    pub address: Option<u64>,
    /// Whether this symbol is imported from an external library
    pub is_import: bool,
    /// The section this symbol belongs to (if available)
    pub section: Option<String>,
    /// Symbol type (function, object, etc.)
    pub symbol_type: SymbolType,
}

/// Types of symbols found in binaries
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolType {
    Function,
    Object,
    Section,
    File,
    Unknown,
}

/// Information about a binary file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// The file path of the binary
    pub path: String,
    /// The format of the binary (ELF, PE, etc.)
    pub format: BinaryFormat,
    /// The architecture of the binary
    pub architecture: String,
    /// Whether the binary is 32-bit or 64-bit
    pub bitness: u8,
    /// The entry point address (if available)
    pub entry_point: Option<u64>,
    /// List of shared libraries this binary depends on
    pub dependencies: Vec<String>,
}

/// Supported binary formats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    ELF,
    PE,
    MachO,
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::ELF => write!(f, "ELF"),
            BinaryFormat::PE => write!(f, "PE"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Results from analyzing a binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Basic information about the binary
    pub binary_info: BinaryInfo,
    /// All symbols found in the binary
    pub symbols: HashSet<Symbol>,
    /// Imported functions (subset of symbols)
    pub imported_functions: HashSet<String>,
    /// Strings extracted from the binary
    pub strings: HashSet<String>,
    /// Any errors encountered during analysis
    pub errors: Vec<String>,
}

/// Trait for binary parsers
pub trait BinaryParser {
    /// Parse a binary file and extract symbols and metadata
    fn parse(&self, data: &[u8], file_path: &str) -> Result<AnalysisResult>;

    /// Check if this parser can handle the given binary format
    fn can_parse(&self, data: &[u8]) -> bool;

    /// Get the name of this parser
    fn name(&self) -> &'static str;
}

/// Trait for symbol extractors
pub trait SymbolExtractor {
    /// Extract symbols from binary data
    fn extract_symbols(&self, data: &[u8]) -> Result<HashSet<Symbol>>;
}

/// Helper function to determine if a symbol name looks like a libc function
pub fn is_libc_symbol(name: &str) -> bool {
    // Common libc function prefixes and patterns
    const LIBC_PATTERNS: &[&str] = &[
        // Standard library functions
        "printf",
        "scanf",
        "malloc",
        "free",
        "memcpy",
        "memset",
        "strlen",
        "strcpy",
        "strcat",
        "strcmp",
        "strncpy",
        "strncat",
        "strncmp",
        "sprintf",
        "snprintf",
        "fprintf",
        "fscanf",
        "fopen",
        "fclose",
        "fread",
        "fwrite",
        "fseek",
        "ftell",
        "rewind",
        // Math functions
        "sin",
        "cos",
        "tan",
        "log",
        "exp",
        "sqrt",
        "pow",
        "floor",
        "ceil",
        // Time functions
        "time",
        "ctime",
        "gmtime",
        "localtime",
        "mktime",
        "strftime",
        // Process functions
        "fork",
        "exec",
        "wait",
        "exit",
        "_exit",
        // Threading functions (pthread)
        "pthread_create",
        "pthread_join",
        "pthread_mutex",
        // Socket functions
        "socket",
        "bind",
        "listen",
        "accept",
        "connect",
        "send",
        "recv",
        // Signal handling
        "signal",
        "sigaction",
        "kill",
        "alarm",
        // File operations
        "open",
        "close",
        "read",
        "write",
        "lseek",
        "stat",
        "fstat",
        // Memory management
        "mmap",
        "munmap",
        "brk",
        "sbrk",
        // String/locale functions
        "setlocale",
        "wcscpy",
        "wcslen",
    ];

    // Check if the symbol starts with any known libc pattern
    LIBC_PATTERNS.iter().any(|pattern| name.starts_with(pattern))
        // Also check for symbols that start with underscores (internal libc symbols)
        || (name.starts_with('_') && name.len() > 1 &&
            LIBC_PATTERNS.iter().any(|pattern| name[1..].starts_with(pattern)))
        // Check for versioned symbols (e.g., "malloc@@GLIBC_2.2.5")
        || name.contains("@@GLIBC_")
        || name.contains("@@LIBC_")
}

/// Helper function to extract version information from versioned symbols
pub fn extract_version_from_symbol(symbol: &str) -> Option<String> {
    if let Some(pos) = symbol.find("@@") {
        let version_part = &symbol[pos + 2..];
        if version_part.starts_with("GLIBC_") || version_part.starts_with("LIBC_") {
            return Some(version_part.to_string());
        }
    }
    None
}

/// Helper function to clean symbol names (remove decorations, etc.)
pub fn clean_symbol_name(name: &str) -> String {
    // Remove version information
    if let Some(pos) = name.find("@@") {
        name[..pos].to_string()
    } else if let Some(pos) = name.find('@') {
        name[..pos].to_string()
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_libc_symbol() {
        assert!(is_libc_symbol("printf"));
        assert!(is_libc_symbol("malloc"));
        assert!(is_libc_symbol("_malloc"));
        assert!(is_libc_symbol("printf@@GLIBC_2.2.5"));
        assert!(!is_libc_symbol("custom_function"));
        assert!(!is_libc_symbol("main"));
    }

    #[test]
    fn test_extract_version_from_symbol() {
        assert_eq!(
            extract_version_from_symbol("printf@@GLIBC_2.2.5"),
            Some("GLIBC_2.2.5".to_string())
        );
        assert_eq!(
            extract_version_from_symbol("malloc@@LIBC_2.1"),
            Some("LIBC_2.1".to_string())
        );
        assert_eq!(extract_version_from_symbol("printf"), None);
    }

    #[test]
    fn test_clean_symbol_name() {
        assert_eq!(clean_symbol_name("printf@@GLIBC_2.2.5"), "printf");
        assert_eq!(clean_symbol_name("malloc@GLIBC_2.1"), "malloc");
        assert_eq!(clean_symbol_name("strlen"), "strlen");
    }
}
