//! watc - What Are Those C libraries?
//!
//! A library for analyzing binaries to determine C library versions used during compilation.
//! Supports ELF and PE formats with multiple analysis methods including symbol extraction,
//! string analysis, and online database queries.

pub mod analysis;
pub mod binary;
pub mod cli;
pub mod libc;

// Re-export main types for convenience
pub use analysis::{
    CategorizedSymbol, ComprehensiveAnalysis, ComprehensiveAnalyzer, SymbolCategory,
};
pub use binary::{AnalysisResult, BinaryAnalyzer, BinaryFormat, Symbol};
pub use cli::{Args, CliApp, OutputFormat};
pub use libc::{DetectionResult, LibcMatch, LibcMatcher};
