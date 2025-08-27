//! Readelf integration module for enhanced ELF analysis
//!
//! This module provides functionality to integrate with the `readelf` command-line tool
//! to extract additional information from ELF binaries that might not be easily
//! accessible through the goblin parser alone.

use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::process::Command;

/// Configuration for readelf integration
#[derive(Debug, Clone)]
pub struct ReadelfConfig {
    /// Path to the readelf executable
    pub readelf_path: String,
    /// Timeout for readelf commands (in seconds)
    pub timeout_secs: u64,
    /// Whether to use verbose output
    pub verbose: bool,
}

impl Default for ReadelfConfig {
    fn default() -> Self {
        Self {
            readelf_path: "readelf".to_string(),
            timeout_secs: 30,
            verbose: false,
        }
    }
}

/// Information extracted from readelf output
#[derive(Debug, Clone)]
pub struct ReadelfInfo {
    /// Dynamic symbols with version information
    pub versioned_symbols: HashMap<String, String>,
    /// Library dependencies with version requirements
    pub version_dependencies: HashMap<String, Vec<String>>,
    /// Symbol version definitions
    pub version_definitions: Vec<VersionDefinition>,
    /// Symbol version requirements
    pub version_requirements: Vec<VersionRequirement>,
    /// Additional strings found in various sections
    pub section_strings: HashMap<String, Vec<String>>,
    /// Interpreter (dynamic linker) path
    pub interpreter: Option<String>,
    /// Build ID if available
    pub build_id: Option<String>,
    /// GNU version information
    pub gnu_version_info: Vec<String>,
}

/// Version definition information
#[derive(Debug, Clone)]
pub struct VersionDefinition {
    /// Version name
    pub name: String,
    /// Version index
    pub index: u16,
    /// Version flags
    pub flags: u16,
    /// Associated symbols
    pub symbols: Vec<String>,
}

/// Version requirement information
#[derive(Debug, Clone)]
pub struct VersionRequirement {
    /// Library name
    pub library: String,
    /// Required version
    pub version: String,
    /// Version flags
    pub flags: u16,
}

/// Readelf integration wrapper
pub struct ReadelfAnalyzer {
    config: ReadelfConfig,
    // Regex patterns for parsing readelf output
    symbol_version_regex: Regex,
    version_def_regex: Regex,
    version_req_regex: Regex,
    interpreter_regex: Regex,
    build_id_regex: Regex,
}

impl ReadelfAnalyzer {
    /// Create a new readelf analyzer with configuration
    pub fn new(config: ReadelfConfig) -> Result<Self> {
        let symbol_version_regex =
            Regex::new(r"^\s*\d+:\s+[0-9a-f]+\s+\d+\s+\w+\s+\w+\s+\w+\s+\w+\s+(\S+)@@?(\S+)?")?;
        let version_def_regex = Regex::new(
            r"^\s*0x[0-9a-f]+:\s+Rev:\s+\d+\s+Flags:\s+(\w+)\s+Index:\s+(\d+)\s+Cnt:\s+\d+\s+Name:\s+(\S+)",
        )?;
        let version_req_regex = Regex::new(r"^\s*0x[0-9a-f]+:\s+Cnt:\s+\d+\s+File:\s+(\S+)")?;
        let interpreter_regex = Regex::new(r"\[Requesting program interpreter:\s+(.+)\]")?;
        let build_id_regex = Regex::new(r"Build ID:\s+([0-9a-f]+)")?;

        Ok(Self {
            config,
            symbol_version_regex,
            version_def_regex,
            version_req_regex,
            interpreter_regex,
            build_id_regex,
        })
    }

    /// Create a default readelf analyzer
    pub fn default() -> Result<Self> {
        Self::new(ReadelfConfig::default())
    }

    /// Check if readelf is available on the system
    pub fn is_available(&self) -> bool {
        Command::new(&self.config.readelf_path)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Analyze an ELF file using readelf and extract comprehensive information
    pub fn analyze_elf(&self, file_path: &str) -> Result<ReadelfInfo> {
        if !self.is_available() {
            return Err(anyhow!(
                "readelf command not available at: {}",
                self.config.readelf_path
            ));
        }

        let mut info = ReadelfInfo {
            versioned_symbols: HashMap::new(),
            version_dependencies: HashMap::new(),
            version_definitions: Vec::new(),
            version_requirements: Vec::new(),
            section_strings: HashMap::new(),
            interpreter: None,
            build_id: None,
            gnu_version_info: Vec::new(),
        };

        // Extract versioned symbols
        if let Ok(symbols) = self.extract_versioned_symbols(file_path) {
            info.versioned_symbols = symbols;
        }

        // Extract version definitions
        if let Ok(defs) = self.extract_version_definitions(file_path) {
            info.version_definitions = defs;
        }

        // Extract version requirements
        if let Ok(reqs) = self.extract_version_requirements(file_path) {
            info.version_requirements = reqs;
        }

        // Extract interpreter information
        if let Ok(interp) = self.extract_interpreter(file_path) {
            info.interpreter = interp;
        }

        // Extract build ID
        if let Ok(build_id) = self.extract_build_id(file_path) {
            info.build_id = build_id;
        }

        // Extract strings from various sections
        if let Ok(strings) = self.extract_section_strings(file_path) {
            info.section_strings = strings;
        }

        // Extract GNU version information
        if let Ok(gnu_info) = self.extract_gnu_version_info(file_path) {
            info.gnu_version_info = gnu_info;
        }

        Ok(info)
    }

    /// Extract versioned symbols using readelf -sW
    fn extract_versioned_symbols(&self, file_path: &str) -> Result<HashMap<String, String>> {
        let output = self.run_readelf(&["-sW", file_path])?;
        let mut versioned_symbols = HashMap::new();

        for line in output.lines() {
            if let Some(captures) = self.symbol_version_regex.captures(line) {
                if let (Some(symbol), Some(version)) = (captures.get(1), captures.get(2)) {
                    let symbol_name = symbol.as_str().to_string();
                    let version_name = version.as_str().to_string();

                    // Skip if version is just a number (not a real version string)
                    if !version_name.chars().all(|c| c.is_ascii_digit()) {
                        versioned_symbols.insert(symbol_name, version_name);
                    }
                }
            }
        }

        Ok(versioned_symbols)
    }

    /// Extract version definitions using readelf -V
    fn extract_version_definitions(&self, file_path: &str) -> Result<Vec<VersionDefinition>> {
        let output = self.run_readelf(&["-V", file_path])?;
        let mut definitions = Vec::new();

        for line in output.lines() {
            if let Some(captures) = self.version_def_regex.captures(line) {
                if let (Some(flags_str), Some(index_str), Some(name)) =
                    (captures.get(1), captures.get(2), captures.get(3))
                {
                    let flags = self.parse_version_flags(flags_str.as_str());
                    let index = index_str.as_str().parse().unwrap_or(0);

                    definitions.push(VersionDefinition {
                        name: name.as_str().to_string(),
                        index,
                        flags,
                        symbols: Vec::new(), // Could be enhanced to extract associated symbols
                    });
                }
            }
        }

        Ok(definitions)
    }

    /// Extract version requirements using readelf -V
    fn extract_version_requirements(&self, file_path: &str) -> Result<Vec<VersionRequirement>> {
        let output = self.run_readelf(&["-V", file_path])?;
        let mut requirements = Vec::new();

        let mut current_file = None;
        for line in output.lines() {
            if let Some(captures) = self.version_req_regex.captures(line) {
                if let Some(file_name) = captures.get(1) {
                    current_file = Some(file_name.as_str().to_string());
                }
            } else if line.contains("Version:") && current_file.is_some() {
                // Parse individual version requirements
                if let Some(version_info) = self.parse_version_requirement_line(line) {
                    requirements.push(VersionRequirement {
                        library: current_file.as_ref().unwrap().clone(),
                        version: version_info.0,
                        flags: version_info.1,
                    });
                }
            }
        }

        Ok(requirements)
    }

    /// Extract interpreter (dynamic linker) path using readelf -l
    fn extract_interpreter(&self, file_path: &str) -> Result<Option<String>> {
        let output = self.run_readelf(&["-l", file_path])?;

        for line in output.lines() {
            if let Some(captures) = self.interpreter_regex.captures(line) {
                if let Some(interpreter) = captures.get(1) {
                    return Ok(Some(interpreter.as_str().to_string()));
                }
            }
        }

        Ok(None)
    }

    /// Extract build ID using readelf -n
    fn extract_build_id(&self, file_path: &str) -> Result<Option<String>> {
        let output = self.run_readelf(&["-n", file_path])?;

        for line in output.lines() {
            if let Some(captures) = self.build_id_regex.captures(line) {
                if let Some(build_id) = captures.get(1) {
                    return Ok(Some(build_id.as_str().to_string()));
                }
            }
        }

        Ok(None)
    }

    /// Extract strings from various sections using readelf -p
    fn extract_section_strings(&self, file_path: &str) -> Result<HashMap<String, Vec<String>>> {
        let mut section_strings = HashMap::new();

        // Common sections that might contain interesting strings
        let sections_to_check = vec![
            ".comment",
            ".note.gnu.version",
            ".gnu.version_r",
            ".rodata",
            ".data.rel.ro",
        ];

        for section in sections_to_check {
            if let Ok(output) = self.run_readelf(&["-p", section, file_path]) {
                let strings = self.parse_section_strings(&output);
                if !strings.is_empty() {
                    section_strings.insert(section.to_string(), strings);
                }
            }
        }

        Ok(section_strings)
    }

    /// Extract GNU version information
    fn extract_gnu_version_info(&self, file_path: &str) -> Result<Vec<String>> {
        let mut version_info = Vec::new();

        // Try to get version information from .comment section
        if let Ok(output) = self.run_readelf(&["-p", ".comment", file_path]) {
            for line in output.lines() {
                if line.contains("GCC:") || line.contains("clang") || line.contains("GNU") {
                    // Clean up the line and extract version information
                    if let Some(cleaned) = self.clean_version_string(line) {
                        version_info.push(cleaned);
                    }
                }
            }
        }

        // Try to get version information from version sections
        if let Ok(output) = self.run_readelf(&["-V", file_path]) {
            for line in output.lines() {
                if line.contains("GLIBC_") || line.contains("LIBC_") {
                    if let Some(version) = self.extract_version_from_line(line) {
                        version_info.push(version);
                    }
                }
            }
        }

        // Remove duplicates and sort
        version_info.sort();
        version_info.dedup();

        Ok(version_info)
    }

    /// Run readelf command with given arguments
    fn run_readelf(&self, args: &[&str]) -> Result<String> {
        let mut cmd = Command::new(&self.config.readelf_path);
        cmd.args(args);

        // Set timeout if configured
        let output = if self.config.timeout_secs > 0 {
            // In a real implementation, you might want to use tokio::time::timeout
            // or implement a custom timeout mechanism
            cmd.output()
        } else {
            cmd.output()
        }
        .map_err(|e| anyhow!("Failed to execute readelf: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("readelf command failed: {}", stderr));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Parse version flags from readelf output
    fn parse_version_flags(&self, flags_str: &str) -> u16 {
        match flags_str {
            "none" => 0,
            "BASE" => 1,
            "WEAK" => 2,
            _ => 0,
        }
    }

    /// Parse version requirement line
    fn parse_version_requirement_line(&self, line: &str) -> Option<(String, u16)> {
        // Simple parsing - could be enhanced for more complex cases
        if let Some(start) = line.find("Version:") {
            let version_part = &line[start + 8..].trim();
            if let Some(end) = version_part.find(' ') {
                let version = &version_part[..end];
                return Some((version.to_string(), 0));
            } else {
                return Some((version_part.to_string(), 0));
            }
        }
        None
    }

    /// Parse strings from section output
    fn parse_section_strings(&self, output: &str) -> Vec<String> {
        let mut strings = Vec::new();

        for line in output.lines() {
            // readelf -p output format: "  [offset] string_content"
            if let Some(bracket_end) = line.find(']') {
                if bracket_end + 1 < line.len() {
                    let string_content = line[bracket_end + 1..].trim();
                    if !string_content.is_empty() && string_content.len() > 2 {
                        strings.push(string_content.to_string());
                    }
                }
            }
        }

        strings
    }

    /// Clean and extract version string from comment lines
    fn clean_version_string(&self, line: &str) -> Option<String> {
        // Remove readelf formatting and extract meaningful version info
        if let Some(bracket_end) = line.find(']') {
            if bracket_end + 1 < line.len() {
                let content = line[bracket_end + 1..].trim();
                if content.len() > 5
                    && (content.contains("GCC")
                        || content.contains("clang")
                        || content.contains("GNU"))
                {
                    return Some(content.to_string());
                }
            }
        }
        None
    }

    /// Extract version information from a line
    fn extract_version_from_line(&self, line: &str) -> Option<String> {
        let version_regex = Regex::new(r"(GLIBC_[\d.]+|LIBC_[\d.]+)").ok()?;

        if let Some(captures) = version_regex.find(line) {
            return Some(captures.as_str().to_string());
        }
        None
    }

    /// Get configuration reference
    pub fn config(&self) -> &ReadelfConfig {
        &self.config
    }
}

/// Helper function to merge readelf information with existing analysis
pub fn merge_readelf_info(
    existing_strings: &mut HashSet<String>,
    existing_symbols: &mut HashMap<String, String>,
    readelf_info: &ReadelfInfo,
) {
    // Merge versioned symbols
    for (symbol, version) in &readelf_info.versioned_symbols {
        existing_symbols.insert(symbol.clone(), version.clone());
    }

    // Merge strings from all sections
    for strings in readelf_info.section_strings.values() {
        for string in strings {
            existing_strings.insert(string.clone());
        }
    }

    // Add version information as strings
    for version_info in &readelf_info.gnu_version_info {
        existing_strings.insert(version_info.clone());
    }

    // Add interpreter as a string if available
    if let Some(ref interpreter) = readelf_info.interpreter {
        existing_strings.insert(interpreter.clone());
    }

    // Add build ID as a string if available
    if let Some(ref build_id) = readelf_info.build_id {
        existing_strings.insert(format!("Build ID: {}", build_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readelf_analyzer_creation() {
        let analyzer = ReadelfAnalyzer::default();
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_config_default() {
        let config = ReadelfConfig::default();
        assert_eq!(config.readelf_path, "readelf");
        assert_eq!(config.timeout_secs, 30);
        assert!(!config.verbose);
    }

    #[test]
    fn test_version_flags_parsing() {
        let analyzer = ReadelfAnalyzer::default().unwrap();
        assert_eq!(analyzer.parse_version_flags("none"), 0);
        assert_eq!(analyzer.parse_version_flags("BASE"), 1);
        assert_eq!(analyzer.parse_version_flags("WEAK"), 2);
        assert_eq!(analyzer.parse_version_flags("unknown"), 0);
    }

    #[test]
    fn test_section_strings_parsing() {
        let analyzer = ReadelfAnalyzer::default().unwrap();
        let output = r#"
String dump of section '.comment':
  [     0]  GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
  [    31]  clang version 12.0.0
"#;
        let strings = analyzer.parse_section_strings(output);
        assert!(strings.len() >= 2);
        assert!(strings.iter().any(|s| s.contains("GCC")));
        assert!(strings.iter().any(|s| s.contains("clang")));
    }

    #[test]
    fn test_version_extraction() {
        let analyzer = ReadelfAnalyzer::default().unwrap();

        assert_eq!(
            analyzer.extract_version_from_line("  0x0020: Name: GLIBC_2.2.5"),
            Some("GLIBC_2.2.5".to_string())
        );

        assert_eq!(
            analyzer.extract_version_from_line("random line without version"),
            None
        );
    }

    #[test]
    fn test_merge_readelf_info() {
        let mut existing_strings = HashSet::new();
        let mut existing_symbols = HashMap::new();

        existing_strings.insert("existing_string".to_string());
        existing_symbols.insert("printf".to_string(), "GLIBC_2.2".to_string());

        let mut readelf_info = ReadelfInfo {
            versioned_symbols: HashMap::new(),
            version_dependencies: HashMap::new(),
            version_definitions: Vec::new(),
            version_requirements: Vec::new(),
            section_strings: HashMap::new(),
            interpreter: Some("/lib64/ld-linux-x86-64.so.2".to_string()),
            build_id: Some("abcdef123456".to_string()),
            gnu_version_info: vec!["GLIBC_2.31".to_string()],
        };

        readelf_info
            .versioned_symbols
            .insert("malloc".to_string(), "GLIBC_2.17".to_string());
        readelf_info
            .section_strings
            .insert(".comment".to_string(), vec!["GCC: 9.4.0".to_string()]);

        merge_readelf_info(&mut existing_strings, &mut existing_symbols, &readelf_info);

        // Check that information was merged
        assert!(existing_strings.contains("existing_string"));
        assert!(existing_strings.contains("/lib64/ld-linux-x86-64.so.2"));
        assert!(existing_strings.contains("Build ID: abcdef123456"));
        assert!(existing_strings.contains("GLIBC_2.31"));
        assert!(existing_strings.contains("GCC: 9.4.0"));

        assert_eq!(
            existing_symbols.get("printf"),
            Some(&"GLIBC_2.2".to_string())
        );
        assert_eq!(
            existing_symbols.get("malloc"),
            Some(&"GLIBC_2.17".to_string())
        );
    }
}
