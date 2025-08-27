//! Strings analysis module for integrating with external tools
//!
//! This module provides functionality to extract strings from binaries using
//! both built-in parsing and external tools like the `strings` command.

use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::HashSet;
use std::process::Command;

/// Configuration for string extraction
#[derive(Debug, Clone)]
pub struct StringsConfig {
    /// Minimum string length to extract
    pub min_length: usize,
    /// Maximum string length to extract (to avoid huge strings)
    pub max_length: usize,
    /// Whether to use external strings command
    pub use_external_strings: bool,
    /// Additional arguments for the strings command
    pub strings_args: Vec<String>,
    /// Character sets to include
    pub char_sets: Vec<CharSet>,
}

/// Character sets for string extraction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CharSet {
    /// ASCII printable characters
    Ascii,
    /// Wide characters (Unicode)
    Wide,
    /// Both ASCII and wide characters
    Both,
}

impl Default for StringsConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 256,
            use_external_strings: true,
            strings_args: vec!["-a".to_string()], // Print strings from all sections
            char_sets: vec![CharSet::Both],
        }
    }
}

/// String extractor that can use multiple methods
pub struct StringsExtractor {
    config: StringsConfig,
    // Regex patterns for filtering interesting strings
    libc_patterns: Vec<Regex>,
}

impl StringsExtractor {
    /// Create a new strings extractor with configuration
    pub fn new(config: StringsConfig) -> Result<Self> {
        // Patterns that might indicate libc functions or version info
        let libc_patterns = vec![
            Regex::new(r"GLIBC_[\d.]+")?,
            Regex::new(r"LIBC_[\d.]+")?,
            Regex::new(r"GNU C Library")?,
            Regex::new(r"glibc")?,
            Regex::new(r"libc\.so")?,
            Regex::new(r"ld-linux")?,
            Regex::new(r"__libc_")?,
            Regex::new(r"_IO_")?,
            Regex::new(r"malloc_")?,
            Regex::new(r"free_")?,
            Regex::new(r"printf_")?,
            Regex::new(r"scanf_")?,
            // Version strings
            Regex::new(r"\d+\.\d+(\.\d+)?")?,
            // File paths that might contain version info
            Regex::new(r"/lib/.*\.so\.?\d*")?,
            Regex::new(r"/usr/lib/.*\.so\.?\d*")?,
        ];

        Ok(Self {
            config,
            libc_patterns,
        })
    }

    /// Create a default strings extractor
    pub fn default() -> Result<Self> {
        Self::new(StringsConfig::default())
    }

    /// Extract strings from binary data using multiple methods
    pub fn extract_strings(&self, data: &[u8], file_path: Option<&str>) -> Result<HashSet<String>> {
        let mut all_strings = HashSet::new();

        // Method 1: Built-in string extraction
        let builtin_strings = self.extract_strings_builtin(data)?;
        all_strings.extend(builtin_strings);

        // Method 2: External strings command (if enabled and file path provided)
        if self.config.use_external_strings {
            if let Some(path) = file_path {
                match self.extract_strings_external(path) {
                    Ok(external_strings) => {
                        all_strings.extend(external_strings);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to use external strings command: {}", e);
                    }
                }
            }
        }

        // Filter and clean the strings
        Ok(self.filter_strings(all_strings))
    }

    /// Extract strings using built-in parser
    fn extract_strings_builtin(&self, data: &[u8]) -> Result<HashSet<String>> {
        let mut strings = HashSet::new();

        // Extract ASCII strings
        if self.config.char_sets.contains(&CharSet::Ascii)
            || self.config.char_sets.contains(&CharSet::Both)
        {
            strings.extend(self.extract_ascii_strings(data));
        }

        // Extract wide character strings
        if self.config.char_sets.contains(&CharSet::Wide)
            || self.config.char_sets.contains(&CharSet::Both)
        {
            strings.extend(self.extract_wide_strings(data));
        }

        Ok(strings)
    }

    /// Extract ASCII strings from binary data
    fn extract_ascii_strings(&self, data: &[u8]) -> HashSet<String> {
        let mut strings = HashSet::new();
        let mut current_string = Vec::new();

        for &byte in data {
            if byte.is_ascii() && byte >= 32 && byte < 127 {
                // Printable ASCII character
                current_string.push(byte);
            } else if byte == 0 || !byte.is_ascii() {
                // Null terminator or non-ASCII byte
                if current_string.len() >= self.config.min_length
                    && current_string.len() <= self.config.max_length
                {
                    if let Ok(s) = String::from_utf8(current_string.clone()) {
                        strings.insert(s);
                    }
                }
                current_string.clear();
            } else {
                // Other non-printable ASCII
                current_string.clear();
            }
        }

        // Handle string at end of data
        if current_string.len() >= self.config.min_length
            && current_string.len() <= self.config.max_length
        {
            if let Ok(s) = String::from_utf8(current_string) {
                strings.insert(s);
            }
        }

        strings
    }

    /// Extract wide character (UTF-16) strings from binary data
    fn extract_wide_strings(&self, data: &[u8]) -> HashSet<String> {
        let mut strings = HashSet::new();

        // Process data in 2-byte chunks for UTF-16
        let mut i = 0;
        while i + 1 < data.len() {
            let mut wide_chars = Vec::new();
            let mut j = i;

            // Collect consecutive wide characters
            while j + 1 < data.len() {
                let low = data[j] as u16;
                let high = data[j + 1] as u16;
                let wide_char = (high << 8) | low;

                // Check if it's a printable character or null terminator
                if wide_char == 0 {
                    break;
                } else if wide_char >= 32 && wide_char < 127 {
                    // Basic ASCII range in wide char
                    wide_chars.push(wide_char);
                } else if wide_char > 127 {
                    // Extended Unicode (simplified check)
                    wide_chars.push(wide_char);
                } else {
                    // Non-printable, reset
                    wide_chars.clear();
                }

                j += 2;

                // Avoid extremely long strings
                if wide_chars.len() > self.config.max_length {
                    break;
                }
            }

            // Convert to string if long enough
            if wide_chars.len() >= self.config.min_length {
                if let Ok(s) = String::from_utf16(&wide_chars) {
                    // Only add if it contains reasonable characters
                    if s.chars()
                        .any(|c| c.is_alphanumeric() || c.is_ascii_punctuation())
                    {
                        strings.insert(s);
                    }
                }
            }

            i += 2;
        }

        strings
    }

    /// Extract strings using external strings command
    fn extract_strings_external(&self, file_path: &str) -> Result<HashSet<String>> {
        let mut cmd = Command::new("strings");
        cmd.arg(file_path);

        // Add configured arguments
        for arg in &self.config.strings_args {
            cmd.arg(arg);
        }

        // Set minimum length
        cmd.arg("-n").arg(self.config.min_length.to_string());

        let output = cmd
            .output()
            .map_err(|e| anyhow!("Failed to execute strings command: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("strings command failed: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let strings: HashSet<String> = stdout
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.len() >= self.config.min_length
                    && trimmed.len() <= self.config.max_length
                {
                    Some(trimmed.to_string())
                } else {
                    None
                }
            })
            .collect();

        Ok(strings)
    }

    /// Filter strings to keep only interesting ones
    fn filter_strings(&self, strings: HashSet<String>) -> HashSet<String> {
        strings
            .into_iter()
            .filter(|s| self.is_interesting_string(s))
            .collect()
    }

    /// Check if a string is potentially interesting for libc analysis
    fn is_interesting_string(&self, s: &str) -> bool {
        // Check against libc patterns
        for pattern in &self.libc_patterns {
            if pattern.is_match(s) {
                return true;
            }
        }

        // Check for common library-related keywords
        let lower = s.to_lowercase();
        let interesting_keywords = [
            "glibc",
            "libc",
            "gnu",
            "version",
            "copyright",
            "malloc",
            "free",
            "printf",
            "scanf",
            "memcpy",
            "strlen",
            "strcpy",
            "strcmp",
            "__libc",
            "_IO_",
            ".so",
            "lib",
            "/usr",
            "/lib",
            "ld-",
            "rtld",
        ];

        for keyword in &interesting_keywords {
            if lower.contains(keyword) {
                return true;
            }
        }

        // Check for version-like patterns
        let version_pattern = Regex::new(r"\d+\.\d+").unwrap();
        if version_pattern.is_match(s) {
            return true;
        }

        // Keep strings that look like function names (alphanumeric with underscores)
        let func_pattern = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();
        if func_pattern.is_match(s) && s.len() >= 3 {
            return true;
        }

        // Keep file paths
        if s.starts_with('/') && s.contains('/') {
            return true;
        }

        false
    }

    /// Extract version strings specifically
    pub fn extract_version_strings(&self, strings: &HashSet<String>) -> Vec<String> {
        let version_patterns = [
            Regex::new(r"GLIBC_[\d.]+").unwrap(),
            Regex::new(r"LIBC_[\d.]+").unwrap(),
            Regex::new(r"GNU C Library.*version.*[\d.]+").unwrap(),
            Regex::new(r"glibc.*[\d.]+").unwrap(),
            Regex::new(r"libc.*[\d.]+").unwrap(),
        ];

        let mut version_strings = Vec::new();

        for string in strings {
            for pattern in &version_patterns {
                if pattern.is_match(string) {
                    version_strings.push(string.clone());
                    break;
                }
            }
        }

        version_strings.sort();
        version_strings.dedup();
        version_strings
    }

    /// Get configuration
    pub fn config(&self) -> &StringsConfig {
        &self.config
    }

    /// Check if external strings command is available
    pub fn is_strings_available() -> bool {
        Command::new("strings")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strings_extractor_creation() {
        let extractor = StringsExtractor::default();
        assert!(extractor.is_ok());
    }

    #[test]
    fn test_ascii_string_extraction() {
        let config = StringsConfig::default();
        let extractor = StringsExtractor::new(config).unwrap();

        let data =
            b"Hello\x00World\x00This is a test\x00Short\x00VeryLongStringThatShouldBeExtracted\x00";
        let strings = extractor.extract_ascii_strings(data);

        assert!(strings.contains("Hello"));
        assert!(strings.contains("World"));
        assert!(strings.contains("This is a test"));
        assert!(strings.contains("VeryLongStringThatShouldBeExtracted"));
        // "Short" should be filtered out due to min_length = 4
        assert!(!strings.contains("Short"));
    }

    #[test]
    fn test_interesting_string_filtering() {
        let config = StringsConfig::default();
        let extractor = StringsExtractor::new(config).unwrap();

        assert!(extractor.is_interesting_string("printf"));
        assert!(extractor.is_interesting_string("GLIBC_2.2.5"));
        assert!(extractor.is_interesting_string("libc.so.6"));
        assert!(extractor.is_interesting_string("/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(extractor.is_interesting_string("malloc_hook"));
        assert!(extractor.is_interesting_string("version 2.31"));

        assert!(!extractor.is_interesting_string("abc"));
        assert!(!extractor.is_interesting_string("random_text"));
        assert!(!extractor.is_interesting_string("123"));
    }

    #[test]
    fn test_version_string_extraction() {
        let config = StringsConfig::default();
        let extractor = StringsExtractor::new(config).unwrap();

        let mut strings = HashSet::new();
        strings.insert("GLIBC_2.2.5".to_string());
        strings.insert("LIBC_2.1".to_string());
        strings.insert("GNU C Library stable release version 2.31".to_string());
        strings.insert("random string".to_string());
        strings.insert("printf".to_string());

        let version_strings = extractor.extract_version_strings(&strings);

        assert!(version_strings.contains(&"GLIBC_2.2.5".to_string()));
        assert!(version_strings.contains(&"LIBC_2.1".to_string()));
        assert!(version_strings.contains(&"GNU C Library stable release version 2.31".to_string()));
        assert!(!version_strings.contains(&"random string".to_string()));
        assert!(!version_strings.contains(&"printf".to_string()));
    }

    #[test]
    fn test_wide_string_extraction() {
        let config = StringsConfig::default();
        let extractor = StringsExtractor::new(config).unwrap();

        // Create UTF-16LE encoded "Hello" (H=0x48, e=0x65, l=0x6C, l=0x6C, o=0x6F)
        let data = vec![
            0x48, 0x00, // H
            0x65, 0x00, // e
            0x6C, 0x00, // l
            0x6C, 0x00, // l
            0x6F, 0x00, // o
            0x00, 0x00, // null terminator
        ];

        let strings = extractor.extract_wide_strings(&data);
        assert!(strings.contains("Hello"));
    }

    #[test]
    fn test_strings_availability_check() {
        // This test may fail on systems without the strings command
        // but that's expected behavior
        let available = StringsExtractor::is_strings_available();
        println!("Strings command available: {}", available);
    }

    #[test]
    fn test_config_customization() {
        let mut config = StringsConfig::default();
        config.min_length = 10;
        config.max_length = 50;
        config.use_external_strings = false;

        let extractor = StringsExtractor::new(config).unwrap();
        assert_eq!(extractor.config().min_length, 10);
        assert_eq!(extractor.config().max_length, 50);
        assert!(!extractor.config().use_external_strings);
    }
}
