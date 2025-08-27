//! PE binary parser implementation

use super::common::{AnalysisResult, BinaryFormat, BinaryInfo, BinaryParser, Symbol, SymbolType};
use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::collections::HashSet;

/// PE binary parser
pub struct PeParser;

impl PeParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract architecture information from PE header
    fn get_architecture(pe: &PE) -> String {
        match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => "x86_64".to_string(),
            goblin::pe::header::COFF_MACHINE_X86 => "i386".to_string(),
            goblin::pe::header::COFF_MACHINE_ARM => "ARM".to_string(),
            goblin::pe::header::COFF_MACHINE_ARM64 => "ARM64".to_string(),
            goblin::pe::header::COFF_MACHINE_ARMNT => "ARM (Windows RT)".to_string(),
            _ => format!("Unknown (0x{:x})", pe.header.coff_header.machine),
        }
    }

    /// Determine if the PE is 32-bit or 64-bit
    fn get_bitness(pe: &PE) -> u8 {
        if pe.is_64 {
            64
        } else {
            32
        }
    }

    /// Extract symbols from PE import table
    fn extract_symbols(pe: &PE, data: &[u8]) -> Result<HashSet<Symbol>> {
        let mut symbols = HashSet::new();

        // Extract imported symbols
        for import in &pe.imports {
            let dll_name = import.dll.to_string();

            // goblin PE imports don't have a functions field - they represent individual imports
            let symbol = Symbol {
                name: import.name.to_string(),
                address: if import.rva != 0 {
                    Some(import.rva as u64)
                } else {
                    None
                },
                is_import: true,
                section: Some(dll_name),
                symbol_type: SymbolType::Function,
            };
            symbols.insert(symbol);
        }

        // Extract exported symbols if present
        for export in &pe.exports {
            let symbol = Symbol {
                name: export
                    .name
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unknown_export".to_string()),
                address: if export.rva != 0 {
                    Some(export.rva as u64)
                } else {
                    None
                },
                is_import: false,
                section: None,
                symbol_type: SymbolType::Function,
            };
            symbols.insert(symbol);
        }

        Ok(symbols)
    }

    /// Extract DLL dependencies
    fn extract_dependencies(pe: &PE) -> Vec<String> {
        pe.imports
            .iter()
            .map(|import| import.dll.to_string())
            .collect()
    }

    /// Extract imported functions specifically
    fn extract_imported_functions(symbols: &HashSet<Symbol>) -> HashSet<String> {
        symbols
            .iter()
            .filter(|sym| sym.is_import && sym.symbol_type == SymbolType::Function)
            .map(|sym| sym.name.clone())
            .collect()
    }

    /// Extract strings from PE sections
    fn extract_strings_from_sections(pe: &PE, data: &[u8]) -> HashSet<String> {
        let mut strings = HashSet::new();

        // Look through sections for string data
        for section in &pe.sections {
            let section_name = String::from_utf8_lossy(&section.name);

            // Focus on sections that typically contain strings
            if section_name.starts_with(".rdata")
                || section_name.starts_with(".data")
                || section_name.starts_with(".rodata")
            {
                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                let end = start + size;

                if start < data.len() && end <= data.len() && size > 0 {
                    let section_data = &data[start..end];

                    // Extract null-terminated strings
                    let mut current_string = Vec::new();
                    for &byte in section_data {
                        if byte == 0 {
                            if current_string.len() > 3 {
                                if let Ok(s) = String::from_utf8(current_string.clone()) {
                                    // Check if it's a reasonable string (printable ASCII)
                                    if s.chars().all(|c| {
                                        c.is_ascii()
                                            && (c.is_alphanumeric()
                                                || c.is_ascii_punctuation()
                                                || c.is_whitespace())
                                    }) {
                                        strings.insert(s);
                                    }
                                }
                            }
                            current_string.clear();
                        } else if byte.is_ascii() && byte >= 32 {
                            current_string.push(byte);
                        } else {
                            current_string.clear();
                        }
                    }
                }
            }
        }

        strings
    }
}

impl Default for PeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryParser for PeParser {
    fn parse(&self, data: &[u8], file_path: &str) -> Result<AnalysisResult> {
        let pe = PE::parse(data).map_err(|e| anyhow!("Failed to parse PE: {}", e))?;

        let binary_info = BinaryInfo {
            path: file_path.to_string(),
            format: BinaryFormat::PE,
            architecture: Self::get_architecture(&pe),
            bitness: Self::get_bitness(&pe),
            entry_point: Some(pe.entry as u64),
            dependencies: Self::extract_dependencies(&pe),
        };

        let symbols = Self::extract_symbols(&pe, data)?;
        let imported_functions = Self::extract_imported_functions(&symbols);
        let strings = Self::extract_strings_from_sections(&pe, data);

        Ok(AnalysisResult {
            binary_info,
            symbols,
            imported_functions,
            strings,
            errors: Vec::new(),
        })
    }

    fn can_parse(&self, data: &[u8]) -> bool {
        // Check for PE magic number (MZ header followed by PE signature)
        if data.len() < 64 {
            return false;
        }

        // Check MZ signature
        if &data[0..2] != b"MZ" {
            return false;
        }

        // Get PE header offset
        if let Ok(pe_offset_bytes) = data[60..64].try_into() {
            let pe_offset = u32::from_le_bytes(pe_offset_bytes) as usize;

            // Check if PE signature exists at the offset
            if pe_offset + 4 <= data.len() {
                return &data[pe_offset..pe_offset + 4] == b"PE\x00\x00";
            }
        }

        false
    }

    fn name(&self) -> &'static str {
        "PE Parser"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_parse_pe() {
        let parser = PeParser::new();

        // Create minimal PE header for testing
        let mut pe_data = vec![0u8; 1024];

        // MZ signature
        pe_data[0] = b'M';
        pe_data[1] = b'Z';

        // PE header offset at position 60
        let pe_offset = 128u32;
        pe_data[60..64].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature at offset
        pe_data[128..132].copy_from_slice(b"PE\x00\x00");

        assert!(parser.can_parse(&pe_data));

        // Invalid MZ signature
        let mut invalid_data = pe_data.clone();
        invalid_data[0] = b'X';
        assert!(!parser.can_parse(&invalid_data));

        // Invalid PE signature
        let mut invalid_pe = pe_data.clone();
        invalid_pe[128..132].copy_from_slice(b"XX\x00\x00");
        assert!(!parser.can_parse(&invalid_pe));

        // Too short
        let short_data = b"MZ";
        assert!(!parser.can_parse(short_data));
    }
}
