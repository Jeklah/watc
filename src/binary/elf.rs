//! ELF binary parser implementation

use super::common::{AnalysisResult, BinaryFormat, BinaryInfo, BinaryParser, Symbol, SymbolType};
use anyhow::{anyhow, Result};
use goblin::elf::Elf;
use std::collections::HashSet;

/// ELF binary parser
pub struct ElfParser;

impl ElfParser {
    pub fn new() -> Self {
        Self
    }

    /// Extract architecture information from ELF header
    fn get_architecture(elf: &Elf) -> String {
        match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
            goblin::elf::header::EM_386 => "i386".to_string(),
            goblin::elf::header::EM_ARM => "ARM".to_string(),
            goblin::elf::header::EM_AARCH64 => "AArch64".to_string(),
            goblin::elf::header::EM_RISCV => "RISC-V".to_string(),
            goblin::elf::header::EM_PPC => "PowerPC".to_string(),
            goblin::elf::header::EM_PPC64 => "PowerPC64".to_string(),
            goblin::elf::header::EM_MIPS => "MIPS".to_string(),
            _ => format!("Unknown ({})", elf.header.e_machine),
        }
    }

    /// Determine if the ELF is 32-bit or 64-bit
    fn get_bitness(elf: &Elf) -> u8 {
        match elf.header.e_ident[goblin::elf::header::EI_CLASS] {
            goblin::elf::header::ELFCLASS32 => 32,
            goblin::elf::header::ELFCLASS64 => 64,
            _ => 0, // Unknown
        }
    }

    /// Convert goblin symbol type to our SymbolType
    fn convert_symbol_type(st_type: u8) -> SymbolType {
        match st_type {
            goblin::elf::sym::STT_FUNC => SymbolType::Function,
            goblin::elf::sym::STT_OBJECT => SymbolType::Object,
            goblin::elf::sym::STT_SECTION => SymbolType::Section,
            goblin::elf::sym::STT_FILE => SymbolType::File,
            _ => SymbolType::Unknown,
        }
    }

    /// Extract symbols from ELF symbol tables
    fn extract_symbols(elf: &Elf, data: &[u8]) -> Result<HashSet<Symbol>> {
        let mut symbols = HashSet::new();

        // Extract from dynamic symbol table
        for sym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    let symbol = Symbol {
                        name: name.to_string(),
                        address: if sym.st_value != 0 {
                            Some(sym.st_value)
                        } else {
                            None
                        },
                        is_import: sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize,
                        section: None, // We could resolve this from section headers if needed
                        symbol_type: Self::convert_symbol_type(sym.st_type()),
                    };
                    symbols.insert(symbol);
                }
            }
        }

        // Extract from regular symbol table
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    let symbol = Symbol {
                        name: name.to_string(),
                        address: if sym.st_value != 0 {
                            Some(sym.st_value)
                        } else {
                            None
                        },
                        is_import: sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize,
                        section: None,
                        symbol_type: Self::convert_symbol_type(sym.st_type()),
                    };
                    symbols.insert(symbol);
                }
            }
        }

        Ok(symbols)
    }

    /// Extract shared library dependencies
    fn extract_dependencies(elf: &Elf) -> Vec<String> {
        let mut dependencies = Vec::new();

        // Look through dynamic entries for needed libraries
        if let Some(dynamic) = &elf.dynamic {
            for dyn_entry in &dynamic.dyns {
                if dyn_entry.d_tag == goblin::elf::dynamic::DT_NEEDED {
                    if let Some(lib_name) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                        dependencies.push(lib_name.to_string());
                    }
                }
            }
        }

        dependencies
    }

    /// Extract imported functions specifically
    fn extract_imported_functions(symbols: &HashSet<Symbol>) -> HashSet<String> {
        symbols
            .iter()
            .filter(|sym| sym.is_import && sym.symbol_type == SymbolType::Function)
            .map(|sym| sym.name.clone())
            .collect()
    }
}

impl Default for ElfParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryParser for ElfParser {
    fn parse(&self, data: &[u8], file_path: &str) -> Result<AnalysisResult> {
        let elf = Elf::parse(data).map_err(|e| anyhow!("Failed to parse ELF: {}", e))?;

        let binary_info = BinaryInfo {
            path: file_path.to_string(),
            format: BinaryFormat::ELF,
            architecture: Self::get_architecture(&elf),
            bitness: Self::get_bitness(&elf),
            entry_point: if elf.header.e_entry != 0 {
                Some(elf.header.e_entry)
            } else {
                None
            },
            dependencies: Self::extract_dependencies(&elf),
        };

        let symbols = Self::extract_symbols(&elf, data)?;
        let imported_functions = Self::extract_imported_functions(&symbols);

        // Extract strings from various sections
        let mut strings = HashSet::new();

        // Add strings from string tables
        for string in elf.strtab.to_vec()? {
            if !string.is_empty() && string.len() > 3 {
                strings.insert(string.to_string());
            }
        }

        for string in elf.dynstrtab.to_vec()? {
            if !string.is_empty() && string.len() > 3 {
                strings.insert(string.to_string());
            }
        }

        // Look for .rodata section and extract strings from it
        for section in &elf.section_headers {
            if let Some(section_name) = elf.shdr_strtab.get_at(section.sh_name) {
                if section_name == ".rodata" && section.sh_size > 0 {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    if end <= data.len() {
                        let section_data = &data[start..end];
                        // Simple string extraction - look for null-terminated strings
                        let mut current_string = Vec::new();
                        for &byte in section_data {
                            if byte == 0 {
                                if current_string.len() > 3 {
                                    if let Ok(s) = String::from_utf8(current_string.clone()) {
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
        }

        // Note: For more comprehensive analysis of ELF files, consider using readelf
        // which can extract additional information like version requirements,
        // symbol versioning, and detailed section information.
        let mut errors = Vec::new();
        if symbols.is_empty() && imported_functions.is_empty() {
            errors.push(
                "No symbols found. Consider using readelf for enhanced analysis.".to_string(),
            );
        }

        Ok(AnalysisResult {
            binary_info,
            symbols,
            imported_functions,
            strings,
            errors,
        })
    }

    fn can_parse(&self, data: &[u8]) -> bool {
        // Check for ELF magic number
        data.len() >= 4 && &data[0..4] == b"\x7fELF"
    }

    fn name(&self) -> &'static str {
        "ELF Parser"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_parse_elf() {
        let parser = ElfParser::new();

        // Valid ELF magic
        let elf_data = b"\x7fELF\x02\x01\x01\x00";
        assert!(parser.can_parse(elf_data));

        // Invalid magic
        let invalid_data = b"MZ\x90\x00";
        assert!(!parser.can_parse(invalid_data));

        // Too short
        let short_data = b"\x7f";
        assert!(!parser.can_parse(short_data));
    }
}
