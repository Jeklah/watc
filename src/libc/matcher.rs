//! Symbol matching logic for libc version detection
//!
//! This module provides functionality to match symbols against libc versions
//! and determine the most likely C library version used in a binary.

use super::api::{LibcApiClient, LibcMatch, LibcResponse};
use crate::analysis::{ComprehensiveAnalysis, SymbolCategory};
use anyhow::Result;
use std::collections::HashMap;

/// Confidence thresholds for different types of matches
const HIGH_CONFIDENCE_THRESHOLD: f64 = 0.8;
const MEDIUM_CONFIDENCE_THRESHOLD: f64 = 0.5;
const MIN_SYMBOL_MATCHES: usize = 3;

/// Result of libc version detection
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// The most likely libc matches, sorted by confidence
    pub matches: Vec<LibcMatchWithScore>,
    /// Total number of symbols used for detection
    pub symbols_analyzed: usize,
    /// Best overall confidence score
    pub best_confidence: f64,
    /// Detection strategy used
    pub strategy: DetectionStrategy,
    /// Any warnings or notes about the detection
    pub warnings: Vec<String>,
}

/// A libc match with additional scoring information
#[derive(Debug, Clone)]
pub struct LibcMatchWithScore {
    /// The original libc match from the API
    pub libc_match: LibcMatch,
    /// Overall confidence score (0.0 to 1.0)
    pub overall_score: f64,
    /// Symbol match score
    pub symbol_score: f64,
    /// Version consistency score
    pub version_score: f64,
    /// Architecture compatibility score
    pub arch_score: f64,
    /// Reasons for this score
    pub score_reasons: Vec<String>,
}

/// Detection strategy used
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionStrategy {
    /// Used versioned symbols (highest confidence)
    VersionedSymbols,
    /// Used high-confidence function symbols
    HighConfidenceSymbols,
    /// Used mixed symbol categories
    MixedSymbols,
    /// Used string analysis
    StringAnalysis,
    /// Combined multiple strategies
    Combined,
}

/// Libc matcher for symbol-based version detection
pub struct LibcMatcher {
    api_client: LibcApiClient,
}

impl LibcMatcher {
    /// Create a new libc matcher with API client
    pub fn new(api_client: LibcApiClient) -> Self {
        Self { api_client }
    }

    /// Create a matcher with default API client
    pub fn default() -> Result<Self> {
        Ok(Self {
            api_client: LibcApiClient::new()?,
        })
    }

    /// Detect libc version from comprehensive analysis results
    pub async fn detect_libc_version(
        &self,
        analysis: &ComprehensiveAnalysis,
    ) -> Result<DetectionResult> {
        let mut all_matches = Vec::new();
        let mut strategies_used = Vec::new();
        let mut warnings = Vec::new();
        let mut total_symbols = 0;

        // Check if we have symbols with addresses
        let symbols_with_addresses = analysis
            .categorized_symbols
            .iter()
            .filter(|sym| sym.symbol.address.is_some())
            .count();

        if symbols_with_addresses == 0 {
            warnings.push(
                "No symbols with addresses found - binary uses dynamic linking. \
                API requires runtime addresses for accurate matching."
                    .to_string(),
            );
        } else if symbols_with_addresses < 5 {
            warnings.push(format!(
                "Only {} symbols with addresses found - results may be limited. \
                Dynamic binaries are harder to match accurately.",
                symbols_with_addresses
            ));
        }

        // Strategy 1: Try versioned symbols first (highest confidence)
        let versioned_symbols = self.extract_versioned_symbols(analysis);
        if !versioned_symbols.is_empty() {
            match self.query_api_with_symbols(&versioned_symbols).await {
                Ok(response) => {
                    let matches = self.score_matches(
                        response,
                        &analysis.binary_analysis.binary_info.architecture,
                        DetectionStrategy::VersionedSymbols,
                    );
                    all_matches.extend(matches);
                    strategies_used.push(DetectionStrategy::VersionedSymbols);
                    total_symbols += versioned_symbols.len();
                }
                Err(e) => {
                    warnings.push(format!("Failed to query versioned symbols: {}", e));
                }
            }
        }

        // Strategy 2: High-confidence symbols
        let high_conf_symbols = self.extract_high_confidence_symbols(analysis);
        if !high_conf_symbols.is_empty() && all_matches.len() < 5 {
            match self.query_api_with_symbols(&high_conf_symbols).await {
                Ok(response) => {
                    let matches = self.score_matches(
                        response,
                        &analysis.binary_analysis.binary_info.architecture,
                        DetectionStrategy::HighConfidenceSymbols,
                    );
                    all_matches.extend(matches);
                    strategies_used.push(DetectionStrategy::HighConfidenceSymbols);
                    total_symbols += high_conf_symbols.len();
                }
                Err(e) => {
                    warnings.push(format!("Failed to query high-confidence symbols: {}", e));
                }
            }
        }

        // Strategy 3: Mixed symbols from different categories
        if all_matches.len() < 3 {
            let mixed_symbols = self.extract_mixed_category_symbols(analysis);
            if !mixed_symbols.is_empty() {
                match self.query_api_with_symbols(&mixed_symbols).await {
                    Ok(response) => {
                        let matches = self.score_matches(
                            response,
                            &analysis.binary_analysis.binary_info.architecture,
                            DetectionStrategy::MixedSymbols,
                        );
                        all_matches.extend(matches);
                        strategies_used.push(DetectionStrategy::MixedSymbols);
                        total_symbols += mixed_symbols.len();
                    }
                    Err(e) => {
                        warnings.push(format!("Failed to query mixed symbols: {}", e));
                    }
                }
            }
        }

        // Merge and deduplicate matches
        let final_matches = self.merge_and_rank_matches(all_matches);

        let strategy = if strategies_used.len() > 1 {
            DetectionStrategy::Combined
        } else {
            strategies_used
                .first()
                .cloned()
                .unwrap_or(DetectionStrategy::MixedSymbols)
        };

        let best_confidence = final_matches
            .first()
            .map(|m| m.overall_score)
            .unwrap_or(0.0);

        // Add warnings based on results
        if final_matches.is_empty() {
            if symbols_with_addresses == 0 {
                warnings.push(
                    "No libc matches found - dynamically linked binary requires runtime addresses. \
                    Consider analyzing the binary at runtime or with a debugger to get actual function addresses."
                        .to_string(),
                );
            } else {
                warnings.push(
                    "No libc matches found - addresses may not match database entries or unsupported libc version"
                        .to_string(),
                );
            }
        } else if best_confidence < MEDIUM_CONFIDENCE_THRESHOLD {
            warnings.push(
                "Low confidence in detection results - consider manual verification".to_string(),
            );
        }

        if total_symbols < MIN_SYMBOL_MATCHES {
            warnings
                .push("Few symbols available for analysis - results may be unreliable".to_string());
        }

        Ok(DetectionResult {
            matches: final_matches,
            symbols_analyzed: total_symbols,
            best_confidence,
            strategy,
            warnings,
        })
    }

    /// Extract versioned symbols (e.g., printf@@GLIBC_2.2.5)
    fn extract_versioned_symbols(
        &self,
        analysis: &ComprehensiveAnalysis,
    ) -> Vec<(String, Option<u64>)> {
        analysis
            .categorized_symbols
            .iter()
            .filter(|sym| sym.category == SymbolCategory::Versioned)
            .map(|sym| (sym.symbol.name.clone(), sym.symbol.address))
            .collect()
    }

    /// Extract high-confidence symbols
    fn extract_high_confidence_symbols(
        &self,
        analysis: &ComprehensiveAnalysis,
    ) -> Vec<(String, Option<u64>)> {
        analysis
            .libc_symbols
            .iter()
            .filter(|sym| sym.confidence >= HIGH_CONFIDENCE_THRESHOLD)
            .map(|sym| (sym.clean_name.clone(), sym.symbol.address))
            .take(15) // Limit to avoid overwhelming the API
            .collect()
    }

    /// Extract symbols from different categories for broader matching
    fn extract_mixed_category_symbols(
        &self,
        analysis: &ComprehensiveAnalysis,
    ) -> Vec<(String, Option<u64>)> {
        let mut symbols = Vec::new();
        let categories_to_include = vec![
            SymbolCategory::LibcStandard,
            SymbolCategory::Memory,
            SymbolCategory::String,
            SymbolCategory::FileIO,
        ];

        for category in categories_to_include {
            let category_symbols: Vec<(String, Option<u64>)> = analysis
                .libc_symbols
                .iter()
                .filter(|sym| {
                    sym.category == category && sym.confidence >= MEDIUM_CONFIDENCE_THRESHOLD
                })
                .map(|sym| (sym.clean_name.clone(), sym.symbol.address))
                .take(3) // Take a few from each category
                .collect();

            symbols.extend(category_symbols);
        }

        symbols
    }

    /// Query the API with a list of symbols
    async fn query_api_with_symbols(
        &self,
        symbols: &[(String, Option<u64>)],
    ) -> Result<LibcResponse> {
        if symbols.is_empty() {
            return Ok(LibcResponse {
                results: Vec::new(),
                query_info: None,
            });
        }

        self.api_client.query_symbols(symbols).await
    }

    /// Score and rank matches from API response
    fn score_matches(
        &self,
        response: LibcResponse,
        target_arch: &str,
        strategy: DetectionStrategy,
    ) -> Vec<LibcMatchWithScore> {
        response
            .results
            .into_iter()
            .map(|libc_match| self.calculate_match_score(libc_match, target_arch, &strategy))
            .collect()
    }

    /// Calculate comprehensive score for a libc match
    fn calculate_match_score(
        &self,
        libc_match: LibcMatch,
        target_arch: &str,
        strategy: &DetectionStrategy,
    ) -> LibcMatchWithScore {
        let mut score_reasons = Vec::new();

        // Symbol match score (based on API confidence)
        let symbol_score = libc_match.confidence;
        if symbol_score >= HIGH_CONFIDENCE_THRESHOLD {
            score_reasons.push("High symbol match confidence".to_string());
        } else if symbol_score >= MEDIUM_CONFIDENCE_THRESHOLD {
            score_reasons.push("Medium symbol match confidence".to_string());
        } else {
            score_reasons.push("Low symbol match confidence".to_string());
        }

        // Architecture compatibility score
        let arch_score = if let Some(ref arch) = libc_match.arch {
            if arch.to_lowercase() == target_arch.to_lowercase() {
                score_reasons.push("Architecture matches perfectly".to_string());
                1.0
            } else if self.architectures_compatible(arch, target_arch) {
                score_reasons.push("Architecture is compatible".to_string());
                0.8
            } else {
                score_reasons.push("Architecture mismatch".to_string());
                0.3
            }
        } else {
            score_reasons.push("Architecture not specified".to_string());
            0.7
        };

        // Version consistency score
        let version_score = match strategy {
            DetectionStrategy::VersionedSymbols => {
                score_reasons.push("Used versioned symbols for detection".to_string());
                0.95
            }
            DetectionStrategy::HighConfidenceSymbols => {
                score_reasons.push("Used high-confidence symbols".to_string());
                0.8
            }
            _ => {
                score_reasons.push("Used mixed symbol analysis".to_string());
                0.6
            }
        };

        // Bonus for more matched symbols
        let symbol_bonus = if libc_match.symbols_matched >= 10 {
            score_reasons.push("High number of symbol matches".to_string());
            1.1
        } else if libc_match.symbols_matched >= 5 {
            score_reasons.push("Good number of symbol matches".to_string());
            1.0
        } else {
            score_reasons.push("Few symbol matches".to_string());
            0.9
        };

        // Calculate overall score
        let overall_score =
            ((symbol_score * 0.4 + arch_score * 0.3 + version_score * 0.3) * symbol_bonus).min(1.0);

        LibcMatchWithScore {
            libc_match,
            overall_score,
            symbol_score,
            version_score,
            arch_score,
            score_reasons,
        }
    }

    /// Check if architectures are compatible
    fn architectures_compatible(&self, arch1: &str, arch2: &str) -> bool {
        let arch1_norm = arch1.to_lowercase();
        let arch2_norm = arch2.to_lowercase();

        // Handle common architecture aliases
        let compatible_pairs = vec![
            (
                vec!["x86_64", "amd64", "x64"],
                vec!["x86_64", "amd64", "x64"],
            ),
            (
                vec!["i386", "i486", "i586", "i686", "x86"],
                vec!["i386", "i486", "i586", "i686", "x86"],
            ),
            (
                vec!["arm", "armv7", "armv7l"],
                vec!["arm", "armv7", "armv7l"],
            ),
            (vec!["aarch64", "arm64"], vec!["aarch64", "arm64"]),
        ];

        for (group1, group2) in compatible_pairs {
            if group1.contains(&arch1_norm.as_str()) && group2.contains(&arch2_norm.as_str()) {
                return true;
            }
        }

        false
    }

    /// Merge and rank matches, removing duplicates
    fn merge_and_rank_matches(&self, matches: Vec<LibcMatchWithScore>) -> Vec<LibcMatchWithScore> {
        // Group by libc ID and keep the best score for each
        let mut best_matches: HashMap<String, LibcMatchWithScore> = HashMap::new();

        for match_result in matches {
            let id = match_result.libc_match.id.clone();

            if let Some(existing) = best_matches.get(&id) {
                if match_result.overall_score > existing.overall_score {
                    best_matches.insert(id, match_result);
                }
            } else {
                best_matches.insert(id, match_result);
            }
        }

        // Convert to vector and sort by overall score
        let mut final_matches: Vec<LibcMatchWithScore> = best_matches.into_values().collect();
        final_matches.sort_by(|a, b| b.overall_score.partial_cmp(&a.overall_score).unwrap());

        // Limit to top 10 results
        final_matches.truncate(10);
        final_matches
    }

    /// Get the API client reference
    pub fn api_client(&self) -> &LibcApiClient {
        &self.api_client
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::symbols::SymbolAnalyzer;
    use crate::binary::common::{BinaryFormat, BinaryInfo, Symbol, SymbolType};
    use std::collections::HashSet;

    fn create_test_analysis() -> ComprehensiveAnalysis {
        let mut symbols = HashSet::new();
        symbols.insert(Symbol {
            name: "printf@@GLIBC_2.2.5".to_string(),
            address: Some(0x1000),
            is_import: true,
            section: None,
            symbol_type: SymbolType::Function,
        });

        let analyzer = SymbolAnalyzer::new().unwrap();
        let symbol_vec: Vec<Symbol> = symbols.iter().cloned().collect();
        let categorized = analyzer.analyze_symbols(&symbol_vec);

        ComprehensiveAnalysis {
            binary_analysis: crate::binary::AnalysisResult {
                binary_info: BinaryInfo {
                    path: "/test".to_string(),
                    format: BinaryFormat::ELF,
                    architecture: "x86_64".to_string(),
                    bitness: 64,
                    entry_point: Some(0x1000),
                    dependencies: vec!["libc.so.6".to_string()],
                },
                symbols,
                imported_functions: HashSet::new(),
                strings: HashSet::new(),
                errors: Vec::new(),
            },
            categorized_symbols: categorized.clone(),
            libc_symbols: categorized,
            version_strings: vec!["GLIBC_2.2.5".to_string()],
            filtered_strings: HashSet::new(),
            symbol_statistics: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_matcher_creation() {
        let client = LibcApiClient::new().unwrap();
        let _matcher = LibcMatcher::new(client);
    }

    #[test]
    fn test_extract_versioned_symbols() {
        let client = LibcApiClient::new().unwrap();
        let matcher = LibcMatcher::new(client);
        let analysis = create_test_analysis();

        let versioned = matcher.extract_versioned_symbols(&analysis);
        assert!(!versioned.is_empty());
        assert!(versioned
            .iter()
            .any(|(name, _)| name == "printf@@GLIBC_2.2.5"));
    }

    #[test]
    fn test_architecture_compatibility() {
        let client = LibcApiClient::new().unwrap();
        let matcher = LibcMatcher::new(client);

        assert!(matcher.architectures_compatible("x86_64", "amd64"));
        assert!(matcher.architectures_compatible("amd64", "x64"));
        assert!(matcher.architectures_compatible("i386", "i686"));
        assert!(matcher.architectures_compatible("arm64", "aarch64"));

        assert!(!matcher.architectures_compatible("x86_64", "arm64"));
        assert!(!matcher.architectures_compatible("i386", "x86_64"));
    }

    #[test]
    fn test_match_scoring() {
        let client = LibcApiClient::new().unwrap();
        let matcher = LibcMatcher::new(client);

        let libc_match = LibcMatch {
            id: "test-id".to_string(),
            buildid: String::new(),
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            download_url: None,
            symbols_url: None,
            libs_url: None,
            symbols: std::collections::HashMap::new(),
            confidence: 0.95,
            symbols_matched: 5,
            matched_symbols: vec!["printf".to_string(), "malloc".to_string()],
            name: "GNU C Library".to_string(),
            arch: Some("x86_64".to_string()),
            os: Some("linux".to_string()),
            version: Some("2.31".to_string()),
        };

        let scored = matcher.calculate_match_score(
            libc_match,
            "x86_64",
            &DetectionStrategy::VersionedSymbols,
        );

        assert!(scored.overall_score > 0.8);
        assert!(scored.arch_score > 0.9); // Perfect arch match
        assert!(scored.version_score > 0.9); // Versioned symbols strategy
        assert!(!scored.score_reasons.is_empty());
    }
}
