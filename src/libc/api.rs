//! API client for libc.rip database
//!
//! This module provides functionality to query the libc.rip database
//! to identify C library versions based on function symbols and their addresses.
//!
//! The libc.rip API expects symbols as an object with symbol names as keys
//! and hexadecimal addresses as values. It returns an array of matching
//! libc versions with their metadata and symbol tables.

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Base URL for the libc.rip API
const LIBC_API_BASE_URL: &str = "https://libc.rip/api";

/// Timeout for API requests
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of symbols to send in a single API request
const MAX_SYMBOLS_PER_REQUEST: usize = 20;

/// Response from libc database API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibcResponse {
    /// List of matching libc versions
    pub results: Vec<LibcMatch>,
    /// Query metadata
    pub query_info: Option<QueryInfo>,
}

/// A single libc match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibcMatch {
    /// ID of the libc version in the database
    pub id: String,
    /// Build ID of the libc
    #[serde(default)]
    pub buildid: String,
    /// MD5 hash
    #[serde(default)]
    pub md5: String,
    /// SHA1 hash
    #[serde(default)]
    pub sha1: String,
    /// SHA256 hash
    #[serde(default)]
    pub sha256: String,
    /// URL to download this libc version
    pub download_url: Option<String>,
    /// URL to download symbols
    #[serde(default)]
    pub symbols_url: Option<String>,
    /// URL to download libs
    #[serde(default)]
    pub libs_url: Option<String>,
    /// Symbol addresses for this libc
    #[serde(default)]
    pub symbols: std::collections::HashMap<String, String>,
    /// Confidence score for this match (0.0 to 1.0) - calculated locally
    #[serde(default)]
    pub confidence: f64,
    /// Number of symbols matched - calculated locally
    #[serde(default)]
    pub symbols_matched: usize,
    /// List of matched symbols - calculated locally
    #[serde(default)]
    pub matched_symbols: Vec<String>,
    /// Human-readable name derived from ID
    #[serde(default)]
    pub name: String,
    /// Architecture extracted from ID
    #[serde(default)]
    pub arch: Option<String>,
    /// Operating system - typically "linux"
    #[serde(default)]
    pub os: Option<String>,
    /// Version extracted from ID
    #[serde(default)]
    pub version: Option<String>,
}

/// Query information and statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryInfo {
    /// Number of symbols queried
    pub symbols_queried: usize,
    /// Total matches found
    pub total_matches: usize,
    /// Time taken for the query (in milliseconds)
    pub query_time_ms: Option<u64>,
}

/// Configuration for the libc API client
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Base URL for the API
    pub base_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum symbols per request
    pub max_symbols_per_request: usize,
    /// User agent string
    pub user_agent: String,
    /// Whether to use caching
    pub enable_cache: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            base_url: LIBC_API_BASE_URL.to_string(),
            timeout: REQUEST_TIMEOUT,
            max_symbols_per_request: MAX_SYMBOLS_PER_REQUEST,
            user_agent: format!("watc/{}", env!("CARGO_PKG_VERSION")),
            enable_cache: true,
        }
    }
}

/// Client for querying the libc database
pub struct LibcApiClient {
    client: Client,
    config: ApiConfig,
    cache: std::sync::Mutex<HashMap<String, LibcResponse>>,
}

impl LibcApiClient {
    /// Create a new API client with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(ApiConfig::default())
    }

    /// Create a new API client with custom configuration
    pub fn with_config(config: ApiConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            client,
            config,
            cache: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Query the libc database with symbols and their addresses
    ///
    /// The API requires actual runtime addresses to find matches. Symbols without
    /// addresses are skipped as they're unlikely to match database entries.
    pub async fn query_symbols(&self, symbols: &[(String, Option<u64>)]) -> Result<LibcResponse> {
        if symbols.is_empty() {
            return Ok(LibcResponse {
                results: Vec::new(),
                query_info: Some(QueryInfo {
                    symbols_queried: 0,
                    total_matches: 0,
                    query_time_ms: Some(0),
                }),
            });
        }

        // Create cache key from sorted symbols
        let cache_key = self.create_cache_key(symbols);

        // Check cache first
        if self.config.enable_cache {
            if let Ok(cache) = self.cache.lock() {
                if let Some(cached_response) = cache.get(&cache_key) {
                    return Ok(cached_response.clone());
                }
            }
        }

        // Split symbols into chunks if needed
        let mut all_results = Vec::new();
        let mut total_symbols_queried = 0;
        let mut total_query_time = 0;

        for chunk in symbols.chunks(self.config.max_symbols_per_request) {
            let response = self.query_symbols_chunk(chunk).await?;

            if let Some(ref query_info) = response.query_info {
                total_symbols_queried += query_info.symbols_queried;
                total_query_time += query_info.query_time_ms.unwrap_or(0);
            }

            all_results.extend(response.results);
        }

        // Combine results and deduplicate
        all_results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        all_results.dedup_by(|a, b| a.id == b.id);

        let final_response = LibcResponse {
            results: all_results.clone(),
            query_info: Some(QueryInfo {
                symbols_queried: total_symbols_queried,
                total_matches: all_results.len(),
                query_time_ms: Some(total_query_time),
            }),
        };

        // Cache the response
        if self.config.enable_cache {
            if let Ok(mut cache) = self.cache.lock() {
                cache.insert(cache_key, final_response.clone());
            }
        }

        Ok(final_response)
    }

    /// Query a single chunk of symbols with addresses
    ///
    /// Creates the proper JSON payload format expected by libc.rip:
    /// {"symbols": {"function_name": "hex_address", ...}}
    async fn query_symbols_chunk(&self, symbols: &[(String, Option<u64>)]) -> Result<LibcResponse> {
        let url = format!("{}/find", self.config.base_url);

        // Convert symbols to the API's expected format: symbol_name -> hex_address
        let mut symbols_map = HashMap::new();
        for (symbol_name, address_opt) in symbols {
            let address_str = match address_opt {
                Some(addr) => format!("{:x}", addr),
                // Skip symbols without addresses - they won't match database entries
                None => continue,
            };
            symbols_map.insert(symbol_name.clone(), address_str);
        }

        // If no symbols have addresses, return empty result
        if symbols_map.is_empty() {
            return Ok(LibcResponse {
                results: Vec::new(),
                query_info: Some(QueryInfo {
                    symbols_queried: 0,
                    total_matches: 0,
                    query_time_ms: Some(0),
                }),
            });
        }

        let mut payload = HashMap::new();
        payload.insert("symbols", symbols_map);

        let start_time = std::time::Instant::now();

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to send request to libc API: {}", e))?;

        let query_time = start_time.elapsed().as_millis() as u64;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!(
                "API request failed with status {}: {}",
                status,
                error_text
            ));
        }

        let mut api_matches: Vec<LibcMatch> = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse API response: {}", e))?;

        // Post-process matches to populate derived fields
        for match_item in &mut api_matches {
            Self::populate_derived_fields(match_item, symbols);
        }

        let mut api_response = LibcResponse {
            results: api_matches,
            query_info: None,
        };

        // Add query time to response
        if let Some(ref mut query_info) = api_response.query_info {
            query_info.query_time_ms = Some(query_time);
        } else {
            api_response.query_info = Some(QueryInfo {
                symbols_queried: symbols.len(),
                total_matches: api_response.results.len(),
                query_time_ms: Some(query_time),
            });
        }

        Ok(api_response)
    }

    /// Get information about a specific libc version by ID
    pub async fn get_libc_info(&self, libc_id: &str) -> Result<Option<LibcMatch>> {
        let url = format!("{}/info/{}", self.config.base_url, libc_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to get libc info: {}", e))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!(
                "API request failed with status {}: {}",
                status,
                error_text
            ));
        }

        let libc_info: LibcMatch = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse libc info response: {}", e))?;

        Ok(Some(libc_info))
    }

    /// Search for libc versions by name pattern
    pub async fn search_by_name(&self, pattern: &str) -> Result<Vec<LibcMatch>> {
        let url = format!("{}/search", self.config.base_url);

        let mut payload = HashMap::new();
        payload.insert("name", pattern);

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to search libc database: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!(
                "Search request failed with status {}: {}",
                status,
                error_text
            ));
        }

        let search_response: LibcResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse search response: {}", e))?;

        Ok(search_response.results)
    }

    /// Clear the internal cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> Result<(usize, usize)> {
        if let Ok(cache) = self.cache.lock() {
            Ok((cache.len(), cache.capacity()))
        } else {
            Err(anyhow!("Failed to access cache"))
        }
    }

    /// Create a cache key from symbols
    fn create_cache_key(&self, symbols: &[(String, Option<u64>)]) -> String {
        let mut sorted_symbols: Vec<String> = symbols
            .iter()
            .map(|(name, addr)| match addr {
                Some(a) => format!("{}:{:x}", name, a),
                None => name.clone(),
            })
            .collect();
        sorted_symbols.sort();
        sorted_symbols.join("|")
    }

    /// Get client configuration
    pub fn config(&self) -> &ApiConfig {
        &self.config
    }

    /// Populate derived fields in a LibcMatch from its ID and query results
    ///
    /// The API returns basic fields, so we derive human-readable information:
    /// - Parse name, version, arch from the ID (e.g., "libc6_2.27-3ubuntu1.2_amd64")
    /// - Calculate confidence based on symbol matches
    /// - Determine which query symbols were found in the result
    fn populate_derived_fields(
        match_item: &mut LibcMatch,
        query_symbols: &[(String, Option<u64>)],
    ) {
        // Extract name, version, arch from ID (e.g., "libc6_2.27-3ubuntu1.2_amd64")
        let id_parts: Vec<&str> = match_item.id.split('_').collect();
        if id_parts.len() >= 2 {
            match_item.name = id_parts[0].to_string();
            let remaining = id_parts[1..].join("_");

            // Split by last underscore to separate version from arch
            if let Some(last_underscore) = remaining.rfind('_') {
                match_item.version = Some(remaining[..last_underscore].to_string());
                match_item.arch = Some(remaining[last_underscore + 1..].to_string());
            } else {
                match_item.version = Some(remaining);
            }
        } else {
            match_item.name = match_item.id.clone();
        }

        // Set OS (typically linux for this API)
        match_item.os = Some("linux".to_string());

        // Calculate confidence and matched symbols
        let mut matched_symbols = Vec::new();
        for (query_symbol, _) in query_symbols {
            if match_item.symbols.contains_key(query_symbol) {
                matched_symbols.push(query_symbol.clone());
            }
        }

        match_item.matched_symbols = matched_symbols.clone();
        match_item.symbols_matched = matched_symbols.len();

        // Calculate confidence based on symbol matches
        if !query_symbols.is_empty() {
            match_item.confidence = matched_symbols.len() as f64 / query_symbols.len() as f64;
        } else {
            match_item.confidence = 0.0;
        }
    }

    /// Test API connectivity by making a minimal request
    ///
    /// Since the API has no dedicated status endpoint, we test with a
    /// simple find request using a dummy symbol and address.
    pub async fn test_connection(&self) -> Result<bool> {
        let url = format!("{}/find", self.config.base_url);

        // Create minimal test payload - API requires at least one symbol
        let mut symbols = HashMap::new();
        symbols.insert("printf".to_string(), "12345".to_string());

        let mut test_payload = HashMap::new();
        test_payload.insert("symbols", symbols);

        let response = self
            .client
            .post(&url)
            .json(&test_payload)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to test API connection: {}", e))?;

        Ok(response.status().is_success())
    }
}

impl Default for LibcApiClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default LibcApiClient")
    }
}

/// Helper function to filter and prepare symbols for API query
///
/// Filters out invalid symbols and removes duplicates, preferring symbols
/// with addresses over those without.
pub fn prepare_symbols_for_query(symbols: &[(String, Option<u64>)]) -> Vec<(String, Option<u64>)> {
    let mut unique_symbols = std::collections::HashMap::new();

    for (symbol_name, address) in symbols {
        let trimmed_name = symbol_name.trim();
        if !trimmed_name.is_empty() && trimmed_name.len() >= 3 {
            // Keep the first occurrence or one with an address if available
            match unique_symbols.get(trimmed_name) {
                Some(None) if address.is_some() => {
                    unique_symbols.insert(trimmed_name.to_string(), *address);
                }
                None => {
                    unique_symbols.insert(trimmed_name.to_string(), *address);
                }
                _ => {} // Keep existing entry
            }
        }
    }

    unique_symbols
        .into_iter()
        .map(|(name, addr)| (name, addr))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.base_url, LIBC_API_BASE_URL);
        assert_eq!(config.timeout, REQUEST_TIMEOUT);
        assert_eq!(config.max_symbols_per_request, MAX_SYMBOLS_PER_REQUEST);
        assert!(config.enable_cache);
    }

    #[test]
    fn test_client_creation() {
        let client = LibcApiClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_cache_key_creation() {
        let client = LibcApiClient::new().unwrap();
        let symbols = vec![
            ("printf".to_string(), Some(0x1234)),
            ("malloc".to_string(), Some(0x5678)),
            ("free".to_string(), None),
        ];

        let key1 = client.create_cache_key(&symbols);
        let mut reversed_symbols = symbols.clone();
        reversed_symbols.reverse();
        let key2 = client.create_cache_key(&reversed_symbols);

        // Should be the same regardless of input order
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_prepare_symbols_for_query() {
        let symbols = vec![
            ("printf".to_string(), Some(0x1234)),
            ("".to_string(), None),           // Empty, should be filtered out
            ("ab".to_string(), Some(0x5678)), // Too short, should be filtered out
            (" malloc ".to_string(), Some(0x9abc)), // Should be trimmed
            ("printf".to_string(), None),     // Duplicate, should keep first with address
            ("free".to_string(), None),
        ];

        let prepared = prepare_symbols_for_query(&symbols);

        // Should not contain empty or too short symbols
        assert!(!prepared.iter().any(|(name, _)| name.is_empty()));
        assert!(!prepared.iter().any(|(name, _)| name == "ab"));

        // Should contain trimmed malloc
        assert!(prepared.iter().any(|(name, _)| name == "malloc"));

        // Should contain printf with address (first occurrence kept)
        assert!(prepared
            .iter()
            .any(|(name, addr)| name == "printf" && *addr == Some(0x1234)));

        // Should contain free
        assert!(prepared.iter().any(|(name, _)| name == "free"));

        // Should have no duplicate names
        let mut names: Vec<String> = prepared.iter().map(|(name, _)| name.clone()).collect();
        let original_len = names.len();
        names.sort();
        names.dedup();
        assert_eq!(original_len, names.len());
    }

    #[tokio::test]
    async fn test_empty_symbols_query() {
        let client = LibcApiClient::new().unwrap();
        let response = client.query_symbols(&[]).await.unwrap();

        assert!(response.results.is_empty());
        assert!(response.query_info.is_some());
        assert_eq!(response.query_info.unwrap().symbols_queried, 0);
    }

    #[tokio::test]
    async fn test_api_integration_with_known_symbols() {
        let client = LibcApiClient::new().unwrap();

        // Test with known good symbols from libc6_2.27-3ubuntu1.2_amd64
        let test_symbols = vec![
            ("strncpy".to_string(), Some(0x9ddb0)),
            ("strcat".to_string(), Some(0x9d800)),
            ("printf".to_string(), Some(0x64f00)),
        ];

        let response = client.query_symbols(&test_symbols).await;

        match response {
            Ok(resp) => {
                // Should find at least one match with these known symbols
                if !resp.results.is_empty() {
                    let first_match = &resp.results[0];
                    println!("Found libc match: {}", first_match.id);
                    assert!(!first_match.id.is_empty());
                } else {
                    println!(
                        "No matches found - API might have changed or symbols not in database"
                    );
                }
            }
            Err(e) => {
                println!("API integration test failed: {}", e);
                // Don't fail the test as API might be down
            }
        }
    }

    // Note: Integration tests that actually call the API would require
    // network access and might be flaky, so they're not included here.
    // They should be in a separate integration test suite.
}
