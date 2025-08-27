//! API client for libc.rip database
//!
//! This module provides functionality to query the libc.rip database
//! to identify C library versions based on function symbols.

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
    /// Human-readable name of the libc version
    pub name: String,
    /// Architecture (e.g., "amd64", "i386")
    pub arch: Option<String>,
    /// Operating system (e.g., "linux", "windows")
    pub os: Option<String>,
    /// Version string (e.g., "2.31-0ubuntu9.9")
    pub version: Option<String>,
    /// URL to download this libc version
    pub download_url: Option<String>,
    /// Confidence score for this match (0.0 to 1.0)
    pub confidence: f64,
    /// Number of symbols matched
    pub symbols_matched: usize,
    /// List of matched symbols
    pub matched_symbols: Vec<String>,
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

    /// Query the libc database with a list of symbols
    pub async fn query_symbols(&self, symbols: &[String]) -> Result<LibcResponse> {
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

    /// Query a single chunk of symbols
    async fn query_symbols_chunk(&self, symbols: &[String]) -> Result<LibcResponse> {
        let url = format!("{}/find", self.config.base_url);

        // Prepare request payload
        let mut payload = HashMap::new();
        payload.insert("symbols", symbols);

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

        let mut api_response: LibcResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse API response: {}", e))?;

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
    fn create_cache_key(&self, symbols: &[String]) -> String {
        let mut sorted_symbols = symbols.to_vec();
        sorted_symbols.sort();
        sorted_symbols.join("|")
    }

    /// Get client configuration
    pub fn config(&self) -> &ApiConfig {
        &self.config
    }

    /// Test API connectivity
    pub async fn test_connection(&self) -> Result<bool> {
        // Since there's no status endpoint, test with a minimal find request
        let url = format!("{}/find", self.config.base_url);

        // Create a test payload with a dummy symbol (API requires at least one filter)
        let mut symbols = HashMap::new();
        symbols.insert("printf".to_string(), "0x12345".to_string());

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
pub fn prepare_symbols_for_query(symbols: &[String]) -> Vec<String> {
    symbols
        .iter()
        .filter(|s| !s.is_empty() && s.len() >= 3) // Minimum length filter
        .map(|s| s.trim().to_string())
        .collect::<std::collections::HashSet<_>>() // Remove duplicates
        .into_iter()
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
            "printf".to_string(),
            "malloc".to_string(),
            "free".to_string(),
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
            "printf".to_string(),
            "".to_string(),         // Empty, should be filtered out
            "ab".to_string(),       // Too short, should be filtered out
            " malloc ".to_string(), // Should be trimmed
            "printf".to_string(),   // Duplicate, should be removed
            "free".to_string(),
        ];

        let prepared = prepare_symbols_for_query(&symbols);

        assert!(!prepared.contains(&"".to_string()));
        assert!(!prepared.contains(&"ab".to_string()));
        assert!(prepared.contains(&"malloc".to_string())); // Trimmed
        assert!(prepared.contains(&"printf".to_string()));
        assert!(prepared.contains(&"free".to_string()));

        // Should have no duplicates
        let unique_count = prepared.len();
        let mut sorted = prepared.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(unique_count, sorted.len());
    }

    #[tokio::test]
    async fn test_empty_symbols_query() {
        let client = LibcApiClient::new().unwrap();
        let response = client.query_symbols(&[]).await.unwrap();

        assert!(response.results.is_empty());
        assert!(response.query_info.is_some());
        assert_eq!(response.query_info.unwrap().symbols_queried, 0);
    }

    // Note: Integration tests that actually call the API would require
    // network access and might be flaky, so they're not included here.
    // They should be in a separate integration test suite.
}
